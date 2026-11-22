# Reliability harness - results

Product commit `7ff9e38bd4d90b0900fa4201a234e71a95353d39` (image `asi:rel`), run 2026-11-21, `eval/reliability/run.sh all`.
Evidence: `eval/results/reliability/<scenario>/commands.log` + `result.json`; numbers: `summary.json`.
| # | Scenario | Result | Measured |
|---|---|---|---|
| 1 | kill-resume | PASS | baseline 97.9 s; kill -9 at 42 s (1/3 groups done); after resume 54 hosts / 70 services, identical, no duplicates |
| 2 | db-restart | PASS | restart: scan exit 0, identical; 20 s outage: scan exit 1 with a one-line error, resume -> identical |
| 3 | host-vanishes | FAIL | window hit; run exit 0; 2 `service_changed` entries (9 fields each) for the vanished host |
| 4 | hostile-http | PASS | 57.7 s / 57.8 s for 17 targets; 17/17 open; export 50 kB valid UTF-8 JSON; 0 diff changes; 0 requests to the off-target host |
| 5 | concurrent-runs | PASS | different names: both exit 0, equal, diff empty; same name: `inventory: run already exists: "c-same"`, exit 1 |
| 6 | bad-input | FAIL | 17 of 18 cases OK; a /8 is accepted and scanned |
| 7 | repeat-stability | PASS | 10 x 17.2 s; 9 empty diffs; +116 rows per run (205 -> 1249); DB 9.07 -> 9.44 MB; no nmap left |
| 8 | key-rotation-and-wrong-key | PASS | export/diff with another key: exit 1, `field encryption: unknown key id`, no file written |

## FAIL 3: host-vanishes
A host that answered discovery and nmap `-sV` but was gone before the HTTP probe is stored as `open`, `service: http`,
`http: null`, and that empty record is diffed against the previous and the next run as if the service had changed.
Repro: `KEEP=1 eval/reliability/run.sh host-vanishes` (target exits right after nmap's service probe; `target-requests.log` proves no later request was served).

    $ asi diff --from v0 --to v1 ...   (v1 = run in which the host vanished; diff v1 -> v2 is the mirror image)
    {"type": "service_changed", "address": "172.29.0.50", "port": 80, "fields": [
      {"field": "http.status_code", "old": 200, "new": null}, {"field": "http.title", "old": "Vanishing host", "new": null},
      {"field": "http.headers.x-powered-by", "old": "PHP/7.4.3", "new": null}, {"field": "technologies", "old": ["PHP 7.4.3"], "new": []}, ...

Guess: `internal/scan/scan.go:641-647` leaves `svc.HTTP` nil when `Probe` fails and the service is still written;
`internal/diff/diff.go:183` treats a nil HTTP block as "all http fields empty" instead of "not observed in this run".

## FAIL 6: bad-input, /8
`10.0.0.0/8` is neither refused nor bounded: the run starts and walks all 16.7 M addresses in 16 389 groups
(at `--max-rate 2` that is about 190 days). Killed by the harness after 45 s. The other 17 cases give a one-line error and exit 1.
Repro: `echo 10.0.0.0/8 > t.txt; asi scan run --targets-file t.txt --name b5 --ports 80 --max-rate 2 --wait`

    $ asi scan show b5        (45 s after the start)
    run b5 status=running started=2026-11-21T18:30:47Z finished=- groups=1733 addresses=1769792 hosts=0 rate=262661.6/s groups_done=1733/16389 failed_groups=0 eta=57s
    group=0 addresses=64 hosts=0 duration=9ms

Harness note: 10.0.0.0/8 is black-holed inside the product container (`ip route replace blackhole`) so nothing left the lab;
nmap therefore skipped every target instantly, which is why 1.7 M addresses were "done" in 45 s. Second finding in the same
output: nmap skipping every target ("failed to determine route") is recorded as a finished group with 0 hosts, not as a failed group.
Guess: no size check in `internal/targets` (`Parse`/`Build`) or in `parseScanRun` (`cmd/asi/inventory.go`).

## Passed, but worth a ticket
- Stale `running`: after `kill -9` and after the DB outage `scan show` still prints `status=running finished=-`
  (`internal/scan/scan.go:125-143` sets the final status only in-process; no heartbeat). A dead run and a live one look the same;
  `scan resume` on a run that really is running was not tested.
- `kill -9` of `asi` leaves its nmap children running (2 orphans, they finished on their own within about 60 s).
- DB outage: no retry at all; the first failed write ends the run (exit 1). The error is one line but 400 characters long.
- hostile-http: slow-body and never-ending-chunked targets send a complete header block and title, yet are stored with no
  http data at all (status code lost on body timeout); same for the CR/LF/NUL header target. The 5 kB title and the 4 kB
  cookie name are stored and exported untruncated. `<script>` title is exported verbatim (fine for JSON; UI not tested).
- Key change: a scan under a new key on old data writes all its observations and then exits 1
  (`list live addresses before run 2: ... unknown key id`); afterwards each key can read only its own run. There is no key-rotation command.

## Not tested / limits
- db-restart timing is one sample per variant (fault at 25 s); the restart variant may simply have fallen between two writes.
- host-vanishes covers "host gone" (container exit); "port closes, host stays" was not run.
- Invalid TLS = garbage ServerHello only; expired/mismatched certificates were not tried. UI rendering of hostile titles not tested.
- Resume while the original process is still alive, and SIGTERM (graceful pause), were not tested.
