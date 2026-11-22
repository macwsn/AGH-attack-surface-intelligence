# Reliability harness - run 2

Run 1: `7ff9e38` (2026-11-21). Run 2: `182dc8af0a05eb7514c8155728f7bd89c807edc0`, `RUN=run2 eval/reliability/run.sh all`.
Evidence: `eval/results/reliability/run2/<scenario>/commands.log` + `result.json`, `run2/summary.json`, `run2/extra/`.
| # | Scenario | Run 1 | Run 2 | Run 2 measured |
|---|---|---|---|---|
| 1 | kill-resume | PASS | PASS | baseline 119.5 s; kill -9 at 43 s; resume right away refused (exit 1); `stalled` after 55 s; resumed = baseline (54 hosts / 70 services) |
| 2 | db-restart | PASS | PASS | restart and 20 s outage: scan exit 0 both, no resume needed, export = baseline |
| 3 | host-vanishes | FAIL | PASS | both diffs empty; service stored with `http.error: "connection refused"` |
| 4 | hostile-http | PASS (58 s) | **FAIL** | not finished after 900 s (killed), twice; 0 hosts recorded |
| 5 | concurrent-runs | PASS | PASS | unchanged |
| 6 | bad-input | FAIL | PASS | 18/18; /8: `the targets expand to 16777216 addresses, more than the bound of 262144`, exit 1 |
| 7 | repeat-stability | PASS | PASS | 10 x 33.7 s (was 17.2 s); 9 empty diffs; 332 -> 2218 rows, linear; DB 9.66 -> 10.6 MB; no nmap left |
| 8 | key-rotation-and-wrong-key | PASS | PASS | export, diff and a new scan with another key: exit 1, one line naming the key id and `ASI_MASTER_KEY_PREVIOUS` |
| 9 | port-flap | - | PASS | `service_missing` :80, then `service_returned` :80, no host-level change; service `unstable`, host `active` |
| 10 | sigterm-pause | - | PASS | exit 1 `run "st" paused: context canceled` 0.3 s after SIGTERM; `status=paused`; 0 nmap; resumed = baseline |
| 11 | recheck-mode | - | PASS | only `host_missing 172.29.0.149`; SYN seen on all 24 known (addr, port) pairs of live hosts, 0 on the 82 pairs without a known service; 0 ICMP echo; no neighbour lookups outside known hosts |

Scenarios 1, 2 and 10 first reported FAIL because of the harness: the new export fields `response_time_ms`, `ttfb_ms` and
`availability` differ between any two runs. `check.py` now ignores them; the three scenarios were re-run and the tables show the re-run.
## NEW failure: hostile-http no longer completes in bounded time (regression)
Run 1 scanned the 17 hostile targets in 58 s. Run 2 was killed after 900 s with group 0 unfinished, in both attempts.

    $ asi scan run --targets-file /rel/targets-hostile.txt --ports 80,443 --max-rate 300 --wait --name h1     -> exit 137 after 900 s
    $ asi scan show h1    -> run h1 status=running ... groups=0 addresses=0 hosts=0 groups_done=0/1 failed_groups=0 eta=-
    $ ps:  nmap -Pn -sT -sV -p 80 --max-rate 37 -n -oX - 172.29.0.10 172.29.0.11 ... 172.29.0.17

Cause, measured: service detection now defaults to `standard` (nmap `-sV` without `--version-light`). One tarpit host alone
(`silent`: accepts, never answers) takes 259 s: `RUN=run2 eval/reliability/extra.sh` -> `group=0 addresses=1 hosts=1 duration=4m18.865s`.
With `--service-detection light` the same 17 targets pass: 58.0 s / 57.9 s, 17/17 open, 0 diff changes
(`HOSTILE_ARGS="--service-detection light" HOSTILE_NAME=hostile-http-light run.sh hostile-http`).
The true bound with the default was not measured (more than 15 min; `DefaultGroupTimeout` is 10 min, `internal/scan/scan.go:36`).
Repro: `KEEP=1 RUN=run2 eval/reliability/run.sh hostile-http`.

## Run-1 findings now
| Finding | Now | Decisive output |
|---|---|---|
| /8 accepted | fixed | `--max-addresses: the targets expand to 16777216 addresses, more than the bound of 262144` |
| nmap-skipped group counted as done | fixed, but exit 0 | `status=completed ... failed_groups=1`, `reason="... nmap scanned none of the targets (0 of 2)"`; the run still exits 0 as completed |
| vanished host as `service_changed` | fixed | `diff v0->v1: []`, `diff v1->v2: []`, `http.error: "connection refused"` |
| stale `running` after kill -9 | fixed | `status=stalled (process gone)` 55 s after the kill; resume before that: `still running in another process`, exit 1 |
| orphan nmap after kill -9 | still present | 2 nmap right after the kill and 2 s later; gone before the resume (within 55 s). SIGTERM leaves none |
| DB outage ends the run | fixed | 20 s outage: scan exit 0, export = baseline. "paused after retries" was not reached: a longer outage was not tried |
| partial HTTP data dropped | fixed (light variant) | slow body: `200 "slow body"`; endless chunked: `200 "chunked forever"`; CR/LF/NUL: 200 with 6 headers |
| title / cookie name uncapped | fixed (light variant) | title 5000 -> 512 chars, cookie name 4096 -> 256 |
| scan under a new key writes, then fails | fixed | `ASI_MASTER_KEY cannot read stored data: findings.evidence holds values under key id ...`, before scanning |

Also changed: the invalid-TLS target on 443 is exported as `service: http` (run 1: `https`); the small set scans in 33.7 s instead of 17.2 s.
Not tested: DB outage longer than the retry window; resuming a `stalled` run while its nmap orphans still run; a host whose only
port closes; the true completion time of hostile-http with the default detection; UI rendering of hostile titles.

Run 3 (`6ff06c0865504fe423e8b1f00a3faae5d909989b`, hostile-http only, default settings, `RUN=run3`): PASS - 17 hostile targets in 80.3 s / 80.3 s (run 1: 58 s, run 2: >900 s), 17 hosts / 17 services all open, 0 diff changes, 0 requests to the off-target host, no nmap left; single silent host alone 78 s (run 2: 259 s). Evidence: `run3/hostile-http/`, `run3/extra/`.
