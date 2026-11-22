# ASI acceptance scorecard, re-run on current main

Product commit: `89dd7a7` (main, 12 commits after `983887d`). Date 2026-11-22 (times below UTC; Warsaw = UTC+1).

Setup:
- `LAB_SLOT=5 lab/run.sh`: **LAB: PASS (0 failures)** (lab-1 11 hosts, lab-2 10 hosts / 5 changes, lab-3 11 hosts / 2 changes).
- Then the same lab brought up again by hand (project `asi-lab-5`, `172.30.5.0/24`). `asi serve` ran inside the lab's
  asi container (it has nmap) on the lab network, using schema `accept2` of the test Postgres (127.0.0.1:55432) and its own
  `ASI_MASTER_KEY`. A socat container on the lab network forwarded it to 127.0.0.1:18741, so `172.30.5.4` (the
  forwarder) shows up as one extra live host. The UI was driven with curl (login + CSRF) as admin/editor/operator/viewer,
  plus a custom role.
- Runs: 5 UI runs of `ui-lab` (baseline, 2 with no change, lab stage 2, stage 3), a paused/resumed run, a windowed run
  (`win-slow`, rate 3), 2 manual entries, a CSV import and a JSON import, a recheck and a CLI run with mixed target forms.
- README quick start run word for word in a `git archive HEAD` copy with `COMPOSE_PROJECT_NAME=asi-accept2`.
- Cleaned up afterwards: lab down -v, forwarder removed, schema dropped, my images and temp files deleted.

Status values: works / partly / missing / pending task (area of a UI task still being merged) / skipped (password-change
and picker tasks in progress) / not checked.

## A. Functional requirements

| Id | Requirement | Status | How checked | Evidence |
|---|---|---|---|---|
| R1 | IPs, CIDR, domains | works | `scan plan` on IP + /24 + range `10.20.2.10-20` + `localhost` + /18 from a file with `#` comment; real CLI run on `172.30.5.10-12`, `flap` (host name), `172.30.5.20/31` | `asi scan plan --targets-file t1.txt --exclude-file ex1.txt` → `addresses=16521` (= 16649 − 127 − 1); `asi scan run ... --name cli-mix` → `addresses=6 hosts=5`, hostname `flap` attached. The UI takes pasted targets only, no file upload (new-scan form task is pending) |
| R1b | Excludes win | works | /25 and one address excluded in plan; `172.30.5.11` excluded in cli-mix | plan count above; cli-mix scanned 6 addresses |
| R1c | Port lists, ranges, presets | works | `21,80,8000-8100,80` sorted and deduplicated; `top100`, `top1000`; `all` refused by the work ceiling with a clear message; `70000` → `invalid port` | `asi scan plan --ports ...` |
| R2 | Safe multi-threaded nmap scan, duration, subgroups from measured speed | partly | groups adapt (windowed run: 64,64,64,22,16,16,5); duration per group; plan preview still leads with the worst case and its measured estimate is too low | `/scans/1/preview`: tiles "16 min 47 s Duration at max rate" for a /24 that takes 20 s; "At measured speed 8 s" (real runs 20 s); `/18` top100 @200/s → `duration_at_max_rate=394h40m` |
| R3 | Live hosts | works | 12/12 live (11 lab + forwarder), stage 2: .19 new, .17/.21 missing | `/changes` after stage 2; `lab/run.sh` PASS |
| R4 | Basic services | works | SSH, Redis, nginx, PostgreSQL in quick start | `/hosts/`; quick start CSV: `PostgreSQL DB,9.6.0 or later` |
| R5 | HTTP: title, status, headers, cookies, TLS, redirects | works | host .12 page | `/hosts/172.30.5.12`: 200, "Admin Panel - Sign in", redirect `/admin/login`, `PHPSESSID; HttpOnly`, cert subject/issuer/SANs/valid until/self-signed |
| R6 | CMS, framework, app server, IoT | works | WordPress 6.4.2, Drupal 10, PHP 7.4.3, nginx 1.27.5, OpenSSH, Redis, NETCAM camera | `/hosts/172.30.5.10`, `.11`, `.16`. The camera is found only through `lab/signatures`; in a run without it (cli-mix) .16 got no IoT finding |
| R7 | Staging/test, admin panel | works (was partly) | built-in `builtin-staging-title`, `builtin-staging-header`, `builtin-admin-login` | `/hosts/172.30.5.13`; imported CSV host titled `[TEST] Old intranet` got `builtin-staging-title` |
| R8 | Compare consecutive runs | works | 2 rescans with no change and a recheck: 0 changes each | `asi diff --from ui-lab-...001302 --to ui-lab-...001413` → `"changes": []` |
| R9 | New, missing, changed services | works | stage 2: Missing .17/.21, New host .19, New service .18:8081, Changed .18:80 title + `x-app-version` 1.0→2.0; stage 3: Returned .17, Inactive .21 | `/changes` |
| R10 | Custom signatures | works | created in `/signatures/new`; test on stored data ("Matches 172.30.5.18 80/tcp, version 2.0"); retro-hunt found inactive .21; 13 unsafe drafts all refused with 422 "Rule violated: ..." (POST, PUT, DELETE, body, headers, credentials, query, absolute URL, relative path, `//user:pw@host`, `/../`, `%2e%2e`, bad regex); 5-path cap enforced | `POST /signatures`, `/signatures/test`, `/signatures/hunts/1`. Raw YAML only |
| R11 | Manual entry, CSV, JSON processed like scans | works (was partly) | form host `nginx 1.14.0` / `Apache httpd 2.2.15` → technologies + `outdated-nginx`, `outdated-apache`, staging; CSV `OpenSSH 7.4` → `outdated-openssh`; JSON `PHP/5.6.40` → `outdated-php`, Drupal, header/cookie findings | `/hosts/10.99.1.10`, `/hosts/10.99.2.11`, `/hosts/10.99.3.10` |
| R12 | Roles can be created and managed | works | role `auditor` (inventory.read + export) created, user assigned: export 200, scans/import/audit/host edit 403; role deleted | `/roles`, `/users/create`. Raw permission codes (roles pickers task: skipped) |
| R13 | Four built-in roles | works | 19 GET and 8 POST endpoints × 4 roles behave as the matrix | admin all; editor 403 users/roles/audit/scan create; operator edits hosts, 403 scans/signatures/import; viewer 403 on every POST and export |
| R14 | Edits independent of scan state, kept | works | .10 tags/display name/owner/criticality/notes set after run 1, intact after 8 later runs incl. recheck, windowed run and CLI run; edits while `win-slow` was paused/running | `hosts` row: `{crown-jewel,web} | web team | WP-main | high` |
| R15 | Clear UI per role, dashboard | pending task | dashboard, navigation and run pages are being reworked | see "Pending-task observations" |
| R16 | Encryption at rest of sensitive fields | partly | raw rows in `accept2` | ciphertext: `service_observations.http_headers/http_cookies/http_body/field_state`, `findings.evidence`, `hunt_results.evidence`, `hosts.notes`, `settings.value` (DefectDojo token, checked: no plaintext). Plain: `hosts.owner`, `hosts.display_name`, `host_observations.hostnames`, `service_observations.http` (URL, title, TLS subject/issuer/SANs), `host_summary.titles/hostnames`, `signatures.source`, `scan_definitions.settings` (targets), `audit_log`, `sessions.csrf_token` |
| R16b | Key status and rotation | works | `asi key status`; with only a new key reads fail closed with a clear message; `ASI_MASTER_KEY_PREVIOUS=old asi key rotate --batch 50` rewrote 452 rows; afterwards the old key is refused | `key rotate: done, all encrypted rows are under key id 7491c93797f79553` |
| R17 | Windows and frequency; overrun stopped and continued | works | `win-slow` windows `sun 01:19-01:21; sun 01:23-01:45` Warsaw: started by the scheduler 00:19:11Z, paused 00:21:11Z, continued 00:23:16Z, completed 00:32:58Z | `asi scan show win-slow-20261122-001911`. Work of the first window was redone (0 groups kept) |
| R17b | Manual pause / resume | works | paused at 3/4 groups, resumed, continued from group 4 only | `/runs/1/pause`, `/runs/1/resume`; groups 1-3 keep their first durations |
| R18 | Rate limiting | works | `--max-rate` is handed to nmap (`--max-rate 1` per slot at cap 3, `--max-rate 37` for a recheck); run summaries keep peak/average | `ps` in the container; not measured on the wire this time. The estimated count (2662 packets in about 700 s of window time = 3.8/s at cap 3) and `actual_peak=0.9/s` disagree |
| R19 | Export JSON/CSV; import JSON/CSV | works | `/export.json`, `/export.csv` with tag/status filters; `asi export`; imports above | `/export.json?tag=crown-jewel` → 1 host; owner/display name/criticality are exported |
| R20 | Unstable hosts, confidence, inactive threshold | partly | unstable after 1 miss (stability 0.75), inactive after 2, returned; confidences on technologies. But an inactive host becomes `unstable` again as of every manual/import run | `asi export --run acc-imp.json` → .21 `('unstable', 2)` while it was `inactive` in the run before |

## B. Minimum scope

| Item | Status | How checked | Evidence |
|---|---|---|---|
| Import host/range lists | works | CSV row with only an address imported | `10.99.2.12` |
| Import scan results JSON/CSV | works | dry run then real import | "Imported 3 hosts and 2 services as run acc-imp.csv" |
| Large ranges (10 000+) | partly | plan for 16 649 addresses works; the measured /18 result exists only in the local checkout | `git ls-files eval/results/perf` is empty; `.git/info/exclude` excludes `eval/results/perf/` |
| Scan configuration: window, frequency | works | R17 | - |
| Rate limiting | works | R18 | - |
| Live hosts / services | works | R3, R4 | - |
| Results stored in a database | works | 26 tables in `accept2` | - |
| Compare two scans | works | R8 | - |
| Dashboard/report with key changes | pending task | - | - |
| Export JSON/CSV | works | R19 | - |
| Role separation | works | R13 | - |
| Edit scans, results, configuration | partly | `/scans/{id}/edit`, host edit, service delete work; a scan definition cannot be deleted and a finding cannot be dismissed | `POST /scans/1/delete` → 404; no route in `internal/web` |
| Data protection | partly | R16 | - |

## C. Nice to have

| Item | Status | How checked | Evidence |
|---|---|---|---|
| Cyclic schedule | works | R17 | - |
| Time-of-day differences | not checked | needs 6+ covering runs in different hours | `/hosts/172.30.5.17/availability` "No regular hours yet" |
| Interest score | works | dashboard top hosts, reasons on timeline | .12 went 95 → 85 with nothing changed on the host |
| Repeated measurement of unstable hosts | not checked | re-probe not observable from the outside | - |
| Grouping similar services | works | `/groups`: 14 groups | - |
| Tags | works | `/hosts/?tag=crown-jewel` → 1 | - |
| DefectDojo export | partly | CLI dry run only (no external host contacted): `nmap.xml` 17 hosts / 20 services, `findings.json` 74 (54 findings + 20 open services), token stored encrypted, `test` against 127.0.0.1:9 → clear "connection refused" | `asi defectdojo export --run ui-lab-20261122-002152 --dry-run --out /tmp/dd`. No dry run in the UI; the payload of a scan run also contains the 5 manual/imported hosts that run never covered. Selection in the UI: skipped (pickers task) |
| Changes over time | partly | per-host timeline works; host page still has no link to it; dashboard chart is pending | `/hosts/172.30.5.18/timeline`; links on `/hosts/172.30.5.18`: only `/availability` |
| Passive data sources | missing | - | `docs/requirements-coverage.md` |

## D. Lab validation points

| # | Point | Status | Evidence |
|---|---|---|---|
| D1 | Live hosts | works | 12/12, then .19 new, no false host |
| D2 | Services | works | 13 then 14 services (8081 new) |
| D3 | HTTP/HTTPS fingerprint | works | R5 |
| D4 | CMS/technology | works | R6, `outdated-php` on .12 |
| D5 | Headers and cookies | works | `X-Powered-By`, `X-Environment`, `X-Debug-Token` redacted, cookie flags; every nginx host still carries a "Header" badge for `Server:` |
| D6 | Custom signatures | works | R10 |
| D7 | Comparison | works | R8, R9 |
| D8 | Unstable / changing hosts | works | .17 missing → returned, .21 inactive after 2 misses, .18 changed |
| D9 | Safety | works | only listed ports, rate cap handed to nmap, every unsafe signature refused incl. `..` and `%2e%2e` |
| D10 | Dashboard readability | pending task | - |
| D11 | Import/export | works | R11, R19 |
| D12 | Role separation | works | R13 |

## E. Documentation and ease of running

| Item | Status | How checked | Evidence |
|---|---|---|---|
| README quick start | works | five commands word for word; port published on `127.0.0.1:8080` only | `run first status=completed groups=1 addresses=2 hosts=2`; dashboard "2 Active hosts"; `docker port` → `127.0.0.1:8080` |
| README CLI section | works | `scan run ... --name second`, `scan show`, `export --out /dev/stdout`, `diff` | the status line "exported 2 hosts ... to /dev/stdout" ends up inside the CSV/JSON on stdout |
| README feature table and "In progress" | partly | compared with the binary | "In progress" lists recheck mode, plan preview and adaptive back-off, which exist; "49 signatures" vs 54 in `/signatures` |
| operations.md command reference | partly | compared with `asi --help` | missing `key status`, `key rotate`, `scan plan`, `user list/set-role/delete`, `role list`, `ASI_MASTER_KEY_PREVIOUS`; "Rotation is not supported in place. There is no command that re-encrypts stored values" is false |
| technical.md | partly | limits section | "there is no heartbeat" (migration `0016_run_heartbeat` exists), "No key rotation and no re-encryption command" |
| requirements-coverage.md | partly | per row | R12 "partly ... no page and no command"; 10% row "no user or role management interface; no key rotation"; R16 "No key rotation"; DefectDojo "never against a real DefectDojo" while commit `d396b88` says it was run against DefectDojo 3.5 |
| Evidence referenced by the docs | missing | `git ls-files` | `eval/results/perf/post-scale.json`, `eval/results/reliability/summary.md` are not tracked (`.git/info/exclude`) |
| `lab/run.sh` | works | slot 5 | `LAB: PASS (0 failures)` |

## Pending-task observations (not failed)

- Dashboard: after a recheck "Changes in the latest run: No changes since run ..."; after a partial CLI run "Latest run
  cli-mix, Addresses covered 6"; the changes chart counts manual entries and imports as runs; "Newest admin panels,
  staging and IoT" lists the same finding twice or three times.
- Run page: no auto-refresh; 0% and 0 packets for minutes inside a group; times in UTC without a zone while windows are
  in Europe/Warsaw ("next window opens at 2026-11-22 00:23" for a 01:23 window); a run paused by its window shows both
  "Pause run" and "Resume run"; `packets=512 nmap_packets_estimated=1024` while running.
- New scan form: windows pre-filled `mon-fri 22:00-06:00`; no targets file upload.
- Navigation: flat list of 13 items for admin; viewer has no Scans entry but `/runs/{id}` answers 200; `GET /runs`
  answers 404 "This run does not exist."

## Shortcomings found (most expensive in the jury's sheet first)

1. **Sensitive fields still stored in plain text (R16; 10% criterion).** Repro: run any scan, set an owner on a host,
   then `select owner, display_name from hosts; select http->'tls'->>'subject_cn', http->>'title' from
   service_observations; select source from signatures; select settings from scan_definitions; select * from
   audit_log;` – all readable. The docs only justify "addresses, ports, titles, product names". Fix:
   `internal/store/crypt.go` + the writers in `internal/inventory/record.go`, `internal/auth`, `internal/schedule`; or
   state and justify every plain column in `docs/technical.md#encryption-at-rest`.
2. **Docs contradict the binary (20% criterion).** Repro: `asi --help` lists `key status`, `key rotate`, `scan plan`,
   `user list|set-role|delete`, `role list`; `docs/operations.md` "Command line reference" lacks them and "Key
   management" says rotation does not exist; `docs/technical.md` says "no heartbeat" and "No key rotation";
   `README.md` "In progress" lists recheck, plan preview and adaptive back-off; README says 49 built-in signatures,
   `/signatures` says 54; `docs/requirements-coverage.md` R12 says roles have no page, R16 and the 10% row say no key
   rotation, DefectDojo row says never run against a real instance. Fix: those four files.
3. **The large-network evidence is not in the repository (30% criterion).** Repro: `git ls-files eval/results/perf
   eval/results/reliability` → empty; `docs/requirements-coverage.md` rows R3, R18 and the 30%/15% rows cite
   `eval/results/perf/post-scale.json` and `eval/results/reliability/summary.md`. Fix: commit them (they are excluded in
   `.git/info/exclude`).
4. **Plan preview misleads (R2; 30% and 15% criteria).** Repro: create scan `172.30.5.0/24`, 7 ports, rate 300, open
   `/scans/1/preview`: headline tile "16 min 47 s Duration at max rate"; after one 20 s run "At measured speed 8 s";
   a recheck is previewed at 6 s and took 49 s. `asi scan plan` for a /18 top100 at 200/s: `duration_at_max_rate=394h`.
   Fix: lead with the measured estimate, model group parallelism and dead addresses; `internal/web/scans.go`
   (preview) and the plan code in `internal/scan`.
5. **Inactive host flips back to unstable as of manual/import runs, then "becomes inactive" again (R20, R9).** Repro: scan
   definition with `inactive_after=2`, let a host be missed twice (inactive), add a host through `/hosts/entry` or
   import a CSV, run the scan again: `asi export --run <import run>` shows the host `unstable, missed 2`, and `/changes`
   from the import run to the next scan shows "Inactive host" a second time. Likely the import/manual run applies the
   default threshold 3. Fix: `internal/inventory/status.go` / `record.go` (threshold of an import run).
6. **Duplicate findings (10% fingerprinting).** Repro: lab .12 shows "Admin panel" twice per service
   (`admin-panel-login` + `builtin-admin-login`), .10 two WordPress technologies, .13 three "Staging or test environment"
   findings, all exported to DefectDojo; every nginx host carries a "Header" finding for `Server:`. Fix: dedupe by
   kind + name + version per service in `internal/detect`, and in the badges of `internal/web` host list/page.
7. **Scan definitions cannot be deleted, findings cannot be dismissed (minimum scope "edit scans").** Repro: `POST
   /scans/1/delete` → 404; no control on `/scans/1` or on a finding row. Fix: `internal/web/scans.go`,
   `internal/schedule`.
8. **Windowed runs lose the work of the window that ended (R17; 15% intensity).** Repro: rate 3, windows
   `01:19-01:21`, `01:23-01:45`: 512 packets sent in window 1, 0 groups kept, the group restarted at 01:23. Counters
   disagree (`packets=512 nmap_packets_estimated=1024`, `actual_peak=0.9/s` against 2662 estimated packets ≈ 3.8/s for a
   cap of 3). Fix: `internal/scan/scan.go` (checkpoint inside a group, one packet counter).
9. **Recheck is slower than a full run.** Repro: `POST /scans/1/start mode=recheck` on 11 known hosts: 49 s, a full
   run of the /24 takes 20 s. Fix: `internal/scan` recheck path (nmap `-sV` per service).
10. **DefectDojo: no dry run in the UI; a run's payload includes hosts the run never covered.** Repro: `/defectdojo`
    has only Save/Test/Export; `asi defectdojo export --run ui-lab-... --dry-run` writes 17 hosts incl. 5 manual/imported
    `10.99.*` hosts for a run that covered 12. Fix: `internal/web/defectdojo*.go`, `internal/exchange/defectdojo`.
11. **Signature UI is raw YAML only** and points to `docs/contracts.md §4`, which the UI does not serve; signatures from
    `ASI_SIGNATURES_DIR` or a scan's directory are not listed on `/signatures`. Fix: `internal/web` signatures pages.
12. **Import page:** no hidden `csrf_token` (only htmx `hx-headers`), so without JavaScript the upload gets 403
    (repro: plain multipart POST with the page's token → "Invalid or missing CSRF token"); CSV columns are not listed;
    "Imported 1 hosts and 1 services". Fix: `internal/web` import template.
13. **Host page has no link to the host timeline** (`/hosts/{a}/timeline`). Fix: host page template in `internal/web`.
14. **`--out /dev/stdout` (used in the README) mixes the status line into the data.** Repro: `asi export --format csv
    --out /dev/stdout | tail -1` → `exported 2 hosts as of run second to /dev/stdout`. Fix: `cmd/asi`, print status to
    stderr.
15. **Built-in pack does not recognise the lab IP camera** without `lab/signatures` (cli-mix: .16 only
    `builtin-header-server`). Fix: `internal/detect` built-in pack (title "NETCAM" / favicon).
16. **Interest score drifts without a change** (.12: 95 → 85 within 10 minutes; reasons only on the timeline page).
    Fix: `internal/inventory/interest.go` or show the reasons on the dashboard.
