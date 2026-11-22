# ASI acceptance scorecard (jury walk-through)

Product commit: `983887d9842283e663a6dbbd3b41cead780fd6fa` (main, image `asi:acc`). Date 2026-11-21.
Setup: own compose `asi-acc` (README stack with the port moved to 127.0.0.1:18880, not the verbatim quick start), lab slot 9 (`172.30.9.0/24`), ports 22,80,443,6379,8000,8080,8081, `/lab/signatures`.
Driven through the web UI (real browser for login, new scan, preview, start, run page, dashboard, hosts, host page, changes, signatures form, roles, users, import page; other form posts with curl + CSRF), then the CLI.
Runs: 1 baseline, 2 no change, 3 lab stage 2, 4 lab stage 3 (+2 UI signatures), manual entry, CSV import, JSON import, 8 recheck, 9 windowed slow run.
Evidence: `evidence/` (text, exports, payloads), `screens/` (PNG + saved HTML). UI times are UTC; local time was CET.

## A. Required functions

| # | Item | Status | Evidence | Intuitiveness |
|---|---|---|---|---|
| A1 | Load IPs, CIDR, domains | WORKS | `/scans/new` took `172.30.9.0/24`; `big-18` took a /18 + `agh.edu.pl` + `192.168.5.10-20`; `preview-18.txt` "16 138 Addresses after excludes" | Paste only; no file upload for a target list in the UI |
| A2 | Safe multi-threaded discovery, nmap, duration, subgroups | PARTLY | run page: 4 groups of 64, 251/251, 19 s; `cli-scan-show.txt` `packets=2151 ... groups_done=4/4` | Preview says "16 min 47 s" for a 19 s run; run page does not refresh itself; 0% until a whole group ends |
| A3 | Live hosts | WORKS | run 1: "11 Hosts found" of 11 lab hosts; stage 2: .19 new, .17/.21 missing | clear |
| A4 | Basic services | WORKS | `/hosts/`: 22 OpenSSH, 6379 Redis, 80/443/8000/8080 nginx; `/hosts/entry?address=172.30.9.14` version `8.9p1 Ubuntu 3ubuntu0.6` | 443 is shown as service `http`; https only visible in the URL |
| A5 | HTTP: title, status, headers, cookies, TLS, redirects | WORKS | `/hosts/172.30.9.12` (`screens/host12.png`): 200, "Admin Panel - Sign in", redirect `/admin/login`, `PHPSESSID; HttpOnly`, cert `admin.lab.asi.test` self-signed, SANs | clear |
| A6 | Technology: CMS, framework, server, IoT | WORKS | WordPress 6.4.2, Drupal 10, PHP 7.4.3, nginx 1.27.5, "NETCAM IP Camera" IoT (lab signature); 54 built-in signatures | Same WordPress listed twice (lab + built-in signature) |
| A7 | Staging/test and admin panels | PARTLY | Admin panel: built-in `builtin-admin-login` hit on .12. Staging on .13 came only from `lab/signatures`; no built-in signature of kind `staging` exists (grep of the repo; imported host titled "[STAGING] ..." got no finding) | With the README defaults a staging site is not flagged |
| A8 | Compare consecutive runs | WORKS | `/changes` run 2->3: 5 changes; run 1->2: "0 changes"; `evidence/diff-stage2.json` | From/To pickers obvious |
| A9 | New, disappearing, changed services | WORKS | `screens/changes-stage2.png`: Missing host .17/.21, New host .19, New service .18:8081, Changed .18:80 `http.title Intranet v1 -> v2`; stage 3: Returned .17, Inactive .21 | good, old/new values shown |
| A10 | Custom signatures | WORKS | `signatures-create-test.txt`: header + body signature created in `/signatures/new`, test "Matches 172.30.9.18 80/tcp, version 2.0", run 4 produced findings `acc-app-version-header`, `acc-metrics-console` | Raw YAML only, points to `docs/contracts.md §4` which the UI does not serve; test says "bodies are not stored" while the hunt matches the body |
| A11 | Entry form, CSV, JSON processed like scans | PARTLY | `import-entry.txt`, `imported-hosts.txt`: all three recorded as runs with diffs; JSON host got 7 findings + Drupal/PHP. Form and CSV host got none: they cannot carry headers/body, typed product `nginx 1.14.0` / `Apache httpd 2.2.15` gives no technology row and no `outdated`; JSON `PHP/5.6.40` got no `outdated` either (scanned PHP 7.4.3 did) | Import page does not list CSV columns; plain multipart POST with the form's token = 403 (works only via the htmx header) |
| A12 | RBAC, roles can be created and managed | WORKS | `/roles`: custom role `auditor` (inventory.read + export) created, user assigned, behaves as set (`rbac-matrix.txt`) | Permission names are raw codes; table wider than 1440 px |
| A13 | Four concrete roles | WORKS | `rbac-matrix.txt`: admin all 200/303; editor 403 on scan create, users, roles, audit; operator edits host (303), 403 on delete/start/import/signatures; viewer 403 on every POST and on export | Viewer has no Scans menu yet `/runs/1` answers 200 |
| A14 | Edits independent of scan state, kept across scans | WORKS | .10 tags/owner/criticality/notes set after run 1, intact after runs 2-4 + recheck and in `export-ui.json`; .11 edited while run 9 was running (`edit-during-scan.txt`) | "Edit host" is a collapsed block at the very bottom of a long page |
| A15 | Clear UI for every role, main dashboard | PARTLY | `screens/dash1.png` is good; `screens/dash-final.png`: "Latest run" = a running/imported run with zeros, "Changes in the latest run: No changes" although stage 2/3 changes exist | Dashboard forgets the last real changes as soon as an import, recheck or new run starts |
| A16 | Encryption at rest of sensitive fields | PARTLY | `encryption-select.txt`: ciphertext (bytea, key id `adc97e48...`): `service_observations.http_headers/http_cookies/http_body`, `findings.evidence`, `hunt_results.evidence`, `hosts.notes`, `settings.value` (DefectDojo token). Plain: `hosts.owner`, display name, tags, titles, URLs, TLS subject/SANs, product and technology versions, `signatures.source`, scan targets, audit log, `sessions.csrf_token`; passwords argon2id | `asi key status` is clear; no UI view of what is encrypted |
| A+ | Time windows and frequency | WORKS | `/scans/3` "Enabled. Runs once a day in sat 23:23-23:25; sat 23:27-23:47 (Europe/Warsaw)"; scheduler started run 9 at 22:23:08Z | Form pre-fills `mon-fri 22:00-06:00`; pages show UTC, windows are local |
| A+ | Run over its window is stopped and continued | WORKS | `window-test.txt`: 23:25:21 `status=paused`; `rate-measure.txt`: 4 packets in 30 s while paused; 23:27:16 `status=running`; page: "paused until its next window opens" | Restarted its unfinished groups from zero (2 min of work lost); run 9 then completed at 22:32:23Z, `packets=3167 actual_peak=2.4/s`; paused page shows both "Pause run" and "Resume run" |
| A+ | Rate limiting | WORKS | `rate-measure.txt`: max rate 4 -> 2.3 packets/s measured on the scanner's interface; run 4: `max_rate=300 actual_peak=20.5/s` | Rate chart on the run page is good |
| A+ | Signatures only detect | PARTLY | `unsafe-signatures.txt`: POST, PUT, body, custom header, `?query`, absolute URL all 422 "Rule violated: ..."; but `path: /../../etc/passwd` was saved (303) | Refusal text is clear |

## B. Minimum scope

| Item | Status | Evidence | Intuitiveness |
|---|---|---|---|
| Import host/range lists | WORKS | CSV row with only an address imported (10.99.1.12); ranges go into scan targets | two different places, not explained |
| Import scan results JSON/CSV | WORKS | `import-entry.txt` dry run + real import, "Imported 3 hosts and 2 services as run acc-imp.csv" | dry run is a nice touch |
| Large ranges (10 000+) | PARTLY | Not re-run. `/scans/4/preview`: 16 138 addresses, 253 groups, "154 h 12 min at most". Measured /18: `eval/results/perf/post-scale.json` (16 384 addresses, 126-131 s, host and service recall 1.0) exists only untracked in the working checkout, not in commit 983887d | Preview contradicts the measurement by a factor of 4000 |
| Scan config: window, frequency | WORKS | see A+ | - |
| Rate limiting | WORKS | see A+ | - |
| Live hosts / services | WORKS | A3, A4 | - |
| Results saved to database | WORKS | Postgres tables, history on host page | - |
| Compare two scans | WORKS | A8; `asi diff` gives the same document | - |
| Dashboard/report with key changes | PARTLY | A15 | - |
| Export JSON/CSV | WORKS | `/export.json` (16 hosts, `asi.export/v1`), `/export.csv` (19 lines); `asi export` | filters on the page work |
| Role separation | WORKS | A13 | - |
| Edit scans, results, configuration | PARTLY | `/scans/1/edit` works, host fields and `/hosts/entry?address=` work; a scan definition cannot be deleted (no route, `rbac-admin` is stuck in the list); a single finding cannot be dismissed | no delete anywhere on the scan page |
| Data protection | PARTLY | A16 | - |

## C. Nice to have

| Item | Status | Evidence | Intuitiveness |
|---|---|---|---|
| Schedule of cyclic scans | WORKS | daily/weekly/interval + windows, run 9 started by the scheduler | - |
| Time-of-day differences | NOT CHECKED | `/hosts/172.30.9.17/availability`: "No regular hours yet" (needs 6 covering runs at different hours) | - |
| Interest score | WORKS | dashboard "Top hosts by interest", reasons with points on `/hosts/{a}/timeline` | score drifted 95 -> 85 within minutes without explanation on the dashboard |
| Repeated measurements for unstable hosts | NOT CHECKED | only indirect: .17 "80% Stability, last 10 runs"; re-probe not observed | - |
| HTTP/HTTPS fingerprinting | WORKS | A5 | - |
| CMS/technology detection | WORKS | A6 | - |
| Grouping similar services | WORKS | `/groups`: .12:80 and .12:443 in one group of 2 | 13 of 14 groups have one member |
| Tags | WORKS | tag filter `/hosts/?tag=crown-jewel` -> 1 host | - |
| DefectDojo export | PARTLY | `evidence/defectdojo-dryrun/`: `nmap.xml` (11 hosts, 13 services), `findings.json` (31 Info findings); test against fake URL -> 502 "no such host" | whole run only, no selection; dry run only in the CLI; never run against a real DefectDojo |
| Visualisation of changes over time | PARTLY | dashboard bar chart, per-host timeline | chart labels all cut to "lab-net-2026"; host page has no link to its timeline |
| Passive data sources | MISSING | `docs/requirements-coverage.md`: "not yet" | - |

## D. Lab verification (three runs)

| # | Item | Status | Evidence |
|---|---|---|---|
| D1 | Live hosts | WORKS | 11/11, then 10 + new .19, no false hosts in 251 addresses |
| D2 | Services | WORKS | 12 services run 1, 13 after stage 2 (8081 new) |
| D3 | HTTP/HTTPS fingerprint | WORKS | host .12 page, `export-ui.json` |
| D4 | CMS/technology | WORKS | WordPress 6.4.2, Drupal 10, PHP 7.4.3 + `outdated-php` |
| D5 | Headers and cookies | WORKS | `X-Powered-By`, `Server`, PHPSESSID flags; noisy: every nginx host carries a red "Header" badge |
| D6 | Custom signatures | WORKS | A10 |
| D7 | Comparison | WORKS | A8, A9 |
| D8 | Unstable / changing hosts | WORKS | .17 missing -> returned, .21 inactive after 2 misses, .18 title/header change; time-of-day not shown |
| D9 | Safety | WORKS | only listed ports, rate held, unsafe signatures refused (one gap: `..` path) |
| D10 | Dashboard readability | PARTLY | A15 |
| D11 | Import/export | WORKS | A11, B |
| D12 | Role separation | WORKS | A13 |

## E. Per criterion

- **Discovery and identification on a large network (30%)**: lab results are exact. Loses points on the plan preview (154 h for a /18 the team measured at about 2 min), on the measured /18 result not being in the repository, and on no built-in staging detection.
- **Technical quality, docs, ease of running, import/export, DefectDojo (20%)**: runs from one compose file. Loses points on stale docs (README "In progress" lists recheck and plan preview that exist; coverage doc says roles have "no page"; operations.md lacks `key rotate`, `scan plan`, `user list`), on DefectDojo being whole-run and never proven against a real instance, and on form/CSV data not getting detection.
- **Change detection, unstable hosts, reporting (15%)**: diff and timeline are strong. Loses points because the dashboard shows "No changes" after any later import/recheck/running run, and time-of-day needs 6+ runs to show anything.
- **Safe operation, intensity control, dashboard clarity (15%)**: rate limit and windows proven. Loses points on the resumed run redoing unfinished groups, no live refresh, UTC vs local time, `..` path accepted.
- **Fingerprinting quality (10%)**: good. Loses a little on duplicate findings (two "Admin panel", two "WordPress" per service) and on "Header" noise for every `Server:` header.
- **Roles and data protection (10%)**: RBAC solid with audit log. Loses points on plaintext owner, hostnames, titles, certificate names, versions and signature source.

## Top 10 things to fix before the jury sees it

1. Dashboard "Latest run" and "Changes in the latest run" must show the latest completed scan run with changes (skip imports, manual entries, rechecks, running runs) or the last N changes across runs.
2. Plan preview: show the measured-speed estimate from other scans or a realistic model (dead addresses cost one discovery probe), keep "at most" as a footnote; 154 h for a /18 kills the 30% criterion.
3. Ship a built-in `staging` signature (title/hostname/header `staging|test|dev|uat`) so A7 works without the lab directory.
4. Commit `eval/results/perf/post-scale.json` and link it from README and the coverage doc.
5. Manual entry and CSV: derive technologies and `outdated` from product/version, run title signatures, allow headers in the form; apply `outdated` to imported JSON too.
6. Run page and dashboard: auto-refresh while a run is running and show progress inside a group (packets sent), not 0% for minutes.
7. Signature form: add fields (kind, matcher type, name, value, path) or at least an in-app format help page with examples; fix the "bodies are not stored" message; reject paths containing `..`.
8. Update README, operations.md and requirements-coverage.md to the current feature set (recheck, preview, roles page, key rotate).
9. Encrypt or justify in the docs: owner, hostnames, titles, TLS names, versions, signature source; add the list of encrypted columns to the UI or docs.
10. DefectDojo: dry run and per-host/finding selection in the UI; allow deleting a scan definition; show all times in the scan's timezone with the zone named.

## Papercuts

- New scan form silently pre-fills windows `mon-fri 22:00-06:00`; a first user who clicks Enable on a Saturday sees nothing happen.
- "Signatures directory: Path on the server" - the user must guess a container path; file signatures are not listed on `/signatures`.
- "Start scan now" ignores the window without saying so; "Start recheck" has no explanation next to it; recheck took 49 s against 19 s for a full run.
- Paused run shows "Pause run" and "Resume run" together; completed manual/import runs show "0% Done".
- Host page: duplicate badges in the services table (Admin panel x2, Cookie x3), `outdated` lower-case among capitalised kinds, no timeline link, edit form hidden at the bottom.
- "1 hosts and 1 services", "1 users" plural errors.
- Roles: raw permission codes, no description of what each allows; table cut at 1440 px.
- Users: password reset field inline in every row, Delete user and Delete host have no confirmation step.
- Import and manual entries are named like runs (`manual-20261121T222127.330201Z`) and fill the changes chart and the From/To pickers.
- Viewer cannot open Scans but can open `/runs/{id}`; operator sees DefectDojo but not Scans.
- Interest score changes between page loads (95 -> 85) with reasons only on the timeline page.
- Changes chart x-axis labels are truncated to identical text.

## Not checked

Verbatim README quick start on port 8080, a real 10 000+ address scan, a real DefectDojo, time-of-day profiles, the re-probe of missed hosts, service-level manual edits against a later scan, manual Pause/Resume buttons, key rotation, 800 px layout.
