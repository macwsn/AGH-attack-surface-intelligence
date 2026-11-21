# Open-source tools on the comparison lab (asi-complab), 2026-11-21

Lab: 172.31.0.0/24, ports 22,80,443,6379,8000,8080,8081, three stages, ground truth `eval/complab/expected-reference.json`.
Expected hosts/services: stage 1 = 11/12, stage 2 = 10/12, stage 3 = 11/13. Scanner container at 172.31.0.2; .1-.3 excluded.
Raw outputs and exact commands: `raw/<tool>/commands.md`. Machine-readable: `comparison.json`.

Run: **nmap 7.93 + ndiff**, **naabu v2.3.3 + httpx v1.6.10 + nuclei v3.4.10** (tags tech,panel), **WhatWeb 0.5.5**.
Partly run: **IVRE 0.9.22** (database + CLI only, fed with the nmap XML; no web UI, no scans of its own).
Not run: **secureCodeBox** (needs Kubernetes + Helm), **reNgine** (own installer and multi-container stack, domain-centric).

Cell legend: yes = structured field or named finding; raw = the value is in the output (header dump, title) but not recognised;
part = see note; no = not reported; (d) = from documentation or prior knowledge, not from this run.

## 1. Detection (identical in all three stages unless noted)

| | nmap -sV + scripts | naabu + httpx + nuclei | WhatWeb -a 3 |
|---|---|---|---|
| Live hosts TP / FP / missed (st. 1, 2, 3) | 11/0/0, 10/0/0, 11/0/0 | 11/0/0, 10/0/0, 11/0/0 | n/a (URLs taken from httpx) |
| Open services TP / FP / missed | 12/0/0, 12/0/0, 13/0/0 | 12/0/0, 12/0/0, 13/0/0 | 10/10, 10/10, 11/11 HTTP URLs fingerprinted |
| Service names right / wrong | 12/0, 12/0, 13/0 | HTTP vs HTTPS right on all web ports; no name for ssh, redis | n/a |
| Non-HTTP versions | OpenSSH 8.9p1 Ubuntu, Redis 7.4.12 | no | n/a |
| Page title | yes | yes | yes |
| Status code | no | yes | yes |
| Headers | yes (dump) | yes (dump) | part (names of uncommon headers; full dump only in verbose log) |
| Cookie names | raw (Set-Cookie line) | raw (set_cookie) | yes |
| TLS subject / SANs | yes / yes | yes / yes | no |
| TLS self-signed | part (issuer = subject shown, not flagged) | yes; SHA-256 equals ground truth | no |
| Redirect chain | part (final URL only) | yes (302 -> 200, final URL) | yes (one record per hop) |
| Favicon hash | no (http-favicon not run) | no (flag set; nothing for the lab's 26-byte placeholder icon) | no |
| WordPress + version | no | yes, 6.4.2 (httpx and nuclei) | yes, 6.4.2 |
| Drupal | raw (X-Generator) | yes, Drupal 10 | no (header name only) |
| PHP + version | raw (X-Powered-By) | yes, 7.4.3 | yes, 7.4.3 |
| nginx + version | yes, 1.27.5 + CPE | yes, 1.27.5 | yes, 1.27.5 |
| Admin panel (.12) | no (title only) | no stock template matches; nuclei does flag wordpress-login and drupal-login | part (generic PasswordField) |
| Staging marker (.13) | raw | raw | part (header name listed) |
| IP camera (.16) | no (title only) | no | no |
| X-Debug-Token | raw | raw | part (header name listed) |
| PHPSESSID cookie | raw | raw | yes (Cookies, HttpOnly) |
| False positives | none | nuclei `waf-detect:nginxgeneric` on every HTTP endpoint (10, 10, 11) | none |
| Stage-1 wall clock | 15 s (-sV), 15 s (scripts) | naabu 21 s, httpx 11 s, nuclei 492 s at 50 req/s (161-177 s at 150 req/s) | 86 s |

Stage-1 commands (inside a container on `asi-complab_lab`):
- `nmap -sT -sV --max-rate 300 -p 22,80,443,6379,8000,8080,8081 --exclude 172.31.0.1,172.31.0.2,172.31.0.3 -oX sv.xml 172.31.0.0/24`, then the same with `--script http-title,http-headers,ssl-cert`
- `naabu -host 172.31.0.0/24 -exclude-hosts ... -p ... -rate 300 -json` -> `httpx -l hostports.txt -rl 50 -sc -title -td -server -location -fr -favicon -tls-grab -irh -json` -> `nuclei -l urls.txt -tags tech,panel -rl 50 -jsonl`
- `whatweb -a 3 --max-threads 5 -i urls.txt --log-json=...`

## 2. Change detection (reported by the tool itself)

| | nmap + ndiff | naabu/httpx/nuclei | WhatWeb | IVRE (partial run) |
|---|---|---|---|---|
| Has a diff function | yes (two XML files) | no | no | no (keeps dated scans, merged view of 12 hosts) |
| New host .19 (1->2) | yes | no | no | no |
| Missing hosts .17, .21 (1->2) | yes, both | no | no | no |
| Returned host .17 (2->3) | part: shown as an added host, no "returned" vs "new" | no | no | no |
| .21 stays inactive (2->3) | no (no memory beyond the two files) | no | no | no |
| New port .18:8081 | yes (closed -> open, nginx 1.27.5) | no | no | no |
| Title change .18:80 | part: not in -sV data; yes with `--script http-title` and `ndiff --xml` only | no | no | no |
| Header change .18:80 (X-App-Version) | part: whole http-headers blob differs, no field | no | no | no |
| False changes on stable hosts | 0 with -sV; 0 with http-title; 9 of 9 HTTP hosts with http-headers (Date) | n/a | n/a | n/a |

ndiff problems seen in this run (all in `raw/nmap/ndiff/`): ndiff 7.93, 7.95 and 7.99 crash while loading XML that has more than one
script result per port, so the requested `http-title,http-headers,ssl-cert` scans could not be diffed at all; with one script per port the
text output crashes as soon as a script output differs and only `--xml` works. The title/header rows above therefore come from a replay of
the three stages with single-script scans (`raw/nmap/replay/`). ndiff also reports the MAC change of .18 (container recreated).

## 3. Features (all cells (d) unless marked "seen")

| | nmap + ndiff | naabu/httpx/nuclei (CLI) | WhatWeb | secureCodeBox (not run) | reNgine (not run) | IVRE |
|---|---|---|---|---|---|---|
| Change tracking over time | two-file diff (seen) | none (seen); hosted PD cloud has it | none (seen) | none itself; via DefectDojo / Elasticsearch | new/removed subdomains and endpoints, chat notifications | scan history + merged view, no diff (seen) |
| Unstable hosts (thresholds, "inactive after N") | none | none | none | none | none documented | none (time filters on queries) |
| Custom safe signatures | NSE (Lua), service-probe entries | nuclei YAML templates, large library; httpx regex flags | Ruby plugins, `--grep` | wrapped scanners + cascading rules (YAML) | custom nuclei templates, GF patterns, YAML engines | through wrapped tools |
| Scheduling, time windows, resume | cron; `--resume`; no windows | none; `-resume`; no windows | none | ScheduledScan (interval/cron); no windows | clocked and periodic scans; no windows | cron; agents; no windows |
| RBAC with roles | none | none | none | Kubernetes RBAC | 3 roles (admin, pentester, auditor) | none of its own (web server auth, per-user filters) |
| Encryption at rest | none | none | none | depends on S3 / cluster | not documented | depends on database |
| Analyst edits survive rescans | no | no | no | only in DefectDojo | notes, todos, "important" marks | not documented |
| CSV / JSON export, import | XML, grepable, text; target lists | JSONL, CSV, SARIF; host/URL lists (seen) | JSON, XML, SQL, Mongo; no CSV (JSON seen) | JSON findings in S3; hooks | PDF reports; target import | JSON + CSV out, nmap/masscan/nuclei/httpx in (seen) |
| DefectDojo | DefectDojo imports nmap XML | DefectDojo imports nuclei JSON | no importer known | official hook | not mentioned | none |
| Setup effort | 1 Dockerfile + 2 commands, ~2 min (seen) | 3 pulls + 3 commands, ~3 min; nuclei pass 3-8 min (seen) | 1 Dockerfile + 2 commands, ~2 min (seen) | Kubernetes + Helm operator + chart per scanner | clone, .env, install.sh, many containers | 2 pulls + 4 commands, ~3 min for DB + CLI (seen); 5 containers with UI |

## 4. Where each tool is likely better or weaker than a "scan + probe + diff" product

nmap + ndiff
- Better: service/version database for non-HTTP protocols (exact OpenSSH and Redis versions, CPEs), mature host discovery, NSE library, XML that everything else imports (DefectDojo, IVRE); fastest full pass here (15 s).
- Weaker: nothing above the HTTP header level (no CMS, panel, camera); ndiff is a two-file comparison without state (no returned/inactive, no thresholds), is noisy on volatile fields and crashed on multi-script XML in three versions; no storage, roles, schedule or annotations.

naabu + httpx + nuclei
- Better: the richest HTTP probe in one pass (status, title, headers, redirect chain, TLS with SANs, self-signed flag and SHA-256, technology with versions); nuclei's template library found WordPress login, version and end-of-life, Drupal, PHP end-of-life without any custom work, and custom signatures are simple YAML; JSONL/CSV everywhere; DefectDojo reads nuclei output.
- Weaker: three tools glued by the user, no service names for non-HTTP ports, no comparison of runs, no state, roles or schedule in the open-source CLIs; lab-specific things (custom admin panel, staging header, NETCAM) need own templates; one systematic false positive (waf-detect); the template pass is slow and sends thousands of requests per URL (492 s at 50 req/s for 10 URLs).

WhatWeb
- Better: good web fingerprint per URL with almost no setup; names cookies and their flags, follows redirects hop by hop, WordPress and PHP versions right; large plugin set (d).
- Weaker: missed Drupal when only the X-Generator header gives it away; no TLS data, no port discovery, no diff, no state; aggression level 3 took 86 s for 10 URLs.

IVRE (partial run)
- Better: real asset database with history, passive sources (Zeek, p0f), imports from nmap, masscan, nuclei, httpx, fast "top values" queries, JSON/CSV export, web UI (d).
- Weaker: no report of what changed between scans, no host status model, no roles of its own, no analyst notes (d); detection quality is whatever the imported tool delivered.

secureCodeBox (d, not run)
- Better: orchestration of many scanners with schedules, cascading scans and an official DefectDojo hook; fits teams that already run Kubernetes.
- Weaker: Kubernetes is mandatory; no asset inventory or diff of its own; change tracking and analyst workflow live in DefectDojo.

reNgine (d, not run)
- Better: web UI with roles, periodic scans, notes/todos, notifications about new or removed subdomains and endpoints, PDF reports, custom nuclei templates.
- Weaker: built around domains and subdomains rather than IP ranges; heavy stack; no flap handling, time windows or DefectDojo integration documented.

Caveats: one lab, one run per stage, all services are nginx behind fake banners, so real-world fingerprinting spread is not measured.
WhatWeb's host/port numbers depend on httpx. The (d) cells were not re-verified beyond the secureCodeBox install guide, the reNgine README
and the IVRE overview page read today.
