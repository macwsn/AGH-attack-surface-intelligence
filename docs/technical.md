# Technical documentation

How ASI is built and how it behaves. Operating it is covered in [operations.md](operations.md), signatures in
[signatures.md](signatures.md). The fixed formats (command line, export, diff, signatures) are in
[contracts.md](contracts.md); the per-capability behaviour with test scenarios is in `specs/*.md`.

## Architecture

One Go module (`asi`), one binary (`cmd/asi`). `asi serve` runs the web UI, the scheduler and the scan workers in one
process; the other commands (`scan run`, `export`, `diff`, `import`, ...) use the same packages directly against the
database, so a scan started from the command line and one started by the scheduler go through the same code.

- PostgreSQL 17 through `pgx/v5`, plain SQL, migrations embedded in the binary.
- The UI is rendered on the server (`html/template`), with htmx and one CSS file embedded in the binary. No external
  resources are loaded at runtime.
- The only external program is `nmap`. It sits behind the interface `nmap.Runner`, so unit tests use recorded XML and
  never scan anything.

| Package | Responsibility |
|---|---|
| `cmd/asi` | command line parsing, wiring of the packages below |
| `internal/config` | configuration from environment variables |
| `internal/targets` | parse targets and excludes, resolve names, expand and count addresses |
| `internal/scan` | one run: groups, worker pool, rate limiter, adaptive rate, group timeout, pause and resume, heartbeat, re-probe, progress, plan preview, work ceiling |
| `internal/scan/nmap` | nmap command lines, the light probe file, XML parsing |
| `internal/probe` | HTTP/HTTPS probe: status, title, headers, cookies, redirects, TLS, favicon hashes, timing |
| `internal/detect` | built-in technology rules, notable headers and cookies, staging detection, the embedded fingerprint dataset and heuristics, technologies from nmap, the version table, the signature engine, the built-in pack, stored signatures, the guided signature form |
| `internal/inventory` | runs, hosts, services, observations; status and stability; availability profile; interest score; time-of-day pattern; service groups; retro-hunt; learned volatile fields; deletion; the host summary used by the host list |
| `internal/diff` | changes between two states, volatile-value rules, change counts |
| `internal/schedule` | scan definitions, windows, frequency, rechecks, the scheduler loop |
| `internal/exchange` | JSON and CSV import and export, manual entry |
| `internal/exchange/defectdojo` | DefectDojo settings, payloads and client |
| `internal/auth` | users, passwords, sessions, roles and permissions, login rate limit, audit log |
| `internal/store` | connection pool, migrations, field encryption, key check and rotation |
| `internal/web` | routes, pages, templates, static files |

## Data model

Migrations live in `internal/store/migrations/` and are applied by `asi migrate` in file-name order, in one
transaction under an advisory lock; each is recorded in `schema_migrations` under its file name without `.sql`. Two
files share the number 0005 (`0005_scan_definitions.sql` and `0005_signatures.sql`); because the version is the whole
name they are two separate entries and both are applied, `0005_scan_definitions` first. Do not rename either: a
renamed file would be applied again.

| Table | Holds |
|---|---|
| `runs` | one row per scan run, import or manual entry: unique name, `inactive_after`, status (`running`, `paused`, `completed`, `failed`), source (`scan`, `import`, `manual`), a copy of the settings and schedule it was started with, its targets and excludes (`scope`, encrypted), the scan definition it belongs to and whether that was deleted (`definition_deleted`), `held` (paused by a user), `address_total`, `packets`, `ports`, `heartbeat_at` |
| `run_groups` | one row per recorded group of a run: address count, hosts found, duration, completion time |
| `run_group_addresses` | the addresses each recorded group covered, and for a recheck the ports it covered (`ports`, NULL for all). This is what "the run covered this address" means |
| `run_failed_groups` | groups given up after a timeout, with their addresses and the reason |
| `run_rate_samples` | per run and minute: measured HTTP requests (`sent`), estimated nmap packets (`estimated_packets`), the rate in effect |
| `hosts` | one row per address ever seen, plus the user-owned fields: tags, notes, display name, owner, criticality, status override |
| `services` | one row per (host, port, protocol) ever seen |
| `host_observations` | a host seen in a run, with the hostnames known then |
| `service_observations` | a service seen in a run: state, service, product, version, the HTTP document (status, title, URL, redirect chain, TLS, favicon hashes, timing, error), and separately the headers, cookies, body excerpt and the learned field state |
| `technologies` | technologies of a service observation: name, category, version, confidence, source |
| `findings` | matches of a service observation: signature id, kind, name, version, confidence, evidence, source |
| `host_summary` | derived, one row per host: status, missed runs, stability, interest score, ports, service names, technologies, finding kinds, titles. Rewritten when a group is recorded; the host list reads only this table |
| `scan_definitions` | named scans: enabled flag, targets and excludes (`scope`, encrypted), settings (ports, rate, workers, signatures directory, volatile headers, recheck interval), schedule (timezone, windows, frequency), `last_run_at` |
| `signatures` | signatures stored through the UI: id, name, kind, YAML source (encrypted), enabled flag, who changed it last |
| `builtin_signatures` | which signatures of the built-in pack were switched off or on again, and by whom |
| `hunts`, `hunt_results` | retro-hunts and their per-service results |
| `users`, `roles`, `permissions`, `role_permissions`, `sessions` | accounts (with a `disabled` flag), role definitions, server-side sessions (only the SHA-256 of the session token and of the CSRF token are stored) |
| `audit_log` | time, actor, action, target, client address |
| `settings` | encrypted key/value settings; today only the DefectDojo connection |
| `encryption_keys_in_use` | which key ids hold values in which encrypted table, kept by triggers; read by the key check at start |

Current state is never stored as such. It is derived from the observations up to a chosen run, which is why
`asi export --run NAME` and `asi diff` can answer for any past run.

## Scan pipeline

1. **Targets.** Targets and excludes are parsed (`internal/targets`): IPv4 address, CIDR, last-octet range
   (`10.0.0.5-20`), domain or host name. Names are resolved to their IPv4 addresses; the host is recorded under the
   address and keeps the name, which is also sent as `Host` header and TLS SNI. Excludes are removed from the
   expanded set. IPv6 targets are not accepted.
2. **Work ceiling.** Before a run exists its settings and signatures are checked. Addresses × ports above
   `scan.DefaultMaxWork` (262 144 000) are refused for command-line runs, scan definitions, **Start scan now** and
   scheduled starts; `asi scan run` also refuses more than `--max-addresses` (default 262 144) addresses. Both
   messages name the counts.
3. **Groups.** The addresses are split into groups. The size starts at 64 and is recomputed from the seconds per
   address of the last 4 groups whenever the expected time of a group leaves 30 to 60 s, aiming at 45 s; it stays
   between 16 and 1024 (`scan.InitialGroupSize`, `MinGroupSize`, `MaxGroupSize`). `--workers` groups are scanned at
   the same time (default 4).
4. **Host discovery** per group: `nmap -sn -PE -PS<ports> --max-rate R -n -oX -` (ICMP echo plus a TCP SYN to the
   configured ports, so hosts that drop ICMP are still found). No `-T` timing template and no `--host-timeout` are
   passed.
5. **Service detection**, first pass, on the hosts found up:
   `nmap -Pn -sT -sV --version-light --versiondb <file> -p <ports> --max-rate R -n -oX -`. The file is a temporary
   copy of nmap's `nmap-service-probes` in which soft matches (except `ssl`) are final, so a Go HTTP server that nmap
   soft-matches does not cost 17 more probes of 5 s each. Anything nmap reports outside the port list, not `open`, or
   for an address outside the group is dropped. Ports on the never-probe list (step 8) are left out of this call and
   scanned with `nmap -Pn -sT -p <ports>` without `-sV`, so they receive a TCP connect and nothing else.
   A port whose result came from a soft match that stock nmap would not have taken as final is marked and checked
   again in step 6, so the converted probe file does not identify less than stock nmap.
6. **Second pass** (`--service-detection standard`, the default): ports still unidentified (no service, `unknown`,
   `tcpwrapped`, a name only guessed from the port table), ports whose banner needs it (ftp, ssh, smtp, pop3 or imap
   without a product, generic AMQP) and the soft-matched ports of step 5 get one more `nmap -Pn -sT -sV -p <those
   ports>` at nmap's default intensity with the same rate. With `light`, only the soft-matched ports get a second
   call, with `--version-light` and nmap's own probe file. A result replaces the first one unless it is unidentified
   too. The second pass is one nmap call per group with `--host-timeout` of 20 s per port, at most 90 s per host,
   and fewer retries, so a host that accepts connections and never answers cannot stall the run; hosts cut off this
   way get a scan note on the run.
7. **HTTP probe** of every open port whose service name contains `http` or that speaks TLS. A port nmap could not
   identify is tried over HTTP and then over TLS (TLS only when nmap saw a TLS tunnel), each try limited to
   `min(--http-timeout, 3 s)`; when one answers, the service is renamed `http` or `https`. The probe fetches `/`,
   follows up to 5 redirects on the same host and port, fetches `/favicon.ico` (a second time when its hash differs
   from the previous run, to tell a changed favicon from one that changes on every request), and records status code,
   title, headers, cookie names and flags, the redirect chain, the TLS certificate, favicon SHA-256 and MurmurHash3,
   time to first byte and total response time. Every request has a deadline (`--http-timeout`, default 10 s). A port
   whose probe does not complete is recorded as open with `http.error` `timeout`, `tls handshake failed` or
   `request failed`. A host with 3 timeouts in a row is paused; its remaining ports are tried once more at the end of
   the group and then recorded with `timeout`.
8. **Ports that are never probed.** Industrial and printing protocols can misbehave when they receive an HTTP
   request or a service probe (`neverProbeServices`, `neverProbePorts`, `neverProbeTablePorts` in
   `internal/scan/scan.go`).
   - By port: 102, 502, 515, 789, 1883, 1911, 1962, 2222, 2404, 4840, 4911, 5007, 8883, 9100-9107, 9600, 18245,
     18246, 20000, 20547, 34962-34964, 44818, 47808. These get only the TCP connect of step 5: no nmap service
     probe, no second pass, no HTTP request. The service is recorded open with the finding
     `builtin-not-probed-by-policy` (kind `custom`, confidence 100).
   - By service name, as nmap's light pass named them on another port: modbus, mbap, s7comm, iso-tsap, bacnet, dnp,
     dnp3, iec-104, iec-60870-5-104, enip, ethernetip (and -1, -2), opc-ua, opcua, opcua-tcp, fins, omron-fins, mqtt,
     secure-mqtt, jetdirect, pdl-datastream, printer. These got the light pass but get no second pass and no HTTP
     request.
   - Port 2222 is on the list (EtherNet/IP), so an SSH or web server moved there is not identified.
9. **Detection.** See [Detection sources](#detection-sources-and-confidence).
10. **Recording.** One group is written in one transaction (`inventory.RecordGroup`): the covered addresses, host and
    service observations, technologies, findings, learned field state. A worker does not take the next group before
    the write returns, so a slow database slows the scan instead of filling memory. When the database does not
    answer, the write is retried for up to 60 s (1 s, doubling to 10 s); after that the run is marked `paused`.
11. **Re-probe.** After the last group, addresses that were `active` or `unstable` in the previous run (the run with
    the next lower id, of any definition) and were not found in this one are scanned once more, unless they were in
    a failed group or are outside the targets. Only then do they count as missed.
12. **Status.** The run ends `completed`; a cancelled run (window end, user pause, SIGINT/SIGTERM, database outage)
    ends `paused`; another error ends it `failed`. While it runs, the process writes a heartbeat every 5 s; a
    `running` run whose heartbeat is older than 60 s is shown as `stalled (process gone)`. Resuming a `paused`,
    `failed` or stalled run continues with the addresses that no recorded group covers.

A group that takes longer than 10 minutes (`scan.DefaultGroupTimeout`) is cancelled, split in half and each half is
tried once more; a half that times out again, or a group of which nmap scanned none of the targets, is stored in
`run_failed_groups` and the run goes on. Addresses of failed groups are not covered by the run, so their hosts are not
counted as missed; they are not retried on resume.

nmap runs in its own process group. When ASI cancels a call (timeout, pause, Ctrl-C) the whole group gets SIGKILL.
When the `asi` process itself is killed with `kill -9`, nothing is left to cancel it: the running nmap calls continue
until they finish their group or fail writing to the closed pipe. With the default group size that is about a minute
at most (group durations in [requirements-coverage.md](requirements-coverage.md#scheduling-check) are 15 to 61 s;
this was not measured after a kill), but ASI enforces no limit; check with `ps` for leftover `nmap` processes before
restarting a large scan.

### What nmap sends

The rule "GET and HEAD only, no payloads" applies to ASI's own HTTP probe and to signatures. nmap's service
detection (`-sV`) sends nmap's own probes from `nmap-service-probes`: the light set in the first pass and the default
set (intensity 7) in the second. Those include protocol greetings and requests for other protocols (for example a
TLS hello, SMB, RPC or SIP probes) on unidentified ports. Use `--service-detection light` to keep to the light set,
and keep fragile devices on the exclude list. Ports on the never-probe list get no nmap probe at all, only the TCP
connect. Web ports are not exempt: when a web port is left unidentified, nmap's stock service pass sends its own
probes to it as well.

### Rechecks

A `recheck` run (`--mode recheck`, **Start recheck**, or the "Recheck every" interval of a definition) contacts only
the tcp services that were `active` or `unstable` in its base run: the latest completed run of the same definition,
otherwise the latest completed run with the same targets and excludes. Without such a run it fails with
`no earlier run to recheck` and creates no run. It still sends host discovery (`-sn -PE -PS<known ports>`) and the
service passes, but only to the known addresses and ports, and records per address the ports it covered, so
uncontacted hosts and services keep their state. Only known HTTP services are HTTP-probed.

A recheck saves packets on a sparse range (`TestRecheckLabPacketSaving`: at most 10% of a full run's packets on the
lab). Hosts with different sets of known ports are scanned in parallel calls, bounded by the run's nmap slots, so a
recheck of a sparse range is not slower than the full run (8.3 s against 18.4 s in the test scenario of a /24 with
8 live hosts). It is not faster on a single host: the time is spent in the same per-host nmap passes and HTTP
probes as in a full run.

The scheduler starts a recheck when the definition has a recheck interval, no full run is due and the interval has
passed since the last run of any mode. It rechecks only hosts of its own targets, puts hosts usually up at this hour
first and skips a periodic host in an hour it is usually down unless it was last seen more than 24 h ago.

### Rate limit and adaptive rate

`--max-rate` is one limit in packets and requests per second for the whole run. nmap gets half (rounded down),
divided between the nmap calls that run at the same time (each call gets `--max-rate max(half/slots, 1)`); the HTTP
probe gets the other half as a token bucket. At most 2 ports per host and 8 hosts per group are probed at once.

Unless `--no-adaptive` is given, the probe watches the latency of its last 20 requests. When the median is more than
twice the median of the first 20, or more than 10% time out, the rate is halved (not below
`min(max(ceil(rate/10), 2 × nmap slots), rate)`); otherwise it rises by a tenth up to the limit. Changes are at least
5 s apart.

What the run page and `asi scan show` report as the sent rate is not one measurement:

- HTTP requests are **counted** when the limiter releases them (`requests_measured`, "HTTP requests ... measured");
- nmap packets are **estimated**, not counted: `addresses × (1 + ports)` for discovery and `addresses × ports` per
  service pass, spread evenly over the minutes the call took (`nmap_packets_estimated`, "nmap packets ...
  estimated"). nmap's retransmissions and version probes are not in the estimate.

`runs.packets` is the sum of both and is written when the run ends. `asi scan plan` uses a different, worst-case
estimate (2 discovery tries and 10 probes per port), so plan and run figures are not comparable.

## Detection sources and confidence

Detection runs on every recorded service, from a scan, an import or a manual entry. Confidence is 0-100.

| Source | What | Confidence |
|---|---|---|
| built-in rules (`internal/detect/detect.go`, source `builtin`) | nginx, Apache from `Server`; PHP from `X-Powered-By` or `Server`; WordPress, Drupal, Joomla from the generator tag, product headers, body paths and cookies | 95 generator tag, 90 `Server`/`X-Powered-By`/`X-Generator`, 80 product-only header (`X-Drupal-Cache`, WordPress REST `Link`), 70 body path, 60 cookie (`PHPSESSID`, `wordpress_*`); Joomla body path 60 |
| technologies from nmap (`internal/detect/services.go`) | vsftpd, ProFTPD, Pure-FTPd, OpenSSH, Redis, PostgreSQL, MariaDB, MySQL, ActiveMQ, RabbitMQ, nginx, Apache Tomcat, Apache from nmap's product and version | 80; 60 when nmap gives only a bound (`or later`, `x.*`) |
| built-in signature pack (`internal/detect/pack/*.yaml`, 54 signatures, ids `builtin-*`) | products, admin interfaces and devices | 95, 90 or 85 by evidence; 70 for the generic admin login page |
| notable headers (`internal/detect/notable.go`, `builtin-header-*`) | `X-Powered-By`, `X-Generator` and `Server` with a version, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Environment`, `X-Backend-Server`, `X-Served-By`, `X-Debug-Token` and `X-Debug-Token-Link` (value redacted), `Via` with an internal name | 80 |
| notable cookies (`builtin-cookie-*`) | a session cookie that names the stack (also adds the technology at 40), a session cookie without `HttpOnly`, without `Secure` on HTTPS | 60, 70, 70 |
| login form (`builtin-login-form`, kind `admin-panel`) | a form with a password input, only when no other admin panel finding matched | 50 |
| staging (`builtin-staging-*`) | `X-Environment`, `X-Env` or `X-Stage` starting with staging, stage, test, dev, uat, preprod or sandbox; such a word in the host name; `[staging]`-style marker or bare word in the title | 75 header, 65 host name, 70 title marker, 60 title word |
| version table (`internal/detect/outdated.yaml`, `outdated-<product>`) | a detected version below the supported minimum: WordPress 6.0, PHP 8.1, nginx 1.24, Apache 2.4.52, OpenSSH 8.9, vsftpd 3.0.3, ProFTPD 1.3.7, Pure-FTPd 1.0.50, MySQL 8.0, phpMyAdmin 5.2, Apache Tomcat 9.0, Jenkins 2.580, Grafana 11.6, Elasticsearch 8.19, Redis 6.0, ActiveMQ 5.18, Joomla 5.4, Drupal 10.5, Gitea 1.22 | that of the technology it judged |
| fingerprint dataset (source `wappalyzer`) | the public Wappalyzer fingerprints embedded through `github.com/projectdiscovery/wappalyzergo` v0.3.10 (about 7 700 applications), matched on headers, cookies (names only), HTML, script sources, inline scripts and meta tags of the responses already fetched; no extra request. A few generic entries are skipped (Basic, HSTS, Open Graph, HTTP/3, PWA, RSS, Priority Hints, Cart Functionality) and some names are aligned with ASI's (Apache, nginx, ASP.NET, Synology DSM) | 60 |
| heuristics (source `heuristic`, finding ids `builtin-heuristic-generator`, `-title`, `-header`) | a product named by `<meta name="generator">`, by an installer, login or panel title, by an `X-<name>-Version` header or a `Server`/`X-Powered-By` token with a version; names made only of generic words are ignored, and a heuristic is dropped when another source already names the product (it may add the version) | 40 |
| generic admin findings | `builtin-unfinished-installation` (an installer page), `builtin-management-interface`, `builtin-login-form` | 50 |
| policy finding | `builtin-not-probed-by-policy` on ports of the never-probe list | 100 |
| own signatures (database, `ASI_SIGNATURES_DIR`, `--signatures-dir`) | anything, in the format of [signatures.md](signatures.md) | as written by the author |

- Notable headers, cookies, the login form, staging detection, the fingerprint dataset and the heuristics run only
  while at least one signature of the built-in pack is enabled; there is no separate switch.
- The dataset is MIT-licensed code by ProjectDiscovery; its fingerprints are compiled from the webappanalyzer and
  HTTP Archive Wappalyzer projects. `NOTICE` in the repository root gives the details. Its own confidence values are
  not used; every match gets 60. A version is kept only when it starts with a digit.
- When several sources name the same technology, the entry with the highest confidence wins and takes the most
  specific version any of them found (`detect.Merge`). Built-in rules, the dataset and heuristics join entries of
  the same name from any source; an own signature and a pack signature of the same product stay separate entries.
- Imported and manually entered services get the same detection on the stored response for `/`, without sending a
  request. An import holds no page body, so body rules, `body_regex` signatures and the login form do not fire on
  imported data, and signatures with a `request.path` other than `/` are skipped; the fingerprint dataset sees only
  headers and cookies there.

**Reported confidence.** The stored value is the one detected. Where it is reported (`asi export`, `/export`, the
host page) a technology's `confidence` is `round(detected × host stability)` and the detected value is in
`confidence_raw`; a technology on a host seen in 5 of its last 10 covering runs reports half its confidence. Findings
keep their detected confidence.

## How changes are computed

`diff.Compute(from, to)` compares two derived states (the state as of run `from` and as of run `to`). `asi diff`,
`/changes`, `/changes.json`, the dashboard and the import report all use it.

| Type | Condition |
|---|---|
| `host_new` | the address is absent in `from` |
| `host_missing` | `active` in `from`, `unstable` in `to` |
| `host_inactive` | not `inactive` in `from`, `inactive` in `to` |
| `host_returned` | `unstable` or `inactive` in `from`, `active` in `to` |
| `service_new`, `service_missing`, `service_inactive`, `service_returned` | the same rules per (port, protocol), only for hosts without a host-level change |
| `service_changed` | the service is `active` in both and a compared field differs; every differing field is listed with old and new value |

Compared fields: `service`, `product`, `version`, `http.status_code`, `http.title`, `http.headers.<name>`,
`http.cookies` (set of names), `http.redirect_chain`, `http.tls.sha256`, `http.favicon_sha256`, `technologies`
(set of name and version), `findings` (set of signature ids).

Never reported:

- the headers `date`, `expires`, `last-modified`, `etag`, `age`, `set-cookie`, `content-length`, `x-request-id`,
  `cf-ray` (`inventory.DefaultVolatileHeaders`), the headers in `ASI_VOLATILE_HEADERS` and those in "Volatile
  headers" of the run's scan definition;
- parts of header values that differ per request: CSP nonces and hashes, UUIDs, timestamps, long token-like strings
  are replaced by a placeholder before comparing;
- a field learned as volatile: a field that changed in 3 consecutive compared runs of a service stops being
  reported, and the host page and the export (`volatile`) list it with its last 3 values. It is reported again when
  it changes after having stayed the same for 3 runs;
- the favicon when it differed between two fetches in the same run (`http.favicon_unstable`);
- cookie values and flags; TLS dates of the same certificate; response times; the interest score.

When either side has `http.error` (timeout, failed TLS handshake, failed request), only `product` and `version` are
compared, so a probe that failed once does not flap the service name or the HTTP fields. A scan diff skips hosts that
no scan ever covered. The output is sorted by address, port, protocol and type, so equal inputs give identical bytes.

## Status model

Status is derived per host and per service from the **covering runs**: runs whose recorded groups contain the
address, starting with the first run that saw it. A run that did not scan the address (other targets, an unfinished
or failed group, an import of other hosts) is ignored, it is not a miss.

| Status | Meaning |
|---|---|
| `active` | seen in the latest covering run |
| `unstable` | missed in 1 to N-1 consecutive covering runs |
| `inactive` | missed in N or more consecutive covering runs |

`missed_runs` is that count and `stability` is the share of the last 10 covering runs in which it was seen
(`inventory.DeriveStatus`, `inventory.StabilityWindow`). The status override a user can set is stored and exported
as `status_override`; it is shown next to the derived status and does not replace it.

**Availability profile.** Each host has 24 hour-of-day buckets in the timezone of the run's scan definition (UTC
without one), each an exponentially weighted average of seen and missed over the covering scan runs, starting at 0.5.
With at least 6 samples, one bucket at 0.8 or more and one at 0.2 or less, the host is periodic. A periodic host
missed in an hour it is usually down keeps its status, missed runs and stability; only the profile is updated. A
miss in an hour it is usually up gives `host_missing` the note `expected up at this hour`. Imports and manual entries
are not samples. The profile is shown on `/hosts/{address}/availability` and exported as `availability`.

## The three open questions of the challenge

### How is a change reported for a host that answers at some times of day and not others?

- The first run that misses it reports `host_missing` and the host becomes `unstable`. Before that, the run re-probes
  it once at its end, so a short outage during the scan does not produce a change.
- While it stays missed below the threshold nothing more is reported (`unstable` in both runs yields no change).
  When it answers again, `host_returned` is reported. If it stays away for N covering runs, `host_inactive`.
  Its services are not listed one by one: a host-level change suppresses the service-level changes of that host.
- Once its availability profile shows it as periodic (6 covering scan runs), a miss in an hour it is usually down
  is not counted and produces no change; a miss in an hour it is usually up is reported with the note
  `expected up at this hour`.
- The host timeline (`/hosts/{address}/timeline`) also shows the label `Usually seen HH:00-HH:00` (UTC) after six
  covering runs in which the host was both seen and missed, and a presence strip of the last 50 runs.
- Rechecks of a definition skip a periodic host in an hour it is usually down, unless it has not been seen for 24 h.

### How is the confidence of a technology identification determined?

Each source gives a fixed confidence per kind of evidence, listed in
[Detection sources](#detection-sources-and-confidence); a signature's author sets it in the signature. The detected
value is stored. When it is reported, a technology's confidence is multiplied by the host's stability
(`confidence_raw` keeps the detected value), so a technology on a host that answers only half the time reports half
the confidence. An `outdated` finding takes the confidence of the technology whose version it judged.

### After how many missed scans is a host reported inactive?

After **3** consecutive missed covering runs by default (`inventory.DefaultInactiveAfter`). After 1 and 2 it is
`unstable`. The threshold belongs to the run:

- command line: `asi scan run --inactive-after N` and `asi import --inactive-after N`;
- UI: the field "Inactive after" of a scan definition.

The status as of a run is always computed with that run's threshold. Services follow the same rule on their own
count, so a port that closes on a live host becomes `unstable` and then `inactive` while the host stays `active`.

## Interest score

`inventory.Score` gives every host 0-100 points and the reasons, shown on the dashboard ("Top hosts by interest"),
the host list and the timeline. Each reason counts once per host; inactive services are skipped.

| Reason | Code | Default points |
|---|---|---|
| admin panel finding | `admin-panel` | 30 |
| IoT finding | `iot` | 25 |
| staging finding | `staging` | 20 |
| first seen in this run | `new` | 20 |
| outdated version (an `outdated` finding, or a version below the minimum of `outdated.yaml`) | `outdated` | 15 |
| notable header finding | `interesting-header` | 10 |
| notable cookie finding | `interesting-cookie` | 10 |
| first seen within the last 7 days | `recent` | 10 |
| self-signed certificate | `self-signed` | 10 |
| certificate expired or expiring within 30 days | `expiring-cert` | 10 |

The weights can be changed with `ASI_INTEREST_WEIGHTS` (see [operations.md](operations.md#environment-variables)).

## Security model

- **Accounts.** Local users only. Passwords are stored as argon2id hashes and need at least 12 characters. A failed
  login reads the same for a wrong password and an unknown user. Users can be disabled; disabling, deleting or
  resetting the password of a user ends that user's sessions, and changing one's own password ends one's other
  sessions.
- **Login rate limit.** 5 failed logins per username or 20 per client address within 15 minutes block further
  attempts (HTTP 429). The counters are kept in memory of the `asi serve` process. The client address is the TCP
  peer: behind a reverse proxy every user has the proxy's address, so 20 failures there block everyone for 15
  minutes, and the audit log shows the proxy's address.
- **Sessions.** Server-side, in PostgreSQL; the cookie `asi_session` is `HttpOnly`, `SameSite=Lax`, and `Secure`
  when the request arrived over TLS. Sessions end after 30 minutes without use and after 12 hours in any case.
  Permissions are read again on every request, so a role change applies at once.
- **CSRF.** Every state-changing request needs the session's token (form field `csrf_token` or header
  `X-CSRF-Token`); for an upload the field comes before the first file part. Every form works as a plain browser
  form without JavaScript. The token is derived from the session cookie and stored only as a hash. The login form
  has its own token.
- **Headers.** Every response carries a Content-Security-Policy without inline scripts or external sources,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: same-origin`.
- **Output.** Everything that comes from a scan, a signature or a user is HTML-escaped by the templates. CSV export
  prefixes cells that start with `=`, `+`, `-`, `@`, tab or CR with `'`.
- **Uploads.** Import files are limited to 20 MiB, parsed in memory and never written to disk.
- **Audit log.** Written to `audit_log` with actor and client address and shown on `/audit` (filters actor, action,
  target, from, to; 50 rows a page). Actions: `login`, `login_failed`, `logout`; `user.create`, `user.update` (role
  change), `user.password`, `user.disable`, `user.enable`, `user.delete`; `role.create`, `role.update`,
  `role.delete`; `host.edit`, `host.delete`, `service.delete`, `host.entry`, `import`; `scan.create`, `scan.update`,
  `scan.enable`, `scan.disable`, `scan.start`, `scan.pause`, `scan.resume`, `scan.delete`; `signature.create`, `signature.update`,
  `signature.enable`, `signature.disable`, `signature.delete`, `signature.import`, `signature.hunt`,
  `signature.hunt.record`; `defectdojo.configure`, `defectdojo.export`. Command-line actions are recorded with actor
  `cli` and address `local` (`user create`, `user set-role`, `user delete`, `import`, `host edit`,
  `signature hunt`, `defectdojo configure`, `defectdojo export`). `asi scan run`, `asi scan resume` and
  `asi key rotate` are not recorded.
- **Transport.** `asi serve` speaks plain HTTP. Put a TLS-terminating reverse proxy in front of it for anything but
  localhost.

### RBAC matrix

Permissions are fixed strings (`internal/auth/auth.go`); a role is a named set of them. The four built-in roles are
created by migration `0003_auth.sql` and cannot be changed or deleted. Every user has exactly one role. Custom roles
are created, changed and deleted on `/roles`; a role that is still assigned cannot be deleted.

| Permission | admin | editor | operator | viewer |
|---|---|---|---|---|
| `inventory.read` | yes | yes | yes | yes |
| `inventory.edit` | yes | yes | yes | - |
| `inventory.create` | yes | yes | - | - |
| `inventory.delete` | yes | yes | - | - |
| `scan.run` | yes | yes | - | - |
| `scan.configure` | yes | - | - | - |
| `signature.manage` | yes | yes | - | - |
| `export` | yes | yes | yes | - |
| `import` | yes | yes | - | - |
| `user.manage` | yes | - | - | - |
| `role.manage` | yes | - | - | - |

These map to the roles the challenge asks for: administration (`admin`), add/delete/modify (`editor`), modify and
read (`operator`), read only (`viewer`).

Assigning a role requires holding every permission of that role, nobody can change their own role, and user
actions (password reset, disable, delete, role change) apply only to users whose role the actor fully holds; one's
own account is changed only on `/account`. The dashboard shows no inventory data to a role without
`inventory.read`; signature test and hunt need `inventory.read`, the hunt CSV needs `export`. Before these rules,
`user.manage` and `role.manage` were effectively admin-level. The last full administrator (a user holding every
permission) cannot be deleted, demoted or disabled.

Every route is registered with the access it needs, and `asi serve` refuses to start when a route has none
(`web.Router.Handle`).

| Route | Needs |
|---|---|
| `GET /login`, `POST /login`, `GET /healthz`, `GET /static/{name}` | nothing (public) |
| `GET /` (dashboard), `POST /logout`, `GET /account`, `POST /account/password` | a session |
| `GET /hosts/`, `GET /hosts/{address}`, `GET /hosts/{address}/timeline`, `GET /hosts/{address}/availability` | `inventory.read` |
| `GET /changes`, `GET /changes.json`, `GET /groups`, `GET /runs/{id}` | `inventory.read` |
| `POST /hosts/{address}` (edit tags, notes, owner, ...) | `inventory.edit` |
| `GET`/`POST /hosts/entry` (add a host by hand; editing an existing one also needs `inventory.edit`) | `inventory.create` |
| `GET`/`POST /hosts/{address}/delete`, `GET`/`POST /hosts/{address}/services/{port}/{protocol}/delete` | `inventory.delete` |
| `GET /scans`, `GET /scans/{id}`, `GET /scans/{id}/preview`, `POST /scans/{id}/start`, `GET /runs`, `POST /runs/{id}/pause`, `POST /runs/{id}/resume` | `scan.run` |
| `GET /scans/new`, `POST /scans`, `POST /scans/plan`, `POST /scans/schedule-summary`, `POST /scans/custom-ports`, `GET /scans/{id}/edit`, `POST /scans/{id}`, `POST /scans/{id}/enable`, `POST /scans/{id}/disable`, `GET`/`POST /scans/{id}/delete` | `scan.configure` |
| `POST /scans/quick` (create and start a scan in one step) | `scan.configure` and `scan.run` |
| every `/signatures...` route, including the guided form (`POST /signatures/form`), test, hunt, import and export | `signature.manage` |
| `GET`/`POST /import`, `GET /import/sample.csv`, `GET /import/sample.json` | `import` |
| `GET /export`, `GET /export.json`, `GET /export.csv` | `export` |
| `GET /defectdojo`, `POST /defectdojo/test`, `POST /defectdojo/export` | `export` |
| `POST /defectdojo/settings` | `scan.configure` |
| `GET /users/`, `POST /users/create`, `POST /users/{u}/role`, `/password`, `/disable`, `/enable`, `GET`/`POST /users/{u}/delete`, `GET /audit` | `user.manage` |
| `GET /roles`, `POST /roles/create`, `POST /roles/{name}`, `GET`/`POST /roles/{name}/delete` | `role.manage` |

The navigation shows only the entries the signed-in role may open, in groups; a group with nothing to show has no
heading:

| Group | Entries |
|---|---|
| Overview | Dashboard, Changes |
| Inventory | Hosts, Groups |
| Scanning | Scans (also the run pages), Signatures |
| Data | Import, Export, DefectDojo |
| Administration | Users, Roles, Audit log |

The current page is marked in the navigation. A request without the permission gets a 403 page. The user name in the page header links to `/account`, where every signed-in user can
change their own password: it needs the current password (failures count against the login rate limit and are
logged as `login_failed`), the new one must differ and have at least 12 characters, and the user's other sessions
end. An administrator resets other users' passwords on `/users/`.

### Encryption at rest

Sensitive values are encrypted by the application before they reach PostgreSQL (`internal/store/crypt.go`).
Encrypted columns: `findings.evidence`, `hunt_results.evidence`, `hunts.source`, `hosts.notes`,
`hosts.display_name`, `hosts.owner`, `runs.scope` and `scan_definitions.scope` (targets and excludes),
`service_observations.http_headers`, `http_cookies`, `http_body` (first 64 KiB of the root page, kept for the newest
10 observations of a service, `ASI_BODY_RETENTION_RUNS`) and `field_state`, `settings.value` (the DefectDojo
connection including the API token), `signatures.source`. Every column of the schema is listed in
[Protection of every column](#protection-of-every-column) as encrypted, hashed or plain.

- Algorithm: AES-256-GCM with a random 96-bit nonce per value.
- Key derivation: `ASI_MASTER_KEY` (32 random bytes, base64) is the input of HKDF-SHA-256; one derived key encrypts,
  a second derivation gives an 8-byte key id.
- Stored format: version byte, key id, nonce, ciphertext; version and key id are authenticated.
- Older keys: `ASI_MASTER_KEY_PREVIOUS` lists keys that may still hold data; they are used only to read. New values
  are always written with `ASI_MASTER_KEY`. `asi key rotate` re-encrypts every value under an older key id;
  `asi key status` shows how many rows are left per table.
- Key check: `encryption_keys_in_use` records which key ids hold values in each table. At start, `asi serve` and every
  inventory command check it against the configured keys and refuse to run when a table holds values under a key
  that is neither `ASI_MASTER_KEY` nor in `ASI_MASTER_KEY_PREVIOUS`, naming the table and the key id. A value read
  with an unknown key fails closed with `field encryption: unknown key id`.
- Columns used for searching, sorting and diffs (addresses, ports, titles, product and technology names, versions,
  tags, the HTTP document without headers, cookies and body) are not encrypted. Use an encrypted volume for the
  PostgreSQL data directory as well.
- The display name is encrypted although the host list searches and sorts by it: the list decrypts the display names
  (one small value per named host) and passes the matching host ids and the sort order to the query.
- Upgrading: migration `0020` turns the owner, display name, scan targets and excludes and the sources of stored
  signatures and retro-hunts of an existing database into values marked as pending. `asi migrate` encrypts every
  pending value with `ASI_MASTER_KEY` after the migrations and prints `field encryption: encrypted N stored values`;
  `asi serve` does the same at start and only logs a failure. Values are encrypted only after the key check confirmed
  that the key reads the values already stored; a wrong key stops with `ASI_MASTER_KEY cannot read stored data` and
  encrypts nothing.
- The same migration ends all sessions, because their CSRF tokens were stored in plain text: every user signs in
  again once after the upgrade.
- Session tokens and CSRF tokens are stored only as SHA-256 hashes. The CSRF token of a session is derived from the
  session cookie (HMAC-SHA-256), so the server can put it into forms without storing it.
- Import uploads are parsed in memory and not kept, so there is no stored raw payload to encrypt.

### Protection of every column

`TestColumnProtectionTableMatchesSchema` (`internal/store`) checks this table against the migrated schema and the
rotation list in `internal/store/rotate.go`: a new column fails the test until it is listed here, every encrypted
column is rotated by `asi key rotate`, and every plain column gives its reason.

| Column | Protection | Reason or content |
|---|---|---|
| `audit_log.id` | plain | key; diff and joins |
| `audit_log.at` | plain | time; filter and sort |
| `audit_log.actor` | plain | username; filter (a username is not secret, see users.username) |
| `audit_log.action` | plain | action name; filter |
| `audit_log.target` | plain | host address, scan, run or signature name; filter |
| `audit_log.address` | plain | client address; needed to investigate the log |
| `builtin_signatures.id` | plain | signature id; key |
| `builtin_signatures.enabled` | plain | flag; filter |
| `builtin_signatures.updated_at` | plain | time |
| `builtin_signatures.updated_by` | plain | username; shown in the list |
| `encryption_keys_in_use.table_name` | plain | name of a column, no data |
| `encryption_keys_in_use.column_name` | plain | name of a column, no data |
| `encryption_keys_in_use.key_header` | plain | key id (public), no data |
| `findings.id` | plain | key; diff and joins |
| `findings.service_observation_id` | plain | key; joins |
| `findings.ordinal` | plain | order; diff |
| `findings.signature_id` | plain | signature id; filter and diff |
| `findings.kind` | plain | finding kind; filter and diff |
| `findings.name` | plain | finding name; diff |
| `findings.version` | plain | version; diff and outdated check |
| `findings.confidence` | plain | number; sort and diff |
| `findings.evidence` | encrypted | what a signature matched on |
| `findings.source` | plain | signature origin (builtin, directory, database); diff |
| `host_observations.run_id` | plain | key; joins |
| `host_observations.group_index` | plain | key; joins |
| `host_observations.host_id` | plain | key; joins |
| `host_observations.hostnames` | plain | hostnames; search and diff |
| `host_observations.observed_at` | plain | time; status and diff |
| `host_observations.notes` | plain | scanner notes such as a second service pass timeout; host page |
| `host_summary.host_id` | plain | key; joins |
| `host_summary.address` | plain | address; search and sort |
| `host_summary.last_run_id` | plain | key; joins |
| `host_summary.status` | plain | status; filter and sort |
| `host_summary.missed_runs` | plain | number; status |
| `host_summary.stability` | plain | number; sort |
| `host_summary.interest_score` | plain | number; sort |
| `host_summary.ports` | plain | ports; filter |
| `host_summary.services` | plain | service names; filter |
| `host_summary.technologies` | plain | technology names; filter |
| `host_summary.finding_kinds` | plain | finding kinds; filter |
| `host_summary.titles` | plain | page titles; search |
| `host_summary.hostnames` | plain | hostnames; search |
| `host_summary.first_seen` | plain | time; sort |
| `host_summary.last_seen` | plain | time; sort |
| `hosts.id` | plain | key; diff and joins |
| `hosts.address` | plain | address; search, sort and diff |
| `hosts.created_at` | plain | time; sort |
| `hosts.tags` | plain | tags; filter |
| `hosts.notes` | encrypted | analyst notes |
| `hosts.display_name` | encrypted | name an analyst gave the host |
| `hosts.owner` | encrypted | owner of the host (a person or team) |
| `hosts.criticality` | plain | fixed list of levels; filter and interest score |
| `hosts.status_override` | plain | fixed list of statuses; status |
| `hosts.user_updated_at` | plain | time; shown on the host |
| `hunt_results.hunt_id` | plain | key; joins |
| `hunt_results.service_id` | plain | key; joins |
| `hunt_results.address` | plain | address; sort |
| `hunt_results.port` | plain | port; sort |
| `hunt_results.protocol` | plain | protocol; sort |
| `hunt_results.evaluable` | plain | flag; filter |
| `hunt_results.first_run_id` | plain | key; joins |
| `hunt_results.last_run_id` | plain | key; joins |
| `hunt_results.in_latest` | plain | flag; filter |
| `hunt_results.version` | plain | version; diff and outdated check |
| `hunt_results.evidence` | encrypted | what a retro-hunt signature matched on |
| `hunts.id` | plain | key; diff and joins |
| `hunts.signature_id` | plain | signature id; shown in the list |
| `hunts.source` | encrypted | YAML source of the signature a retro-hunt ran |
| `hunts.actor` | plain | username; shown in the list |
| `hunts.since` | plain | time; scope of the hunt |
| `hunts.latest_run_id` | plain | key; joins |
| `hunts.observations` | plain | count |
| `hunts.matched` | plain | count |
| `hunts.in_latest` | plain | count |
| `hunts.not_evaluable` | plain | count |
| `hunts.duration_ns` | plain | duration |
| `hunts.created_at` | plain | time; sort |
| `permissions.name` | plain | permission name; RBAC |
| `role_permissions.role` | plain | role name; RBAC |
| `role_permissions.permission` | plain | permission name; RBAC |
| `roles.name` | plain | role name; RBAC |
| `roles.builtin` | plain | flag; RBAC |
| `roles.created_at` | plain | time; sort |
| `run_failed_groups.run_id` | plain | key; joins |
| `run_failed_groups.group_index` | plain | key; joins |
| `run_failed_groups.addresses` | plain | addresses; retry of the group |
| `run_failed_groups.reason` | plain | error text of a failed group, no response data |
| `run_failed_groups.failed_at` | plain | time; progress |
| `run_group_addresses.run_id` | plain | key; joins |
| `run_group_addresses.group_index` | plain | key; joins |
| `run_group_addresses.address` | plain | address; coverage and status |
| `run_group_addresses.ports` | plain | ports; coverage |
| `run_groups.run_id` | plain | key; joins |
| `run_groups.group_index` | plain | key; joins |
| `run_groups.completed_at` | plain | time; progress |
| `run_groups.address_count` | plain | count; progress |
| `run_groups.hosts_found` | plain | count; progress |
| `run_groups.duration_ns` | plain | duration; progress |
| `run_rate_samples.run_id` | plain | key; joins |
| `run_rate_samples.minute` | plain | time; rate chart |
| `run_rate_samples.configured_limit` | plain | rate; chart |
| `run_rate_samples.effective_limit` | plain | rate; chart |
| `run_rate_samples.sent` | plain | count; chart |
| `run_rate_samples.estimated_packets` | plain | count; chart |
| `runs.id` | plain | key; diff and joins |
| `runs.name` | plain | run name; search, sort and diff |
| `runs.inactive_after` | plain | number; status |
| `runs.started_at` | plain | time; sort and status |
| `runs.finished_at` | plain | time; sort |
| `runs.status` | plain | run state; filter |
| `runs.settings` | plain | ports, rate, workers, mode and recheck host addresses (targets and excludes are in scope); recheck planning |
| `runs.definition_id` | plain | key; joins |
| `runs.schedule` | plain | windows and frequency; scheduler |
| `runs.held` | plain | flag; scheduler |
| `runs.address_total` | plain | count; progress |
| `runs.source` | plain | scan, import or manual; filter |
| `runs.packets` | plain | count; traffic |
| `runs.ports` | plain | ports; coverage |
| `runs.heartbeat_at` | plain | time; stalled runs |
| `runs.inflight_addresses` | plain | count; progress of running groups |
| `runs.scope` | encrypted | targets and excludes the run scanned |
| `runs.definition_deleted` | plain | flag; shown on the run |
| `scan_definitions.id` | plain | key; diff and joins |
| `scan_definitions.name` | plain | scan name; sort and unique |
| `scan_definitions.enabled` | plain | flag; scheduler |
| `scan_definitions.inactive_after` | plain | number; status |
| `scan_definitions.settings` | plain | ports, rate and workers (targets and excludes are in scope); scheduler |
| `scan_definitions.schedule` | plain | windows and frequency; scheduler |
| `scan_definitions.last_run_at` | plain | time; scheduler |
| `scan_definitions.created_at` | plain | time; sort |
| `scan_definitions.updated_at` | plain | time; sort |
| `scan_definitions.scope` | encrypted | targets and excludes of the scan |
| `schema_migrations.version` | plain | migration name |
| `schema_migrations.applied_at` | plain | time |
| `service_observations.id` | plain | key; diff and joins |
| `service_observations.run_id` | plain | key; joins |
| `service_observations.group_index` | plain | key; joins |
| `service_observations.service_id` | plain | key; joins |
| `service_observations.state` | plain | port state; diff |
| `service_observations.service` | plain | service name; filter and diff |
| `service_observations.product` | plain | product name; diff |
| `service_observations.version` | plain | version; diff and outdated check |
| `service_observations.http` | plain | HTTP document without headers, cookies and body (status, title, TLS certificate); search and diff |
| `service_observations.http_headers` | encrypted | response headers |
| `service_observations.http_cookies` | encrypted | cookie names and flags (values are never stored) |
| `service_observations.observed_at` | plain | time; status and diff |
| `service_observations.http_body` | encrypted | first 64 KiB of the root page, for retro-hunts |
| `service_observations.field_state` | encrypted | last values of fields that change every run (volatility tracking) |
| `services.id` | plain | key; diff and joins |
| `services.host_id` | plain | key; joins |
| `services.port` | plain | port; filter, sort and diff |
| `services.protocol` | plain | protocol; diff |
| `sessions.token_hash` | hashed | SHA-256 of the session cookie |
| `sessions.user_id` | plain | key; joins |
| `sessions.created_at` | plain | time; session expiry |
| `sessions.last_used_at` | plain | time; session expiry |
| `sessions.address` | plain | client address; audit of sign-ins |
| `sessions.csrf_hash` | hashed | SHA-256 of the session CSRF token |
| `settings.key` | plain | setting name, no data |
| `settings.value` | encrypted | the DefectDojo connection including the API token |
| `settings.updated_at` | plain | time |
| `signatures.id` | plain | signature id; key and diff |
| `signatures.name` | plain | signature name; list and sort |
| `signatures.kind` | plain | finding kind; filter |
| `signatures.source` | encrypted | YAML source of a stored signature |
| `signatures.enabled` | plain | flag; filter |
| `signatures.created_at` | plain | time |
| `signatures.updated_at` | plain | time; sort |
| `signatures.updated_by` | plain | username; shown in the list |
| `technologies.id` | plain | key; diff and joins |
| `technologies.service_observation_id` | plain | key; joins |
| `technologies.ordinal` | plain | order; diff |
| `technologies.name` | plain | technology name; filter and diff |
| `technologies.category` | plain | category; filter |
| `technologies.version` | plain | version; diff and outdated check |
| `technologies.confidence` | plain | number; sort and diff |
| `technologies.source` | plain | signature origin; diff |
| `users.id` | plain | key; diff and joins |
| `users.username` | plain | username; sign-in lookup |
| `users.password_hash` | hashed | Argon2id hash of the password |
| `users.role` | plain | role name; RBAC |
| `users.created_at` | plain | time; sort |
| `users.updated_at` | plain | time; sort |
| `users.disabled` | plain | flag; sign-in |

### Protection of every column

`TestColumnProtectionTableMatchesSchema` (`internal/store`) checks this table against the migrated schema and the
rotation list in `internal/store/rotate.go`: a new column fails the test until it is listed here, every encrypted
column is rotated by `asi key rotate`, and every plain column gives its reason.

| Column | Protection | Reason or content |
|---|---|---|
| `audit_log.id` | plain | key; diff and joins |
| `audit_log.at` | plain | time; filter and sort |
| `audit_log.actor` | plain | username; filter (a username is not secret, see users.username) |
| `audit_log.action` | plain | action name; filter |
| `audit_log.target` | plain | host address, scan, run or signature name; filter |
| `audit_log.address` | plain | client address; needed to investigate the log |
| `builtin_signatures.id` | plain | signature id; key |
| `builtin_signatures.enabled` | plain | flag; filter |
| `builtin_signatures.updated_at` | plain | time |
| `builtin_signatures.updated_by` | plain | username; shown in the list |
| `encryption_keys_in_use.table_name` | plain | name of a column, no data |
| `encryption_keys_in_use.column_name` | plain | name of a column, no data |
| `encryption_keys_in_use.key_header` | plain | key id (public), no data |
| `findings.id` | plain | key; diff and joins |
| `findings.service_observation_id` | plain | key; joins |
| `findings.ordinal` | plain | order; diff |
| `findings.signature_id` | plain | signature id; filter and diff |
| `findings.kind` | plain | finding kind; filter and diff |
| `findings.name` | plain | finding name; diff |
| `findings.version` | plain | version; diff and outdated check |
| `findings.confidence` | plain | number; sort and diff |
| `findings.evidence` | encrypted | what a signature matched on |
| `findings.source` | plain | signature origin (builtin, directory, database); diff |
| `host_observations.run_id` | plain | key; joins |
| `host_observations.group_index` | plain | key; joins |
| `host_observations.host_id` | plain | key; joins |
| `host_observations.hostnames` | plain | hostnames; search and diff |
| `host_observations.observed_at` | plain | time; status and diff |
| `host_summary.host_id` | plain | key; joins |
| `host_summary.address` | plain | address; search and sort |
| `host_summary.last_run_id` | plain | key; joins |
| `host_summary.status` | plain | status; filter and sort |
| `host_summary.missed_runs` | plain | number; status |
| `host_summary.stability` | plain | number; sort |
| `host_summary.interest_score` | plain | number; sort |
| `host_summary.ports` | plain | ports; filter |
| `host_summary.services` | plain | service names; filter |
| `host_summary.technologies` | plain | technology names; filter |
| `host_summary.finding_kinds` | plain | finding kinds; filter |
| `host_summary.titles` | plain | page titles; search |
| `host_summary.hostnames` | plain | hostnames; search |
| `host_summary.first_seen` | plain | time; sort |
| `host_summary.last_seen` | plain | time; sort |
| `hosts.id` | plain | key; diff and joins |
| `hosts.address` | plain | address; search, sort and diff |
| `hosts.created_at` | plain | time; sort |
| `hosts.tags` | plain | tags; filter |
| `hosts.notes` | encrypted | analyst notes |
| `hosts.display_name` | encrypted | name an analyst gave the host |
| `hosts.owner` | encrypted | owner of the host (a person or team) |
| `hosts.criticality` | plain | fixed list of levels; filter and interest score |
| `hosts.status_override` | plain | fixed list of statuses; status |
| `hosts.user_updated_at` | plain | time; shown on the host |
| `hunt_results.hunt_id` | plain | key; joins |
| `hunt_results.service_id` | plain | key; joins |
| `hunt_results.address` | plain | address; sort |
| `hunt_results.port` | plain | port; sort |
| `hunt_results.protocol` | plain | protocol; sort |
| `hunt_results.evaluable` | plain | flag; filter |
| `hunt_results.first_run_id` | plain | key; joins |
| `hunt_results.last_run_id` | plain | key; joins |
| `hunt_results.in_latest` | plain | flag; filter |
| `hunt_results.version` | plain | version; diff and outdated check |
| `hunt_results.evidence` | encrypted | what a retro-hunt signature matched on |
| `hunts.id` | plain | key; diff and joins |
| `hunts.signature_id` | plain | signature id; shown in the list |
| `hunts.source` | encrypted | YAML source of the signature a retro-hunt ran |
| `hunts.actor` | plain | username; shown in the list |
| `hunts.since` | plain | time; scope of the hunt |
| `hunts.latest_run_id` | plain | key; joins |
| `hunts.observations` | plain | count |
| `hunts.matched` | plain | count |
| `hunts.in_latest` | plain | count |
| `hunts.not_evaluable` | plain | count |
| `hunts.duration_ns` | plain | duration |
| `hunts.created_at` | plain | time; sort |
| `permissions.name` | plain | permission name; RBAC |
| `role_permissions.role` | plain | role name; RBAC |
| `role_permissions.permission` | plain | permission name; RBAC |
| `roles.name` | plain | role name; RBAC |
| `roles.builtin` | plain | flag; RBAC |
| `roles.created_at` | plain | time; sort |
| `run_failed_groups.run_id` | plain | key; joins |
| `run_failed_groups.group_index` | plain | key; joins |
| `run_failed_groups.addresses` | plain | addresses; retry of the group |
| `run_failed_groups.reason` | plain | error text of a failed group, no response data |
| `run_failed_groups.failed_at` | plain | time; progress |
| `run_group_addresses.run_id` | plain | key; joins |
| `run_group_addresses.group_index` | plain | key; joins |
| `run_group_addresses.address` | plain | address; coverage and status |
| `run_group_addresses.ports` | plain | ports; coverage |
| `run_groups.run_id` | plain | key; joins |
| `run_groups.group_index` | plain | key; joins |
| `run_groups.completed_at` | plain | time; progress |
| `run_groups.address_count` | plain | count; progress |
| `run_groups.hosts_found` | plain | count; progress |
| `run_groups.duration_ns` | plain | duration; progress |
| `run_rate_samples.run_id` | plain | key; joins |
| `run_rate_samples.minute` | plain | time; rate chart |
| `run_rate_samples.configured_limit` | plain | rate; chart |
| `run_rate_samples.effective_limit` | plain | rate; chart |
| `run_rate_samples.sent` | plain | count; chart |
| `run_rate_samples.estimated_packets` | plain | count; chart |
| `runs.id` | plain | key; diff and joins |
| `runs.name` | plain | run name; search, sort and diff |
| `runs.inactive_after` | plain | number; status |
| `runs.started_at` | plain | time; sort and status |
| `runs.finished_at` | plain | time; sort |
| `runs.status` | plain | run state; filter |
| `runs.settings` | plain | ports, rate, workers, mode and recheck host addresses (targets and excludes are in scope); recheck planning |
| `runs.definition_id` | plain | key; joins |
| `runs.schedule` | plain | windows and frequency; scheduler |
| `runs.held` | plain | flag; scheduler |
| `runs.address_total` | plain | count; progress |
| `runs.source` | plain | scan, import or manual; filter |
| `runs.packets` | plain | count; traffic |
| `runs.ports` | plain | ports; coverage |
| `runs.heartbeat_at` | plain | time; stalled runs |
| `runs.scope` | encrypted | targets and excludes the run scanned |
| `runs.definition_deleted` | plain | flag; shown on the run |
| `scan_definitions.id` | plain | key; diff and joins |
| `scan_definitions.name` | plain | scan name; sort and unique |
| `scan_definitions.enabled` | plain | flag; scheduler |
| `scan_definitions.inactive_after` | plain | number; status |
| `scan_definitions.settings` | plain | ports, rate and workers (targets and excludes are in scope); scheduler |
| `scan_definitions.schedule` | plain | windows and frequency; scheduler |
| `scan_definitions.last_run_at` | plain | time; scheduler |
| `scan_definitions.created_at` | plain | time; sort |
| `scan_definitions.updated_at` | plain | time; sort |
| `scan_definitions.scope` | encrypted | targets and excludes of the scan |
| `schema_migrations.version` | plain | migration name |
| `schema_migrations.applied_at` | plain | time |
| `service_observations.id` | plain | key; diff and joins |
| `service_observations.run_id` | plain | key; joins |
| `service_observations.group_index` | plain | key; joins |
| `service_observations.service_id` | plain | key; joins |
| `service_observations.state` | plain | port state; diff |
| `service_observations.service` | plain | service name; filter and diff |
| `service_observations.product` | plain | product name; diff |
| `service_observations.version` | plain | version; diff and outdated check |
| `service_observations.http` | plain | HTTP document without headers, cookies and body (status, title, TLS certificate); search and diff |
| `service_observations.http_headers` | encrypted | response headers |
| `service_observations.http_cookies` | encrypted | cookie names and flags (values are never stored) |
| `service_observations.observed_at` | plain | time; status and diff |
| `service_observations.http_body` | encrypted | first 64 KiB of the root page, for retro-hunts |
| `service_observations.field_state` | encrypted | last values of fields that change every run (volatility tracking) |
| `services.id` | plain | key; diff and joins |
| `services.host_id` | plain | key; joins |
| `services.port` | plain | port; filter, sort and diff |
| `services.protocol` | plain | protocol; diff |
| `sessions.token_hash` | hashed | SHA-256 of the session cookie |
| `sessions.user_id` | plain | key; joins |
| `sessions.created_at` | plain | time; session expiry |
| `sessions.last_used_at` | plain | time; session expiry |
| `sessions.address` | plain | client address; audit of sign-ins |
| `sessions.csrf_hash` | hashed | SHA-256 of the session CSRF token |
| `settings.key` | plain | setting name, no data |
| `settings.value` | encrypted | the DefectDojo connection including the API token |
| `settings.updated_at` | plain | time |
| `signatures.id` | plain | signature id; key and diff |
| `signatures.name` | plain | signature name; list and sort |
| `signatures.kind` | plain | finding kind; filter |
| `signatures.source` | encrypted | YAML source of a stored signature |
| `signatures.enabled` | plain | flag; filter |
| `signatures.created_at` | plain | time |
| `signatures.updated_at` | plain | time; sort |
| `signatures.updated_by` | plain | username; shown in the list |
| `technologies.id` | plain | key; diff and joins |
| `technologies.service_observation_id` | plain | key; joins |
| `technologies.ordinal` | plain | order; diff |
| `technologies.name` | plain | technology name; filter and diff |
| `technologies.category` | plain | category; filter |
| `technologies.version` | plain | version; diff and outdated check |
| `technologies.confidence` | plain | number; sort and diff |
| `technologies.source` | plain | signature origin; diff |
| `users.id` | plain | key; diff and joins |
| `users.username` | plain | username; sign-in lookup |
| `users.password_hash` | hashed | Argon2id hash of the password |
| `users.role` | plain | role name; RBAC |
| `users.created_at` | plain | time; sort |
| `users.updated_at` | plain | time; sort |
| `users.disabled` | plain | flag; sign-in |

## Scanner safety rules

What ASI ever sends to a target:

| Step | Traffic |
|---|---|
| host discovery | ICMP echo requests and TCP SYN packets to the configured ports (`nmap -sn -PE -PS`) |
| service detection | TCP connections to the configured ports and nmap's light version probes (none on never-probe ports) (`-sT -sV --version-light`), then nmap's default-intensity probes (`-sT -sV`) on unidentified ports; see [What nmap sends](#what-nmap-sends) |
| HTTP probe | `GET /`, up to 5 redirects, `GET /favicon.ico` (twice when it changed); on unidentified ports the same over HTTP, then TLS |
| signatures | `GET` or `HEAD` of at most 5 further literal paths per service |

- Only the ports on the run's list are contacted; results for other ports are discarded.
- Excluded addresses are removed before anything is sent.
- No request body, no custom headers, no credentials, no query strings. The `User-Agent` is `asi-discovery/<version>`.
- A redirect is followed only when it stays on the same host and port; a redirect elsewhere is recorded in the chain
  and not fetched.
- TLS certificates are read, not verified (self-signed certificates are a finding, not an error).
- Response bodies are read up to 1 MiB; every request has a deadline.
- Industrial and printing ports listed in [the pipeline](#scan-pipeline) get only a TCP connect: no nmap service
  probe and no HTTP request.
- The rate limit covers nmap packets and HTTP requests together and backs off when targets slow down (see
  [Rate limit and adaptive rate](#rate-limit-and-adaptive-rate)).
- Signatures are checked against these rules when they are loaded or saved; a signature that breaks one is rejected
  ([signatures.md](signatures.md#safety-rules)).

## Import and export

- **Export** (`asi export`, `/export`): the state as of a run as `asi.export/v1` JSON or as CSV with one row per
  service. The UI picks the run from a list (all runs, newest first) and can filter by status, tag and address or
  hostname.
- **Import** (`asi import`, `/import`): the same JSON, or a CSV that needs only an `address` column. Every row is
  validated on its own; invalid rows are listed (`Row 4: "172.30.9.300" is not an address.`) and do not stop the
  rest. `--dry-run` shows what would change and records nothing.
- **Manual entry** (`/hosts/entry`): a form for one host with hostnames, tags, notes and service rows.
- An import or a manual entry is recorded as its own completed run (source `import` or `manual`) covering exactly
  the imported addresses. Detection runs on the imported HTTP data as described in
  [Detection sources](#detection-sources-and-confidence) without sending a request, and the result takes part in
  status and diffs like a scan. Imports and manual entries are not availability samples.
- Imported tags are added and empty user fields are filled; values a user already set are kept.
- A later scan that covers an imported address and does not find the host counts as a miss, like for any other host.
- **Deletion** (`/hosts/{address}/delete` and per service): removes the host or service with its whole history. A
  deleted host found again later is `host_new`. Deleting a scan definition (`/scans/{id}/delete`) keeps its runs and
  their observations; the run pages then say "Definition deleted". A definition with a run in progress or paused
  cannot be deleted.
- **Samples.** `/import` lists the accepted columns and offers `/import/sample.csv` and `/import/sample.json`, three
  example hosts in the documentation range 192.0.2.0/24.

## DefectDojo integration

`internal/exchange/defectdojo` exports a run to one engagement of a DefectDojo instance through its API v2:

- the open services as an nmap XML document, scan type `Nmap Scan`;
- findings of kind admin panel, staging, IoT, notable header, notable cookie and custom with severity `Info`, and
  `outdated` findings with severity `Low`, as Generic Findings Import JSON with the endpoint and a stable
  `unique_id_from_tool` (`asi:<address>:<protocol>/<port>:<signature id>`);
- every open service as an `Info` finding `Open service: <address>:<port> <product> <version>`
  (`asi:<address>:<protocol>/<port>`), so services that appear or vanish open and close findings on reimport.

The first export uses `/api/v2/import-scan/`; DefectDojo's test ids are stored per base URL, product and engagement
and later exports use `/api/v2/reimport-scan/`, so the same two tests are updated. A test deleted in DefectDojo is
recreated once and the output says so. A run older than the last one exported to that engagement is refused unless
forced. A changed connection is tested before it is saved. The connection (URL, token, product, engagement) is stored
encrypted; the token is never shown again and is left out of error messages. With a saved token, the page lists
the products and the engagements of the chosen product from DefectDojo (`/api/v2/products/`,
`/api/v2/engagements/?product=N`, at most 2000 each) for users with `scan.configure`; when the lists cannot be
loaded, the page falls back to number fields. The lists are fetched on every view of the page. The run to export is
picked from the completed runs. `asi defectdojo export --run NAME
--dry-run` writes `nmap.xml` and `findings.json` to a directory and sends nothing. The UI page is `/defectdojo`.

The integration was run against a real DefectDojo 3.5 once (commit `d396b88`); the fixes from that run are covered by
`TestDefectDojoFixesFromRealDojoRun`, which replays its answers against a fake server.

## Known limitations

Measured results are quoted from `eval/results/`. Only `eval/results/comparison/` is committed; the `perf`,
`reliability` and `vulhub` files quoted here were in the working copy of the evaluation. The reliability results were
measured at commit `7ff9e38`, before the reliability fixes of `182dc8a` and `97fdcc7`.

Scanning:

- IPv4 only. TCP only; UDP services are not scanned.
- The second nmap pass is bounded per host (20 s per port, at most 90 s); `--service-detection light` avoids it.
- Group, probe and host timeouts are constants; only `--http-timeout` is configurable.
- After `kill -9` of `asi`, running nmap calls are not stopped (see [Scan pipeline](#scan-pipeline)).
- Recheck runs save packets, not time, on a single host or a dense range.
- `asi scan plan` and the run page estimate nmap packets differently; neither counts real nmap packets.
- `--max-addresses` applies to the command line only; the UI and the scheduler are bound by the work ceiling.
- Fingerprinting breadth: the sources listed in [Detection sources](#detection-sources-and-confidence). Everything
  else needs own signatures. Before the pack existed, ASI recognised 13 of 16 real applications and got the exact
  version for 8 (`eval/results/vulhub/asi-score-pre-pack.json`); the measurement has not been repeated with the pack.
- Imported data has no page body, so body-based detection does not apply to it.
- The fingerprint dataset and the heuristics cannot be switched off on their own, only together with the whole
  built-in pack. A failure to load the embedded dataset is not reported; detection then runs without it.
- Heuristics also name products from application metadata (confidence 40) and from a page title corroborated by
  other evidence (30), source `heuristic`. One finding is kept per kind and name per service.

Operation:

- A database outage longer than 60 s pauses the run; it has to be resumed (or is resumed by the scheduler for a
  definition's run).
- At start, `asi serve` marks every `running` run of a definition `paused`, without looking at its heartbeat; do not
  run two `asi serve` processes against one database.
- The login rate limit is per process, is reset by a restart and counts by TCP peer address.
- Observations are kept forever. Only the stored page excerpts are pruned (`ASI_BODY_RETENTION_RUNS`); there is no
  retention setting for the rest. Ten runs of the reliability lab added 116 rows per run
  (`eval/results/reliability/summary.md`, scenario 7).

Access:


- There is no command to disable a user or reset a password, only the `/users/` page.
- `asi scan run`, `asi scan resume` and `asi key rotate` are not in the audit log.

Performance, for orientation (`eval/results/perf/post-scale.json`, a /18 with 16 384 addresses, 485 live hosts,
16 workers, `--max-rate 1000`): three runs took 126 to 131 s (125 to 130 addresses per second), found 485 of 485
hosts and 594 of 594 services, the rate measured at the targets never exceeded the limit, and peak memory was 491 MiB
for `asi` and 48.5 MiB for PostgreSQL. All 92 hosts taken down between runs were reported missing and later returned,
with no other change. It was taken before the adaptive rate and the HTTP probing of unidentified ports were added
and has not been repeated since.
