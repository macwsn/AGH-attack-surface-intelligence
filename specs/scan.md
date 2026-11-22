---
capability: scan
title: Scan runs
code: []
tests: []
---
# Scan runs

## Requirements

### REQ-SCAN-001: Worker pool and group timing
`(*scan.Scanner).Run(ctx, run)` SHALL expand the run's stored targets minus its excludes (`internal/targets`), split the
addresses into groups and scan the groups on `RunSettings.Workers` goroutines (default `scan.DefaultWorkers`). Every
address SHALL belong to exactly one group. With `RunSettings.GroupSize` set every group has that size; otherwise the
size starts at `scan.InitialGroupSize` (64) and stays between `scan.MinGroupSize` (16) and `scan.MaxGroupSize` (1024):
after every recorded group the scanner averages the seconds per address of the last `scan.SizeWindow` (4) groups and,
when the current size times that average falls outside 30-60 s, sets the size to 45 s divided by the average. Per group
the scanner SHALL run nmap `Discover`, then `Services` on the live hosts, probe every open port that speaks HTTP or TLS
(`internal/probe`), run detection (`internal/detect`) and record the group through `RecordGroup` with its duration.

#### Scenario: three workers
- WHEN a run over 10 groups with Workers=3 is started and nmap blocks
- THEN exactly 3 groups are in flight, never more
- AND the union of the recorded group addresses equals the expanded target set

#### Scenario: 16 384 addresses
- WHEN 10.0.0.0/18 (16 384 addresses, 3% live) is scanned with the fake nmap runner and 16 workers
- THEN the run completes, every live host is recorded exactly once and the heap grows by less than 200 MiB

### REQ-SCAN-002: Rate limit
A run SHALL split its effective rate (REQ-SCAN-018; the max rate while the controller has not lowered it or when
adaptive is off): nmap gets effective / 2 (rounded down) and the probe's token bucket (`scan.NewLimiter`, rate =
effective - effective / 2 per second, burst = the same, changed through `(*scan.Limiter).SetRate`, injectable
`scan.Clock`) gets the rest, so nmap packets and probe requests together never exceed the run's max rate. The bucket
SHALL also let at most 60 x its rate requests go in one UTC minute. A max rate below 2 SHALL be rejected before any
nmap call. Every probe HTTP request (root, redirects, favicon, signature paths) SHALL take one token. nmap calls SHALL
get `Options.MaxRate` = max(1, (effective / 2) / min(workers, max rate / 2, addresses)) and at most min(workers, max
rate / 2, addresses) nmap calls run at once, where addresses is the size of the expanded target set (at least 1), so the
rates of concurrent nmap calls never sum above nmap's half and a single-host scan gets all of it. Probe requests to one address SHALL never exceed `scan.PerHostConcurrency` (2) in flight.

#### Scenario: fake clock
- WHEN 100 probe requests are issued with max rate 10
- THEN the fake clock advances at least 9 s and no 1 s window holds more than 20 requests

#### Scenario: combined cap
- WHEN a run with the fake nmap runner and a fake clock uses 1, 4 or 16 workers (max rate 20, 20 and 10)
- THEN the peak sum of concurrent nmap `Options.MaxRate` plus the measured probe rate stays at or below the max rate

#### Scenario: one host
- WHEN one address is scanned with 4 workers and max rate 100
- THEN every nmap call gets `Options.MaxRate` 50

### REQ-SCAN-003: Allowed ports and excludes
nmap `Services` SHALL be called with exactly the run's ports and `Discover` probes only those ports; ports reported
outside the list, non-open ports and hosts outside the group's addresses (excluded or not targeted) SHALL be dropped
before probing or recording. Redirects are followed only on the same host and port (`internal/probe`).

#### Scenario: nmap reports extra ports and an excluded host
- WHEN the runner reports ports 8080 and 22 and an excluded address as up, with ports [80,443]
- THEN only ports 80 and 443 are probed and recorded and the excluded address is never contacted

### REQ-SCAN-004: Pause and resume
When the run context is cancelled the run SHALL stop dispatching groups, record no partial group, skip the re-probe,
set status `paused` and return an error wrapping `context.Canceled`. Running a `paused`, `failed` or `running` run SHALL
continue with the addresses not covered by its recorded groups, using the stored settings, and end `completed`; a group
error ends the run `failed`. Running a `completed` run SHALL fail with `scan.ErrAlreadyCompleted` and change nothing.

#### Scenario: resume equals an uninterrupted run
- WHEN a run is cancelled after two groups and then resumed
- THEN no group scan after the resume touches an address of a finished group
- AND its export equals the export of the same scan run without interruption

### REQ-SCAN-005: Re-probe of missing hosts
After all groups finished the run SHALL re-probe once (one `Discover` and, for hosts found up, one `Services` pass with
the same ports) the addresses that were `active` or `unstable` as of the previous run, are in this run's targets and
were not found in this run, and record hosts found up through `RecordLateHosts`. Hosts never seen, hosts `inactive` as
of the previous run and excluded addresses SHALL NOT be re-probed; without such hosts no extra nmap call is made.

#### Scenario: host back on re-probe
- WHEN a previously active host is down in its group and up on the re-probe
- THEN the export shows it `active` with `missed_runs` 0 and its services
- AND a host down on the re-probe too is `unstable` with `missed_runs` 1

### REQ-SCAN-006: Address total
`(*scan.Scanner).Run` SHALL record the number of addresses of the expanded target set minus excludes through
`Store.SetRunTotal` (`runs.address_total`) before scanning groups, on every start and resume.

### REQ-SCAN-007: Backpressure and bounded database use
A worker SHALL write a group's results with one `RecordGroup` call, in one database transaction, and SHALL NOT take the
next group before that call returns. Results are not queued between workers and the database: a slow database slows
the workers. Database connections are bounded by the pool (`pool_max_conns`).

#### Scenario: stalled store
- WHEN `RecordGroup` blocks for every worker of a run with 4 workers
- THEN no fifth group is scanned until the store returns

### REQ-SCAN-008: Timed-out groups
A group attempt SHALL be cancelled after `Scanner.GroupTimeout` (default `scan.DefaultGroupTimeout`, 10 minutes). A
group that times out SHALL be split in half (a single address is retried as is) and each half scanned once more; a half
that times out again SHALL be recorded through `RecordFailedGroup` (`run_failed_groups`) with its addresses and reason,
and the run continues. Addresses of failed groups are not covered by the run, so their hosts are not counted as
missed, they are not re-probed, and a resumed run does not scan them again.

#### Scenario: one stuck address
- WHEN a group of 8 addresses times out because of one address
- THEN the half without it is recorded, the half with it is listed as a failed group, the run ends `completed`
- AND a host of the failed half that was active before keeps `missed_runs` 0

### REQ-SCAN-009: Progress
`Run` SHALL store the number of addresses of the expanded target set through `SetRunTotal` (`runs.address_total`).
While a run works, the scanner SHALL count the addresses of its running groups whose discovery finished and store that
count with every heartbeat (`Store.Heartbeat(ctx, runID, inFlight)`, `runs.inflight_addresses`, migration 0022); it
SHALL write a heartbeat as soon as the count changes, besides every `HeartbeatInterval`, and subtract a group's
addresses again before the group is recorded or when it is given up; `RecordGroup` SHALL subtract the
group's addresses from `runs.inflight_addresses` in its transaction, so a recorded group is never counted twice. `inventory.Run.InFlight` SHALL carry the stored count.
`scan.RunProgress` SHALL report addresses per second (addresses of recorded groups divided by the sum of their
durations, times the workers), addresses done (recorded and failed groups plus, for a running run only, the addresses
in flight, at most the stored total; they do not count for the groups total and the time left), groups done, the estimated total of groups (done + failed + the addresses left
divided by the size of the most recently completed group) and the estimated time left (addresses left divided by the
rate; unknown without a rate or a stored total; zero for a completed run). `asi scan show NAME` SHALL append
`rate=R/s groups_done=D/T failed_groups=F eta=E` to its first line and print one
`failed_group=I addresses=N reason="…"` line per failed group after the group lines; the run page `/runs/{id}`
(REQ-SCHEDULE-008) SHALL show the same figures, the time left also as a range labelled as an estimate
("Estimate: about 1-2 min left", time left x 0.8 to x 1.25) while the run is open; before the run has a rate, an open
full run SHALL show the plan estimate (REQ-SCAN-021, from the newest earlier completed full run of its definition, or
the live-share model) scaled by the share of addresses left, naming its source, and list failed groups with their
reasons. While the run is running or paused, the run page SHALL wrap its content in `#run-live` with
`hx-get="/runs/{id}" hx-trigger="every 3s" hx-select="#run-live" hx-swap="outerHTML"`; a completed or failed run's page
SHALL carry no polling attributes, so polling stops with the first response after the run ended. An unauthenticated
poll gets 401 with `HX-Redirect` (REQ-WEB-004). `GET /runs?name={name}` (permission `scan.run`) SHALL redirect (303) to
`/runs/{id}` of the run with that name and answer 404 for an unknown name; there is no `/runs/by-name/{name}` page.

#### Scenario: paused run
- WHEN a run of 1 000 addresses with 2 workers has recorded 64 addresses in 32 s and 100 in 50 s and one failed group of 2
- THEN `scan show` reports `rate=4.0/s groups_done=2/12 failed_groups=1 eta=3m29s`

#### Scenario: run page by name
- WHEN a run `nightly` of 40 addresses with 1 worker has recorded 2 addresses in 1 s and one failed group of 2
- AND a user with `scan.run` opens `/runs?name=nightly`
- THEN they are redirected to `/runs/{id}`, which shows 2.0 addresses per second, groups done 1 / 20, 1 failed group
  with its reason and 18 s left

#### Scenario: progress inside the first group
- WHEN the first group of 16 of 64 addresses finished discovery and its service pass still runs
- THEN the last heartbeat stores 16 addresses in flight and the run page shows 25% done before any group is recorded

#### Scenario: polling stops
- WHEN a paused or running run's page is open
- THEN it polls every 3 s; once the run completed, the response has no `hx-get` and polling stops

### REQ-SCAN-010: Response time and HTTP deadline
The probe SHALL measure the root page of every web service: `http.ttfb_ms` (time to first byte of the first request)
and `http.response_time_ms` (until the body of the final response after allowed redirects is read, summed over the
requests), in whole milliseconds rounded up, counted from the moment each connection is requested, so rate-limit waits
do not count. Every HTTP request SHALL have a deadline of `--http-timeout`
(default `10s`, stored in the run settings as `http_timeout_ms`). A service that accepts the connection and then stalls,
trickles its body or never closes SHALL be cut off at that deadline and recorded as an open service with
`http.error = "timeout"`, its URL, scheme and the elapsed time as `http.response_time_ms`; the worker then moves on.
A run cancelled by its caller is not a timeout.

#### Scenario: slow answer
- WHEN a service answers after 150 ms and finishes its body 100 ms later
- THEN `http.ttfb_ms` is at least 150 and `http.response_time_ms` at least 250

#### Scenario: stalled, trickling and never-closing services
- WHEN services stall before the headers, send the body at a few bytes per interval or never close, and `--http-timeout` is 300ms
- THEN the run completes within about the timeout and each service is recorded as `open` with `http.error = "timeout"`

### REQ-SCAN-011: Port lists, ranges and presets
`scan.ParsePorts` (used by `asi scan run --ports` and the scan definition form) SHALL accept a comma-separated list
whose entries are ports (`80`), inclusive ranges (`8000-8100`) and the case-insensitive presets `top100` and `top1000`
(the 100 and 1000 most frequent TCP ports of nmap 7.99, `nmap --top-ports`) and `all` (1-65535), mixed freely. It SHALL
return the ports sorted and without duplicates; that normalised list is what runs and scan definitions store
(`RunSettings.Ports`, unchanged format). An entry that is empty, not a number, outside 1-65535 or a range whose end is
below its start SHALL be rejected with an error naming that entry (`invalid port "abc"`, `invalid port range
"9000-8000"`). `scan.FormatPorts` SHALL render a port list with consecutive ports joined into ranges
(`21,80,8000-8100`); nmap receives its `-p` and `-PS` lists in that form, and the scan pages show it.

#### Scenario: lists and ranges
- WHEN `--ports 21,80,8000-8100,21000-21010` is given
- THEN the run stores the 114 ports in ascending order and nmap `Services` is called with `-p 21,80,8000-8100,21000-21010`

#### Scenario: bad range
- WHEN the form's ports are `80,9000-8000`
- THEN the form is shown again with `invalid port range "9000-8000"` and nothing is stored

### REQ-SCAN-012: Loopback and host name targets
Run targets and excludes SHALL be parsed with `targets.ParseHosts`, which accepts everything `targets.Parse` accepts
plus single-label host names such as `localhost`. A host name target SHALL be resolved to its IPv4 addresses; the host
is recorded under the address and keeps the name in its hostnames, and every probe of its services SHALL use the name
as the HTTP `Host` header and as the TLS SNI server name, while connecting to the resolved address.

#### Scenario: name resolving to loopback
- WHEN the target `host.docker.internal` resolves to 127.0.0.1 and has an HTTP and an HTTPS service
- THEN the host 127.0.0.1 is recorded with hostname `host.docker.internal`, the HTTP request carries
  `Host: host.docker.internal:<port>` and the TLS handshake carries SNI `host.docker.internal`

### REQ-SCAN-013: Technologies of services without HTTP
After probing, `(*scan.Scanner).Run` SHALL add to every recorded service the technologies returned by
`detect.ServiceTechnologies(service, product, version)` for the nmap service name, product and version, with
`source: "builtin"`, category and version, merged with the service's HTTP technologies by `detect.Merge`.
`detect.ServiceTechnologies` maps `ftp`/vsftpd to `vsftpd`, `ftp`/ProFTPD to `ProFTPD` and `ftp`/Pure-FTPd to
`Pure-FTPd` (all `ftp-server`), `ssh`/OpenSSH to `OpenSSH`
(`ssh-server`, version = first word of the nmap version), `redis` to `Redis`, `postgresql` to `PostgreSQL`,
`mysql`/MySQL to `MySQL`, `mysql` with MariaDB in product or version to `MariaDB` (all `database`),
`amqp`/RabbitMQ and `amqps`/RabbitMQ to `RabbitMQ` (version from the nmap version when it has one) and
`apachemq`/ActiveMQ to `ActiveMQ` (both `message-broker`); any other service or
product yields nothing. It SHALL do so through `(*inventory.ServiceResult).Detect` / `(*detect.Set).DetectService`,
the function imports and manual entries use (REQ-EXCHANGE-003), which also maps the nmap products nginx to `nginx`,
Apache httpd to `Apache` (both `web-server`) and Apache Tomcat to `Apache Tomcat` (`application-server`) with the
nmap version, except that a Coyote product (`Apache Tomcat/Coyote JSP engine`) gives no version, and adds the findings
of `detect.Outdated` for the merged technologies. HTTP services otherwise keep their HTTP detection unchanged. A version nmap reports as a bound
(`or later`, `or earlier`, a component `x` such as `8.x` or `2.4.x - 2.4.y`) SHALL stay in the service's `version` as
nmap gave it, but the technology SHALL get an empty version and confidence 60 instead of 80, so no `outdated` finding
comes from the bound; a numeric range (`9.6.0 - 9.6.24`) gives an empty version with confidence 80.
`detect.Merge` SHALL join entries of one technology name (case-insensitive) only when they come from the same origin:
the built-in origin (`source: "builtin"`, and likewise `wappalyzer` and `heuristic`, joining any other entry of that name, and all `signature:builtin-*` pack
signatures together) or one custom signature id; a custom signature and a built-in pack signature naming the same
technology SHALL both stay in `technologies`, each with its own source. When `detect.Merge` joins two entries whose
versions are both set and one extends the other (`8` and `8.5.0`), it SHALL keep the more specific version; otherwise
the version of the higher-confidence entry is kept.

#### Scenario: recorded nmap output without HTTP
- WHEN nmap reports ftp vsftpd 2.3.4, ssh OpenSSH 7.4, redis, postgresql, mysql MySQL 5.7.44 and amqp RabbitMQ 3.13.7
- THEN each of those services is recorded with that one technology, its category and version and source `builtin`
- AND none of them is probed over HTTP, and an HTTP service on the same host gets no duplicate technology

#### Scenario: ActiveMQ OpenWire
- WHEN nmap reports apachemq "ActiveMQ OpenWire transport" 5.17.3
- THEN the service has the technology `ActiveMQ` 5.17.3 (`message-broker`)

#### Scenario: nmap web server products
- WHEN nmap reports http nginx 1.14.0 and http Apache httpd 2.2.15
- THEN the services have `nginx` 1.14.0 with `outdated-nginx` and `Apache` 2.2.15 with `outdated-apache`
- AND http "Apache Tomcat/Coyote JSP engine" 1.1 gives `Apache Tomcat` without a version and no outdated finding

#### Scenario: version bound
- WHEN nmap reports postgresql "PostgreSQL DB" version `9.6.0 or later`
- THEN the service's version is `9.6.0 or later`, the technology `PostgreSQL` has an empty version and confidence 60
- AND the service has no `outdated` finding

#### Scenario: custom signature named like a built-in one
- WHEN a custom technology signature `eval-gitea` named `Gitea` and the built-in pack signature `builtin-gitea` both match
- THEN `technologies` holds a `Gitea` entry with source `signature:builtin-gitea` and one with source `signature:eval-gitea`

### REQ-SCAN-014: Outdated findings
For every recorded service `(*scan.Scanner).Run` SHALL append the findings of `detect.Outdated` over the service's
merged technologies. `detect.Outdated` reads the embedded table `internal/detect/outdated.yaml` (name, minimum, latest,
checked) and returns at most one finding per table entry of kind `outdated` (`detect.KindOutdated`), signature id
`outdated-<product>`, the detected version, the technology's confidence and evidence naming the detected version, the
minimum supported version and the date the table entry was checked (never the latest release), for each
technology whose name equals a table entry case-insensitively and whose leading dotted numeric version is lower than
the minimum. A detected version with fewer parts than the minimum SHALL be compared with the minimum cut to the same
number of parts (Drupal `10` against `10.5` is not outdated). Every table entry SHALL state the date (`checked`,
`YYYY-MM-DD`) its minimum was checked; the table SHALL cover at least WordPress, PHP, nginx, Apache (httpd), OpenSSH,
vsftpd, MySQL, phpMyAdmin, Apache Tomcat, Jenkins, Grafana, Elasticsearch, Redis, ActiveMQ, Joomla, Drupal and Gitea.

#### Scenario: old versions
- WHEN a service shows vsftpd 2.3.4, OpenSSH 7.4, MySQL 5.7.44 or PHP/5.6.40 in `x-powered-by`
- THEN the service has a finding `outdated-vsftpd`, `outdated-openssh`, `outdated-mysql` or `outdated-php`
- AND a version equal to the table minimum or latest, an empty or non-numeric version and a product not in the table
  yield no `outdated` finding

#### Scenario: Vulhub products
- WHEN a service shows Apache Tomcat 8.0.43, Jenkins 2.441, Grafana 8.2.6, Apache 2.4.49, Elasticsearch 1.4.2,
  Redis 4.0.14 or ActiveMQ 5.17.3
- THEN it has the matching `outdated-*` finding, and the current release of each of those products has none

#### Scenario: one Apache finding per service
- WHEN a service's technologies name Apache 2.4.25 twice
- THEN it has one `outdated-apache` finding

### REQ-SCAN-015: HTTP probe of unidentified ports
For every open TCP port the scanner SHALL send HTTP only on evidence. A port that nmap names `https`, `https-*` or
`ssl`, or `http*` over an `ssl` tunnel, SHALL get one HTTPS probe. A port that nmap names `http*` without an `ssl`
tunnel SHALL get a plain HTTP probe first and one HTTPS probe only when the plain probe fails without a timeout, so a
port that answers both keeps its plain-HTTP result. A port whose service nmap did not confirm by probing (an empty
name, `unknown`, `tcpwrapped`, or a name guessed from the port number, XML service `method="table"`) SHALL get one
plain HTTP probe, or one HTTPS probe when nmap reports an `ssl` tunnel. A service nmap confirmed by probing
(`method="probed"`) as anything other than HTTP SHALL get no HTTP request, whatever its name. Industrial and
raw-printing services SHALL never get HTTP, even when the name is a guess or nmap names them HTTP: the names `modbus`,
`mbap`, `s7comm`, `iso-tsap`, `bacnet`, `dnp`, `dnp3`, `iec-104`, `iec-60870-5-104`, `enip`, `ethernetip*`, `opc-ua`,
`opcua`, `opcua-tcp`, `fins`, `omron-fins`, `mqtt`, `secure-mqtt`, `jetdirect`, `pdl-datastream`, `printer`, and the
ports 102, 502, 515, 789, 1911, 1962, 2222, 2404, 4840, 4911, 5007, 9100-9103, 9600, 18245, 18246, 20000, 20547,
34962-34964, 44818 and 47808. When the plain probe of an unconfirmed port gets an HTTP response, the service SHALL be
recorded as `http` with the full HTTP data, technologies and findings. When the first bytes of the answer are a TLS
record (`0x15` or `0x16` followed by `0x03`), one HTTPS probe SHALL follow, and on success the service SHALL be
recorded as `https`. When neither answers, an unconfirmed port SHALL keep nmap's name, product and version and get no
`http` data, so no `http.error` is recorded for such a port (also not on a timeout). When TLS was indicated (nmap's
`https`/`ssl`-tunnel name, or a TLS record in answer to plain HTTP on an `http*` port) and the HTTPS probe fails, the
service SHALL be recorded with `http.scheme` `https`, its URL and `http.error` (`tls handshake failed`,
`request failed` or `timeout`), and a service named `https` SHALL be recorded as `http`.

#### Scenario: httpbin reported as tcpwrapped
- WHEN nmap reports port 8888 as `tcpwrapped` and the port serves httpbin
- THEN the exported service is `http` with status 200, title `httpbin.org` and the `server` header

#### Scenario: TLS server on an unidentified port
- WHEN nmap names a port `unknown` and the server answers a plain request with a TLS alert
- THEN one HTTPS probe follows and the service is recorded as `https` with TLS certificate data

#### Scenario: PostgreSQL with an empty name
- WHEN nmap reports a PostgreSQL port with an empty service name and service detection is `light`
- THEN it gets one plain HTTP connection, no HTTPS probe, and is recorded with an empty service and no `http` data

#### Scenario: service confirmed by nmap as non-HTTP
- WHEN nmap reports `ssh`, `rtsp` or `postgresql` with `method="probed"`
- THEN the port gets no HTTP request; the same names with `method="table"` get one plain HTTP probe

#### Scenario: industrial port with an unidentified service
- WHEN nmap reports port 502 with an empty name or port 9100 as `tcpwrapped`
- THEN the port gets no HTTP request

#### Scenario: port speaking both plain HTTP and TLS
- WHEN nmap names a port `http` and it answers plain HTTP and TLS (Traefik entry point)
- THEN the plain-HTTP answer is recorded in every run, and two runs of the unchanged stack produce no change

#### Scenario: failed TLS handshake
- WHEN nmap names a port `https`, or `http` over `ssl`, and the TLS handshake fails
- THEN the service is exported as `http` with `http.scheme` `https` and `http.error` `tls handshake failed`

### REQ-SCAN-016: Recheck runs
A run whose settings have `mode` `recheck` SHALL, before any nmap call, take its known services from
`Store.RecheckPlan` (REQ-INVENTORY-025) and keep those whose address is in the run's targets minus excludes; without a
base or without such a service the run SHALL fail with an error wrapping `inventory.ErrNoRecheckBase`
(`no earlier run to recheck`) and make no nmap call. `(*scan.Scanner).PlanRecheck(ctx, run)` SHALL make the same check
without a stored run. The run SHALL then scan only the known hosts, in the order of the known services (the settings'
`hosts` order when set), in groups as in REQ-SCAN-001. When all hosts of a group have the same known ports the group
is scanned as one batch (one `Discover`, one `Services` for the hosts found up, and the second service pass); otherwise
the group is scanned as one such batch per known port, holding the hosts that know that port, with that port as the only
`Discover` probe port and `Services` port, and the batches run concurrently within the run's nmap slots (REQ-SCAN-034). The number of
nmap calls of a group is so bounded by its distinct known ports, never by its number of hosts, and no address outside
the known hosts and no port outside a host's known services is contacted. A host's services from several batches are
merged into one host result, ordered by port. Only known services that were HTTP in the base (or whose base service
name is an HTTP/TLS name) SHALL be probed over HTTP. Each recorded group SHALL carry `CoveredPorts` (the known ports of
every address), so a recheck covers only what it contacted. The address total (REQ-SCAN-006) of a recheck is the number
of known hosts. The re-probe (REQ-SCAN-005) SHALL be limited to known hosts and their known ports.

`asi scan run` SHALL take `--mode full|recheck` (default `full`, stored as the legacy empty mode that reads as `full`);
any other value exits 1 with one line naming `--mode` and `full|recheck` before any database access or nmap call. For
`--mode recheck` the CLI SHALL check the plan before creating the run and, without a base, exit 1 with
`no earlier run to recheck` and create no run.

#### Scenario: only known services are contacted
- WHEN a recheck over 10.0.0.0/24 has the known services 10.0.0.5:80, 10.0.0.5:443 and 10.0.0.9:22
- THEN every `Discover` and `Services` call contains only 10.0.0.5 and 10.0.0.9 and only their known ports
- AND HTTP probe requests go only to 10.0.0.5:80 and 10.0.0.5:443
- AND a full run over the same targets calls `Discover` for every address

#### Scenario: nmap calls do not grow with the hosts
- WHEN a recheck of 2 hosts and a recheck of 11 hosts in one group have the same known ports 22, 80, 6379 and 8080
- THEN both make the same number of nmap calls, fewer than 11

#### Scenario: uncontacted host keeps its state
- WHEN a full run saw A on 80 and B on 22 and a recheck with `--ports 80` follows
- THEN B has the same status, `missed_runs` and stability as before and the diff has no change
- AND a known host found down in a later recheck is `unstable` with `missed_runs` 1 and yields `host_missing`

#### Scenario: service changes
- WHEN after a full run X:80 changes its title, Y:80 closes and the unstable Z:80 opens again
- THEN the diff to the recheck is `service_changed` (http.title) for X, `service_missing` for Y, `service_returned` for Z

### REQ-SCAN-017: Packet count
Every run SHALL add to its stored packet count (`Store.AddRunPackets`, `runs.packets`) what it sent: per `Discover`
call `len(addrs) × (1 + len(probe ports))`, per `Services` call `len(addrs) × len(ports)`, plus one per probe HTTP
request (root, redirects, favicon, signature paths), the re-probe included; a resumed run adds to the count of its
earlier attempts. `asi scan show NAME` SHALL show `mode=<full|recheck> packets=<N>` on its first line after
`finished=…` (before `groups=`, so the line still ends with the REQ-SCAN-009 figures).

#### Scenario: lab-sized saving
- WHEN the lab's targets, excludes and ports are scanned in full and then rechecked with the lab's known services
- THEN the recheck sends at most 10% of the full run's packets

### REQ-SCAN-018: Adaptive rate
Unless `RunSettings.NoAdaptive` (`asi scan run --no-adaptive`, JSON `no_adaptive`; default off, so adaptive is on) is
set, every run SHALL own a `scan.Controller` (`scan.NewController(maxRate, clock)`, injectable `scan.Clock`) that sets
the run's effective rate. Every probe HTTP request of a port nmap identified as HTTP or HTTPS SHALL report its response
time (from the moment the rate limiter lets it go until its body is read or it fails) and whether it timed out. The
GETs sent to unidentified or guessed ports (REQ-SCAN-015) SHALL use a short timeout, `scan.GuessTimeout` (3 s, or
the HTTP timeout when that is shorter), and SHALL NOT be reported to the controller, so targets that accept and hang
on such ports do not slow the run. The baseline is the median of the first
`scan.AdaptiveWindow` (20) answered requests of the run, at least `scan.AdaptiveMinBaseline` (10 ms, so a few
milliseconds of jitter on a fast network do not count as a slowdown). Once the last 20 requests are known and at least
`scan.AdaptiveInterval` (5 s) passed since the last change, the controller SHALL halve the effective rate (never below
the floor `scan.MinimumRate(maxRate, slots)`: 10% of the max rate rounded up, at least 2 x the run's nmap slots
`scan.NmapSlots(workers, maxRate, addresses)` = min(workers, max rate / 2, addresses), never above the max rate; so
nmap's minimum of one packet per second per slot always fits in the effective rate) when their median exceeds 2x the
baseline or more than 10% of them timed out, and otherwise raise it by 10% of the max rate (at least 1), never above
the max rate. After a change the window starts empty. The effective rate replaces the max rate in the split of
REQ-SCAN-002: the probe's limiter gets effective - effective / 2 per second and every nmap call started afterwards gets
`Options.MaxRate` = max(1, (effective / 2) / slots). A recheck counts its slots over its known hosts.

#### Scenario: decrease, floor and recovery
- WHEN a controller with max rate 100 sees 20 answers of 40 ms and then 20 of 81 ms
- THEN the rate is 50; further slow windows, one per 5 s of the fake clock, give 25, 12, 10, 10
- AND windows of 60 ms afterwards raise it by 10 per 5 s up to 100 and never above

#### Scenario: timeouts
- WHEN 3 of the last 20 requests timed out at max rate 300
- THEN the rate is 150 and the floor is 30

#### Scenario: hanging unidentified ports
- WHEN 30% of the open ports of every host are unidentified and accept but never answer
- THEN their probes give up after at most 3 s, every sample keeps the effective limit at the max rate and no host is paused

#### Scenario: low max rate
- WHEN a run with max rate 10 and 4 workers backs off
- THEN its effective limit never drops below 8 (one nmap packet per second for each of 4 slots, as much for the probe)

### REQ-SCAN-019: Per-host pause
Within a group, a host whose probe attempts of identified HTTP ports time out `scan.PauseAfterTimeouts` (3) times in
a row (an answer of any kind resets the count; attempts on unidentified or guessed ports neither count nor reset)
SHALL get no further probe attempts in that pass. After every host of the group was probed,
each paused host SHALL be retried once: its ports without an answer (timed out or skipped) are probed again with a
fresh count. A port that the retry leaves unanswered without any attempt SHALL be recorded with `http.error =
"timeout"` and the URL and scheme of its first scheme (like REQ-SCAN-010; an unconfirmed port of REQ-SCAN-015 gets no
`http` data), so the diff treats it as unknown. The host
and all its open ports SHALL be recorded with the group whatever the retry gives, so a pause
never makes a host missing or re-probed.

#### Scenario: host that always times out
- WHEN a host has 12 open HTTP ports that all stall and `--http-timeout` is 100ms
- THEN at most 8 root requests reach it, and the group records the host with 12 open services, each with
  `http.error = "timeout"`, and no failed group

#### Scenario: host that recovers
- WHEN the first 4 requests to a host time out and later ones are answered
- THEN after the retry every one of its 12 services has an HTTP answer

### REQ-SCAN-020: Measured rate
Every run SHALL store per-minute samples (`run_rate_samples`: UTC minute, configured limit = max rate, effective
limit = the highest effective rate in force during the minute, sent, estimated_packets) through
`Store.RecordRateSamples`, after every recorded group and when the run stops. Sent is measured: it counts every probe
HTTP request when the limiter lets it go. Estimated packets are not measured: each nmap call counts addresses x
(1 + ports) for discovery and live addresses x ports for the service scan, spread evenly over the minutes of the
call. The run's `packets` (REQ-SCAN-016) SHALL be the same sum, so `packets` = sum of sent + sum of estimated packets.
Besides the token bucket the probe limiter SHALL let at most 60 x its rate requests go in one UTC minute, so the
measured sent of a minute never exceeds 60 x the probe's share of the effective limit (effective - effective / 2).
`scan.SummarizeRate` gives the peak (highest sent / 60) and the average (sum of sent / (60 x minutes)) of the measured
requests, their total, and the total, peak and average of the estimated packets. `asi scan show NAME` SHALL print
`packets=N requests_measured=R nmap_packets_estimated=E` (N = R + E) and
`max_rate=M adaptive=B actual_peak=P/s actual_avg=A/s actual_chart=C limit_chart=L` on its first line after
`finished=…` (P, A and C from the measured requests; C and L: one block character per minute, at most 60, scaled to
the max rate; `-` without samples). The run page `/runs/{id}` SHALL show a Rate panel with max rate, adaptive on/off,
peak and average sent per second, the measured HTTP requests, the estimated nmap packets (labelled "estimated"), with
adaptive on the lowest rate of REQ-SCAN-018 and the nmap slots, a sentence saying what is measured and what is
estimated, and an inline SVG chart (`svg.chart`, `rect.sent` per minute for measured requests plus estimated packets,
`polyline.limit` for the effective limit, no inline styles).

#### Scenario: measured requests never above the probe's share
- WHEN a run with max rate 20 probes 1 000 hosts with a fake clock, steady or with targets that slow down, adaptive on or off
- THEN every sample has sent <= 60 x 10, steady samples stay at or below their effective limit
- AND only the adaptive run with slow targets has samples with an effective limit below 20

#### Scenario: one formula
- WHEN a run completes
- THEN the sum of sent equals the probe requests, the sum of estimated packets equals the nmap estimate, and both add up to `packets`

### REQ-SCAN-021: Plan preview
`(*scan.Scanner).Plan(ctx, settings)` and `(*scan.Scanner).PlanRun(ctx, run)` SHALL expand targets minus excludes like
a run and contact no target: they return the addresses, ports, groups (addresses / group size, `scan.InitialGroupSize`
unless `GroupSize` is set), worst-case nmap packets (`scan.DiscoveryPackets` = addresses x (1 + ports) x 2, plus
`scan.ServicePackets` = addresses x ports x 10), worst-case HTTP requests (addresses x ports x `scan.RequestsPerPort`,
86: HTTP and HTTPS, root, favicon and 5 signature paths, each with 5 redirects, plus one timed-out attempt per scheme
before a retry), the worst-case duration at the max rate (the larger of packets / (max rate / 2) and requests / (max
rate - max rate / 2)), the nmap slots and the lowest rate (REQ-SCAN-018; the max rate when adaptive is off), and an
estimate range (`EstimateLow`, `EstimateHigh`). Without a measured speed the estimate SHALL charge every address
the discovery packets and only the live share (`Plan.LiveShare`, `scan.DefaultLiveShare` 5%) the service packets and
HTTP requests: low = the larger of (addresses x (1 + ports) + service packets of the live share) / max rate and
(live x ports x 2) / max rate; high = the larger of (discovery packets + service packets of twice the live share) /
(max rate / 2) and (twice the live x ports x 2 x 6) / (max rate - max rate / 2). `Plan.UseLiveShare(share)` replaces
the live share. In recheck mode (`Mode` recheck) the plan SHALL cover only the known services of the recheck base
(REQ-SCAN-016): addresses = hosts with a known service, ports = their ports, packets per host from its own known
ports, requests only for known HTTP services, plus the base run's name and the number of known services; without a
base it fails with `inventory.ErrNoRecheckBase`. `Plan.Measured(addressesPerSecond)` adds the duration at a measured
speed and makes the estimate that duration x 0.8 to x 1.25. `asi scan plan` SHALL take the flags of `scan run`
(`--name` and `--wait` optional, `--mode recheck` included), create no run, and print
`plan addresses=N ports=P groups=G group_size=S packets=K requests=R max_rate=M adaptive=B duration_at_max_rate=D measured_run=X measured_rate=V/s duration_measured=E`
where X is the newest completed run with the same targets and excludes and a measured speed above 0 and V its addresses per second (REQ-SCAN-009);
`-` without such a run; then `plan_mode mode=<full|recheck> base_run=<run|-> services=<n|-> nmap_slots=S min_rate=F`,
in recheck mode a line `recheck: only the N known open services of run X are planned, …`, and with adaptive on a line
`lowest rate when backing off: F/s, …`. `GET /scans/{id}/preview` (permission `scan.run`), linked as "Preview" from the
scan page, SHALL show the addresses, ports, groups, packets and requests at most, the lowest rate with adaptive on, the
"Estimated duration" as a range ("about 2-11 min"; "about 1 min or less" below a minute; whole hours above 90 minutes) and the
live share assumed, using the measured speed and the live share (hosts found / addresses of its groups) of the newest
completed full run (not a recheck) of that scan definition that has a measured speed; `asi scan plan` SHALL skip
recheck runs likewise. The page SHALL NOT show the worst-case duration. `GET /scans/{id}/preview?mode=recheck`, linked
as "Preview recheck", SHALL plan the recheck against the newest completed run of the definition and say so, answer
422 without such a run and 400 for an unknown mode.

#### Scenario: plan of a /24 minus a /28
- WHEN `Plan` gets 10.0.0.0/24 minus 10.0.0.0/28, ports 443,80 and max rate 100
- THEN it returns the expanded address count, ports [80 443], 4 groups of 64 and no nmap call or request was made

#### Scenario: plan of a recheck
- WHEN `Plan` gets recheck mode and the base knows 80 and 443 on one host and 22 on another
- THEN it plans 2 hosts, 3 services, ports [22 80 443], requests for the two HTTP services only, and sends nothing

#### Scenario: a /18 estimates minutes
- WHEN a scan of 10.0.0.0/18 with 6 ports at max rate 1000 has no earlier run
- THEN the preview shows an estimate in minutes ("about N-M min", below an hour) and no "h min" duration
- AND the lab /24 with its 7 ports at max rate 300 estimates under 2 minutes

### REQ-SCAN-022: Second service pass and light probe set
The light service pass (`nmap -Pn -sT -sV --version-light`) SHALL treat nmap's soft matches as final: when the
installed `nmap-service-probes` is found (`$NMAPDIR`, `<nmap binary>/../share/nmap` or the binary's directory),
`nmap.ExecRunner` SHALL pass nmap a temporary copy (`--versiondb`) in which every
`softmatch` line except `softmatch ssl` is a `match` line placed after the hard matches of its probe
(`nmap.WriteLightProbes`); without the file it runs with nmap's own probes. A scan run SHALL write that copy once
(`nmap.LightProber`, on its first light pass), reuse it for every group of the run and remove it when the run ends;
a direct `Services` call without `Options.VersionDB` writes its own copy and removes it after the call. A port the
light pass identified only through such a converted soft match (its service and product fit a `softmatch` template of
the installed file and it carries no version or extra info the template does not produce) SHALL be marked
`nmap.Port.Soft` and counts as unconfirmed for the second pass, so stopping at the first soft match never loses an
identification that stock `nmap -sV --version-light` gives. With the run setting
`service_detection` `standard` (the default; `asi scan run --service-detection light|standard`, stored as
`RunSettings.ServiceDetection`) the scanner SHALL then run one more `Services` call at nmap's default intensity
(`nmap.Options.Standard`: no `--version-light`, nmap's own probes) for the open ports the light pass left without a
confirmed service (empty name, `unknown`, `tcpwrapped`, `method="table"`, or `Soft`) and for the ports REQ-SCAN-023
leaves without a product whose service is `ftp`, `ssh`, `smtp`, `pop3` or `imap` or whose nmap product is the generic
`Advanced Message Queue Protocol`, excluding the never-probe ports and service names of REQ-SCAN-015. With `light` the
scanner SHALL run, for the `Soft` ports only, one `Services` call with nmap's own probes at `--version-light`
(`nmap.Options.StockProbes`). Hosts are grouped by the exact set of such ports, so no host is probed on a port that
was not flagged on it, and all hosts of a group with the same set go into one call. The calls of a group SHALL run in
parallel in the one nmap slot of the group and split the light pass's `--max-rate` share between them (at most as
many calls at once as that share in packets per second), so silent hosts are waited for at the same time and the
run's rate is not exceeded. Each such call SHALL carry `--host-timeout` of `scan.SecondPassPerPort` (20 s) per probed
port, at most `scan.SecondPassHostMax` (90 s) and at most the scanner's `HostTimeout` when one is set, and
`--max-retries` `scan.SecondPassRetries` (1) (`nmap.Options.MaxRetries`). A host nmap reports as timed out
(`timedout="true"`, `nmap.Host.TimedOut`) keeps its light pass results and gets a note in
`inventory.HostResult.Notes`, which the inventory stores with the host observation of that run
(`host_observations.notes`) and returns in `inventory.HostRunEntry.Notes` of `Inventory.HostDetail`; the group still
completes. An open result replaces the light result of that port before the HTTP probe, except that a confirmed light
result is not replaced by an unconfirmed one: it only takes that result's banner. Any other `service_detection` value
is rejected before nmap runs.

#### Scenario: PostgreSQL on a non-standard port
- WHEN the light pass reports 15432 open with an empty name and the second pass reports `postgresql`
- THEN only the unconfirmed ports get the second pass and 15432 is exported as `postgresql` without an HTTP probe

#### Scenario: soft match on a slow Go HTTP server
- WHEN a single host has Gitea on 3001 (nmap soft-matches `Golang net/http server`) and four other identified ports
- THEN the light pass of the five ports finishes in about 11 s instead of 48 s, and only 3001 gets a second pass

#### Scenario: InfluxDB behind a Go soft match
- WHEN the light pass with the converted probes reports 8086 as `Golang net/http server` and stock
  `nmap -sV --version-light` reports `InfluxDB http admin` 1.6.6 (recorded XML)
- THEN 8086 is exported as `InfluxDB http admin` 1.6.6 in both `light` and `standard` mode

#### Scenario: Dovecot, soft-matched vsFTPd and RabbitMQ after the light pass (recorded nmap 7.97)
- WHEN the light pass reports pop3 and imap without a product for Dovecot, ftp without a product for the banner
  `220 ftp.example.org FTP server (vsFTPd 3.0.5) ready` and amqp `Advanced Message Queue Protocol` for
  rabbitmq:3-management
- THEN those ports get the second pass, pop3/imap are exported as `Dovecot pop3d`/`Dovecot imapd` and ftp as vsftpd
  3.0.5 from the banner in nmap's fingerprint, and 5672 as RabbitMQ 3.13.7; ports nmap already named get no second pass

#### Scenario: ftp and ssh without a product
- WHEN the light pass reports ftp on 21 and ssh on 7000 without a product
- THEN both ports get the standard second pass and its open, confirmed result replaces the light result

#### Scenario: one probe copy per run
- WHEN a run of 4 groups of one host each runs the light pass through `nmap.ExecRunner`
- THEN all 4 nmap calls get the same `--versiondb` file and no copy is left in the temp directory after the run

#### Scenario: three listeners that accept and never answer
- WHEN 127.0.0.1 has three ports that accept TCP and never send a byte and the run uses the default `standard`
  detection
- THEN the second pass is bounded at 60 s, the scan finishes in under 120 s (about 90 s with nmap 7.99 instead of
  about 220 s), the three ports keep their light pass results and the host gets a timeout note

#### Scenario: three silent hosts with different flagged ports
- WHEN three hosts each leave a different port unidentified after the light pass and never answer the second pass
- THEN the three second-pass calls are in flight at the same time, their `--max-rate` values add up to at most the
  light pass share, and each host keeps its light result with a timeout note

### REQ-SCAN-023: Failed and partial HTTP probes
When the HTTP probe of an open port fails before any response (host gone, reset, refused), the service SHALL carry
`http.error` saying what failed and no status code, title, headers, cookies, redirect chain, TLS or favicon (`scheme`,
`url` and `response_time_ms` describe the attempt, as for timeouts). When the status line and headers arrived but the
body failed (slow body, endless chunked encoding, connection cut) or a header line was invalid, the status code, the
valid headers, the cookies and the title read so far SHALL be kept and `http.error` SHALL say what failed (`timeout`
for a deadline, as in REQ-SCAN-010). Titles SHALL be capped at `probe.MaxTitleRunes` (512) and cookie names at
`probe.MaxCookieRunes` (256) characters, ending in `…` when cut. The diff treats such services as REQ-DIFF-009 says.

#### Scenario: host gone between discovery and probing
- WHEN a host is open in run 1, resets the probe in run 2 and is open again in run 3
- THEN run 2 records `http.error` only and neither diff reports `service_changed`

### REQ-SCAN-024: Heartbeat and stalled runs
While a run executes, the scanner SHALL write `runs.heartbeat_at` (`Store.Heartbeat`) at start and at least every 10 s
(`scan.HeartbeatInterval`). A `running` run whose heartbeat (or start, without one) is older than 60 s is stalled
(`inventory.Run.Stalled`): `asi scan show` SHALL print `status=stalled (process gone)` and the run page SHALL show
"Stalled (process gone)". `asi scan resume` SHALL accept a stalled run and refuse, with a one-line error and without
calling nmap, a `running` run that is not stalled (its scanner is still alive). On SIGTERM the CLI SHALL kill every nmap child
process group before it exits and leave the run `paused`.

#### Scenario: scanner process killed
- WHEN the `asi scan run` process is killed and its heartbeat is 61 s old
- THEN `scan show` reports `status=stalled (process gone)` and `scan resume` completes the run

### REQ-SCAN-025: Database outage while recording
A failed write of a finished or failed group, or of the rate samples written after a group, SHALL be retried with
exponential backoff (1 s doubling, at most `scan.StoreRetryMax`) for up to `scan.StoreRetryFor` (60 s). When it still
fails the run SHALL stop with status `paused`, resumable, and a one-line error wrapping `scan.ErrStoreUnavailable`. The
final status write SHALL itself be retried for up to `scan.StatusRetryFor` (30 s); when the database is still down
then, the row keeps `running`, the error SHALL say that the paused status could not be written, and the run shows as
stalled after 60 s and is resumable.

#### Scenario: store fails three times then recovers
- WHEN `RecordGroup` fails three times and then succeeds
- THEN the run completes with every host recorded

#### Scenario: rate-sample write fails after the group is saved
- WHEN `RecordRateSamples` keeps failing after a group was recorded
- THEN the write is retried and the run ends `paused`, not `failed`

### REQ-SCAN-026: Master key check
`asi scan run` and `asi scan resume` SHALL check, before they create a run or send anything, that the stored encrypted
data decrypts with `ASI_MASTER_KEY` or a key in `ASI_MASTER_KEY_PREVIOUS` (`store.Store.CheckKeys`, run for every
inventory command) and refuse with a one-line error naming `ASI_MASTER_KEY` otherwise.

#### Scenario: wrong key
- WHEN a scan has been recorded and `asi scan run` is started with another master key
- THEN it exits 1 with `ASI_MASTER_KEY cannot read stored data: …`, creates no run and calls no nmap

### REQ-SCAN-027: Target bound and groups nmap skipped
`asi scan run` SHALL refuse a run whose targets, counted with `targets.Count` (ranges and networks as written, minus
the excludes, each host name counted once), exceed `--max-addresses` (default `scan.DefaultMaxAddresses`, 262144). It
SHALL do this before it opens the database or sends anything, with a one-line error naming the count and the flag.
When nmap exits successfully but reports that it scanned none of the group's targets (`nmap.ErrNoTargetsScanned`, for
example after `Failed to determine route`), the group SHALL be recorded as a failed group whose reason carries nmap's
message, not as a finished group with 0 hosts. On context cancel the nmap child SHALL be killed with its whole process
group.

#### Scenario: a /8 with the default bound
- WHEN `asi scan run` is given `10.0.0.0/8`
- THEN it exits 1 with one line naming 16777216 and `--max-addresses`, and neither the database nor nmap is contacted

#### Scenario: no route to any target
- WHEN nmap prints `Failed to determine route to 192.0.2.10` and an empty run for the group
- THEN the group is listed as a failed group with that reason and no finished group is recorded

### REQ-SCAN-028: Settings and signatures checked before a run exists
`asi scan run` SHALL check its settings and complete signature set (`(*scan.Scanner).Validate`: ports, targets,
excludes, `--signatures-dir` combined with the built-in and stored signatures, max rate) before creating the run; an
invalid set SHALL exit non-zero with the error and leave no run behind.

#### Scenario: signature id clashes with a built-in
- WHEN `--signatures-dir` holds a signature with id `builtin-grafana`
- THEN `asi scan run` exits non-zero naming the rule and the number of runs is unchanged

### REQ-SCAN-029: Work ceiling
`scan.CheckWork(settings)` SHALL refuse settings whose targets, counted with `targets.Count`, times the number of
distinct ports exceed the ceiling `settings.MaxWork` (`max_work`; 0 means `scan.DefaultMaxWork`, 262144 addresses x
1000 ports), with an error wrapping `scan.ErrTooMuchWork` that names the address count, the port count, their product
and the ceiling. `asi scan run` and `asi scan plan` SHALL run the check before they open the database or send
anything (`--max-work N` sets the ceiling; `--max-addresses` still applies on its own), and `(*scan.Scanner).Plan`
SHALL return the same refusal.

#### Scenario: a /14 with 1001 ports
- WHEN `asi scan run` or `asi scan plan` is given `10.0.0.0/14` and `--ports 1-1001`
- THEN it exits 1 with one line naming 262144 addresses and 1001 ports, and neither the database nor nmap is contacted

#### Scenario: a raised ceiling
- WHEN the same targets and ports are given with a ceiling of at least 262144 x 1001
- THEN the check passes

### REQ-SCAN-030: Product from banners and script properties
`nmap.Parse` SHALL read a port's banner (`nmap.Port.Banner`) from the `r(NULL,…)` response of the service fingerprint
(`servicefp`, nmap escapes decoded, `\nSF:` continuations joined) or else from the output of the `banner` script, and
the top-level `product` and `version` elements of a port's scripts (such as `amqp-info` server properties) into
`nmap.Port.ScriptProduct` and `ScriptVersion`. Before recording a service the scanner SHALL drop the generic nmap
product `Advanced Message Queue Protocol`; when the product is then empty it SHALL take the script product and version
when present, or else map the banner or nmap's extra info by a small table (`internal/scan/banner.go`):
`ftp` `(vsFTPd <v>)` → `vsftpd`, `ProFTPD [<v>]` → `ProFTPD`, `Pure-FTPd` → `Pure-FTPd`; `ssh` `SSH-…-OpenSSH_<v>` →
`OpenSSH`; `smtp` `ESMTP Postfix` → `Postfix smtpd`, `ESMTP Exim [<v>]` → `Exim smtpd`; `pop3`/`imap` `Dovecot` →
`Dovecot pop3d`/`Dovecot imapd`; `amqp` `RabbitMQ [<v>]` → `RabbitMQ`, with the version from the banner when it has
one. A product nmap already named is kept; an AMQP port nothing identifies stays `amqp` without a product.

#### Scenario: banners in recorded nmap output
- WHEN nmap reports ftp, ssh, smtp, pop3 and imap without a product and with the banners of vsftpd 3.0.2, OpenSSH 9.6p1,
  Postfix, Exim 4.96, Dovecot, ProFTPD 1.3.8 and Pure-FTPd
- THEN the services are recorded with those products and versions, and ftp has the technology `vsftpd` 3.0.2

#### Scenario: RabbitMQ on AMQP
- WHEN nmap reports amqp "Advanced Message Queue Protocol" with `amqp-info` product RabbitMQ version 3.13.7 on one host
  and without it on another
- THEN the first service has the technology `RabbitMQ` 3.13.7 and the second is `amqp` without a product or technology

### REQ-SCAN-031: Favicon stability within a run
`(*probe.Prober).Probe` SHALL fetch `/favicon.ico` a second time when `probe.Prober.PreviousFavicon` is set and returns
a non-empty hash different from the first fetch, counting the second fetch against
`probe.MaxExtraRequests`. When the two fetches do not return identical bytes, or the cap is reached, the probe SHALL
set `http.favicon_unstable` to `true`. The scanner SHALL set `PreviousFavicon` from the favicon hashes of the latest
observation of each TCP service before the run (`(*inventory.Inventory).PreviousFavicons`).

#### Scenario: favicon different per request
- WHEN a server returns different favicon bytes on every request
- THEN the probe fetches the favicon twice and records `favicon_unstable: true`

#### Scenario: favicon unchanged since the previous run
- WHEN the favicon hash equals the one of the previous run
- THEN the favicon is fetched once and no extra request is used

### REQ-SCAN-032: Outdated FTP servers
The outdated table SHALL contain vsftpd (minimum 3.0.3), ProFTPD (minimum 1.3.7) and Pure-FTPd (minimum 1.0.50), the
oldest releases shipped by a current LTS distribution, so an FTP server older than its supported line gets an
`outdated` finding.

#### Scenario: vsftpd 3.0.2
- WHEN nmap reports ftp vsftpd 3.0.2
- THEN the service has a finding `outdated-vsftpd`
- AND vsftpd 3.0.5, ProFTPD 1.3.7c yield no `outdated` finding, while ProFTPD 1.3.6 and Pure-FTPd 1.0.49 do

### REQ-SCAN-033: Never-probe ports get no service detection
The ports of the never-probe list of REQ-SCAN-015, and the default ports of its never-probe service names (1883
`mqtt`, 8883 `secure-mqtt`, 9104-9107 `jetdirect`), SHALL be passed to `Services` in `nmap.Options.NoVersion`, and
`nmap.ExecRunner` SHALL scan them with a connect scan without `-sV` (`nmap.PortsArgs`: `-Pn -sT -p <ports>`), so
nmap sends none of its own protocol probes (for example the MQTT CONNECT to 1883) to them. They SHALL be reported open
with the name of nmap's port table, get no HTTP request and carry the finding `builtin-not-probed-by-policy` (kind
`custom`, name `Not probed by policy`, confidence 100) whose evidence names the port and that name.

#### Scenario: MQTT and Modbus in the port list
- WHEN a run scans ports 80, 502, 1883, 8883 and 9100 of a host
- THEN no `-sV` call contains 502, 1883, 8883 or 9100, those ports are exported open (1883 as `mqtt`) with
  `builtin-not-probed-by-policy`, and only port 80 gets an HTTP request

### REQ-SCAN-034: Recheck batches run side by side
Within a recheck group, the batches of REQ-SCAN-016 (one per known port when the hosts' known port sets differ) SHALL
run concurrently, bounded by the run's nmap slots, instead of one after another, so a recheck of the known services is
not slower than the full scan of the same targets.

#### Scenario: 3% live hosts
- WHEN a /24 has 8 live hosts with different known port sets and each fake nmap call takes 2 s plus its packets at its `--max-rate`
- THEN the recheck takes less time than the full scan of the same targets
- AND it sends at most 10% of the full scan's packets
