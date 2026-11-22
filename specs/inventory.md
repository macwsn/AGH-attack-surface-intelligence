---
capability: inventory
title: Inventory of hosts, services and observations
code: []
tests: []
---
# Inventory of hosts, services and observations

## Requirements

### REQ-INVENTORY-001: Runs
`(*inventory.Inventory).CreateRun(ctx, RunSpec{Name, InactiveAfter})` SHALL create a run with a unique non-empty name
and its own inactivity threshold `N`; `InactiveAfter <= 0` SHALL store the default 3.

#### Scenario: default threshold
- WHEN a run is created with `InactiveAfter: 0`
- THEN the returned `Run` has `InactiveAfter == 3`

### REQ-INVENTORY-002: Idempotent group recording
`(*inventory.Inventory).RecordGroup(ctx, runID, GroupResult)` SHALL write one group in one transaction: the group's
completion record, its covered addresses (`GroupResult.Addresses` plus every reported host), and a host observation,
service observations, technologies and findings for every reported host. Recording the same `(run, group index)` again
SHALL replace the earlier recording of that group, so row counts and the export stay as after the first call. An
unknown run id SHALL return an error wrapping `inventory.ErrUnknownRun` and write nothing.

#### Scenario: resumed run
- WHEN group 0 of run r1 is recorded twice with the same result
- THEN every observation, technology and finding table has the same number of rows as after the first call
- AND recording group 1 of r1 adds that group's observations

### REQ-INVENTORY-003: Coverage-based status and stability
For a host, the system SHALL consider the covering runs up to the as-of run, starting with the first run that saw the
host; a run covers an address only when the group containing it was recorded. It SHALL derive status with
`inventory.DeriveStatus(seen, N)` and the as-of run's `N`: `active` when seen in the latest covering run, `unstable`
after 1 … N-1 consecutive missed covering runs, `inactive` after N; `missed_runs` is that count and `stability` is the
share of the last 10 covering runs in which the host was seen. A run whose group for the address was not recorded
SHALL NOT count as missed, and misses ignored by REQ-INVENTORY-027 are left out. Services SHALL follow the same model
per (host, port, protocol), seen when the run holds an observation of the service. Every run SHALL record the port list
it covered: the `ports` column of `runs` holds the run's `settings.ports` (NULL when the settings name no port, e.g.
imports). When a group is recorded with `GroupResult.CoveredPorts` (a recheck), each of its addresses covers only the
listed tcp ports plus the services the run observed on it; otherwise, when the run has a port list, each address of
the group covers only the tcp services on those ports plus the services the run observed on it (services of another
protocol stay covered). Any other service of that address is not covered by the run: it is neither missed nor counted
toward `inactive`, and the diff reports no `service_missing` for it.

#### Scenario: group did not complete
- WHEN runs have `InactiveAfter: 2`, host H is seen in r1, missed in r2, its group is not recorded in r3 and H is
  missed again in r4
- THEN the state as of r2 and r3 shows H `unstable` with `missed_runs` 1 and stability 0.5
- AND the state as of r4 shows H `inactive` with `missed_runs` 2

#### Scenario: recheck of part of the services
- WHEN full run r1 sees A on 22 and 80 and B on 22, and recheck r2 records only A with `CoveredPorts` {A: [80]}
- THEN as of r2 B and A:22 have the status, `missed_runs` and stability of r1, and the diff r1 → r2 is empty

#### Scenario: full run on fewer ports
- WHEN full run f1 on ports 22 and 80 sees A on both, and full runs f2 and f3 on port 22 only see A on 22
- THEN as of f2 and f3 A:80 is `active` with `missed_runs` 0, and the diffs f1 → f2 and f2 → f3 report no
  `service_missing` for it

### REQ-INVENTORY-004: User-owned host fields
Tags, notes, display name, owner, criticality and status override SHALL live in their own columns, SHALL be written
only by `(*inventory.Inventory).UpdateHostUserFields` and SHALL never be changed by `RecordGroup`.
`UpdateHostUserFields` on an address never recorded SHALL return an error wrapping `inventory.ErrUnknownHost` and
create no host; a status override other than empty, `active`, `unstable` or `inactive` SHALL be rejected. The status
override is stored and exported as `status_override`; it does not replace the derived `status`.

#### Scenario: edits survive later runs
- WHEN a host's user fields are edited and three more runs record the host with other hostnames and services, or omit it
- THEN `GetHostUserFields` returns exactly the edited values and the export shows the edited tags and notes

### REQ-INVENTORY-005: Encryption of sensitive columns
Response headers, cookie metadata, finding evidence, host notes, host display names and owners, the targets and
excludes of runs (`runs.scope`) and the YAML source of retro-hunts (`hunts.source`) SHALL be stored only as
field-encryption ciphertext produced by `store.Keyring` (AES-256-GCM, key id stored with the value); the plain HTTP
document kept for search and diff SHALL hold no headers and no cookies, and `runs.settings` SHALL hold no targets and
no excludes. Reading through the inventory API SHALL return the original values. The host list (REQ-INVENTORY-016)
SHALL keep searching and sorting by display name by decrypting the display names and passing the matching host ids
and the sort order to the query.

#### Scenario: raw select
- WHEN a host with header value, cookie name, finding evidence and notes markers is recorded and edited
- THEN no `SELECT t::text FROM <table> t` over any table of the schema contains a marker
- AND the export returns all four values verbatim

#### Scenario: owner, display name and run scope
- WHEN a run with target and exclude markers is created and a host gets display name and owner markers
- THEN no table of the schema contains a marker in plain text
- AND the export, the run and a host search by display name return the original values

### REQ-INVENTORY-006: Export state
`(*inventory.Inventory).Export(ctx, asOfRun)` SHALL return the `asi.export/v1` structure for the state as of the named
run, or as of the latest run for an empty name, with each host and service carrying the data of its latest
observation up to that run, hosts sorted by numeric address, services by port then protocol, and `[]` instead of
`null` for hostnames, tags, services, technologies and findings. An unknown run name SHALL return an error.

#### Scenario: state as of an earlier run
- WHEN r1 records host A with title "v1" and r2 records A with title "v2" and a new host B
- THEN the export as of r1 contains only A with title "v1", and the current export contains A with "v2" and B

### REQ-INVENTORY-007: Run status and stored settings
Migration `internal/store/migrations/0004_run_state.sql` SHALL add `runs.status` (`running`, `paused`, `completed`,
`failed`; runs created before the migration become `completed`) and `runs.settings` (JSON). `CreateRun` SHALL store
`RunSpec.Settings` (`inventory.RunSettings`: targets, excludes, ports, signatures dir, max rate, workers, group size)
and create the run with status `running`; a name that already exists SHALL return an error wrapping
`inventory.ErrRunExists` and create nothing. `(*inventory.Inventory).RunByName(ctx, name)` SHALL return the run with
its status, settings and `FinishedAt`; an unknown name SHALL return an error wrapping `inventory.ErrUnknownRun` that
names it, and the empty name SHALL return the latest run. `(*inventory.Inventory).SetRunStatus(ctx, runID, status)`
SHALL set the status, set `finished_at` for `completed` and `failed` and clear it for `running` and `paused`, reject
other statuses and return `inventory.ErrUnknownRun` for an unknown id.

#### Scenario: settings round trip
- WHEN a run is created with settings and looked up by name
- THEN `RunByName` returns status `running`, no `FinishedAt` and settings equal to the stored ones
- AND creating a second run with the same name fails with `ErrRunExists`

#### Scenario: pause and complete
- WHEN a run is set to `paused` and then to `completed`
- THEN it has no `FinishedAt` while paused and has one once completed

### REQ-INVENTORY-008: Group timing
`RecordGroup` SHALL store with each group its address count (covered addresses), the number of hosts found up in it
and `GroupResult.Duration` (nanoseconds, a negative duration is rejected); recording a group again SHALL replace these
values with the group. `(*inventory.Inventory).RunGroups(ctx, runID)` SHALL return every recorded group of the run
ordered by index with its covered addresses, address count, hosts found, duration and completion time, and an empty
slice when none is recorded.

#### Scenario: recorded groups
- WHEN group 1 and then group 0 (twice) are recorded with durations 2 s and 1.5 s
- THEN `RunGroups` returns groups 0 and 1 in order with their addresses, counts and durations

### REQ-INVENTORY-009: Re-probe support
`(*inventory.Inventory).PreviouslyLiveAddresses(ctx, runID)` SHALL return, in address order, the addresses whose status
as of the run preceding `runID` is `active` or `unstable` (none for the first run).
`(*inventory.Inventory).RecordLateHosts(ctx, runID, hosts)` SHALL record each host into the already-recorded group of
the run that covers its address, replacing any earlier observation of that host in the run, and update the group's
hosts-found count; a host whose address no recorded group of the run covers SHALL be rejected, an unknown run SHALL
return `inventory.ErrUnknownRun`.

#### Scenario: host found on re-probe
- WHEN a host seen in r1 is missing from its group in r2 and is then recorded with `RecordLateHosts`
- THEN the export as of r2 shows it `active` with `missed_runs` 0 and its services, and its group's hosts found is 1

### REQ-INVENTORY-010: List runs
`Inventory.ListRuns(ctx)` SHALL return every run with its name, status and timestamps, newest (highest id) first, and
an empty slice when no run exists.

#### Scenario: two runs
- WHEN run `a` was created and completed and then run `b` was created
- THEN `ListRuns` returns `b` (running) followed by `a` (completed)

### REQ-INVENTORY-011: Interest score
`inventory.Score(host, at, weights)` SHALL return a score from 0 to 100 and the contributing reasons
(`Reason{Code, Label, Points}`, in a fixed order). Each code counts at most once per host, whatever the number of
services or findings, and is worth its weight. The codes and default weights (`inventory.DefaultInterestWeights`) are:
`admin-panel` 30, `staging` 20, `iot` 25, `interesting-header` 10 and `interesting-cookie` 10 (finding kinds on a service
that is not inactive); `new` 20 (host first seen at or after `at`, the start of the run); `recent` 10 (first seen within
7 days before `at`); `self-signed` 10 (a TLS certificate with `self_signed`); `expiring-cert` 10 (a certificate whose
`not_after` is within 30 days after `at` or already passed); `outdated` 15 (a service product or technology version below
the built-in minimum for php, nginx, apache, openssh, wordpress, drupal, jquery or iis). The sum SHALL be clamped at 100;
a code with weight 0 SHALL give no reason. `ASI_INTEREST_WEIGHTS` (`code=points,…`, points 0-100) SHALL override single
weights and keep the defaults for the rest. An unknown code or a bad number SHALL be a one-line configuration error that
names the value. `Inventory.Interest` carries the weights (nil means defaults). `Inventory.Export` SHALL fill each host's
`interest_score`, with `at` = the start of the exported run. Diffs SHALL ignore `interest_score`.

#### Scenario: admin panel on a new host
- WHEN a host first seen in the exported run has an `admin-panel` finding on 443/tcp and nothing else notable
- THEN `interest_score` is 50 and the reasons are "Admin panel on 443/tcp" (30) and "First seen in this run" (20)

#### Scenario: unknown weight key
- WHEN `ASI_INTEREST_WEIGHTS=bogus=5`
- THEN every command fails with `ASI_INTEREST_WEIGHTS is malformed: unknown key "bogus" …`

### REQ-INVENTORY-012: Time-of-day presence pattern
`inventory.TimeOfDay(observations, loc)` SHALL consider only covering observations (`Covered`) and read each one's hour
in `loc` (UTC when nil). It SHALL report a pattern only when there are at least 6 covering observations, the host was both
seen and missed, and no missed hour falls inside the smallest circular hour range that holds every seen hour. The pattern
SHALL name that range as `HH:00-HH:00` (end exclusive, may wrap midnight). In every other case there is no pattern, and
the host keeps its usual status.

#### Scenario: office hours
- WHEN a host was seen at 08:15, 11:15 and 15:15 and missed at 02:15, 20:15 and 23:15 in six covering runs
- THEN the pattern is `08:00-16:00`

#### Scenario: not enough covering runs
- WHEN the same host has only five covering runs, plus any number of runs that did not cover it
- THEN there is no pattern

### REQ-INVENTORY-013: Grouping of similar services
`inventory.GroupServices(hosts)` SHALL put every service that has an `http` object into the group keyed by its sorted,
de-duplicated technology set (`name version`), its title and its favicon SHA-256. Services without `http` form no group.
Each group SHALL carry its count and its members (address, port, protocol) in address order. Groups SHALL be ordered by
count (descending), then by key, so equal input in any order gives the same output.

#### Scenario: same login page on three hosts
- WHEN three services share technologies {nginx 1.27, PHP 8.3} in any order, the title "Login" and favicon `aa`, and a
  fourth differs only in favicon
- THEN there is one group with count 3 followed by one with count 1

### REQ-INVENTORY-014: Host timeline
`Inventory.HostTimeline(ctx, address)` SHALL return, for the last 50 runs oldest first, whether each run covered the
address, whether the host was seen, the observation time (the covering group's `completed_at`, else the run's
`started_at`), and for covering runs and the latest run the host's state as of that run. Only that host is loaded, not
the whole network. It SHALL also return the host's latest state with `interest_score`, the score and reasons of
`inventory.Score` (as of the latest run's start, with `Inventory.Interest`), and the `inventory.TimeOfDay` pattern of the
observations (UTC). An address never seen SHALL return an error wrapping `inventory.ErrUnknownHost`.

#### Scenario: office-hours host
- WHEN a host is covered in 7 runs whose groups completed at 09, 22, 11, 03, 15, 19 and 08 UTC, and it was seen only in
  the runs at 08-15
- THEN the timeline's pattern is `08:00-16:00`

### REQ-INVENTORY-015: Host summary
Migration `internal/store/migrations/0009_host_summary.sql` SHALL add the derived table `host_summary` (one row per
host: address, last run, status, missed runs, stability, interest score, ports, service names, technology names,
finding kinds, HTTP titles, hostnames, first and last seen). `RecordGroup` and `RecordLateHosts` SHALL rewrite, in
their own transaction, the rows of every host whose address the group covers (including addresses a replaced
recording covered) with the state of that host as of the latest run covering its address, derived exactly as
`Export` derives it. Ports, service, technology, finding-kind and title columns SHALL hold the host's services that
are not `inactive` or were seen in the host's latest observation. User edits SHALL NOT write `host_summary`; tags and
display name are read from `hosts`. `(*inventory.Inventory).RefreshSummary(ctx)` SHALL rebuild the whole table.
`(*inventory.Inventory).BackfillSummary(ctx)` SHALL rewrite only the rows of hosts that have observations and either
no `host_summary` row or one whose last run is older than the latest run covering the host's address, and return how
many hosts it rewrote. `asi migrate` SHALL call it after applying migrations (printing `host summary: rebuilt N hosts`
when N > 0), and `asi serve` SHALL call it at startup, logging an error instead of exiting. `asi inventory
rebuild-summary` SHALL call `RefreshSummary` and print `host summary: rebuilt`; running it again leaves the table
unchanged.

#### Scenario: summary follows the export
- WHEN runs with `InactiveAfter: 2` record hosts over four runs, one run does not record one of two groups, and a host
  is recorded late with `RecordLateHosts`
- THEN after every run each host's `host_summary` status, missed runs, stability, interest score, first/last seen and
  hostnames equal the current `Export`
- AND recording a group again with the same result leaves `host_summary` unchanged, and so does `RefreshSummary`

#### Scenario: database scanned before the summary existed
- WHEN a run recorded a host and its `host_summary` rows are deleted
- THEN `asi migrate` (or `asi serve` starting) rewrites the row and the hosts page lists the host
- AND a stale row (last run older than the latest run covering the host) is rewritten too, and a second
  `BackfillSummary` rewrites nothing

### REQ-INVENTORY-016: Paged host list
`(*inventory.Inventory).ListHosts(ctx, HostQuery)` SHALL return a `HostPage` with the matching hosts of one page and
the `Total` count of all matches, filtering on all given fields at once: `Status` (`active`, `unstable`, `inactive`),
`Port`, `Service`, `Technology`, `FindingKind`, `Tag` (exact values), and `Text` (case-insensitive substring of the
address, display name, a hostname or an HTTP title; `%`, `_` and `\` are literal). `Sort` SHALL be one of `address`
(numeric, the default), `status` (active, unstable, inactive), `interest`, `last_seen`, `display_name`, ascending or
`Desc`, with the address ascending as tie-breaker. `PerPage` SHALL default to 50 and be capped at 200; `Page` below 1
SHALL mean 1, and a page past the end SHALL return no hosts and no error. An unknown sort key, a status outside the
three values or a port outside 0-65535 SHALL return an error wrapping `inventory.ErrInvalidQuery`; filter values
SHALL only reach SQL as parameters. With 20 000 hosts a page of 50 SHALL be returned in under 300 ms for any single
filter and for a combined filter.

#### Scenario: last partial page
- WHEN 12 hosts exist and `ListHosts` is called with `PerPage: 5` for pages 3 and 4
- THEN page 3 holds the 11th and 12th host by address, page 4 holds none, and both report `Total` 12

#### Scenario: injected sort key
- WHEN `ListHosts` is called with `Sort: "address; DROP TABLE hosts"`
- THEN it returns an error wrapping `ErrInvalidQuery` and the hosts are still listed afterwards

### REQ-INVENTORY-017: Host detail
`(*inventory.Inventory).HostDetail(ctx, address)` SHALL return the host as `Export` shows it as of the latest run
(headers, cookies, evidence and notes decrypted) with the run's name, and its history: one entry per run whose recorded
groups covered the address, newest first, with run name, start time, whether the host was seen and the services
(`port/protocol`) observed in that run. An address that is invalid, unknown or never observed SHALL return an error
wrapping `inventory.ErrUnknownHost`.

#### Scenario: history with a group not recorded
- WHEN host A is seen in h1, missed in h2, its group is not recorded in h3 and it is seen in h4
- THEN its history lists h4 (seen), h2 (missed) and h1 (seen) and no entry for h3

### REQ-INVENTORY-018: Response time history
Every service observation SHALL store the probe's `ttfb_ms`, `response_time_ms` and `error` in its `http` document, and
the export SHALL carry them as optional fields of `http`. `Inventory.ResponseTimes` SHALL return, per service of a host
that has measurements, the latest value, the median of the last `TimingWindow` (10) measured runs and
`Slower = SlowerThanUsual(latest, median)`: the latest is above `SlowFactor` (3) times the median and above `SlowMinMS`
(500) ms. An unknown host is `ErrUnknownHost`.

#### Scenario: one slow run after steady ones
- WHEN a service answered in about 100 ms for nine runs and in 1800 ms in the latest
- THEN its latest is 1800, its median about 100 and it is slower than usual

### REQ-INVENTORY-019: Run source
Migration `internal/store/migrations/0008_run_source.sql` SHALL add `runs.source` (`scan`, `import`, `manual`; existing
runs become `scan`). `CreateRun` SHALL store `RunSpec.Source` (empty means `scan`) and reject other values, and
`RunByName` SHALL return it as `Run.Source`.

### REQ-INVENTORY-020: Formula cells in the CSV export
`exchange.WriteCSV` (`asi export --format csv`) SHALL prefix every cell that starts with `=`, `+`, `-`, `@`, tab or CR with `'` (`exchange.NeutralizeRow`), so a spreadsheet does not evaluate scanned text such as titles as formulas.

#### Scenario: title starting with =
- GIVEN a service whose title is `=HYPERLINK("http://evil","x")`
- WHEN the inventory is exported as CSV
- THEN the title cell is `'=HYPERLINK("http://evil","x")`

### REQ-INVENTORY-021: Previous field encryption keys
`ASI_MASTER_KEY_PREVIOUS` SHALL accept a comma-separated list of base64 keys of exactly 32 bytes; each SHALL be added
to the field keyring as a read-only key, so values written under an old key stay readable while new values are
written under `ASI_MASTER_KEY`. An entry that is not base64 of 32 bytes (including an empty entry) SHALL be a one-line
configuration error naming the entry number and not the key.

#### Scenario: data written under the old key
- WHEN data was written under key A and asi starts with `ASI_MASTER_KEY`=B and `ASI_MASTER_KEY_PREVIOUS`=A
- THEN the export returns the stored notes verbatim

### REQ-INVENTORY-022: Key rotation
`asi key rotate [--batch N]` (default 500) SHALL re-encrypt under the current key every value in the encrypted
columns (`settings.value`, `hosts.notes`, `service_observations.http_headers`/`http_cookies`/`http_body`,
`findings.evidence`, `hunt_results.evidence`) that is under another key, in transactions of at most N rows, and print
`<table>: <n> rows rewritten` per table. Because it selects only rows not yet under the current key, an interrupted
rotation SHALL resume where it stopped and a repeated one SHALL rewrite nothing. It SHALL refuse to start, writing
nothing, when a stored value is under a key that is not in the keyring. `asi key status` SHALL print the current key
id and, per table, the rows under the current key and under old key ids (with a count per old key id), then
`total: <n> rows under old key ids`.

#### Scenario: rotate and drop the old key
- WHEN a database with observations, bodies, finding evidence, notes and the DefectDojo token written under key A is
  rotated with `ASI_MASTER_KEY`=B and `ASI_MASTER_KEY_PREVIOUS`=A
- THEN `asi key status` reports `total: 0 rows under old key ids`, a second rotation rewrites 0 rows per table
- AND with `ASI_MASTER_KEY`=B alone every value decrypts and the export and DefectDojo settings read back unchanged

### REQ-INVENTORY-023: Refuse to start with a key that cannot read the data
`asi serve` and the inventory commands (`scan`, `export`, `diff`, `import`, `host`, `inventory`, `signature`) SHALL
check before any write that every stored encrypted value is under `ASI_MASTER_KEY` or a key in
`ASI_MASTER_KEY_PREVIOUS`; otherwise they SHALL exit 1 with a one-line error starting `ASI_MASTER_KEY cannot read
stored data` that names the column and the key id. The check SHALL read the key ids in use per encrypted column from
the `encryption_keys_in_use` table, which database triggers keep current on every insert and update and `asi key
rotate` prunes, so its cost does not grow with the number of stored rows; a key id listed there that no stored value
uses any more SHALL be forgotten instead of reported. Tables not yet migrated are skipped, and other database errors in
this check SHALL not stop `serve`.

#### Scenario: scan with a new key and no previous key
- WHEN data was written under key A and `asi scan run` or `asi serve` starts with `ASI_MASTER_KEY`=B and no previous key
- THEN it exits 1 with that error, serve does not listen, and no run is created

#### Scenario: large observations table
- WHEN 50 000 service observations hold encrypted headers, cookies and bodies
- THEN the startup key check takes under 200 ms

### REQ-INVENTORY-024: Run mode, recheck hosts and packet count
Migration `internal/store/migrations/0011_network_rhythm.sql` SHALL add `runs.packets` (non-negative, default 0) and
`run_group_addresses.ports` (nullable integer array). `inventory.RunSettings` SHALL carry `Mode` (JSON `mode`:
`full` or `recheck`; the empty value of earlier runs reads as `full` through `RunSettings.RunMode()`) and an optional
ordered address list `Hosts` (JSON `hosts`) for rechecks; `CreateRun` SHALL reject any other mode and create nothing.
`inventory.Run.Packets` SHALL hold the run's stored packet count, returned by `RunByName`;
`(*inventory.Inventory).SetRunPackets` and `AddRunPackets` SHALL set or increase it, reject a negative value and return
`inventory.ErrUnknownRun` for an unknown id.

#### Scenario: packets round trip
- WHEN 40 and then 2 packets are added to a new run
- THEN `RunByName` returns `Packets == 42`

### REQ-INVENTORY-025: Recheck base and known services
`(*inventory.Inventory).RecheckBase(ctx, run)` SHALL return the latest `completed` run (other than `run`, and older
than it when `run.ID` is set) of the run's scan definition when the stored run belongs to one, otherwise the latest
`completed` run whose stored targets and excludes equal `run.Settings`' as sets. `KnownServices(ctx, base, ports,
inScope)` SHALL return, in numeric address then port order, the tcp services whose status as of `base` is `active` or
`unstable`, whose port is in `ports` and whose address passes `inScope` (nil = every address).
`RecheckPlan(ctx, run, inScope)` SHALL combine both with `run.Settings.Ports`, keep only the addresses of
`run.Settings.Hosts` in that order when the list is set, and return an error wrapping `inventory.ErrNoRecheckBase`
(text `no earlier run to recheck`) when there is no base or no known service.

#### Scenario: inactive and out-of-port services
- WHEN the base saw 10.0.0.5 on 80 and 443 (21 now inactive), 10.0.0.9 on 22 and 10.0.0.7 on 8080, and the recheck's
  ports are 21,22,80,443
- THEN the known services are 10.0.0.5:80, 10.0.0.5:443 and 10.0.0.9:22

#### Scenario: no earlier run
- WHEN no completed run with the same targets and excludes exists
- THEN `RecheckPlan` fails with `no earlier run to recheck`

### REQ-INVENTORY-026: Availability profile
`inventory.BuildAvailability([]inventory.HourObservation{{Hour, Seen}})` SHALL return an `inventory.Availability` with
24 buckets `Hours`, each starting at 0.5 and updated per observation as `v[h] = v[h] + 0.3 × (x − v[h])` (x = 1 seen,
0 missed), and `Samples` = number of observations applied (hours outside 0..23 are ignored). `Periodic()` SHALL be true
iff `Samples >= 6`, some bucket is >= 0.8 and some bucket is <= 0.2; `UsualHours()` SHALL return the buckets >= 0.8 in
ascending order, empty when not periodic. A host's profile SHALL be built from its covering runs (REQ-INVENTORY-003) of
source `scan` in order, with the hour of the completion time of the group covering the host in the timezone of the
run's stored schedule (UTC without a schedule or timezone); covering runs of source `import` or `manual` SHALL NOT
update the profile or its `Samples`, but still count for the host's status as before. The export SHALL carry it per
host as the optional `availability` object `{hours, samples, periodic, usual_hours, expected}`, omitted for a host
without samples; `expected` is present only when the export's run covers the host and the host was periodic before
it: `up` when that hour's bucket before the run was >= 0.8, `down` when <= 0.2.

#### Scenario: synthetic history
- WHEN a host is seen 3 times at hour 10 and missed 3 times at hour 2
- THEN `Hours[10]` is 0.8285, `Hours[2]` is 0.1715, every other bucket is 0.5, `Samples` is 6 and the host is
  periodic with usual hours [10]
- AND with only 2 of the misses it is not periodic, and 6 sightings at hour 10 alone are not periodic either

#### Scenario: import between scans
- WHEN a host has 5 scan samples and is then covered by an import run and a manual-entry run at hour 15
- THEN the exports of those runs show the same `hours` and `samples` as before them
- AND the next scan run brings `samples` to 6 and the host becomes periodic

### REQ-INVENTORY-027: Misses in a usually-down hour
A covering run that misses a host periodic by the profile of its earlier covering runs, at an hour whose bucket was
<= 0.2 before that run, SHALL update the profile but SHALL NOT count for the host's status, `missed_runs` and
stability, nor for those of its services in that run. A miss at any other hour counts as before.

#### Scenario: night-time misses
- WHEN a periodic host usually up at 10:00 and down at 02:00 is missed in five consecutive runs at 02:00 with
  inactive-after 3
- THEN it stays `active` with `missed_runs` 0 and its earlier stability, its services likewise, the diff between
  consecutive runs has no change for it and `availability.samples` grows by one per run

### REQ-INVENTORY-028: Delete hosts and services
`Inventory.DeleteHost(ctx, editor, address)` SHALL delete the host with its services, host and service observations,
technologies, findings, summary and hunt results (foreign key cascades), and `Inventory.DeleteService(ctx, editor,
address, port, protocol)` SHALL delete only that service with its observations, technologies, findings and hunt
results; each SHALL add one audit row in the same transaction (action `host.delete` with the address as target, or
`service.delete` with `address:port/protocol`, actor and address from the `Editor`). An unknown or invalid host fails
with `ErrUnknownHost`, an unknown service with `ErrUnknownService`, and a failed delete adds no audit row.
On the web, `RegisterHostDelete` in `internal/web/inventory.go` adds `GET`/`POST /hosts/{address}/delete` and
`GET`/`POST /hosts/{address}/services/{port}/{protocol}/delete`, all `Require(inventory.delete)` with the CSRF check:
the GET shows a confirmation page (`host_delete.html`) and only the POST deletes, then redirects to `/hosts/` with a
"Host … deleted." notice or back to the host page with a "Service … deleted." notice; unknown hosts or services get
404. The host page shows the Delete host button and the per-service Delete buttons only to roles with
`inventory.delete` (editor and admin among the built-in roles).

#### Scenario: delete one service
- WHEN an editor confirms deleting 22/tcp of 10.0.1.4
- THEN only that service is gone, the response redirects to `/hosts/10.0.1.4?deleted=22%2Ftcp`, and one audit row
  `service.delete` with target `10.0.1.4:22/tcp`, the editor and the client address is added

#### Scenario: operator
- WHEN an operator opens a host page or requests a delete route
- THEN the page has no delete controls and the routes answer 403

### REQ-INVENTORY-029: A deleted host found again is new
A host deleted with `DeleteHost` SHALL keep no history, so when a later run records the same address it is a new
host: first seen in that run, no earlier observations, and `diff.Compute` between the run before and that run reports
`host_new` for it. No special-case code exists for this; it follows from the deleted rows.

#### Scenario: delete and rescan
- WHEN host 10.0.0.2 is deleted after run l3 and run l4 records it again
- THEN the diff l3 → l4 has exactly one change for 10.0.0.2, of type `host_new`, and its first seen is l4's time

### REQ-INVENTORY-030: Reported technology confidence
The system SHALL store the detected technology confidence unchanged and SHALL report it as the detected confidence
multiplied by the host's `stability`, rounded to the nearest whole number (`inventory.Reported`), in `asi export`, the web export download
(`(*inventory.Inventory).Report`) and the host page. `(*inventory.Inventory).Export`, `HostDetail` and other inventory
reads return the stored value, so imports, manual edits (`KeepStored`) and diffs never write a reported value back.
A reported technology SHALL carry `confidence` (reported) and `confidence_raw` (detected). An import SHALL store
`confidence_raw` when present and otherwise the given `confidence` as the detected value, so an export → import →
export round trip keeps `confidence_raw`. Diffs compare stored values; a stability change alone is never a technology
change. The dashboard and the DefectDojo export show finding confidence, which is not multiplied (as on the host page).

#### Scenario: host missed one of three runs
- WHEN nginx is detected with confidence 90 on a host seen in two of its three covering runs
- THEN the export reports nginx with confidence 60 and the stored technology row keeps 90

#### Scenario: round trip of an unstable host
- WHEN a host at stability 0.5 with Legacy CRM detected at 80 is exported, imported into an empty database and exported again
- THEN the first export has `"confidence":40,"confidence_raw":80` and both exports carry the same `confidence_raw`

### REQ-INVENTORY-031: Dashboard ignores runs that never scanned
The dashboard's latest run and its previous run SHALL skip runs with status `failed` that recorded no group.

#### Scenario: failed before scanning
- WHEN run `d2` completed and a later run failed before recording a group
- THEN the dashboard shows `d2` as the latest run

### REQ-INVENTORY-032: One outdated-version table
`inventory.Score` SHALL count the `outdated` reason for a service whose product/version or a technology is outdated
according to `detect.IsOutdated`, which reads the same table `internal/detect/outdated.yaml` as the outdated findings.

#### Scenario: table and score agree
- WHEN a technology is `vsftpd 2.3.4` or `Apache 2.4.55`
- THEN the score has the outdated reason exactly when `detect.Outdated` produces a finding (vsftpd yes, Apache no)

### REQ-INVENTORY-033: Host edit prints the changed fields
`asi host edit` SHALL print `host <address> updated: tags=<tags>` followed by ` notes="<notes>"` when `--notes` was given.

### REQ-INVENTORY-034: Dashboard attention data and setup state
`(*inventory.Inventory).Dashboard` SHALL also return, in the same read-only transaction: `Setup` (`HasScan`: a scan definition exists; `HasCompletedRun`: a run with status completed exists; `HasTeam`: more than one user or a role that is not built in exists); `NewPanels`: up to `inventory.AttentionItems` + 1 (6) `admin-panel` findings observed in the latest run whose service had no finding with the same signature in an earlier run; and `Slow`: up to 6 services of the latest run that are slower than usual (`inventory.SlowerThanUsual` of the latest `response_time_ms` against `inventory.Median` of the service's last `TimingWindow` timings up to that run), read from at most 200 candidates of the latest run whose response time exceeds `SlowMinMS`. Every query SHALL be limited and use the `(run_id, service_id)` and `(service_id, run_id)` indexes of `service_observations`, never one query per host.

#### Scenario: a panel seen before is not new
- WHEN run d1 saw an admin panel on 10.4.0.1 and run d2 sees it again plus a new one on 10.4.0.5
- THEN `NewPanels` lists only 10.4.0.5

### REQ-INVENTORY-035: Encrypting values of an older database
Migration `0020` SHALL turn the plain owner, display name, scan definition and run targets and excludes, and the
sources of stored signatures and retro-hunts of an existing database into pending values (a `0x00` byte followed by
the plain text, empty values become NULL), and `(*store.Store).EncryptPending(ctx, keyring, batch)` SHALL encrypt
every pending value of every column in the rotation list with the current key, after `CheckKeys`
(REQ-INVENTORY-023) has confirmed the key reads the values already stored; with a key that cannot, it SHALL return
`ErrKeyMismatch` and leave the pending values unchanged. `asi migrate` SHALL run it after the
migrations and print `field encryption: encrypted N stored values` when N > 0; `asi serve` SHALL run it at startup
before the key check and only log a failure.

#### Scenario: upgrade
- WHEN a database at migration 0019 holds a plain owner, display name, targets, excludes and signature sources
- THEN after `Migrate` and `EncryptPending` no row of those tables holds the plain values and each decrypts to them
- AND a second `EncryptPending` encrypts nothing

#### Scenario: wrong key at upgrade
- WHEN host notes are encrypted under key A and `EncryptPending` runs with key B after migration 0020
- THEN it returns `ErrKeyMismatch`, the owner is still pending, and `EncryptPending` with key A then encrypts it

### REQ-INVENTORY-036: Column protection table
`docs/technical.md` §Protection of every column SHALL list every column of the migrated schema as `encrypted`,
`hashed` or `plain` with its content or the reason it stays plain; `TestColumnProtectionTableMatchesSchema` SHALL fail
when a column is missing or extra, when an encrypted column is not in the rotation list (`internal/store/rotate.go`)
or a rotated column is not marked encrypted, or when a row gives no reason.

