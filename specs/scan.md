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
A run SHALL split its max rate once: nmap gets max rate / 2 (rounded down) and the probe's token bucket
(`scan.NewLimiter`, rate = max rate - max rate / 2 per second, burst = the same, injectable `scan.Clock`) gets the rest,
so nmap packets and probe requests together never exceed the run's max rate. A max rate below 2 SHALL be rejected
before any nmap call. Every probe HTTP request (root, redirects, favicon, signature paths) SHALL take one token. nmap
calls SHALL get `Options.MaxRate` = (max rate / 2) / min(workers, max rate / 2) and at most min(workers, max rate / 2)
nmap calls run at once, so the rates of concurrent nmap calls never sum above nmap's half. Probe requests to one
address SHALL never exceed `scan.PerHostConcurrency` (2) in flight.

#### Scenario: fake clock
- WHEN 100 probe requests are issued with max rate 10
- THEN the fake clock advances at least 9 s and no 1 s window holds more than 20 requests

#### Scenario: combined cap
- WHEN a run with the fake nmap runner and a fake clock uses 1, 4 or 16 workers (max rate 20, 20 and 10)
- THEN the peak sum of concurrent nmap `Options.MaxRate` plus the measured probe rate stays at or below the max rate

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
`scan.RunProgress` SHALL report addresses per second (addresses of recorded groups divided by the sum of their
durations, times the workers), groups done, the estimated total of groups (done + failed + the addresses left divided by
the size of the most recently completed group) and the estimated time left (addresses left divided by the rate; unknown
without a rate or a stored total; zero for a completed run). `asi scan show NAME` SHALL append
`rate=R/s groups_done=D/T failed_groups=F eta=E` to its first line and print one
`failed_group=I addresses=N reason="…"` line per failed group after the group lines; the run page `/runs/by-name/{name}`
(permission `inventory.read`) SHALL show the same figures and list failed groups.

#### Scenario: paused run
- WHEN a run of 1 000 addresses with 2 workers has recorded 64 addresses in 32 s and 100 in 50 s and one failed group of 2
- THEN `scan show` reports `rate=4.0/s groups_done=2/12 failed_groups=1 eta=3m29s`

