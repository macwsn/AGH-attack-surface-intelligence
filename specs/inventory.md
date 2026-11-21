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
SHALL NOT count as missed. Services SHALL follow the same model per (host, port, protocol), seen when the run holds an
observation of the service.

#### Scenario: group did not complete
- WHEN runs have `InactiveAfter: 2`, host H is seen in r1, missed in r2, its group is not recorded in r3 and H is
  missed again in r4
- THEN the state as of r2 and r3 shows H `unstable` with `missed_runs` 1 and stability 0.5
- AND the state as of r4 shows H `inactive` with `missed_runs` 2

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
Response headers, cookie metadata, finding evidence and host notes SHALL be stored only as field-encryption
ciphertext produced by `store.Keyring` (AES-256-GCM, key id stored with the value); the plain HTTP document kept for
search and diff SHALL hold no headers and no cookies. Reading through the inventory API SHALL return the original
values.

#### Scenario: raw select
- WHEN a host with header value, cookie name, finding evidence and notes markers is recorded and edited
- THEN no `SELECT t::text FROM <table> t` over any table of the schema contains a marker
- AND the export returns all four values verbatim

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

