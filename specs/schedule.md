---
capability: schedule
title: Scan definitions and scheduling
code: []
tests: []
---
# Scan definitions and scheduling

## Requirements

### REQ-SCHEDULE-001: Scan definition
A definition SHALL store a unique name, enabled state, targets, excludes, ports, max rate, workers, inactive-after,
an optional signatures directory (`inventory.RunSettings`) and a `schedule.Schedule`: a timezone (IANA name, empty =
UTC), windows (weekdays plus `HH:MM` start and end, written `mon-fri 22:00-06:00`), a frequency (`interval` with a
Go duration of at least 1m, `daily` or `weekly`) and an optional recheck interval (`RecheckEvery`, JSON
`recheck_every`, a Go duration; empty = no rechecks). `(*schedule.Store).CreateDefinition` and `UpdateDefinition` SHALL
reject invalid values with one `<field>: <problem>` line per problem and store nothing; a max rate below 2 SHALL be
rejected with `max rate: enter at least 2 per second`, the minimum a run accepts (REQ-SCAN-002); a recheck interval
below 1m, or not shorter than the full period (the interval for `interval`, 24h for `daily`, 168h for `weekly`), SHALL
be rejected with a `recheck: <problem>` line. Editing the recheck interval is audited as the field `recheck every`.

### REQ-SCHEDULE-002: Windows
`Schedule.WindowAt(t)` SHALL return the window span containing `t` in the schedule's timezone; the end is exclusive,
a window whose end is at or before its start ends on the next day and belongs to the weekday it starts on, touching or
overlapping windows are joined, and start and end are wall-clock times on their own dates, so a daylight-saving change
lengthens or shortens a window (a start inside the spring-forward gap moves one hour later; an ambiguous time takes
the later occurrence). A schedule without windows allows any time.

#### Scenario: night window over the autumn change
- WHEN the window is `sat 22:00-06:00` in Europe/Warsaw on 2026-10-24
- THEN it lasts from 20:00 UTC to 05:00 UTC the next day (9 hours)

### REQ-SCHEDULE-003: Frequency
A new run SHALL be due when the definition never ran, when `interval` has elapsed since the last run start, or for
`daily` / `weekly` when the last run started on an earlier local date / ISO week than the start of the current window,
so a window crossing midnight starts one daily run, not two.

### REQ-SCHEDULE-004: Start only inside a window, pause at its end, resume in the next
`(*Scheduler).Step` SHALL, for each enabled definition without an executing run, resume its open run (`running` or
`paused`, not paused by a user) when the run's schedule has a window at the current time, or else start a new run when
inside a window and due. An executing run SHALL be cancelled once the clock reaches the end of the window it was
started or resumed in; the scanner then marks it `paused` (REQ-SCAN-004) and the next window resumes it from its first
unfinished group. `asi serve` SHALL call `Step` every 30 s (`schedule.DefaultTick`).

#### Scenario: run longer than its window
- WHEN a run has finished two of four groups when its window ends
- THEN it is `paused` with two groups, nmap is not called outside the window
- AND in the next window the same run continues without rescanning the finished groups and ends `completed`

### REQ-SCHEDULE-005: One run per definition, crash recovery, user pause
A definition SHALL have at most one open run (`runs_one_open_per_definition`); starting another fails with
`schedule.ErrRunOpen`. The first `Step` after `asi serve` starts SHALL mark runs of definitions still `running`
(interrupted by a crash) as `paused`, so the scheduler resumes them in their next window. `Pause` SHALL hold a run
(`runs.held`): the scheduler never resumes a held run; `Resume` clears the hold and continues the run at once.
`StartNow(ctx, actor, id[, mode])` starts a new run at once in mode `full` (default) or `recheck`; any other mode is
rejected and starts nothing. A manual recheck SHALL fail before creating a run, with an error wrapping
`inventory.ErrNoRecheckBase` (`no earlier run to recheck`), when the definition has no completed run or its latest
completed run has no active or unstable tcp service on the definition's ports; it rechecks all known services (no host
list). Manual starts and resumes run until done or paused, without a window end. A definition run's `started_at` SHALL
be the scheduler's clock at the start (the same instant stored as the definition's last run start); its settings SHALL
carry the mode (`full` or `recheck`) and, for a scheduled recheck, the picked hosts in order. `Store.Runs` and
`Store.Run` return each run's mode (`Settings.RunMode()`) and packet count (`Packets`).

### REQ-SCHEDULE-006: Progress and time left
`schedule.ProgressOf(total, workers, groups)` SHALL report addresses done (sum of recorded group addresses) of the
run's expanded total, finished groups, hosts found, summed group time, and the time left as
`group time / addresses done × addresses left / workers`, only when at least one group with a duration finished and
addresses are left. `Progress.WithInFlight(n)` SHALL add the addresses in flight of a running run (REQ-SCAN-009) to
addresses done, at most the total, and recompute the percent; the time left stays based on recorded groups.

### REQ-SCHEDULE-007: Edits apply from the next run and are audited
A run SHALL keep a copy of the definition's settings and schedule taken when it started (`runs.settings`,
`runs.schedule`); editing the definition while a run is open SHALL NOT change that run. Creating, editing (with the
changed fields as `<name>: <field>, …`), enabling and disabling a definition and starting, pausing and resuming a run
by a user SHALL write `audit_log` rows `scan.create`, `scan.update`, `scan.enable`, `scan.disable`, `scan.start`,
`scan.pause`, `scan.resume`.

### REQ-SCHEDULE-008: Scan pages
The UI SHALL serve `GET /scans` (list, nav entry "Scans"), `GET /scans/{id}`, `POST /scans/{id}/start`,
`GET /runs?name={name}`, `POST /runs/{id}/pause` and `POST /runs/{id}/resume` with `scan.run`, `GET /runs/{id}` with
`inventory.read`, and `GET /scans/new`, `POST /scans`, `GET /scans/{id}/edit`, `POST /scans/{id}`,
`POST /scans/{id}/enable` and `POST /scans/{id}/disable` with `scan.configure`. The run page SHALL render the pause and
resume forms only for a user with `scan.run`. An invalid form SHALL re-render with 422 and the problem under each
field; starting a scan with an open run SHALL answer 409. The run page SHALL show percent done, addresses done of
total, addresses per second, groups done of the estimated total, failed groups, hosts found, group time and the
estimated time left (all as in REQ-SCAN-009), a table of failed groups with addresses and reason when there are any,
and a table of groups with addresses, hosts, duration and finish time.

#### Scenario: viewer reads a run
- WHEN a user with the built-in role `viewer` (no `scan.run`) opens `/runs/{id}` of an open run
- THEN the page answers 200 with the progress figures and without the pause and resume forms The Scans list SHALL show per definition the last run (or "Never"), its status, its duration (finish minus start;
"-" while open or without a run) and the next planned start (`Schedule.NextPlanned(lastRunAt, now)`: the first time
from now that lies in a window and is due by the frequency, shown in the definition's timezone; "-" for a disabled
definition).

### REQ-SCHEDULE-009: Rechecks between full runs
Inside a window, `Step` SHALL start a full run when the full frequency is due (REQ-SCHEDULE-003, measured from the
last full run start for a definition with a recheck interval); otherwise, for a definition with a recheck interval, a
recheck SHALL be due when at least `recheck_every` has passed since the last run start of any mode. A due recheck of a
definition without a completed run SHALL start a full run instead. Otherwise the scheduler SHALL take the hosts inside
the definition's own targets minus excludes with an active or unstable tcp service on the definition's ports as of the
latest completed run of the definition (with their availability profile, last seen and last covered times from the
export as of that run); hosts of other definitions are never candidates and never hold a recheck back. The hosts
covered by that latest completed run (their `LastCovered` not before the run's start) SHALL all take the latest of
their `LastCovered` times, so the hosts of one run, finished by groups at different times, are rechecked together
instead of alternating between rechecks. The scheduler SHALL pick them with
`PickRecheck(now in the definition's timezone, recheck_every, hosts)` and start a recheck run of exactly the picked
hosts, in that order (`settings.hosts`); when nothing is picked no run is started. A definition without a recheck
interval SHALL behave as before. A manual recheck (`StartNow` in recheck mode) SHALL use the same scoped candidates to
check that a base exists.

`schedule.PickRecheck(now, period, hosts []RecheckHost) []string` SHALL return the addresses to recheck: a host is due
when its `LastCovered` is at least `period` before `now`; a periodic host whose bucket at `now.Hour()` is <= 0.2 is
skipped unless its `LastSeen` is at least 24h before `now`; periodic hosts whose bucket at `now.Hour()` is >= 0.8 come
first, then the rest, each part in numeric address order.

#### Scenario: full every 24h, recheck every hour
- WHEN a definition with interval 24h and `recheck_every` 1h is stepped hourly from its first run
- THEN the first step starts a full run, each following hour a recheck run of the known hosts
- AND 24h after the full run a full run starts again

#### Scenario: expected-down host
- WHEN a periodic host is usually down at 02:00 and was seen 2h ago
- THEN a recheck at 02:30 skips it; when it was last seen 25h ago it is included
- AND a host covered 10 minutes ago is not due for a recheck every hour

#### Scenario: groups finishing after the run start
- GIVEN a full run whose groups finish 1 to 4 minutes after its start and a recheck every hour, stepped every minute
- THEN every following hour one recheck starts with all known hosts, about an hour after the previous run

#### Scenario: two definitions with disjoint targets
- GIVEN definitions A on 10.0.0.0/28 and B on 10.0.1.0/28, both rechecking every hour, B created 30 minutes after A
- THEN A rechecks on every full hour and B on every half hour, each recheck completes and names only its own host

### REQ-SCHEDULE-010: Work ceiling and stalled runs
Saving a scan definition (`Definition.Validate`, so also the scan form) SHALL refuse settings that `scan.CheckWork`
refuses, as a `targets` problem naming the address and port counts. `Step` SHALL run the same check before it starts a
scheduled run, and `StartNow` before a manual start, and start nothing when it fails, returning the error.
When `Step` finds an open run of a definition with no live executor in this process and the run is stalled (status
`running`, heartbeat older than 60 s), it SHALL mark the run `paused` and resume that run, not a new one, in the
definition's next allowed window; a dead run never blocks its definition.

#### Scenario: scan form with too much work
- WHEN the scan form is saved with targets `10.0.0.0/14` and ports `1-1001`
- THEN it is shown again with a targets problem naming 262144 addresses and 1001 ports, and nothing is saved

#### Scenario: stalled run outside the window
- WHEN a run of a definition has a heartbeat 15 hours old, no executor, and `Step` runs outside the window
- THEN the run is `paused` and not resumed; in the next window `Step` resumes it to completion and starts no other run

### REQ-SCHEDULE-011: Deleting a scan definition
`(*schedule.Store).DeleteDefinition(ctx, actor, id)` SHALL delete the definition, mark its runs
`definition_deleted` (read as `Run.DefinitionDeleted`), keep the runs and their observations, and write the audit
entry `scan.delete` with the definition name; it SHALL return `ErrRunOpen` while the definition has a run in progress
or paused and `ErrUnknownDefinition` for an unknown id. The targets and excludes of definitions and runs SHALL be
stored encrypted (`scope`), not in `settings`.

#### Scenario: delete keeps runs
- WHEN the completed run of definition campus exists and campus is deleted
- THEN the run is still readable with its targets, `DefinitionDeleted` is true and the audit log has `scan.delete campus`

### REQ-SCHEDULE-012: Targets from files and line-numbered problems
The targets and excludes textareas SHALL show example placeholders (CIDR, range, single address, host name). The form
SHALL be `multipart/form-data` with optional `targets_file` and `excludes_file` inputs (`.txt`, `.csv`), parsed in
memory under the same 1 MB form limit: one entry per line, or the first CSV column with a `target`/`address` header row
skipped; file entries are appended after the typed ones. Invalid lines SHALL be reported under their field with their
line number (counting every typed line, blank and comment lines included) and the offending text; problems from a
file name the file.

#### Scenario: invalid lines
- WHEN `targets` is `10.0.0.1\nfoo bar\n10.0.0.2\n\n300.1.1.1`
- THEN the answer is 422, nothing is stored and the problem names `line 2` and `line 5`

### REQ-SCHEDULE-013: Plan summary endpoint
`POST /scans/plan` (`scan.configure`) SHALL answer 200 with an HTML fragment "N addresses after excludes, M ports,
G groups, at most P packets and requests, estimated E at this rate (at most T if every address answered)" (E the plan estimate range of REQ-SCAN-021, T the worst case) computed from targets, excludes, ports and pace or
exact rate, without calling nmap, probing HTTP or storing anything. It SHALL warn when the address count exceeds
65 536 or the port preset is All, show the problem and line number for invalid targets, and prompt for targets when
none are given. Under the figures it SHALL say in one hint that network and broadcast addresses of a range are not
scanned and not counted. The new and edit forms SHALL request it with `hx-post` on changes of these fields.

#### Scenario: plan of a /24 with excludes
- WHEN the request has `targets=10.0.0.0/24`, `excludes=10.0.0.0/28`, custom ports `80,443` and pace normal
- THEN the fragment reads "239 addresses after excludes, 2 ports, 4 groups, at most 47 322 packets and requests, estimated about 1 min or less at this rate (at most 13 min 42 s if every address answered)"
  followed by the hint "Network and broadcast addresses of a range are not scanned and not counted."

### REQ-SCHEDULE-014: Port presets
The `port_preset` select SHALL offer Web (80, 443, 8000, 8080, 8443), Top 100, Top 1000, All (65 535) and Custom; Custom
uses the `ports` field (range syntax `80,443,8000-8100`) inside a details element that is open when Custom is chosen; choosing a preset SHALL ask
`POST /scans/custom-ports` for that element, so choosing Custom reveals the field. The stored ports SHALL equal
`scan.ParsePorts` of the preset value and stay accepted by `asi scan run --ports`. A post without `port_preset` SHALL
use the `ports` field as before.

### REQ-SCHEDULE-015: Pace presets
The `pace` choice SHALL offer Careful (20), Normal (100, default) and Fast (500 packets and requests per second), each
with one sentence. An empty `max_rate` SHALL store the pace's number; a non-empty `max_rate` (Advanced, minimum 2)
SHALL override it. The page SHALL describe adaptive back-off in one sentence; it stays on by default.

### REQ-SCHEDULE-016: Form structure
The new and edit pages SHALL group the fields in details sections Basic (name, targets, excludes, ports, pace), Schedule
and Advanced (workers, inactive after, service detection light/standard, mode, signatures directory, exact rate,
window text), with Schedule and Advanced collapsed on a fresh form and opened when they hold a problem; every Advanced
field SHALL have a one-sentence hint.

### REQ-SCHEDULE-017: Schedule controls and summary
The schedule SHALL be off by default ("Run only when started by hand"); `scheduled=on` SHALL enable the definition with
windows from weekday checkboxes (`days`) and `window_start`/`window_end`, a timezone select defaulting to the server's
zone and a frequency select. A non-empty Advanced `windows` text SHALL take precedence over the checkboxes; with
`scheduled=on`, no day and no windows text the form SHALL answer 422, except when editing a definition stored without
windows, which SHALL keep running at any time. A server-computed summary line SHALL be shown on
the form and returned by `POST /scans/schedule-summary` (`scan.configure`).

#### Scenario: weekly night scan
- WHEN the schedule is on with `days=sat`, 22:00-06:00, frequency weekly and recheck every 1h
- THEN the summary reads "Full scan every Saturday 22:00-06:00; recheck of known services every hour"

### REQ-SCHEDULE-018: Starting templates
`GET /scans/new?template=single-host` SHALL pre-fill port preset All with no schedule, and
`?template=large-network` SHALL pre-fill Top 1000 with a weekly Saturday 22:00-06:00 full scan and hourly recheck; an
unknown template SHALL render the default form.

### REQ-SCHEDULE-019: Edit keeps stored values
`GET /scans/{id}/edit` SHALL render the same form with every stored value (including service detection, mode, adaptive
back-off and custom ports); posting it back unchanged SHALL store a definition deep-equal to the original, keeping
fields the form does not show (group size, HTTP timeout), and SHALL write no audit entry.

### REQ-SCHEDULE-020: Scan creation access
`GET /scans/new`, `GET /scans/{id}/edit`, `POST /scans`, `POST /scans/{id}`, `POST /scans/plan`,
`POST /scans/schedule-summary` and `POST /scans/custom-ports` SHALL require `scan.configure`; `POST /scans/quick` SHALL require `scan.configure` and
`scan.run`. The built-in viewer SHALL get 403 for each and nothing SHALL be created.

### REQ-SCHEDULE-021: Quick scan and safe defaults
`GET /scans` SHALL show, above the scan list and only to a user with both `scan.configure` and `scan.run`, one form
posting to `POST /scans/quick` with a targets field, a `port_preset` select (Web selected) and a "Scan now" button.
`POST /scans/quick` SHALL require `scan.configure` (route) and `scan.run` (checked in the handler, 403 otherwise),
create a definition named "Quick scan of …" with the safe defaults (disabled, no windows, max rate
`scan.DefaultMaxRate`, workers `scan.DefaultWorkers`, inactive after `inventory.DefaultInactiveAfter`, adaptive
back-off on, standard service detection) and start a full run with `StartNow`, answering 303 to `/runs/{id}`.
A repeated quick scan of the same targets SHALL get a distinct name. `GET /scans/new` SHALL pre-fill the same defaults.

#### Scenario: quick scan of a small network
- WHEN an admin posts `targets=10.0.0.0/28` and `port_preset=web` to `/scans/quick`
- THEN the answer is 303 to the new run and the stored definition is disabled with the Web ports and max rate 100

#### Scenario: configure without run
- WHEN a user whose role has `scan.configure` but not `scan.run` posts to `/scans/quick`
- THEN the answer is 403 and no definition or run is created

#### Scenario: invalid quick targets
- WHEN the targets are `not a target!`
- THEN the answer is 422 with the problem and its line number next to the targets field, and nothing is stored
