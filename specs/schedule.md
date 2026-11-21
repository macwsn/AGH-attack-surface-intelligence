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
UTC), windows (weekdays plus `HH:MM` start and end, written `mon-fri 22:00-06:00`) and a frequency (`interval` with a
Go duration of at least 1m, `daily` or `weekly`). `(*schedule.Store).CreateDefinition` and `UpdateDefinition` SHALL
reject invalid values with one `<field>: <problem>` line per problem and store nothing.

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
`StartNow` starts a new run at once. Manual starts and resumes run until done or paused, without a window end.

### REQ-SCHEDULE-006: Progress and time left
`schedule.ProgressOf(total, workers, groups)` SHALL report addresses done (sum of recorded group addresses) of the
run's expanded total, finished groups, hosts found, summed group time, and the time left as
`group time / addresses done × addresses left / workers`, only when at least one group with a duration finished and
addresses are left.

### REQ-SCHEDULE-007: Edits apply from the next run and are audited
A run SHALL keep a copy of the definition's settings and schedule taken when it started (`runs.settings`,
`runs.schedule`); editing the definition while a run is open SHALL NOT change that run. Creating, editing (with the
changed fields as `<name>: <field>, …`), enabling and disabling a definition and starting, pausing and resuming a run
by a user SHALL write `audit_log` rows `scan.create`, `scan.update`, `scan.enable`, `scan.disable`, `scan.start`,
`scan.pause`, `scan.resume`.

### REQ-SCHEDULE-008: Scan pages
The UI SHALL serve `GET /scans` (list, nav entry "Scans"), `GET /scans/{id}`, `POST /scans/{id}/start`,
`GET /runs/{id}`, `POST /runs/{id}/pause` and `POST /runs/{id}/resume` with `scan.run`, and `GET /scans/new`,
`POST /scans`, `GET /scans/{id}/edit`, `POST /scans/{id}`, `POST /scans/{id}/enable` and `POST /scans/{id}/disable`
with `scan.configure`. An invalid form SHALL re-render with 422 and the problem under each field; starting a scan
with an open run SHALL answer 409. The run page SHALL show percent done, addresses done of total, finished groups,
hosts found, group time and the estimated time left (REQ-SCHEDULE-006), and a table of groups with addresses, hosts,
duration and finish time.

