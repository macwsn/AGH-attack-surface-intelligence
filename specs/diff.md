---
capability: diff
title: Changes between runs
code: []
tests: []
---
# Changes between runs

## Requirements

### REQ-DIFF-001: Diff document shape
`diff.Compute(from, to, opts)` SHALL return a `diff.Diff` that marshals to
`{"schema":"asi.diff/v1","from":<from.Run>,"to":<to.Run>,"changes":[...]}`, where `changes` is `[]` (never `null`)
when nothing changed. Every change SHALL carry `type` and `address`; service-level changes SHALL also carry `port` and
`protocol`, host-level changes SHALL carry no `port` key. Changes SHALL be sorted by address (numeric), port
(host-level first), protocol and type, so equal inputs give byte-identical JSON.

#### Scenario: deterministic output
- WHEN the same two states are compared twice, with the hosts of `to` in a different order the second time
- THEN both results marshal to identical bytes

### REQ-DIFF-002: Host change types
For every host of `to`, the system SHALL emit `host_new` when the host is absent in `from`; `host_inactive` when it
is not `inactive` in `from` and `inactive` in `to`; `host_missing` when it is `active` in `from` and `unstable` in
`to`; `host_returned` when it is `unstable` or `inactive` in `from` and `active` in `to`. A host whose status is
`unstable` in both or `inactive` in both SHALL yield no host-level change.

#### Scenario: host goes missing
- WHEN a host is `active` in `from` and `unstable` in `to`
- THEN the diff contains exactly one `host_missing` change for that address and no `port`

### REQ-DIFF-003: Service change types
For a host without a host-level change, the system SHALL apply the same status rules to each service of the host,
keyed by (port, protocol), emitting `service_new`, `service_missing`, `service_returned` and `service_inactive`.

#### Scenario: new service on a known host
- WHEN a host is `active` in both states and has a service on port 80 only in `to`
- THEN the diff contains exactly one `service_new` with `port` 80 and `protocol` `tcp`

### REQ-DIFF-004: Host-level changes suppress service-level changes
When a host-level change is emitted for a host, the system SHALL emit no service-level change for that host.

#### Scenario: new host with services
- WHEN a host with two services is absent in `from` and present in `to`
- THEN the diff contains only the single `host_new` entry for that host

### REQ-DIFF-005: Changed service fields
For a service `active` in both states whose non-volatile fields differ, the system SHALL emit one `service_changed`
whose `fields` lists every differing field as `{"field","old","new"}`, sorted by field name, using the export paths
`service`, `product`, `version`, `http.status_code` (number), `http.title`, `http.headers.<name>` (`null` on the side
where the header is absent), `http.cookies` (sorted set of cookie names), `http.redirect_chain`, `http.tls.sha256`,
`http.favicon_sha256`, `technologies` (sorted set of `name version`, the name alone when the version is empty) and
`findings` (sorted set of signature ids). Reordering the members of a set alone SHALL yield no change.

#### Scenario: title changed
- WHEN the title of an active service changes from `Intranet v1` to `Intranet v2`
- THEN the diff contains one `service_changed` with fields `[{"field":"http.title","old":"Intranet v1","new":"Intranet v2"}]`

### REQ-DIFF-006: Volatile values are ignored
The system SHALL never report a change caused only by the headers `date`, `expires`, `last-modified`, `etag`, `age`,
`set-cookie`, `content-length`, `x-request-id`, `cf-ray` (`diff.DefaultVolatileHeaders`), a header named in
`Options.VolatileHeaders`, in `ASI_VOLATILE_HEADERS` (comma-separated, case-insensitive, `Inventory.VolatileHeaders`)
or in the `volatile_headers` setting of either run (`inventory.RunSettings.VolatileHeaders`, set through the scan
definition form), by cookie flags or values beyond the set of cookie names, or by TLS dates, subject or issuer of a
certificate with the same `sha256`. `inventory.Export.VolatileHeaders` carries the configured and run-setting names
(not exported in JSON); the host timeline page passes the same names (`inventory.Timeline.VolatileHeaders` and each entry's run settings). Two identical states SHALL give `changes: []`.

#### Scenario: only volatile values differ
- WHEN two states differ only in `date`, `etag` and the cookie flags of an active service
- THEN the diff has an empty change list

#### Scenario: configured volatile header
- WHEN two states differ only in header `x-trace` and `Options.VolatileHeaders` contains `x-trace`
- THEN the diff has an empty change list
- AND without that option the diff contains one `service_changed` for `http.headers.x-trace`

#### Scenario: volatile header from the environment
- WHEN `ASI_VOLATILE_HEADERS` is `X-Trace-Id, x-backend-node` and two scans differ only in those headers
- THEN `asi diff` between them reports no change

### REQ-DIFF-007: Diff between two named runs
`diff.Between(ctx, src, from, to, opts)` SHALL load the state as of each named run through `src.Export` and return
`diff.Compute` of the two; an empty or unknown run name SHALL return a `*diff.UnknownRunError` that matches
`inventory.ErrUnknownRun` and reads `unknown run "<name>"`. `diff.WriteJSON` SHALL write the diff as two-space
indented JSON followed by a newline. `asi diff` and `GET /changes.json` SHALL both use these two functions.

#### Scenario: unknown run
- WHEN `diff.Between` is called with `to` = `nope` and no run `nope` exists
- THEN it returns an error `unknown run "nope"` for which `errors.Is(err, inventory.ErrUnknownRun)` holds

### REQ-DIFF-008: Change counts per run
`diff.Count(d)` SHALL count the changes of a diff as follows. **New:** `host_new`, `service_new`, `host_returned` and
`service_returned`. **Missing:** `host_missing`, `service_missing`, `host_inactive` and `service_inactive`. **Changed:**
`service_changed`. `diff.Series(ctx, src, runs, limit, opts)` SHALL load each named run (oldest first) once and return
the counts of every consecutive pair, keeping only the last `limit` pairs. An unknown run SHALL return a
`*diff.UnknownRunError`.

#### Scenario: fewer runs than the limit
- WHEN `diff.Series` gets 4 run names and limit 20
- THEN it returns 3 entries, one per consecutive pair

### REQ-DIFF-009: Response time and timeouts are not changes
The diff SHALL never report `http.ttfb_ms`, `http.response_time_ms` or `http.error` as a changed field. When either side
of a service has `http.error` set, the diff SHALL compare only `product` and `version` of that service, because the
probe data of a timed-out side is unknown, not changed; the service name and `http.scheme` are not compared either, so
an `https` service whose TLS probe failed once (recorded as `http` with `http.scheme` `https`) does not flap.

#### Scenario: different response times
- WHEN a service answered in 20 ms in one run and in 9000 ms in the next
- THEN the diff has no change for it

#### Scenario: a probe timed out
- WHEN a service had a title in one run and timed out in the next
- THEN the diff has no change for it unless `product` or `version` changed

#### Scenario: transient TLS failure
- WHEN a service is `https` in run 1, `http` with `http.scheme` `https` and `http.error` `tls handshake failed` in run 2, and `https` again in run 3
- THEN neither the diff of runs 1 and 2 nor that of runs 2 and 3 has a `service_changed` for it

### REQ-DIFF-010: Note on a host missed in a usually-up hour
A change SHALL carry an optional `note` string (JSON `note`, omitted when empty, so a change without a note is
byte-identical to before). `diff.Compute` SHALL set `note` to `expected up at this hour` on a `host_missing` change
when the `to` host's `availability.expected` is `up`, and SHALL set no note otherwise.

#### Scenario: periodic host missed in its usual hour
- WHEN a host goes from `active` to `unstable` and its `to` export has `availability.expected` = `up`
- THEN the diff contains `{"type":"host_missing","address":…,"note":"expected up at this hour"}`

#### Scenario: host without availability
- WHEN a host without `availability` (or with `expected` other than `up`) goes from `active` to `unstable`
- THEN the `host_missing` change has no `note` key

#### Scenario: miss in a usually-down hour
- WHEN the inventory ignores a miss in a usually-down hour, so the host keeps its status and services
- THEN the diff contains no change for that host

### REQ-DIFF-011: Scan diffs skip hosts no scan ever covered
When the `to` state is as of a scan run (`inventory.Export.Source` is `scan`), the system SHALL report no change for
a host that no scan run up to `to` covered (`inventory.ExportHost.ScanCovered` is false), such as a host that exists
only through an import or manual entry. Diffs to an import or manual run, and import previews, are unaffected.

#### Scenario: imported host outside the scanned range
- WHEN run `s1` scans 192.0.2.0/29, an import adds host 198.51.100.5, and run `s2` scans 192.0.2.0/29 again
- THEN `asi diff --from s1 --to s2` contains no change for 198.51.100.5

### REQ-DIFF-014: Per-request tokens in headers are not changes
Before comparing `http.headers.<name>`, the diff SHALL normalise the value with `inventory.NormalizeHeader`: inside
`content-security-policy` and `content-security-policy-report-only` every `'nonce-…'`, `'sha256-…'`, `'sha384-…'` and
`'sha512-…'` source, and in any header UUIDs, ISO 8601 and HTTP dates, Unix timestamps (10 or 13 digits), hex runs of
16 or more characters and base64-like runs of 20 or more characters mixing letters and digits, SHALL be replaced by
`<volatile>`. The normalised value is used for the comparison only: the stored and exported header and the `old`/`new`
values of a reported change SHALL be the raw header.

#### Scenario: Adminer CSP nonce
- WHEN the `content-security-policy` of an active service differs only in its `'nonce-…'` source between two runs
- THEN the diff has no change for it
- AND when the policy also gains `img-src *`, the diff has one `service_changed` for `http.headers.content-security-policy`
  with the raw old and new headers

### REQ-DIFF-015: Learned volatility
Recording a service observation SHALL update a per-service field state (stored sealed with the observation): when the
same compared field changed in each of the last 3 observations of the service (`inventory.VolatileAfter`), the field
SHALL be marked volatile, and stay volatile until it has been unchanged for 3 observations and then changes, which is
reported again. The export SHALL list volatile fields per service as `volatile: [{"field","values"}]` with the last 3
values (omitted when empty), and `diff.Compute` SHALL not report a field that is volatile in the `to` service. When
either side of a comparison has `http.error`, only `product` and `version` count.

#### Scenario: title changes every run
- WHEN the title of a service changes in 3 consecutive runs
- THEN the first two changes are reported and the third and later ones are not
- AND after 3 runs with the same title, the next change is reported again

### REQ-DIFF-016: Unstable favicon is not a change
The diff SHALL compare `http.favicon_sha256` only when neither side has `http.favicon_unstable` set.

#### Scenario: favicon different per request
- WHEN a service's favicon is recorded as unstable in one of two runs
- THEN the diff reports no change of `http.favicon_sha256`

### REQ-DIFF-017: Status lines of asi export and asi diff on stderr
`asi export` and `asi diff` SHALL write their status line (`exported N hosts as of run R to F`,
`N changes from A to B written to F`) to stderr, so `--out /dev/stdout` yields clean JSON or CSV on stdout; exit codes
are unchanged.

