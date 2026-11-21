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
`set-cookie`, `content-length`, `x-request-id`, `cf-ray` (`diff.DefaultVolatileHeaders`) or a header named in
`Options.VolatileHeaders`, by cookie flags or values beyond the set of cookie names, or by TLS dates, subject or
issuer of a certificate with the same `sha256`. Two identical states SHALL give `changes: []`.

#### Scenario: only volatile values differ
- WHEN two states differ only in `date`, `etag` and the cookie flags of an active service
- THEN the diff has an empty change list

#### Scenario: configured volatile header
- WHEN two states differ only in header `x-trace` and `Options.VolatileHeaders` contains `x-trace`
- THEN the diff has an empty change list
- AND without that option the diff contains one `service_changed` for `http.headers.x-trace`

