---
capability: exchange
title: Import, manual entry and export
code: []
tests: []
---
# Import, manual entry and export

## Requirements

### REQ-EXCHANGE-001: Parse JSON and CSV
`exchange.ParseJSON` SHALL accept a document with `"schema": "asi.export/v1"` and read from each host `address`,
`hostnames`, `tags`, `notes`, `display_name`, `owner`, `criticality`, `status_override` and `services` (`port`,
`protocol`, `state`, `service`, `product`, `version`, `http`, `technologies`, `findings`); the other derived fields
(`first_seen`, `last_seen`, `missed_runs`, `stability`, `interest_score`) SHALL be ignored. `exchange.ParseCSV` SHALL
read the columns of `docs/contracts.md` §2 by header name, needing only `address`; rows of the same address SHALL be
merged into one host, a row without `port` SHALL add a host without a service, `technologies` SHALL be read as
`name[:version]` separated by `;` with source `import`, and `findings` as signature ids separated by `;`. A host or
service whose exported `status` (CSV: the row's `status`) is `unstable` or `inactive` SHALL be marked as not active
in the file. A cell that starts with `'` followed by `=`, `+`, `-`, `@`, tab or CR SHALL lose the apostrophe. A
document with another schema, invalid JSON or a CSV without an `address` column SHALL be rejected as a whole.

### REQ-EXCHANGE-002: Row validation
Each JSON host and each CSV row SHALL be validated on its own: the address SHALL be an IPv4 or IPv6 address, ports
SHALL be 1-65535, protocols `tcp`, `udp` or `sctp` (default `tcp`), schemes `http` or `https`, status codes 100-599,
confidences 0-100, technologies SHALL have a name and findings a signature id, and a host or service SHALL NOT be
listed twice. An invalid row SHALL be reported as `exchange.RowError` with row and reason (JSON: 1-based host index;
CSV: record number with the header as row 1) and SHALL NOT stop the valid rows. `Batch.Invalid` SHALL count every
invalid row and at most `exchange.MaxRowErrors` (1000) SHALL be listed. Header names SHALL be lower-cased and
`set-cookie` dropped; host names SHALL be lower-cased.

#### Scenario: invalid rows
- WHEN a CSV holds a row with address `10.0.0.300` in row 3 and valid rows around it
- THEN the batch has `Row 3: "10.0.0.300" is not an address.` and the valid hosts

### REQ-EXCHANGE-003: Shared processing as a run
`exchange.Apply(ctx, inv, batch, opts)` SHALL process every service like a scanned one through
`(*inventory.ServiceResult).Detect`, which calls `(*detect.Set).DetectService`, the function the scan pipeline also
uses: the signatures of `opts.Signatures` and built-in detection on the stored HTTP response
(`(*detect.Set).DetectRecorded`; no request is sent; signatures with a `request.path` other than `/` and body
matchers never match), the technologies of the service product and version (`detect.ServiceTechnologies` and the
web server products nginx, Apache httpd and Apache Tomcat), the outdated table (`detect.Outdated`), merged with the
given technologies (`detect.Merge`) and findings (by signature id). A service whose detection is already stated, a
JSON service with a `technologies` key (as in an export, also when empty) or a form re-save of a stored service with
unchanged product and version, SHALL keep its technologies without the product mapping, so a round trip stays
unchanged. It SHALL record the valid hosts as one completed run of source
`opts.Source` (`import` by default, `manual` for the form) whose only group covers exactly the imported addresses.
Imported user fields SHALL only add tags and fill empty fields; with `ReplaceUserFields` (the form) tags and notes
SHALL be replaced. With `KeepStored` (the form), a service the host already has SHALL keep its stored state and HTTP
data (URL, headers, cookies, redirect chain, TLS, favicon), with only scheme, status code and title taken from the
entry. It SHALL also keep the full stored technology and finding records whose name and version or signature id
the entry lists, so saving an unchanged host yields no change. The report SHALL hold the run name, host and service
counts, the row errors, the invalid and skipped counts (`Report.Skipped`, see REQ-EXCHANGE-006) and the diff from the latest state before the import to the
state after it. A batch without valid rows SHALL return `exchange.ErrNothingToImport` and record nothing.

#### Scenario: import takes part in diffs
- WHEN run s1 saw 10.0.0.1 with title "Intranet v1" and an import `imp` holds 10.0.0.1 with "Intranet v2" and a new host
- THEN `asi diff --from s1 --to imp` contains `service_changed` with `http.title` and `host_new`

#### Scenario: edit only the notes
- WHEN a scanned host with headers, cookies, TLS, technologies and findings is loaded into the form and saved with new notes
- THEN the report has no changes and the export differs only in the notes

#### Scenario: entered nginx
- WHEN a host is entered by form, CSV or JSON with service `http`, product `nginx`, version `1.14.0`
- THEN the service gets the technology nginx 1.14.0 and the finding `outdated-nginx`, as a scanned service does

### REQ-EXCHANGE-004: Dry run
With `opts.DryRun` the system SHALL record nothing and report the changes the import would cause, computed on the
current state with the imported hosts `active` and their unlisted services counted as missed once.

### REQ-EXCHANGE-005: CLI import
`asi import --format json|csv --file FILE [--name NAME] [--dry-run] [--signatures-dir D] [--inactive-after N]` SHALL
print one line `Row N: reason` per listed invalid row, a summary line
`imported|dry run: would import H hosts, S services as run NAME; E invalid rows; C changes; K left as stored (not active in the file)`
and one line per change, and exit 0; it SHALL exit 1 with a one-line error when no row is valid or the file cannot be
read or parsed. It SHALL match the signatures of `--signatures-dir` combined (`detect.Combine`) with the enabled
database signatures, the same set a scan run with that directory uses, and exit 1 when an id is defined in both.

### REQ-EXCHANGE-006: Round trip
Exporting JSON, importing it into an empty database and exporting again SHALL give the same hosts (hostnames, tags,
notes and other user fields) with the same services, HTTP data, technologies and findings, including hosts and
services that were `unstable` or `inactive` in the export; only timestamps, the run name and the derived `status`,
`missed_runs` and `stability` differ, which are derived again from the runs of the target database (one import run
cannot reproduce the source's history of missed runs). A host or service that is not active in the file and that the
inventory already holds SHALL NOT be recorded (the file has no newer evidence of it) and SHALL be counted in
`Report.Skipped`, so importing an export back into its source never reports it as returned.

#### Scenario: unstable service
- WHEN the source saw 10.0.0.1 with ports 22 and 80 and 10.0.0.2 with 22 in s1, and only 10.0.0.1:22 in s2
- THEN importing its export into an empty database gives both hosts with 22, 80 and 22 and the same data
- AND importing the export back into the source skips 10.0.0.2 and 10.0.0.1:80 and reports no change

### REQ-EXCHANGE-007: Upload limits and CSV formula neutralisation
Files SHALL be read into memory through `exchange.ReadAll`, which rejects more than 20 MiB (`exchange.MaxUploadBytes`)
with `exchange.ErrTooLarge`; uploads SHALL be streamed with `multipart.Reader`, never through `ParseMultipartForm`,
so nothing is written to disk. `exchange.WriteCSV` SHALL prefix every data cell that starts with `=`, `+`, `-`, `@`,
tab or CR with `'`.

### REQ-EXCHANGE-008: Import, manual entry and export in the UI
`GET /import` and `POST /import` (multipart: `file`, `format` with the file name extension as default, `name`,
`dry_run`) SHALL require `import`; an upload over 20 MiB SHALL get 413.

`GET /hosts/entry[?address=A]` and `POST /hosts/entry` SHALL require `inventory.create`. They add or edit a host with
hostnames, tags, notes and service rows through `exchange.HostFormFrom(...).Batch()` (the CSV row path) and
`exchange.Apply` with source `manual` and `KeepStored`. The UI import and the manual entry SHALL match the signature set of
`(*detect.Library).Set`: the signatures of the server's signatures directory (`ASI_SIGNATURES_DIR`) combined with the
enabled database signatures. `asi serve` SHALL build one `detect.Library` and share it between the scheduler's
scanner, the signatures pages and the import and entry handlers, so data entered in the UI is matched like
`asi import --signatures-dir` and scans (R11). With `?address=A` the stored host is loaded into the form in
edit mode (hidden `editing` field), and editing SHALL also require `inventory.edit`. A save that is not in edit mode,
for an address already in the inventory, SHALL record nothing and answer 409 with a link to
`/hosts/entry?address=A`. The page SHALL offer a form that loads an existing host. A form with invalid rows SHALL
get 422 with the problems.

`GET /export`, `GET /export.json` and `GET /export.csv` SHALL require `export` and apply the filter of the query
(`run`, `status`, `q` address or hostname substring, `tag`) through `exchange.Filter`; the files are attachments
named `asi-export-<run>.<format>`.

#### Scenario: add an address that exists
- WHEN a user opens "Add host", enters an address already in the inventory with one service and saves
- THEN nothing is recorded, its tags and notes are unchanged and the page links to its edit form

### REQ-EXCHANGE-009: Imports and manual entries are audited
`exchange.Apply` SHALL add one audit row after a successful, non-dry-run apply, using `Options.Actor` (an
`inventory.Editor` passed by the caller, no global state) as actor and address: action `import` with the run name as
target for imports, and action `host.entry` with the entered address as target for the manual host form
(`Source` = manual). A dry run and a failed apply add no row. `asi import` passes actor `cli` and address `local`;
the web import and the manual host form pass the signed-in user and the client address. `asi host edit` SHALL write
its change through `Inventory.EditHostUserFields`, so it adds one `host.edit` row with actor `cli`, address `local`
and the address as target; an unknown host adds none.

#### Scenario: CLI import
- WHEN `asi import --format csv --file hosts.csv --name cli-1` succeeds
- THEN one audit row `cli import cli-1 local` is added, and the same command with `--dry-run` adds none

### REQ-EXCHANGE-010: Sample import files
`GET /import/sample.csv` and `GET /import/sample.json` SHALL require `import` and return, as attachments `asi-import-sample.csv` / `.json`, `exchange.Sample(format)`: the fixed inventory `exchange.SampleExport()` (three active hosts in 192.0.2.0/24 with three services, one host without services) written by the same encoders as the export (`exchange.WriteCSV`, `exchange.WriteJSON`). Importing either file into an empty inventory SHALL give no invalid rows, 3 hosts and 3 services. The import page SHALL link to both.

### REQ-EXCHANGE-011: CSV columns on the import page
`exchange.CSVColumns` SHALL list every CSV column the importer reads, each with a one-line meaning, and include every column of `exchange.CSVHeader`; `exchange.ParseCSV` SHALL read only these columns (others are ignored), so a column the parser reads is always in the list. The import page SHALL show the list as a table in that order.

### REQ-EXCHANGE-012: Dry run first, then import the same upload
The dry-run checkbox on `GET /import` SHALL be checked by default. An import result SHALL show the counts new hosts (`Report.NewHosts`: addresses not in the inventory), new services (`Report.NewServices`: services the inventory does not have), changed (changed or returned in the diff) and invalid rows, with the row errors listed. After a dry run with at least one valid host the page SHALL show an "Import N hosts" button that posts a random 128-bit token to `POST /import/confirm`, which imports the upload held by the handler (format and run name as in the dry run) without uploading it again. The handler SHALL hold at most one upload per user, for 15 minutes, and at most 60 MiB in total (oldest evicted first); a token is used once. An unknown, expired, already used or another user's token SHALL get 410 with "This dry run has expired or was started by another user, so nothing was imported. Upload the file again." and record nothing.

#### Scenario: dry run then import
- WHEN an editor uploads a JSON file with two valid hosts and one invalid row as a dry run and then presses "Import 2 hosts"
- THEN the dry run records nothing and shows 2 new hosts, 1 new service, 1 invalid row, and the confirm records one run with the two hosts

### REQ-EXCHANGE-013: Imports keep the inactive threshold of the scans
An import or manual entry run without an explicit threshold (`exchange.Options.InactiveAfter` 0: the UI, and
`asi import` without `--inactive-after`) SHALL be created with the `inactive_after` of the latest run (3 when there is
no run), so the status of hosts and services the import does not contain is derived as before and does not change;
an explicit `--inactive-after N` SHALL still be at least 1.

#### Scenario: inactive host and an import of another host
- WHEN scans with `--inactive-after 2` miss 192.0.2.1 twice (inactive) and a CSV of 192.0.2.5 is imported
- THEN 192.0.2.1 is still `inactive` as of the import and the diff to the import has no change for it
- AND the next scan with `--inactive-after 2` reports no second `host_inactive` for 192.0.2.1

### REQ-EXCHANGE-014: Pluralised import counts
The import and manual entry report SHALL pluralise its counts (`Imported 1 host and 1 service`,
`Dry run: 2 hosts and 3 services would be imported`).

