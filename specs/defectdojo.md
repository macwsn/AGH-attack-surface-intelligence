---
capability: defectdojo
title: DefectDojo export
code: []
tests: []
---
# DefectDojo export

## Requirements

### REQ-DEFECTDOJO-001: Encrypted configuration
The system SHALL store the DefectDojo base URL, API token, product id, engagement id, the returned test ids and the last exported run as one AES-256-GCM sealed value under the key `defectdojo` of the `settings` table (`defectdojo.DBStore`), SHALL never print, render or log the token, and SHALL keep the saved token when a configuration is saved with an empty token and the same base URL; saving a different base URL without a new token SHALL be rejected, so the saved token is never sent to a new host. When the base URL, product, engagement or token change, saving SHALL first run the connection test of REQ-DEFECTDOJO-002 with the new values and SHALL not save when it fails, unless forced (`asi defectdojo configure --force`, or "Save even if the connection test fails" on the page). Saving is written to the audit log as `defectdojo.configure`.

#### Scenario: new host without token
- WHEN the configuration with a saved token is saved with base URL `https://other.example` and an empty token
- THEN the save is rejected with "the API token is required when the base URL changes" and the settings are unchanged

#### Scenario: token not shown again
- WHEN a user saves the configuration with a token and opens `/defectdojo` again
- THEN the token field is empty and the page says a token is saved

#### Scenario: rejected token
- WHEN a configuration is saved and DefectDojo answers the connection test with 403
- THEN nothing is saved and the error says "not saved: the connection test failed" and that the API token was rejected

### REQ-DEFECTDOJO-002: Test connection
The system SHALL check the saved configuration with `GET /api/v2/engagements/<engagement>/` and the header `Authorization: Token <token>`, and SHALL fail when the engagement belongs to another product, from `asi defectdojo test` and the "Test connection" action of `/defectdojo`; it SHALL then check the stored test ids as REQ-DEFECTDOJO-008 says.

### REQ-DEFECTDOJO-003: Nmap scan import and reimport
The system SHALL export the open services seen in the exported run (`defectdojo.NmapXML`) as nmap XML with scan type `Nmap Scan`, posting multipart to `/api/v2/import-scan/` with the engagement id when no test id is stored and to `/api/v2/reimport-scan/` with the stored test id afterwards, and SHALL store the test id returned by DefectDojo.

#### Scenario: second export
- WHEN run `d1` was exported and returned test 101 and run `d2` is exported
- THEN the nmap XML is posted to `/api/v2/reimport-scan/` with `test=101`

### REQ-DEFECTDOJO-004: Findings
The system SHALL export findings of kinds `admin-panel`, `staging`, `iot`, `interesting-header`, `interesting-cookie`, `custom` and `outdated` on services seen in the run (`defectdojo.GenericFindings`) as Generic Findings Import JSON with the host address and port as the endpoint, the evidence in the description and `unique_id_from_tool` `asi:<address>:<protocol>/<port>:<signature id>`; `outdated` findings SHALL have severity `Low` and the detected version and the evidence with the minimum version in the description, the others severity `Info`. Every open service seen in the run SHALL also be exported as an `Info` finding titled `Open service: <address>:<port> <product> <version>` (the service name when there is no product) with `unique_id_from_tool` `asi:<address>:<protocol>/<port>`, so services that appear or vanish open and close findings on reimport. Findings are imported and reimported like the nmap scan in their own test; `technology` findings are not exported. The nmap scan stays the endpoint inventory.

### REQ-DEFECTDOJO-005: Errors with the cause, without the token
The system SHALL send every DefectDojo request through the `defectdojo.Doer` interface and SHALL report a failed request with its method, path, response status and DefectDojo's response body, whitespace collapsed and cut to 300 characters, leaving out every JSON value (and every non-JSON body) that contains the token; a 401 or 403 SHALL say the API token was rejected, and an answer that is not JSON SHALL say the base URL does not look like a DefectDojo API.

### REQ-DEFECTDOJO-006: CLI and UI
The system SHALL provide `asi defectdojo configure --url URL --product ID --engagement ID [--token-stdin] [--force]`, `asi defectdojo test` and `asi defectdojo export --run NAME [--dry-run [--out DIR] | --force]`; `--dry-run` SHALL write `nmap.xml` and `findings.json` to DIR (default `defectdojo-NAME`) byte-identical to what an export of the same run sends (the nmap `start` is the run's start time) and print the endpoints it would use without sending any request. The page `/defectdojo` SHALL explain where the product and engagement ids are found in DefectDojo and, after an export, link to the engagement and the tests in DefectDojo. The page and its actions `POST /defectdojo/test` and `POST /defectdojo/export` SHALL require the `export` permission; changing the connection (`POST /defectdojo/settings`) SHALL require `scan.configure`, and users without it see the saved connection read-only.

### REQ-DEFECTDOJO-007: Test ids per target
The system SHALL remember the nmap and findings test ids and the last exported run per target (base URL, product id, engagement id) in the sealed `defectdojo` settings, so that switching the engagement and switching back reimports into the tests created for that target instead of creating new ones.

#### Scenario: engagement round trip
- WHEN run `r2` was exported to engagement 3 into tests 41 and 42, the engagement is saved as 999 and then as 3 again, and `r2` is exported
- THEN the nmap XML is posted to `/api/v2/reimport-scan/` with `test=41` and the findings with `test=42`

### REQ-DEFECTDOJO-008: Recreating a deleted test
The system SHALL, when a reimport into a stored test is answered with 404, or with 400 saying the test does not exist, import the payload once with `/api/v2/import-scan/` into the configured engagement, store the new test id and say in the result of the export (CLI output and the page) that the test was recreated. `asi defectdojo test` and "Test connection" SHALL also check with `GET /api/v2/tests/<id>/` that the stored test ids still exist and name the ones that do not.

#### Scenario: deleted nmap test
- WHEN the stored nmap test 101 was deleted in DefectDojo and a run is exported
- THEN one import creates a new test, the output says "the nmap test 101 no longer existed in DefectDojo and was recreated as test 103"

### REQ-DEFECTDOJO-009: Older runs need confirmation
The system SHALL refuse to export a run that started before the run last exported to the same target, with a message naming both runs, unless the export is forced: `asi defectdojo export --run NAME --force` on the CLI, or the "Export run NAME anyway" button that the page shows after the refusal.

#### Scenario: export of an older run
- WHEN run `d2` was exported and run `d1`, which started before `d2`, is exported
- THEN nothing is sent and the CLI fails with "run d1 is older than run d2, the last one exported to this engagement …"

### REQ-DEFECTDOJO-010: Product, engagement and run are picked from lists
For users with `scan.configure`, when a base URL and token are saved, the page `/defectdojo` SHALL load the products
(`GET /api/v2/products/`) and the engagements of the chosen product (`GET /api/v2/engagements/?product=<id>`), paged
with `limit` and `offset` and sorted by name, from the saved base URL only and with the saved token
(`defectdojo.Service.Choices`), and SHALL show Product and Engagement as selects of "name (id N)"; changing the product
reloads the engagement select from `GET /defectdojo?product_id=<id>`. When the lists cannot be loaded the numeric id
inputs SHALL stay, with the hint where the id is found in DefectDojo and that the list could not be loaded. The token
SHALL never be rendered. The Run of "Export a run" SHALL be a select of the completed runs, newest first, with
"Latest" (empty value) first and selected by default.

#### Scenario: lists not available
- WHEN DefectDojo answers `GET /api/v2/products/` with 404
- THEN the page shows the numeric Product id and Engagement id inputs with "2 in /product/2" and "3 in /engagement/3"

### REQ-DEFECTDOJO-011: Payload limited to what the run covered
`asi defectdojo export --run NAME`, its `--dry-run` and the UI export SHALL send only the hosts the run observed and,
on them, only the services the run observed (`inventory.ExportHost.NotInRun`, `inventory.ExportService.NotInRun`,
set by the inventory when the as-of run did not see the host or service); hosts and services kept active from earlier
runs are left out. The findings payload SHALL carry each kind, name and version of one service once
(`detect.MergeFindings`, REQ-SIGNATURES-027), also for stored data recorded before the merge existed.

#### Scenario: run covering one host
- WHEN run d1 saw 192.0.2.1:80 and 192.0.2.2:22 and run d2 only scanned 192.0.2.1
- THEN `asi defectdojo export --run d2 --dry-run` reports `(1 hosts, 1 services)` and neither file names 192.0.2.2

### REQ-DEFECTDOJO-012: Preview on the DefectDojo page
The export form of `/defectdojo` SHALL offer a `Preview` button (`preview=1` on `POST /defectdojo/export`) that builds
the payloads of the run exactly as an export would (`(*defectdojo.Service).Preview`) and shows the number of tests that
would be sent (2), the hosts, services and findings and whether each test is created or updated, without any request to
DefectDojo.

