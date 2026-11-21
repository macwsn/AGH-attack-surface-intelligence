---
capability: signatures
title: Database signatures and their UI
code: []
tests: []
---
# Database signatures and their UI

## Requirements

### REQ-SIGNATURES-001: Manage signatures through forms
The system SHALL serve `GET /signatures` (list with id, name, kind, enabled state, last change), `GET /signatures/new`, `POST /signatures` (create), `GET /signatures/{id}`, `POST /signatures/{id}` (save), `POST /signatures/{id}/enable`, `POST /signatures/{id}/disable` and `POST /signatures/{id}/delete`. A form holds one signature as YAML in the format of `docs/contracts.md` §4 (a mapping or a one-item list). Saving SHALL run `detect.ParseOne` (the rules of `detect.Parse`) and, on a violation, re-render the form with 422 and `Rule violated: <rule>.` plus the detail; the id of a stored signature SHALL NOT change on save.

#### Scenario: unsafe method
- WHEN a user saves a signature with `request: {method: POST}`
- THEN nothing is stored and the page shows `Rule violated: methods GET and HEAD only.`

### REQ-SIGNATURES-002: Test a draft against a stored observation
`POST /signatures/test` SHALL evaluate the draft in the form (unsaved) against the latest stored observation of the service given by address, port and protocol, without sending any request, and SHALL show whether it matches, the extracted version, the evidence and the run of the observation. Only the stored response for `/` is available and bodies are not stored, so a signature with another `request.path` never matches in a test and body matchers never hold.

### REQ-SIGNATURES-003: Scans use database signatures
`(*scan.Scanner).Run` SHALL combine the enabled database signatures (`Scanner.Signatures`, wired to `detect.Library` by `asi scan run`) with the run's `--signatures-dir` signatures through `detect.Combine`, and fail the run when an id is defined in both or the extra-request limit is exceeded. Saving, enabling or importing a signature SHALL be rejected with the rule `id is unique` when its id is already stored or defined in the server's signatures directory (`ASI_SIGNATURES_DIR`), and with `at most 5 extra requests per service` when the enabled signatures together exceed it.

### REQ-SIGNATURES-004: Import and export
`GET /signatures/export` SHALL return all stored signatures as one YAML list in the format of `docs/contracts.md` §4 (`application/yaml`, attachment `signatures.yaml`). `POST /signatures/import` SHALL take such a list (pasted, at most 1 MiB), validate it as a whole, replace stored signatures with the same id, add new ones enabled, and store nothing when any signature violates a rule.

### REQ-SIGNATURES-005: Audit and access
Every create, save, enable, disable, delete and imported signature SHALL write an `audit_log` row (`signature.create`, `signature.update`, `signature.enable`, `signature.disable`, `signature.delete`, `signature.import`) with the actor, the signature id and the client address, in the same transaction as the change. Every `/signatures` route SHALL require `signature.manage`; viewer and operator get 403 and do not see the nav entry.

