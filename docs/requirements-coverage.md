# Requirements coverage

One row per requirement of [requirements.md](requirements.md): what it asks, the status, where it is implemented
and how it was verified. Status is strict:

- **met**: seen working while this documentation was written (commands and output are in [demo.md](demo.md) unless
  another source is named), or proven by a named test;
- **partly**: a part works, the gap is stated;
- **not yet**: not in this version.

The demo output was captured at commit `872c951`; features added after it are verified by the named tests.
Page URLs are relative to the UI (`http://127.0.0.1:8080`). Tests are Go test names; those in files ending in
`_integration_test.go` need the build tag `integration`.

`requirements.md` lists the functional requirements R1-R20, the nice-to-haves and the judging criteria. It has no
separate "minimum scope" list and no numbered list of validation points; the validation rows below follow its
section "How it will be judged".

## Functional requirements

| Id | Requirement | Status | Where it is implemented | How it was verified |
|---|---|---|---|---|
| R1 | Load IP addresses, CIDR ranges or domains | met | `internal/targets`; `asi scan run --targets-file`, `--exclude-file`; "Targets" and "Excludes" of `/scans/new` | `lab/targets.txt` is a CIDR with three excluded addresses: `asi scan show` reports 251 addresses for the /24. The quick start in the README scans two host names. IPv4 only. Oversized lists are refused: `TestScanRunAndPlanRefuseAddressesTimesPortsAboveCeiling`, `TestDefinitionValidateRefusesAddressesTimesPortsAboveCeiling`. Targets file upload and quick scan in the UI: `TestScanFormTargetsFile`, `TestQuickScan` |
| R2 | Safe discovery scan: multi-threaded, nmap, duration measured, subgroups sized from measured speed | met | `internal/scan`, `internal/scan/nmap`; `/runs/{id}`, `/scans/{id}/preview`, `asi scan plan` | `asi scan show NAME` prints one line per group with its duration. Adaptive size: `TestGroupSizeAdaptsDuringRun`, `TestSizerAdaptsToMovingAverage`, and the slow run in [the note below](#scheduling-check), where groups shrank from 64 to 47 addresses. Back-off and plan: `TestControllerDecreaseFloorRecovery`, `TestPlanSendsNothing`; plan summary in the scan form: `TestScanPlanEndpoint`. Never-probe ports get no service probe: `TestNeverProbePortsExcludedFromServiceDetection` |
| R3 | Detect live hosts | met | `internal/scan/nmap` (`-sn -PE -PS<ports>`) | 11 of 11 lab hosts in demo step 1; 485 of 485 on a /18 (`eval/results/perf/post-scale.json`, not committed) |
| R4 | Identify basic services | met | `internal/scan/nmap` (`-sT -sV --version-light`, then a default-intensity pass for unidentified ports); `internal/detect/services.go` | demo step 1: http, ssh (OpenSSH 8.9p1), redis (7.4.12) with product and version. Second pass: `TestSecondServicePassOptions`, `TestSecondServicePassOnlyFlaggedPortsPerHost`; technologies from nmap: `TestServiceTechnologies`, `TestRunNonHTTPServiceTechnologies`; no regression against stock nmap's soft matches: `TestSoftMatchGetsStockLightPass` |
| R5 | HTTP/HTTPS: title, status code, headers, cookies, TLS certificate, redirects | met | `internal/probe`; `/hosts/{address}` | host page of `172.30.9.12` in the lab: status 200, title, redirect to `/admin/login`, cookie `PHPSESSID; HttpOnly`, self-signed certificate with names and expiry, header table. Unidentified ports: `TestUnidentifiedPortsGetHTTPThenTLS` |
| R6 | Technology detection: CMS, framework, application server, IoT | met | `internal/detect`: built-in rules, technologies from nmap, 54-signature pack, embedded Wappalyzer dataset, heuristics, notable cookies, own signatures | demo step 1: WordPress 6.4.2, Drupal 10, PHP 7.4.3, nginx 1.27.5, NETCAM camera. Pack: `TestPackVulhubProducts`, `TestPackLabAGHProducts`. Products no signature knows: `TestHoldoutRecognisedWithoutFalseTechnologies`, `TestWappalyzerOfflineOnFetchedResponse`, `TestHeuristics`. Breadth is limited to the sources in [technical.md](technical.md#detection-sources-and-confidence) |
| R7 | Service traits: test/staging environment, administration panel | met | signature kinds `staging`, `admin-panel`; built-in `builtin-staging-*`, `builtin-login-form`, pack admin signatures; dashboard panel "Newest admin panels, staging and IoT" | demo step 1: `staging-environment` on `172.30.9.13`, `admin-panel-login` and `builtin-admin-login` on `172.30.9.12`. Built-in staging: `TestPackDetectsStagingEnvironments`; login form: `TestNotableLoginForm`; installers and management interfaces: `TestGenericAdminPanelOnHoldout` |
| R8 | Compare results between consecutive runs | met | `internal/diff`; `asi diff`; `/changes`, `/changes.json` | demo step 4 |
| R9 | Mark new, disappearing and changed services | met | change types in `internal/diff`; `/changes`, `/hosts/{address}/timeline`, dashboard | demo step 4: `host_new`, `host_missing`, `service_new`, `service_changed` with old and new values; step 8: `host_returned`, `host_inactive`. No false changes from per-request tokens or flapping fields: `TestPerRequestHeaderTokensAreNotAChange`, `TestLearnedVolatilityThroughRecordGroup`, `TestVanishedHostProbeFailureCarriesHTTPErrorAndNoServiceChanged` |
| R10 | Users create their own detection signatures | met | `internal/detect`; `/signatures`, `/signatures/new`; `--signatures-dir`, `ASI_SIGNATURES_DIR` | [signatures.md](signatures.md): a signature created, tested and exported through the UI; the lab's seven signatures run in every demo scan. Traversal rejected: `TestSignaturePathRejectsTraversal`; HEAD: `TestHeadAndGetSignaturesOnOnePathAreSentWithTheirOwnMethods`; guided form: `TestGuidedSignatureFormEndToEnd` |
| R11 | Form for manual entry and CSV and/or JSON files; entered data processed like scanned data | met | `internal/exchange`; `/hosts/entry`, `/import`; `asi import` | demo step 6: a CSV row gets a staging finding from a signature and appears in the diff. Same detection as a scan: `TestEnteredAndImportedServicesGetSameDetectionAsScanned`, `TestImportedJSONWithOldPHPGetsOutdatedFinding`. Sample files: `TestImportSamplesImportCleanly`. Imported data has no page body, so body-based rules cannot fire on it |
| R12 | RBAC: roles can be created and managed | met | `internal/auth`; `/roles`, `/users/`; `asi role list`, `asi user set-role` | `TestRolesPageMatrixAndChanges`, `TestCustomRoleGetsExactlyItsPermissions`, `TestCustomRoleLifecycle`, `TestDeleteRoleInUse`, `TestUsersPageAdminActions`, `TestUserAdminCommands`. Assigning a role needs all of its permissions, nobody edits their own role, and user actions apply only to users whose role the actor fully holds (commits `8ceb709`, `7b6fd3f`) |
| R13 | Built-in roles: administration; add/delete/modify; modify and read; read only | met | migration `0003_auth.sql`: `admin`, `editor`, `operator`, `viewer` | `TestBuiltinRolesAfterMigrate`; matrix in [technical.md](technical.md#rbac-matrix); demo step 7 for `viewer`; delete only for `editor` and `admin`: `TestHostAndServiceDeleteByRole` |
| R14 | Entered values can be edited regardless of scan state; edits survive later scans | met | user-owned columns of `hosts`; `/hosts/{address}` ("Edit host"), `asi host edit` | demo steps 2 and 5: tags, owner and notes set before run 2 are unchanged after runs 2 and 3. Editing during a running scan: `TestHostEditDuringRun`. Scanned values themselves (title, version) are observations; a correction entered through `/hosts/entry` is replaced by what the next scan sees |
| R15 | Clear UI for every role; main dashboard with the most important findings | met | `internal/web`; `/` | demo step 1 (dashboard: host and service counts, latest run, changes, top hosts by interest, newest admin panels, staging and IoT, certificates to check) and step 7 (navigation per role). Grouped navigation per role: `TestNavGroupsPerBuiltinRole`; first-run guidance: `TestDashboardFirstRunSteps`; pickers instead of typed ids: `TestExportRunIsPickedFromList`, `TestDefectDojoPicksProductEngagementAndRun`, `TestAuditActionFilterIsSelect`. "Clear" is a judgement |
| R16 | Database with encryption at rest for every field holding sensitive data | met | `internal/store/crypt.go`, `rotate.go`; columns listed in [technical.md](technical.md#encryption-at-rest) | demo step 11 shows a stored note as ciphertext; `TestSensitiveColumnsEncrypted` selects every table and finds no plaintext marker; rotation: `TestKeyRotate`; start refused with a wrong key: `TestStartupKeyCheckIsBoundedOnLargeObservationsTable`. Owners, display names, scan targets, signature sources: `TestOwnerDisplayNameAndRunScopeEncrypted`, `TestStoredSignatureSourceEncrypted`; upgrade of older data: `TestMigrationEncryptsExistingSensitiveRows`, `TestEncryptPendingRefusesWrongKey`; CSRF tokens hashed: `TestCSRFTokenStoredHashed`; every column classified: `TestColumnProtectionTableMatchesSchema` and [technical.md](technical.md#protection-of-every-column). Not encrypted by design: addresses, ports, titles, product names |
| R17 | Scheduling: time windows and frequency; a scan that exceeds its window is stopped and continued in the next | met | `internal/schedule`; `/scans`, `/scans/new`, `/runs/{id}` | `TestSchedulerStopsAtWindowEndAndResumes`. Also run live once: see [the note below](#scheduling-check). Rechecks between full runs: `TestSchedulerFullAndHourlyRechecks`, `TestRecheckOfKnownServicesIsFasterAndCheaperThanFullScan`; deleting a definition keeps its runs: `TestDeleteScanDefinition` |
| R18 | Request rate limiting | met | `internal/scan/limiter.go`, `adaptive.go`; `--max-rate`, "Max rate", `--no-adaptive` | `TestMaxRateCapsNmapAndProbeTogether`, `TestRateSamplesNeverExceedLimit`; measured at the targets: 0 seconds over the limit (`eval/results/perf/post-scale.json`, not committed). The nmap part of the shown rate is an estimate |
| R19 | Export to JSON or CSV; import of scan results from JSON or CSV | met | `internal/exchange`; `asi export`, `asi import`; `/export`, `/import` | demo steps 1, 5, 6 and 8 (CSV export), step 6 (CSV import); JSON export and import: the JSON round trip of the lab gave 0 changes (run once outside the demo) |
| R20 | Unstable hosts: how a change is reported, confidence of identification, missed scans before inactive | met | `internal/inventory/status.go`, `availability.go`, `export.go`; `internal/detect` | the three decisions are written down in [technical.md](technical.md#the-three-open-questions-of-the-challenge); demo step 4 (`unstable` after one miss) and step 8 (`inactive` at the threshold, `host_returned`). Usually-down hours: `TestApplyRhythmIgnoresDownHourMisses`; confidence times stability: `TestHostViewReportsConfidenceTimesStabilityAndLabelsOutdated` |

Signature rule of the challenge (detect presence only, never exploit): met for ASI's own probe and signatures. The
loader rejects any method but GET and HEAD, bodies, custom headers, credentials, query strings and path traversal;
each rejection is listed with its message in [signatures.md](signatures.md#safety-rules). nmap's service detection
sends nmap's own protocol probes, which are outside this rule ([technical.md](technical.md#what-nmap-sends)).

## Nice to have

| Item | Status | Where it is implemented | How it was verified |
|---|---|---|---|
| Time-of-day dependent differences | met | `inventory` availability profile; `/hosts/{address}/availability`, timeline label; rechecks by hour | `TestPeriodicAndUsualHours`, `TestApplyRhythmIgnoresDownHourMisses`, `TestAvailabilityExpected` (note `expected up at this hour`), `TestScheduledRecheckPicksHostsByAvailability`; label `Usually seen HH:00-HH:00`: `TestTimeOfDay`. Not shown live: it needs six covering runs at different hours |
| Interest or analytic priority score | met | `inventory.Score`; dashboard, `/hosts/?sort=interest&dir=desc`, timeline | demo step 1: "Top hosts by interest" |
| Repeated measurements for unstable hosts | met | re-probe at the end of a run, per-host retry after timeouts, recheck runs (`internal/scan`) | `TestReprobeMissing`, `TestReprobeBoundaries`, `TestHostPauseRetriedAtEnd`, `TestRecheckContactsOnlyKnownServices` |
| Grouping of similar services | met | `inventory.GroupServices`; `/groups` | the lab's two admin panel services (80 and 443) form one group of 2; `TestGroupServices` |
| Tags | met | `hosts.tags`; host page, `asi host edit --add-tag`, filter `tag` on `/hosts/` | demo steps 2 and 5 |
| Export to DefectDojo as informational findings | met | `internal/exchange/defectdojo`; `/defectdojo`, `asi defectdojo ...` | dry run in demo step 10; run once against a real DefectDojo 3.5 (commit `d396b88`, output not in the repository); its fixes are covered by `TestDefectDojoFixesFromRealDojoRun` against a fake server that replays DefectDojo's answers |
| Visualisation of changes over time | met | dashboard "Changes per run" chart, presence and availability strips on the host pages | `/` after two completed runs; `/hosts/{address}/timeline` |
| Passive data sources | not yet | - | the nearest thing is importing CSV or JSON from another system |

## Validation points

`docs/requirements.md` states how the solution is judged: a lab of hosts and services, at least two scan runs, then
editing of findings, import and role separation, weighted by six criteria.

| Point | Status | Where it is implemented | How it was verified |
|---|---|---|---|
| Runs against a lab imitating a varied infrastructure | met | `lab/run.sh` (own lab); `lab-agh/` (the organisers' environments) | `lab/run.sh` compares exports and diffs with `lab/expected.json`; the pack and detection were tuned on `lab-agh/` (`TestPackLabAGHProducts`). ASI was not scored against the organisers' reference results for this document |
| At least two scan runs with changes detected | met | `internal/diff` | demo steps 1, 4 and 8 |
| Editing of findings | partly | host-level fields; host and service deletion | tags, notes, owner, criticality, status override are edited and survive scans (demo steps 2, 5); a host or a service can be deleted (`TestHostAndServiceDeleteByRole`). A single finding cannot be annotated, dismissed or changed on its own |
| Import | met | `internal/exchange` | demo step 6; `TestEnteredAndImportedServicesGetSameDetectionAsScanned` |
| Role separation | met | `internal/auth`, `internal/web/router.go` | demo step 7; `TestViewerCannotChangeInventoryPages`, `TestRunPageReadableByEveryRoleActionsNeedScanRun`, `TestUsersPageOnlyForUserManage`, `TestRolesPageOnlyForRoleManage` |

| Weight | Criterion | Evidence | Open points |
|---|---|---|---|
| 30% | Discovery effectiveness and service identification on a large infrastructure | /18 with 16 384 addresses: 485 of 485 hosts, 594 of 594 services, 126-131 s per run (`eval/results/perf/post-scale.json`); lab: `lab/run.sh` | measured on a synthetic network, before adaptive rate and probing of unidentified ports; not repeated |
| 20% | Technical quality, documentation, presentation, ease of running, import/export, DefectDojo | five-command quick start ([README](../README.md)); this documentation; import and export in UI and command line; DefectDojo run once against a real instance | - |
| 15% | Change detection over time, unstable hosts, reporting | demo steps 4 and 8; 92 of 92 hosts taken down reported missing and returned with no other change (`eval/results/perf/post-scale.json`); 9 empty diffs over 10 unchanged runs (`eval/results/reliability/summary.md`); volatility tests under R9 | the reliability figures predate the fixes of `182dc8a` and `97fdcc7` |
| 15% | Safe operation, scan intensity control, dashboard | safety rules in [technical.md](technical.md#scanner-safety-rules); rate limit and back-off as in R18; pace presets; work ceiling; plan preview and live plan summary; no service probes to industrial and printing ports; dashboard as in R15 | nmap's own probes; the shown nmap packet rate is an estimate |
| 10% | Fingerprinting: technologies, CMSes, headers, cookies, signatures | lab findings in demo step 1; signature engine with seven matcher types; 54-signature pack; embedded Wappalyzer dataset and heuristics; built-in notable headers and cookies | 13 of 16 real applications recognised, 8 exact versions, before the pack (`eval/results/vulhub/asi-score-pre-pack.json`); not re-measured with the pack |
| 10% | Role separation and data protection | RBAC matrix, user and role pages with permission descriptions, own password page, audit page, demo steps 7 and 11, encryption of every personal or sensitive column, hashed session and CSRF tokens, key rotation | - |

## Scheduling check

A scan definition `nightly` was created through `/scans/new` on the acceptance lab (the lab /24, ports 22, 80
and 443, max rate 8, one worker, timezone Europe/Warsaw, frequency daily) with two windows a few minutes ahead:
`sat 20:27-20:28` and `sat 20:30-20:33`, then enabled. What happened, times in UTC:

| Time | Observed |
|---|---|
| 19:27:19 | the scheduler started run `nightly-20261121-192719` inside the first window |
| 19:28 | window end: the run page showed "Paused" and "The run is paused until its next window opens at 2026-11-21 19:30. It continues from its first unfinished group." |
| 19:30:19 | second window: the same run was `running` again |
| 19:32:57 | the run completed |

```
$ asi scan show nightly-20261121-192719
run nightly-20261121-192719 status=completed started=2026-11-21T19:27:19Z finished=2026-11-21T19:32:57Z groups=5 addresses=251 hosts=11 rate=1.6/s groups_done=5/5 failed_groups=0 eta=0s
group=0 addresses=64 hosts=11 duration=1m0.825s
group=1 addresses=64 hosts=0 duration=32.476s
group=2 addresses=47 hosts=0 duration=23.987s
group=3 addresses=47 hosts=0 duration=23.528s
group=4 addresses=29 hosts=0 duration=15.008s
```

The same output shows the group size following the measured speed (R2): after a first group of 64 addresses took
61 s, the next groups were cut to 47 addresses.

Not covered by this check: a run paused with finished groups behind it (here the first window ended before the
first group was recorded), and weekly or interval frequencies. Those are covered by the tests in
`internal/schedule`.
