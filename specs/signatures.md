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
`POST /signatures/test` SHALL evaluate the draft in the form (unsaved) against the latest stored observation of the service given by address, port and protocol, without sending any request, and SHALL show whether it matches, the extracted version, the evidence and the run of the observation. It SHALL use the stored response for `/` and the stored body excerpt (`detect.(*Signature).EvaluateHistory`), so a signature with another `request.path` never matches in a test and body matchers hold only on observations stored with a body.

### REQ-SIGNATURES-003: Scans use database signatures
`(*scan.Scanner).Run` SHALL combine the enabled built-in and database signatures (`Scanner.Signatures`, wired to
`detect.Library` by `asi scan run`) with the run's `--signatures-dir` signatures through `detect.Combine`, and fail the
run when an id is defined in both or the non-built-in signatures exceed the extra-request limit. Built-in signatures do
not count toward that limit: their extra paths are fetched only with the budget the other signatures leave, so a service
still gets at most 5 extra requests. When `Scanner.Signatures` is a shared library (`scan.SharedSignatures`, the one
`detect.Library` that `asi serve` builds with `ASI_SIGNATURES_DIR`), the run SHALL use its loaded set
(`(*detect.Library).Set`: the server's signatures directory and the enabled built-in and database signatures) and SHALL
NOT load the run's directory again when it is the server's directory. `(*detect.Library).Set` SHALL load the set once and
reuse it until a create, save, enable, disable, delete or import through the same library, so the scheduler and the web
layer share one loaded set. Saving, enabling or importing a signature
SHALL be rejected with the rule `id is unique` when its id is already stored, is a built-in id or is defined in the
server's signatures directory (`ASI_SIGNATURES_DIR`), and with `at most 5 extra requests per service` when the enabled
non-built-in signatures together exceed it.

### REQ-SIGNATURES-004: Import and export
`GET /signatures/export` SHALL return all stored signatures as one YAML list in the format of `docs/contracts.md` §4 (`application/yaml`, attachment `signatures.yaml`). `POST /signatures/import` SHALL take such a list (pasted, at most 1 MiB), validate it as a whole, replace stored signatures with the same id, add new ones enabled, and store nothing when any signature violates a rule.

### REQ-SIGNATURES-005: Audit and access
Every create, save, enable, disable, delete and imported signature SHALL write an `audit_log` row (`signature.create`, `signature.update`, `signature.enable`, `signature.disable`, `signature.delete`, `signature.import`) with the actor, the signature id and the client address, in the same transaction as the change. Every `/signatures` route SHALL require `signature.manage`; viewer and operator get 403 and do not see the nav entry.

### REQ-SIGNATURES-006: Retro-hunt over stored history
`(*inventory.Inventory).RunHunt` SHALL evaluate one signature (stored or draft) against every stored service observation with an HTTP response (optionally only runs started since a time), streamed in service and run order, without sending any request. It SHALL use the stored status, title, headers, cookie names, favicon hashes and, for `body_regex`, the stored body excerpt (`detect.(*Signature).EvaluateHistory`). Per service it SHALL report the address, port, protocol, the first and last run in which it matched, whether it matches in the latest run and the version extracted from the last match. A signature whose `request.path` is not `/`, or that needs a body on observations stored without one, SHALL be reported per service as not evaluable from history instead of not matching. Results SHALL be stored in `hunt_results` so they can be paged and exported.

#### Scenario: signature with a request path
- WHEN a hunt runs a signature with `request: {path: /api/health}`
- THEN every service with a stored HTTP response is listed as not evaluable from history and none as matching

### REQ-SIGNATURES-007: Stored body excerpt
The scan pipeline SHALL store the first 64 KiB (`inventory.MaxStoredBody`) of the root response body of each HTTP service observation in `service_observations.http_body`, encrypted with the field keyring. When a run finishes (`SetRunStatus` to completed or failed), the body excerpts of every service observed in that run SHALL be deleted except in its newest `ASI_BODY_RETENTION_RUNS` observations (default 10, `inventory.DefaultBodyRetention`; a value that is not a whole number of at least 1 is a configuration error). The rest of the observation stays; a hunt that needs a body treats the pruned observations as stored without one.

#### Scenario: retention bound
- GIVEN `ASI_BODY_RETENTION_RUNS=2` and a service observed with a body in runs r1 to r4
- WHEN run r4 finishes
- THEN only the observations of r3 and r4 keep a body, and a body hunt reports the service as first matching in r3

### REQ-SIGNATURES-008: Hunt from the CLI
`asi signature hunt --file SIG.yaml [--since DURATION] [--format text|json]` SHALL run a hunt for the one signature in the file (rules of `detect.ParseOne`), audited as actor `cli`, and print a summary line and one line per service, or with `--format json` a document `{"schema": "asi.hunt/v1", "hunt": {…}, "results": [{address, port, protocol, evaluable, first_run, last_run, matches_latest_run, version}]}`. `--since` takes a Go duration or a number of days (`30d`).

### REQ-SIGNATURES-009: Hunt in the UI
The signature form SHALL offer "Hunt in history" (`POST /signatures/hunt`) for the draft in the form, with a period. `GET /signatures/hunts/{id}` SHALL show the results 50 per page with figures for matching services, matches in the latest run and services not evaluable; `GET /signatures/hunts/{id}/csv` SHALL return all results as CSV with the columns `address,port,protocol,evaluable,first_run,last_run,matches_latest_run,version`. Like the inventory CSV export (`exchange.WriteCSV`), every cell that starts with `=`, `+`, `-`, `@`, tab or CR SHALL be prefixed with `'` (`exchange.NeutralizeRow`).

#### Scenario: formula in a title
- GIVEN a hunt whose version is extracted from the title `=HYPERLINK(...)`
- WHEN the hunt CSV is downloaded
- THEN the version cell is `'=HYPERLINK(...)`

### REQ-SIGNATURES-010: Save after a hunt and record findings
`POST /signatures/hunts/{id}/save` SHALL store the hunted signature (create, or update keeping the enabled state) and, when `record` is set, add a finding with `source: "retro-hunt"` to the latest-run observation of every service that matches in the latest run, once per signature; these findings SHALL appear in export (`findings[].source`, omitted for scanned findings) and diff like scanned findings. When a run newer than the hunt's latest run exists, nothing SHALL be recorded (409) and the user is asked to hunt again.

### REQ-SIGNATURES-011: Hunt audit and access
Every hunt SHALL write an `audit_log` row `signature.hunt` and every recording a row `signature.hunt.record`, with the actor, the signature id and the client address. All hunt routes SHALL require `signature.manage`; a viewer gets 403.

### REQ-SIGNATURES-012: Built-in signatures are loaded by default
`(*detect.Library).Enabled` SHALL return every signature of the built-in pack (`detect.Pack()`, ids `builtin-*`) that
is not disabled, together with the enabled database signatures. The enabled state of a pack signature is stored in
the table `builtin_signatures` (migration `0010_builtin_signatures.sql`); a pack signature without a row is enabled.
Creating or importing a signature whose id equals a pack id SHALL be rejected with the rule `id is unique` and store
nothing. `GET /signatures/export` and `(*detect.Library).List` SHALL contain only stored signatures, never pack ones.

#### Scenario: fresh database
- WHEN no row exists in `builtin_signatures`
- THEN `Enabled` returns every pack signature plus the enabled database signatures

### REQ-SIGNATURES-013: Enable and disable built-in signatures in the UI
`GET /signatures` SHALL list every pack signature (id, name, kind, enabled state, last change) in a section
"Built-in signatures", each marked `Built-in`, with an Enable or Disable button. `GET /signatures/{id}` for a pack id
SHALL show its YAML read-only with Enable or Disable and without Save or Delete. `POST /signatures/{id}/disable` and
`/enable` for a pack id SHALL behave as for database signatures (redirect, audit `signature.disable` /
`signature.enable` with the id, persistent across restarts, same `signature.manage` permission) and change what
`Enabled` returns. `POST /signatures/{id}` (save) and `POST /signatures/{id}/delete` for a pack id SHALL store nothing
and answer 422 with `Rule violated: id is unique.` and the detail that built-in signatures can only be enabled or
disabled.

#### Scenario: disable a built-in signature
- WHEN an editor disables `builtin-grafana`
- THEN the list shows it Disabled with an Enable button, an `audit_log` row `signature.disable builtin-grafana` exists
- AND scans no longer use it, also after the server restarts

### REQ-SIGNATURES-014: Built-in admin interfaces and versions of the Vulhub products
The built-in pack SHALL report an `admin-panel` finding for the Grafana login page (`builtin-grafana-login`: boot data
of a signed-out user with the login form hints), for phpMyAdmin on its login page (`builtin-phpmyadmin-login`) and
when it opens without a login (`builtin-phpmyadmin-open`: the navigation panel), for the ActiveMQ web console
(`builtin-activemq-console`: a 401 with the realm `ActiveMQRealm` or the console welcome or admin page) and for
Jenkins (`builtin-jenkins-admin`). It SHALL recognise Elasticsearch from its REST root (version from
`version.number`) and ActiveMQ from the same markers as its console. Drupal SHALL report the most specific version
the page shows (core asset `?v=` versions refine the major of `X-Generator`/generator, a major alone stays a major),
and Apache Tomcat its version from its own page, never from the `Apache-Coyote` connector string. Against every
fixture in `internal/detect/testdata/pack/` the pack SHALL yield only that fixture's product.

#### Scenario: Vulhub fixtures
- WHEN the pack runs on the Grafana 8.2.6 login page, phpMyAdmin 4.8.1 without a login, ActiveMQ 401 or welcome page
- THEN each yields its technology and an `admin-panel` finding and nothing else
- AND Tomcat 8.0.43 behind `Server: Apache-Coyote/1.1` is `Apache Tomcat` 8.0.43, Drupal 8.5.0 is 8.5.0 and Drupal 10
  with only `X-Generator: Drupal 10` is `10`

### REQ-SIGNATURES-015: Built-in notable headers, cookies and login forms
When the signature set contains the built-in pack, `(*detect.Set).Detect` and `DetectRecorded` SHALL add, from the
root response already fetched (no extra request), these built-in findings:
- kind `interesting-header` (`builtin-header-<name>`) for `X-Powered-By`, `X-Generator` and `Server` whose value
  carries a version number, for any `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Debug-Token`,
  `X-Debug-Token-Link`, `X-Environment`, `X-Backend-Server` and `X-Served-By`, and for `Via` naming an internal host
  (private IPv4, `localhost`, `.local`, `.localdomain`, `.internal`, `.intranet`, `.lan`, `.corp`, `.home.arpa`).
  The evidence SHALL be `<Header>: <value>`; the value of the two debug-token headers SHALL be redacted. A missing
  security header SHALL NOT be a finding.
- kind `interesting-cookie`: `builtin-cookie-stack` when a cookie name identifies the stack (`PHPSESSID` PHP,
  `JSESSIONID` Java, `ASP.NET_SessionId` ASP.NET, `laravel_session` Laravel, `connect.sid` Express, `phpMyAdmin`
  phpMyAdmin, `wordpress_*` WordPress), each implied technology also recorded with confidence 40 and source
  `builtin`; `builtin-cookie-no-httponly` for a session cookie set without HttpOnly; `builtin-cookie-no-secure` for a
  session cookie set without Secure on an `https` service. Evidence SHALL name cookies, never their values.
- kind `admin-panel`, `builtin-login-form`, name `Login form`, confidence 50, when the root response (after
  redirects) contains a password input inside a form and no other `admin-panel` finding matched the service.
A set without built-in signatures yields none of these.

#### Scenario: organisers' stacks
- WHEN the root response carries `X-Powered-By: PHP/5.6.30` and the cookie `phpMyAdmin`
- THEN the service has `builtin-header-x-powered-by` with evidence `X-Powered-By: PHP/5.6.30` and
  `builtin-cookie-stack` naming `phpMyAdmin`, and the technology phpMyAdmin

#### Scenario: DVWA login page
- WHEN the root redirects to a page with `<form><input type="password"></form>` and only a technology signature matched
- THEN the service has one `builtin-login-form` finding of kind `admin-panel`; with a specific admin-panel match it has none

### REQ-SIGNATURES-016: HEAD requests
A signature with `request.method: HEAD` SHALL be sent as `HEAD` through `(*probe.Session).Head`, which shares the
cache-per-request and the cap of `probe.MaxExtraRequests` with `Fetch`. Extra requests are deduplicated by method and
path: a path requested by both `HEAD` and `GET` signatures is fetched once with each method. A `HEAD` signature on `/`
is evaluated against the root `GET` response the probe already holds and costs no extra request.

#### Scenario: HEAD and GET signatures
- WHEN one signature requests `HEAD /h` and another `GET /g`
- THEN the server receives exactly one `HEAD /h` and one `GET /g`, and both signatures match

#### Scenario: HEAD and GET signatures on one path
- WHEN two signatures request `HEAD /x` and one requests `GET /x`
- THEN the server receives exactly one `HEAD /x` and one `GET /x`, and all three signatures match

### REQ-SIGNATURES-017: Hunt "latest" is relative to the run that covers the service
`asi signature hunt` SHALL mark a result `latest` (`matches_latest_run`) when it matched in the latest run, up to the
hunt's latest run, that covers the service: the latest run whose group covered the address, or the latest run with
the same targets and excludes as the run that last observed the service; a failed run that recorded no group counts
as no run. Recording hunt findings writes them on that
observation.

#### Scenario: a different network was scanned last
- WHEN Grafana matched on 10.0.2.1 in `lan-1` and the last run `dmz-1` scanned only 10.0.3.0/29
- THEN the hunt reports the 10.0.2.1 result as latest and recording adds the finding to its `lan-1` observation

### REQ-SIGNATURES-018: Request paths are normalised and traversal is rejected
`detect.Parse` SHALL reject, under the rule `RulePath`, a `request.path` that does not start with `/`, starts with `//` (a host) or has a scheme, has a query (`?`) or a fragment (`#`), contains a backslash, an invalid percent-encoding, or a `.` or `..` segment, also with a `;` path parameter (`/..;/`) or when percent-encoded (`%2e%2e`). The error SHALL name the rule and the reason. An accepted path SHALL be stored cleaned (`path.Clean`, keeping a trailing slash).

#### Scenario: traversal
- WHEN a signature file has `request: {path: /../../etc/passwd}` or `request: {path: /%2e%2e/etc/passwd}`
- THEN loading fails with a `detect.RuleError` whose rule is `RulePath`

### REQ-SIGNATURES-019: Built-in staging and test environment detection
With the built-in pack loaded, detection (live and on stored HTTP data) SHALL report findings of kind `staging`: `builtin-staging-header` (confidence 75) when `X-Environment`, `X-Env` or `X-Stage` names staging, stage, test, testing, dev, development, uat, preprod or sandbox; `builtin-staging-hostname` (65) when the hostname has staging, stage, test, dev, uat, preprod or sandbox as a separate word; `builtin-staging-title` when the title has such a marker in brackets (70) or as a separate word (60). Words that only contain a marker (`latest`, `contest`, `device`, `developer`, `testimonials`, `backstage`) SHALL NOT match.

#### Scenario: bracketed title
- WHEN a stored response has the title `[STAGING] Shop`
- THEN the service gets the finding `builtin-staging-title` of kind `staging`

### REQ-SIGNATURES-020: Embedded public fingerprint dataset
When the signature set contains the built-in pack, `(*detect.Set).Detect` and `DetectRecorded` SHALL also run the
fingerprints embedded in `github.com/projectdiscovery/wappalyzergo` (MIT, named in `NOTICE`) over the headers, the
cookie names (minus the stack cookies of REQ-SIGNATURES-015) and the body already fetched, with no network access and
no extra request. Each result SHALL become a technology with source `wappalyzer`, confidence 60, its version when the
dataset gives an exact one, and its category mapped to ours (for example `Web servers` `web-server`, `CMS` `cms`,
`JavaScript libraries` `javascript-library`, `Issue trackers` and `Development` `development-tool`), technologies the dataset only implies whose category is `database` or `search-engine` (MySQL for WordPress,
Elasticsearch for Kibana: a separate service, not seen on this port) SHALL be left out; the rest is merged with the
technologies of nmap, the signatures and the built-in rules by `detect.Merge` (dataset names `Nginx`, `Apache HTTP
Server`, `Microsoft ASP.NET` map onto `nginx`, `Apache`, `ASP.NET`). A result that rests only on a response header
SHALL be kept only when its header pattern matches a whole word of the header value (not inside a longer word: `bun`
in `PHP/7.2.24-0ubuntu0.18.04.17` is no evidence of Bun; digits and punctuation count as word boundaries); a
technology the dataset implies SHALL be kept only when the technology implying it was kept.

#### Scenario: Gogs installer
- WHEN the root response is the Gogs installation page
- THEN the technologies include `Gogs` with source `wappalyzer`, category `development-tool`, confidence 60

#### Scenario: Ubuntu build of PHP
- WHEN a WordPress page sends `X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.17`
- THEN the dataset technologies include `PHP` and `Ubuntu` and not `bun`

### REQ-SIGNATURES-021: Generic heuristics
With the built-in pack the same functions SHALL add, for products no signature or dataset named, a technology with
source `heuristic` and a finding of kind `technology` with the evidence it came from, from what the page says about
itself, using only responses already fetched (no extra request):
- confidence 40 (`builtin-heuristic-app-metadata`): the content of `<meta name="application-name">`,
  `<meta property="og:site_name">`, `<meta name="apple-mobile-web-app-title">`, and the `name` and `short_name` of the
  web app manifest linked with `<link rel="manifest">` when that manifest was already fetched by a signature, when the
  value is 1-3 words (an explicit `x.y[.z]` at the end is the version) and not only generic words; the evidence names
  the tag or the manifest path and field;
- confidence 40 (`builtin-heuristic-generator`, `builtin-heuristic-title`, `builtin-heuristic-header`): the content of
  `<meta name="generator">` (name and version); a product name in the title of an installer, login or dashboard page
  (`Installation - Gogs`, `Sign in - X`, `Login to X`, `X Console`, `X Admin`, `Welcome to X`); `Server` and
  `X-Powered-By` tokens with a version (`CouchDB/3.2.1`); and `X-<Product>-Version` headers;
- confidence 30 (`builtin-heuristic-title-corroborated`), only when neither the metadata, the generator nor a title
  pattern above named a product and no technology of another source has a product category (`cms`, `database-admin`,
  `database`, `search-engine`, `webmail`, `network-device`, `camera`, `ci-cd`, `container-management`, `nas`,
  `identity`, `development-tool`, `monitoring`, `web-application`): the title is split on ` - `, ` | `, ` · `,
  ` :: `, `: ` and en/em dashes, a trailing ` by <vendor>` is dropped from each part, and the first part of 1-3 words
  (an explicit `x.y[.z]` next to the name is the version) that is not only generic words or bare numbers, not an
  address or host name (no word starting with a digit or containing a dot, not the host name of the URL or its first
  label) and not a sentence (no function word such as `the`, `to`, `is`, no final `.`, `!` or `?`) becomes the
  product when its normalised form (lower case, words joined or joined with hyphens) also occurs as a whole word
  (camelCase counts) in a `script`/`img` `src` or `link` `href` path, a cookie name, a response header name or value
  (host names in values do not count), an element `id` or `class`, a JS global (`window.X`, `window["X"]`,
  `var|let|const X`) in an inline script, or the application metadata above; the evidence is `page title,
  corroborated by <where> <value>`. An `admin-panel` finding on the page does not change this confidence.

The stop list of generic words is shared by all these rules. Names made only of generic words (`Login`, `Dashboard`,
`Home`, `Index of /`, `Web Console`, `Admin Login`, and non-English login words such as `Logowanie`, `Zaloguj`,
`Anmelden`, `Connexion`, …, and ordinary page names such as `Contact Us`, `About Us`, `Careers`, `News`) SHALL never become products, and a heuristic SHALL not add a product already named by
another source. Heuristic technologies keep source `heuristic` and their confidence in the export and on the host page.

#### Scenario: titles
- WHEN the title is `Installation - Gogs`, `Openfire Admin Console` or `Solr Admin`
- THEN the heuristic technology is `Gogs`, `Openfire` or `Solr`
- AND the titles `Login`, `Dashboard`, `Home` and `Index of /` yield no technology

#### Scenario: corroborated title
- WHEN the title is `Quorvel` and the page loads `/static/js/quorvel.min.js`
- THEN the technology `Quorvel` has source `heuristic`, confidence 30 and the evidence
  `page title, corroborated by asset path /static/js/quorvel.min.js`

#### Scenario: ordinary sites
- WHEN the title is `Campus Blog`, `Campus Portal`, `[STAGING] Rekrutacja`, `Intranet v1`, `Admin Panel - Sign in`,
  `NETCAM Web Client` or `Host 10.x`, or a two-word blog title that occurs only in the body text, or a default
  web-server page, or the host name
- THEN no technology comes from the title

### REQ-SIGNATURES-022: Generic admin panels and unfinished installations
Unless another `admin-panel` finding matched the service, the built-in rules SHALL add one `admin-panel` finding with
confidence 50 from the root response after redirects: `builtin-unfinished-installation`, name `Unfinished
installation`, for an installer page (title or path naming install, installer, installation or setup, or boot data
saying setup is not completed, such as `"has-user-setup": false` or a non-null `"setup-token"`); else `builtin-login-form`, name `Login form`, for a password input inside a form (on
the root page or the redirect target); else `builtin-management-interface`, name `Management interface`, when the
title or path contains admin, console, manager, dashboard, login or sign in. This replaces the login-form bullet of
REQ-SIGNATURES-015, which it keeps as its second case.

#### Scenario: holdout products
- WHEN the root responses of Webmin, Metabase (setup not completed), Openfire, the Solr admin and the Gogs installer
  are detected
- THEN they get `Login form`, `Unfinished installation`, `Login form`, `Management interface` and `Unfinished
  installation`

### REQ-SIGNATURES-023: Guided signature form
The signature page (`GET /signatures/new`, `GET /signatures/{id}` of a non-built-in signature) SHALL have two tabs, "Form" and "Edit as YAML" (`?view=yaml`); "Form" is the default for a new signature and for a stored signature the form can represent. The form SHALL offer name, id (new signatures only; empty derives it from the name: lower case, runs of other characters become `-`), a kind select of `detect.Kinds` (the kinds `detect.Parse` accepts), category, confidence, "All conditions must hold" / "Any condition is enough", one or more conditions, each a matcher select (`detect.FormMatchers`: header, cookie, title, body, status, favicon) with a header or cookie name and a value, an optional version (source header, title or body, header name and an RE2 pattern whose first group is the version, group 0 without a group) and an optional request path. `detect.Form.YAML` SHALL turn the form into one signature in the format of `docs/contracts.md` §4: title and body map to `title_regex` and `body_regex`, favicon to `favicon_sha256` when the value is 64 hex characters and to `favicon_mmh3` otherwise, cookie keeps only the name, an empty path or `/` writes no `request`. Every form post (create, save, test, hunt) SHALL carry `mode=form` and use that YAML as the source, so the stored `Source` is exactly the YAML the page shows read-only beside the form. The YAML SHALL be refreshed by htmx on every change (`hx-post="/signatures/form"`, `hx-select="#signature-yaml"`, no inline script); `POST /signatures/form` re-renders the page without saving, adds a condition (`add`), removes condition `remove=<index>` or, with `view=yaml`, opens the generated YAML in the YAML tab. "Test against stored data" and "Hunt in history" SHALL be submit buttons of the same form (`formaction` `/signatures/test` and `/signatures/hunt`).

#### Scenario: two conditions
- WHEN an editor submits name "Nginx web server", kind technology, any of header Server ~ nginx and status 200, version from header Server `nginx/([0-9.]+)`
- THEN signature `nginx-web-server` is stored with that YAML as source, and `detect.ParseOne` of it equals the parse of the YAML shown beside the form

### REQ-SIGNATURES-024: Signatures the form cannot show
`detect.FormOf(source)` SHALL return the form of a stored source only when the form's YAML parses to the same signature (id, name, kind, category, confidence, method, path, matchers and version); a signature with both all and any, a HEAD request, a cookie value, a condition group or another version group opens on the "Edit as YAML" tab with a note that the form cannot show it. The YAML tab SHALL edit the raw YAML as before; built-in signatures show only the read-only YAML.

### REQ-SIGNATURES-025: Rule violations next to their field
`detect.RuleError` SHALL carry `Field`: `id`, `name`, `kind`, `confidence`, `request`, `match`, `version` or `match.<all|any>.<index>` (`detect.ConditionField`) for the condition that broke the rule; a signature without both name and id reports the missing name. When a form post is rejected, the page SHALL show the detail inside the label of that field as `<span class="problem" id="problem-…">`, referenced by `aria-describedby` and `aria-invalid="true"` on its input, in addition to the page notice.

#### Scenario: invalid regex in the second condition
- WHEN the form is tested with conditions status 200 and body `([`
- THEN the response is 422 and the Value field of the second condition shows `Rule violated: regexes are valid RE2.` with `aria-describedby="problem-condition-1"`

### REQ-SIGNATURES-026: Tests and hunts on stored data need inventory permissions
Routes that read or change stored inventory data SHALL require more than `signature.manage`:
- `POST /signatures/test`, `POST /signatures/hunt`, `GET /signatures/hunts/{id}` and `POST /signatures/hunts/{id}/save`
  SHALL require `signature.manage` and `inventory.read`.
- `GET /signatures/hunts/{id}/csv` SHALL require `signature.manage`, `inventory.read` and `export`.
- `POST /signatures/hunts/{id}/save` with `record` set SHALL answer 403 to a role without `inventory.edit`. It SHALL
  store neither the signature nor any finding.

The other `/signatures` routes keep `signature.manage` alone. These are the list, the form, create, save, enable,
disable, delete, import and export. The signature form SHALL offer "Test against a service" and "Hunt in history" only
to a role with `inventory.read`. The hunt page SHALL offer "Export CSV" only with `export` and the record option only
with `inventory.edit`.

#### Scenario: signature.manage alone
- WHEN a user whose role holds only `signature.manage` posts a test against the stored service 10.0.0.1:80/tcp, starts a hunt, or opens a stored hunt
- THEN each answers 403 and shows no stored address, title or run
- AND the same user can still list, create, edit, enable, disable, delete and export signatures

#### Scenario: record without inventory.edit
- WHEN a user with `signature.manage` and `inventory.read` saves a hunt with `record=1`
- THEN the answer is 403 and no finding is recorded

### REQ-SIGNATURES-027: One finding per service for the same trait
Detection (`(*detect.Set).Detect`, `DetectRecorded`, `DetectService`) SHALL return at most one finding per trait of a
service (`detect.MergeFindings`). Findings are the same trait when they have the same `kind` and `version` and: for
`admin-panel` and `staging`, any name (a service is an admin panel or a staging environment once, whichever
signatures say so); for `interesting-header`, the same header named at the start of the evidence (`X-Debug-Token: …`
or `GET /: header x-debug-token …`), else the same name; for every other kind the same `name`. Of such findings it
SHALL keep one: a finding of a user signature (an id without the `builtin-` prefix) before a built-in one, then the
one with the highest confidence (the first on a tie), so the ids user signatures and expected results name stay
visible. The kept finding SHALL get the highest confidence of the group and `; also matched by <id>, <id>` with the
signature ids of the others appended to its evidence. Findings of one kind and name with different versions stay apart.

#### Scenario: staging found three ways
- WHEN a service sends `X-Environment: staging` and the title `[STAGING] Rekrutacja` and the lab signature
  `staging-environment` also matches
- THEN the service has one `staging` finding with confidence 75 whose evidence names `builtin-staging-header` and
  `builtin-staging-title`

#### Scenario: WordPress from a user signature and the pack
- WHEN `wordpress-generator` and `builtin-wordpress` both find WordPress 6.4.2
- THEN the service has one `technology` finding WordPress listing both signature ids

#### Scenario: admin panel found by two signatures
- WHEN the lab admin service matches `admin-panel-login` (Admin panel login form, 80) and `builtin-admin-login`
  (Admin login page, 70)
- THEN the service has one `admin-panel` finding from `admin-panel-login` whose evidence names `builtin-admin-login`

