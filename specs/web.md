---
capability: web
title: Web UI shell
code: []
tests: []
---
# Web UI shell

## Requirements

### REQ-WEB-001: Every route declares its access
The system SHALL register every UI route through `Router.Handle(method, path, access, handler)` where access is `web.Public()`, `web.SignedIn()` or `web.Require(permission, more...)`, and `web.New` SHALL fail at startup when a route or nav entry has no declared access, an unknown permission in any position, an unsupported method, a nil handler or a duplicate method and path. A route declared with several permissions SHALL be allowed only to a user holding every one of them; `Access.Permissions()` returns all of them in declaration order, `Access.Permission()` returns the first one, and `Access.String()` names all of them.

#### Scenario: undeclared access
- WHEN a feature registers a route with the zero `web.Access{}`
- THEN `web.New` returns an error and `asi serve` does not start

#### Scenario: several permissions
- WHEN a route is declared `web.Require(inventory.read, export)` and a user holds only `export`
- THEN the route answers 403; a user holding both gets the page

### REQ-WEB-002: Feature registry
The system SHALL build the UI from the `features` slice in `internal/web/web.go`, one `Register<Feature>(r *Router, d Deps)` function per line, each defined in the feature's own file; `docs/ui-conventions.md` SHALL describe how to add a page, a nav entry and a template.

### REQ-WEB-003: Login and logout
The system SHALL serve `GET /login` and `POST /login` publicly, sign users in through `internal/auth`, set the session cookie and redirect with 303 to a local `next` path or `/`; a failed login SHALL re-render the form with 401 (wrong credentials) or 429 (rate limited). `POST /login` SHALL require a CSRF token matching the `asi_login_csrf` cookie set by the form. `POST /logout` SHALL require a session and its CSRF token, end the session and redirect to `/login`.

#### Scenario: open redirect
- WHEN `next` is not a local path (for example `//evil.example/`) or contains a backslash or an ASCII control character (for example `/\t/evil.example/`)
- THEN login redirects to `/`

### REQ-WEB-004: Sessions, 401 and 403
The system SHALL require a valid session for every non-public route; without one a browser request SHALL be redirected with 303 to `/login` (with `next` for GET requests other than `/`), an htmx request SHALL get 401 with `HX-Redirect: /login`, and a stale session cookie SHALL be cleared. A signed-in user lacking the route's permission SHALL get a 403 HTML error page.

### REQ-WEB-005: CSRF
The system SHALL reject non-GET/HEAD requests on non-public routes with 403 unless they carry the session's CSRF token in the `X-CSRF-Token` header or the `csrf_token` form field. A `multipart/form-data` request without the header SHALL carry the field among the form fields before the first file part; the router SHALL read at most 64 KiB of the body to find it, compare it in constant time and hand the unchanged body to the handler, so an upload is still streamed and never parsed by the router. Templates SHALL get the token as `.CSRFToken` and a hidden form field as `.CSRFField`, and the layout SHALL send the token on htmx requests through `hx-headers`.

### REQ-WEB-006: Navigation by permission
The system SHALL show in the layout navigation only the nav entries whose access the signed-in user's role satisfies, and no navigation to anonymous users.
Every nav entry SHALL belong to a group registered with `(*Router).NavIn(group, label, path, access, also...)`; the layout SHALL render each group as `<div class="nav-group">` with a short heading `<h2 class="nav-heading">` followed by its entries, in the fixed order of the router (`web.NavOverview`, `NavInventory`, `NavScanning`, `NavData`, `NavAdministration`) regardless of feature registration order: Overview (Dashboard, Changes), Inventory (Hosts, Groups), Scanning (Scans, Signatures), Data (Import, Export, DefectDojo), Administration (Users, Roles, Audit log). A group with no entry shown to the user SHALL render no heading. `(*Router).Nav` without a group renders its entries in a group without a heading before the others; an unknown group SHALL make `web.New` fail.
The system SHALL mark exactly one shown nav entry with `aria-current="page"`: the entry whose path is the longest match of the request path, where `/` matches only `/` and any other entry matches its own path and every path below it (e.g. `/hosts/10.0.0.1` and `/hosts/entry` mark Hosts, `/scans/42` marks Scans). An entry may name further prefixes of its section: Scans also covers `/runs` and `/runs/{id}`, so a run page marks Scans. A path under no entry marks none.

#### Scenario: viewer
- WHEN a viewer (only `inventory.read`) signs in
- THEN the navigation shows Overview (Dashboard, Changes) and Inventory (Hosts, Groups) and no Scanning, Data or Administration heading

### REQ-WEB-007: Templates and assets
The system SHALL render pages with `html/template` from a base `layout.html` and one page template per feature file in `internal/web`, all embedded and parsed at startup; a template that fails to parse, lacks a `content` block, or a missing `layout.html` or `error.html` SHALL make `web.New` fail. The system SHALL serve one embedded CSS file (`/static/app.css`) and embedded htmx (`/static/htmx.min.js`) and SHALL reference no external resources.

### REQ-WEB-008: Security headers
The system SHALL send on every response `Content-Security-Policy` without `unsafe-inline`, `unsafe-eval` or external sources (`default-src 'none'; script-src 'self'; style-src 'self'; ... frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: same-origin`, including error pages and redirects.

### REQ-WEB-009: Dashboard and health
The system SHALL serve the dashboard at `GET /` to any signed-in user, showing the username and role. To a user
whose role holds `inventory.read` it SHALL show, from `(*inventory.Inventory).Dashboard`: the number of active,
unstable and inactive hosts; the number of active, unstable and inactive services in the latest run's export; the
changes of the latest scan (see below); the 10 hosts with the highest interest score (address as tie-breaker); the 10
most recently first-seen `admin-panel`, `staging` and `iot` findings on hosts that are not inactive; certificates that
are self-signed or expire within 30 days, soonest first; and the latest run's name, status, start, groups recorded,
addresses covered and hosts found. An empty database SHALL render empty states instead. To a user whose role lacks
`inventory.read` the dashboard SHALL load no inventory data and show no counts, hosts, findings, certificates or run
names: only the message "Your role cannot see inventory data." and links to the navigation entries the role may open
(the main navigation filtered by access, without the dashboard itself). The system SHALL render unknown paths as a 404
HTML error page and keep `GET /healthz` public. `asi serve` SHALL wire the store, keyring, `auth.Service` and `web.New`.

The change panel SHALL compare the latest run with source `scan`, status `completed` and a mode other than `recheck`
(`Dashboard.ChangesTo`) against the newest earlier run matching the same conditions (`Dashboard.ChangesFrom`); imports,
manual entries, rechecks, running, paused and failed runs SHALL never be part of the pair. The changes SHALL be counted
per `asi.diff/v1` change type with `diff.Compute` and recomputed only when the pair or the latest run's data changes
(the cache key holds both run ids). The panel SHALL name both runs ("Scan <to> against scan <from>", each linking to
`/runs/<id>`), link "All changes" to `/changes?from=<from>&to=<to>`, and list the changed hosts (at most 10, each
linking to `/hosts/<address>`, then "N more hosts" linking to the change list). A pair without changes SHALL say
"No changes since run <from>." (below the line naming both scans); with one completed scan it SHALL say "Changes appear after the second
scan. Scan <name> is the only completed scan so far."; with none, "Changes appear after the second run.".
Below, the panel SHALL list, each linking to its run page, the newest run after the compared scan (after any run when
there is none) of each kind: "Latest import" (source `import`, completed), "Latest manual entry" (source `manual`,
completed), "Latest recheck" (source `scan`, mode `recheck`, completed) and "Running now" (status `running`; "Paused
now" for `paused`). These lines SHALL never replace the compared pair.

The "Latest run" panel SHALL count the addresses in flight of a running run in "Addresses covered" (REQ-SCAN-009) and,
while that run is running or paused, carry `id="latest-run" hx-get="/" hx-trigger="every 3s" hx-select="#latest-run"
hx-swap="outerHTML"`; without an open latest run it SHALL carry no polling attributes.

#### Scenario: two runs
- WHEN run d1 saw hosts .1-.4 and the running run d2 sees .1, .2 (changed title), .4 and a new .5 with an admin panel
- THEN the dashboard shows 4 active and 1 unstable host, .1 first by interest, the .5 admin panel as the newest
  finding, d2 as running with 1 group recorded, "Changes appear after the second scan." and "Running now d2"
- AND once d2 completes, one new host, one missing host, one changed and one missing service

#### Scenario: scan, scan, import, manual entry, running scan
- WHEN completed scans scan-one and scan-two (new host 10.60.0.2) are followed by the import import-one, the manual
  entry manual-one and the running scan scan-three
- THEN the panel shows New hosts 1 for scan-two against scan-one, links to `/changes` and `/hosts/10.60.0.2`, and the
  lines "Latest import import-one", "Latest manual entry manual-one" and "Running now scan-three"

#### Scenario: recheck and failed scan
- WHEN a completed recheck or a failed scan follows completed scans scan-a and scan-b
- THEN the panel still compares scan-b against scan-a; the recheck appears as "Latest recheck", the failed run not at all

#### Scenario: role without inventory.read
- WHEN run audit-run-seven recorded host 10.0.0.1 with an http service titled "Audit Leak Portal" and a user whose role
  holds only `export` (or no permission at all) opens `GET /`
- THEN the page answers 200 with the no-inventory message, contains neither the address, the title, the run name nor
  any count, links `/export` but not `/hosts/` (no link at all for the zero-permission role), while the built-in
  viewer still sees the full dashboard

### REQ-WEB-020: Hosts list page
`GET /hosts/` SHALL require `inventory.read`, appear in the navigation as "Hosts" and render `inventory.html` with one
page of 50 hosts from `(*inventory.Inventory).ListHosts`; `GET /hosts` SHALL redirect to it. The query parameters `q`
(free text), `status`, `port`, `service`, `technology`, `finding`, `tag`, `sort` (`address`, `display_name`, `status`,
`interest`, `last_seen`), `dir=desc` and `page` SHALL filter, sort and page the list, and the filter form SHALL show
them. Column headers SHALL link to the same filter sorted by that column (the current column flips direction, the page
resets), and the previous/next links SHALL keep every filter and the sort. A status outside active/unstable/inactive,
a port outside 1-65535, an unknown sort key or a page below 1 SHALL render the 400 error page naming the value. No
match SHALL show an empty state with a link that clears the filters, and a page past the end an empty state with a link
to the first page.
The lede SHALL read "1 host in the inventory" / "N hosts in the inventory" (filtered: "1 matching host" / "N matching
hosts"). In the ports column a port whose services in the host's latest state are all unstable or inactive SHALL be a
`.status unstable` or `.status inactive` span titled with the status; ports with an active service stay plain text.
Every relative time on the hosts list, host page, changes page, timeline and dashboard SHALL carry its exact time in a
`title`.

#### Scenario: filtered pages
- WHEN 61 active hosts run ssh and a viewer opens `/hosts/?service=ssh&status=active`
- THEN the page shows 50 hosts and "Showing 1-50 of 61", and its next link keeps `service=ssh&status=active` and
  leads to the remaining 11 hosts

### REQ-WEB-021: Host page
`GET /hosts/{address}` SHALL require `inventory.read` and render `host.html` from `(*inventory.Inventory).HostDetail`:
status, missed runs, stability, interest score, user fields, every service (port/protocol, state, status, service,
product and version, finding kinds), for each HTTP service its URL, status code, title, server, redirects, cookie
names and flags, decrypted response headers and TLS subject, issuer, names, expiry and self-signed flag, its
technologies with confidence and its findings with evidence, and one history row per run that covered the address
(run name, date, seen or missed, services seen). An unknown or invalid address SHALL render the 404 error page.
The page SHALL show, in this order: an "Edit host" action in the page head for users who may edit, the summary
figures, the user-owned fields (tags, owner, criticality, status override, notes) in the panel "Owner, tags and
notes", the Services table, the per-service detail panels, response times, the remaining host fields and History, and
last, for users who may edit, the edit form inside a `<details id="edit">` disclosure whose summary reads "Edit host".
The "Edit host" action links to `/hosts/{address}?edit=1#edit`; the disclosure is open when `edit=1` is given or the
submitted form has problems, and closed otherwise.

#### Scenario: unknown host
- WHEN a viewer opens `/hosts/10.9.9.9` or `/hosts/not-an-address`
- THEN the response is the 404 error page

#### Scenario: edit from the first screen
- WHEN an operator opens a host page and follows "Edit host"
- THEN `/hosts/{address}?edit=1#edit` opens with the edit form expanded; a viewer sees the owned fields but no action

### REQ-WEB-022: Edit user-owned host fields
The host page SHALL show an "Edit host" form (tags as a comma-separated list, display name, owner, criticality,
status override, notes) only to users with `inventory.edit`. `POST /hosts/{address}` SHALL require `inventory.edit` and
the CSRF token. It SHALL trim the values, split tags on commas and drop empty and repeated tags, and reject more than 32
tags, a tag over 64 characters, a display name or owner over 200 characters, notes over 10 000 characters, a
criticality other than empty, low, medium, high or critical, and a status override other than empty, active, unstable
or inactive. A rejected form SHALL be rendered again with status 422, the submitted values, each problem next to its
field, and no change. An unknown host SHALL get the 404 error page. A valid form SHALL be saved with
`(*inventory.Inventory).EditHostUserFields`, which writes the fields and an `audit_log` row (`host.edit`, actor, host,
client address) in one transaction, and SHALL redirect with 303 to `/hosts/{address}?saved=1`, which shows "Saved.
Later scans keep these values." The edit SHALL neither wait for nor be overwritten by groups recorded by a running
scan.

#### Scenario: edit while a scan runs
- WHEN an editor saves the form while a running run records groups covering the host, and the run then completes
- THEN the edit returns 303 and the host keeps the edited values, while the page also shows the new scan results

### REQ-WEB-023: Viewers cannot change inventory pages
Every non-GET route registered by the inventory and dashboard features SHALL answer a signed-in viewer with a valid
CSRF token with the 403 error page and leave the host unchanged; operators, editors and admins SHALL succeed.

#### Scenario: viewer posts the edit form
- WHEN a viewer posts a valid edit form with their own CSRF token to `/hosts/10.0.0.2`
- THEN the response is the 403 error page and `GetHostUserFields` returns the previous values

### REQ-WEB-024: Escaped output
Every value from scans, signatures or users (titles, headers, cookies, certificate fields, technologies, findings and
evidence, hostnames, tags, display name, owner, criticality, notes, query parameters) SHALL be HTML-escaped on the
dashboard, the hosts list, the host page, the edit form and error pages; no stored or submitted value SHALL appear as
markup.

#### Scenario: script in a title, a header and a note
- WHEN a host has `<script>alert(1)</script>` as HTTP title, as a response header value and in its notes, and
  `"><script>…` and `' onmouseover='…` in other fields
- THEN `/`, `/hosts/`, `/hosts/?q=<payload>` and `/hosts/{address}` contain no unescaped copy of any payload, and the
  host page shows the escaped text

### REQ-WEB-010: Change feed between two runs
`GET /changes` SHALL require `inventory.read` and appear in the navigation as "Changes". Without `from` and `to` it
SHALL compare the two most recent `completed` runs (older as `from`); with `from` and `to` it SHALL compare the named
runs. The page SHALL let the analyst pick both runs from all runs (newest first) and a change type (`host_new`,
`host_missing`, `host_returned`, `host_inactive`, `service_new`, `service_missing`, `service_returned`,
`service_inactive`, `service_changed`); with `type` set it SHALL show only changes of that type. The rows SHALL be the
`changes` of `diff.Between` for the two runs in the same order, each with a `.change` mark, the service as
`<port>/<protocol>` for service changes, `.diff` old (`del`) and new (`ins`) values for `service_changed`, and the
address linked to `/hosts/{address}/timeline`.
An empty old or new value SHALL render as a muted `(none)` in place of the `del` or `ins` (`old → (none)`,
`(none) → new`). A `service_changed` whose HTTP data disappeared (its `http.status_code` and every other changed `http.*` field became empty) SHALL show the single line
"HTTP data no longer available" instead of those fields. A change with more than 5 fields SHALL show all of them inside
a `<details>` whose summary reads "N changed fields". Fields that are empty in both runs SHALL not be listed.

#### Scenario: HTTP data disappears
- WHEN a web service stops answering HTTP between two runs and every `http.*` field becomes empty
- THEN its row reads "HTTP data no longer available" and lists none of those fields

#### Scenario: default selection
- WHEN runs `w1`, `w2`, `w3` have completed and the analyst opens `/changes`
- THEN the page compares `w2` to `w3` and lists exactly the changes of `asi diff --from w2 --to w3`

#### Scenario: type filter
- WHEN the analyst opens `/changes?from=w1&to=w2&type=service_changed`
- THEN only the `service_changed` rows of that diff are listed, in diff order

### REQ-WEB-011: Change feed as JSON
`GET /changes.json?from=<run>&to=<run>` SHALL require `inventory.read` and respond with the `asi.diff/v1` document
byte-identical to the file `asi diff --from <run> --to <run> --format json` writes. A missing `from` or `to` SHALL
give 400 and an unknown run 404, both as plain text.

#### Scenario: same bytes as the CLI
- WHEN `asi diff --from d1 --to d2` writes a file and a signed-in viewer requests `/changes.json?from=d1&to=d2`
- THEN the response body equals the file byte for byte

### REQ-WEB-012: Change feed errors and empty state
An unknown change type or only one of `from`/`to` SHALL give the 400 error page and an unknown run name the 404 error
page, each with a plain message naming the offending value, never a 500. With fewer than two completed runs and no
`from`/`to`, `/changes` SHALL show an empty state. Run names, values and messages SHALL be HTML-escaped.

#### Scenario: unknown run
- WHEN the analyst opens `/changes?from=w1&to=nope`
- THEN the response is 404 with the message `Run "nope" does not exist.`

### REQ-WEB-013: Host timeline
`GET /hosts/{address}/timeline` SHALL require `inventory.read`. A value that is not an IP address SHALL give the 400
error page and an address never seen the 404 error page, each naming the value. For a known host the page SHALL show:
- the status, or `Usually seen HH:00-HH:00` instead of it when `inventory.TimeOfDay` finds a pattern and the host is
  not inactive;
- the interest score as a `.meter` (`high` from 70) and every reason of `inventory.Score` with its points;
- an inline `<svg class="strip">` with one `<rect>` per run (up to the last 50, oldest first), classed `seen`, `missed`
  or `uncovered`, each with a `<title>` naming the run, its time (UTC) and the presence;
- a table of the runs, newest first, with the presence and the changes of that run. Host-level changes are taken against
  the previous covering run and service changes (with `.diff` old/new fields) against the previous run in which the host
  was seen, both computed with `diff.Compute` on single-host states.
The page SHALL use no inline styles or scripts and no external assets. The SVG strip is an `app.css` component shown in
the styleguide.

#### Scenario: title change after a missed run
- WHEN a host is seen with title "Intranet v1", missed in the next covering run, not covered in the next, and then seen
  with "Intranet v2"
- THEN the strip reads seen, missed, uncovered, seen, and the last run lists "Returned host" plus "Changed service 80/tcp"
  with `http.title` v1 → v2

### REQ-WEB-014: Service groups page
`GET /groups` SHALL require `inventory.read` and appear in the navigation as "Groups". It SHALL show the
`inventory.GroupServices` groups of the state as of the latest run, counting only services that are not `inactive`.
There SHALL be one row per group, largest first: count, technologies, title, favicon SHA-256, and up to 10 members
(`address:port`), each linked to `/hosts/{address}/timeline`, followed by "and N more". With no web services the page
SHALL show an empty state. All values SHALL be HTML-escaped.

#### Scenario: three equal login pages
- WHEN three services share the technologies {nginx, PHP} in any order, the title "Login" and favicon `aa`, and a fourth
  differs only in favicon
- THEN `/groups` lists a group of 3 followed by a group of 1

### REQ-WEB-015: Change chart on the dashboard
For a user with `inventory.read`, the dashboard SHALL show a "Changes per run" panel, defined in its own template block
`change-chart` (`changes_chart.html`). The panel holds an inline `<svg class="chart">` with one `<g>` per run for the
last 20 consecutive pairs of completed runs, oldest first. Each `<g>` carries the run name, a `<title>` with the counts
in words, and three bars (`new`, `missing`, `changed`) scaled to the highest count. Counts follow REQ-DIFF-008. With
fewer pairs the chart shows the ones that exist; with fewer than two completed runs the panel shows an empty state.

#### Scenario: 22 completed runs
- WHEN 22 runs have completed
- THEN the chart has exactly 20 entries, for runs 3 to 22, each with the counts of `diff.Count(diff.Between(previous, run))`

### REQ-WEB-016: Host page response times
`GET /hosts/{address}` (permission `inventory.read`) SHALL list the web services of the host with the latest response
time, the median of the last 10 runs and the number of measured runs, mark a service `Slower than usual` (`.kind.slow`)
by REQ-INVENTORY-018 and `Timed out` (`.kind.timeout`) when the latest probe timed out. An unknown host is 404.

#### Scenario: slow service
- WHEN a viewer opens the page of a host whose port 80 answered in 1200 ms after ten runs around 100 ms
- THEN the row of port 80 shows `1200 ms`, `100 ms` and `Slower than usual`

### REQ-WEB-025: Host availability strip
The UI SHALL serve `GET /hosts/{address}/availability` with `inventory.read` (403 without it; a 404 page for an
address that is not a host of the inventory as of the latest run, or is not an address). It SHALL render the host's
availability profile (`inventory.ExportHost.Availability`, REQ-INVENTORY) as a `<span class="presence">` with exactly
24 `<i>` cells for hours 00..23, class `seen` when the bucket is >= 0.8, `missed` when <= 0.2 and no class otherwise,
each with a `title` like `14:00 up 83%`, followed by the usual hours in words: `Usually up 08:00-18:00` for a periodic
host (consecutive usual hours joined into ranges ending one hour after the last usual hour, a range across midnight
written `22:00-06:00`, several ranges in order of their start separated by `, `), `No regular hours yet` for a host
with samples that is not periodic, and `No availability data yet` without a strip for a host without samples. The
strip is the template block `availability-strip` in the partial `availability_strip.html`, taking the page's data. The
host page `GET /hosts/{address}` SHALL show the same strip and words in its Host panel as `Availability`, followed by a
link `By hour` to `/hosts/{address}/availability` when the host has samples. Only existing `app.css` classes are used.

#### Scenario: periodic host
- GIVEN a host seen 3 times at each hour 08..17 and missed 3 times at 02
- WHEN a user with `inventory.read` opens `/hosts/<address>/availability`
- THEN the strip has 24 cells, cells 08..17 are `seen`, cell 02 is `missed`, and the page says `Usually up 08:00-18:00`

#### Scenario: host page
- GIVEN the same host
- WHEN a user with `inventory.read` opens `/hosts/<address>`
- THEN the Host panel shows the 24-cell strip, `Usually up 08:00-18:00` and a link to `/hosts/<address>/availability`

### REQ-WEB-026: Recheck controls and run modes on the scan pages
The scan form SHALL have a `Recheck every` field (`recheck_every`, REQ-SCHEDULE-001) that shows the `recheck` problem
under it when the form is re-rendered with 422. `POST /scans/{id}/start` SHALL accept the form field `mode` = `full`
(default when absent) or `recheck` and start a run of that mode (audit `scan.start` as before); any other value SHALL
answer 400 and start nothing; `recheck` without an earlier run to recheck (`inventory.ErrNoRecheckBase`) SHALL
re-render the definition page with 422 and an error notice containing `no earlier run to recheck`, creating no run.
The definition page SHALL offer `Start recheck` next to `Start scan now` (both hidden while a run is open), show the
recheck interval in its settings, and list each run with its mode (`Full` or `Recheck`), packet count and, for a
recheck, the saving against the latest earlier completed full run of the same definition as a whole percent,
round(100 × (1 − recheck packets / full packets)); a full run, or a recheck without such a full run (or one with 0
packets), shows `—`.

#### Scenario: saving of a recheck
- GIVEN a definition with a completed full run of 2000 packets and a later recheck of 100 packets
- WHEN a user opens `/scans/{id}`
- THEN the full run shows `Full`, `2000` and `—`, and the recheck shows `Recheck`, `100` and `95%`

### REQ-WEB-027: Users page
The system SHALL serve a Users page at `GET /users/` (`GET /users` redirects there; feature `RegisterUsers` in
`internal/web/users.go`, template `internal/web/users.html`) listing every user with username, role, enabled or
disabled state and creation time, with forms to create a user with a role and an initial password
(`POST /users/create`), change a user's role (`POST /users/{username}/role`), reset a password
(`POST /users/{username}/password`), disable or enable a user (`POST /users/{username}/disable`, `.../enable`) and
delete a user after a confirmation step (`GET /users/{username}/delete` shows the confirmation, only
`POST /users/{username}/delete` deletes). Each change goes through the `web.UserAdmin` dependency (`Deps.Users`,
`auth.Service` in `asi serve`) with the signed-in user as audit actor and the client address as audit address, then
redirects to `/users/` with a confirmation notice. The Users nav entry
opens the Administration group of the navigation (REQ-WEB-006).

#### Scenario: create a user
- WHEN an admin submits the create form with username dave, role editor and a 12+ character password
- THEN the response redirects to `/users/?done=created&user=dave`, dave can sign in, and one `user.create` audit row
  with the admin as actor and the client address is added

#### Scenario: delete needs confirmation
- WHEN an admin follows Delete for dave
- THEN a confirmation panel with a "Delete user" button is shown and dave still exists until that form is posted

### REQ-WEB-028: Users page problems
The system SHALL answer a rejected user change with the Users page and a `notice warn` message instead of a server
error, changing nothing and writing no audit row: the last enabled admin (`auth.ErrLastAdmin`, 409, "Nothing was
changed: "U" is the last enabled admin. Make another user an admin first."), an existing username
(`auth.ErrUserExists`, 409), a password under 12 characters (`auth.ErrPasswordTooShort`, 422), an unknown role
(`auth.ErrUnknownRole`, 422) and an empty username (422); an unknown user gets the 404 page. For the create form the
same message SHALL also appear as a `span.problem` next to the field it concerns (username for an existing or empty
username, initial password for a short password). The page header SHALL count users as "1 user" or "N users".

#### Scenario: demote the last admin
- WHEN the only enabled admin submits Change role with role viewer for themselves
- THEN the response is 409 with the last-admin message and the user is still an enabled admin

#### Scenario: duplicate username
- WHEN an admin creates a user with an existing username
- THEN the response is 409 with the message in the warn notice and next to the username field

### REQ-WEB-029: Users page access
Every `/users` route SHALL require `user.manage`, so every role without it (editor, operator and viewer among the
built-in roles) gets 403 on each of them, and SHALL require the CSRF token on every POST; the Users nav entry SHALL be
shown only to roles with `user.manage`. The page SHALL use only `app.css` classes and no inline styles.

#### Scenario: editor
- WHEN an editor requests `GET /users/` or posts to any `/users` route
- THEN the response is 403 and the editor's navigation has no Users entry

### REQ-WEB-030: Roles page
The system SHALL serve a Roles page at `GET /roles` (feature `RegisterRoles` in `internal/web/roles.go`, template
`internal/web/roles.html`) showing every built-in and custom role as a row of a permission matrix with one column per
permission of `auth.AllPermissions`, ticked where the role has it. Custom roles are edited in place by ticking
permissions and saving (`POST /roles/{name}`), created from a name and ticked permissions (`POST /roles/create`) and
deleted after a confirmation step (`GET /roles/{name}/delete` shows it, only `POST /roles/{name}/delete` deletes),
through the `web.RoleAdmin` dependency (`Deps.Roles`, `auth.Service` in `asi serve`) with the signed-in user and the
client address as audit actor and address. Built-in roles are shown with disabled ticks and no edit or delete
controls. Rejected changes re-render the page with a `notice warn` and change nothing: a built-in role
(`auth.ErrBuiltinRole`, 409, also for its confirmation page), an existing name (`auth.ErrRoleExists`, 409), a role
assigned to a user (`auth.ErrRoleInUse`, 409), an unknown permission (`auth.ErrUnknownPermission`, 422) and an empty
name (422); an unknown role gets the 404 page.

#### Scenario: built-in role
- WHEN an admin posts changed permissions to `/roles/viewer`
- THEN the response is 409 with "Nothing was changed: "viewer" is a built-in role and cannot be edited or deleted.
  Create a custom role instead." and viewer keeps only `inventory.read`

#### Scenario: delete a role in use
- WHEN an admin posts `/roles/auditor/delete` while a user has role auditor
- THEN the response is 409 with a message that the role is assigned to a user and the role still exists

### REQ-WEB-031: Custom roles get exactly their permissions
A user whose custom role has a set of permissions SHALL be allowed on every route whose access is signed-in or one of
those permissions and SHALL get 403 on every other permission-gated route, and the navigation SHALL show exactly the
entries those permissions allow.

#### Scenario: inventory.read and export
- WHEN a role with exactly `inventory.read` and `export` is created on the Roles page and a user with it signs in
- THEN the hosts, changes, groups, run, timeline, DefectDojo and export routes work, every other gated route returns
  403, and the navigation is Dashboard, Changes, Hosts, Groups, Export and DefectDojo

### REQ-WEB-032: Roles page access
Every `/roles` route SHALL require `role.manage` (403 for editor, operator, viewer and any role without it) and the
CSRF token on every POST; the Roles nav entry, placed right after Users in the Administration group, SHALL be shown
only to roles with `role.manage`. The page SHALL use only `app.css` classes and no inline styles.

### REQ-WEB-033: Audit log page
The system SHALL serve `GET /audit` (feature `RegisterAudit` in `internal/web/audit.go`, template
`internal/web/audit.html`, nav entry "Audit log" after Roles, `Require(user.manage)`) listing audit entries with time,
actor, action, target and address, newest first, 50 per page, through the `web.AuditLog` dependency (`Deps.Audit`,
`auth.Service.ListAudit` and `auth.Service.ListAuditActions` in `asi serve`). Filters `actor`, `action` and `target`
match exactly; the Action filter SHALL be a select of "Any" and the distinct action names in the log (plus the
requested action when it is not among them), while Actor and Target stay free text; `from` and `to` take
`2026-11-21` or `2026-11-21 14:05` in local time, `from` inclusive and `to` inclusive of its whole day or minute; an
invalid date or page answers 400. The page shows "Showing a-b of n" with Previous/Next links that keep the filters.

#### Scenario: second page
- WHEN 120 entries exist and an admin opens `/audit?page=2`
- THEN entries 51 to 100 (newest first) are shown with "Showing 51-100 of 120" and links to pages 1 and 3

### REQ-WEB-034: Every web change is audited
Each of these web actions SHALL add exactly one audit row with the signed-in user as actor, the client address and
the affected name as target: UI import (`import`, run name), manual host entry (`host.entry`, address), host edit
(`host.edit`), signature create, update and delete (`signature.*`, id), scan create (`scan.create`, name), scan start,
pause and resume (`scan.start`, `scan.pause`, `scan.resume`, run name), DefectDojo configure (`defectdojo.configure`,
base URL) and DefectDojo export (`defectdojo.export`, run name); a dry-run import adds none.

### REQ-WEB-035: Administration access
A viewer SHALL get 403 on every `GET` and `POST` route under `/users`, `/roles` and `/audit` and on every delete
route (hosts, services, signatures), changing nothing. The navigation SHALL show Users and Audit log only to roles
with `user.manage` and Roles only to roles with `role.manage`, including custom roles that hold only one of them.

### REQ-WEB-036: Hosts list does not show technology as a finding
The hosts list Findings column and its `finding` filter options SHALL omit the `technology` kind, which the
Technologies column already shows. The host page SHALL keep listing technologies with their source and technology
findings.

#### Scenario: WordPress host
- WHEN a host has a WordPress technology and the findings `admin-panel` and `technology`
- THEN its hosts list row shows WordPress under Technologies and only "Admin panel" under Findings, and the Finding
  filter has no Technology option

### REQ-WEB-037: Outdated findings and volatile headers in the UI
Findings of kind `outdated` SHALL be shown with the mark label "Outdated version" (class `kind outdated`) and offered
in the finding kind filter. The scan definition form SHALL have a "Volatile headers" field (comma-separated) stored in
the definition's `volatile_headers` setting. The definition page lists the volatile headers in its Settings panel. Dashboard, host and import/export pages use the
configured `Deps.Inventory` (with `ASI_VOLATILE_HEADERS`) when one is given, so the dashboard's "Changes in the latest
run" ignores configured volatile headers like `/changes` does.

### REQ-WEB-038: Fields that change every run on the host page
The host page SHALL show, in the panel of each service with volatile fields (REQ-DIFF-015), a table headed
`Changes every run` and `Last values` with one row per volatile field and its last values.

#### Scenario: volatile title
- WHEN a service's `http.title` is volatile with the last values `t1`, `t2`, `t3`
- THEN the host page lists `http.title` under `Changes every run` with `t1`, `t2` and `t3`

### REQ-WEB-040: Your account page
The system SHALL serve `GET /account` (feature `RegisterAccount` in `internal/web/account.go`, template
`internal/web/account.html`) to every signed-in user of any role (`web.SignedIn()` in the route table), showing a page
"Your account" with the user's username and role and a change-password form with the fields current password
(`current_password`), new password (`password`) and repeat (`repeat`), posting to `POST /account/password`. The user
name in the rail (`div.account` in `layout.html`) SHALL link to `/account`. There is no navigation entry.

#### Scenario: viewer opens their account
- WHEN a viewer requests `GET /account`
- THEN the response is 200 with "Your account", the viewer's name and role and the three password fields

#### Scenario: not signed in
- WHEN a request without a session asks for `GET /account`
- THEN it is redirected to `/login`

### REQ-WEB-041: Change own password on the account page
`POST /account/password` SHALL require the CSRF token, reject a new password under 12 characters and a repeat that
differs from the new password without checking the current password, then call `web.UserAdmin.ChangePassword`
(`auth.Service.ChangePassword`) with the request's session cookie. On success it SHALL redirect to
`/account?done=password`, which shows "Password changed. Your other sessions have ended." Each rejection SHALL answer
with the account page and a `span.problem` message next to the offending field (`aria-invalid="true"`), changing
nothing: wrong current password (422, current password field), too many failed attempts (`auth.ErrRateLimited`, 429,
current password field), too short (422, new password field), equal to the current password (422, new password field),
mismatch (422, repeat field).

#### Scenario: mismatch
- WHEN a user submits two different new passwords
- THEN the response is 422 with "The two new passwords do not match." next to the repeat field and the password is
  unchanged

### REQ-WEB-046: Forms work without JavaScript
Every `<form method="post">` of every page SHALL contain the hidden `csrf_token` field (the import form as its first
field) and SHALL be accepted when posted as a plain browser form without htmx headers, file uploads included.

#### Scenario: crawl and post
- WHEN an admin crawls every reachable page and posts every POST form with its own fields and no htmx header
- THEN no post is refused with 401 or 403 or a CSRF error
- AND the same posts without the `csrf_token` field are refused with 403

### REQ-WEB-047: Delete a scan definition
`/scans/{id}` SHALL show a "Delete scan" link to users with `scan.configure`; `GET /scans/{id}/delete` SHALL show a
confirmation page and only `POST /scans/{id}/delete` SHALL delete (REQ-SCHEDULE-011) and redirect with 303 to
`/scans?msg=deleted`, where the list shows "Scan deleted. Its past runs and their observations stay.". A definition
with a run in progress or paused SHALL not be deleted: the scan page is shown with 409 and the reason. A run page of a
deleted definition SHALL say "Definition deleted".

#### Scenario: delete with confirmation
- WHEN an admin follows Delete scan on a scan whose run has completed and confirms
- THEN the scan is gone (404), the list says it was deleted and the run page shows "Definition deleted"
- AND an editor without `scan.configure` gets 403 on both the confirmation page and the post

### REQ-WEB-050: Export page picks the run
The "As of run" filter of `GET /export` SHALL be a select of every run from `ListRuns`, newest first, with "Latest"
(empty value) first and selected by default, built like the run selects of the Changes page. The query parameter
`run` and `asi export` are unchanged; an unknown run still answers 404 and the page then still lists the runs.

#### Scenario: pick an older run
- WHEN runs `seed` and then `second` exist and a user opens `/export`
- THEN the select lists Latest, second, seed in that order with Latest selected, and `/export?run=seed` selects seed

### REQ-WEB-051: Permission descriptions
`auth.PermissionDescriptions` SHALL hold one one-sentence description for every permission of `internal/auth`. The
Roles page SHALL show each description next to the permission key in the create form and in a "Permissions" legend
under the role matrix, whose column headers stay the permission keys.

### REQ-WEB-052: Finding kinds counted on the host page
The Findings cell of a service row on the host page SHALL show each finding kind once with the number of findings of
that kind, for example "Outdated version 2", instead of one badge per finding.

### REQ-WEB-039: Add host button on the Hosts list
"Add host" SHALL NOT be a nav entry. The Hosts list (`GET /hosts/`) SHALL show an "Add host" button
(`<a class="btn primary" href="/hosts/entry">`) in its page head to users whose role has `inventory.create`, and no
such button to others; `/hosts/entry` marks Hosts as the current nav entry.

#### Scenario: editor and operator
- WHEN an editor and an operator open `GET /hosts/`
- THEN the editor's page shows the Add host button, the operator's does not, and neither navigation links to `/hosts/entry`

### REQ-WEB-043: First-run steps on the dashboard
Until every step is done the dashboard SHALL show a "Get started" panel with numbered steps, each kept at its number and left out once done: 1 "Create a scan" (done when a scan definition exists; button `/scans/new` for `scan.configure`), 2 "Look at hosts and changes" (done when a run has completed; buttons `/hosts/` and `/changes` for `inventory.read`), 3 "Add users and roles" (done when there is more than one user or a custom role; buttons `/users/` for `user.manage` and `/roles` for `role.manage`). A step whose permission the user lacks shows its text without the button; when all three are done the panel is not rendered.

#### Scenario: empty installation
- WHEN an admin opens `/` on an empty database
- THEN the steps 1, 2 and 3 are shown in that order with their buttons, and after a scan definition is created step 1 is gone

### REQ-WEB-044: Needs attention on the dashboard
When the latest run gives anything to look at, the dashboard SHALL start with a "Needs attention" panel listing, in this order and leaving out empty groups: new admin panels (`Dashboard.NewPanels`), new hosts (`host_new` of the latest run against the run before), services that went missing (`service_missing`), certificates of current observations expiring within 30 days (`inventory.CertExpiringWindow`; 29 and 30 days are listed, 31 are not) and services slower than usual (`Dashboard.Slow`). Each group shows at most 5 items (address and detail) and, when there are more, "N more" (or "More" when the count is not known) linking to the full page (`/changes`, `/hosts/?finding=admin-panel`); the panel header links to `/changes`. Addresses link to `/hosts/{address}`. A user whose role lacks `inventory.read` sees neither this panel nor the "Get started" panel of REQ-WEB-043, only the message and links of REQ-WEB-009, so no attention item or address reaches that user.

### REQ-WEB-045: Ledes and destructive buttons
Every list page (`/hosts/`, `/groups`, `/changes`, `/scans`, `/signatures`, `/users/`, `/roles`, `/audit`, `/import`, `/export`, `/defectdojo`) SHALL have exactly one `<p class="lede">` in its page head, one sentence saying what the page shows and, where there is one, what to do next. Every `button.danger` SHALL name its object: "Delete host 10.0.0.5", "Delete service 10.0.0.5 22/tcp", "Delete user alice", "Delete role auditor", "Delete signature my-panel".

### REQ-WEB-053: Host pages without inventory.read
These host pages SHALL show host data only to a user with `inventory.read`, and SHALL answer an existing and a missing
address the same way to a user without it:
- `GET /hosts/entry?address=A` (still `inventory.create`) SHALL answer 403 before any lookup when the role lacks
  `inventory.read`. With `inventory.read` an existing host loads into the form (403 without `inventory.edit`) and a
  missing one gets 404, as before. Without an address the empty form is unchanged.
- `GET /hosts/{address}/delete` and `GET /hosts/{address}/services/{port}/{protocol}/delete` SHALL require
  `inventory.delete` and `inventory.read`. The `POST` delete routes keep `inventory.delete` alone.
- A rejected `POST /hosts/{address}` (REQ-WEB-022) by a user without `inventory.read` SHALL get the 400 error page,
  which lists the form problems and shows nothing of the host. It SHALL be checked before the host is looked up and
  SHALL change nothing. A valid form is saved and redirected as before. A user with `inventory.read` still gets the host
  page again with 422.

#### Scenario: creator probes an address
- WHEN a user with only `inventory.create` opens `/hosts/entry?address=10.0.0.1` (stored) and `?address=10.9.9.9` (not stored)
- THEN both answer 403 and neither shows the host's services or titles

### REQ-WEB-054: DefectDojo settings without export
`POST /defectdojo/settings` SHALL keep requiring `scan.configure`. When the user's role lacks `export`, the system SHALL
NOT render the DefectDojo page. A saved configuration SHALL redirect with 303 to `/defectdojo`. A rejected one SHALL get
the error page with the cause, and a server error stays a 500. A user with `export` gets the page as before.

#### Scenario: configure-only role
- WHEN a user with only `scan.configure` saves valid settings with `force=1`
- THEN the settings are stored (token encrypted) and the answer is 303 to `/defectdojo`, which itself answers 403

### REQ-WEB-055: Host page links to its timeline
The host page `/hosts/{address}` SHALL link to `/hosts/{address}/timeline` (REQ-WEB-013) in its page actions.

### REQ-WEB-057: Times in the server's zone
`asi` SHALL read the optional `ASI_TIMEZONE` (an IANA zone name; an unknown name fails configuration with
`ASI_TIMEZONE is malformed`) and use it as the process local zone; without it the process local zone applies. Every
time the web UI shows SHALL carry its zone abbreviation (`2006-01-02 15:04 MST`, the audit log with seconds): times of
a run of a scan definition in the timezone of that run's schedule, all others, the host timeline included (its column now reads
"Time" instead of "Time (UTC)"), in the local zone. Recent times on the dashboard and hosts list SHALL show relative text ("3 minutes ago") with the exact zoned time
in `title`.

#### Scenario: zones
- WHEN 2026-11-21 22:42 UTC is shown with the zone Europe/Warsaw
- THEN the UI shows `2026-11-21 23:42 CET`; a run of a definition in America/New_York shows it as `17:42 EST`

### REQ-WEB-058: Host links from changes and host pages
The host page SHALL link its timeline (`/hosts/<address>/timeline`, button "Timeline"); every row of the change feed
`/changes` SHALL link its host page (`/hosts/<address>`, column "Host", "Host page") besides the address link to the
timeline.

#### Scenario: navigation
- WHEN a user opens a change row of 10.0.0.1
- THEN it links `/hosts/10.0.0.1`, and that page links `/hosts/10.0.0.1/timeline`

