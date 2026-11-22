# Signatures

A signature tells ASI how to recognise something on an HTTP or HTTPS service: a technology, an administration
panel, a staging environment, an IoT device, a notable header or cookie. Signatures only detect presence. They
cannot log in, send data or exploit anything; the format has no way to express it and the loader rejects attempts.

The format is fixed in [contracts.md](contracts.md) section 4. The examples below are taken from
`lab/signatures/lab.yaml`, which the acceptance lab runs on every build, except where noted.

## Where signatures live

| Place | How it is used |
|---|---|
| a directory of `*.yaml` files | `ASI_SIGNATURES_DIR` for everything `asi serve` runs; per scan `asi scan run --signatures-dir D` or "Signatures directory" of a scan definition; `asi import --signatures-dir D`. Each file is a YAML list |
| the database | created, edited, enabled and disabled under **Signatures** in the UI (permission `signature.manage`). Every scan, import and manual entry loads the enabled ones |
| the built-in pack | 54 signatures embedded in the binary, ids starting with `builtin-`. Loaded by every scan unless switched off |

A scan uses all three sets together. An id may exist only once across them; a scan whose directory defines an id
that is also stored is refused before a run is created and before anything is sent.

When changes take effect:

- signatures saved, enabled, disabled, deleted or imported in the UI: from the next scan, import or manual entry,
  without a restart;
- files in `ASI_SIGNATURES_DIR`: read once when `asi serve` starts. **A file changed on disk needs a restart of
  `asi serve`** (a change to any signature in the UI also makes it re-read the directory);
- a directory named in a scan definition (other than `ASI_SIGNATURES_DIR`) or with `--signatures-dir`: read at the
  start of every run.

### The built-in pack

The pack recognises common products (Grafana, Jenkins, GitLab, Tomcat, ActiveMQ, Elasticsearch, Kibana, Portainer,
MinIO, Prometheus, Keycloak, Joomla, Drupal, WordPress and its installer, Roundcube, Zabbix, phpMyAdmin, Adminer,
DVWA, Gitea, RabbitMQ management, Traefik, Nginx Proxy Manager, httpbin, Toxiproxy), devices (Proxmox VE, pfSense,
Synology DSM, MikroTik RouterOS, Hikvision and Dahua cameras, HP and Brother printers) and a generic admin login
page. Confidence is 95, 90 or 85 by the strength of the evidence and 70 for the generic login page. The sources are in
`internal/detect/pack/*.yaml` (`common.yaml` 20, `devices.yaml` 16, `lab-agh.yaml` 18) and are good examples to copy
from.

- The signatures page lists them under "Built-in signatures". Each can be disabled and enabled again; the choice is
  kept across restarts and written to the audit log. They cannot be edited or deleted; opening one shows its YAML
  read-only.
- Their ids are reserved: a stored or imported signature with a `builtin-` id that exists in the pack is rejected
  with the rule `id is unique`.
- Their extra requests do not count against the limit of 5 for your own signatures. They are fetched only with what
  your signatures leave of that budget, so a service still receives at most 5 extra requests.
- The export on the signatures page contains only stored signatures, never the pack.

Besides signatures, ASI has built-in detection that is not written as signatures (confidence in parentheses; the full
table is in [technical.md](technical.md#detection-sources-and-confidence)):

- notable headers, `builtin-header-<name>` (80): `X-Powered-By`, `X-Generator` and `Server` with a version number,
  `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Environment`, `X-Backend-Server`, `X-Served-By`, `X-Debug-Token`,
  `X-Debug-Token-Link` (token values are redacted in the evidence), `Via` naming an internal host;
- notable cookies: `builtin-cookie-stack` (60) for session cookies that name the stack (`PHPSESSID`, `JSESSIONID`,
  `ASP.NET_SessionId`, `laravel_session`, `connect.sid`, `phpMyAdmin`, `wordpress_*`; the stack is also added as a
  technology with confidence 40), `builtin-cookie-no-httponly` (70), `builtin-cookie-no-secure` (70, HTTPS only);
- `builtin-login-form` (50, kind `admin-panel`): a form with a password input, when no other admin panel finding
  matched;
- staging: `builtin-staging-header` (75) for `X-Environment`, `X-Env` or `X-Stage` naming staging, stage, test, dev,
  uat, preprod or sandbox; `builtin-staging-hostname` (65) for such a word in the host name;
  `builtin-staging-title` (70 for a bracketed marker such as `[STAGING]`, 60 for the bare word). Words that only
  contain a marker (`latest`, `contest`, `device`) do not match.

Two more sources fill in technologies on pages no signature knows: the embedded Wappalyzer fingerprint dataset
(source `wappalyzer`, confidence 60) and generic heuristics (source `heuristic`, confidence 40, ids
`builtin-heuristic-generator`, `-title`, `-header`), plus the generic findings `builtin-unfinished-installation` and
`builtin-management-interface` (50). Ports on the never-probe list get `builtin-not-probed-by-policy`. Details are in
[technical.md](technical.md#detection-sources-and-confidence). A technology your own signature names is kept as its
own entry next to these.

All of these run only while at least one pack signature is enabled; switching the whole pack off switches them off
too.

ASI also adds findings of kind `outdated` (ids `outdated-<product>`) when a detected version is below the minimum in
`internal/detect/outdated.yaml` (19 products). `outdated` is produced only from that table; a signature of your own
with `kind: outdated` is rejected.

## Format

```yaml
- id: wordpress-generator          # unique, lower-case letters, digits and hyphens
  name: WordPress                  # shown in the UI and in exports
  kind: technology                 # technology | admin-panel | staging | iot | interesting-header | interesting-cookie | custom
  category: cms                    # optional, free text; used for technologies
  confidence: 95                   # 0-100, required
  request: { method: GET, path: /admin/login }   # optional; without it the response for "/" is used
  match:
    all: [ ... ]                   # every matcher must hold
    any: [ ... ]                   # at least one must hold
  version: { type: body_regex, value: 'v([0-9.]+)', group: 1 }   # optional
```

- `match` needs `all`, `any` or both. With both, all of `all` and one of `any` must hold.
- Without `request`, matchers look at the response ASI already has for `/` (after redirects on the same host and
  port). With `request.path`, ASI fetches that path once per service and the matchers look at that response.
- `request.method` is `GET` (default) or `HEAD`. A `HEAD` request is sent as `HEAD`; for the path `/` the response
  already fetched with `GET` is used instead.
- `version` takes a `header`, `title_regex` or `body_regex` matcher and stores capture group `group` as the version.
- A match always creates a **finding** with the signature's id, kind, name, confidence and the evidence (which
  matchers held). A signature of kind `technology` also adds a **technology** with `source: signature:<id>`.
- Regular expressions use RE2 syntax (Go `regexp`): no look-ahead, no back-references. `(?i)` makes one
  case-insensitive.
- Unknown fields are rejected, so a typo in a field name is an error, not a silently ignored line.

## Matchers, one example each

### body_regex

Matches the response body (the first 1 MiB).

```yaml
- id: wordpress-generator
  name: WordPress
  kind: technology
  category: cms
  confidence: 95
  match:
    all:
      - { type: body_regex, value: '<meta name="generator" content="WordPress ([0-9.]+)"' }
  version: { type: body_regex, value: '<meta name="generator" content="WordPress ([0-9.]+)"', group: 1 }
```

### header

`name` is the header name (case does not matter), `value` a regular expression for its value.

```yaml
- id: drupal-x-generator
  name: Drupal
  kind: technology
  category: cms
  confidence: 90
  match:
    all:
      - { type: header, name: X-Generator, value: '^Drupal ([0-9]+)' }
  version: { type: header, name: X-Generator, value: '^Drupal ([0-9]+)', group: 1 }
```

### title_regex and favicon_sha256

`title_regex` matches the page title. `favicon_sha256` is the SHA-256 of `/favicon.ico` in hex; the value for a
known device is in the `favicon_sha256` field of an export or on the **Groups** page.

```yaml
- id: netcam
  name: NETCAM IP Camera
  kind: iot
  category: camera
  confidence: 90
  match:
    all:
      - { type: favicon_sha256, value: 16fbd143c0bf4559bc4e631bd119d18f3e5c61a40dedb8b199cb9a9e6800856f }
      - { type: title_regex, value: 'NETCAM' }
  version: { type: body_regex, value: 'Firmware V([0-9.]+)', group: 1 }
```

### favicon_mmh3

The 32-bit MurmurHash3 of the base64-encoded favicon, the value Shodan calls `http.favicon.hash`. Exports carry it
as `favicon_mmh3`. This example is not in the lab file; it was checked with the test action of the signatures page
against the lab camera and matched with the evidence `favicon mmh3 1918245699`.

```yaml
- id: netcam-mmh3
  name: NETCAM camera by favicon
  kind: iot
  category: camera
  confidence: 85
  match:
    all:
      - { type: favicon_mmh3, value: 1918245699 }
```

### status, with a request path

`status` compares the status code. This signature fetches `/admin/login` with a plain `GET` and looks for a password
field; nothing is submitted.

```yaml
- id: admin-panel-login
  name: Admin panel login form
  kind: admin-panel
  confidence: 80
  request: { method: GET, path: /admin/login }
  match:
    all:
      - { type: status, value: 200 }
      - { type: body_regex, value: 'type="password"' }
```

### cookie

`name` is a regular expression for the cookie name. Cookie values are never stored or matched.

```yaml
- id: php-session-cookie
  name: PHP session cookie
  kind: interesting-cookie
  confidence: 70
  request: { method: GET, path: /admin/login }
  match:
    all:
      - { type: cookie, name: '^PHPSESSID$' }
```

### any

```yaml
- id: staging-environment
  name: Staging or test environment
  kind: staging
  confidence: 75
  match:
    any:
      - { type: header, name: X-Environment, value: '(?i)^(staging|test|dev)' }
      - { type: title_regex, value: '(?i)\[(staging|test|dev)\]' }
```

## The guided form

**New signature** opens a form instead of a YAML editor: name, id (default: the name in lower case with hyphens),
kind, category, confidence (default 80), whether all or any of the conditions must hold, condition rows (header,
cookie, title, body, status, favicon; **Add condition** and **Remove** per row), where the version comes from
(header, title or body with a pattern), and an optional request path. The YAML it produces is shown next to it and
updates on every change; it is what is saved, tested and hunted. A title condition becomes `title_regex`, a body
condition `body_regex`, a favicon value of 64 hex characters `favicon_sha256` and any other `favicon_mmh3`; a
version pattern with a capture group gets `group: 1`. **Edit as YAML** switches to the plain editor.

A stored signature opens in the form when the form can represent it. A signature with both `all` and `any`, a
`HEAD` request or a capture group other than 1 opens in the YAML editor with a note saying so. A cookie condition
takes only the name; a value typed into its value field is not used.

## Safety rules

The rules are checked when a directory is loaded (a scan with a bad file does not start), when a signature is saved
or imported in the UI, and by `asi signature hunt`. The error names the signature and the rule. All messages below
were produced by the product.

| Rule | Example that breaks it | Error |
|---|---|---|
| methods GET and HEAD only | `request: { method: POST, path: /login }` | `signature "bad-method" violates rule "methods GET and HEAD only": method POST` |
| no request body | `request: { path: /login, body: "user=admin" }` | `signature "bad-body" violates rule "no request body": request field "body"` |
| no custom headers | `request: { path: /login, headers: { X-Forwarded-For: 127.0.0.1 } }` | `signature "bad-headers" violates rule "no custom headers": request field "headers"` |
| no credentials | `request: { path: /admin, password: admin }` | `signature "bad-credentials" violates rule "no credentials": request field "password"` |
| path is a literal absolute path without query string | `request: { path: "/search?q=1" }` or `path: "http://other.example/"`; also `//host`, `#`, a backslash, a bad percent-encoding, and `.` or `..` segments, also as `%2e%2e` or `/..;/` | `signature "bad-path" violates rule "path is a literal absolute path without query string": path /search?q=1` (for traversal the detail reads `path "/../etc/passwd" contains a dot segment (..), also when percent-encoded`) |
| at most 5 extra requests per service | six signatures with six different paths | `signature "p6" violates rule "at most 5 extra requests per service": path "/p6" is extra request number 6` |
| id is unique | the same id in two files | `signature "wordpress-generator" violates rule "id is unique": already defined in /out/dup/a.yaml` |
| regexes are valid RE2 | `value: '(?=lookahead)'` | ``signature "bad-regex" violates rule "regexes are valid RE2": title_regex "(?=lookahead)": error parsing regexp: invalid or unsupported Perl syntax: `(?=` `` |
| signature format | `id: Bad_ID`, `kind: exploit`, a missing `confidence`, an unknown matcher type | `signature "Bad_ID" violates rule "signature format (docs/contracts.md §4)": id "Bad_ID" must match [a-z0-9-]+` |

Further limits that apply to every signature request: the same `User-Agent` as the rest of the probe, response
bodies read up to 1 MiB, the run's rate limit and HTTP timeout, and no redirect followed to another host or port.
Paths are counted once per service across all signatures: several signatures may share `/admin/login` at the cost
of one request. A `GET` and a `HEAD` of the same path are two requests when they are sent, although the loader counts
the path once; with 5 distinct paths in use, a later signature may then not get its request, without an error.
Accepted paths are stored cleaned (`path.Clean`, a trailing slash kept).

nmap's own service probes are not covered by these rules; see [technical.md](technical.md#what-nmap-sends).

In the UI a violation re-renders the form with status 422 and a line such as
`Rule violated: methods GET and HEAD only. method POST`; nothing is stored.

## Testing a signature against stored data

Both ways use what earlier scans stored and send nothing to any host.

### Test action in the UI

1. **Signatures**, then **New signature** (or open a stored one).
2. Fill in the guided form or write the signature as YAML (see [the guided form](#the-guided-form)).
3. Under "Test against a service" enter the address, port and protocol of a service in the inventory and press
   **Test signature**.

The page shows whether the draft matches the latest stored observation of that service, the extracted version, the
evidence and the run the observation is from. The draft is not saved by testing.

Stored data has limits: only the response for `/` is kept, so a signature with another `request.path` cannot be
tested this way.

### Retro-hunt over the whole history

A hunt evaluates one signature against every stored HTTP observation of every service and run.

From the command line, with a file that holds exactly one signature:

```
$ asi signature hunt --file /out/hunt-php.yaml
hunt 3 signature=php-7-exposed observations=32 matched=2 not_evaluable=0 latest_run=demo-3 duration=6ms
172.30.9.12 80/tcp first_run=demo-1 last_run=demo-3 latest=true version=7.4.3
172.30.9.12 443/tcp first_run=demo-1 last_run=demo-3 latest=true version=7.4.3
```

- `--since 30d` (or a Go duration such as `72h`) limits the hunt to runs started in that period.
- `--format json` prints an `asi.hunt/v1` document with the same fields per service.
- `latest` says whether the service matches in the latest run. The latest run can be an import that does not cover
  the service; then it reads `false` although the service matched in the last scan.

In the UI, the signature form has **Hunt in history** with a period. The result page (`/signatures/hunts/{id}`)
lists the services with the first and last matching run, offers the list as CSV, and can save the signature and
record its findings on the latest run for the services that match there. Recorded findings carry
`source: retro-hunt` in exports.

What a hunt can evaluate: status code, title, headers, cookie names, favicon hashes and, for `body_regex`, the
first 64 KiB of the root page. That excerpt is kept for the newest 10 observations of each service
(`ASI_BODY_RETENTION_RUNS`); on older observations a body matcher counts as not evaluable. A signature with a `request.path` other than `/` is
reported as "not evaluable from history" for every service, not as "no match".

## Import and export of signatures

- **Export YAML** on the signatures page (`GET /signatures/export`) downloads all stored signatures as one YAML
  list, `signatures.yaml`. The file is a valid signatures directory file.
- **Import signatures** on the same page takes such a list pasted into the form (at most 1 MiB). The list is
  validated as a whole: if one signature breaks a rule, nothing is stored. Signatures with an id that is already
  stored are replaced; new ones are added enabled.
- To move file signatures into the database, paste the file into the import form. To use stored signatures as a
  file, save the export into a signatures directory. Do not keep the same id in both places.

Every create, save, enable, disable, delete, import and hunt is written to the audit log with the user and the
signature id.

## Writing good signatures

- Prefer evidence that only the product produces: a generator tag, a product-specific header, a favicon hash. A
  title alone is weak.
- Set `confidence` to how sure a match makes you. As a scale, the built-in rules use 95 for a generator tag, 90 for
  a `Server` or `X-Powered-By` header, 70 for a path pattern in the body and 60 for a cookie name. Reports multiply a
  technology's confidence by the host's stability; the value you wrote stays in `confidence_raw`.
- Remember that imported data has no page body: `body_regex` signatures do not fire on imports.
- Anchor regular expressions (`^Drupal ([0-9]+)`) and escape dots in versions and host names.
- Use `request.path` sparingly: every distinct path costs one request per web service in every run, and only 5 are
  allowed in total.
- Test against a service that should match and one that should not, then run a hunt to see how many services the
  signature would flag before enabling it.
