# Contracts

Fixed interfaces of ASI. The acceptance lab (`lab/run.sh`, `lab/check.py`, `lab/expected.json`) uses exactly these and
is the definition of "works". A change may extend a contract (new optional fields, new flags) but never rename or
remove what is written here. `lab/**` is owned by the maintainers: other changes do not edit it.

## 1. CLI

One binary, `asi`. Configuration from environment: `ASI_DATABASE_URL` (Postgres), `ASI_MASTER_KEY` (base64, 32 bytes,
field encryption key), `ASI_LISTEN` (default `:8080`). Every command exits 0 on success, non-zero with a one-line
error on stderr otherwise.

| Command | Behaviour |
|---|---|
| `asi migrate` | apply embedded schema migrations; idempotent |
| `asi serve` | web UI + JSON API + scheduler + scan workers |
| `asi user create --username U --role R [--password-stdin]` | create a local user |
| `asi scan run --targets-file F [--exclude-file F] --ports LIST --name NAME [--signatures-dir D] [--inactive-after N] [--max-rate PPS] [--workers N] [--mode full\|recheck] --wait` | create a scan run named NAME and execute it in this process; `--wait` returns when it finished; exit 0 only when the run completed |
| `asi export --format json\|csv --out FILE [--run NAME]` | current inventory (or the state as of a run) |
| `asi diff --from NAME --to NAME --format json --out FILE` | changes between two runs |
| `asi import --format json\|csv --file FILE` | import hosts/targets or scan results; imported data goes through the same normalisation, signature matching and diffing as scanned data |
| `asi host edit ADDRESS [--add-tag T]… [--remove-tag T]… [--notes TEXT]` | user-owned fields; never overwritten by later scans |
| `asi user list` | a header line, then one line per user in aligned columns: username, role, `enabled` or `disabled`, creation time (RFC3339, UTC) |
| `asi user set-role --username U --role R` | change the role of a user; refused for the last enabled `admin` |
| `asi user delete --username U` | delete a user; refused for the last enabled `admin` |
| `asi role list` | a header line, then one line per role in aligned columns: name, `true` for built-in roles, permissions comma-separated; built-in roles first |
| `asi scan plan` (flags of `scan run`, `--name` and `--wait` not needed) | print the planned addresses, groups, worst-case packets and requests and the expected duration; sends nothing to any target (host names are resolved) |
| `asi scan resume NAME` | continue a `paused`, `failed` or stalled run in this process; refused while the run is `running` with a live heartbeat |
| `asi scan show NAME` | status, mode, packets, measured requests, estimated nmap packets, rate, progress, one line per group and per failed group |
| `asi inventory rebuild-summary` | rebuild the derived `host_summary` table behind the host list |
| `asi signature hunt --file SIG.yaml [--since DURATION] [--format text\|json]` | evaluate one signature against stored history; sends nothing; `--since` takes a Go duration or `Nd`; `json` prints `asi.hunt/v1` |
| `asi defectdojo configure --url URL --product ID --engagement ID [--token-stdin] [--force]` | store the DefectDojo connection (encrypted); a changed connection is tested first and not saved when the test fails, unless `--force` |
| `asi defectdojo test` | check the stored connection and that the stored test ids still exist |
| `asi defectdojo export --run NAME [--dry-run [--out DIR] \| --force]` | export a run; `--dry-run` writes `nmap.xml` and `findings.json` to DIR (default `defectdojo-NAME`) and sends nothing; `--force` exports a run older than the last exported one |
| `asi key status` | the current key id and, per encrypted table, the rows under the current and under older key ids |
| `asi key rotate [--batch N]` | re-encrypt every value written under an older key with `ASI_MASTER_KEY`, N rows per transaction (default 500); idempotent |
| `asi version` | print the version |

Further flags of `asi scan run` and `asi scan plan`:

| Flag | Default | Behaviour |
|---|---|---|
| `--http-timeout D` | `10s` | deadline of every HTTP request, a Go duration, at least `1ms` |
| `--max-addresses N` | `262144` | refuse targets that expand to more addresses (after excludes); command line only |
| `--max-work N` | `262144000` | refuse targets whose addresses × ports exceed N; the default also applies to scan definitions and scheduled runs |
| `--service-detection light\|standard` | `standard` | `light`: one nmap pass with light probes; `standard`: plus a second pass at default intensity for ports left unidentified |
| `--no-adaptive` | off | keep the rate fixed instead of backing off when targets slow down |

Further flags of `asi import`: `--name NAME` (name of the import run, default generated from the time), `--dry-run`
(report what would change, record nothing).

Exit codes: 0 success, 1 error (`asi <command>: <message>` on stderr), 2 wrong usage (the usage text on stderr).

Further environment variables read by `asi`:

| Variable | Default | Behaviour |
|---|---|---|
| `ASI_MASTER_KEY_PREVIOUS` | empty | comma-separated base64 keys (32 bytes each) that wrote older data; used only for reading |
| `ASI_INTEREST_WEIGHTS` | built-in weights | `code=points,...`, points 0-100; codes `admin-panel`, `staging`, `iot`, `interesting-header`, `interesting-cookie`, `new`, `recent`, `self-signed`, `expiring-cert`, `outdated` |
| `ASI_SIGNATURES_DIR` | empty | a signatures directory `asi serve` checks at start and uses for every scan, import and manual entry it runs |
| `ASI_BODY_RETENTION_RUNS` | `10` | number of newest observations per service that keep the stored page excerpt; at least 1 |
| `ASI_VOLATILE_HEADERS` | empty | comma-separated response header names that never count as a change, in addition to the built-in list |

| `ASI_TIMEZONE` | the process's local zone | IANA zone name the UI shows times in; scan windows keep the timezone of their definition |

No other `ASI_*` variable is read by the binary.
`NMAPDIR`, when set, is where ASI looks for nmap's `nmap-service-probes`.

Targets file: one target per line (IPv4, CIDR, IPv4 range `a.b.c.d-e`, domain or host name such as `localhost` or
`host.docker.internal`), `#` comments. Excludes win over targets.
`--ports` is the only set of ports ever touched. LIST is comma-separated ports and ranges (`21,80,8000-8100`) or one of
the presets `top100`, `top1000`, `all`; it is stored sorted and without duplicates. `--max-rate` caps packets/requests per second for the whole run.
`--inactive-after N`: a host or service missed in N consecutive runs becomes `inactive` (default 3).
`--mode full|recheck` (default `full`): a full run discovers hosts and services over all targets; a recheck run contacts
only the services that were `active` or `unstable` as of the latest completed run with the same targets and excludes
(or of the same scan definition), sends no host discovery to other addresses and covers only what it contacted, so
nothing else counts as missed. A recheck without such an earlier run fails with `no earlier run to recheck` and creates
no run; any other mode value is rejected.

The product image is built from the repository root `Dockerfile` and contains `asi` on PATH and `nmap`.

## 2. Export `asi.export/v1`

```json
{
  "schema": "asi.export/v1",
  "generated_at": "RFC3339",
  "run": "lab-3",
  "hosts": [{
    "address": "172.30.0.12",
    "hostnames": ["admin.example"],
    "status": "active",
    "first_seen": "RFC3339", "last_seen": "RFC3339", "missed_runs": 0,
    "stability": 1.0,
    "interest_score": 70,
    "tags": ["crown-jewel"], "notes": "",
    "availability": {"hours": [0.5, "… 24 values 0..1, hour 0 first"], "samples": 12, "periodic": true,
                     "usual_hours": [8, 9, 10], "expected": "up"},
    "services": [{
      "port": 443, "protocol": "tcp", "state": "open", "status": "active",
      "service": "http", "product": "nginx", "version": "1.27.5",
      "first_seen": "RFC3339", "last_seen": "RFC3339",
      "http": {
        "scheme": "https", "url": "https://172.30.0.12/", "status_code": 200, "title": "…",
        "headers": {"x-powered-by": "PHP/7.4.3"},
        "cookies": [{"name": "PHPSESSID", "http_only": true, "secure": false, "same_site": ""}],
        "redirect_chain": ["https://172.30.0.12/admin/login"],
        "tls": {"subject_cn": "", "issuer_cn": "", "sans": [], "not_before": "", "not_after": "", "sha256": "hex", "self_signed": true},
        "favicon_sha256": "hex", "favicon_mmh3": -123
      },
      "technologies": [{"name": "WordPress", "category": "cms", "version": "6.4.2", "confidence": 95, "source": "signature:wordpress-generator"}],
      "findings": [{"signature_id": "admin-panel-login", "kind": "admin-panel", "name": "…", "version": "", "confidence": 80, "evidence": "…"}]
    }]
  }]
}
```

- Host `status`: `active` (seen in the latest run), `unstable` (missed fewer than N consecutive runs), `inactive`.
- `availability` (optional; omitted for a host without covering runs): the host's availability profile as of the
  export's run. `hours` are 24 hour-of-day buckets in the timezone of the covering run's schedule (UTC without one),
  each an exponentially weighted average of seen (1) / missed (0) over the covering runs, starting at 0.5; `samples` is
  the number of covering runs applied. `periodic` is true with at least 6 samples, some bucket >= 0.8 and some bucket
  <= 0.2; `usual_hours` lists the buckets >= 0.8 of a periodic host (else `[]`). `expected` is present only when the
  export's run covers the host and the host was periodic before it: `up` when that hour's bucket was >= 0.8, `down`
  when <= 0.2. A periodic host missed in an hour it is usually down keeps its `status`, `missed_runs` and `stability`
  (the miss only updates the profile); the same holds for its services.
- Header names are lower-case; values are strings (repeated headers joined with `, `). Cookie values are never exported.
- `status_code`, `title`, `headers`, `cookies` describe the final response after redirects; `redirect_chain` lists every
  URL visited after the first.
- `http.scheme` is `https` when the port speaks TLS; `service` stays `http`.
- A signature match always produces a `findings` entry; signatures of kind `technology` also produce a `technologies`
  entry with `source: "signature:<id>"`. Built-in detection uses `source: "builtin"`.
- Fields added since v1 was fixed (all optional for readers):
  - host: `display_name`, `owner`, `criticality`, `status_override` (user-owned, omitted when empty);
  - service: `missed_runs`, `stability` (the service's own count and share, like the host's), `volatile` (omitted
    when empty): a list of `{"field": "<diff field>", "values": [...]}` for fields ASI learned to treat as volatile,
    with up to 3 recent values;
  - `http.ttfb_ms`, `http.response_time_ms`: time to first byte and total response time of `/` in milliseconds
    (omitted when 0); they never produce a change;
  - `http.error`: `timeout`, `tls handshake failed` or `request failed` when the probe of the port did not complete
    (omitted otherwise); a service with an error on either side is compared on `product` and `version` only;
  - `http.favicon_unstable`: true when the favicon hash differed on a second fetch in the same run; the favicon is
    then left out of the diff;
  - `technologies[].confidence_raw`: the confidence as detected; `confidence` in `asi export` and `/export` is then
    `round(confidence_raw × host stability)`. An import that carries `confidence_raw` stores it as the detected value;
  - `findings[].source` (omitted when empty): `retro-hunt` for findings recorded from a hunt.
  - `technologies[].source` values besides `builtin` and `signature:<id>`: `wappalyzer` (the embedded fingerprint
    dataset) and `heuristic` (generic heuristics). Further built-in finding ids: `builtin-heuristic-generator`,
    `builtin-heuristic-title`, `builtin-heuristic-header`, `builtin-unfinished-installation`,
    `builtin-management-interface`, and `builtin-not-probed-by-policy` (kind `custom`) on ports that receive no
    service probe by policy.
- CSV export: one row per service (hosts without services get one row with empty service columns). Columns at least
  `address,hostnames,status,port,protocol,service,product,version,scheme,status_code,title,technologies,findings,tags,first_seen,last_seen`.

## 3. Diff `asi.diff/v1`

```json
{"schema": "asi.diff/v1", "from": "lab-1", "to": "lab-2",
 "changes": [{"type": "service_changed", "address": "172.30.0.18", "port": 80, "protocol": "tcp",
              "fields": [{"field": "http.title", "old": "Intranet v1", "new": "Intranet v2"}]}]}
```

Types: `host_new`, `host_missing` (seen in `from`, not in `to`, not yet inactive), `host_returned` (missing or inactive
before, seen again), `host_inactive` (crossed the inactive threshold in `to`), `service_new`, `service_missing`,
`service_returned`, `service_inactive`, `service_changed`. Host-level changes carry no `port`; a host-level change
suppresses service-level changes of the same host. A change may carry an optional `note` (omitted when empty):
`host_missing` of a host whose `to` availability has `expected: "up"` carries `"note": "expected up at this hour"`.

`service_changed.fields[].field` uses export paths: `service`, `product`, `version`, `http.status_code`, `http.title`,
`http.headers.<name>`, `http.cookies` (set of names), `http.redirect_chain`, `http.tls.sha256`, `http.favicon_sha256`,
`technologies` (set of name+version), `findings` (set of signature ids).

Volatile values never produce a change: headers `date`, `expires`, `last-modified`, `etag`, `age`, `set-cookie`,
`content-length`, `x-request-id`, `cf-ray` and anything listed in configuration; cookie values; TLS dates of the same
certificate. A host scanned twice with no real change yields no change entries.

Extensions of the volatile rules: "anything listed in configuration" is `ASI_VOLATILE_HEADERS` plus the "Volatile
headers" of the run's scan definition. Header values are normalised before they are compared: CSP nonces and hashes,
UUIDs, timestamps and long token-like strings count as equal. A field that changed in 3 consecutive compared runs
is learned as volatile and no longer reported (it is listed under the service's `volatile` in the export); response
times, `http.error` and an unstable favicon never produce a change.

## 4. Signatures

A signatures directory holds `*.yaml` files; each file is a YAML list of signatures:

```yaml
- id: admin-panel-login            # unique, [a-z0-9-]
  name: Admin panel login form
  kind: admin-panel                # technology | admin-panel | staging | iot | interesting-header | interesting-cookie | outdated | custom
  category: cms                    # optional, for technologies
  confidence: 80                   # 0-100
  request: { method: GET, path: /admin/login }   # optional; default: the response already fetched for "/"
  match:
    all: [ … ]                     # and/or
    any: [ … ]                     # all listed groups must hold
  version: { type: body_regex, value: 'v([0-9.]+)', group: 1 }   # optional
```

Matchers: `status` (value int), `header` (name, value regex; name match case-insensitive), `cookie` (name regex),
`title_regex`, `body_regex`, `favicon_sha256` (hex), `favicon_mmh3` (int, Shodan style). Regexes are RE2.

Safety rules, enforced when a signature is loaded or saved: methods `GET` and `HEAD` only; no request body, no custom
headers, no credentials; `path` is a literal absolute path without query string; at most 5 extra requests per service
across all signatures (deduplicated by path); response bodies read up to 1 MiB. A signature that violates a rule is
rejected with an error naming the rule. Signatures created in the UI are stored in the database and behave the same.

Extensions:

- Kind `outdated`: a product version older than the supported line, produced from a version table shipped with ASI.
  The finding's `version` is the detected version and `evidence` names the minimum supported one.
- ASI ships a built-in signature pack in this same format (embedded in the binary). It is loaded by default together
  with file and database signatures; each built-in signature can be disabled in the signatures UI. Findings and
  technologies from the pack use `source: "signature:<id>"` like any other signature.
- `outdated` is produced only from the version table; a user signature with `kind: outdated` is rejected.
- `request.method: HEAD` sends a real `HEAD` for a path other than `/`; for `/` the response already fetched is used.
- A `path` with a `.` or `..` segment (also percent-encoded), `//`, `#`, a backslash or a bad percent-encoding is
  rejected under the rule "path is a literal absolute path without query string".
- Built-in detection outside signatures (ids `builtin-header-*`, `builtin-cookie-*`, `builtin-login-form`,
  `builtin-staging-*`) produces findings in the same shape, with `source` empty like signature findings; it runs only
  while at least one signature of the built-in pack is enabled. `outdated-*` findings come from the version table
  and do not depend on the pack.
