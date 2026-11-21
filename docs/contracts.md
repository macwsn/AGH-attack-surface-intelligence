# Contracts

Fixed interfaces of ASI. The acceptance lab (`lab/run.sh`, `lab/check.py`, `lab/expected.json`) uses exactly these and
is the definition of "works". A task may extend a contract (new optional fields, new flags) but never rename or
remove what is written here. `lab/**` is owned by the supervisor: tasks do not edit it.

## 1. CLI

One binary, `asi`. Configuration from environment: `ASI_DATABASE_URL` (Postgres), `ASI_MASTER_KEY` (base64, 32 bytes,
field encryption key), `ASI_LISTEN` (default `:8080`). Every command exits 0 on success, non-zero with a one-line
error on stderr otherwise.

| Command | Behaviour |
|---|---|
| `asi migrate` | apply embedded schema migrations; idempotent |
| `asi serve` | web UI + JSON API + scheduler + scan workers |
| `asi user create --username U --role R [--password-stdin]` | create a local user |
| `asi scan run --targets-file F [--exclude-file F] --ports LIST --name NAME [--signatures-dir D] [--inactive-after N] [--max-rate PPS] [--workers N] --wait` | create a scan run named NAME and execute it in this process; `--wait` returns when it finished; exit 0 only when the run completed |
| `asi export --format json\|csv --out FILE [--run NAME]` | current inventory (or the state as of a run) |
| `asi diff --from NAME --to NAME --format json --out FILE` | changes between two runs |
| `asi import --format json\|csv --file FILE` | import hosts/targets or scan results; imported data goes through the same normalisation, signature matching and diffing as scanned data |
| `asi host edit ADDRESS [--add-tag T]… [--remove-tag T]… [--notes TEXT]` | user-owned fields; never overwritten by later scans |

Targets file: one target per line (IPv4, CIDR, IPv4 range `a.b.c.d-e`, domain), `#` comments. Excludes win over targets.
`--ports` is the only set of ports ever touched. `--max-rate` caps packets/requests per second for the whole run.
`--inactive-after N`: a host or service missed in N consecutive runs becomes `inactive` (default 3).

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
- Header names are lower-case; values are strings (repeated headers joined with `, `). Cookie values are never exported.
- `status_code`, `title`, `headers`, `cookies` describe the final response after redirects; `redirect_chain` lists every
  URL visited after the first.
- `http.scheme` is `https` when the port speaks TLS; `service` stays `http`.
- A signature match always produces a `findings` entry; signatures of kind `technology` also produce a `technologies`
  entry with `source: "signature:<id>"`. Built-in detection uses `source: "builtin"`.
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
suppresses service-level changes of the same host.

`service_changed.fields[].field` uses export paths: `service`, `product`, `version`, `http.status_code`, `http.title`,
`http.headers.<name>`, `http.cookies` (set of names), `http.redirect_chain`, `http.tls.sha256`, `http.favicon_sha256`,
`technologies` (set of name+version), `findings` (set of signature ids).

Volatile values never produce a change: headers `date`, `expires`, `last-modified`, `etag`, `age`, `set-cookie`,
`content-length`, `x-request-id`, `cf-ray` and anything listed in configuration; cookie values; TLS dates of the same
certificate. A host scanned twice with no real change yields no change entries.

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
