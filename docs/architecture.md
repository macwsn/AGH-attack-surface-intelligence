# Architecture decisions

Decided up front by the maintainers. A change that needs to deviate says so in its description and is reviewed by the
maintainers.

## Shape

- Go 1.27, one module `asi`, one binary `asi` (`cmd/asi`), packages under `internal/`. One process runs the web UI,
  the JSON API, the scheduler and the scan workers; the CLI commands in `docs/contracts.md` reuse the same packages.
- PostgreSQL 17 through `pgx/v5`. Plain SQL, migrations embedded with `embed` and applied by `asi migrate`.
- UI is server-rendered: `html/template` + htmx + one embedded CSS file. No Node toolchain, no CDN at runtime.
- Dependencies are kept few and pure Go. External programs: `nmap` only.
- Runs with `docker compose up` from the repository root (`Dockerfile`, `docker-compose.yml`): Postgres + asi.

## Packages

| Package | Responsibility |
|---|---|
| `internal/targets` | parse and expand IPs, CIDRs, ranges, domains; excludes; split into groups |
| `internal/scan` | a run: groups, worker pool, rate limiter, time window, checkpoint/resume, timing |
| `internal/scan/nmap` | build nmap command lines, parse XML; behind a `Runner` interface so tests use recorded XML |
| `internal/probe` | HTTP/HTTPS probing: title, status, headers, cookies, redirects, TLS, favicon hashes |
| `internal/detect` | built-in technology detection and the signature engine (`docs/contracts.md` §4) |
| `internal/inventory` | hosts, services, observations per run, status and stability, user-owned fields |
| `internal/diff` | changes between runs, volatile-field rules |
| `internal/store` | Postgres access, migrations, field encryption |
| `internal/auth` | users, sessions, roles and permissions |
| `internal/web` | UI handlers, templates, JSON API |
| `internal/exchange` | import/export JSON and CSV, DefectDojo export |
| `internal/schedule` | schedules, windows, frequency |

## Scan pipeline

1. Expand targets minus excludes, split into groups. Group size starts at 64 addresses and adapts to the measured
   speed so a group takes roughly 30-60 s; every group records its duration.
2. Per group: host discovery (`nmap -sn`, plus a TCP connect to the allowed ports for hosts that drop ICMP), then
   service detection on live hosts (`nmap -sT -sV --version-light -p <ports> -oX -`, soft matches taken as final), only on
   the allowed ports, then one `nmap -sT -sV` pass at default intensity for the ports left unidentified (setting
   `service_detection`, default `standard`; `light` skips it).
3. Per open port that speaks HTTP or TLS, and per port nmap could not identify (tried over HTTP, then TLS): HTTP
   probe, then built-in detection and signatures. Industrial and printing ports (a fixed list in `internal/scan`) get
   only a TCP connect: no nmap service probe and no HTTP request.
4. Results are written per group, so a stopped run (window end, crash, cancel) resumes from the first unfinished group.
5. `--max-rate` is split once per run: nmap gets half (rounded down), shared by the concurrently running nmap calls so their `--max-rate` values never sum above it, and the probe's token bucket gets the rest; per-host concurrency is 2.

The scanner never sends anything but discovery probes and plain `GET`/`HEAD` requests, never follows a redirect to a
host outside the run's targets, identifies itself with a fixed `User-Agent: asi-discovery/<version>`, and never
touches a port outside the configured list.

## Inventory and change model

- `host` (address) and `service` (host, port, protocol) are long-lived rows. Each run writes an `observation` per
  host and per service it saw. Current state is derived from observations and never edited by users.
- User-owned fields (tags, notes, display name, owner, criticality, manual status override) live in their own
  columns and are never written by the scan pipeline (R14).
- Status: seen in the latest run that covered it → `active`; missed `1 … N-1` consecutive covering runs → `unstable`;
  missed `N` → `inactive`. `N` is per run configuration (default 3). `stability` = share of the last 10 covering runs
  in which it was seen. A run "covers" a host only when the host's group completed.
- Hosts that were `active` or `unstable` in the previous run and were not found are re-probed once at the end of the
  run before they are counted as missed.
- Run modes: a `full` run covers every address of its groups for every port; a `recheck` run (`RunSettings.Mode`)
  contacts only the known services, i.e. the tcp services `active` or `unstable` as of its base (the latest completed
  run of the same scan definition, or with the same targets and excludes), and records per covered address the ports
  it covered (`run_group_addresses.ports`, NULL for full coverage). A service counts as covered by a run only when its
  address is covered and the port is in that list (or the run observed it), so uncontacted hosts and services keep
  their state. Every run stores the traffic it sent (`runs.packets`): measured HTTP requests plus an estimate of nmap's
  packets from addresses and ports.
- Availability profile: per host 24 hour-of-day buckets, each starting at 0.5 and updated per covering run with an
  exponentially weighted average `v = v + 0.3 × (x − v)` (x = 1 seen, 0 missed). The hour is that of the covering
  group's completion time (`run_groups.completed_at`) in the timezone of the run's stored schedule (UTC without one).
  A host with at least 6 samples, a bucket >= 0.8 and a bucket <= 0.2 is periodic; a miss in an hour whose bucket was
  <= 0.2 before the run updates the profile but is left out of status, `missed_runs` and stability for the host and
  its services. The profile is derived from observations at read time, like status; nothing is stored.
- Technology confidence 0-100: taken from the signature or built-in rule, multiplied by `stability` when reported.
- Interest score 0-100: weighted sum of finding kinds (admin panel, staging, IoT, notable header/cookie), newness,
  self-signed or expiring certificate, outdated version markers.

## Security

- Local accounts, argon2id password hashes, server-side sessions in Postgres, `HttpOnly` + `SameSite=Lax` cookies,
  CSRF tokens on every state-changing form, audit log of logins, edits, imports and scan control.
- RBAC: permissions are fixed strings (`inventory.read`, `inventory.edit`, `inventory.create`, `inventory.delete`,
  `scan.run`, `scan.configure`, `signature.manage`, `export`, `import`, `user.manage`, `role.manage`); a role is a
  named set of permissions. Built-in roles: `admin` (all), `editor` (create, delete, edit, read, import, export,
  scan.run, signature.manage), `operator` (edit, read, export), `viewer` (read). Custom roles can be created.
  Every handler declares the permission it needs; a test walks the route table and fails on an undeclared route.
- Encryption at rest: sensitive columns (response headers, cookie metadata, bodies kept as evidence, learned field
  state, finding evidence, notes, DefectDojo connection and token; imported files are not stored at all) are stored as AES-256-GCM ciphertext with a key derived from
  `ASI_MASTER_KEY` (HKDF, key id stored with the value so keys can rotate). Columns needed for search and diff
  (address, port, title, technology names) hold no secrets and stay plain. Deployment docs also require an encrypted
  volume for Postgres.
- No secrets in logs. Uploaded files are size-limited and parsed, never executed or stored on disk unencrypted.

## Testing

- Unit tests next to the code; nmap behind an interface with recorded XML fixtures; HTTP probing against `httptest`.
- Integration tests (build tag `integration`) need Postgres from `docker-compose.test.yml`.
- Acceptance: `lab/run.sh` brings up a fixed /24 of known services, runs three scans with changes in between and
  compares exports and diffs with `lab/expected.json`. It only uses `docs/contracts.md`.
