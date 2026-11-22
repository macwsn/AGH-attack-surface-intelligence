# Operations

Running ASI: configuration, deployment, keys, backups, upgrades, scheduling, safe scanning and troubleshooting.
How it works inside is in [technical.md](technical.md).

## Environment variables

Read by every `asi` command.

| Variable | Default | Meaning |
|---|---|---|
| `ASI_DATABASE_URL` | none, required | PostgreSQL URL, `postgres://user:password@host:port/db`. Standard pgx parameters work, for example `?sslmode=require` or `&pool_max_conns=20` |
| `ASI_MASTER_KEY` | none, required | base64 of exactly 32 bytes; the field encryption key. Generate with `openssl rand -base64 32` |
| `ASI_MASTER_KEY_PREVIOUS` | empty | comma-separated base64 keys that wrote older data; only used to read it. Needed during a key rotation, see [Key management](#key-management) |
| `ASI_LISTEN` | `:8080` | listen address of `asi serve` |
| `ASI_INTEREST_WEIGHTS` | built-in weights | interest score weights as `code=points,...` with points 0-100; codes not named keep their default. Codes: `admin-panel`, `staging`, `iot`, `interesting-header`, `interesting-cookie`, `new`, `recent`, `self-signed`, `expiring-cert`, `outdated` |
| `ASI_BODY_RETENTION_RUNS` | `10` | how many of the newest observations of a service keep their stored page excerpt (used by retro-hunts with `body_regex`); older excerpts are deleted when a run finishes. A whole number, at least 1 |
| `ASI_SIGNATURES_DIR` | empty | a signatures directory for `asi serve`: checked at start (a bad file stops the start), then used for every scan, import and manual entry of that process, and for the id check of the signatures UI. Read once; see [Signature files](#signature-files) |
| `ASI_TIMEZONE` | the process's local zone | IANA zone name (for example `Europe/Warsaw`) the UI shows times in |
| `ASI_VOLATILE_HEADERS` | empty | response header names, comma-separated, that never count as a change, in addition to the built-in list (`date`, `etag`, ...). Case does not matter |

No other `ASI_*` variable is read by the binary. Scan windows use the timezone of their scan definition, not
`ASI_TIMEZONE`. `NMAPDIR`, when set, is where ASI looks for nmap's
`nmap-service-probes`.

Used by the Compose files and the tests, not by the binary:

| Variable | Default | Meaning |
|---|---|---|
| `ASI_POSTGRES_PASSWORD` | `asi` | password of the PostgreSQL container in `docker-compose.yml` |
| `ASI_TEST_DATABASE_URL` | none | database for `go test -tags integration`; each test package creates its own schema |
| `LAB_SLOT` | `0` | `lab/run.sh`: compose project `asi-lab-<slot>` and subnet `172.30.<slot>.0/24` |

## Command line reference

`asi <command>`; every command exits 0 on success and prints a one-line error to stderr otherwise (exit 1; wrong
usage prints the usage text and exits 2). `asi --help` prints the list.

| Command | Purpose |
|---|---|
| `asi migrate` | apply the embedded schema migrations; safe to repeat |
| `asi serve` | web UI, scheduler and scan workers |
| `asi user create --username U --role R --password-stdin` | create a user; the password is one line on stdin, at least 12 characters |
| `asi user list` | users with role, `enabled`/`disabled` and creation time |
| `asi user set-role --username U --role R` | change a user's role |
| `asi user delete --username U` | delete a user |
| `asi role list` | roles, whether built in, and their permissions |
| `asi scan run ... --wait` | create a run and execute it in this process |
| `asi scan plan ...` | the same flags without `--name` and `--wait`: print what a run would cover, the worst-case traffic and the expected duration; sends nothing |
| `asi scan resume NAME` | continue a paused, failed or stalled run in this process |
| `asi scan show NAME` | status, mode, traffic, rate, progress and groups of a run |
| `asi export --format json\|csv --out FILE [--run NAME]` | the inventory as of the latest or the named run |
| `asi diff --from NAME --to NAME [--format json] --out FILE` | changes between two runs |
| `asi import --format json\|csv --file FILE [...]` | import hosts and services as a run |
| `asi host edit ADDRESS [--add-tag T]... [--remove-tag T]... [--notes TEXT]` | change user-owned fields of a host |
| `asi inventory rebuild-summary` | rebuild the derived table behind the host list; only needed if the list and the exports disagree |
| `asi signature hunt --file SIG.yaml [--since D] [--format text\|json]` | run one signature over the stored history |
| `asi defectdojo configure --url URL --product ID --engagement ID [--token-stdin] [--force]` | store the DefectDojo connection; a changed connection is tested first, `--force` saves it even when the test fails |
| `asi defectdojo test` | check the stored connection and the stored test ids |
| `asi defectdojo export --run NAME [--dry-run [--out DIR] \| --force]` | export a run, or write the payloads to files (default directory `defectdojo-NAME`); `--force` exports a run older than the last exported one |
| `asi key status` | current key id and rows per table under the current and older keys |
| `asi key rotate [--batch N]` | re-encrypt values written under older keys, N rows per transaction (default 500) |
| `asi version` | print the version |

`--out /dev/stdout` writes a document to the terminal. Every command except `version` and `--help` needs
`ASI_DATABASE_URL` and `ASI_MASTER_KEY`. The inventory commands (`scan`, `export`, `diff`, `import`, `host`,
`inventory`, `signature`) refuse to run when the database holds data under a key they were not given.

Users can be disabled and enabled, and passwords reset, only on `/users/` in the UI.

### asi scan run

| Flag | Default | Meaning |
|---|---|---|
| `--targets-file F` | required | one target per line: IPv4 address, CIDR, last-octet range `a.b.c.d-e`, domain or host name; `#` starts a comment |
| `--exclude-file F` | none | same format; excluded addresses are never contacted |
| `--ports LIST` | required | ports, ranges and presets separated by commas: `21,80,8000-8100`, `top100`, `top1000`, `all` |
| `--name NAME` | required | unique name of the run |
| `--wait` | required | run in this process and return when the run has finished |
| `--max-rate PPS` | `100` | packets and requests per second for the whole run, at least 2 |
| `--workers N` | `4` | groups scanned at the same time, at least 1 |
| `--inactive-after N` | `3` | consecutive missed runs after which a host or service is `inactive`, at least 1 |
| `--http-timeout D` | `10s` | deadline of each HTTP request, a Go duration, at least `1ms` |
| `--service-detection M` | `standard` | `standard`: light nmap pass plus one default-intensity pass for unidentified ports; `light`: light pass only |
| `--signatures-dir D` | none | directory of `*.yaml` signature files to load in addition to the stored signatures and the built-in pack; read when the run starts |
| `--mode M` | `full` | `full` or `recheck` (only the services known from the base run, see [technical.md](technical.md#rechecks)) |
| `--no-adaptive` | off | keep the rate fixed; by default it is halved when targets slow down or time out |
| `--max-addresses N` | `262144` | refuse targets that expand to more addresses after excludes |
| `--max-work N` | `262144000` | refuse targets whose addresses × ports exceed N |

`asi scan plan` takes the same flags (except `--name` and `--wait`) and prints a `plan` line (addresses, ports,
groups, group size, worst-case packets and requests, duration at the max rate and, when an earlier run with the same
targets exists, at its measured rate), a `plan_mode` line and the line
`nothing was sent: packets and requests are worst-case counts (every address up, every port open and speaking HTTP)`.
It resolves host names and reads the database; it sends nothing to the targets.

`asi scan show NAME` prints one line with `status` (`stalled (process gone)` for a running run whose heartbeat is
older than 60 s), `mode`, `packets`, `requests_measured`, `nmap_packets_estimated`, `max_rate`, `adaptive`, the peak
and average sent rate with two small charts, groups, addresses, hosts, rate, progress and time left, then one line
per group and per failed group.

### asi import

| Flag | Default | Meaning |
|---|---|---|
| `--format json\|csv` | required | file format |
| `--file FILE` | required | file to import, at most 20 MiB |
| `--name NAME` | generated from the time | name of the run the import is recorded as; must be unused |
| `--dry-run` | off | report what would change, record nothing |
| `--signatures-dir D` | none | signatures to run on the imported HTTP data, in addition to the stored signatures and the pack (`ASI_SIGNATURES_DIR` is not used by `asi import`) |
| `--inactive-after N` | `3` | threshold of the import run |

### asi signature hunt

| Flag | Default | Meaning |
|---|---|---|
| `--file SIG.yaml` | required | a file with exactly one signature |
| `--since D` | whole history | only runs started within this period: a Go duration (`72h`) or days (`30d`) |
| `--format text\|json` | `text` | `json` prints an `asi.hunt/v1` document |

## Deployment with Docker Compose

The repository root has a `Dockerfile` (a static `asi` binary on Alpine with `nmap`) and a `docker-compose.yml`
with two services: `postgres` (PostgreSQL 17, data in the volume `pgdata`) and `asi`, which runs `asi migrate` and
then `asi serve`.

```sh
export ASI_MASTER_KEY="$(openssl rand -base64 32)"
export ASI_POSTGRES_PASSWORD="$(openssl rand -hex 24)"
docker compose up -d --build --wait
printf '%s\n' 'a-long-password' | docker compose exec -T asi asi user create --username admin --role admin --password-stdin
```

Compose refuses to start without `ASI_MASTER_KEY`. Keep both values in a secrets store or an `.env` file readable by
the operator only; Compose reads `.env` from the directory of the compose file.

Before using it on a real network:

- **TLS.** The UI is published on `127.0.0.1:8080` over plain HTTP. Put a reverse proxy with TLS in front of it and
  keep the port bound to localhost. The session cookie is marked `Secure` only when ASI itself receives the request
  over TLS, so restrict access to the proxy.
- **Database.** Set `ASI_POSTGRES_PASSWORD`, and put the `pgdata` volume on an encrypted disk: field encryption
  covers the sensitive columns, not addresses, ports and titles.
- **Network position.** The `asi` container must be able to reach the scanned networks. With the default bridge
  network scans leave through the Docker host's address; that address is what target owners will see.
- **Privileges.** nmap needs raw sockets for ICMP and SYN discovery. The container runs as root with Docker's
  default capabilities, which include `NET_RAW`. If you drop capabilities, keep `NET_RAW`.
- **Signature files.** To use a signatures directory, mount it into the `asi` container and set
  `ASI_SIGNATURES_DIR`, enter its path in the scan definition ("Signatures directory") or pass `--signatures-dir`.
  See [Signature files](#signature-files).
- **Health.** `GET /healthz` answers `ok` without a session; the Compose health check uses it.

Roles for further users: `admin`, `editor`, `operator`, `viewer` (what each may do is in
[technical.md](technical.md#rbac-matrix)).

## Key management

`ASI_MASTER_KEY` encrypts response headers, cookie data, stored page excerpts, learned field state, finding
evidence, host notes and the DefectDojo connection.

- Generate it once (`openssl rand -base64 32`) and store it outside the database backup. Without it the encrypted
  columns cannot be read; there is no recovery.
- `asi serve` and the inventory commands refuse to start when a table holds values under a key that is neither
  `ASI_MASTER_KEY` nor in `ASI_MASTER_KEY_PREVIOUS`:
  `ASI_MASTER_KEY cannot read stored data: <table>.<column> holds values under key id <hex>, which is neither ASI_MASTER_KEY nor in ASI_MASTER_KEY_PREVIOUS; start with the key that wrote the data, or add it to ASI_MASTER_KEY_PREVIOUS`.
- `asi key status` prints `current key id <hex>`, one line per encrypted table with the rows under the current key
  and under each older key id, and a total.

Rotating the key:

1. Take a backup (dump and the old key).
2. Generate a new key. Set `ASI_MASTER_KEY` to the new key and `ASI_MASTER_KEY_PREVIOUS` to the old one, and restart
   `asi serve` (with Compose, add `ASI_MASTER_KEY_PREVIOUS` to the `asi` service environment first). New values are
   written with the new key from now on; old ones stay readable.
3. Run `asi key rotate` with the same two variables, for example
   `docker compose exec -T asi asi key rotate`. It rewrites the rows under older keys in batches of 500 (`--batch N`)
   and prints `<table>: N rows rewritten` per table and
   `key rotate: done, all encrypted rows are under key id <hex>`. Run it while no scan is running. It can be repeated;
   an interrupted rotation continues where it stopped, a repeated one rewrites nothing.
4. `asi key status` must print `total: 0 rows under old key ids`. Then remove `ASI_MASTER_KEY_PREVIOUS` and restart.

`asi key rotate` is not written to the audit log.

## Backup and restore

Everything ASI stores is in PostgreSQL. A backup is a database dump plus the master key, kept separately.

```sh
docker compose exec -T postgres pg_dump -U asi -Fc asi > asi-$(date +%F).dump
```

Restore into the running stack (this replaces the current content):

```sh
docker compose stop asi
docker compose exec -T postgres pg_restore -U asi -d asi --clean --if-exists < asi-2026-11-21.dump
docker compose start asi
```

Start `asi` with the `ASI_MASTER_KEY` that was in use when the dump was taken. A run that was in progress at the
moment of the dump comes back as `paused` (`scheduler: 1 interrupted runs marked paused, they resume in their next
window` in the log); resume it from its run page or let its next window pick it up.

For a portable copy of the inventory alone, `asi export --format json --out FILE` and `asi import` work between
installations with different keys.

## Upgrading

1. Take a backup.
2. Build and start the new version: `docker compose up -d --build --wait`. The `asi` container runs `asi migrate`
   before `asi serve`.
3. Check `docker compose logs asi`: it prints `migrations: applied <names>` or `migrations: up to date`, then
   `asi serve: listening on ...`. A line `host summary: rebuilt N hosts` means the derived table behind the host
   list was filled for hosts recorded by an older version. A line `field encryption: encrypted N stored values`
   means values an older version kept in plain text were encrypted (see below).

Migrations are embedded in the binary, run in one transaction under an advisory lock and are recorded in
`schema_migrations`, so repeating `asi migrate` or starting two instances at once is safe. There are no down
migrations; to go back, restore the backup.

Migrations are recorded by file name, not by number. Two files share the number 0005 (`0005_scan_definitions.sql`
and `0005_signatures.sql`); both are applied, in name order. Never rename a migration file: the renamed file would
be applied a second time. `asi serve` does not apply migrations itself.

Outside Compose: run `asi migrate` with the new binary before starting `asi serve`.

Upgrading over migration `0020` (data protection):

- Host owners and display names, the targets and excludes of scan definitions and runs, and the YAML sources of
  stored signatures and retro-hunts were plain text before. The migration marks them pending; `asi migrate`, and
  `asi serve` at start, encrypt them with `ASI_MASTER_KEY`. Start with the key the database was written with: a
  wrong key stops with `ASI_MASTER_KEY cannot read stored data` and encrypts nothing.
- The migration ends every session, because CSRF tokens were stored in plain text until then. Every user signs in
  again once.

## Creating scans in the UI

**Scans** offers three ways to start (scan definitions need `scan.configure`):

- **Quick scan** at the top of the Scans page, for roles with both `scan.configure` and `scan.run`: targets
  (comma-separated) and a port set. It creates a disabled definition named `Quick scan of <first target>[ and N
  more], <date> <time>` with the defaults below and starts a full run at once; the browser goes to the run page.
- **New scan** (`/scans/new`), the full form. **Templates**: `/scans/new?template=single-host` (all ports, no
  schedule) and `/scans/new?template=large-network` (top 1000, Saturday 22:00-06:00 weekly, recheck every hour).
- Editing a definition uses the same form.

The form:

| Part | Fields |
|---|---|
| Basic | name; targets (one per line, or a `.txt`/`.csv` file: one target per line or the first CSV column, a header `target`, `targets`, `address` or `addresses` is skipped); excludes (same, also as a file); ports; pace; plan summary |
| Schedule | on or off, weekdays, start and end time, timezone, frequency, interval, recheck interval |
| Advanced | workers, inactive after, service detection, mode, signatures directory, volatile headers, exact rate (overrides the pace), windows as text |

| Port set | Ports |
|---|---|
| Web (default) | 80, 443, 8000, 8080, 8443 |
| Top 100, Top 1000 | nmap's most common 100 or 1000 ports |
| All | 1-65535 |
| Custom | the ports field |

| Pace | Max rate |
|---|---|
| Careful | 20 per second |
| Normal (default) | 100 per second |
| Fast | 500 per second |

The pace sets only the rate; workers (default 4) and adaptive back-off are unchanged. Other defaults: inactive after
3, service detection `standard`, mode `full`, schedule off (window 22:00-06:00 daily in the server's timezone when
switched on).

The **plan summary** under the targets updates while typing and sends nothing to the network: `N addresses after
excludes, M ports, G groups, at most P packets and requests, about T at this rate`, with a warning above 65 536
addresses or for all ports. A schedule summary does the same for the schedule part. The form, uploads included, is
limited to 1 MB; invalid target lines are listed with their line number (the first 10).

**Delete scan** on a scan page (`scan.configure`) removes the definition after a confirmation page. Its runs and their
observations stay; their run pages say "Definition deleted". A definition with a run in progress or paused cannot be
deleted.

## Scheduling and time windows

A scan definition (**Scans** in the UI) holds targets, excludes, ports, max rate, workers, the inactivity threshold,
an optional signatures directory, volatile headers, an optional recheck interval and a schedule. Saving is refused
when the targets times the ports exceed the work ceiling (262 144 000 address-ports); the form names the counts.

| Field | Format |
|---|---|
| Windows | one per line: weekdays and times, `mon-fri 22:00-06:00`, `sat,sun 00:00-00:00`. A window whose end is at or before its start ends the next day. Empty means any time |
| Timezone | an IANA name such as `Europe/Warsaw`; empty means UTC. Windows follow daylight saving time |
| Frequency | once a day, once a week, or at an interval (a duration of at least `1m`, for example `6h`) |
| Recheck every | optional duration shorter than the frequency, for example `1h`: between full runs, revisit only the known open services |

How the scheduler behaves (`asi serve` checks every 30 seconds):

- A definition is created disabled. Only enabled definitions are started by the scheduler.
- A new run starts when the clock is inside a window and a run is due: never run before, the interval has passed
  since the last start, or for daily and weekly the last run started on an earlier day or week.
- A run still going at the end of its window is cancelled between groups and marked `paused`. In the next window the
  same run continues with the addresses it has not covered yet. Finished groups are not scanned again.
- A definition has at most one open run. Starting a second one answers "This scan already has a run in progress or
  paused."
- **Start scan now** starts a full run at once and ignores the windows; it runs until it is done or paused.
  **Start recheck** does the same for a recheck run. **Preview** and **Preview recheck** (`/scans/{id}/preview`)
  show what a full run or a recheck would send and how long it would take, without sending anything.
- With "Recheck every", the scheduler starts a full run when the frequency is due and otherwise a recheck when the
  interval has passed since the last run of either mode. A recheck takes only hosts of the definition's own targets
  with an active or unstable service, puts hosts usually up at this hour first, and skips a host in an hour it is
  usually down unless it was last seen more than 24 h ago. Without a completed run, a due recheck starts a full run.
- **Pause run** holds a run: the scheduler does not resume it until someone presses **Resume run**.
- Runs interrupted by a restart of `asi serve` are marked `paused` at the next start and resumed in their next window.
  A run whose process died while `asi serve` kept running (heartbeat older than 60 s) is marked `paused` by the
  scheduler and resumed in the next window; it never blocks its definition.
- Runs of a definition are bound by the work ceiling but not by `--max-addresses`.
- Editing a definition does not change a run that is already open; the run keeps the settings it started with.
- Runs are named `<definition>-<YYYYMMDD>-<HHMMSS>` (UTC).

Runs started with `asi scan run` do not belong to a definition and are not touched by the scheduler. Interrupt one
with Ctrl-C or SIGTERM and it is marked `paused`; `asi scan resume NAME` continues it. After `kill -9` the run stays
`running` and shows `stalled (process gone)` after 60 s; `asi scan resume NAME` takes it over then. The nmap calls of
the killed process may still be running for up to about a minute (ASI does not bound them); check with
`docker compose exec asi ps` (or `ps` on the host) before resuming a large scan.

## Rate limiting and safe scanning

`--max-rate` (UI: "Max rate") is one limit for the whole run, in packets and requests per second:

- half of it (rounded down) goes to nmap, divided between the nmap processes that run at the same time, so their
  `--max-rate` values never add up to more than that half;
- the rest is a token bucket for HTTP requests (root page, redirects, favicon, signature paths);
- at most 2 HTTP requests are in flight per host, and at most 8 hosts of a group are probed at the same time;
- unless `--no-adaptive` is set, the rate is halved when the probe's median latency doubles or more than 10% of its
  requests time out, and raised again by a tenth when targets recover; a host with 3 timeouts in a row is paused.

Workers set how many groups are scanned in parallel; they do not raise the limit.

The rate shown on the run page and by `asi scan show` mixes a measurement and an estimate: HTTP requests are counted,
nmap packets are estimated from addresses and ports (nmap's retransmissions and version probes are not included).
The page labels them "measured" and "estimated". Use the target side (firewall counters, IDS) when an exact packet
rate matters.

What the rate limit does not change: nmap's service detection sends its own probes, not only TCP connects (see
[technical.md](technical.md#what-nmap-sends)); `--service-detection light` keeps to nmap's light probe set. Industrial
and printing ports (Modbus 502, S7 102, BACnet 47808, EtherNet/IP 44818 and 2222, MQTT 1883 and 8883, JetDirect
9100-9107, LPD 515 and others) get only a TCP connect, no nmap service probe and no HTTP request; the full list is in
[technical.md](technical.md#scan-pipeline).

Guidance for a production network:

- Start low. The default is 100 per second; 100 to 300 is a reasonable start for a campus network. Raise it only
  after watching a full run. The measured reference is in
  [technical.md](technical.md#known-limitations): a /18 at `--max-rate 1000` with 16 workers took about 130 s.
- List only the ports you need. `all` on a large range multiplies the traffic by orders of magnitude; `top100` is a
  sensible ceiling for wide ranges.
- Maintain the exclude list: fragile devices, medical and laboratory equipment, anything with a contractual ban on
  scanning, the scanner itself and its database.
- Use windows. Scan user networks at night and server networks outside maintenance windows.
- Check the size of a target list before the first run with `asi scan plan` or **Preview**. `asi scan run` refuses
  more than 262 144 addresses (`--max-addresses`) and every run refuses more than 262 144 000 address-ports
  (`--max-work`); a mistyped `/16` with `top100` is still accepted.
- Recheck runs save packets on sparse ranges, not time on a single host: the same nmap passes and HTTP probes run
  for each known service.
- Tell the network operations team the scanner's source address and its `User-Agent` (`asi-discovery/<version>`),
  so the traffic is recognised in logs and on intrusion detection systems.
- Watch the first runs on the run page: addresses per second, failed groups and the time left. Failed groups mean
  a group hit the 10-minute timeout twice; look at the addresses listed there.
- Keep `--http-timeout` at the default unless services are known to be slow; a stalled service costs one timeout per
  request, not the whole run.

What ASI sends, exactly, is listed in [technical.md](technical.md#scanner-safety-rules).

## Signature files

- Signatures stored through the UI are picked up by the next scan without a restart.
- Files in `ASI_SIGNATURES_DIR` are read when `asi serve` starts and kept in memory. A file changed on disk is used
  only after a restart of `asi serve` (any change to a signature in the UI also makes it re-read the directory).
- A directory named in a scan definition that differs from `ASI_SIGNATURES_DIR`, and `--signatures-dir` of
  `asi scan run`, are read again at the start of every run; a changed file applies from the next run.
- A file that breaks a rule stops `asi serve` from starting (`ASI_SIGNATURES_DIR: ...`) or a run from being created.

## Users and roles

- `/users/` (permission `user.manage`): create users, change the role, reset the password, disable, enable and
  delete. A reset, a disable and a delete end the user's sessions.
- `/roles` lists every permission with a description of what it allows.
- `/account` (every signed-in user, linked from the user name in the page header): change one's own password with
  the current one. Wrong current passwords count against the login rate limit; the other sessions of the user end.
- `/roles` (permission `role.manage`): the permission matrix of every role; create, change and delete custom roles.
  Built-in roles cannot be changed; a role still assigned cannot be deleted.
- The last enabled user with the role `admin` cannot be deleted, demoted or disabled
  (`the last enabled admin cannot be deleted, demoted or disabled`).
- Strength rule: resetting a password, disabling, deleting or changing the role of a user is allowed only when the
  actor holds every permission of that user's role. Assigning a role needs every permission of that role. Nobody
  changes their own role; one's own account is changed only on `/account`. The last full administrator cannot be
  deleted, demoted or disabled.

## Reading the audit log

**Audit log** in the UI (`/audit`, permission `user.manage`) lists the entries newest first, 50 per page, with filters
for actor, action (picked from the actions in the log) and target (exact match) and a from/to date (`2026-11-21` or `2026-11-21 14:00`, server local
time). From the database:

```sh
docker compose exec -T postgres psql -U asi -c \
  "SELECT at, actor, action, target, address FROM audit_log ORDER BY id DESC LIMIT 20"
```

The actions are listed in [technical.md](technical.md#security-model). Command-line actions are recorded with the
actor `cli`; `asi scan run`, `asi scan resume` and `asi key rotate` are not recorded.

## Troubleshooting

| Message | Cause and what to do |
|---|---|
| `required variable ASI_MASTER_KEY is missing a value: set ASI_MASTER_KEY to base64 of 32 random bytes, e.g. openssl rand -base64 32` (docker compose) | export `ASI_MASTER_KEY` or put it in `.env` before `docker compose up` |
| `ASI_DATABASE_URL is not set`, `ASI_MASTER_KEY is not set` | the variable is missing in the environment of the command |
| `ASI_MASTER_KEY is malformed: want base64 of exactly 32 bytes` | generate the key with `openssl rand -base64 32` |
| `ASI_DATABASE_URL is malformed: want postgres://user:password@host:port/db` | fix the URL |
| `connect to database: ... password authentication failed` | wrong user or password in `ASI_DATABASE_URL`; with Compose, `ASI_POSTGRES_PASSWORD` changed after the volume was created |
| `field encryption: unknown key id` | the data was written with another `ASI_MASTER_KEY`; use the original key |
| `ASI_MASTER_KEY cannot read stored data: T.C holds values under key id ...` | start with the key that wrote the data, or add it to `ASI_MASTER_KEY_PREVIOUS` and run `asi key rotate` |
| `ASI_MASTER_KEY_PREVIOUS is malformed: entry N is not base64 of exactly 32 bytes; want comma-separated keys` | fix entry N of the list |
| `ASI_SIGNATURES_DIR: ...` at `asi serve` start | a file in the directory breaks a rule; fix it, see [signatures.md](signatures.md#safety-rules) |
| `ASI_INTEREST_WEIGHTS is malformed: unknown key "..."` | use only the codes listed above |
| `ASI_BODY_RETENTION_RUNS is malformed: want a whole number of runs, at least 1` | fix or unset the variable |
| `password must be given on stdin: use --password-stdin` | pipe the password: `printf '%s\n' "$PW" \| asi user create ... --password-stdin` |
| `password must be at least 12 characters` | choose a longer password |
| `unknown role: "..."` | use a role from `asi role list` |
| `unknown user: "..."` | check the name with `asi user list` |
| `the last enabled admin cannot be deleted, demoted or disabled` | create or enable another `admin` first |
| `--targets-file: FILE: line N: invalid target "...": ...` | the line is not an IPv4 address, CIDR, range or name; IPv6 is not supported |
| `--ports: invalid port "..."`, `invalid port range "9000-8000"` | fix the port list |
| `--max-rate must be at least 2` | the limit is shared between nmap and the HTTP probe, so 2 is the minimum |
| `--max-addresses: the targets expand to N addresses, more than the bound of M; ...` | split the targets or raise `--max-addresses` |
| `--max-work: too much work for one run: the targets expand to ... address-ports, more than the ceiling of M; ...` | split the targets or the ports, or raise `--max-work` (UI and scheduler use the default) |
| `--service-detection must be light or standard`, `--mode must be full\|recheck, got "..."` | fix the flag |
| `no earlier run to recheck ...` | a recheck needs a completed run of the same definition or with the same targets and excludes; run a full scan first |
| `run "NAME" is still running in another process; ...` | wait until it is paused or shown as `stalled (process gone)`, then `asi scan resume NAME` |
| `inventory: run already exists: "NAME"` | run names are unique; choose another `--name` |
| `unknown run "NAME"` | check the name with the run list on the dashboard or the scan page |
| `run "NAME" paused: context canceled` (exit 1) | the run was interrupted; continue it with `asi scan resume NAME` |
| `run "NAME": scan: run is already completed` | nothing to resume |
| `--signatures-dir: FILE: signature "ID" violates rule "...": ...` | a signature breaks a safety or format rule; see [signatures.md](signatures.md#safety-rules) |
| `Row N: "..." is not an address.` (import) | the row is skipped, the others are imported; fix the row and import again if needed |
| `defectdojo is not configured: set the base URL, API token, product and engagement first` | run `asi defectdojo configure` or fill in `/defectdojo` |
| `not saved: the connection test failed ... (use --force to save it anyway)` | check URL, token, product and engagement; the message names the cause |
| `run ... is older than run ..., the last one exported to this engagement ... (use --force to export it anyway)` | export a newer run, or confirm with `--force` |
| "Too many failed sign-in attempts. Try again later." | 5 failures for the user or 20 from the address within 15 minutes; wait, or restart `asi serve` to clear the counters |
| "Invalid or missing CSRF token. Reload the page and try again." | the session expired or the page is stale; reload |
| "Your role does not allow this page." | the signed-in role lacks the permission; see the RBAC matrix |
| "This scan already has a run in progress or paused." | open that run and resume or wait for it |
| a run shows `stalled (process gone)` | the process that ran it was killed. For a command-line run use `asi scan resume NAME`; runs of scan definitions are paused by the scheduler and resumed in their next window |
| a file changed in `ASI_SIGNATURES_DIR` has no effect | restart `asi serve` |
| every user is signed out after an upgrade | expected once after migration `0020`, which ends all sessions |
| "Your role does not allow starting scans." on Quick scan | the quick scan needs `scan.run` as well as `scan.configure` |
| "Target lists over 1 MB are not accepted." | split the targets file or use `asi scan run --targets-file` |
| a scan cannot be deleted | it has a run in progress or paused; finish, or wait for, that run first |
| `/defectdojo` shows number fields instead of product and engagement lists | the lists could not be loaded; **Test connection** shows why |
| the run page shows a lower rate than `--max-rate` | the adaptive rate backed off because targets slowed down; the run page shows the rate in effect. Use `--no-adaptive` to keep it fixed |
| a group listed under "failed groups" | it hit the group timeout twice; the reason and the addresses are on the run page and in `asi scan show` |
