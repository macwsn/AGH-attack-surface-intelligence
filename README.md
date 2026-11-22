# ASI - Attack Surface Intelligence

ASI is a tool for cyclic discovery scanning of large networks (10 000 addresses and more). It finds live hosts,
identifies the services they expose, collects HTTP/HTTPS details and technology fingerprints, and records how all of
that changes from one scan run to the next. It was built for the Information Security Centre of AGH University
(monitoring, incident handling, pentest preparation). It only discovers: its own HTTP probe and signatures send plain
`GET` and `HEAD` requests, it never logs in, and it never touches a port that is not on the configured list. nmap's
service detection, which ASI runs, sends nmap's own protocol probes to the listed ports (see
[docs/technical.md](docs/technical.md#what-nmap-sends)).

One Go binary (`asi`) holds the web UI, the scheduler, the scan workers and the command line. It needs PostgreSQL and
`nmap`; both come with the Docker setup.

## What it does

| Area | What exists |
|---|---|
| Targets | IPv4 addresses, CIDR ranges, last-octet ranges (`10.0.0.5-20`), domain and host names; an exclude list that always wins |
| Discovery | `nmap` host discovery and two-pass service/version detection on a fixed port list (ports, ranges, or the presets `top100`, `top1000`, `all`), several groups in parallel, group size adapted to the measured speed; `full` runs and `recheck` runs that revisit only known services |
| Safe scanning | one rate limit for nmap and HTTP together, backing off when targets slow down; pace presets; a plan preview that sends nothing; a ceiling on addresses × ports; industrial and printing ports get no service probe and no HTTP request |
| HTTP/HTTPS | status code, title, headers, cookie names and flags, redirect chain, TLS certificate, favicon hashes, response time; ports nmap could not identify are tried over HTTP and TLS |
| Technologies | built-in rules (nginx, Apache, PHP, WordPress, Drupal, Joomla), technologies from nmap's product and version (OpenSSH, vsftpd, Redis, PostgreSQL, MySQL, RabbitMQ and others), a built-in pack of 54 signatures (Grafana, Jenkins, GitLab, phpMyAdmin, routers, cameras, printers and others), the embedded Wappalyzer fingerprint dataset (about 7 700 applications, see `NOTICE`), generic heuristics, built-in notable headers, cookies, login forms and staging markers, `outdated` findings from a version table of 19 products, and your own signatures in YAML |
| Dashboard | "Needs attention" compares the two latest completed scans; run pages update every 3 s while running or paused, with plan estimates as a range; times in `ASI_TIMEZONE` |
| Changes | new, missing, returned, inactive and changed hosts and services between any two runs; per-request tokens and fields that change every run are not reported; a change feed, a per-host timeline, a chart per run |
| Unstable hosts | `active` / `unstable` / `inactive` with a configurable threshold, a stability figure, one re-probe before a host counts as missed, an hour-of-day availability profile; confidence reported times stability |
| Inventory | host list with filters and sorting, host page, tags, notes, owner, criticality; edits are never overwritten by scans; hosts, services and scan definitions can be deleted |
| Import and export | JSON and CSV, in the UI and on the command line, with sample files and a column list; a form for manual entry; imported data goes through the same detection and change tracking |
| Signatures | files in a directory or stored through the UI with a guided form; built-in ones can be switched off one by one; test against stored data; retro-hunt over the whole history without sending a packet |
| Scheduling | scan definitions with time windows, timezone, frequency and an optional recheck interval; a run that outlives its window is paused and continues in the next one; a run whose process died is taken over |
| Access | local accounts, four built-in roles and custom roles, roles assignable only by users holding all their permissions, user and role pages, own password change, audit log page, personal and sensitive columns encrypted in the database, session and CSRF tokens stored hashed, key rotation |
| DefectDojo | export of a run as an Nmap scan plus informational findings, reimport into the same tests; dry run to files |

Details and limits: [docs/technical.md](docs/technical.md). What is met of the challenge requirements:
[docs/requirements-coverage.md](docs/requirements-coverage.md).

## Quick start

You need Docker with Compose. Five commands, run in the repository root:

```sh
export ASI_MASTER_KEY="$(openssl rand -base64 32)"        # field encryption key - keep it, see docs/operations.md
docker compose up -d --build --wait                       # PostgreSQL + asi (migrations run on start)
printf '%s\n' 'choose-a-long-password' | docker compose exec -T asi asi user create --username admin --role admin --password-stdin
docker compose exec -T asi sh -c 'printf "postgres\nasi\n" > /tmp/targets.txt'
docker compose exec -T asi asi scan run --targets-file /tmp/targets.txt --ports 5432,8080 --name first --wait
```

The UI is at <http://127.0.0.1:8080> (published on localhost only). Sign in as `admin` with the password you chose;
passwords need at least 12 characters. The fourth and fifth command scan the two containers of the stack itself, so
there is something to look at: after about half a minute the dashboard shows two hosts.

```
$ docker compose exec -T asi asi scan run --targets-file /tmp/targets.txt --ports 5432,8080 --name first --wait
run first status=completed groups=1 addresses=2 hosts=2
```

## The first scan

### From the UI

The dashboard shows a "Get started" list until a scan exists, a run has completed and a second user or a custom
role has been added.

**Quick scan**, at the top of **Scans**: enter the targets (comma-separated addresses, CIDRs, ranges or names), pick
a port set (Web, Top 100, Top 1000, All) and press the button. ASI creates a scan with safe defaults (100 packets and
requests per second, 4 workers) and starts it at once; the browser goes to the run page.

**New scan** gives the full form:

1. Name, targets and excludes (typed, or uploaded as a `.txt` or `.csv` file), a port set or your own ports, and a
   pace (Careful 20, Normal 100, Fast 500 per second). The plan summary under the targets shows the addresses,
   groups, worst-case traffic and the expected duration while you type; nothing is sent.
2. Optionally a schedule (weekdays and hours, timezone, frequency, recheck interval) and the advanced settings.
   Two templates fill the form: one host with all ports, and a large network scanned weekly at night.
3. **Create scan**. The scan is created disabled. **Preview** shows what a run would send and how long it would take.
   **Start scan now** runs it once at once; **Enable** hands it to the scheduler, which starts it in its next window.

The run page (`/runs/{id}`) shows progress, speed, the time left and every group; **Pause run** and **Resume run**
are there too. Results appear under **Hosts** group by group while the run is going.

Scan definitions need the permission `scan.configure` (role `admin`); starting and pausing needs `scan.run`
(`admin`, `editor`); the quick scan needs both.

### From the command line

```sh
docker compose exec -T asi asi scan plan --targets-file /tmp/targets.txt --ports 5432,8080
docker compose exec -T asi asi scan run \
  --targets-file /tmp/targets.txt --ports 5432,8080 \
  --max-rate 100 --workers 4 --inactive-after 3 --name second --wait
docker compose exec -T asi asi scan show second
docker compose exec -T asi asi export --format csv --out /dev/stdout
```

A targets file has one target per line and `#` comments. `--ports` is the only set of ports ever touched.
`asi scan plan` takes the same flags and sends nothing.
All commands and flags: [docs/operations.md](docs/operations.md#command-line-reference).

## Seeing what changed between two runs

- UI: **Changes** compares the two latest completed runs; pick any other pair and a change type at the top. Each
  address links to the host timeline. **Export JSON** gives the same document as the command line.
- Command line:

  ```sh
  docker compose exec -T asi asi diff --from first --to second --format json --out /dev/stdout
  ```

A complete walk-through with two runs and a change in between is in [docs/demo.md](docs/demo.md).

## Tests and the acceptance lab

```sh
go test ./...                                             # unit tests, no network, no database

docker compose -f docker-compose.test.yml up -d --wait    # PostgreSQL on 127.0.0.1:55432 for integration tests
ASI_TEST_DATABASE_URL='postgres://asi:asi-test@127.0.0.1:55432/asi?sslmode=disable' go test -tags integration ./...

lab/run.sh                                                # acceptance lab, needs Docker and python3
```

`lab/run.sh` builds the image, starts a /24 of known services (WordPress, Drupal, an admin panel with TLS, a staging
site, SSH, Redis, an IP camera, a flapping host and others), runs three scans with known changes in between and
compares the exports and diffs with `lab/expected.json`. It prints `LAB: BLOCKED` and exits 3 when Docker itself
could not start the lab. `LAB_SLOT=0..9` selects the compose project and the subnet `172.30.<slot>.0/24`, so
several labs can run side by side.

`lab-agh/` holds the sample environments published by the organisers (see `lab-agh/README.md`); they listen on
`127.0.0.1` of the Docker host.

## Repository map

| Path | Content |
|---|---|
| `cmd/asi` | the binary: command line parsing and wiring |
| `internal/config` | configuration from environment variables |
| `internal/targets` | target and exclude lists, expansion |
| `internal/scan`, `internal/scan/nmap` | a scan run: groups, workers, rate limit, adaptive rate, rechecks, pause and resume, plan preview; the nmap wrapper |
| `internal/probe` | the HTTP/HTTPS probe |
| `internal/detect` | built-in detection, the version table, the built-in pack and the signature engine |
| `internal/inventory` | hosts, services, observations, status, availability, interest score, retro-hunt |
| `internal/diff` | changes between two states |
| `internal/schedule` | scan definitions, windows, the scheduler |
| `internal/exchange`, `internal/exchange/defectdojo` | import, export, DefectDojo |
| `internal/auth` | users, sessions, roles, audit log |
| `internal/store` | PostgreSQL access, migrations, field encryption, key check and rotation |
| `internal/web` | UI pages and templates |
| `lab/` | acceptance lab and its expected results |
| `lab-agh/` | the organisers' sample environments |
| `eval/` | evaluation harnesses and measured results |
| `specs/` | current behaviour, one file per capability |
| `docs/` | documentation |

## Documentation

| Document | For |
|---|---|
| [docs/technical.md](docs/technical.md) | architecture, data model, scan pipeline, change and status model, security, known limitations |
| [docs/operations.md](docs/operations.md) | configuration, deployment, keys, backup, upgrades, scheduling, safe scanning, troubleshooting |
| [docs/signatures.md](docs/signatures.md) | writing, testing, importing and exporting signatures |
| [docs/demo.md](docs/demo.md) | a 10-minute demo script with real output |
| [docs/requirements-coverage.md](docs/requirements-coverage.md) | requirement by requirement: status, where it lives, how to see it |
| [docs/requirements.md](docs/requirements.md) | the challenge requirements |
| [docs/contracts.md](docs/contracts.md) | command line, export, diff and signature formats |
| [docs/architecture.md](docs/architecture.md) | the design decisions taken up front |
