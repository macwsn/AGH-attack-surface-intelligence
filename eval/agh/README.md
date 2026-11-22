# eval/agh: ASI against the organisers' sample environments

Black-box acceptance harness. It starts the stacks from `lab-agh/`, scans them with the product CLI only
(`asi scan run / export / diff / import`), and compares the exports with what the environments really contain.
No product code is touched; everything is written under `eval/agh/` and `eval/results/agh/` (both git-excluded).

## Run

```bash
eval/agh/run.sh all            # A B D C E F G, then the report, then tear everything down
eval/agh/run.sh A              # one scenario (leaves the product project up; `run.sh down` removes it)
eval/agh/run.sh report         # rebuild summary.json / summary.md from the saved results
eval/agh/run.sh down           # tear down all asi-agh-* projects and the snapshot worktree
ASI_AGH_REBUILD=1 eval/agh/run.sh all   # re-snapshot main and rebuild the image first (after new features land)
```

Needs docker compose, python3, curl, lsof. A full run takes about 25-30 minutes.

## How it works

- Product: image `asi:agh`, built from a detached worktree of `main` (`/tmp/claude-502/aghsnap`, commit recorded in
  `eval/results/agh/commit.txt`). Project `asi-agh-prod` (`prod-compose.yml`): `postgres:17-alpine` + an `asi`
  container (`sleep infinity`, NET_RAW/NET_ADMIN, no published ports). Each scenario starts from a dropped and
  re-migrated database.
- Target: the scan target is `host.docker.internal`, i.e. the stacks' ports published on the host's 127.0.0.1.
- Stacks: `run.sh` copies `lab-agh/docker-compose-<stack>.yml` to `eval/agh/stacks/<stack>.yml` and runs it as project
  `asi-agh-<stack>`. A published host port that is already taken (checked with `lsof`, waiting up to 3 minutes) is
  remapped to port+20000; the mapping is in `eval/results/agh/portmap-<stack>.tsv` and the report uses the organisers'
  port numbers. The script refuses to start a file with a port not bound to 127.0.0.1.
- The `vulnerable` stack is up only for scenario E and is removed right after its scan (also on error).
- Request counting / safety: after every scan the target containers' logs since the scan start are saved under
  `eval/results/agh/<scenario>/logs/<scan>/`; `analyze.py` counts HTTP request lines and lists methods and paths.
  Services without an access log (RabbitMQ, Traefik, Toxiproxy, Redis, PostgreSQL, FTP) contribute 0.

## Scenarios

| | Stack | What |
|---|---|---|
| A | custom-network (flask-app, gitea, rabbitmq) | README quickstart: 3 scans with 8787 stopped in the middle, diffs; `--ports` with a range and with `top1000` |
| B | custom-network (all) | per-port identification |
| C | modern | WordPress, phpMyAdmin, Redis, Nginx Proxy Manager (TLS, cookies, headers) |
| D | modern-proxy | Toxiproxy: baseline, 500 ms latency, 1000 ms timeout; response time fields and diffs |
| E | vulnerable | vsftpd, WordPress 4.7, Adminer, DVWA: outdated / admin-panel findings, GET/HEAD only |
| F | custom-network | `signatures/agh-custom.yaml` via `--signatures-dir`; an unsafe (POST) signature must be rejected |
| G | (none) | JSON and CSV export of B imported into fresh databases and re-exported |

## Output

`eval/results/agh/<scenario>/`: `<run>.json` (export as of the run), `<run>.scan.log` (command, output, `scan show`),
`scans.tsv` (run, wall seconds, exit code, ports, command), `diff-*.json`, `logs/`.
`eval/results/agh/summary.json` (all checks with command and evidence, recognition table, scores, per-run durations and
request counts) and `summary.md` (short version). The expectations and the truth table live in `analyze.py`
(`TRUTH`): extend it when a stack changes.
