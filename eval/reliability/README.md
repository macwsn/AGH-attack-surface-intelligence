# Reliability (fault-injection) harness

Black-box tests of the `asi` CLI (docs/contracts.md) under faults: killed scanner, database outage, vanishing and
misbehaving targets, concurrent runs, bad input, repeated scans, wrong master key. No product code is touched.

## Run

    git worktree add --detach /tmp/claude-502/relsnap HEAD      # snapshot of the product
    docker build -t asi:rel /tmp/claude-502/relsnap
    git -C /tmp/claude-502/relsnap rev-parse HEAD > eval/reliability/PRODUCT_COMMIT
    eval/reliability/run.sh all                                 # or one scenario; KEEP=1 keeps the lab up
    git worktree remove --force /tmp/claude-502/relsnap

`RUN=run2 run.sh all` writes everything under `eval/results/reliability/run2/` instead. `extra.sh` holds two ad-hoc checks
(unroutable target, one tarpit host with default service detection). `run.sh all` takes about 50 minutes (11 scenarios), prints `PASS|FAIL <scenario>: <reason>` and tears the lab down
(`docker compose -p asi-rel down -v`). Exit code 3 = the lab could not start.

## Lab (compose project `asi-rel`, 172.29.0.0/24, no published ports)

| Address | What |
|---|---|
| .2 | product container (`asi:rel`, `sleep infinity`, commands via `docker compose exec`) |
| .3 | Postgres; every scenario gets its own freshly created database `rel_*` |
| .4 + .145-.254 | `eval/bignet/responder.py` at /25 scale: 54 simulated hosts |
| .9 + .10-.26, .40 | `hostile.py serve`: one misbehaving HTTP target per address (table in `hostile.py`), .40 = off-target redirect destination |
| .50 | `hostile.py vanish`: exits right after answering nmap's service probe when armed |
| .51 | `hostile.py toggle`: port 80 closes/reopens on command, 8080 and the host stay up |

## Files

- `run.sh` - scenarios; `check.py` - export comparison and verdict helpers; `hostile.py` - hostile targets
- `targets-*.txt`, `exclude.txt` - target sets; `PRODUCT_COMMIT` - commit the image was built from

## Results (`eval/results/reliability/`)

- `<scenario>/commands.log` - every command with its output and exit code; `<scenario>/result.json` - verdict and numbers
- `<scenario>/*.out|*.err|*.rc|*.json` - raw outputs, exports, diffs; `_baseline/` - the uninterrupted reference run
- `_lab/` - target-side logs (requests seen by the hostile targets, bignet truth)
- `summary.json` - all scenarios; `summary.md` - written by hand after a run
