#!/usr/bin/env bash
# Performance run on the simulated /18. usage: run.sh <workers> <max-rate> [label]
# Writes ../results/perf/<label>.json: duration, addresses/s, hosts found vs truth, peak memory, rate seen by the target.
set -euo pipefail
cd "$(dirname "$0")"
WORKERS="${1:-16}"; RATE="${2:-1000}"; LABEL="${3:-w${WORKERS}-r${RATE}}"
DC="docker compose -f docker-compose.yml"
ASI="$DC exec -T asi asi"
PORTS="22,80,443,6379,8000,8080"
RES="../results/perf"; mkdir -p "$RES"
trap '$DC down -v --remove-orphans >/dev/null 2>&1 || true' EXIT
$DC down -v --remove-orphans >/dev/null 2>&1 || true
rm -rf out && mkdir -p out
$DC up -d --build --wait postgres asi bignet >/dev/null
$ASI migrate >/dev/null

stats() { while :; do docker stats --no-stream --format '{{.Name}},{{.MemUsage}},{{.CPUPerc}}' asi-bignet-asi-1 asi-bignet-postgres-1 >> out/stats.csv 2>/dev/null || true; sleep 2; done; }
stats & STATS=$!

scan() { # scan <name>
  local t0 t1; t0=$(date +%s)
  $ASI scan run --targets-file /bignet/targets.txt --exclude-file /bignet/exclude.txt --ports "$PORTS" \
    --name "$1" --workers "$WORKERS" --max-rate "$RATE" --inactive-after 3 --wait > "out/$1.log" 2>&1 || echo "scan $1 exit $?" >> "out/$1.log"
  t1=$(date +%s); echo $((t1 - t0)) > "out/$1.seconds"
  $ASI export --format json --out "/out/$1.json" >/dev/null
  $ASI scan show "$1" > "out/$1.show" 2>&1 || true
}
scan big-1
$DC exec -T bignet python3 /responder.py down 20 > out/down.log
scan big-2
$ASI diff --from big-1 --to big-2 --format json --out /out/diff-1-2.json >/dev/null
$DC exec -T bignet python3 /responder.py up >> out/down.log
scan big-3
$ASI diff --from big-2 --to big-3 --format json --out /out/diff-2-3.json >/dev/null
kill $STATS 2>/dev/null || true

python3 summarize.py out "$WORKERS" "$RATE" > "$RES/$LABEL.json"
cat "$RES/$LABEL.json"
