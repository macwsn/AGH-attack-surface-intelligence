#!/usr/bin/env bash
# Acceptance run against the lab: three scan passes with known changes in between, then check.py.
# Uses only the product's public CLI contract (docs/contracts.md).
# Exit 0 = every expectation holds, 1 = an expectation failed, 3 = the lab itself could not start (not the product's fault).
# LAB_SLOT (0-9, default 0) selects the compose project and subnet 172.30.<slot>.0/24, so several labs can run at once;
# the caller makes sure a slot is used by one run at a time.
set -euo pipefail
cd "$(dirname "$0")"
export LAB_SLOT="${LAB_SLOT:-0}"
NET="172.30.$LAB_SLOT"
DC="docker compose -p asi-lab-$LAB_SLOT -f docker-compose.yml"
ASI="$DC exec -T asi asi"
PORTS="22,80,443,6379,8000,8080,8081"
SCAN="scan run --targets-file /out/targets.txt --exclude-file /out/exclude.txt --ports $PORTS --signatures-dir /lab/signatures --inactive-after 2 --max-rate 300 --wait"

blocked() { echo "LAB: BLOCKED ($1)"; exit 3; }
down() { $DC --profile stage2 down -v --remove-orphans >/dev/null 2>&1 || true; }
trap down EXIT
down
rm -rf out && mkdir -p out
sed "s/172\\.30\\.0\\./$NET./g" targets.txt > out/targets.txt
sed "s/172\\.30\\.0\\./$NET./g" exclude.txt > out/exclude.txt
sed "s/172\\.30\\.0\\./$NET./g" expected.json > out/expected.json

LAB_CHANGING=v1 $DC up -d --build --wait postgres asi wp drupal admin staging ssh redis camera flap changing redirect legacy || blocked "docker compose up failed"
$ASI migrate

echo "== stage 1"
$ASI $SCAN --name lab-1
$ASI export --format json --out /out/export-1.json
$ASI host edit $NET.10 --add-tag crown-jewel --notes "owned by web team"

echo "== stage 2"
$DC stop flap legacy || blocked "docker compose stop failed"
LAB_CHANGING=v2 $DC up -d --force-recreate --wait changing || blocked "recreating a lab service failed"
$DC --profile stage2 up -d --wait newhost || blocked "starting a lab service failed"
$ASI $SCAN --name lab-2
$ASI diff --from lab-1 --to lab-2 --format json --out /out/diff-1-2.json

echo "== stage 3"
$DC start flap || blocked "docker compose start failed"
sleep 2
$ASI $SCAN --name lab-3
$ASI diff --from lab-2 --to lab-3 --format json --out /out/diff-2-3.json
$ASI export --format json --out /out/export-3.json
$ASI export --format csv --out /out/export-3.csv

python3 check.py out/expected.json out
