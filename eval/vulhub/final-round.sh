#!/usr/bin/env bash
# Final round for one lab: ASI (prebuilt image) + nmap -sV light and default, scored, then the lab is torn down.
# RAW_ROOT=<absolute dir> keeps every raw file outside the repository.
# NMAP_MODES='' skips the nmap baselines (ASI only).
# usage: ASI_IMAGE=asi:vulhub-<commit> ./final-round.sh main|holdout|holdout2 <commit>
set -uo pipefail
cd "$(dirname "$0")"
LAB=$1 COMMIT=$2
case $LAB in
  main) COMPOSE=docker-compose.yml TRUTH=truth.json NET=asi-vulhub_vh PREFIX=172.32.0 OUT=out ;;
  *) COMPOSE=docker-compose.$LAB.yml TRUTH=truth-$LAB.json NET=asi-vulhub-${LAB}_vh PREFIX=${PREFIX:-} OUT=out/$LAB ;;
esac
[ $LAB = holdout ] && PREFIX=172.28.33; [ $LAB = holdout2 ] && PREFIX=172.28.34; [ $LAB = holdout3 ] && PREFIX=172.28.35
if [ -n "${RAW_ROOT:-}" ]; then R=$RAW_ROOT/$COMMIT/$LAB; mkdir -p "$R"; export RAW_DIR=$R; OUT=$R; NAME=asi-score; RABS=$R
else R=../results/vulhub/final-$COMMIT/$LAB; mkdir -p "$R"; NAME="final-$COMMIT/$LAB/asi-score"; RABS=$PWD/$R; fi
LAB=$LAB ./run.sh "$NAME" > "$R/run-asi.log" 2>&1; echo "asi exit=$?" | tee -a "$R/run-asi.log"
cp "$OUT/export.json" "$R/asi-export.json" 2>/dev/null; cp "$OUT/scan-seconds.txt" "$R/asi-scan-seconds.txt" 2>/dev/null; true
P=$(python3 -c 'import json,sys;print(",".join(map(str,sorted({p for s in json.load(open(sys.argv[1]))["services"] for p in s["ports"]}))))' $TRUTH)
for mode in ${NMAP_MODES-light default}; do
  flag=; [ $mode = light ] && flag=--version-light
  T0=$(date +%s)
  docker run --rm --network "$NET" -v "$RABS:/out" instrumentisto/nmap -sT -sV $flag -n -p "$P" $PREFIX.0/24 --exclude $PREFIX.1 -oX /out/nmap-$mode.xml >/dev/null 2>&1
  echo $(( $(date +%s) - T0 )) > "$R/nmap-$mode-seconds.txt"
  python3 score.py --truth $TRUTH --baseline "$R/nmap-$mode.xml" > "$R/nmap-$mode-score.json"
done
[ $LAB = holdout ] && docker logs asi-vulhub-holdout-mosquitto-1 > "$R/mqtt-log-full.txt" 2>&1
docker compose -f $COMPOSE down -v >/dev/null 2>&1
for f in asi ${NMAP_MODES-light default}; do f=${f/#light/nmap-light}; f=${f/#default/nmap-default}; echo "$LAB $f: $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["totals"]["summary"])' "$R/$f-score.json" 2>&1 | tail -1) [$(cat $R/$f-seconds.txt $R/$f-scan-seconds.txt 2>/dev/null)s]"; done
