#!/usr/bin/env bash
# Vulhub lab run: lab up -> build asi -> scan -> export -> score.
# usage: ./run.sh [score-name]              writes ../results/vulhub/<score-name>.json (default asi-score)
#        ASI_IMAGE=<tag> skips the build and scans with that image; scan wall-clock goes to <out>/scan-seconds.txt
#        LAB=holdout|holdout2|holdout3 ./run.sh [score-name]  same for a holdout lab (default <lab>/asi-score)
# The lab stays up afterwards; stop it with: docker compose [-f docker-compose.<lab>.yml] down -v
set -euo pipefail
cd "$(dirname "$0")"

if [ "${LAB:-main}" = holdout ]; then
  COMPOSE=docker-compose.holdout.yml TRUTH=truth-holdout.json SFX=-holdout PREFIX=172.28.33 OUT=out/holdout
  SCORE_NAME=${1:-holdout/asi-score}
elif [ "${LAB:-main}" = holdout2 ]; then
  COMPOSE=docker-compose.holdout2.yml TRUTH=truth-holdout2.json SFX=-holdout2 PREFIX=172.28.34 OUT=out/holdout2
  SCORE_NAME=${1:-holdout2/asi-score}
elif [ "${LAB:-main}" = holdout3 ]; then
  COMPOSE=docker-compose.holdout3.yml TRUTH=truth-holdout3.json SFX=-holdout3 PREFIX=172.28.35 OUT=out/holdout3
  SCORE_NAME=${1:-holdout3/asi-score}
else
  COMPOSE=docker-compose.yml TRUTH=truth.json SFX= PREFIX=172.32.0 OUT=out
  SCORE_NAME=${1:-asi-score}
fi
NET=asi-vulhub${SFX}_vh
# RAW_DIR=<absolute dir> keeps export, timing and score outside the repository (unseen sets).
RES=../results/vulhub
if [ -n "${RAW_DIR:-}" ]; then OUT=$RAW_DIR RES=$RAW_DIR OUT_ABS=$RAW_DIR; else OUT_ABS=$PWD/$OUT; fi
SCANNER=asi-vulhub${SFX}-scanner PG=asi-vulhub${SFX}-postgres
PORTS=$(python3 -c 'import json;print(",".join(map(str,sorted({p for s in json.load(open("'$TRUTH'"))["services"] for p in s["ports"]}))))')
URLS=$(python3 -c 'import json;print(" ".join("%s://%s:%d/"%(k,s["address"],p) for s in json.load(open("'$TRUTH'"))["services"] for k in ("http","https") for p in s.get(k+"_ports",[])))')

[ -d src ] || git clone --depth 1 https://github.com/vulhub/vulhub.git src
docker compose -f $COMPOSE up -d

echo "waiting for web services (up to 5 min)..." >&2
docker run --rm --network "$NET" --entrypoint sh curlimages/curl -c '
  end=$(( $(date +%s) + 300 ))
  for u in '"$URLS"'; do
    until [ "$(curl -sk -o /dev/null -m 10 -w "%{http_code}" "$u")" != 000 ]; do
      [ "$(date +%s)" -lt "$end" ] || { echo "not answering: $u" >&2; exit 1; }
      sleep 5
    done
  done'

IMAGE=${ASI_IMAGE:-asi:vulhub}
[ -n "${ASI_IMAGE:-}" ] || docker build -t "$IMAGE" ../..

mkdir -p "$OUT" "$(dirname "$RES/$SCORE_NAME.json")"
docker rm -f $SCANNER $PG >/dev/null 2>&1 || true
trap "docker rm -f $SCANNER $PG >/dev/null 2>&1 || true" EXIT

docker run -d --name $PG --network "$NET" --ip $PREFIX.3 \
  -e POSTGRES_USER=asi -e POSTGRES_PASSWORD=asi -e POSTGRES_DB=asi postgres:17-alpine >/dev/null
docker run -d --name $SCANNER --network "$NET" --ip $PREFIX.2 --cap-add NET_RAW \
  -e "ASI_DATABASE_URL=postgres://asi:asi@$PREFIX.3:5432/asi?sslmode=disable" \
  -e "ASI_MASTER_KEY=$(printf 'vulhub-only-key-vulhub-only-0001' | base64)" \
  -v "$PWD:/eval:ro" -v "$OUT_ABS:/out" \
  --entrypoint sleep "$IMAGE" infinity >/dev/null

for _ in $(seq 60); do
  docker exec $PG pg_isready -q -h $PREFIX.3 -U asi -d asi && break
  sleep 1
done

docker exec $SCANNER asi migrate
T0=$(date +%s)
docker exec $SCANNER asi scan run --targets-file /eval/targets$SFX.txt --exclude-file /eval/exclude$SFX.txt \
  --ports "$PORTS" --name vulhub$SFX-1 --max-rate 300 --wait
echo $(( $(date +%s) - T0 )) > "$OUT/scan-seconds.txt"
docker exec $SCANNER asi export --format json --out /out/export.json

python3 score.py --truth "$TRUTH" "$OUT/export.json" > "$RES/$SCORE_NAME.json"
python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["totals"]["summary"])' "$RES/$SCORE_NAME.json"
