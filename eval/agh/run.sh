#!/usr/bin/env bash
# Acceptance harness: ASI against the organisers' sample environments (lab-agh/).
# Usage: run.sh <A|B|C|D|E|F|G|H|all|report|down>
# Black box: only the product CLI and its exports. Writes only under eval/agh and eval/results/agh.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
LAB="$REPO/lab-agh"
RUN="${ASI_AGH_RUN:-}"            # optional sub-directory, e.g. run2
RES="$REPO/eval/results/agh${RUN:+/$RUN}"
OUT="/out${RUN:+/$RUN}"         # the same directory inside the asi container
QUICK="${ASI_AGH_QUICK:-0}"      # 1: A without range/top1000, D without the timeout run
IMAGE="${ASI_AGH_IMAGE:-asi:agh}"
SNAP="${ASI_AGH_SNAP:-/tmp/claude-502/aghsnap}"
RATE="${ASI_AGH_RATE:-300}"
SCAN_TIMEOUT="${ASI_AGH_SCAN_TIMEOUT:-1500}"
mkdir -p "$RES" "$HERE/work" "$HERE/stacks"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

# ---------- product ----------
build_image() {
  # Snapshot main into a detached worktree so merges do not disturb the build.
  if [ -n "${ASI_AGH_COMMIT:-}" ] && [ "${ASI_AGH_REBUILD:-0}" = 1 ]; then   # build from `git archive <commit>`
    local src; src=$(mktemp -d /tmp/claude-502/aghsrc.XXXXXX) || exit 1
    git -C "$REPO" archive "$ASI_AGH_COMMIT" | tar -x -C "$src" || exit 1
    git -C "$REPO" rev-parse "$ASI_AGH_COMMIT" > "$HERE/.commit"
    log "building $IMAGE from git archive $(cat "$HERE/.commit")"
    docker build -q -t "$IMAGE" "$src" >/dev/null || exit 1
    rm -rf "$src"
  elif [ "${ASI_AGH_REBUILD:-0}" = 1 ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    git -C "$REPO" worktree remove --force "$SNAP" >/dev/null 2>&1
    git -C "$REPO" worktree add --detach "$SNAP" main >/dev/null || exit 1
    git -C "$SNAP" rev-parse HEAD > "$HERE/.commit"
    log "building $IMAGE from $(cat "$HERE/.commit")"
    docker build -q -t "$IMAGE" "$SNAP" >/dev/null || exit 1
    git -C "$REPO" worktree remove --force "$SNAP"
  fi
  cp "$HERE/.commit" "$RES/commit.txt" 2>/dev/null
}
pc() { docker compose -p asi-agh-prod --env-file "$HERE/prod.env" -f "$HERE/prod-compose.yml" "$@"; }
pexec() { pc exec -T asi "$@"; }
asi() { pexec asi "$@"; }
prod_up() {
  build_image
  [ -f "$HERE/prod.env" ] || echo "ASI_MASTER_KEY=$(head -c 32 /dev/urandom | base64)" > "$HERE/prod.env"
  pc up -d >/dev/null 2>&1 || { log "product project failed to start"; exit 1; }
  echo host.docker.internal > "$HERE/work/targets.txt"
}
fresh_db() {
  pc exec -T postgres psql -q -U asi -d postgres -c 'DROP DATABASE IF EXISTS asi WITH (FORCE)' -c 'CREATE DATABASE asi' >/dev/null
  asi migrate >/dev/null || { log "migrate failed"; exit 1; }
}

# ---------- target stacks ----------
port_taken() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
sc() { # stack compose: sc <stack> [--env-file F] args...
  local s=$1; shift
  local envf="$HERE/stacks/$s.env"
  docker compose -p "asi-agh-$s" --project-directory "$LAB" --env-file "$envf" -f "$HERE/stacks/$s.yml" "$@"
}
stack_prepare() { # generate eval/agh/stacks/<stack>.yml, remapping taken host ports by +20000
  local s=$1 src="$LAB/docker-compose-$1.yml" out="$HERE/stacks/$1.yml" map="$RES/portmap-$1.tsv"
  [ -f "$HERE/stacks/$s.env" ] || : > "$HERE/stacks/$s.env"
  [ -f "$out" ] && sc "$s" down -v --remove-orphans >/dev/null 2>&1
  cp "$src" "$out"; : > "$map"
  local waited=0 spec lo hi p busy
  for spec in $(grep -oE '127\.0\.0\.1:[0-9]+(-[0-9]+)?:' "$src" | cut -d: -f2); do
    lo=${spec%-*}; hi=${spec#*-}
    while :; do
      busy=""; for p in $(seq "$lo" "$hi"); do port_taken "$p" && busy=$p && break; done
      [ -z "$busy" ] && break
      [ "$waited" -ge 180 ] && break
      [ "$waited" = 0 ] && log "host port $busy is taken; waiting up to 180 s"
      sleep 10; waited=$((waited+10))
    done
    if [ -n "$busy" ]; then
      local nlo=$((lo+20000)) nhi=$((hi+20000)) nspec
      nspec=$nlo; [ "$lo" != "$hi" ] && nspec="$nlo-$nhi"
      sed -i '' "s/127\.0\.0\.1:$spec:/127.0.0.1:$nspec:/" "$out"
      log "remapped host port $spec -> $nspec (taken by: $(lsof -nP -iTCP:"$busy" -sTCP:LISTEN | tail -1 | awk '{print $1}'))"
      for p in $(seq "$lo" "$hi"); do printf '%s\t%s\n' "$p" "$((p+20000))" >> "$map"; done
    else
      for p in $(seq "$lo" "$hi"); do printf '%s\t%s\n' "$p" "$p" >> "$map"; done
    fi
  done
  # safety: every published port must be bound to 127.0.0.1
  if grep -A12 -E '^\s+ports:' "$out" | grep -E '^\s+- "' | grep -vq '"127\.0\.0\.1:'; then
    log "refusing: $out publishes a port not bound to 127.0.0.1"; exit 1
  fi
}
P() { awk -v p="$2" '$1==p{print $2}' "$RES/portmap-$1.tsv"; }           # actual host port
plist() { local s=$1 out="" p; shift; for p in "$@"; do out="$out,$(P "$s" "$p")"; done; echo "${out#,}"; }
wait_tcp() { local p i; for p in "$@"; do for i in $(seq 1 120); do (exec 3<>/dev/tcp/127.0.0.1/"$p") 2>/dev/null && break; sleep 1; done; done; }
wait_http() { # wait until the port answers HTTP(S) with a non-5xx status (GET only)
  local p=$1 scheme=${2:-http} i code
  for i in $(seq 1 90); do
    code=$(curl -ksS -o /dev/null -m 5 -w '%{http_code}' "$scheme://127.0.0.1:$p/" 2>/dev/null)
    case "$code" in 000|5*) sleep 2;; *) return 0;; esac
  done
  log "port $p never answered HTTP (last $code)"
}
remap_port() { # remap_port <stack> <host port>: move one published port to +20000 in the generated file
  local s=$1 p=$2
  sed -i '' "s/127\.0\.0\.1:$p:/127.0.0.1:$((p+20000)):/" "$HERE/stacks/$s.yml"
  awk -v p="$p" 'BEGIN{OFS="\t"} $1==p{$2=p+20000} {print}' "$RES/portmap-$s.tsv" > "$RES/portmap-$s.tsv.new" && mv "$RES/portmap-$s.tsv.new" "$RES/portmap-$s.tsv"
  log "remapped host port $p -> $((p+20000)) after a bind failure"
}
stack_up() { # stack_up <stack> [compose up args]; a port grabbed by someone else between the check and the bind is remapped
  local s=$1 out p i; shift
  for i in 1 2 3 4 5 6; do
    out=$(sc "$s" up -d "$@" 2>&1) && return 0
    p=$(echo "$out" | grep -oE '127\.0\.0\.1:[0-9]+ failed|0\.0\.0\.0:[0-9]+ failed|:[0-9]+: bind: address already in use' | grep -oE '[0-9]+( failed|: bind)' | grep -oE '[0-9]+' | head -1)
    [ -n "$p" ] || { log "stack $s failed to start: $(echo "$out" | tail -2)"; return 1; }
    remap_port "$s" "$p"
  done
  return 1
}
stack_down() { [ -f "$HERE/stacks/$1.yml" ] && sc "$1" down -v --remove-orphans >/dev/null 2>&1; }

# ---------- target-side logs (request counting, safety) ----------
FILELOGS="vulnerable:dvwa:/var/log/apache2/access.log modern:nginx-proxy-manager:/data/logs/*access.log"
mark_logs() { # remember line counts of access logs that live in files
  local s=$1 e svc glob cid
  for e in $FILELOGS; do
    [ "${e%%:*}" = "$s" ] || continue
    svc=$(echo "$e" | cut -d: -f2); glob=$(echo "$e" | cut -d: -f3)
    cid=$(sc "$s" ps -q "$svc" 2>/dev/null); [ -n "$cid" ] || continue
    docker exec "$cid" sh -c "for f in $glob; do [ -f \"\$f\" ] && echo \"\$f \$(wc -l < \"\$f\")\"; done" > "$HERE/work/marks-$svc.txt" 2>/dev/null
  done
}
collect_logs() { # collect_logs <scenario> <scan> <stack> <since-iso>
  local dir="$RES/$1/logs/$2" s=$3 since=$4 svc cid e glob
  mkdir -p "$dir"
  for svc in $(sc "$s" ps --services 2>/dev/null); do
    cid=$(sc "$s" ps -q "$svc"); [ -n "$cid" ] || continue
    docker logs --since "$since" "$cid" > "$dir/$svc.log" 2>&1
  done
  for e in $FILELOGS; do
    [ "${e%%:*}" = "$s" ] || continue
    svc=$(echo "$e" | cut -d: -f2); glob=$(echo "$e" | cut -d: -f3)
    cid=$(sc "$s" ps -q "$svc" 2>/dev/null); [ -n "$cid" ] || continue
    for f in $(docker exec "$cid" sh -c "ls $glob 2>/dev/null"); do
      n=$(awk -v f="$f" '$1==f{print $2}' "$HERE/work/marks-$svc.txt" 2>/dev/null); n=${n:-0}
      docker exec "$cid" tail -n "+$((n+1))" "$f"
    done > "$dir/$svc.file.log" 2>/dev/null
  done
}

# ---------- scanning ----------
scan() { # scan <scenario> <stack> <name> <ports> [extra scan-run flags]
  local scn=$1 s=$2 name=$3 ports=$4; shift 4
  mkdir -p "$RES/$scn"
  local cmd="asi scan run --targets-file /work/targets.txt --ports $ports --name $name --max-rate $RATE $* --wait"
  mark_logs "$s"; sleep 1
  local iso t0 t1 rc; iso=$(date -u +%Y-%m-%dT%H:%M:%SZ); t0=$(date +%s)
  log "$scn: $cmd"
  { echo "\$ docker compose -p asi-agh-prod exec -T asi $cmd"; pexec timeout "$SCAN_TIMEOUT" $cmd; rc=$?; echo "exit=$rc"; } > "$RES/$scn/$name.scan.log" 2>&1
  t1=$(date +%s)
  asi scan show "$name" >> "$RES/$scn/$name.scan.log" 2>&1
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$((t1-t0))" "$rc" "$ports" "$cmd" >> "$RES/$scn/scans.tsv"
  asi export --format json --run "$name" --out "$OUT/$scn/$name.json" >> "$RES/$scn/$name.scan.log" 2>&1
  collect_logs "$scn" "$name" "$s" "$iso"
  log "$scn: $name finished in $((t1-t0)) s (exit $rc)"
}
diff_runs() { # diff_runs <scenario> <from> <to>
  { echo "\$ asi diff --from $2 --to $3 --format json --out $OUT/$1/diff-$2-$3.json"
    asi diff --from "$2" --to "$3" --format json --out "$OUT/$1/diff-$2-$3.json"; echo "exit=$?"; } > "$RES/$1/diff-$2-$3.log" 2>&1
}
nmap_base() { # nmap_base <scenario> <ports>: plain nmap on the same target and ports, light and default version detection
  local scn=$1 ports=$2 mode flag t0
  : > "$RES/$scn/nmap.tsv"
  for mode in light default; do
    flag=""; [ "$mode" = light ] && flag="--version-light"
    t0=$(date +%s)
    pexec timeout 900 nmap -Pn -sT -sV $flag -p "$ports" -oX - host.docker.internal > "$RES/$scn/nmap-$mode.xml" 2> "$RES/$scn/nmap-$mode.err"
    printf '%s\t%s\t%s\n' "$mode" "$(( $(date +%s) - t0 ))" "nmap -Pn -sT -sV $flag -p $ports host.docker.internal" >> "$RES/$scn/nmap.tsv"
    log "$scn: nmap $mode finished in $(( $(date +%s) - t0 )) s"
  done
}
twice() { # twice <scenario> <stack> <run> <ports>: a second scan of the unchanged stack, diff, then the nmap baseline
  scan "$1" "$2" "$3b" "$4"; diff_runs "$1" "$3" "$3b"; nmap_base "$1" "$4"
}
begin() { rm -rf "${RES:?}/$1"; mkdir -p "$RES/$1"; prod_up; fresh_db; log "=== scenario $1 ==="; }

QS="2223 3001 5673 8787 15673"

scenario_A() {
  begin A; stack_prepare custom-network
  stack_up custom-network flask-app gitea rabbitmq || return 1
  wait_tcp $(plist custom-network $QS | tr , ' '); wait_http "$(P custom-network 3001)"; wait_http "$(P custom-network 15673)"
  local ports; ports=$(plist custom-network $QS)
  scan A custom-network a1 "$ports"
  sc custom-network stop flask-app >/dev/null 2>&1
  scan A custom-network a2 "$ports"
  sc custom-network start flask-app >/dev/null 2>&1; wait_http "$(P custom-network 8787)"
  scan A custom-network a3 "$ports"
  diff_runs A a1 a2; diff_runs A a2 a3
  [ "$QUICK" = 1 ] && { stack_down custom-network; return 0; }
  # port list syntax: a range and a preset, each from a fresh database
  fresh_db
  if [ -s "$RES/portmap-custom-network.tsv" ] && ! awk '$1!=$2{f=1}END{exit !f}' "$RES/portmap-custom-network.tsv"; then
    scan A custom-network a-range "2223,3001,5673,8000-9000,15673"
  else
    scan A custom-network a-range "$(plist custom-network 2223 3001 5673),$(( $(P custom-network 8787) - 787 ))-$(( $(P custom-network 8787) + 213 )),$(P custom-network 15673)"
  fi
  fresh_db
  scan A custom-network a-top1000 top1000
  stack_down custom-network
}

BPORTS="2223 3001 5673 8787 8888 15432 15673"
scenario_B() {
  begin B; stack_prepare custom-network
  stack_up custom-network || return 1
  wait_tcp $(plist custom-network $BPORTS | tr , ' ')
  for p in 3001 15673 8888 8787; do wait_http "$(P custom-network $p)"; done; sleep 5
  scan B custom-network b1 "$(plist custom-network $BPORTS)"
  asi export --format csv --run b1 --out $OUT/B/b1.csv > "$RES/B/export-csv.log" 2>&1
  twice B custom-network b1 "$(plist custom-network $BPORTS)"
  stack_down custom-network
}

CPORTS="80 81 443 6379 8080 8081"
scenario_C() {
  begin C; stack_prepare modern
  stack_up modern || return 1
  wait_tcp $(plist modern $CPORTS | tr , ' ')
  wait_http "$(P modern 8080)"; wait_http "$(P modern 8081)"; wait_http "$(P modern 81)"; sleep 5
  scan C modern c1 "$(plist modern $CPORTS)"
  twice C modern c1 "$(plist modern $CPORTS)"
  { echo "\$ curl -ksv https://127.0.0.1:$(P modern 443)/"; curl -ksv -o /dev/null -m 8 "https://127.0.0.1:$(P modern 443)/" 2>&1 | grep -iE 'alert|handshake|subject:|issuer:|HTTP/' | head -6; echo "exit=${PIPESTATUS[0]}"; } > "$RES/C/truth-443.txt" 2>&1
  stack_down modern
}

DPORTS="8085 8086 8474"
d_env() { cp "$LAB/.env.example" "$HERE/stacks/modern-proxy.env"; local kv; for kv in "$@"; do sed -i '' "s/^${kv%%=*}=.*/$kv/" "$HERE/stacks/modern-proxy.env"; done; cp "$HERE/stacks/modern-proxy.env" "$RES/D/env-$DRUN"; }
d_up() {
  stack_up modern-proxy --force-recreate || return 1
  wait_tcp $(plist modern-proxy $DPORTS | tr , ' ')
  local i; for i in $(seq 1 60); do [ "$(docker inspect -f '{{.State.Status}}' "$(sc modern-proxy ps -aq toxiproxy-init)" 2>/dev/null)" = exited ] && break; sleep 2; done
  curl -s -m 5 "http://127.0.0.1:$(P modern-proxy 8474)/proxies" > "$RES/D/toxiproxy-$DRUN.json"
}
scenario_D() {
  begin D
  cp "$LAB/.env.example" "$HERE/stacks/modern-proxy.env"; stack_prepare modern-proxy
  local ports; ports=$(plist modern-proxy $DPORTS)
  DRUN=d1; d_env; d_up; wait_http "$(P modern-proxy 8085)"; sleep 5
  scan D modern-proxy d1 "$ports"
  twice D modern-proxy d1 "$ports"   # unchanged stack scanned twice: the diff must be empty
  { local p86; p86=$(P modern-proxy 8086)   # ground truth for the plain-HTTP Traefik port (GET only)
    echo "\$ curl -si http://127.0.0.1:$p86/ | head -2"; curl -si -m 5 "http://127.0.0.1:$p86/" | head -2
    echo "\$ curl -s http://127.0.0.1:$p86/dashboard/ | grep -o '<title>.*</title>'"; curl -s -m 5 "http://127.0.0.1:$p86/dashboard/" | grep -o '<title>.*</title>'
    echo "\$ curl -ski https://127.0.0.1:$p86/ | head -1"; curl -ski -m 5 "https://127.0.0.1:$p86/" | head -1
    echo "\$ curl -s http://127.0.0.1:$p86/api/version"; curl -s -m 5 "http://127.0.0.1:$p86/api/version"; echo
    echo "\$ curl -s http://127.0.0.1:$(P modern-proxy 8474)/version"; curl -s -m 5 "http://127.0.0.1:$(P modern-proxy 8474)/version"; echo
  } > "$RES/D/truth.txt" 2>&1
  DRUN=d2; d_env ENABLE_LATENCY=true LATENCY_MS=500 LATENCY_JITTER=0; d_up; sleep 5
  scan D modern-proxy d2 "$ports"
  [ "$QUICK" = 1 ] && { diff_runs D d1 d2; stack_down modern-proxy; return 0; }
  DRUN=d3; d_env ENABLE_TIMEOUT=true TIMEOUT_MS=1000; d_up; sleep 5
  scan D modern-proxy d3 "$ports"
  diff_runs D d1 d2; diff_runs D d1 d3
  stack_down modern-proxy
}

EPORTS="21 8088 8089 8090"
scenario_E() {
  begin E; stack_prepare vulnerable
  trap 'stack_down vulnerable' EXIT
  stack_up vulnerable || return 1
  wait_tcp $(plist vulnerable $EPORTS | tr , ' ')
  for p in 8088 8089 8090; do wait_http "$(P vulnerable $p)"; done; sleep 5
  local eports; eports="$(plist vulnerable $EPORTS),$(P vulnerable 21000)-$(P vulnerable 21010)"
  sleep 5
  if [ "$(docker inspect -f '{{.State.Running}}' "$(sc vulnerable ps -aq ftp)" 2>/dev/null)" != true ]; then
    { echo "ftp container (fauria/vsftpd) is not running; port 21 and the passive range are skipped"; docker logs --tail 5 "$(sc vulnerable ps -aq ftp)"; } > "$RES/E/ftp-skipped.txt" 2>&1
    log "E: ftp container is not running, skipping port 21"; eports="$(plist vulnerable 8088 8089 8090)"
  fi
  scan E vulnerable e1 "$eports"
  twice E vulnerable e1 "$eports"
  stack_down vulnerable; trap - EXIT
}

scenario_F() {
  begin F; stack_prepare custom-network
  rm -rf "$HERE/work/signatures"; mkdir -p "$HERE/work/signatures"; cp "$HERE/signatures/"*.yaml "$HERE/work/signatures/"
  cp "$HERE/signatures/"*.yaml "$RES/F/"
  stack_up custom-network flask-app gitea rabbitmq || return 1
  wait_tcp $(plist custom-network $QS | tr , ' '); wait_http "$(P custom-network 3001)"; wait_http "$(P custom-network 15673)"
  local ports; ports=$(plist custom-network $QS)
  scan F custom-network f0 "$ports"
  scan F custom-network f1 "$ports" --signatures-dir /work/signatures
  diff_runs F f0 f1
  # a signature that breaks the safety rules must be rejected
  mkdir -p "$HERE/work/badsig"; cat > "$HERE/work/badsig/bad.yaml" <<'EOF'
- id: agh-bad-post
  name: Unsafe signature (must be rejected)
  kind: custom
  confidence: 50
  request: { method: POST, path: /login }
  match:
    all: [ { type: status, value: 200 } ]
EOF
  { echo "\$ asi scan run ... --name f-bad --signatures-dir /work/badsig --wait"
    asi scan run --targets-file /work/targets.txt --ports "$ports" --name f-bad --max-rate "$RATE" --signatures-dir /work/badsig --wait; echo "exit=$?"; } > "$RES/F/f-bad.scan.log" 2>&1
  stack_down custom-network
}

scenario_G() {
  [ -f "$RES/B/b1.json" ] || scenario_B
  begin G
  cp "$RES/B/b1.json" "$RES/G/source.json"; cp "$RES/B/b1.csv" "$RES/G/source.csv" 2>/dev/null
  { echo "\$ asi import --format json --file $OUT/G/source.json"; asi import --format json --file $OUT/G/source.json; echo "exit=$?"; } > "$RES/G/import.log" 2>&1
  asi export --format json --out $OUT/G/reexport.json >> "$RES/G/import.log" 2>&1
  asi export --format csv --out $OUT/G/reexport.csv >> "$RES/G/import.log" 2>&1
  # CSV round trip into another fresh database
  fresh_db
  { echo "\$ asi import --format csv --file $OUT/G/source.csv"; asi import --format csv --file $OUT/G/source.csv; echo "exit=$?"; } > "$RES/G/import-csv.log" 2>&1
  asi export --format json --out $OUT/G/reexport-from-csv.json >> "$RES/G/import-csv.log" 2>&1
}

scenario_H() { # recheck mode after a full scan
  begin H; stack_prepare custom-network
  stack_up custom-network || return 1
  wait_tcp $(plist custom-network $BPORTS | tr , ' ')
  for p in 3001 15673 8888 8787; do wait_http "$(P custom-network $p)"; done; sleep 5
  local ports; ports=$(plist custom-network $BPORTS)
  scan H custom-network h1 "$ports"
  scan H custom-network h2 "$ports" --mode recheck
  diff_runs H h1 h2
  sc custom-network stop flask-app >/dev/null 2>&1
  scan H custom-network h3 "$ports" --mode recheck
  diff_runs H h2 h3
  stack_down custom-network
}

report() { python3 "$HERE/analyze.py" "$RES"; }
teardown() {
  local s; for s in custom-network modern modern-proxy vulnerable; do stack_down "$s"; done
  [ -f "$HERE/prod.env" ] && pc down -v >/dev/null 2>&1
  git -C "$REPO" worktree remove --force "$SNAP" >/dev/null 2>&1
  return 0
}

case "${1:-}" in
  A|B|C|D|E|F|G|H) "scenario_$1"; report ;;
  all) for x in A B D C E F G H; do "scenario_$x"; done; report; teardown ;;
  report) report ;;
  down) teardown ;;
  *) echo "usage: $0 <A|B|C|D|E|F|G|H|all|report|down>" >&2; exit 2 ;;
esac
