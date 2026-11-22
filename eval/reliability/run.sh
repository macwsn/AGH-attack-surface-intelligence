#!/usr/bin/env bash
# Reliability (fault-injection) harness for ASI, black box through the CLI (docs/contracts.md).
# usage: [RUN=run2] run.sh <scenario>|all|up|down      scenarios: see SCENARIOS below
# Every scenario starts from a clean database, prints PASS/FAIL with a one-line reason and writes its evidence to
# ../results/reliability/<scenario>/ (commands.log = every command with output and exit code, result.json = verdict).
# KEEP=1 leaves the compose project running afterwards.
set -uo pipefail
cd "$(dirname "$0")"
SCENARIOS="kill-resume db-restart hostile-http bad-input repeat-stability host-vanishes concurrent-runs key-rotation-and-wrong-key port-flap sigterm-pause recheck-mode"
mkdir -p ../results/reliability/_lab/bignet ../results/reliability/_lab/hostile ../results/reliability/_lab/vanish
BASE="$(cd ../results/reliability && pwd)"
RES="$BASE${RUN:+/$RUN}"; O="/out${RUN:+/$RUN}"; mkdir -p "$RES"   # RUN=run2 puts everything under run2/
COMMIT="$(cat PRODUCT_COMMIT 2>/dev/null || echo unknown)"
DC="docker compose -p asi-rel -f docker-compose.yml"
PGPASS="asi-rel"
KEY="cmVsLW9ubHkta2V5LXJlbC1vbmx5LWtleS1yZWwtMDE="
KEY2="b3RoZXIta2V5LW90aGVyLWtleS1vdGhlci1rZXktMDI="   # another valid 32-byte key
PORTS="22,80,443,6379,8000,8080"
BIG="--targets-file /rel/targets-big.txt --exclude-file /rel/exclude.txt --ports $PORTS --max-rate 20 --workers 2 --wait"
SMALL="--targets-file /rel/targets-small.txt --ports $PORTS --max-rate 300 --wait"
DB=asi; SC=; EV=

dburl() { echo "postgres://asi:${2:-$PGPASS}@172.29.0.3:5432/$1?sslmode=disable"; }
# asi <args>: the product CLI against database $DB, optional overrides ASI_KEY / ASI_URL, TMO = timeout in seconds
asi() { $DC exec -T -e ASI_DATABASE_URL="${ASI_URL:-$(dburl "$DB")}" -e ASI_MASTER_KEY="${ASI_KEY-$KEY}" asi timeout -s KILL "${TMO:-900}" asi "$@"; }
psql() { $DC exec -T postgres psql -U asi -d "${1}" -At -F, -c "$2"; }
now() { python3 -c 'import time; print(time.time())'; }
since() { python3 -c "import time,sys; print(round(time.time()-float(sys.argv[1]),1))" "$1"; }

# rec <label> <cmd...>: run, keep stdout/stderr/exit code as files and in commands.log
rec() {
  local label=$1 rc; shift
  echo "\$ $*  [db=$DB]" >> "$EV/commands.log"
  "$@" > "$EV/$label.out" 2> "$EV/$label.err"; rc=$?
  { head -c 3000 "$EV/$label.out" | sed 's/^/  out: /'; head -c 3000 "$EV/$label.err" | sed 's/^/  err: /'; echo "  exit: $rc"; } >> "$EV/commands.log"
  echo "$rc" > "$EV/$label.rc"
  return $rc
}
rc() { cat "$EV/$1.rc" 2>/dev/null || echo none; }
note() { echo "# $*" >> "$EV/commands.log"; }

fresh_db() { # fresh_db <name>: empty database with the schema applied
  DB=$1
  $DC exec -T postgres psql -U asi -d postgres -q -c "DROP DATABASE IF EXISTS $DB WITH (FORCE)" -c "CREATE DATABASE $DB" >/dev/null 2>&1
  asi migrate >/dev/null || echo "migrate failed on $DB" >&2
}
begin() { SC=$1; EV="$RES/$SC"; rm -rf "$EV"; mkdir -p "$EV"; echo "== $SC"; note "product commit $COMMIT"; }
finish() { # finish <PASS|FAIL> <reason> <property> [measured-json]
  python3 - "$EV/result.json" "$1" "$2" "$3" "${4:-{\}}" <<'EOF'
import json, sys
path, status, reason, prop, measured = sys.argv[1:6]
try:
    measured = json.loads(measured)
except ValueError:
    measured = {"raw": measured}
json.dump({"status": status, "reason": reason, "property": prop, "measured": measured}, open(path, "w"), indent=1)
EOF
  echo "$1 $SC: $2"
}
nmap_procs() { $DC exec -T asi ps -o pid,ppid,stat,args | grep -c ' nmap ' || true; }   # running nmap (any state)
show_field() { sed -n "1s/.* $2=\([^ ]*\).*/\1/p" "$EV/$1.out"; }
wait_not_running() { # wait_not_running <run>: until scan show stops saying status=running (max 120 s); prints seconds waited
  local t0 i st; t0=$(now)
  for i in $(seq 60); do
    st=$(asi scan show "$1" 2>/dev/null | sed -n '1s/.* status=\([^ ]*\).*/\1/p'); [ "$st" != running ] && break; sleep 2
  done; since "$t0"; }
wait_idle() { # wait until no nmap is left in the product container (max 60 s); prints what is left
  local i; for i in $(seq 30); do [ "$(nmap_procs)" = 0 ] && break; sleep 2; done; nmap_procs; }

baseline() { # uninterrupted run of the BIG target set in its own database; export kept in _baseline/
  [ -s "$RES/_baseline/export.json" ] && return 0
  local keep_ev=$EV keep_db=$DB t0
  EV="$RES/_baseline"; rm -rf "$EV"; mkdir -p "$EV"; fresh_db rel_base; t0=$(now)
  rec scan asi scan run $BIG --name base
  since "$t0" > "$EV/seconds"
  rec show asi scan show base
  rec export asi export --format json --out $O/_baseline/export.json
  EV=$keep_ev; DB=$keep_db
  [ -s "$RES/_baseline/export.json" ]
}

# ---------------------------------------------------------------------------------------------------------------
kill-resume() {
  local prop="after kill -9 and 'scan resume' the export equals the export of an uninterrupted run (same hosts, same services, no duplicates)"
  begin kill-resume
  baseline || { finish FAIL "baseline run failed, see _baseline/" "$prop"; return; }
  fresh_db rel_kill
  local t0 i done=0 killed_at
  t0=$(now)
  ( rec scan asi scan run $BIG --name kr ) &
  for i in $(seq 40); do   # kill 15 s after the first group is done (or after 95 s)
    sleep 2
    asi scan show kr > "$EV/poll.out" 2>/dev/null || continue
    done=$(sed -n '1s/.* groups_done=\([0-9]*\)\/.*/\1/p' "$EV/poll.out")
    [ "${done:-0}" -ge 1 ] && break
  done
  sleep 15
  asi scan show kr > "$EV/show-before-kill.out" 2>/dev/null
  killed_at=$(since "$t0")
  note "kill -9 after ${killed_at}s, groups_done=$done"
  rec kill $DC exec -T asi pkill -9 -f "asi scan run"
  wait
  rec ps-after-kill $DC exec -T asi ps -o pid,ppid,stat,args
  local orphans; orphans=$(grep -c ' nmap ' "$EV/ps-after-kill.out" || true)
  rec show-after-kill asi scan show kr
  local status_after; status_after=$(show_field show-after-kill status)
  sleep 2; rec ps-2s-after-kill $DC exec -T asi ps -o pid,ppid,stat,args
  rec resume-right-after-kill asi scan resume kr
  local stalled_after; stalled_after=$(wait_not_running kr)
  rec show-when-not-running asi scan show kr
  local left; left=$(wait_idle)
  rec resume asi scan resume kr
  local resume_rc; resume_rc=$(rc resume)
  rec show-after-resume asi scan show kr
  rec export asi export --format json --out $O/kill-resume/export.json
  rec compare python3 check.py cmp "$RES/_baseline/export.json" "$EV/export.json"
  local cmp_rc; cmp_rc=$(rc compare)
  local m="{\"baseline_seconds\": $(cat "$RES/_baseline/seconds"), \"killed_after_seconds\": $killed_at, \"groups_done_at_kill\": ${done:-0}, \"scan_exit_after_kill\": \"$(rc scan)\", \"status_shown_after_kill\": \"$status_after\", \"orphan_nmap_after_kill\": $orphans, \"nmap_2s_after_kill\": $(grep -c ' nmap ' "$EV/ps-2s-after-kill.out" || true), \"resume_right_after_kill_exit\": \"$(rc resume-right-after-kill)\", \"seconds_until_not_shown_running\": $stalled_after, \"status_then\": \"$(show_field show-when-not-running status)\", \"nmap_left_before_resume\": $left, \"resume_exit\": \"$resume_rc\", \"compare\": $(cat "$EV/compare.out" 2>/dev/null || echo null)}"
  if [ "$resume_rc" != 0 ]; then finish FAIL "scan resume exited $resume_rc: $(head -c 200 "$EV/resume.err")" "$prop" "$m"
  elif [ "$cmp_rc" != 0 ]; then finish FAIL "export after resume differs from the uninterrupted run (see compare.out)" "$prop" "$m"
  else finish PASS "resumed run equals the uninterrupted one; scan show said status=$status_after after the kill; $orphans orphan nmap" "$prop" "$m"; fi
}

db_fault() { # db_fault <variant> <fault command...>: run BIG, inject the fault after 25 s, resume if needed, compare
  local v=$1; shift
  fresh_db "rel_db_$v"
  local t0; t0=$(now)
  ( rec "$v-scan" asi scan run $BIG --name "db-$v" ) &
  sleep 25
  asi scan show "db-$v" > "$EV/$v-show-before-fault.out" 2>&1
  note "$v: fault after $(since "$t0")s: $*"
  "$@" >> "$EV/commands.log" 2>&1
  wait
  note "$v: scan returned after $(since "$t0")s"
  $DC up -d --wait postgres >/dev/null 2>&1
  rec "$v-show-after" asi scan show "db-$v"
  local st scan_rc resumed=no; st=$(show_field "$v-show-after" status); scan_rc=$(rc "$v-scan")
  if [ "$scan_rc" != 0 ]; then
    resumed=yes; wait_idle >/dev/null; wait_not_running "db-$v" >/dev/null
    rec "$v-show-before-resume" asi scan show "db-$v"
    rec "$v-resume" asi scan resume "db-$v"
    rec "$v-show-after-resume" asi scan show "db-$v"
  fi
  rec "$v-export" asi export --format json --out "$O/db-restart/$v-export.json"
  rec "$v-compare" python3 check.py cmp "$RES/_baseline/export.json" "$EV/$v-export.json"
  rec "$v-clean" python3 check.py clean "$EV/$v-scan.err" "$EV/$v-scan.out" "$EV/$v-resume.err" "$EV/$v-resume.out"
  local verdict=ok why=""
  [ "$(rc "$v-clean")" = 0 ] || { verdict=bad; why="stack trace in output"; }
  [ "$(rc "$v-compare")" = 0 ] || { verdict=bad; why="$why export differs from uninterrupted run"; }
  if [ "$resumed" = yes ]; then
    [ "$(rc "$v-resume")" = 0 ] || { verdict=bad; why="$why resume exited $(rc "$v-resume")"; }
    [ "$(python3 -c "import sys; print(len([l for l in open(sys.argv[1]) if l.strip()]))" "$EV/$v-scan.err")" -le 2 ] || { verdict=bad; why="$why error is not a short message"; }
    st="$st -> $(show_field "$v-show-before-resume" status)"
  fi
  echo "{\"variant\": \"$v\", \"verdict\": \"$verdict\", \"why\": \"$why\", \"scan_exit\": \"$scan_rc\", \"status_after_fault\": \"$st\", \"needed_resume\": \"$resumed\", \"resume_exit\": \"$(rc "$v-resume")\", \"scan_stderr\": $(head -c 300 "$EV/$v-scan.err" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'), \"compare\": $(cat "$EV/$v-compare.out" 2>/dev/null || echo null)}" > "$EV/$v-verdict.json"
}
db-restart() {
  local prop="a Postgres restart (and a 20 s outage) mid-scan: the scan completes correctly or ends in a clearly reported, resumable state; after resume the export equals the uninterrupted one; no panic"
  begin db-restart
  baseline || { finish FAIL "baseline run failed, see _baseline/" "$prop"; return; }
  db_fault restart $DC restart postgres
  db_fault outage bash -c "$DC stop postgres; sleep 20; $DC start postgres"
  local m="{\"restart\": $(cat "$EV/restart-verdict.json"), \"outage\": $(cat "$EV/outage-verdict.json")}"
  if grep -q '"verdict": "bad"' "$EV"/*-verdict.json; then
    finish FAIL "$(python3 -c "import json,sys; print('; '.join(f\"{d['variant']}: {d['why'].strip() or 'ok'} (scan exit {d['scan_exit']}, status {d['status_after_fault']})\" for d in map(lambda p: json.load(open(p)), sys.argv[1:])))" "$EV/restart-verdict.json" "$EV/outage-verdict.json")" "$prop" "$m"
  else finish PASS "both variants ended equal to the uninterrupted run (restart: scan exit $(rc restart-scan), outage: scan exit $(rc outage-scan))" "$prop" "$m"; fi
}

host-vanishes() {
  local prop="a host that answers discovery and nmap but is gone before the HTTP probe: the run completes and the host produces no service_changed entry in the diffs around that run"
  begin host-vanishes
  fresh_db rel_vanish
  local S="--targets-file /rel/targets-vanish.txt --ports 80 --max-rate 300 --wait"
  $DC up -d --wait vanish >/dev/null 2>&1; : > "$BASE/_lab/vanish/requests.log"
  rec v0-scan asi scan run $S --name v0
  rec v0-export asi export --format json --out $O/host-vanishes/v0.json
  $DC exec -T vanish touch /tmp/armed; note "armed: the target exits right after answering nmap's service probe"
  TMO=600 rec v1-scan asi scan run $S --name v1
  rec v1-export asi export --format json --out $O/host-vanishes/v1.json
  local state; state=$(docker inspect -f '{{.State.Status}}' asi-rel-vanish-1)
  cp "$BASE/_lab/vanish/requests.log" "$EV/target-requests.log"
  local probed_after_exit; probed_after_exit=$(python3 - "$EV/target-requests.log" <<'EOF'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
i = max((n for n, r in enumerate(rows) if r.get("armed")), default=-1)
print(len([r for r in rows[i + 1:] if "request" in r]))
EOF
)
  note "target container state after v1: $state; requests served after the armed one: $probed_after_exit"
  $DC start vanish >/dev/null 2>&1; sleep 2
  rec v2-scan asi scan run $S --name v2
  rec v2-export asi export --format json --out $O/host-vanishes/v2.json
  rec diff-v0-v1 asi diff --from v0 --to v1 --format json --out $O/host-vanishes/diff-v0-v1.json
  rec diff-v1-v2 asi diff --from v1 --to v2 --format json --out $O/host-vanishes/diff-v1-v2.json
  local summary; summary=$(python3 - "$EV" <<'EOF'
import json, sys
ev = sys.argv[1]
out = {}
for d in ("diff-v0-v1", "diff-v1-v2"):
    try:
        ch = [c for c in json.load(open(f"{ev}/{d}.json"))["changes"]]
    except Exception as e:
        out[d] = f"unreadable: {e}"; continue
    out[d] = [c for c in ch if c.get("address") == "172.29.0.50"]
    out[d + "_other_hosts"] = len(ch) - len(out[d])
try:
    h = [h for h in json.load(open(f"{ev}/v1.json"))["hosts"] if h["address"] == "172.29.0.50"]
    out["v1_record"] = [{"status": x["status"], "services": [{k: s.get(k) for k in ("port", "state", "status", "service", "product", "http")} for s in x.get("services") or []]} for x in h]
except Exception as e:
    out["v1_record"] = f"unreadable: {e}"
out["service_changed"] = sum(1 for d in ("diff-v0-v1", "diff-v1-v2") if isinstance(out[d], list) for c in out[d] if c["type"] == "service_changed")
print(json.dumps(out))
EOF
)
  local changed; changed=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['service_changed'])" "$summary")
  local m="{\"window_hit\": \"$([ "$state" = exited ] && [ "$probed_after_exit" = 0 ] && echo yes || echo no)\", \"target_state_after_v1\": \"$state\", \"v1_exit\": \"$(rc v1-scan)\", \"detail\": $summary}"
  if [ "$state" != exited ] || [ "$probed_after_exit" != 0 ]; then finish FAIL "could not hit the window (target state $state, $probed_after_exit requests after arming)" "$prop" "$m"
  elif [ "$(rc v1-scan)" != 0 ]; then finish FAIL "the run with the vanishing host exited $(rc v1-scan): $(head -c 200 "$EV/v1-scan.err")" "$prop" "$m"
  elif [ "$changed" != 0 ]; then finish FAIL "the vanished host shows up as $changed service_changed entries (half-recorded service)" "$prop" "$m"
  else finish PASS "run completed, no service_changed for the vanished host" "$prop" "$m"; fi
}

hostile-http() {
  local prop="17 misbehaving HTTP targets: the run completes in bounded time, the export is valid UTF-8 JSON, bodies are capped, every hostile service is recorded as open, a second identical scan gives zero diff changes, an off-target redirect is recorded but not followed"
  begin "${HOSTILE_NAME:-hostile-http}"   # HOSTILE_ARGS="--service-detection light" HOSTILE_NAME=hostile-http-light for a variant
  fresh_db rel_hostile
  $DC restart hostile >/dev/null 2>&1; $DC up -d --wait hostile >/dev/null 2>&1; : > "$BASE/_lab/hostile/requests.log"
  local S="--targets-file /rel/targets-hostile.txt --ports 80,443 --max-rate 300 ${HOSTILE_ARGS:-} --wait" t0 s1 s2
  t0=$(now); TMO=900 rec h1-scan asi scan run $S --name h1; s1=$(since "$t0")
  rec h1-show asi scan show h1
  rec h1-export asi export --format json --out $O/$SC/h1.json
  rec ps-after-h1 $DC exec -T asi ps -o pid,ppid,stat,args
  t0=$(now); TMO=900 rec h2-scan asi scan run $S --name h2; s2=$(since "$t0")
  rec h2-export asi export --format json --out $O/$SC/h2.json
  rec diff asi diff --from h1 --to h2 --format json --out $O/$SC/diff-h1-h2.json
  rec check-export python3 check.py hostile "$EV/h1.json"
  rec check-diff python3 check.py changes "$EV/diff-h1-h2.json"
  rec clean python3 check.py clean "$EV/h1-scan.err" "$EV/h1-scan.out" "$EV/h2-scan.err" "$EV/h2-scan.out"
  cp "$BASE/_lab/hostile/requests.log" "$EV/target-requests.log"
  local offsite dbsize; offsite=$(grep -c '"addr": "172.29.0.40"' "$EV/target-requests.log" || true)
  dbsize=$(psql rel_hostile "select pg_database_size('rel_hostile')")
  local m="{\"scan1_seconds\": $s1, \"scan2_seconds\": $s2, \"scan1_exit\": \"$(rc h1-scan)\", \"scan2_exit\": \"$(rc h2-scan)\", \"requests_to_offsite_host\": $offsite, \"db_bytes_after_two_scans\": $dbsize, \"export\": $(cat "$EV/check-export.out" 2>/dev/null || echo null), \"diff\": $(cat "$EV/check-diff.out" 2>/dev/null || echo null)}"
  local why=""
  [ "$(rc h1-scan)" = 0 ] && [ "$(rc h2-scan)" = 0 ] || why="$why scan exit $(rc h1-scan)/$(rc h2-scan) (137 = hung past 900 s);"
  [ "$(rc check-export)" = 0 ] || why="$why $(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print('missing: ' + ', '.join(x.split()[-1] for x in d['missing']) if d.get('missing') else 'not open: %s' % d.get('not_open') if d.get('not_open') else 'export invalid')" "$EV/check-export.out" 2>/dev/null);"
  [ "$(rc check-diff)" = 0 ] || why="$why second scan diff has $(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['changes'])" "$EV/check-diff.out" 2>/dev/null) changes;"
  [ "$offsite" = 0 ] || why="$why off-target redirect was followed ($offsite requests);"
  [ "$(rc clean)" = 0 ] || why="$why stack trace in output;"
  [ "$dbsize" -lt 100000000 ] || why="$why database grew to $dbsize bytes;"
  if [ -n "$why" ]; then finish FAIL "${why# }" "$prop" "$m"; else finish PASS "completed in ${s1}s / ${s2}s, all 17 recorded open, zero changes" "$prop" "$m"; fi
}

concurrent-runs() {
  local prop="two runs with different names at once give equal, duplicate-free results; two runs with the same name: one is rejected with a one-line error"
  begin concurrent-runs
  fresh_db rel_conc
  ( rec a-scan asi scan run $SMALL --name c-a ) & ( rec b-scan asi scan run $SMALL --name c-b ) & wait
  rec a-export asi export --format json --run c-a --out $O/concurrent-runs/c-a.json
  rec b-export asi export --format json --run c-b --out $O/concurrent-runs/c-b.json
  rec ab-compare python3 check.py cmp "$EV/c-a.json" "$EV/c-b.json" --identity
  rec ab-diff asi diff --from c-a --to c-b --format json --out $O/concurrent-runs/diff-a-b.json
  rec ab-changes python3 check.py changes "$EV/diff-a-b.json"
  ( rec s1-scan asi scan run $SMALL --name c-same ) & ( rec s2-scan asi scan run $SMALL --name c-same ) & wait
  rec same-show asi scan show c-same
  rec same-export asi export --format json --run c-same --out $O/concurrent-runs/c-same.json
  rec same-compare python3 check.py cmp "$EV/c-a.json" "$EV/c-same.json" --identity
  rec s3-scan asi scan run $SMALL --name c-same
  rec clean python3 check.py clean "$EV"/*-scan.err "$EV"/*-scan.out
  local loser=s2; [ "$(rc s1-scan)" != 0 ] && loser=s1
  local loser_lines; loser_lines=$(grep -c . "$EV/$loser-scan.err" || true)
  local m="{\"different_names_exit\": \"$(rc a-scan)/$(rc b-scan)\", \"different_names_compare\": $(cat "$EV/ab-compare.out" 2>/dev/null || echo null), \"diff_a_b\": $(cat "$EV/ab-changes.out" 2>/dev/null || echo null), \"same_name_exit\": \"$(rc s1-scan)/$(rc s2-scan)\", \"same_name_loser_stderr\": $(head -c 300 "$EV/$loser-scan.err" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'), \"same_name_compare\": $(cat "$EV/same-compare.out" 2>/dev/null || echo null), \"same_name_again_after_completion_exit\": \"$(rc s3-scan)\"}"
  local why=""
  [ "$(rc a-scan)" = 0 ] && [ "$(rc b-scan)" = 0 ] || why="$why different names: exit $(rc a-scan)/$(rc b-scan);"
  [ "$(rc ab-compare)" = 0 ] || why="$why different names: results differ or duplicate;"
  [ "$(rc ab-changes)" = 0 ] || why="$why diff between the two simultaneous runs is not empty;"
  { [ "$(rc s1-scan)" = 0 ] && [ "$(rc s2-scan)" != 0 ]; } || { [ "$(rc s1-scan)" != 0 ] && [ "$(rc s2-scan)" = 0 ]; } || why="$why same name: exit $(rc s1-scan)/$(rc s2-scan), expected exactly one rejection;"
  [ "$loser_lines" = 1 ] || why="$why same name: rejection is $loser_lines lines;"
  [ "$(rc same-compare)" = 0 ] || why="$why same name: result differs from a clean run;"
  [ "$(rc s3-scan)" != 0 ] || why="$why re-using a completed run name was accepted;"
  [ "$(rc clean)" = 0 ] || why="$why stack trace;"
  if [ -n "$why" ]; then finish FAIL "${why# }" "$prop" "$m"; else finish PASS "both cases clean; rejection: $(head -c 120 "$EV/$loser-scan.err")" "$prop" "$m"; fi
}

bad_case() { # bad_case <label> <cmd...>: expects non-zero exit (not a timeout), exactly one stderr line, no stack trace
  local label=$1 r lines verdict=ok; shift
  TMO="${TMO:-60}" rec "$label" "$@"; r=$(rc "$label")
  lines=$(grep -c . "$EV/$label.err" || true)
  python3 check.py clean "$EV/$label.err" "$EV/$label.out" >/dev/null || verdict="stack trace"
  [ "$r" != 0 ] || verdict="exit 0"
  [ "$r" != 137 ] || verdict="not refused: still running after ${TMO:-60}s (killed)"
  [ "$verdict" != ok ] || [ "$lines" = 1 ] || verdict="$lines stderr lines"
  python3 -c 'import json,sys; print(json.dumps({"case": sys.argv[1], "verdict": sys.argv[2], "exit": sys.argv[3], "stderr": open(sys.argv[4], "rb").read()[:240].decode("utf-8", "replace")}))' "$label" "$verdict" "$r" "$EV/$label.err" >> "$EV/cases.jsonl"
}
bad-input() {
  local prop="every invalid input gives a one-line error on stderr, a non-zero exit and no panic; a /8 is refused or bounded"
  begin bad-input
  fresh_db rel_bad
  local IN="$EV/in"; mkdir -p "$IN"; local C=$O/bad-input/in
  printf 'not an ip!!\n999.1.1.1\n172.29.0.0/33\n\x00\xff\xfe\n' > "$IN/garbage.txt"
  : > "$IN/empty.txt"; printf '# nothing here\n\n' > "$IN/comments.txt"
  echo 10.0.0.0/8 > "$IN/slash8.txt"; echo 172.29.0.150 > "$IN/one.txt"
  local R="--ports 80 --max-rate 300 --wait"
  bad_case targets-garbage asi scan run --targets-file $C/garbage.txt --name b1 $R
  bad_case targets-empty asi scan run --targets-file $C/empty.txt --name b2 $R
  bad_case targets-comments-only asi scan run --targets-file $C/comments.txt --name b3 $R
  bad_case targets-missing-file asi scan run --targets-file $C/nope.txt --name b4 $R
  # the /8 is black-holed inside the product container, so nothing leaves it if the product does try
  $DC exec -T asi ip route replace blackhole 10.0.0.0/8
  TMO=45 bad_case targets-slash8 asi scan run --targets-file $C/slash8.txt --name b5 --ports 80 --max-rate 2 --wait
  rec slash8-show asi scan show b5
  rec slash8-ps $DC exec -T asi ps -o pid,ppid,stat,args
  $DC exec -T asi pkill -9 nmap >/dev/null 2>&1
  bad_case ports-0 asi scan run --targets-file $C/one.txt --name b6 --ports 0 --wait
  bad_case ports-70000 asi scan run --targets-file $C/one.txt --name b7 --ports 70000 --wait
  bad_case ports-empty asi scan run --targets-file $C/one.txt --name b8 --ports "" --wait
  bad_case ports-word asi scan run --targets-file $C/one.txt --name b9 --ports http --wait
  bad_case diff-unknown asi diff --from nope-1 --to nope-2 --format json --out $O/bad-input/x-diff.json
  bad_case export-unknown asi export --format json --run nope-1 --out $O/bad-input/x-export.json
  bad_case resume-unknown asi scan resume nope-1
  bad_case show-unknown asi scan show nope-1
  ASI_KEY="c2hvcnQta2V5LTE2LWJ5dGU=" bad_case key-16-bytes asi export --format json --out $O/bad-input/x-key16.json
  ASI_KEY="not base64 at all!" bad_case key-not-base64 asi export --format json --out $O/bad-input/x-keybad.json
  ASI_KEY="" bad_case key-empty asi export --format json --out $O/bad-input/x-keyempty.json
  ASI_URL="$(dburl rel_bad wrong-password)" bad_case db-wrong-password asi export --format json --out $O/bad-input/x-dbpw.json
  ASI_URL="$(dburl rel_bad wrong-password)" bad_case db-wrong-password-scan asi scan run --targets-file $C/one.txt --name b10 $R
  local bad total; total=$(grep -c . "$EV/cases.jsonl"); bad=$(grep -vc '"verdict": "ok"' "$EV/cases.jsonl" || true)
  local m; m=$(python3 -c 'import json,sys; rows=[json.loads(l) for l in open(sys.argv[1])]; print(json.dumps({"cases": len(rows), "failed": [r for r in rows if r["verdict"] != "ok"], "ok": [r["case"] for r in rows if r["verdict"] == "ok"]}))' "$EV/cases.jsonl")
  if [ "$bad" != 0 ]; then finish FAIL "$bad of $total cases: $(python3 -c 'import json,sys; print("; ".join(r["case"] + " -> " + r["verdict"] for r in map(json.loads, open(sys.argv[1])) if r["verdict"] != "ok"))' "$EV/cases.jsonl")" "$prop" "$m"
  else finish PASS "$total cases, each a one-line error and non-zero exit" "$prop" "$m"; fi
}

repeat-stability() {
  local prop="10 scans of an unchanged target set: 9 diffs with zero changes, row counts and database size grow at most linearly, no nmap process left after any run"
  begin repeat-stability
  fresh_db rel_repeat
  local i changes=0 leftovers=0 failed=0 n
  echo "run,seconds,db_bytes,total_rows,nmap_left,diff_changes" > "$EV/growth.csv"
  for i in $(seq 10); do
    local t0 s size rows left ch=""; t0=$(now)
    rec "r$i-scan" asi scan run $SMALL --name "r-$i" || failed=$((failed + 1)); s=$(since "$t0")
    left=$(nmap_procs); [ "$left" = 0 ] || { leftovers=$((leftovers + 1)); $DC exec -T asi ps -o pid,ppid,stat,args > "$EV/r$i-ps.out"; }
    psql rel_repeat "select table_name, (xpath('/row/c/text()', query_to_xml('select count(*) as c from '||quote_ident(table_name), false, true, '')))[1]::text::bigint from information_schema.tables where table_schema='public' order by 1" > "$EV/r$i-rows.csv"
    rows=$(awk -F, '{s+=$2} END {print s}' "$EV/r$i-rows.csv"); size=$(psql rel_repeat "select pg_database_size('rel_repeat')")
    if [ "$i" -gt 1 ]; then
      rec "diff-$((i - 1))-$i" asi diff --from "r-$((i - 1))" --to "r-$i" --format json --out "$O/repeat-stability/diff-$((i - 1))-$i.json"
      n=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))['changes']))" "$EV/diff-$((i - 1))-$i.json" 2>/dev/null || echo 999)
      ch=$n; [ "$n" = 0 ] || changes=$((changes + 1))
    fi
    echo "$i,$s,$size,$rows,$left,$ch" >> "$EV/growth.csv"
  done
  rec export asi export --format json --out $O/repeat-stability/export.json
  local m; m=$(python3 - "$EV/growth.csv" "$failed" <<'EOF'
import csv, json, sys
rows = list(csv.DictReader(open(sys.argv[1])))
tot = [int(r["total_rows"]) for r in rows]; size = [int(r["db_bytes"]) for r in rows]
d = [b - a for a, b in zip(tot, tot[1:])]
print(json.dumps({"scans_failed": int(sys.argv[2]), "seconds": [float(r["seconds"]) for r in rows], "total_rows": tot, "row_delta_per_run": d,
                  "db_bytes": size, "db_bytes_per_run": [b - a for a, b in zip(size, size[1:])],
                  "diffs_with_changes": sum(1 for r in rows if r["diff_changes"] not in ("", "0")),
                  "runs_with_nmap_left": sum(1 for r in rows if r["nmap_left"] != "0"),
                  "linear": bool(d) and max(d[4:]) <= 1.25 * max(d[:4]) + 5}))
EOF
)
  local linear; linear=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['linear'])" "$m")
  local why=""
  [ "$failed" = 0 ] || why="$why $failed scans failed;"
  [ "$changes" = 0 ] || why="$why $changes of 9 diffs have changes;"
  [ "$leftovers" = 0 ] || why="$why nmap left after $leftovers runs;"
  [ "$linear" = True ] || why="$why row growth is not linear;"
  if [ -n "$why" ]; then finish FAIL "${why# }" "$prop" "$m"; else finish PASS "9 empty diffs, linear growth, no leftover nmap" "$prop" "$m"; fi
}

key-rotation-and-wrong-key() {
  local prop="asi export with a different valid ASI_MASTER_KEY fails closed: non-zero exit, a clear one-line error, no output file with data, no garbage or partial plaintext"
  begin key-rotation-and-wrong-key
  fresh_db rel_key
  rec scan asi scan run $SMALL --name k1
  rec export-good asi export --format json --out $O/key-rotation-and-wrong-key/good.json
  ASI_KEY=$KEY2 rec export-wrong-key asi export --format json --out $O/key-rotation-and-wrong-key/wrong.json
  ASI_KEY=$KEY2 rec export-wrong-key-csv asi export --format csv --out $O/key-rotation-and-wrong-key/wrong.csv
  ASI_KEY=$KEY2 rec diff-wrong-key asi diff --from k1 --to k1 --format json --out $O/key-rotation-and-wrong-key/wrong-diff.json
  # informational: a second scan under the new key on top of data written with the old one
  ASI_KEY=$KEY2 rec scan-new-key asi scan run $SMALL --name k2
  ASI_KEY=$KEY2 rec export-new-key-after-rescan asi export --format json --out $O/key-rotation-and-wrong-key/after-rescan.json
  local r lines wrote=no leak=no binary; r=$(rc export-wrong-key); lines=$(grep -c . "$EV/export-wrong-key.err" || true)
  [ -s "$EV/wrong.json" ] && wrote=yes
  [ -s "$EV/wrong.json" ] && grep -q -E 'PHP/7.4.3|x-powered-by|PHPSESSID' "$EV/wrong.json" && leak=yes
  binary=$(python3 -c "import sys; d=b''.join(open(p,'rb').read() for p in sys.argv[1:]); print(sum(1 for c in d if c < 9 or 13 < c < 32))" "$EV/export-wrong-key.err" "$EV/export-wrong-key.out")
  local m="{\"export_good_exit\": \"$(rc export-good)\", \"export_wrong_key_exit\": \"$r\", \"stderr\": $(head -c 300 "$EV/export-wrong-key.err" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'), \"stderr_lines\": $lines, \"output_file_written\": \"$wrote\", \"plaintext_of_encrypted_fields_in_output\": \"$leak\", \"control_bytes_in_output\": $binary, \"csv_wrong_key_exit\": \"$(rc export-wrong-key-csv)\", \"diff_wrong_key_exit\": \"$(rc diff-wrong-key)\", \"rescan_with_new_key_exit\": \"$(rc scan-new-key)\", \"export_after_rescan_with_new_key_exit\": \"$(rc export-new-key-after-rescan)\", \"key_rotation_command\": \"none in the CLI of this snapshot\"}"
  local why=""
  [ "$(rc scan)" = 0 ] && [ "$(rc export-good)" = 0 ] || why="$why setup failed;"
  [ "$r" != 0 ] || why="$why export with the wrong key exited 0;"
  [ "$wrote" = no ] || why="$why an output file was written;"
  [ "$lines" = 1 ] || why="$why error is $lines lines;"
  [ "$binary" = 0 ] || why="$why control bytes in the output;"
  [ "$(rc export-wrong-key-csv)" != 0 ] || why="$why csv export with the wrong key exited 0;"
  if [ -n "$why" ]; then finish FAIL "${why# }" "$prop" "$m"; else finish PASS "fails closed: $(head -c 140 "$EV/export-wrong-key.err")" "$prop" "$m"; fi
}

port-flap() {
  local prop="a port that closes while the host stays up, then reopens: service_missing, then service_returned, and no host-level change"
  begin port-flap
  fresh_db rel_flap
  $DC up -d --wait toggle >/dev/null 2>&1; $DC exec -T toggle rm -f /tmp/close80; sleep 2
  local S="--targets-file /rel/targets-toggle.txt --ports 80,8080 --max-rate 300 --wait" i
  rec p0-scan asi scan run $S --name p0
  $DC exec -T toggle touch /tmp/close80; sleep 2; note "port 80 closed on 172.29.0.51, 8080 stays open"
  rec p1-scan asi scan run $S --name p1
  $DC exec -T toggle rm -f /tmp/close80; sleep 2; note "port 80 reopened"
  rec p2-scan asi scan run $S --name p2
  for i in 0 1 2; do rec "p$i-export" asi export --format json --run "p$i" --out "$O/port-flap/p$i.json"; done
  rec diff-p0-p1 asi diff --from p0 --to p1 --format json --out $O/port-flap/diff-p0-p1.json
  rec diff-p1-p2 asi diff --from p1 --to p2 --format json --out $O/port-flap/diff-p1-p2.json
  local m; m=$(python3 check.py port-flap "$EV")
  if [ "$(rc p0-scan)$(rc p1-scan)$(rc p2-scan)" != 000 ]; then finish FAIL "scan exit $(rc p0-scan)/$(rc p1-scan)/$(rc p2-scan)" "$prop" "$m"
  elif [ "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['ok'])" "$m")" != True ]; then finish FAIL "diffs are not exactly service_missing then service_returned for 172.29.0.51:80 (see result.json)" "$prop" "$m"
  else finish PASS "service_missing then service_returned for :80, no host-level change" "$prop" "$m"; fi
}

sigterm-pause() {
  local prop="SIGTERM during a scan: non-zero exit with a one-line message, the run is shown as paused, no nmap process is left, scan resume completes it and the export equals the uninterrupted run"
  begin sigterm-pause
  baseline || { finish FAIL "baseline run failed, see _baseline/" "$prop"; return; }
  fresh_db rel_term
  local t0; t0=$(now)
  ( rec scan asi scan run $BIG --name st ) &
  sleep 45
  asi scan show st > "$EV/show-before-term.out" 2>&1
  rec term $DC exec -T asi pkill -TERM -f "^asi scan run"
  wait
  local returned; returned=$(since "$t0")
  rec ps-after-term $DC exec -T asi ps -o pid,ppid,stat,args
  local nm; nm=$(grep -c ' nmap ' "$EV/ps-after-term.out" || true)
  rec show-after-term asi scan show st
  local st; st=$(show_field show-after-term status)
  rec resume asi scan resume st
  rec show-after-resume asi scan show st
  rec export asi export --format json --out $O/sigterm-pause/export.json
  rec compare python3 check.py cmp "$RES/_baseline/export.json" "$EV/export.json"
  rec clean python3 check.py clean "$EV/scan.err" "$EV/scan.out" "$EV/resume.err"
  local lines; lines=$(grep -c . "$EV/scan.err" || true)
  local m="{\"sigterm_after_seconds\": 45, \"scan_returned_after_seconds\": $returned, \"scan_exit\": \"$(rc scan)\", \"scan_stderr\": $(head -c 300 "$EV/scan.err" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'), \"status_after_sigterm\": \"$st\", \"groups_before\": \"$(sed -n '1s/.* groups_done=\([^ ]*\).*/\1/p' "$EV/show-before-term.out")\", \"nmap_left\": $nm, \"resume_exit\": \"$(rc resume)\", \"compare\": $(cat "$EV/compare.out" 2>/dev/null || echo null)}"
  local why=""
  [ "$(rc scan)" != 0 ] && [ "$(rc scan)" != 137 ] || why="$why scan exit $(rc scan);"
  [ "$lines" = 1 ] || why="$why message is $lines lines;"
  [ "$st" = paused ] || why="$why status shown as '$st', not paused;"
  [ "$nm" = 0 ] || why="$why $nm nmap left;"
  [ "$(rc resume)" = 0 ] || why="$why resume exit $(rc resume): $(head -c 160 "$EV/resume.err");"
  [ "$(rc compare)" = 0 ] || why="$why export differs from the uninterrupted run;"
  [ "$(rc clean)" = 0 ] || why="$why stack trace;"
  if [ -n "$why" ]; then finish FAIL "${why# }" "$prop" "$m"; else finish PASS "paused after ${returned}s, no nmap left, resumed run equals the uninterrupted one" "$prop" "$m"; fi
}

recheck-mode() {
  local prop="recheck after a full scan with one host stopped in between: only that host is reported missing, and no (address, port) without a known service is contacted (SYN counters on the responder, neighbour table of the scanner)"
  begin recheck-mode
  fresh_db rel_recheck
  local STOP=172.29.0.149
  $DC exec -T bignet sh -c "ip addr add $STOP/25 dev eth0 2>/dev/null; true"
  rec full-scan asi scan run $SMALL --name rc-full
  rec full-export asi export --format json --out $O/recheck-mode/full.json
  python3 check.py recheck-rules "$BASE/_lab/bignet/truth.json" > "$EV/pairs.txt"
  { echo "iptables -F RELCHK 2>/dev/null; iptables -N RELCHK 2>/dev/null; iptables -C INPUT -j RELCHK 2>/dev/null || iptables -I INPUT -j RELCHK"
    echo "iptables -A RELCHK -p icmp --icmp-type echo-request"
    while read -r a p; do echo "iptables -A RELCHK -p tcp --syn -d $a --dport $p"; done < "$EV/pairs.txt"; } | $DC exec -T bignet sh
  $DC exec -T bignet ip addr del "$STOP/25" dev eth0; note "host $STOP stopped (address removed from the responder)"
  $DC exec -T asi ip neigh flush all >/dev/null 2>&1; sleep 1
  rec recheck-scan asi scan run $SMALL --mode recheck --name rc-re
  rec neigh $DC exec -T asi ip neigh show
  rec counters $DC exec -T bignet iptables -L RELCHK -v -x -n
  rec recheck-show asi scan show rc-re
  rec diff asi diff --from rc-full --to rc-re --format json --out $O/recheck-mode/diff.json
  rec recheck-export asi export --format json --out $O/recheck-mode/recheck.json
  $DC exec -T bignet sh -c "ip addr add $STOP/25 dev eth0; iptables -D INPUT -j RELCHK; iptables -F RELCHK; iptables -X RELCHK" >/dev/null 2>&1
  rec verify python3 check.py recheck-verify "$EV/full.json" "$EV/counters.out" "$EV/neigh.out" "$STOP" "$EV/diff.json"
  local m; m=$(cat "$EV/verify.out" 2>/dev/null); [ -n "$m" ] || m=null
  if [ "$(rc full-scan)" != 0 ]; then finish FAIL "full scan exit $(rc full-scan)" "$prop" "$m"
  elif [ "$(rc recheck-scan)" != 0 ]; then finish FAIL "recheck exit $(rc recheck-scan): $(head -c 200 "$EV/recheck-scan.err")" "$prop" "$m"
  elif [ "$(rc verify)" != 0 ]; then finish FAIL "$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['why'])" "$EV/verify.out" 2>/dev/null || echo 'verification failed')" "$prop" "$m"
  else finish PASS "only $STOP reported missing; no SYN to unknown services, no neighbour lookups for other addresses" "$prop" "$m"; fi
}

up() { $DC up -d --build --wait >/dev/null 2>&1 || { echo "LAB: BLOCKED (docker compose up failed)"; exit 3; }; }
down() { $DC down -v --remove-orphans >/dev/null 2>&1 || true; }

case "${1:-}" in
  up) up ;;
  down) down ;;
  all) up; for s in $SCENARIOS; do $s; done; python3 check.py summary "$RES" "$COMMIT"; [ -n "${KEEP:-}" ] || down ;;
  kill-resume|db-restart|host-vanishes|hostile-http|concurrent-runs|bad-input|repeat-stability|key-rotation-and-wrong-key|port-flap|sigterm-pause|recheck-mode)
    up; "$1"; python3 check.py summary "$RES" "$COMMIT" >/dev/null; [ -n "${KEEP:-}" ] || down ;;
  *) echo "usage: run.sh <scenario>|all|up|down   scenarios: $SCENARIOS"; exit 2 ;;
esac
