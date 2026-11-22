#!/usr/bin/env bash
# Two ad-hoc checks next to run.sh (lab must be up: KEEP=1 run.sh up). Evidence: ../results/reliability/${RUN:-.}/extra/
#  1. a target nmap cannot route to (black-holed 10.1.2.0/30): the group must be recorded as failed, not as "0 hosts"
#  2. the "silent" hostile target alone with the default service detection: how long does one tarpit host take?
set -uo pipefail
cd "$(dirname "$0")"
E="../results/reliability/${RUN:-.}/extra"; O="/out/${RUN:-.}/extra"; mkdir -p "$E"
DC="docker compose -p asi-rel -f docker-compose.yml"
U="ASI_DATABASE_URL=postgres://asi:asi-rel@172.29.0.3:5432/rel_extra?sslmode=disable"
$DC exec -T postgres psql -U asi -d postgres -q -c "DROP DATABASE IF EXISTS rel_extra WITH (FORCE)" -c "CREATE DATABASE rel_extra" >/dev/null 2>&1
$DC exec -T -e "$U" asi asi migrate >/dev/null
printf '10.1.2.0/30\n' > "$E/blackholed.txt"; printf '172.29.0.14\n' > "$E/silent.txt"
$DC exec -T asi ip route replace blackhole 10.0.0.0/8
{ $DC exec -T -e "$U" asi timeout -s KILL 120 asi scan run --targets-file "$O/blackholed.txt" --ports 80 --name bh --wait; echo "exit: $?"
  $DC exec -T -e "$U" asi asi scan show bh; } > "$E/blackholed.log" 2>&1
t0=$(date +%s)
{ $DC exec -T -e "$U" asi timeout -s KILL "${SILENT_TMO:-800}" asi scan run --targets-file "$O/silent.txt" --ports 80 --name silent1 --wait; echo "exit: $?"
  echo "seconds: $(( $(date +%s) - t0 ))"
  $DC exec -T -e "$U" asi asi scan show silent1; $DC exec -T asi ps -o pid,stat,args; } > "$E/silent-default-detection.log" 2>&1
$DC exec -T asi pkill -9 nmap >/dev/null 2>&1
cut -c1-400 "$E/blackholed.log" "$E/silent-default-detection.log"
