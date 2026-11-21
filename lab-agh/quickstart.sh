#!/usr/bin/env bash

set -euo pipefail

COMPOSE=(docker compose -f docker-compose-custom-network.yml)

usage() {
  cat <<'EOF'
Użycie:
  ./quickstart.sh up      uruchom lub przywróć trzy usługi
  ./quickstart.sh change  zatrzymaj jedną usługę, pozostawiając dwie aktywne
  ./quickstart.sh down    zatrzymaj i usuń środowisko
EOF
}

wait_for_port() {
  local port="$1"
  for _ in $(seq 1 60); do
    if (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
      exec 3>&-
      return 0
    fi
    sleep 1
  done
  return 1
}

case "${1:-}" in
  up)
    "${COMPOSE[@]}" up -d flask-app gitea rabbitmq
    for port in 8787 3001 2223 5673 15673; do
      if ! wait_for_port "$port"; then
        echo "Port $port nie stał się dostępny w oczekiwanym czasie." >&2
        exit 1
      fi
    done
    cat <<'EOF'

Lab jest gotowy.

Aktywne usługi:
  HTTP       http://localhost:8787
  Gitea      http://localhost:3001, SSH localhost:2223
  RabbitMQ   AMQP localhost:5673, panel http://localhost:15673

Przykładowy skan:
  nmap -Pn -sV -p 2223,3001,5673,8787,15673 localhost
EOF
    ;;
  change)
    "${COMPOSE[@]}" stop flask-app
    cat <<'EOF'

Usługa HTTP na porcie 8787 została zatrzymana.

Gitea i RabbitMQ nadal działają. Wykonaj ponownie skan i sprawdź,
czy zniknął tylko port 8787.
Aby przywrócić usługę HTTP, uruchom:
  ./quickstart.sh up
EOF
    ;;
  down)
    "${COMPOSE[@]}" down
    ;;
  *)
    usage
    exit 1
    ;;
esac
