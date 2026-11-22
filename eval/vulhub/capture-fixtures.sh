#!/bin/sh
# Runs inside curlimages/curl on the vh network (see run.sh / README in truth.json notes). GET only.
# usage: capture-fixtures.sh "<service>=<url> ..."   writes /fx/<service>/<port>/hopN.{headers,body,url}
set -u
for item in "$@"; do
  svc=${item%%=*}; url=${item#*=}
  port=$(echo "$url" | sed -E 's#^https?://[^:/]+:?([0-9]*)/.*#\1#'); [ -n "$port" ] || port=80
  d=/fx/$svc/$port; mkdir -p "$d"; rm -f "$d"/*
  base=$(echo "$url" | sed -E 's#^(https?://[^/]+)/.*#\1#')
  n=0
  while [ $n -le 5 ] && [ -n "$url" ]; do
    echo "$url" > "$d/hop$n.url"
    next=$(curl -sk -m 30 -D "$d/hop$n.headers" -w '%{redirect_url}' -o "$d/hop$n.full" "$url")
    head -c 65536 "$d/hop$n.full" > "$d/hop$n.body" 2>/dev/null; rm -f "$d/hop$n.full"
    url=$next; n=$((n+1))
  done
  code=$(curl -sk -m 30 -D "$d/favicon.headers" -o "$d/favicon.ico" -w '%{http_code}' "$base/favicon.ico")
  if [ "$code" = 200 ] && [ -s "$d/favicon.ico" ]; then sha256sum "$d/favicon.ico" | cut -d' ' -f1 > "$d/favicon.sha256"
  else rm -f "$d/favicon.ico"; echo "$code" > "$d/favicon.absent"; fi
  echo "$svc $port hops=$n favicon=$code"
done
