#!/usr/bin/env bash
# Para la demo, el túnel de cloudflared y (si se usó) el servidor de ficheros.
DIR="${DEMO_DIR:-/tmp/vig-demo}"
for p in demo tunel ficheros; do
  f="$DIR/$p.pid"
  if [ -f "$f" ]; then
    kill -- -"$(cat "$f")" 2>/dev/null || kill "$(cat "$f")" 2>/dev/null
    rm -f "$f"; echo "parado: $p"
  fi
done
