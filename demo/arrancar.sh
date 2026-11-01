#!/usr/bin/env bash
# Arranca la DEMO del vigilante (todo simulado) y la publica con un túnel rápido de cloudflared.
# Si cloudflared no funciona, sirve la carpeta del proyecto con python3 -m http.server en 0.0.0.0.
#   bash demo/arrancar.sh            -> imprime URL, usuario y contraseña
#   bash demo/parar.sh               -> lo para todo
set -uo pipefail
AQUI="$(cd "$(dirname "$0")" && pwd)"; RAIZ="$(dirname "$AQUI")"
DIR="${DEMO_DIR:-/tmp/vig-demo}"; PUERTO="${DEMO_PUERTO:-8090}"; PUERTO_FICHEROS=8091
mkdir -p "$DIR"
VENV="${VENV:-/work/.home/venv-vigilante}"
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV" && "$VENV/bin/pip" install -q "anthropic>=2.3,<3"
fi
CF="${CLOUDFLARED:-$(command -v cloudflared || echo /work/.home/bin/cloudflared)}"
bash "$AQUI/parar.sh" >/dev/null 2>&1 || true

CLAVE="${DEMO_CLAVE:-$(python3 -c 'import secrets;print(secrets.token_urlsafe(9))')}"
USUARIO="${DEMO_USUARIO:-diego}"
umask 077; echo "$CLAVE" > "$DIR/clave"; umask 022

URL=""
if [ -x "$CF" ]; then
  setsid nohup "$CF" tunnel --no-autoupdate --url "http://localhost:$PUERTO" > "$DIR/tunel.log" 2>&1 < /dev/null &
  echo $! > "$DIR/tunel.pid"
  for _ in $(seq 1 45); do
    URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$DIR/tunel.log" | head -1)
    [ -n "$URL" ] && break; sleep 1
  done
fi

if [ -z "$URL" ]; then
  echo "cloudflared no disponible o sin URL: sirvo la carpeta del proyecto por HTTP en la red local" >&2
  [ -f "$DIR/tunel.pid" ] && kill -- -"$(cat "$DIR/tunel.pid")" 2>/dev/null; rm -f "$DIR/tunel.pid"
  setsid nohup python3 -m http.server "$PUERTO_FICHEROS" --bind 0.0.0.0 --directory "$RAIZ" \
      > "$DIR/ficheros.log" 2>&1 < /dev/null &
  echo $! > "$DIR/ficheros.pid"
  IP=$(hostname -I | awk '{print $1}')
  echo "FICHEROS: http://$IP:$PUERTO_FICHEROS/   (ej.: wget -r -np -nH http://$IP:$PUERTO_FICHEROS/)"
fi

# La demo se relanza sola cuando se pulsa «Reiniciar demo» (sale con código 3)
setsid nohup env DEMO_DIR="$DIR" DEMO_PUERTO="$PUERTO" DEMO_CLAVE="$CLAVE" DEMO_USUARIO="$USUARIO" DEMO_URL="$URL" \
  bash -c 'while true; do "$0" "$1"; c=$?; [ $c -eq 3 ] || { echo "demo terminó con código $c"; break; }; done' \
  "$VENV/bin/python" "$AQUI/demo.py" > "$DIR/demo.log" 2>&1 < /dev/null &
echo $! > "$DIR/demo.pid"

for _ in $(seq 1 90); do grep -q "DEMO LISTA\|Traceback" "$DIR/demo.log" 2>/dev/null && break; sleep 2; done
grep -q "DEMO LISTA" "$DIR/demo.log" || { echo "La demo no arrancó; mira $DIR/demo.log" >&2; exit 1; }
echo "PANEL: ${URL:-http://127.0.0.1:$PUERTO (solo local)}"
echo "USUARIO: $USUARIO"
echo "CLAVE: $CLAVE"
