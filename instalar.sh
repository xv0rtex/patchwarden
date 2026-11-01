#!/usr/bin/env bash
# Instalador del Vigilante de vulnerabilidades. No hay que editar nada.
#
#   curl -fsSL https://raw.githubusercontent.com/USUARIO/REPO/main/instalar.sh | bash
#   (o, con el proyecto ya descargado)   bash instalar.sh
#
# Qué hace:
#   1. Se descarga (o actualiza) el vigilante y construye su imagen.
#   2. Descubre solo las apps que ya corren en Docker (rutas, redes y puertos).
#   3. Elige un puerto libre, genera la configuración y una contraseña, y lo arranca.
#   4. Por defecto SOLO avisa y propone: no puede modificar tus apps.
#
# Opciones:  --dir RUTA  --puerto N  --local  --permitir-aplicar  --solo NOMBRE  --sin-preguntas
#            --tunel (acceso desde internet, gratis)  --url (ver la URL del túnel)  --parar  --desinstalar
# Se puede volver a ejecutar cuando quieras: actualiza, refresca las apps y conserva tus claves.
set -euo pipefail

# --- Lo único que fija quien publica el proyecto (una vez): de dónde se descarga
REPO="${VIGILANTE_REPO:-https://github.com/USUARIO/vigilante-cve}"
RAMA="${VIGILANTE_RAMA:-main}"

DIR=""; PUERTO=""; LOCAL=""; APLICAR=""; SOLO=""; TUNEL=""; PREGUNTAR=1; ACCION="instalar"
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --puerto) PUERTO="$2"; shift 2 ;;
    --local) LOCAL=1; shift ;;
    --permitir-aplicar) APLICAR=1; shift ;;
    --solo) SOLO="$2"; shift 2 ;;
    --tunel) TUNEL=1; shift ;;
    --url) ACCION="url"; shift ;;
    --sin-preguntas) PREGUNTAR=""; shift ;;
    --parar) ACCION="parar"; shift ;;
    --desinstalar) ACCION="desinstalar"; shift ;;
    -h|--help) sed -n '2,19p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$DIR" ]; then
  if [ "$(id -u)" = "0" ]; then DIR=/opt/vigilante; else DIR="$HOME/vigilante"; fi
fi
msg() { printf '\n\033[1m%s\033[0m\n' "$*"; }
fallo() { printf '\n\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fallo "No encuentro Docker. Instálalo primero."
docker compose version >/dev/null 2>&1 || fallo "Falta el plugin «docker compose» (Docker Compose v2)."
docker info >/dev/null 2>&1 || fallo "No puedo hablar con Docker. ¿Estás en el grupo docker o ejecutas como root?"

url_tunel() { docker compose -f "$DIR/docker-compose.yml" logs cloudflared 2>&1 | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' | tail -1 || true; }
if [ "$ACCION" = "url" ]; then
  U="$(url_tunel)"; [ -n "$U" ] || fallo "No hay túnel activo. Instala con: bash instalar.sh --tunel"
  echo "$U"; exit 0
fi
if [ "$ACCION" = "parar" ]; then
  docker compose -f "$DIR/docker-compose.yml" down; echo "Vigilante parado. Datos conservados."; exit 0
fi
if [ "$ACCION" = "desinstalar" ]; then
  docker compose -f "$DIR/docker-compose.yml" down -v 2>/dev/null || true
  docker rmi vigilante:local >/dev/null 2>&1 || true
  echo "Vigilante desinstalado (contenedores, datos e imagen). Para borrar también los ficheros: rm -rf $DIR"; exit 0
fi

mkdir -p "$DIR"

# --- 1. Código fuente: si el script está dentro del proyecto, se usa; si no, se descarga
AQUI="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "$AQUI" ] && [ -f "$AQUI/vigilante/Dockerfile" ]; then
  FUENTE="$AQUI"
else
  case "$REPO" in *USUARIO*) fallo "No encuentro el código del vigilante junto a este script ni hay una URL configurada. Ejecuta instalar.sh desde la carpeta descomprimida del proyecto." ;; esac
  FUENTE="$DIR/fuente"
  msg "Descargando el vigilante..."
  if command -v git >/dev/null 2>&1; then
    if [ -d "$FUENTE/.git" ]; then git -C "$FUENTE" pull -q --ff-only; else git clone -q --depth 1 -b "$RAMA" "$REPO" "$FUENTE"; fi
  else
    command -v curl >/dev/null 2>&1 || fallo "Hace falta git o curl para descargar el proyecto."
    rm -rf "$FUENTE"; mkdir -p "$FUENTE"
    curl -fsSL "${REPO}/archive/refs/heads/${RAMA}.tar.gz" | tar -xz -C "$FUENTE" --strip-components=1
  fi
fi

msg "Construyendo la imagen (la primera vez tarda un par de minutos)..."
docker build -q -t vigilante:local "$FUENTE/vigilante" >/dev/null

# --- 2. Datos opcionales (Intro para saltar). Si ya los diste antes, no vuelve a preguntar.
leer() { grep -s "^$1=" "$DIR/.env" | head -1 | cut -d= -f2- || true; }
pedir() {  # nombre-variable  pregunta  [secreto]
  local v="${!1:-}"
  [ -z "$v" ] && v="$(leer "$1")"
  if [ -z "$v" ] && [ -n "$PREGUNTAR" ] && [ -r /dev/tty ]; then
    if [ "${3:-}" = "s" ]; then read -r -s -p "$2 (Intro para saltar): " v </dev/tty || true; echo
    else read -r -p "$2 (Intro para saltar): " v </dev/tty || true; fi
  fi
  printf -v "$1" '%s' "$v"
}
if [ -n "$PREGUNTAR" ] && [ -r /dev/tty ] && [ -z "$(leer TELEGRAM_TOKEN)$(leer ANTHROPIC_API_KEY)" ]; then
  msg "Dos datos opcionales (puedes saltarlos y funcionará igual, solo con panel):"
fi
pedir TELEGRAM_TOKEN "Token del bot de Telegram (lo da @BotFather)" s
[ -n "${TELEGRAM_TOKEN:-}" ] && pedir TELEGRAM_CHAT_ID "Tu chat id de Telegram (lo da @userinfobot)"
pedir ANTHROPIC_API_KEY "Clave de Anthropic para poder pedirle correcciones a Claude (solo actuará cuando se lo pidas)" s
export TELEGRAM_TOKEN="${TELEGRAM_TOKEN:-}" TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}" ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"

# --- 3. Descubrimiento y generación de la configuración (en un contenedor efímero)
msg "Buscando tus apps en Docker..."
ARGS=(--salida /salida)
[ -n "$PUERTO" ] && ARGS+=(--puerto "$PUERTO")
[ -n "$LOCAL" ] && ARGS+=(--local)
[ -n "$APLICAR" ] && ARGS+=(--permitir-aplicar)
[ -n "$SOLO" ] && ARGS+=(--solo "$SOLO")
[ -n "$TUNEL" ] && ARGS+=(--tunel)
SALIDA="$(docker run --rm --network host \
  -v /var/run/docker.sock:/var/run/docker.sock:ro -v "$DIR":/salida \
  -e TELEGRAM_TOKEN -e TELEGRAM_CHAT_ID -e ANTHROPIC_API_KEY \
  vigilante:local python -m vigilante.instalar "${ARGS[@]}")" || fallo "No se pudo descubrir el entorno Docker."
echo "$SALIDA" | grep -v '^RESULTADO '
RES="$(echo "$SALIDA" | sed -n 's/^RESULTADO //p')"
campo() { python3 -c 'import json,sys;print(json.loads(sys.argv[1])[sys.argv[2]])' "$RES" "$1" 2>/dev/null \
          || echo "$RES" | sed -n "s/.*\"$1\": \"\{0,1\}\([^\",}]*\).*/\1/p"; }

# --- 4. Arranque
msg "Arrancando el vigilante..."
docker compose -f "$DIR/docker-compose.yml" up -d --remove-orphans >/dev/null
P="$(campo puerto)"; ESPERA="${VIGILANTE_ESPERA:-60}"; OK=""
for _ in $(seq 1 "$ESPERA"); do
  if (command -v curl >/dev/null && curl -fs "http://127.0.0.1:$P/salud" >/dev/null 2>&1) \
     || (command -v wget >/dev/null && wget -qO- "http://127.0.0.1:$P/salud" >/dev/null 2>&1); then OK=1; break; fi
  sleep 1
done
[ -n "$OK" ] || echo "AVISO: el panel aún no responde. Mira: docker compose -f $DIR/docker-compose.yml logs vigilante"

# --- 5. Túnel de cloudflared: se espera a que dé la URL y se deja guardada para los enlaces de los avisos
URL_PUBLICA=""
if [ -n "$TUNEL" ]; then
  msg "Abriendo el túnel de cloudflared..."
  for _ in $(seq 1 "$ESPERA"); do URL_PUBLICA="$(url_tunel)"; [ -n "$URL_PUBLICA" ] && break; sleep 1; done
  if [ -n "$URL_PUBLICA" ]; then
    sed -i "s|^VIGILANTE_PANEL_URL=.*|VIGILANTE_PANEL_URL=$URL_PUBLICA|" "$DIR/.env"
    docker compose -f "$DIR/docker-compose.yml" up -d --force-recreate vigilante >/dev/null
    T="$(leer TELEGRAM_TOKEN)"; C="$(leer TELEGRAM_CHAT_ID)"
    if [ -n "$T" ] && [ -n "$C" ] && command -v curl >/dev/null; then   # avisa por Telegram de la URL
      curl -fsS -m 10 -o /dev/null "https://api.telegram.org/bot$T/sendMessage" \
        --data-urlencode "chat_id=$C" --data-urlencode "text=Vigilante instalado. Panel: $URL_PUBLICA (usuario $(campo usuario))" || true
    fi
  else
    echo "AVISO: el túnel aún no ha dado URL. Pruébalo en un minuto con: bash instalar.sh --url"
  fi
fi

cat <<EOF

================================================================
 Vigilante instalado
================================================================
 Panel:       $(campo url)
$( [ -n "$URL_PUBLICA" ] && printf ' Desde internet: %s\n   (túnel gratuito y temporal: si se reinicia, la URL cambia; para verla: bash instalar.sh --url)\n   Protegido con usuario y contraseña; en cuanto puedas, mejor con tu dominio o VPN.\n' "$URL_PUBLICA" )
 Usuario:     $(campo usuario)
 Contraseña:  $(campo clave)
 (se guardan en $DIR/.env)

 Telegram:    $( [ "$(campo telegram)" = "True" ] || [ "$(campo telegram)" = "true" ] && echo configurado || echo "no configurado (los avisos salen en el panel)")
 Claude:      $( [ "$(campo claude)" = "True" ] || [ "$(campo claude)" = "true" ] && echo "configurado (Claude solo actúa cuando TÚ se lo pides)" || echo "no configurado (solo avisos; sin clave no se le puede pedir nada)")

 Ver logs:        docker compose -f $DIR/docker-compose.yml logs -f vigilante
 Parar:           bash instalar.sh --parar
 Actualizar o refrescar las apps:  vuelve a ejecutar este mismo script
 Desinstalar:     bash instalar.sh --desinstalar
================================================================
EOF
