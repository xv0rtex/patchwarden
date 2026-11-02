#!/usr/bin/env bash
# Instalador de Patchwarden (vigilante de vulnerabilidades). No hay que editar nada.
#
#   curl -fsSL https://raw.githubusercontent.com/xv0rtex/patchwarden/main/instalar.sh | bash
#   (o, con el proyecto ya descargado)   bash instalar.sh
#
# Sin opciones enseña un menú: qué instalar o, si ya está instalado, actualizar, volver a buscar apps,
# cambiar tokens, parar o desinstalar. Actualizar conserva tokens, cuenta, datos y análisis.
#
# Qué se instala:
#   Panel central   el dashboard: vigila este servidor, recibe a los agentes y prepara correcciones con Claude
#   Agente          cliente de un panel central: detecta, verifica y aplica en su servidor; solo conexiones salientes
#
# Opciones:
#   --panel                          instalar el panel central sin pasar por el menú
#   --agente --central URL --codigo C   instalar el agente (el código se crea en el panel: Ajustes > Equipos)
#   --actualizar                     descargar lo nuevo de GitHub y redesplegar (sin preguntas, conserva todo)
#   --reconfigurar                   actualizar y volver a buscar las apps de Docker
#   --estado  --url  --parar  --desinstalar
#   --dir RUTA  --puerto N  --local  --permitir-aplicar  --solo NOMBRE  --tunel  --permitir-http  --sin-preguntas
set -euo pipefail

# --- Lo único que fija quien publica el proyecto (una vez): de dónde se descarga
REPO="${VIGILANTE_REPO:-https://github.com/xv0rtex/patchwarden}"
RAMA="${VIGILANTE_RAMA:-main}"

ROL=""; ACCION=""; DIR=""; PUERTO=""; LOCAL=""; APLICAR=""; SOLO=""; TUNEL=""; PERMITIR_HTTP=""
CENTRAL_URL=""; CODIGO=""; PREGUNTAR=1; DE_MENU=""
uso() { sed -n '2,23p' "${BASH_SOURCE[0]:-$0}" 2>/dev/null | sed 's/^# \{0,1\}//' || true; }
while [ $# -gt 0 ]; do
  case "$1" in
    --panel) ROL="central"; shift ;;
    --agente) ROL="agente"; shift ;;
    --central) CENTRAL_URL="$2"; shift 2 ;;
    --codigo) CODIGO="$2"; shift 2 ;;
    --permitir-http) PERMITIR_HTTP=1; shift ;;
    --actualizar) ACCION="actualizar"; shift ;;
    --reconfigurar) ACCION="reconfigurar"; shift ;;
    --estado) ACCION="estado"; shift ;;
    --url) ACCION="url"; shift ;;
    --parar) ACCION="parar"; shift ;;
    --desinstalar) ACCION="desinstalar"; shift ;;
    --dir) DIR="$2"; shift 2 ;;
    --puerto) PUERTO="$2"; shift 2 ;;
    --local) LOCAL=1; shift ;;
    --permitir-aplicar) APLICAR=1; shift ;;
    --solo) SOLO="$2"; shift 2 ;;
    --tunel) TUNEL=1; shift ;;
    --sin-preguntas) PREGUNTAR=""; shift ;;
    -h|--help) uso; exit 0 ;;
    *) echo "Opción desconocida: $1 (mira: bash instalar.sh --help)" >&2; exit 1 ;;
  esac
done

msg() { printf '\n\033[1m%s\033[0m\n' "$*"; }
aviso() { printf '\033[33mAviso:\033[0m %s\n' "$*"; }
fallo() { printf '\n\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }
interactivo() { [ -n "$PREGUNTAR" ] && [ -r /dev/tty ]; }
preguntar() {  # variable  pregunta  [s = secreto]
  local v=""
  if [ "${3:-}" = "s" ]; then read -r -s -p "$2" v </dev/tty || true; echo
  else read -r -p "$2" v </dev/tty || true; fi
  printf -v "$1" '%s' "$v"
}
si_no() {  # pregunta  defecto(s|n) -> 0 si sí
  local r; preguntar r "$1 [$( [ "$2" = s ] && echo S/n || echo s/N )]: "
  r="${r:-$2}"; case "$r" in [sSyY]*) return 0 ;; *) return 1 ;; esac
}

command -v docker >/dev/null 2>&1 || fallo "No encuentro Docker. Instálalo primero."
docker compose version >/dev/null 2>&1 || fallo "Falta el plugin «docker compose» (Docker Compose v2)."
docker info >/dev/null 2>&1 || fallo "No puedo hablar con Docker. ¿Estás en el grupo docker o ejecutas como root?"

# --- Dónde vive cada instalación
if [ "$(id -u)" = "0" ]; then BASE=/opt; else BASE="$HOME"; fi
DIR_CENTRAL="$BASE/vigilante"; DIR_AGENTE="$BASE/vigilante-agente"
AQUI="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
# Cada instalación deja una copia de este script en su carpeta: si se ejecuta esa, se sabe a qué instalación toca
ROL_CARPETA=""
if [ -n "$AQUI" ] && [ -f "$AQUI/instalacion.conf" ]; then
  case "$(grep -s '^ROL=' "$AQUI/instalacion.conf" | cut -d= -f2-)" in
    agente) DIR_AGENTE="$AQUI"; ROL_CARPETA=agente ;; *) DIR_CENTRAL="$AQUI"; ROL_CARPETA=central ;;
  esac
fi
if [ -n "$DIR" ]; then
  if [ "$ROL" = agente ]; then DIR_AGENTE="$DIR"; else DIR_CENTRAL="$DIR"; fi
fi
dir_de() { if [ "$1" = agente ]; then echo "$DIR_AGENTE"; else echo "$DIR_CENTRAL"; fi; }  # rol -> carpeta
imagen_de() { [ "$1" = agente ] && echo vigilante-agente:local || echo vigilante:local; }
servicio_de() { [ "$1" = agente ] && echo agente || echo vigilante; }
nombre_de() { [ "$1" = agente ] && echo "Agente" || echo "Panel central"; }
instalado() { [ -f "$(dir_de "$1")/docker-compose.yml" ]; }
compose() { local d; d="$(dir_de "$1")"; shift; docker compose -f "$d/docker-compose.yml" --project-directory "$d" "$@"; }

# Valores guardados de una instalación: instalacion.conf (opciones) y .env (secretos)
leer() { grep -s "^$2=" "$(dir_de "$1")/$3" | head -1 | cut -d= -f2- || true; }
conf() { leer "$1" "$2" instalacion.conf; }
env_de() { leer "$1" "$2" .env; }
poner() {  # rol fichero clave valor : reescribe (o añade) la clave sin tocar el resto
  local f; f="$(dir_de "$1")/$2"; local tmp="$f.tmp" hecho=""
  : >"$tmp"; chmod 600 "$tmp"
  if [ -f "$f" ]; then
    while IFS= read -r l || [ -n "$l" ]; do
      if [ "${l%%=*}" = "$3" ]; then printf '%s=%s\n' "$3" "$4" >>"$tmp"; hecho=1; else printf '%s\n' "$l" >>"$tmp"; fi
    done <"$f"
  fi
  [ -n "$hecho" ] || printf '%s=%s\n' "$3" "$4" >>"$tmp"
  mv "$tmp" "$f"
}
# Opciones de una instalación anterior al menú (sin instalacion.conf): se deducen de su docker-compose.yml
opcion_guardada() {  # rol clave
  local v; v="$(conf "$1" "$2")"
  if [ -z "$v" ] && [ ! -f "$(dir_de "$1")/instalacion.conf" ]; then
    local y; y="$(dir_de "$1")/docker-compose.yml"
    case "$2" in
      APLICAR) grep -q docker-proxy-pruebas "$y" && v=1 ;;
      TUNEL) grep -q cloudflared "$y" && v=1 ;;
      LOCAL) grep -q '"127.0.0.1:' "$y" && v=1 ;;
    esac
  fi
  echo "$v"
}

# --- Código fuente: el de esta carpeta si el script está dentro del proyecto; si no, se descarga
VERSION_ANTES=""; VERSION=""
version_de() { git -C "$1" rev-parse --short HEAD 2>/dev/null || echo "desconocida"; }
obtener_fuente() {  # rol  -> deja FUENTE y VERSION
  local d; d="$(dir_de "$1")"
  if [ -n "$AQUI" ] && [ -f "$AQUI/central/Dockerfile" ] && [ "$AQUI" != "$d/fuente" ]; then
    FUENTE="$AQUI"; VERSION_ANTES="$(version_de "$FUENTE")"
    if [ -d "$FUENTE/.git" ] && [ "$ACCION_ACTUAL" != "instalar" ]; then
      msg "Trayendo los cambios de GitHub a $FUENTE..."
      git -C "$FUENTE" pull -q --ff-only || aviso "no se pudo hacer git pull en $FUENTE (¿cambios locales?); uso el código tal como está."
    fi
  else
    FUENTE="$d/fuente"; VERSION_ANTES="$(version_de "$FUENTE")"
    local rama; rama="$(conf "$1" RAMA)"; rama="${VIGILANTE_RAMA:-${rama:-$RAMA}}"
    msg "Descargando Patchwarden ($REPO, rama $rama)..."
    mkdir -p "$d"
    if command -v git >/dev/null 2>&1; then
      if [ -d "$FUENTE/.git" ]; then
        git -C "$FUENTE" fetch -q --depth 1 origin "$rama" && git -C "$FUENTE" reset -q --hard FETCH_HEAD
      else
        rm -rf "$FUENTE"; git clone -q --depth 1 -b "$rama" "$REPO" "$FUENTE"
      fi
    else
      command -v curl >/dev/null 2>&1 || fallo "Hace falta git o curl para descargar el proyecto."
      rm -rf "$FUENTE"; mkdir -p "$FUENTE"
      curl -fsSL "${REPO}/archive/refs/heads/${rama}.tar.gz" | tar -xz -C "$FUENTE" --strip-components=1
    fi
    RAMA="$rama"
  fi
  [ -f "$FUENTE/central/Dockerfile" ] || fallo "El código descargado no tiene central/Dockerfile (¿rama antigua?)."
  VERSION="$(version_de "$FUENTE")"
}

construir() {  # rol
  local df="$FUENTE/$1/Dockerfile"      # central/Dockerfile o agente/Dockerfile
  # la imagen en marcha se guarda como :anterior para poder volver a ella si la nueva no arranca
  docker image inspect "$(imagen_de "$1")" >/dev/null 2>&1 \
    && docker tag "$(imagen_de "$1")" "$(imagen_de "$1" | sed 's/:local$/:anterior/')"
  msg "Construyendo la imagen de $(nombre_de "$1" | tr '[:upper:]' '[:lower:]') (la primera vez tarda un par de minutos)..."
  docker build -q -f "$df" --build-arg VERSION="$VERSION" -t "$(imagen_de "$1")" "$FUENTE" >/dev/null
}

# --- ¿Arrancó bien? Panel: responde /salud. Agente: sigue en marcha sin reinicios.
ESPERA="${VIGILANTE_ESPERA:-60}"
sano() {  # rol
  if [ "$1" = central ]; then
    local p; p="$(env_de central VIGILANTE_PUERTO)"
    for _ in $(seq 1 "$ESPERA"); do
      if (command -v curl >/dev/null && curl -fs "http://127.0.0.1:$p/salud" >/dev/null 2>&1) \
         || (command -v wget >/dev/null && wget -qO- "http://127.0.0.1:$p/salud" >/dev/null 2>&1); then return 0; fi
      sleep 1
    done
    return 1
  fi
  local id; sleep 15; id="$(compose agente ps -q agente 2>/dev/null | head -1)"
  [ -n "$id" ] && [ "$(docker inspect -f '{{.State.Running}} {{.RestartCount}}' "$id" 2>/dev/null)" = "true 0" ]
}
arrancar() {  # rol  [volver_atras_si_falla]
  compose "$1" up -d --remove-orphans >/dev/null
  sano "$1" && return 0
  local ant; ant="$(imagen_de "$1" | sed 's/:local$/:anterior/')"
  if [ -n "${2:-}" ] && docker image inspect "$ant" >/dev/null 2>&1; then
    aviso "la versión nueva no arranca bien. Vuelvo a la anterior; tus datos no se han tocado."
    compose "$1" logs --tail 30 "$(servicio_de "$1")" 2>&1 | sed 's/^/    /' || true
    docker tag "$ant" "$(imagen_de "$1")"
    compose "$1" up -d --force-recreate >/dev/null
    fallo "Actualización deshecha. Revisa el error de arriba o abre un issue en $REPO/issues"
  fi
  aviso "aún no responde bien. Últimas líneas del log:"
  compose "$1" logs --tail 15 "$(servicio_de "$1")" 2>&1 | sed 's/^/    /' || true
  echo "  Más: docker compose -f $(dir_de "$1")/docker-compose.yml logs $(servicio_de "$1")"
}

guardar_conf() {  # rol
  local r="$1"
  poner "$r" instalacion.conf ROL "$r"
  poner "$r" instalacion.conf RAMA "$RAMA"
  poner "$r" instalacion.conf FUENTE "$FUENTE"
  poner "$r" instalacion.conf VERSION "$VERSION"
  poner "$r" instalacion.conf FECHA "$(date '+%Y-%m-%d %H:%M')"
  for k in PUERTO LOCAL APLICAR SOLO TUNEL PERMITIR_HTTP; do poner "$r" instalacion.conf "$k" "${!k:-}"; done
  chmod 644 "$(dir_de "$r")/instalacion.conf"
  # copia del instalador junto a la instalación: «bash <carpeta>/instalar.sh» abre el menú para actualizar
  # (cp + mv: si el script en marcha es esa copia, bash sigue leyendo la vieja sin mezclarlas)
  local dest; dest="$(dir_de "$r")/instalar.sh"
  if ! [ "$FUENTE/instalar.sh" -ef "$dest" ]; then cp "$FUENTE/instalar.sh" "$dest.tmp" && mv "$dest.tmp" "$dest"; fi
}

# --- Descubrimiento de las apps y generación de la configuración (en un contenedor efímero)
generar_config() {  # rol
  local r="$1" d; d="$(dir_de "$1")"
  msg "Buscando tus apps en Docker..."
  local args=(--salida /salida --rol "$r")
  [ -n "$PUERTO" ] && args+=(--puerto "$PUERTO")
  [ -n "$LOCAL" ] && args+=(--local)
  [ -n "$APLICAR" ] && args+=(--permitir-aplicar)
  [ -n "$SOLO" ] && args+=(--solo "$SOLO")
  [ -n "$TUNEL" ] && args+=(--tunel)
  [ -n "$CENTRAL_URL" ] && args+=(--central "$CENTRAL_URL")
  [ -n "$CODIGO" ] && args+=(--codigo "$CODIGO")
  [ -n "$PERMITIR_HTTP" ] && args+=(--permitir-http)
  SALIDA="$(docker run --rm --network host \
    -v /var/run/docker.sock:/var/run/docker.sock:ro -v "$d":/salida \
    -e TELEGRAM_TOKEN -e TELEGRAM_CHAT_ID -e CLAUDE_CODE_OAUTH_TOKEN \
    "$(imagen_de "$r")" python -m vigilante.instalar "${args[@]}")" || fallo "No se pudo descubrir el entorno Docker."
  echo "$SALIDA" | grep -v '^RESULTADO '
  RES="$(echo "$SALIDA" | sed -n 's/^RESULTADO //p')"
}
campo() { echo "$RES" | sed -n "s/.*\"$1\": \"\{0,1\}\([^\",}]*\).*/\1/p"; }

cargar_opciones() {  # rol : lo que no se haya dado por línea de comandos sale de la instalación anterior
  for k in PUERTO LOCAL APLICAR SOLO TUNEL PERMITIR_HTTP; do
    [ -n "${!k:-}" ] || printf -v "$k" '%s' "$(opcion_guardada "$1" "$k")"
  done
}

# --- Túnel de cloudflared: se espera a que dé la URL y se guarda para los enlaces de los avisos
url_tunel() { compose central logs cloudflared 2>&1 | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' | tail -1 || true; }
URL_PUBLICA=""
revisar_tunel() {
  grep -q cloudflared "$(dir_de central)/docker-compose.yml" || return 0
  for _ in $(seq 1 "$ESPERA"); do URL_PUBLICA="$(url_tunel)"; [ -n "$URL_PUBLICA" ] && break; sleep 1; done
  if [ -z "$URL_PUBLICA" ]; then aviso "el túnel aún no ha dado URL. Pruébalo en un minuto con: bash instalar.sh --url"; return 0; fi
  if [ "$(env_de central VIGILANTE_PANEL_URL)" != "$URL_PUBLICA" ]; then
    poner central .env VIGILANTE_PANEL_URL "$URL_PUBLICA"
    compose central up -d --force-recreate vigilante >/dev/null
    local t c; t="$(env_de central TELEGRAM_TOKEN)"; c="$(env_de central TELEGRAM_CHAT_ID)"
    if [ -n "$t" ] && [ -n "$c" ] && command -v curl >/dev/null; then   # avisa por Telegram de la URL nueva
      curl -fsS -m 10 -o /dev/null "https://api.telegram.org/bot$t/sendMessage" \
        --data-urlencode "chat_id=$c" --data-urlencode "text=Panel de Patchwarden: $URL_PUBLICA" || true
    fi
  fi
}

# ================================================================== acciones

pedir_tokens() {  # central: Telegram y Claude (Intro = dejar como está / saltar)
  local actual
  interactivo || return 0
  msg "Datos opcionales (Intro para dejar como está o saltar; funciona igual solo con el panel):"
  for k in TELEGRAM_TOKEN TELEGRAM_CHAT_ID CLAUDE_CODE_OAUTH_TOKEN; do
    [ -n "${!k:-}" ] && continue
    actual="$(env_de central "$k")"
    local estado; estado="$( [ -n "$actual" ] && echo "ya configurado, Intro para conservarlo" || echo "Intro para saltar")"
    case "$k" in
      TELEGRAM_TOKEN) preguntar "$k" "Token del bot de Telegram, de @BotFather ($estado): " s ;;
      TELEGRAM_CHAT_ID) [ -n "${TELEGRAM_TOKEN:-}$(env_de central TELEGRAM_TOKEN)" ] || continue
                        preguntar "$k" "Tu chat id de Telegram, de @userinfobot ($estado): " ;;
      CLAUDE_CODE_OAUTH_TOKEN) preguntar "$k" "Token de Claude Code para pedir correcciones con tu plan, sin API; genéralo con «claude setup-token» ($estado): " s ;;
    esac
  done
}

instalar() {  # rol
  local r="$1"; ACCION_ACTUAL="instalar"
  if [ "$r" = agente ]; then
    if interactivo; then
      [ -n "$CENTRAL_URL" ] || preguntar CENTRAL_URL "URL del panel central (p. ej. https://panel.ejemplo.com): "
      [ -n "$CODIGO" ] || [ -n "$(env_de agente VIGILANTE_CODIGO)" ] \
        || preguntar CODIGO "Código de alta (en el panel central: Ajustes > Equipos > Añadir equipo): "
    fi
    [ -n "$CENTRAL_URL$(env_de agente VIGILANTE_CENTRAL)" ] || fallo "Falta la URL del panel central: --central https://..."
    case "$CENTRAL_URL" in http://localhost*|http://127.0.0.1*|https://*|"") ;;
      http://*) if [ -z "$PERMITIR_HTTP" ]; then
                  if interactivo && si_no "El central usa http:// sin cifrar. ¿Está en tu red privada o VPN?" n; then PERMITIR_HTTP=1
                  else fallo "Usa https:// para el central, o --permitir-http si va por una red privada o VPN."; fi
                fi ;;
    esac
  fi
  if [ -n "$DE_MENU" ] && interactivo && [ -z "$APLICAR" ]; then
    echo
    echo "Por defecto Patchwarden solo avisa y propone: no puede modificar tus apps."
    si_no "¿Permitir que aplique los cambios que TÚ apruebes (con copia de seguridad y vuelta atrás)?" n && APLICAR=1
    if [ "$r" = central ] && [ -z "$TUNEL" ]; then
      si_no "¿Publicar el panel en internet con un túnel gratuito de Cloudflare?" n && TUNEL=1
    fi
  fi
  [ "$r" = central ] && pedir_tokens
  export TELEGRAM_TOKEN="${TELEGRAM_TOKEN:-}" TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}" CLAUDE_CODE_OAUTH_TOKEN="${CLAUDE_CODE_OAUTH_TOKEN:-}"

  mkdir -p "$(dir_de "$r")"
  obtener_fuente "$r"
  construir "$r"
  generar_config "$r"
  guardar_conf "$r"
  msg "Arrancando..."
  arrancar "$r"
  [ "$r" = central ] && revisar_tunel
  resumen "$r"
}

actualizar() {  # rol  [rebuscar]
  local r="$1"; ACCION_ACTUAL="actualizar"
  instalado "$r" || fallo "$(nombre_de "$r") no está instalado en $(dir_de "$r")."
  cargar_opciones "$r"
  obtener_fuente "$r"
  local antes; antes="$(conf "$r" VERSION)"; antes="${antes:-$VERSION_ANTES}"
  if [ "$antes" = "$VERSION" ] && [ "$antes" != "desconocida" ]; then
    msg "$(nombre_de "$r"): ya tienes la última versión ($VERSION). Se reconstruye igualmente por si cambió la base."
  elif [ "$antes" != "desconocida" ] && [ "$VERSION" != "desconocida" ] && [ -n "$antes" ]; then
    msg "$(nombre_de "$r"): $antes -> $VERSION"
    git -C "$FUENTE" log --oneline "$antes..$VERSION" 2>/dev/null | head -20 | sed 's/^/  /' || true
  fi
  construir "$r"
  if [ -n "${2:-}" ]; then
    generar_config "$r"
  fi
  guardar_conf "$r"
  msg "Redesplegando (tokens, cuenta, datos y análisis se conservan)..."
  arrancar "$r" volver
  [ "$r" = central ] && revisar_tunel
  docker image rm "$(imagen_de "$r" | sed 's/:local$/:anterior/')" >/dev/null 2>&1 || true
  docker image prune -f >/dev/null 2>&1 || true
  resumen "$r"
}

cambiar_tokens() {
  instalado central || fallo "El panel central no está instalado."
  interactivo || fallo "Para cambiar los tokens hace falta una terminal."
  TELEGRAM_TOKEN=""; TELEGRAM_CHAT_ID=""; CLAUDE_CODE_OAUTH_TOKEN=""
  pedir_tokens
  local cambiado=""
  for k in TELEGRAM_TOKEN TELEGRAM_CHAT_ID CLAUDE_CODE_OAUTH_TOKEN; do
    [ -n "${!k}" ] && { poner central .env "$k" "${!k}"; cambiado=1; }
  done
  [ -n "$cambiado" ] || { echo "Sin cambios."; return 0; }
  compose central up -d --force-recreate vigilante >/dev/null
  echo "Tokens guardados en $(dir_de central)/.env y panel reiniciado."
}

parar() { compose "$1" down; echo "$(nombre_de "$1") parado. Datos conservados. Para arrancarlo: bash instalar.sh (menú)"; }

desinstalar() {  # rol
  local r="$1" d; d="$(dir_de "$1")"
  if interactivo; then
    echo; echo "Se borrarán los contenedores, la imagen y los DATOS de $(nombre_de "$r" | tr '[:upper:]' '[:lower:]') en $d:"
    [ "$r" = central ] && echo "  análisis, cuenta del panel, planes de corrección, consumo de Claude y equipos dados de alta."
    [ "$r" = agente ] && echo "  el alta en el panel central (habrá que pedir un código nuevo) y las copias de seguridad."
    local c; preguntar c "Escribe «borrar» para confirmar: "
    [ "$c" = "borrar" ] || { echo "Cancelado."; return 0; }
  fi
  compose "$r" down -v 2>/dev/null || true
  docker rmi "$(imagen_de "$r")" >/dev/null 2>&1 || true
  echo "$(nombre_de "$r") desinstalado. Los ficheros (tokens incluidos) siguen en $d; para borrarlos: rm -rf $d"
}

en_marcha() { [ -n "$(compose "$1" ps -q --status running "$(servicio_de "$1")" 2>/dev/null)" ]; }
estado() {
  local algo=""
  for r in central agente; do
    instalado "$r" || continue; algo=1
    printf '  %-14s %s  versión %s (%s)  %s\n' "$(nombre_de "$r")" "$(dir_de "$r")" \
      "$(conf "$r" VERSION || true)" "$(conf "$r" FECHA || true)" "$(en_marcha "$r" && echo '[en marcha]' || echo '[parado]')"
  done
  [ -n "$algo" ] || echo "  Nada instalado todavía."
}

resumen() {
  local r="$1" d; d="$(dir_de "$1")"
  if [ "$r" = agente ]; then
    cat <<EOF

================================================================
 Agente listo  (versión $VERSION)
================================================================
 Panel central:  $(env_de agente VIGILANTE_CENTRAL)
 Este servidor aparecerá en el central (Ajustes > Equipos) en cuanto se conecte.
 Modo:           $( [ -n "$APLICAR" ] && echo "puede aplicar lo que apruebes" || echo "solo propone (no modifica nada)")

 Ver logs:       docker compose -f $d/docker-compose.yml logs -f agente
 Actualizar:     bash $d/instalar.sh   (menú; o --actualizar sin preguntas)
================================================================
EOF
    return
  fi
  local usuario clave; usuario="$(env_de central VIGILANTE_PANEL_USUARIO)"; clave="$(env_de central VIGILANTE_PANEL_CLAVE)"
  cat <<EOF

================================================================
 Panel central listo  (versión $VERSION)
================================================================
 Panel:       $(env_de central VIGILANTE_PANEL_URL)
$( [ -n "$URL_PUBLICA" ] && printf ' Desde internet: %s\n   (túnel gratuito y temporal: si se reinicia, la URL cambia; para verla: bash instalar.sh --url)\n' "$URL_PUBLICA" )
 Usuario:     $usuario
 Contraseña:  $clave   (en $d/.env)

 Telegram:    $( [ -n "$(env_de central TELEGRAM_TOKEN)" ] && [ -n "$(env_de central TELEGRAM_CHAT_ID)" ] && echo configurado || echo "no configurado (los avisos salen en el panel)")
 Claude:      $( [ -n "$(env_de central CLAUDE_CODE_OAUTH_TOKEN)" ] && echo "configurado (Claude solo actúa cuando TÚ se lo pides)" || echo "no configurado (solo avisos)")

 Otros servidores: en el panel, Ajustes > Equipos > Añadir equipo te da el comando del agente.
 Ver logs:        docker compose -f $d/docker-compose.yml logs -f vigilante
 Actualizar, buscar apps nuevas, cambiar tokens, parar o desinstalar:
                  bash $d/instalar.sh   (menú; o --actualizar sin preguntas)
================================================================
EOF
}

# ================================================================== menú

menu() {
  local opciones=() acciones=() n r
  msg "Patchwarden"
  estado
  for r in central agente; do
    if instalado "$r"; then
      local nom; nom="$(nombre_de "$r" | tr '[:upper:]' '[:lower:]')"
      opciones+=("Actualizar el $nom: descarga lo nuevo de GitHub y redespliega (conserva tokens, datos y análisis)"); acciones+=("actualizar $r")
      opciones+=("Actualizar el $nom y volver a buscar apps (si has añadido o quitado webs)"); acciones+=("reconfigurar $r")
      [ "$r" = central ] && { opciones+=("Cambiar los tokens de Telegram o Claude"); acciones+=("tokens central"); }
      if en_marcha "$r"; then opciones+=("Parar el $nom"); acciones+=("parar $r")
      else opciones+=("Arrancar el $nom"); acciones+=("arrancar $r"); fi
      opciones+=("Desinstalar el $nom"); acciones+=("desinstalar $r")
    fi
  done
  instalado central || { opciones+=("Instalar el panel central (dashboard): vigila este servidor, recibe agentes y prepara correcciones con Claude"); acciones+=("instalar central"); }
  instalado agente || { opciones+=("Instalar un agente: conecta este servidor a un panel central que ya tienes"); acciones+=("instalar agente"); }
  echo; echo "¿Qué quieres hacer?"
  for n in "${!opciones[@]}"; do printf '  %d) %s\n' "$((n + 1))" "${opciones[$n]}"; done
  echo "  0) Salir"
  local e; preguntar e "Elige [1-${#opciones[@]}, 0]: "
  [ "$e" = 0 ] || [ -z "$e" ] && exit 0
  [[ "$e" =~ ^[0-9]+$ ]] && [ "$e" -ge 1 ] && [ "$e" -le "${#opciones[@]}" ] || fallo "Opción no válida."
  DE_MENU=1
  ejecutar ${acciones[$((e - 1))]}
}

ejecutar() {  # accion rol
  ROL="$2"
  case "$1" in
    instalar) instalar "$2" ;;
    actualizar) actualizar "$2" ;;
    reconfigurar) actualizar "$2" rebuscar ;;
    tokens) cambiar_tokens ;;
    parar) parar "$2" ;;
    arrancar) compose "$2" up -d >/dev/null && echo "$(nombre_de "$2") en marcha." ;;
    desinstalar) desinstalar "$2" ;;
  esac
}

# Rol al que se aplica una acción por línea de comandos: el indicado, el de la carpeta de este script
# o, si no, todos los que estén instalados
roles_objetivo() {
  if [ -n "$ROL" ]; then echo "$ROL"; return; fi
  if [ -n "$ROL_CARPETA" ]; then echo "$ROL_CARPETA"; return; fi
  local hay=""; for r in central agente; do instalado "$r" && { echo "$r"; hay=1; }; done
  [ -n "$hay" ] || fallo "No hay nada instalado en este servidor. Ejecuta: bash instalar.sh"
}

ACCION_ACTUAL=""
case "$ACCION" in
  url) U="$(url_tunel)"; [ -n "$U" ] || fallo "No hay túnel activo. Instala con: bash instalar.sh --panel --tunel"; echo "$U" ;;
  estado) estado ;;
  actualizar|reconfigurar)
    for r in $(roles_objetivo); do ejecutar "$ACCION" "$r"; done ;;
  parar) for r in $(roles_objetivo); do parar "$r"; done ;;
  desinstalar)
    R="$(roles_objetivo)"; [ "$(echo "$R" | wc -l)" -eq 1 ] || fallo "Hay panel central y agente: indica cuál con --panel o --agente."
    desinstalar "$R" ;;
  "")
    if [ -n "$ROL" ]; then
      # instalar (o, si ya está instalado, reinstalar refrescando las apps y conservando claves)
      if instalado "$ROL"; then cargar_opciones "$ROL"; actualizar "$ROL" rebuscar; else instalar "$ROL"; fi
    elif interactivo; then
      menu
    elif instalado central || instalado agente; then
      for r in $(roles_objetivo); do actualizar "$r" rebuscar; done      # comportamiento anterior: refrescar
    else
      instalar central
    fi ;;
esac
