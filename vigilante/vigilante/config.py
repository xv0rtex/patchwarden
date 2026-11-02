"""Carga de configuración: fichero TOML + variables de entorno (las variables mandan)."""
from __future__ import annotations

import copy
import os
import tomllib

DEFECTO = {
    "general": {
        "nombre_web": "Mi web",
        "intervalo_horas": 6,          # cada cuánto se vuelve a consultar CVE
        "carpeta_datos": "/datos",
        "idioma": "es",
    },
    "deteccion": {
        "docker": True,                 # leer contenedores vía /var/run/docker.sock (solo lectura)
        "docker_socket": "/var/run/docker.sock",
        "apps": {},                     # {carpeta del proyecto = "nombre de la app"} (el instalador lo rellena)
        "todos": False,                 # vigilar TODOS los contenedores salvo el propio stack (lo usa el instalador)
        "contenedores": [],             # nombres; vacío = los que tengan la etiqueta vigilante.vigilar=true
        "mismo_proyecto_compose": True, # si no hay etiquetas, vigilar el resto del mismo docker compose
        "exec_sondas": False,           # ejecutar `php -v`, `nginx -v`… dentro (más preciso, más invasivo)
        "rutas_proyecto": ["/proyecto"],# código montado en solo lectura (composer.lock, package-lock…)
        "url_web": "",                  # para leer cabeceras Server / X-Powered-By
        "manual": {},                   # {"php" = "8.2.10"} para forzar versiones
    },
    "fuentes": {
        "nvd": True,
        "nvd_api_key": "",              # opcional; con clave el límite pasa de 5 a 50 peticiones/30 s
        "osv": True,
        "kev": True,
        "epss": True,
        "fin_de_soporte": True,         # endoflife.date
    },
    "reglas": {
        "cvss_critico": 9.0,
        "epss_critico": 0.5,            # CVSS>=7 y EPSS>=0,5 también cuenta como crítico
        "kev_es_critico": True,
        "severidad_minima_aviso": "BAJA",
        "ignorar": [],                  # IDs a ignorar (falsos positivos aceptados)
    },
    "avisos": {
        "consola": True,
        "telegram_token": "",
        "telegram_chat_id": "",
        "webhook_url": "",              # POST JSON (sirve para n8n, Slack, Discord…)
        "webhook_formato": "generico",  # generico | slack | discord
        "smtp_servidor": "",
        "smtp_puerto": 587,
        "smtp_usuario": "",
        "smtp_clave": "",
        "email_de": "",
        "email_para": "",
        "recordatorio_horas": 24,       # repetir aviso de críticos sin resolver
        "telegram_usuarios": [],        # ids de usuario autorizados a aprobar (vacío = cualquiera del chat)
        "telegram_api": "https://api.telegram.org",
    },
    "claude": {
        "comando": "claude",            # Claude Code; usa tu plan de Claude, nunca una clave de API
        "oauth_token": "",              # CLAUDE_CODE_OAUTH_TOKEN (de `claude setup-token`); vacío = sesión del equipo
        "timeout_s": 1800,              # tiempo máximo de cada análisis
        "modelo": "claude-opus-5-5",
        "esfuerzo": "high",
        "modo": "a_peticion",           # a_peticion = Claude SOLO actúa cuando el usuario lo pide (por defecto);
                                        # auto = prepara planes él solo tras cada análisis
        "severidad_minima": "ALTA",     # a partir de qué severidad se ofrece / se resuelve una app entera
        "max_planes_por_solicitud": 6,  # componentes máximos al pedir «resolver toda la app»
        "max_planes_por_ciclo": 3,
        "investigar_web": True,         # leer changelogs / guías de migración con WebSearch/WebFetch
        "reintento_si_falla": True,     # si la verificación falla, Claude corrige el plan (1 vez)
    },
    "verificacion": {
        "docker_host": "",              # Docker PARA PRUEBAS (proxy con permisos de build/exec o un
                                        # host de pruebas aparte). Vacío = solo verificación estática
        "red": "",                      # red Docker para que el vigilante alcance los contenedores de prueba
        "herramientas": {},             # {composer = "composer:2", npm = "node:22-alpine"}
        "servicios": [],                # [[verificacion.servicios]] ver vigilante.ejemplo.toml
        "conservar_copias": False,
    },
    "aplicacion": {
        "salud": {},                    # {carpeta del proyecto = "http://contenedor:puerto"} comprobación por app
        "solo_lectura": False,          # True = el vigilante solo propone y verifica; no puede aplicar
        "comando_despliegue": "",       # p. ej. "docker compose -p web up -d --build php"
        "webhook_despliegue": "",       # alternativa: POST a tu CI/CD
        "timeout_despliegue_s": 900,
        "url_salud": "",                # dónde comprobar la web tras aplicar (vacío = url_web)
        "rutas_salud": ["/"],
        "espera_s": 120,
        "rollback_automatico": True,    # si la web no responde bien tras aplicar, restaurar lo anterior
        "git_commit": False,            # si el proyecto es un repo git, hacer commit del cambio
        "respaldo_imagenes": True,      # etiquetar la imagen en marcha como vigilante-respaldo:<plan>
        "contenedores": [],             # contenedores extra cuya imagen respaldar
    },
    "mantenimiento": {
        "modo": "manual",               # off | manual (botón/enlace) | auto
        "carpeta": "/mantenimiento",    # volumen compartido con el servidor web
        "comando": "",                  # alternativa: comando a ejecutar al activar
        "webhook": "",                  # alternativa: URL a la que hacer POST al activar
        "solo_kev_o_epss": True,        # en auto, exigir además KEV o EPSS alto (evita falsas alarmas)
    },
    "central": {                        # solo para el AGENTE (python -m vigilante --agente)
        "url": "",                      # https://panel-central.ejemplo
        "codigo": "",                   # código de alta de un solo uso (Ajustes › Equipos en el central)
        "permitir_http": False,         # http:// solo con localhost, salvo que se permita aquí (p. ej. en una VPN)
    },
    "panel": {
        "activo": True,
        "puerto": 8080,
        "token": "",                    # opcional: token de API para scripts (cabecera X-Token); el panel usa login
        "host": "0.0.0.0",              # 127.0.0.1 si solo se accede a través de un túnel/proxy
        "usuario": "",                  # si se dan, la cuenta del panel se crea con ellos en el primer arranque;
        "clave": "",                    # si no, se crea desde /configuracion-inicial con el código del log
        "url_publica": "",              # para enlaces en los avisos, p. ej. http://192.168.1.10:8080
    },
}

# Variables de entorno -> (sección, clave)
ENTORNO = {
    "VIGILANTE_NOMBRE_WEB": ("general", "nombre_web"),
    "VIGILANTE_INTERVALO_HORAS": ("general", "intervalo_horas"),
    "VIGILANTE_DATOS": ("general", "carpeta_datos"),
    "VIGILANTE_CONTENEDORES": ("deteccion", "contenedores"),
    "VIGILANTE_RUTAS_PROYECTO": ("deteccion", "rutas_proyecto"),
    "VIGILANTE_URL_WEB": ("deteccion", "url_web"),
    "VIGILANTE_DOCKER": ("deteccion", "docker"),
    "DOCKER_HOST": ("deteccion", "docker_socket"),
    "VIGILANTE_EXEC_SONDAS": ("deteccion", "exec_sondas"),
    "NVD_API_KEY": ("fuentes", "nvd_api_key"),
    "TELEGRAM_TOKEN": ("avisos", "telegram_token"),
    "TELEGRAM_CHAT_ID": ("avisos", "telegram_chat_id"),
    "VIGILANTE_WEBHOOK": ("avisos", "webhook_url"),
    "SMTP_SERVIDOR": ("avisos", "smtp_servidor"),
    "SMTP_USUARIO": ("avisos", "smtp_usuario"),
    "SMTP_CLAVE": ("avisos", "smtp_clave"),
    "EMAIL_PARA": ("avisos", "email_para"),
    "CLAUDE_CODE_OAUTH_TOKEN": ("claude", "oauth_token"),
    "VIGILANTE_DOCKER_PRUEBAS": ("verificacion", "docker_host"),
    "VIGILANTE_RED_PRUEBAS": ("verificacion", "red"),
    "VIGILANTE_COMANDO_DESPLIEGUE": ("aplicacion", "comando_despliegue"),
    "VIGILANTE_URL_SALUD": ("aplicacion", "url_salud"),
    "VIGILANTE_MANTENIMIENTO": ("mantenimiento", "modo"),
    "VIGILANTE_PANEL_TOKEN": ("panel", "token"),
    "VIGILANTE_PANEL_URL": ("panel", "url_publica"),
    "VIGILANTE_PANEL_PUERTO": ("panel", "puerto"),
    "VIGILANTE_PANEL_USUARIO": ("panel", "usuario"),
    "VIGILANTE_PANEL_CLAVE": ("panel", "clave"),
    "VIGILANTE_CENTRAL": ("central", "url"),
    "VIGILANTE_CODIGO": ("central", "codigo"),
    "VIGILANTE_CENTRAL_PERMITIR_HTTP": ("central", "permitir_http"),
}


def _convertir(valor: str, ejemplo):
    if isinstance(ejemplo, bool):
        return valor.strip().lower() in ("1", "true", "si", "sí", "yes", "on")
    if isinstance(ejemplo, int):
        return int(valor)
    if isinstance(ejemplo, float):
        return float(valor)
    if isinstance(ejemplo, list):
        return [v.strip() for v in valor.split(",") if v.strip()]
    return valor


def cargar(ruta: str | None = None) -> dict:
    cfg = copy.deepcopy(DEFECTO)
    ruta = ruta or os.environ.get("VIGILANTE_CONFIG", "/config/vigilante.toml")
    if ruta and os.path.exists(ruta):
        with open(ruta, "rb") as f:
            fichero = tomllib.load(f)
        for seccion, valores in fichero.items():
            if isinstance(valores, dict):
                cfg.setdefault(seccion, {}).update(valores)
    # lo cambiado desde Ajustes en el panel va encima del fichero; las variables de entorno, encima de todo
    from .ajustes import aplicar_guardados
    datos = os.environ.get("VIGILANTE_DATOS") or cfg["general"]["carpeta_datos"]
    aplicar_guardados(cfg, os.path.join(datos, "ajustes.json"))
    for var, (sec, clave) in ENTORNO.items():
        if os.environ.get(var):
            cfg[sec][clave] = _convertir(os.environ[var], DEFECTO[sec][clave])
    sock = cfg["deteccion"].get("docker_socket", "")
    if sock.startswith("unix://"):
        cfg["deteccion"]["docker_socket"] = sock[len("unix://"):]
    return cfg
