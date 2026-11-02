"""Modo demo del vigilante: panel real + Docker, Claude y Telegram SIMULADOS.

No usa ninguna clave ni acceso real:
  - Docker: simulador por socket Unix (pruebas/docker_falso.py), con contenedores de ejemplo.
  - Claude: API falsa local que devuelve planes de ejemplo (pruebas/apis_falsas.py).
  - Telegram: Bot API falsa; los mensajes se ven y se «pulsan» en /demo del panel.
  - La web «desplegada» es una copia del proyecto de ejemplo en /tmp/vig-demo/proyecto.
  - Un segundo servidor, «srv-madrid», con un AGENTE real conectado al panel por HTTP (como en
    producción): su app «tienda-web» es otra copia del ejemplo, en /tmp/vig-demo/proyecto-srv2.
Lo único real son las consultas públicas de vulnerabilidades (NVD, OSV, KEV, EPSS…).

    DEMO_CLAVE=xxxx python3 demo/demo.py      (puerto 8090 en 127.0.0.1; usuario «demo»)

Sale con código 3 cuando se pide «Reiniciar demo» (el script arrancar.sh lo vuelve a lanzar).
"""
import copy
import html
import logging
import os
import shutil
import sys
import threading
import time
import urllib.parse

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(AQUI)
sys.path.insert(0, os.path.join(RAIZ, "vigilante"))
sys.path.insert(0, os.path.join(RAIZ, "pruebas"))

import apis_falsas  # noqa: E402
import docker_falso  # noqa: E402

TMP = os.environ.get("DEMO_DIR", "/tmp/vig-demo")
PUERTO = int(os.environ.get("DEMO_PUERTO", "8090"))
E = html.escape
log = logging.getLogger("demo")


def preparar_datos():
    proyecto = os.path.join(TMP, "proyecto")
    for d in ("proyecto", "proyecto-srv2", "datos-agente", "mant-srv2",
              "datos/planes", "datos/respaldos", "datos/pruebas", "mant"):
        shutil.rmtree(os.path.join(TMP, d), ignore_errors=True)
    # la cuenta se recrea con DEMO_USUARIO/DEMO_CLAVE y los ajustes vuelven a los de la demo en cada arranque
    for f in ("datos/estado.json", "datos/cuenta.json", "datos/ajustes.json", "datos/equipos.json",
              "despliegues.log", "web_rota", "romper"):
        try:
            os.remove(os.path.join(TMP, f))
        except OSError:
            pass
    shutil.copytree(os.path.join(RAIZ, "ejemplo"), proyecto, ignore=shutil.ignore_patterns(".env"))
    shutil.copytree(os.path.join(RAIZ, "ejemplo"), os.path.join(TMP, "proyecto-srv2"), ignore=shutil.ignore_patterns(".env"))
    cache = os.path.join(TMP, "datos", "cache")
    if not os.path.isdir(cache):
        for origen in ("/tmp/vig-flujo/datos/cache", "/tmp/vig/datos/cache"):
            if os.path.isdir(origen):
                shutil.copytree(origen, cache)
                break
    return proyecto


class ExtensionDemo:
    """Rutas /demo del panel: el «móvil» con el chat del bot simulado."""

    def __init__(self, tg, vigilante):
        self.tg, self.v = tg, vigilante

    def get(self, h, ruta, q, panel, ctx):
        from vigilante import vista as V
        if ruta not in ("/demo", "/demo/"):
            return 404, "No encontrado", "text/plain"
        burbujas, hora, primera = [], time.strftime("%H:%M"), None
        for i in self.tg.orden:
            m = self.tg.mensajes[i]
            if primera is None and "Propuesta de corrección" in m["text"]:
                primera = i
                burbujas.append('<div class="tg-sep"><span>Propuestas de corrección</span></div>')
            teclado = "".join(
                "<div>" + "".join(
                    f"<form method='post' action='/demo/pulsar'><input type='hidden' name='m' value='{i}'>"
                    f"<input type='hidden' name='d' value='{E(b['callback_data'])}'><button>{E(b['text'])}</button></form>"
                    for b in fila) + "</div>" for fila in m["botones"])
            # mensajes con parse_mode=HTML: el vigilante ya escapa los datos y solo usa <b>/<i>;
            # el resto es texto plano (descripciones de CVE…) y se escapa aquí
            texto = m["text"] if m.get("html") else E(m["text"])
            burbujas.append(f"<div class='tg-m' id='m{i}'>{texto.replace(chr(10), '<br>')}<time>{hora}</time></div>"
                            + (f"<div class='tg-k'>{teclado}</div>" if teclado else ""))
        if not burbujas:
            burbujas.append('<div class="tg-sep"><span>Sin mensajes todavía</span></div>')
        telefono = f'''<div class="telefono"><div class="tg-h"><div class="tg-av">{V.icono("escudo", 20)}</div>
<div><b>Vigilante</b><small>bot · simulado</small></div></div>
<div class="tg-chat">{"".join(burbujas)}<div id="fin"></div></div>
<div class="tg-pie">{V.icono("candado", 15)}Solo atiende pulsaciones de tu chat autorizado</div></div>'''
        ir = V.boton("Ir a las propuestas", "secundario", "flecha", href=f"#m{primera}") if primera else ""
        lateral = V.tarjeta(
            "<p style='margin-top:0'>Así llegarían los avisos y las propuestas a tu Telegram. Los botones funcionan "
            "igual que en el móvil: aprobar o rechazar cada cambio, aprobar todo, aplicar (con confirmación) y "
            "revertir.</p><p class='muted'>Docker, Claude y Telegram son simulados. Lo que apliques solo modifica una "
            "copia del proyecto de ejemplo en el servidor de la demo.</p>"
            + f"<div style='display:flex;gap:10px;flex-wrap:wrap;margin-top:16px'>{ir}"
            + V.boton("Ver correcciones en el panel", "secundario", "llave", href="/correcciones") + "</div>",
            "Telegram simulado", icono_nombre="chat")
        reinicio = V.tarjeta(
            "<p style='margin-top:0' class='muted'>Vuelve al estado inicial: sin correcciones pedidas. Tarda unos 20 segundos.</p><form method='post' action='/demo/reiniciar' data-confirmar="
            "'Se borrarán las decisiones y aplicaciones hechas en la demo y se prepararán planes nuevos.' "
            "data-titulo='Reiniciar la demo' data-boton='Reiniciar'>"
            + V.boton("Reiniciar la demo", "secundario", "refrescar") + "</form>",
            "Empezar de cero", icono_nombre="refrescar")
        if q.get("r"):
            ctx = {**ctx, "msg": "Respuesta del bot: " + q["r"]}
        cuerpo = (f"<div class='grid g2b'><div>{telefono}</div><div style='display:flex;flex-direction:column;gap:18px'>"
                  f"{lateral}{reinicio}</div></div>")
        return 200, panel.envolver("Telegram (simulado)", cuerpo, "/demo", ctx,
                                   subtitulo="Los mensajes que el vigilante enviaría a tu móvil, con sus botones")

    def post(self, h, ruta, form):
        if ruta == "/demo/pulsar":
            antes = len(self.tg.respuestas)
            self.tg.pulsar(int(form["m"]), form["d"])
            self.tg.esperar(lambda: len(self.tg.respuestas) > antes, 8)
            time.sleep(0.4)
            r = self.tg.respuestas[-1] if len(self.tg.respuestas) > antes else ""
            return "redirigir", f"/demo?r={urllib.parse.quote(r)}#fin"
        if ruta == "/demo/reiniciar":
            threading.Timer(0.5, lambda: os._exit(3)).start()
            return 200, ("<!doctype html><meta charset='utf-8'><meta http-equiv='refresh' content='25;url=/demo'>"
                         "<body style='margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f5f8;"
                         "font:16px system-ui,sans-serif;color:#0f172a'><div style='background:#fff;border:1px solid #e5e7ee;"
                         "border-radius:16px;padding:32px 36px;text-align:center;box-shadow:0 12px 32px rgba(15,23,42,.08)'>"
                         "<b style='font-size:18px'>Reiniciando la demo</b><p style='color:#667085'>Preparando planes nuevos "
                         "(unos 20 segundos). Esta página se recargará sola.</p></div></body>")
        return 404, "No encontrado", "text/plain"


def arrancar_agente(v, cfg):
    """Segundo servidor simulado: un agente de verdad, dado de alta con un código y hablando por HTTP."""
    from vigilante.agente import Agente
    srv2 = os.path.join(TMP, "proyecto-srv2")
    c = copy.deepcopy(cfg)
    c["general"]["carpeta_datos"] = os.path.join(TMP, "datos-agente")
    c["deteccion"].update(docker=False, rutas_proyecto=[srv2], apps={srv2: "tienda-web"}, url_web="")
    c["mantenimiento"]["carpeta"] = os.path.join(TMP, "mant-srv2")
    c["central"].update(url=f"http://127.0.0.1:{PUERTO}")
    agente = Agente(c)
    agente.dar_de_alta(v.registro.crear_alta("srv-madrid"))
    threading.Thread(target=agente.ejecutar, daemon=True, name="agente-srv-madrid").start()
    fin = time.time() + 30
    while time.time() < fin and not any((e.get("inventario") or {}).get("componentes")
                                        for e in v.registro.activos().values()):
        time.sleep(0.2)
    log.info("Agente «srv-madrid» conectado (app tienda-web)")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                        stream=sys.stdout)
    clave = os.environ.get("DEMO_CLAVE")
    if not clave:
        sys.exit("Falta DEMO_CLAVE (contraseña de acceso al panel)")
    os.makedirs(TMP, exist_ok=True)
    proyecto = preparar_datos()

    # Varias apps en el mismo servidor, como en un LXC real: la web de ejemplo y dos más sin código montado
    docker_falso.CONTENEDORES.update({
        "ddd444": {"Name": "/blog-api", "Image": "eclipse-temurin:17.0.8_7-jre", "etiquetas": True, "proyecto": "blog",
                   "Env": ["JAVA_VERSION=jdk-17.0.8+7"], "sonda": "", "puertos": [{"PrivatePort": 8080, "PublicPort": 8080, "Type": "tcp"}]},
        "eee555": {"Name": "/tienda-db", "Image": "mysql:8.0.30", "etiquetas": True, "proyecto": "tienda",
                   "Env": ["MYSQL_VERSION=8.0.30"], "sonda": ""},
    })
    sock = os.path.join(TMP, "docker.sock")
    docker_falso.arrancar(sock)
    claude, tg = apis_falsas.ClaudeFalso(), apis_falsas.TelegramFalso("1234")
    web = apis_falsas.WebFalsa(os.path.join(TMP, "web_rota"))

    from vigilante import config, panel
    from vigilante.motor import Vigilante
    cfg = config.cargar("/no/existe.toml")
    cfg["general"].update(carpeta_datos=os.path.join(TMP, "datos"), nombre_web="Web de ejemplo (DEMO)",
                          intervalo_horas=1000)
    cfg["deteccion"].update(docker_socket=sock, rutas_proyecto=[proyecto], url_web="", apps={proyecto: "ejemplo"})
    cfg["claude"].update(comando=claude.comando, oauth_token="demo-no-es-real", max_planes_por_ciclo=2)  # Claude Code falso
    cfg["verificacion"].update(docker_host=sock, servicios=[
        {"nombre": "php", "contexto": "web/app", "dockerfile": "Dockerfile",
         "comandos_prueba": ["php -v", "php -l /var/www/html/index.php"],
         "puerto_http": web.puerto, "rutas": ["/"], "espera_s": 5},
        {"nombre": "nginx", "compose": "docker-compose.yml", "hosts_extra": ["php:127.0.0.1"],
         "comandos_prueba": ["nginx -t"], "espera_s": 5,
         "subir": {"web/nginx/default.conf": "/etc/nginx/conf.d/default.conf", "web/app/public": "/var/www/html"}}])
    cfg["aplicacion"].update(comando_despliegue=f"sh -c 'echo $(date +%T) $VIGILANTE_ACCION $VIGILANTE_PLAN >> {TMP}/despliegues.log'",
                             url_salud=web.url, espera_s=3)
    cfg["avisos"].update(telegram_token="DEMO", telegram_chat_id="1234", telegram_api=tg.url)
    cfg["mantenimiento"].update(carpeta=os.path.join(TMP, "mant"))
    cfg["panel"].update(host="127.0.0.1", puerto=PUERTO, usuario=os.environ.get("DEMO_USUARIO", "demo"),
                        clave=clave, token="", url_publica=os.environ.get("DEMO_URL", ""),
                        banner="<b>DEMO</b> Docker, Claude y Telegram simulados: no se toca nada real. Claude solo actúa cuando pulsas «Corregir con Claude» · "
                               "<a href='/demo'>Ver el Telegram simulado con los botones</a>",
                        nav_extra=[("/demo", "Telegram (simulado)", "chat")])

    v = Vigilante(cfg)
    v.gestor.arrancar_bot()
    panel.arrancar(v, PUERTO, extension=ExtensionDemo(tg, v))
    arrancar_agente(v, cfg)
    log.info("Preparando datos de ejemplo (análisis de vulnerabilidades; Claude no se usa hasta que alguien lo pida)…")
    v.ciclo("demo")
    v.gestor.cola.join()
    log.info("DEMO LISTA en http://127.0.0.1:%d (usuario %s)", PUERTO, cfg["panel"]["usuario"])
    threading.Event().wait()


if __name__ == "__main__":
    main()
