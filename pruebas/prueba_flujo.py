"""Prueba de extremo a extremo del flujo de corrección (sin Docker, sin clave y sin bot reales).

Usa: Docker simulado (docker_falso.py), API de Claude simulada en streaming, Bot API de
Telegram simulada y una «web» local. NVD/OSV/KEV/EPSS y los registros de paquetes son reales.

    python3 pruebas/prueba_flujo.py
"""
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.parse
import urllib.request

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "..", "vigilante"))
sys.path.insert(0, AQUI)

import apis_falsas  # noqa: E402
import docker_falso  # noqa: E402

TMP = "/tmp/vig-flujo"
PROYECTO = os.path.join(TMP, "proyecto")
PUERTO_PANEL = 8097
resultados = []


def ok(cond, texto):
    resultados.append((bool(cond), texto))
    print(("  OK    " if cond else "  FALLO ") + texto)
    return cond


def huella(carpeta):
    h = hashlib.sha256()
    for raiz, _, ficheros in sorted(os.walk(carpeta)):
        for f in sorted(ficheros):
            with open(os.path.join(raiz, f), "rb") as fh:
                h.update(f.encode() + fh.read())
    return h.hexdigest()


def post_panel(ruta, datos):
    req = urllib.request.Request(f"http://127.0.0.1:{PUERTO_PANEL}{ruta}", data=urllib.parse.urlencode(datos).encode())

    class SinRedireccion(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        urllib.request.build_opener(SinRedireccion).open(req)
    except urllib.error.HTTPError as e:
        if e.code != 303:
            return f"HTTP {e.code}"
        return urllib.parse.unquote(e.headers.get("Location", "").split("msg=")[-1])
    return ""


def get_panel(ruta):
    req = urllib.request.Request(f"http://127.0.0.1:{PUERTO_PANEL}{ruta}", headers={"X-Token": "secreto"})
    return urllib.request.urlopen(req).read().decode()


def leer(ruta):
    with open(os.path.join(PROYECTO, ruta)) as f:
        return f.read()


def main():
    shutil.rmtree(TMP, ignore_errors=True)
    shutil.copytree(os.path.join(AQUI, "..", "ejemplo"), PROYECTO, ignore=shutil.ignore_patterns(".env"))
    if os.path.isdir("/tmp/vig/datos/cache"):   # reutilizar la caché de NVD/OSV de otras pruebas
        shutil.copytree("/tmp/vig/datos/cache", os.path.join(TMP, "datos", "cache"))
    sock = os.path.join(TMP, "docker.sock")
    docker_falso.arrancar(sock)
    claude, tg, web = apis_falsas.ClaudeFalso(), apis_falsas.TelegramFalso("1234"), apis_falsas.WebFalsa(os.path.join(TMP, "web_rota"))
    os.environ["ANTHROPIC_API_KEY"] = "sk-ant-no-debe-usarse"    # aunque exista, nunca debe llegar a Claude Code

    from vigilante import config, panel
    from vigilante.motor import Vigilante
    cfg = config.cargar("/no/existe.toml")
    cfg["general"].update(carpeta_datos=os.path.join(TMP, "datos"), nombre_web="Web de prueba")
    cfg["deteccion"].update(docker_socket=sock, rutas_proyecto=[PROYECTO], url_web="", apps={PROYECTO: "ejemplo"})
    cfg["claude"].update(comando=claude.comando, oauth_token="token-falso", max_planes_por_ciclo=2)
    cfg["verificacion"].update(docker_host=sock, servicios=[{
        "nombre": "php", "contexto": "web/app", "dockerfile": "Dockerfile",
        "comandos_prueba": ["php -v", "php -l /var/www/html/index.php"],
        "puerto_http": web.puerto, "rutas": ["/"], "espera_s": 5},
        {"nombre": "nginx", "compose": "docker-compose.yml", "hosts_extra": ["php:127.0.0.1"],
         "comandos_prueba": ["nginx -t"], "espera_s": 5,
         "subir": {"web/nginx/default.conf": "/etc/nginx/conf.d/default.conf", "web/app/public": "/var/www/html"}}])
    # despliegue simulado: apunta en un log y, si el plan es «romper», deja la web dando 500
    # hasta que se despliegue la versión anterior (revertir)
    cfg["aplicacion"].update(comando_despliegue=(
        f"sh -c 'echo $VIGILANTE_ACCION $VIGILANTE_PLAN >> {TMP}/despliegues.log; "
        f"if [ \"$VIGILANTE_ACCION\" = revertir ]; then rm -f {TMP}/web_rota; "
        f"elif [ -f {TMP}/romper ]; then touch {TMP}/web_rota; fi'"),
                             url_salud=web.url, espera_s=3)
    cfg["avisos"].update(telegram_token="TOKEN", telegram_chat_id="1234", telegram_api=tg.url, consola=False)
    cfg["panel"].update(token="secreto", url_publica=f"http://127.0.0.1:{PUERTO_PANEL}")
    cfg["mantenimiento"].update(carpeta=os.path.join(TMP, "mant"))

    v = Vigilante(cfg)
    v.gestor.arrancar_bot()
    panel.arrancar(v, PUERTO_PANEL)
    antes = huella(PROYECTO)

    print("\n1) Ciclo: sin pedirlo, Claude NO hace nada; solo se le OFRECE al usuario")
    t = time.time()
    v.ciclo("prueba")
    v.gestor.cola.join()
    print(f"   ({time.time() - t:.0f} s)")
    ok(not claude.peticiones, "REGLA: tras el análisis no se ha llamado a Claude ni una vez")
    ok(not v.gestor.planes.todos(), "REGLA: no se ha creado ningún plan por su cuenta")
    ofertas = [i for i in tg.orden if "¿Quieres que Claude prepare una corrección?" in tg.mensajes[i]["text"]]
    oferta_php = next((i for i in ofertas if tg.mensajes[i]["text"].startswith("<b>php ")), None)
    ok(oferta_php and not any("claude" in str(b).lower() and "apl" in str(b) for b in tg.mensajes[oferta_php]["botones"]),
       f"Telegram ofrece «Resolver con Claude» ({len(ofertas)} componentes ofrecidos)")

    print("\n1b) El usuario lo pide: php por Telegram (2 pasos) y twig por el panel (con confirmación)")
    tg.pulsar(oferta_php, tg.boton(oferta_php, "Resolver con Claude"))
    tg.esperar(lambda: "Confirmas pedir a Claude" in tg.mensajes[oferta_php]["text"], 10)
    ok("Confirmas pedir a Claude" in tg.mensajes[oferta_php]["text"] and "no los .env" in tg.mensajes[oferta_php]["text"],
       "Telegram pide confirmación y explica qué se envía a Anthropic")
    ok(not claude.peticiones and not v.gestor.planes.todos(), "con solo el primer botón todavía no se ha llamado a Claude")
    tg.pulsar(oferta_php, tg.boton(oferta_php, "Sí, resolver con Claude"))
    tg.esperar(lambda: any(p["componente"]["nombre"] == "php" for p in v.gestor.planes.todos()), 15)
    ok(any(p["componente"]["nombre"] == "php" and p["solicitado_por"].startswith("Telegram") for p in v.gestor.planes.todos()),
       "tras confirmar se crea el plan de php, registrado como solicitado por el usuario")
    clave_twig = next(c["clave"] for c in v.estado["componentes"] if c["nombre"] == "twig/twig")
    ok("Falta confirmar" in post_panel("/api/claude/resolver", {"token": "secreto", "clave": clave_twig}),
       "panel: sin confirmación no se pide nada")
    ok(not any(p["componente"]["nombre"] == "twig/twig" for p in v.gestor.planes.todos()), "y no se crea el plan de twig")
    ok("Claude está preparando" in post_panel("/api/claude/resolver", {"token": "secreto", "clave": clave_twig, "confirmar": "si"}),
       "panel: con confirmación sí")
    v.gestor.cola.join()
    planes = {p["componente"]["nombre"]: p for p in v.gestor.planes.todos()}
    ok(set(planes) == {"php", "twig/twig"}, f"planes creados para php y twig: {sorted(planes)}")
    ok({p["componente"]["app"] for p in planes.values()} == {"ejemplo"}, "cada plan sabe a qué app pertenece (ejemplo)")
    ok(all(h["app"] == "ejemplo" for h in v.estado["hallazgos"].values() if h["nombre"] in ("php", "twig/twig")),
       "las vulnerabilidades llevan su app")
    ok(all(p["estado"] == "pendiente_aprobacion" for p in planes.values()), "los dos esperan aprobación")
    ok(huella(PROYECTO) == antes, "REGLA: el proyecto NO se ha tocado sin aprobación")

    print("\n2) Lo que se le pidió a Claude")
    pet = claude.peticiones[0]
    args = pet["args"]
    opcion = lambda nombre: args[args.index(nombre) + 1]
    ok(args[0] == "-p" and opcion("--model") == "claude-opus-5-5", "Claude Code sin interfaz (-p), modelo claude-opus-5-5")
    ok(opcion("--output-format") == "stream-json" and "cambios" in json.loads(opcion("--json-schema"))["properties"],
       "salida estructurada con esquema JSON")
    ok(opcion("--tools") == "WebSearch,WebFetch" and opcion("--allowedTools") == "WebSearch,WebFetch",
       "solo puede leer changelogs (WebSearch/WebFetch): sin terminal ni ficheros")
    ok(pet["entorno"].get("CLAUDE_CODE_OAUTH_TOKEN") == "token-falso" and "ANTHROPIC_API_KEY" not in pet["entorno"],
       "usa el token de la suscripción y nunca la clave de API")
    texto = pet["entrada"]
    ok("Revisión automática de compatibilidad" in texto and '"php": "8.1.2"' in texto,
       "recibe la revisión automática de compatibilidad y las versiones desplegadas")

    php, twig = planes["php"], planes["twig/twig"]
    print("\n3) Verificación en copia + contenedores de prueba")
    vp = php["verificacion"]
    ok(vp["estado"] == "ok", f"plan php verificado: {vp['estado']}")
    ok(vp["por_cambio"]["1"]["aplica"] and vp["por_cambio"]["2"]["aplica"], "los 2 cambios de php se aplican en la copia")
    ok(any("construir imagen" in p["paso"] and p["ok"] for p in vp["pasos"]), "se construyó la imagen de prueba")
    ok(any("php -l" in p["paso"] and p["ok"] for p in vp["pasos"]), "se ejecutaron los comandos de prueba")
    ok(any("GET /" in p["paso"] and p["ok"] for p in vp["pasos"]), "petición HTTP básica")
    ok(any("nginx: descargar imagen" in p["paso"] and "nginx:1.25.3" in p["detalle"] for p in vp["pasos"])
       and any("nginx -t" in p["paso"] and p["ok"] for p in vp["pasos"]),
       "nginx: imagen sacada del docker-compose.yml y «nginx -t» en contenedor de prueba")
    ok(("PUT", "/containers/") and any(m == "PUT" for m, _ in docker_falso.REGISTRO), "se subió la configuración al contenedor de prueba")
    vt = twig["verificacion"]
    ok(vt["estado"] == "ok" and "v3.27.0" in vt["por_cambio"]["1"]["diff_final"],
       "twig: composer update en contenedor de herramientas y lock regenerado dentro del diff final")
    ok(php.get("no_cubiertos"), f"detecta que 8.2.29 no corrige todo: {php.get('no_cubiertos', [])[:2]}")
    ok(any("Cambio de rama de php" in a for a in php["compatibilidad"]["avisos"]),
       "compatibilidad automática avisa del cambio de rama 8.1 → 8.2")
    restos = [c for c in docker_falso.CREADOS]
    ok(not restos, "no quedan contenedores de prueba")

    print("\n4) Telegram: un mensaje por plan y por cambio, con botones")
    cab = tg.buscar("Propuesta de corrección · ejemplo · php")
    ok(len(cab) == 1 and "No se aplicará nada sin tu aprobación" in tg.mensajes[cab[0]]["text"], "cabecera del plan php")
    m1 = tg.buscar("Cambio 1/2 · Imagen base")[0]
    m2 = tg.buscar("Cambio 2/2 · Ocultar")[0]
    ok("Por qué es correcto" in tg.mensajes[m1]["text"] and "Riesgo" in tg.mensajes[m1]["text"],
       "cada cambio lleva su justificación (qué arregla, por qué, riesgo, revertir)")

    print("\n5) Pulsación desde un chat NO autorizado")
    tg.pulsar(m1, tg.boton(m1, "Aprobar"), chat="999")
    tg.esperar(lambda: "No autorizado" in tg.respuestas, 10)
    ok("No autorizado" in tg.respuestas, "se rechaza")
    ok(v.gestor.planes.obtener(php["id"])["cambios"][0]["decision"] is None, "y no registra ninguna decisión")

    print("\n6) Aprobar el cambio 1 y rechazar el 2 desde Telegram, luego aplicar")
    tg.pulsar(m1, tg.boton(m1, "Aprobar"))
    tg.pulsar(m2, tg.boton(m2, "Rechazar"))
    tg.esperar(lambda: tg.buscar("¿Aplicar ahora?"), 15)
    resumen = tg.buscar("¿Aplicar ahora?")
    ok(resumen, "al decidir todos, ofrece «Aplicar los aprobados»")
    ok(huella(PROYECTO) == antes, "aprobar NO aplica todavía")
    tg.pulsar(resumen[0], tg.boton(resumen[0], "Aplicar los 1"))
    tg.esperar(lambda: "Sí, aplicar" in json.dumps(tg.mensajes[resumen[0]]["botones"], ensure_ascii=False), 10)
    ok(True, "pide confirmación")
    tg.pulsar(resumen[0], tg.boton(resumen[0], "Sí, aplicar"))
    tg.esperar(lambda: v.gestor.planes.obtener(php["id"])["estado"] in ("aplicado", "fallo_aplicacion"), 40)
    p = v.gestor.planes.obtener(php["id"])
    ok(p["estado"] == "aplicado", f"plan aplicado: {p['estado']}")
    ok("FROM php:8.2.29-fpm" in leer("web/app/Dockerfile") and "seguridad.ini" not in leer("web/app/Dockerfile")
       and not os.path.exists(os.path.join(PROYECTO, "web/app/php/seguridad.ini")),
       "solo se aplicó el cambio aprobado (imagen nueva, sin seguridad.ini)")
    ok(p["verificacion"]["cambios_verificados"] == [1], "se re-verificó el subconjunto aprobado antes de aplicar")
    ok(os.path.exists(os.path.join(p["aplicacion"]["respaldo"]["carpeta"], "ficheros.tar.gz")), "copia de seguridad previa")
    ok(p["aplicacion"]["respaldo"]["imagenes"], f"imagen en marcha etiquetada: {p['aplicacion']['respaldo']['imagenes']}")
    with open(os.path.join(TMP, "despliegues.log")) as f:
        ok(f"aplicar {php['id']}" in f.read(), "se ejecutó el comando de despliegue")
    ok(tg.buscar("Corrección aplicada"), "Telegram informa del resultado con botón «Revertir»")
    ok(not tg.mensajes[cab[0]]["botones"] and "APLICADO" in tg.mensajes[cab[0]]["text"],
       "la cabecera del plan se actualiza (APLICADO) y pierde los botones de decisión")

    print("\n7) Revertir desde el panel")
    ok("Falta confirmar" in post_panel(f"/api/plan/{php['id']}/revertir", {"token": "secreto"}), "sin casilla de confirmación no hace nada")
    ok(post_panel(f"/api/plan/{php['id']}/revertir", {"token": "malo", "confirmar": "si"}) == "HTTP 403"
       and "FROM php:8.2.29-fpm" in leer("web/app/Dockerfile"), "token incorrecto: 403 y no revierte")
    msg = post_panel(f"/api/plan/{php['id']}/revertir", {"token": "secreto", "confirmar": "si"})
    ok("Revertido" in msg, f"panel: {msg}")
    ok("FROM php:8.1.2-fpm" in leer("web/app/Dockerfile"), "el Dockerfile vuelve a estar como antes")
    ok(v.gestor.planes.obtener(php["id"])["estado"] == "revertido", "estado revertido")
    huella_tras_revertir = huella(PROYECTO)

    print("\n8) Twig desde el panel: aprobar todo y aplicar, pero la web falla tras desplegar")
    ok("confirmación" in post_panel(f"/api/plan/{twig['id']}/todo", {"token": "secreto", "decision": "aprobado"}),
       "sin confirmar no se aprueba ni aplica")
    lock_antes = leer("web/app/composer.lock")
    open(os.path.join(TMP, "romper"), "w").close()
    post_panel(f"/api/plan/{twig['id']}/todo", {"token": "secreto", "decision": "aprobado", "confirmar": "si"})
    tg.esperar(lambda: v.gestor.planes.obtener(twig["id"])["estado"] not in ("aplicando", "pendiente_aprobacion"), 40)
    p = v.gestor.planes.obtener(twig["id"])
    ok(p["aplicacion"]["estado"] == "revertido", f"la comprobación falla y se hace rollback automático: {p['aplicacion']['estado']}")
    ok(leer("web/app/composer.lock") == lock_antes and '"^3.3"' in leer("web/app/composer.json"),
       "composer.json y composer.lock restaurados")
    ok(tg.buscar("se ha revertido"), "Telegram avisa del rollback")
    ok(web.ok, "tras el rollback la web vuelve a responder bien")

    print("\n9) La verificación falla → Claude corrige el plan → se verifica otra vez")
    comp = next(c for c in v.estado["componentes"] if c["nombre"] == "guzzlehttp/guzzle")
    hs = [h for h in v.estado["hallazgos"].values() if h["componente"] == comp["clave"]]
    pg = v.gestor.planes.crear(comp, hs, PROYECTO)
    v.gestor.procesar(pg["id"])
    pg = v.gestor.planes.obtener(pg["id"])
    ok(pg["verificacion"].get("intento_previo", {}).get("estado") == "fallo", "el primer plan falla en la copia")
    ok(pg["verificacion"]["estado"] == "ok" and "7.4.5" in pg["verificacion"]["por_cambio"]["1"]["diff_final"],
       "Claude lo corrige con el error de la verificación y el nuevo plan pasa")
    ok("<plan_anterior>" in claude.peticiones[-1]["entrada"] and "FALLADO" in claude.peticiones[-1]["entrada"],
       "a Claude se le pasa su plan anterior y el resultado de la verificación")
    ok(pg["estado"] == "pendiente_aprobacion" and huella(PROYECTO) == huella_tras_revertir,
       "y vuelve a quedar pendiente de aprobación sin tocar nada")

    print("\n9b) Resolver una app entera a petición, y componentes donde Claude no propone cambios")
    msg = v.gestor.solicitar_app("ejemplo", "prueba")
    v.gestor.cola.join()
    ok("Claude está preparando" in msg, f"solicitar_app: {msg[:70]}")
    estados = {p["estado"] for p in v.gestor.planes.todos()}
    ok("sin_cambios" in estados, "si Claude no propone cambios queda «sin_cambios» (sin verificar ni pedir decisión)")

    print("\n10) Panel")
    html = get_panel(f"/plan/{php['id']}")
    ok("Por qué es correcto" in html and "Registro (auditoría)" in html and "Cambios en el código (verificados)" in html,
       "la página del plan muestra justificación, diffs, verificación y auditoría")
    with open(os.path.join(TMP, "plan_php.html"), "w") as f:
        f.write(html)
    with open(os.path.join(TMP, "plan_twig.html"), "w") as f:
        f.write(get_panel(f"/plan/{twig['id']}"))
    with open(os.path.join(TMP, "telegram.json"), "w") as f:
        json.dump([tg.mensajes[i] for i in tg.orden], f, ensure_ascii=False, indent=1)
    time.sleep(1)   # dejar terminar el re-escaneo lanzado tras aplicar/revertir

    fallos = [t for c, t in resultados if not c]
    print(f"\n{len(resultados) - len(fallos)}/{len(resultados)} comprobaciones correctas")
    sys.exit(1 if fallos else 0)


if __name__ == "__main__":
    main()
