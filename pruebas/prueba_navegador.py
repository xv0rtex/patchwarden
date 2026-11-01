"""Prueba en un navegador real (Chromium vía Playwright) de la interfaz de la demo recién arrancada:
filtros, paginación, aprobar/rechazar, diálogos de confirmación, aplicar, revertir, mantenimiento y
botones del Telegram simulado. Opcional: pip install playwright && playwright install chromium

    DEMO_DIR=/tmp/vig-prev DEMO_PUERTO=8094 DEMO_CLAVE=clave-de-prueba python3 demo/demo.py &
    DEMO_CLAVE=clave-de-prueba python3 pruebas/prueba_navegador.py
"""
import os, re, time
from playwright.sync_api import sync_playwright
B = os.environ.get("DEMO_URL_LOCAL", "http://127.0.0.1:8094")
DIR = os.environ.get("DEMO_DIR", "/tmp/vig-prev")
CLAVE = os.environ["DEMO_CLAVE"]
res = []
def ok(c, t): res.append((bool(c), t)); print(("OK    " if c else "FALLO ") + t)
with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width":1440,"height":900}, http_credentials={"username":"diego","password":CLAVE})
    pg = ctx.new_page(); err=[]
    pg.on("pageerror", lambda e: err.append(str(e)))
    # Claude NO trabaja solo: hay que pedirlo. Se pide php (cancelando primero) y twig desde Componentes
    pg.goto(B+"/correcciones")
    ok(pg.locator(".item").count() == 0, "al empezar no hay ninguna corrección: Claude no ha hecho nada solo")
    pg.goto(B+"/componentes?app=ejemplo")
    fila_php = pg.locator("tbody tr", has=pg.locator("td:first-child b", has_text=re.compile(r"^php$")))
    fila_php.get_by_role("button", name="Resolver con Claude").click()
    texto_dialogo = pg.inner_text("#dlg-m")
    ok(pg.is_visible("dialog#dlg") and "Anthropic" in texto_dialogo and ".env" in texto_dialogo,
       "el diálogo explica qué se envía a Anthropic")
    pg.click("dialog button[value=no]"); time.sleep(.5)
    pg.goto(B+"/correcciones"); ok(pg.locator(".item").count() == 0, "cancelar el diálogo no pide nada a Claude")
    for nombre in ("php", "twig/twig"):
        pg.goto(B+"/componentes?app=ejemplo")
        fila = pg.locator("tbody tr", has=pg.locator("td:first-child b", has_text=re.compile("^" + re.escape(nombre) + "$")))
        fila.get_by_role("button", name="Resolver con Claude").click()
        with pg.expect_navigation(): pg.click("#dlg-ok")
    for _ in range(40):
        pg.goto(B+"/correcciones")
        if pg.locator(".item", has_text="Esperando tu decisión").count() == 2: break
        time.sleep(1)
    ok(pg.locator(".item", has_text="Esperando tu decisión").count() == 2, "tras confirmar aparecen los 2 planes pedidos, esperando decisión")
    pg.goto(B+"/componentes?app=")   # vuelve a «todas las apps»

    # desplegable de apps (la demo trae varias): filtra todas las páginas y recuerda la elección
    pg.goto(B+"/")
    opciones = pg.eval_on_selector_all("#sel-app option", "os=>os.map(o=>o.value)")
    ok(len(opciones) >= 3 and opciones[0] == "", f"desplegable con todas las apps: {opciones}")
    ok(pg.locator(".app-card").count() == len(opciones) - 1, "tarjetas de apps en el resumen")
    total = int(pg.inner_text(".kpi-v").strip())
    app = next(o for o in opciones if o and o != "ejemplo")
    with pg.expect_navigation(): pg.select_option("#sel-app", app)
    filtrado = int(pg.inner_text(".kpi-v").strip())
    ok(filtrado < total, f"al elegir «{app}» solo se cuentan sus vulnerabilidades ({filtrado} de {total})")
    ok(pg.locator(".app-card").count() == 0, "con una app elegida desaparece el listado de apps")
    pg.goto(B+"/componentes")
    nombres = pg.eval_on_selector_all("table tbody tr td:first-child b", "bs=>bs.map(b=>b.textContent)")
    ok(nombres and "nginx" not in nombres, f"Componentes solo muestra los de {app}: {nombres}")
    ok(pg.eval_on_selector("#sel-app", "s=>s.value") == app, "la elección se recuerda al cambiar de página")
    with pg.expect_navigation(): pg.select_option("#sel-app", "")
    pg.goto(B+"/")
    ok(int(pg.inner_text(".kpi-v").strip()) == total, "«Todas las apps» vuelve a mostrar todo")
    pg.screenshot(path="/tmp/caps/i-apps.png", full_page=True)
    # vulnerabilidades: filtros y paginación
    pg.goto(B+"/vulnerabilidades")
    visibles = lambda: pg.eval_on_selector_all("#t-vulns tbody tr", "rs=>rs.filter(r=>r.style.display!=='none').length")
    ok(visibles()==25, f"tabla paginada: {visibles()} filas visibles")
    pg.click("#f-mas"); ok(visibles()==75, f"Mostrar más: {visibles()}")
    pg.click(".chip[data-sev=CRITICA]"); ok(visibles()==14, f"filtro Crítica: {visibles()}")
    pg.click("#f-kev"); ok(visibles()==3, f"Crítica + solo explotadas: {visibles()}")
    pg.click("#f-kev"); pg.click(".chip[data-sev=CRITICA]"); pg.fill("#f-q","lodash"); ok(visibles()==6, f"búsqueda lodash: {visibles()}")
    pg.screenshot(path="/tmp/caps/i-vulns-filtro.png")
    # plan de php: aprobar cambio 1, rechazar 2, aplicar con diálogo, revertir
    pg.goto(B+"/correcciones")
    import glob, json
    pid = [json.load(open(f))["id"] for f in glob.glob(DIR + "/datos/planes/*.json")
           if json.load(open(f))["componente"]["nombre"] == "php"][0]
    ok(pg.locator(f"a[href='/plan/{pid}']").count() == 1, "el plan de php aparece en Correcciones")
    pg.goto(B + f"/plan/{pid}")
    url_plan = pg.url
    with pg.expect_navigation(): pg.locator("section.cambio").nth(0).locator("button[value=aprobado]").click()
    ok("Cambio 1: aprobado" in pg.inner_text(".toast"), "aprobar cambio 1 (toast)")
    with pg.expect_navigation(): pg.locator("section.cambio").nth(1).locator("button[value=rechazado]").click()
    ok("Cambio 2: rechazado" in pg.inner_text(".toast"), "rechazar cambio 2")
    pg.click("text=Aplicar 1 aprobado(s)")
    ok(pg.is_visible("dialog#dlg"), "aparece el diálogo de confirmación")
    pg.screenshot(path="/tmp/caps/i-dialogo.png")
    with pg.expect_navigation(): pg.click("#dlg-ok")
    for _ in range(30):
        pg.goto(url_plan)
        if "Aplicado" in pg.inner_text(".top"): break
        time.sleep(1)
    ok("Aplicado" in pg.inner_text(".top"), "plan aplicado tras confirmar")
    pg.screenshot(path="/tmp/caps/i-aplicado.png", full_page=True)
    pg.click("text=Revertir a como estaba")
    with pg.expect_navigation(): pg.click("#dlg-ok")
    ok("Revertido" in pg.inner_text(".toast"), "revertir con confirmación")
    # cancelar en el diálogo no hace nada
    pg.goto(B+"/mantenimiento"); pg.click("text=Poner en mantenimiento"); pg.click("dialog button[value=no]")
    time.sleep(.5); ok("está en línea" in pg.inner_text("main"), "cancelar en el diálogo no cambia nada")
    pg.click("text=Poner en mantenimiento")
    with pg.expect_navigation(): pg.click("#dlg-ok")
    ok("modo mantenimiento" in pg.inner_text("main"), "activar mantenimiento")
    pg.click("text=Volver a poner en línea")
    with pg.expect_navigation(): pg.click("#dlg-ok")
    ok("está en línea" in pg.inner_text("main"), "desactivar mantenimiento")
    # Telegram simulado: rechazar todo el plan de twig con el botón
    pg.goto(B+"/demo")
    m = pg.locator(".tg-m", has_text=re.compile(r"Propuesta de corrección · .*twig")).first
    mid = m.get_attribute("id")
    with pg.expect_navigation(): pg.locator(f"#{mid} + .tg-k button", has_text="Rechazar todo").click()
    ok("rechazado" in pg.inner_text(".toast").lower(), f"Telegram simulado: {pg.inner_text('.toast')}")
    pg.screenshot(path="/tmp/caps/i-telegram.png")
    ok(not err, f"sin errores JS {err}")
    b.close()
print(sum(c for c,_ in res), "/", len(res))
