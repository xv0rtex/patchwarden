"""Panel web del vigilante.

Páginas: resumen, vulnerabilidades, componentes, correcciones (planes de Claude), detalle de
cada plan (aprobar / rechazar / aplicar / revertir) y modo mantenimiento.

Acceso: cuenta única con login (usuarios.py). Sin cuenta, todo lleva a /configuracion-inicial,
que pide el código de un solo uso del log. Cada formulario POST lleva el token CSRF de la sesión.
[panel] token, si se configura, es un token de API para scripts (cabecera X-Token o campo «token»).
"""
from __future__ import annotations

import datetime as dt
import functools
import hmac
import ipaddress
import json
import logging
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import claude, consumo, panel_ajustes
from . import vista as V
from .ajustes import Ajustes, ErrorAjuste
from .usuarios import Cuenta, ErrorCuenta
from .modelo import ORDEN_SEVERIDAD
from .planes import aprobados, pendientes
from .versiones import comparar

log = logging.getLogger("vigilante.panel")
E = V.E
TRANSITORIOS = {"analizando", "verificando", "aplicando"}


def _cookie(cabeceras, nombre):
    for trozo in (cabeceras.get("Cookie") or "").split(";"):
        k, _, v = trozo.strip().partition("=")
        if k == nombre:
            return v
    return ""


def _hora(iso: str | None) -> str:
    """'2026-10-27T09:11:27' -> '27/10 09:11'."""
    try:
        d = dt.datetime.fromisoformat(iso)
        return d.strftime("%d/%m %H:%M")
    except (TypeError, ValueError):
        return iso or "—"


def estado_verificacion_cambio(plan, c) -> tuple[str, str]:
    """(texto, tono) del resultado de verificación de un cambio concreto."""
    ver = plan.get("verificacion") or {}
    if c["n"] not in (ver.get("cambios_verificados") or []):
        return "Fuera de la última verificación (solo se verificó lo aprobado)", "neutro"
    if (ver.get("por_cambio") or {}).get(str(c["n"]), {}).get("aplica"):
        return "Se aplica limpio en la copia", "ok"
    return "No se pudo preparar en la copia", "mal"


_FORM_POST = re.compile(r'(<form\b[^>]*\bmethod=["\']?post["\']?[^>]*>)', re.I)


def con_csrf(html: str, csrf: str) -> str:
    """Añade el token CSRF de la sesión a todos los formularios POST de la página."""
    if not csrf:
        return html
    campo = f'<input type="hidden" name="csrf" value="{E(csrf, quote=True)}">'
    return _FORM_POST.sub(lambda m: m.group(1) + campo, html)


def volver_seguro(ruta: str) -> str:
    """Solo rutas internas (evita redirecciones abiertas tras el login)."""
    return ruta if ruta.startswith("/") and not ruta.startswith(("//", "/\\")) else "/"


class LimiteIntentos:
    """Bloquea una IP unos minutos tras varios intentos de contraseña fallidos (el panel puede ser público)."""

    def __init__(self, maximo=10, bloqueo_s=300):
        self.maximo, self.bloqueo_s = maximo, bloqueo_s
        self._f: dict[str, tuple[int, float]] = {}
        self._l = threading.Lock()

    def restante(self, ip: str, ahora: float | None = None) -> int:
        """Segundos de bloqueo que le quedan a esa IP (0 si puede intentarlo)."""
        ahora = time.time() if ahora is None else ahora
        with self._l:
            return max(0, int(self._f.get(ip, (0, 0))[1] - ahora))

    def fallo(self, ip: str, ahora: float | None = None):
        ahora = time.time() if ahora is None else ahora
        with self._l:
            n, hasta = self._f.get(ip, (0, 0.0))
            n = n + 1 if hasta <= ahora else n
            self._f[ip] = (0, ahora + self.bloqueo_s) if n >= self.maximo else (n, 0.0)

    def acierto(self, ip: str):
        with self._l:
            self._f.pop(ip, None)


class Panel:
    def __init__(self, vigilante):
        self.v = vigilante
        self.cfg = vigilante.cfg["panel"]
        self.cuenta = Cuenta(vigilante.datos)
        self.ajustes = Ajustes(vigilante.cfg, vigilante.datos)
        if not self.cuenta.existe():
            if self.cfg.get("usuario") and self.cfg.get("clave"):
                # migración desde la contraseña HTTP Basic: la cuenta se crea con esas credenciales
                self.cuenta.crear(self.cfg["usuario"], self.cfg["clave"], validar=False)
            else:
                log.warning("Panel sin cuenta: abre /configuracion-inicial y usa este código para crearla: %s",
                            self.cuenta.codigo_inicial())

    def token_ok(self, token):
        esperado = self.cfg.get("token") or ""
        return bool(esperado) and hmac.compare_digest(esperado, token or "")

    # ------------------------------------------------------------------ utilidades comunes
    def _planes(self):
        return self.v.gestor.planes.todos()

    def _resumen_apps(self) -> dict:
        """{app: {vulns, crit, comps, pend, contenedores}} de todo lo detectado."""
        est = self.v.estado
        apps: dict[str, dict] = {}
        nuevo = lambda: {"vulns": 0, "crit": 0, "comps": 0, "pend": 0, "contenedores": set()}  # noqa: E731
        for c in est.get("componentes", []):
            if c.get("app"):
                d = apps.setdefault(c["app"], nuevo())
                d["comps"] += 1
                d["contenedores"].update(x.strip() for x in (c.get("contenedor") or "").split(",") if x.strip())
        for h in est.get("hallazgos", {}).values():
            if h.get("app"):
                d = apps.setdefault(h["app"], nuevo())
                d["vulns"] += 1
                d["crit"] += 1 if h["critico"] else 0
        for p in self._planes():
            a = p["componente"].get("app")
            if a in apps and p["estado"] == "pendiente_aprobacion":
                apps[a]["pend"] += 1
        return dict(sorted(apps.items(), key=lambda kv: (-kv[1]["crit"], kv[0])))

    def _datos(self, ctx):
        """(hallazgos, componentes, planes) de la app elegida en el desplegable (o de todas)."""
        est, app = self.v.estado, ctx.get("app", "")
        hs = list(est.get("hallazgos", {}).values())
        comps = list(est.get("componentes", []))
        planes = self._planes()
        if app:
            hs = [h for h in hs if h.get("app") == app]
            comps = [c for c in comps if c.get("app") == app]
            planes = [p for p in planes if p["componente"].get("app") == app]
        return hs, comps, planes

    def envolver(self, titulo, cuerpo, activo="/", ctx=None, **kw):
        ctx = ctx or {}
        hs_f, _, planes = self._datos(ctx)
        pendientes_n = sum(1 for p in planes if p["estado"] == "pendiente_aprobacion")
        criticas = sum(1 for h in hs_f if h["critico"])
        apps, selector = self._resumen_apps(), ""
        if len(apps) > 1 and not activo.startswith("/ajustes"):
            sel = ctx.get("app", "")
            ops = f'<option value="">Todas las apps ({len(apps)})</option>' + "".join(
                f'<option value="{E(a, quote=True)}"{" selected" if a == sel else ""}>{E(a)} · {d["vulns"]} vuln.'
                f'{(", " + str(d["crit"]) + " críticas") if d["crit"] else ""}</option>' for a, d in apps.items())
            selector = f'<label class="sel"><span>App</span><select id="sel-app" aria-label="App">{ops}</select></label>'
        aviso = self.cfg.get("banner") or ""
        if aviso:
            aviso = f'<div class="aviso-demo">{aviso}</div>'
        extra_nav = self.cfg.get("nav_extra") or []
        html = V.pagina(titulo, cuerpo, activo=activo, web=self.v.cfg["general"]["nombre_web"], aviso=aviso,
                        toast=ctx.get("msg", ""), badges={"/correcciones": pendientes_n,
                                                          "/vulnerabilidades": criticas},
                        extra_nav=extra_nav, dialogo_token=False, selector=selector,
                        usuario=ctx.get("usuario", ""), **kw)
        return con_csrf(html, ctx.get("csrf", ""))

    def _form_resolver(self, campos: str, texto: str, etiqueta: str, consulta: dict, tamano_pequeno=True) -> str:
        """Formulario con ventana de confirmación: el usuario inicia EXPLÍCITAMENTE la resolución con Claude."""
        pequeno = 'style="padding:4px 12px"' if tamano_pequeno else ""
        aviso = (" Se enviarán a Anthropic, a través de Claude Code, las vulnerabilidades y los ficheros de despliegue del "
                 "proyecto (nunca los .env ni los datos de la app), y consume uso de tu plan de Claude. Claude solo "
                 "propone: no se modificará nada hasta que apruebes cada cambio.")
        # data-claude: el diálogo muestra la elección de modelo/razonamiento y pide la estimación al abrirse
        return (f'<form method="post" action="/api/claude/resolver" data-confirmar="{E(texto + aviso, quote=True)}" '
                f'data-titulo="Corregir con Claude" data-boton="Sí, corregir con Claude" '
                f'data-claude="{E(urllib.parse.urlencode(consulta), quote=True)}">{campos}'
                f'{V.boton(etiqueta, "secundario", "robot", attrs=pequeno)}</form>')

    def estimacion(self, q: dict) -> dict:
        """Para el diálogo de «Corregir con Claude»: estimaciones por modelo y razonamiento + estado del plan."""
        g = self.v.gestor
        if q.get("app"):
            comps = g.candidatos_app(q["app"])
        else:
            comps = [c for c in self.v.estado.get("componentes", []) if c["clave"] == q.get("clave")]
        m, e = g.eleccion()
        lim = g.consumo.limites()
        return {"defecto": f"{m}|{e}", "n": len(comps), "estimaciones": g.estimaciones(comps),
                "limites": {k: {"uso": w["uso"], "reinicio": consumo.hora_reinicio(w.get("reinicio")),
                                "reiniciada": bool(w.get("reiniciada"))}
                            for k, w in lim["ventanas"].items() if w},
                "medido": _hora(dt.datetime.fromtimestamp(lim["fecha"]).isoformat(timespec="seconds"))
                if lim.get("fecha") else ""}

    def _celda_resolver(self, c: dict) -> str:
        estado, dato = self.v.gestor.estado_resolver(c)
        if estado == "plan":
            return f'<a href="/plan/{E(dato)}">Ver el plan</a>'
        if estado == "disponible":
            return self._form_resolver(f'<input type="hidden" name="clave" value="{E(c["clave"], quote=True)}">',
                                       f"Claude preparará una corrección para {c['nombre']} {c['version']}"
                                       f"{self._resumen_cambio(c)}.", "Corregir con Claude", {"clave": c["clave"]})
        return f'<span class="muted peq">{E(dato) if estado != "sin_vulns" else "—"}</span>'

    def _resumen_cambio(self, c: dict) -> str:
        """' (3 vulnerabilidades: 1 crítica, 2 altas; versiones con fix: 8.1.29)' para el diálogo de confirmación."""
        hs = [h for h in self.v.estado.get("hallazgos", {}).values() if h["componente"] == c["clave"]]
        if not hs:
            return ""
        partes = [f"{n} {V.NOMBRE_SEV[s].lower()}" for s, _ in V.SEVERIDADES
                  for n in [sum(1 for h in hs if h["severidad"] == s)] if n]
        fix = {v for h in hs for v in (h.get("corregido_en") or []) if v[:1].isdigit()}
        texto = f" ({len(hs)} vulnerabilidad(es): {', '.join(partes)}"
        if not fix:
            return texto + ")"
        mayor = max(fix, key=functools.cmp_to_key(comparar))
        return texto + f"; la versión con fix más alta es la {mayor})"

    def _boton_resolver_app(self, ctx) -> str:
        app = ctx.get("app", "")
        if not app:
            return ""
        n = len(self.v.gestor.candidatos_app(app))
        if not n:
            return ""
        return self._form_resolver(f'<input type="hidden" name="app" value="{E(app, quote=True)}">',
                                   f"Claude preparará correcciones para {n} componente(s) de {app} con vulnerabilidades "
                                   "importantes (una por componente).", f"Corregir {app} con Claude", {"app": app}, False)

    def _boton_analizar(self):
        en_curso = self.v.en_curso
        return (f'<form method="post" action="/api/escanear">'
                f'{V.boton("Analizando…" if en_curso else "Analizar ahora", "secundario", "refrescar", attrs="disabled" if en_curso else "")}'
                f'</form>')

    def _subtitulo(self):
        ciclo = (self.v.estado.get("ciclos") or [{}])[0]
        m = self.v.mant.info()
        estado = "en mantenimiento" if m["activo"] else "en línea"
        return (f"Último análisis {E(_hora(ciclo.get('fin')))} · web {estado} · "
                f"fuentes NVD, OSV.dev, CISA KEV, EPSS y endoflife.date")

    # ------------------------------------------------------------------ resumen
    def inicio(self, ctx):
        est = self.v.estado
        hs, comps, planes = self._datos(ctx)
        apps = self._resumen_apps()
        pend = [p for p in planes if p["estado"] == "pendiente_aprobacion"]
        criticas = [h for h in hs if h["critico"]]
        kev = [h for h in hs if h.get("kev")]
        sin_soporte = [c for c in comps if (est.get("info_ramas", {}).get(c["clave"]) or {}).get("sin_soporte")]

        partes = []
        if pend:
            n_c = sum(len(p["cambios"]) for p in pend)
            partes.append(f'''<div class="banner banner-info">{V.icono("llave", 22)}<div><b>{len(pend)} corrección(es) esperan
tu decisión</b><p>Claude ha preparado {n_c} cambio(s) y se han verificado en una copia. No se aplicará nada hasta que lo apruebes.</p></div>
{V.boton("Revisar correcciones", "primario", "flecha", href="/correcciones")}</div>''')
        if self.v.mant.activo():
            partes.append(f'''<div class="banner banner-mal">{V.icono("power", 22)}<div><b>La web está en modo mantenimiento</b>
<p>{E(self.v.mant.info().get("motivo", ""))}</p></div>{V.boton("Gestionar", "secundario", href="/mantenimiento")}</div>''')

        k_vulns = V.kpi("Vulnerabilidades activas", len(hs), f"en {len({h['componente'] for h in hs})} componentes",
                        clave="vulns")
        k_pend = V.kpi("Correcciones pendientes", len(pend), "esperan tu aprobación", "acc" if pend else "ok",
                       href="/correcciones", clave="pend")
        if ctx.get("app"):
            d = self._datos_web(ctx["app"])
            kpis = [k_vulns,
                    V.kpi("Críticas", len(criticas), "CVSS ≥ 9, explotadas o EPSS alto", "crit" if criticas else "ok",
                          href=self._url_filtro("CRITICA", ctx), clave="crit"),
                    V.kpi("Explotadas activamente", len(kev), "catálogo CISA KEV", "crit" if kev else "ok", clave="kev"),
                    V.kpi("Componentes desactualizados", len(d["desact"]), f"de {len(comps)} vigilados",
                          "alta" if d["desact"] else "ok", href="/componentes", clave="desact"),
                    k_pend]
        else:
            datos = {a: self._datos_web(a) for a in apps}
            con_crit = sum(1 for d in datos.values() if d["cuenta"]["CRITICA"])
            con_alta = sum(1 for d in datos.values() if d["cuenta"]["ALTA"])
            desact = sum(1 for d in datos.values() if d["desact"])
            kpis = [V.kpi("Webs vigiladas", len(apps), f"{len(comps)} componentes en total", clave="webs"),
                    V.kpi("Con vulnerabilidades críticas", con_crit, f"{len(criticas)} críticas en total",
                          "crit" if con_crit else "ok", clave="webs-crit"),
                    V.kpi("Con vulnerabilidades altas", con_alta, "CVSS 7 a 8,9", "alta" if con_alta else "ok",
                          clave="webs-alta"),
                    V.kpi("Desactualizadas", desact, f"{len(sin_soporte)} componentes sin soporte" if sin_soporte
                          else "todo con soporte", "media" if desact else "ok", clave="webs-desact"),
                    k_vulns, k_pend]
        partes.append('<div class="kpis">' + "".join(kpis) + "</div>")

        if not ctx.get("app"):
            partes.append(self._tabla_webs(apps))
        # gráfico: vulnerabilidades por componente y gravedad
        por_comp: dict[str, dict] = {}
        nombres = {}
        for h in hs:
            por_comp.setdefault(h["componente"], {}).setdefault(h["severidad"], 0)
            por_comp[h["componente"]][h["severidad"]] += 1
            nombres[h["componente"]] = f"{h['nombre']} {h['version']}"
        orden = sorted(por_comp, key=lambda k: (-por_comp[k].get("CRITICA", 0), -sum(por_comp[k].values())))[:9]
        tope = max((sum(por_comp[k].values()) for k in orden), default=1)
        barras = "".join(V.barra_gravedad(por_comp[k], tope, nombres[k],
                                          "/vulnerabilidades?q=" + urllib.parse.quote(nombres[k].split(" ")[0]))
                         for k in orden) or V.vacio("Sin vulnerabilidades activas")
        grafico = V.tarjeta(V.leyenda_gravedad() + barras, "Vulnerabilidades por componente",
                            V.boton("Ver todas", "secundario", "flecha", href="/vulnerabilidades",
                                    attrs='style="padding:4px 12px"'), icono_nombre="alerta")

        m = self.v.mant.info()
        ew = (f'<div class="estado-web"><div class="ew-i {"ew-off" if m["activo"] else "ew-on"}">'
              f'{V.icono("power" if m["activo"] else "pulso", 26)}</div><div><b>'
              f'{"En mantenimiento" if m["activo"] else "Web en línea"}</b>'
              f'<span class="muted peq">{E(m.get("motivo", "Sirviendo con normalidad"))}</span></div></div>')
        ramas = ""
        if sin_soporte:
            ramas = '<div style="margin-top:16px">' + "".join(
                f'<div class="callout">{V.icono("alerta", 18)}<div><b>{E(c["nombre"])} {E(c["version"])}</b> sin parches '
                f'de seguridad desde {E(str((est["info_ramas"][c["clave"]] or {}).get("fin_soporte")))}</div></div>'
                for c in sin_soporte) + "</div>"
        lateral = V.tarjeta(ew + ramas, "Estado de la web", icono_nombre="pulso")
        partes.append(f'<div class="grid g2">{grafico}{lateral}</div>')

        # correcciones pendientes + lo más urgente
        filas_p = "".join(self._item_plan(p) for p in pend[:5]) or V.vacio("No hay correcciones pendientes")
        urgentes = sorted(hs, key=lambda h: (not h["critico"], not h.get("kev"), -ORDEN_SEVERIDAD[h["severidad"]],
                                             -(h.get("cvss") or 0)))[:6]
        filas_u = "".join(f'''<tr><td>{V.sev(h["severidad"])}</td><td class="mono">{self._enlace_cve(h)}{self._tags(h)}</td>
<td><b>{E(h["nombre"])}</b> <span class="muted">{E(h["version"])}</span>{self._app_txt(h, ctx)}</td><td class="num">{h.get("cvss") or "—"}</td></tr>'''
                          for h in urgentes)
        t_urg = (f'<div class="tabla"><table><thead><tr><th>Gravedad</th><th>Identificador</th><th>Componente</th>'
                 f'<th class="num">CVSS</th></tr></thead><tbody>{filas_u}</tbody></table></div>') if urgentes \
            else V.vacio("Nada urgente")
        partes.append(f'<div class="grid g2">{V.tarjeta(f"<div class=lista>{filas_p}</div>", "Correcciones pendientes", icono_nombre="llave")}'
                      f'{V.tarjeta(t_urg, "Lo más urgente", icono_nombre="alerta")}</div>')
        return self.envolver("Resumen", "".join(partes), "/", ctx, subtitulo=self._subtitulo(),
                             acciones=self._boton_resolver_app(ctx) + self._boton_analizar(),
                             refrescar=6 if self.v.en_curso else 0)

    # ------------------------------------------------------------------ webs (apps)
    ESTADOS_WEB = {"critica": ("Crítica", "mal"), "vulnerable": ("Vulnerable", "aviso"),
                   "desactualizada": ("Desactualizada", "info"), "ok": ("Al día", "ok")}

    def _url_web(self, app: str) -> str:
        """URL con la que se comprueba la web (por app o la general); solo para mostrarla."""
        apl = self.v.cfg.get("aplicacion", {})
        url = (apl.get("salud") or {}).get(self.v.apps_dirs.get(app, ""), "")
        if not url and len(self._resumen_apps()) <= 1:
            url = self.v.cfg["deteccion"].get("url_web") or apl.get("url_salud") or ""
        return url

    def _datos_web(self, app: str) -> dict:
        """Lo que muestran la tabla de webs y la ficha del detalle para una app."""
        est = self.v.estado
        ramas = est.get("info_ramas", {})
        cuenta = {s: 0 for s, _ in V.SEVERIDADES}
        for h in est.get("hallazgos", {}).values():
            if h.get("app") == app and h["severidad"] in cuenta:
                cuenta[h["severidad"]] += 1
        comps = [c for c in est.get("componentes", []) if c.get("app") == app]
        con_rama = [c for c in comps if ramas.get(c["clave"])]
        desact = [c for c in con_rama
                  if ramas[c["clave"]].get("desactualizada") or ramas[c["clave"]].get("sin_soporte")]
        # versión que se enseña: el runtime principal, preferentemente uno con versión más nueva disponible
        principal = (desact or con_rama or [c for c in comps if c["tipo"] == "runtime"] or [None])[0]
        if cuenta["CRITICA"]:
            estado = "critica"
        elif cuenta["ALTA"]:
            estado = "vulnerable"
        elif desact:
            estado = "desactualizada"
        else:
            estado = "ok"
        ultima = (ramas.get(principal["clave"]) or {}).get("ultima_de_rama") if principal else None
        return {"cuenta": cuenta, "comps": comps, "desact": desact, "principal": principal, "estado": estado,
                "ultima": str(ultima) if ultima else None, "url": self._url_web(app)}

    @staticmethod
    def _celda_version(d: dict) -> str:
        c = d["principal"]
        if not c:
            return '<span class="muted">—</span>'
        extra = (f'<div class="muted peq">{len(d["desact"])} componentes desactualizados</div>'
                 if len(d["desact"]) > 1 else "")
        return f'<div class="web-v"><b>{E(c["nombre"])}</b> {V.version_salto(c["version"], d["ultima"])}{extra}</div>'

    def _tabla_webs(self, apps: dict) -> str:
        ciclo = (self.v.estado.get("ciclos") or [None])[0]
        titulo, ic = f"Webs vigiladas ({len(apps)})", "globo"
        if not apps:
            if self.v.en_curso:
                cuerpo = V.cargando("Analizando: las webs aparecerán aquí en cuanto termine.")
            elif not ciclo:
                cuerpo = V.error("Todavía no se ha completado ningún análisis. Pulsa «Analizar ahora» y, si "
                                 "vuelve a fallar, revisa los registros del contenedor.")
            else:
                cuerpo = V.vacio("No se ha detectado ninguna web (proyecto docker compose) en el último análisis.",
                                 "info")
            return V.tarjeta(cuerpo, titulo, icono_nombre=ic)
        escaneo = _hora(ciclo.get("fin")) if ciclo else "—"
        filas = []
        for app, resumen in apps.items():
            d = self._datos_web(app)
            texto_e, tono = self.ESTADOS_WEB[d["estado"]]
            orden_e = list(self.ESTADOS_WEB).index(d["estado"])
            pend = (f'<div class="peq" style="margin-top:4px">{V.pill(str(resumen["pend"]) + " pendiente(s) de aprobar", "aviso")}</div>'
                    if resumen["pend"] else "")
            url = (f'<span class="url" title="{E(d["url"])}">{V.icono("externo", 12)}{E(d["url"])}</span>'
                   if d["url"] else '<span class="url">sin URL configurada</span>')
            href = "/vulnerabilidades?app=" + urllib.parse.quote(app)
            c = d["principal"]
            texto = f'{app} {d["url"]} {" ".join(x["nombre"] for x in d["comps"])}'.lower()
            celdas_sev = "".join(f'<td class="num" data-l="{E(n)}s" data-v="{d["cuenta"][s]}">'
                                 f'{V.contador_sev(d["cuenta"][s], s)}</td>' for s, n in V.SEVERIDADES)
            filas.append(
                f'<tr data-href="{E(href)}" data-estado="{d["estado"]}" data-texto="{E(texto)}">'
                f'<td class="td-n" data-v="{E(app)}"><div class="web-n"><b><a href="{E(href)}">{E(app)}</a></b>{url}</div></td>'
                f'<td data-l="Versión" data-v="{E(c["nombre"] if c else "")}">{self._celda_version(d)}</td>'
                f'<td data-l="Estado" data-v="{orden_e}">{V.pill(texto_e, tono)}{pend}</td>{celdas_sev}'
                f'<td data-l="Último escaneo" data-v="{E((ciclo or {}).get("fin", ""))}"><span class="mono peq">{E(escaneo)}</span></td></tr>')
        filtros = V.filtros("#t-webs", "Buscar web, URL o componente", "webs",
                            [("estado", k, V.ICONO_TONO[t], n) for k, (n, t) in self.ESTADOS_WEB.items()], abajo=True)
        cabecera = (V.th("Web") + V.th("Versión actual → última") + V.th("Estado", "num")
                    + "".join(V.th(n + "s", "num", "num") for _, n in V.SEVERIDADES) + V.th("Último escaneo"))
        tabla = (f'{filtros}<div class="tabla tabla-sola"><table id="t-webs" class="ancha"><thead><tr>{cabecera}'
                 f'</tr></thead><tbody>{"".join(filas)}</tbody></table></div>'
                 + V.sin_coincidencias("#t-webs", "Ninguna web coincide con estos filtros."))
        return V.tarjeta(tabla, titulo, '<span class="muted peq">Pulsa una web para ver sus vulnerabilidades</span>',
                         icono_nombre=ic)

    def _ficha_web(self, app: str) -> str:
        """Cabecera del detalle de una web: URL, estado, versión y recuento por gravedad."""
        d = self._datos_web(app)
        texto_e, tono = self.ESTADOS_WEB[d["estado"]]
        ciclo = (self.v.estado.get("ciclos") or [{}])[0]
        url = (f'<a href="{E(d["url"])}" target="_blank" rel="noopener" class="mono">{E(d["url"])}</a>'
               if d["url"].startswith(("http://", "https://")) else '<span class="muted">sin URL configurada</span>')
        cuentas = " ".join(f'<span>{V.contador_sev(d["cuenta"][s], s)}<span class="muted peq"> {E(n.lower())}</span></span>'
                           for s, n in V.SEVERIDADES)
        return V.tarjeta(
            '<dl class="ficha">'
            f'<div><dt>URL</dt><dd>{url}</dd></div>'
            f'<div><dt>Estado</dt><dd>{V.pill(texto_e, tono)}</dd></div>'
            f'<div><dt>Versión actual → última</dt><dd>{self._celda_version(d)}</dd></div>'
            f'<div><dt>Vulnerabilidades</dt><dd>{cuentas}</dd></div>'
            f'<div><dt>Último escaneo</dt><dd class="mono">{E(_hora(ciclo.get("fin")))}</dd></div></dl>',
            app, icono_nombre="globo")

    def _item_plan(self, p):
        a = p.get("analisis") or {}
        c = p["componente"]
        destino = a.get("version_objetivo") or "…"
        n_ap = len(aprobados(p))
        detalle = f"{len(p['hallazgos'])} vulnerabilidades · {len(p['cambios'])} cambio(s)"
        if c.get("app"):
            detalle = f"{c['app']} · " + detalle
        if n_ap:
            detalle += f" · {n_ap} aprobado(s)"
        return f'''<div class="item"><div class="item-i">{V.icono("caja", 20)}</div>
<div class="item-c"><b>{E(c["nombre"])}</b><span class="version"><span class="de">{E(c["version"])}</span>{V.icono("flecha", 14)}
<span class="a">{E(destino)}</span></span><br><small>{E(detalle)}</small></div>
<div class="item-x">{V.estado_verif((p.get("verificacion") or {}).get("estado"))}{V.estado_plan(p["estado"])}
{V.boton("Revisar", "secundario", "flecha", href=f"/plan/{p['id']}", attrs='style="padding:4px 12px"')}</div></div>'''

    @staticmethod
    def _url_filtro(sev: str, ctx) -> str:
        q = {"sev": sev} | ({"app": ctx["app"]} if ctx.get("app") else {})
        return "/vulnerabilidades?" + urllib.parse.urlencode(q)

    def _app_txt(self, x, ctx) -> str:
        """Nombre de la app bajo el componente, solo cuando se están viendo varias a la vez."""
        if ctx.get("app") or not x.get("app") or len(self._resumen_apps()) < 2:
            return ""
        return f'<div class="muted peq">{E(x["app"])}</div>'

    @staticmethod
    def _enlace_cve(h):
        url = (h.get("referencias") or [None])[0]
        if h["id"].startswith("CVE-"):
            url = f"https://nvd.nist.gov/vuln/detail/{h['id']}"
        return f'<a href="{E(url)}" target="_blank" rel="noopener">{E(h["id"])}</a>' if url else E(h["id"])

    @staticmethod
    def _tags(h):
        t = '<span class="tag tag-kev" title="En el catálogo CISA de vulnerabilidades explotadas">Explotada</span>' \
            if h.get("kev") else ""
        return t

    # ------------------------------------------------------------------ vulnerabilidades
    def vulnerabilidades(self, ctx):
        """Detalle de vulnerabilidades: de una web (si hay app elegida) o de todas."""
        hs = sorted(self._datos(ctx)[0],
                    key=lambda h: (not h["critico"], not h.get("kev"), -ORDEN_SEVERIDAD[h["severidad"]],
                                   -(h.get("cvss") or 0)))
        planes = {p["componente"]["clave"]: p for p in reversed(self._planes())}
        comps = {c["clave"]: c for c in self.v.estado.get("componentes", [])}
        celdas_accion: dict[str, str] = {}      # una vez por componente: estado_resolver no es gratis

        def accion(h):
            clave = h["componente"]
            if clave not in celdas_accion:
                c = comps.get(clave)
                celda = self._celda_resolver(c) if c else '<span class="muted">—</span>'
                pl = planes.get(clave)
                if pl and not (c and self.v.gestor.estado_resolver(c)[0] == "plan"):
                    estado_pl = V.ESTADOS_PLAN.get(pl["estado"], (pl["estado"],))[0]
                    celda += f'<div class="peq"><a href="/plan/{pl["id"]}">Último plan: {E(estado_pl.lower())}</a></div>'
                celdas_accion[clave] = celda
            return celdas_accion[clave]

        filas = []
        for i, h in enumerate(hs):
            epss = h.get("epss")
            epss_html = (f'<div class="meter"><b>{epss:.0%}</b><span><i style="width:{max(epss * 100, 3):.0f}%"></i>'
                         f'</span></div>') if epss is not None else '<span class="muted">—</span>'
            fix = h.get("corregido_en") or []
            fix_html = (f'<span class="mono fix">{E(", ".join(fix))}</span>' if fix
                        else '<span class="muted peq">Sin versión con fix</span>')
            texto = f"{h['id']} {h['nombre']} {h['version']} {h.get('app', '')} {h['resumen']}".lower()
            filas.append(
                f'<tr data-sev="{h["severidad"]}" data-kev="{1 if h.get("kev") else 0}" data-texto="{E(texto)}">'
                f'<td data-v="{ORDEN_SEVERIDAD[h["severidad"]]}">{V.sev(h["severidad"])}</td>'
                f'<td class="td-cve" data-v="{E(h["id"])}"><span class="mono">{self._enlace_cve(h)}</span>{self._tags(h)}'
                f'<div class="clamp muted peq" title="{E(h["resumen"])}">{E(h["resumen"])}</div>'
                f'<div class="muted peq">{E(h["fuente"])} · {E(h.get("publicado") or "")}</div></td>'
                f'<td data-v="{E(h["nombre"])}"><b>{E(h["nombre"])}</b>{self._app_txt(h, ctx)}</td>'
                f'<td class="mono" data-v="{E(h["version"])}">{E(h["version"])}</td>'
                f'<td data-v="{E(fix[0] if fix else "")}">{fix_html}</td>'
                f'<td class="num" data-v="{h.get("cvss") or 0}">{h.get("cvss") or "—"}</td>'
                f'<td class="num" data-v="{epss or 0}">{epss_html}</td>'
                f'<td class="accion">{accion(h)}</td></tr>')
        chips = "".join(f'<button class="chip" data-sev="{s}" type="button">{V.sev(s)}</button>' for s, _ in V.SEVERIDADES)
        filtros = f'''<div class="filtros"><label class="buscar">{V.icono("buscar", 16)}<input id="f-q" type="search"
placeholder="Buscar CVE, componente o texto" aria-label="Buscar vulnerabilidades"></label>{chips}
<button class="chip" id="f-kev" type="button">{V.icono("alerta", 14)}Solo explotadas</button>
<span class="contador" id="f-n"></span></div>'''
        boton_mas = V.boton("Mostrar más", "secundario", "flecha", attrs='id="f-mas" type="button" hidden')
        cabecera = (V.th("Gravedad", "num") + V.th("CVE y descripción") + V.th("Componente") + V.th("Versión afectada")
                    + V.th("Versión con fix") + V.th("CVSS", "num", "num") + V.th("EPSS", "num", "num")
                    + "<th>Corrección</th>")
        if filas:
            tabla = (f'<div class="tabla"><table id="t-vulns" class="ancha"><thead><tr>{cabecera}</tr></thead>'
                     f'<tbody>{"".join(filas)}</tbody></table></div><div class="mas">{boton_mas}</div>')
        elif self.v.en_curso:
            tabla = V.cargando("Analizando: las vulnerabilidades aparecerán aquí en cuanto termine.")
        elif not self.v.estado.get("ciclos"):
            tabla = V.error("Todavía no se ha completado ningún análisis. Pulsa «Analizar ahora».")
        else:
            tabla = V.vacio("Sin vulnerabilidades activas")
        app = ctx.get("app", "")
        ficha = self._ficha_web(app) if app else ""
        cuerpo = ficha + (V.tarjeta(filtros) if filas else "") + V.tarjeta(tabla)
        titulo = f"Vulnerabilidades de {app}" if app else "Vulnerabilidades"
        return self.envolver(titulo, cuerpo, "/vulnerabilidades", ctx,
                             subtitulo=f"{len(hs)} activas, ordenadas por urgencia (explotadas y críticas primero). "
                                       "Pulsa una cabecera para ordenar.",
                             acciones=self._boton_resolver_app(ctx) + self._boton_analizar(),
                             refrescar=6 if self.v.en_curso and not filas else 0)

    # ------------------------------------------------------------------ componentes
    def componentes(self, ctx):
        est = self.v.estado
        hs, comps, _ = self._datos(ctx)
        ramas = est.get("info_ramas", {})
        origenes = {"exec": "Comando en el contenedor", "env": "Variables de la imagen", "imagen": "Etiqueta de imagen",
                    "fichero": "Fichero del proyecto", "http": "Cabeceras HTTP", "manual": "Configuración"}
        filas = []
        for c in comps:
            cuenta = {s: 0 for s, _ in V.SEVERIDADES}
            for h in hs:
                if h["componente"] == c["clave"] and h["severidad"] in cuenta:
                    cuenta[h["severidad"]] += 1
            total = sum(cuenta.values())
            peso = sum(n * 100 ** (3 - i) for i, (s, _) in enumerate(V.SEVERIDADES) for n in [cuenta[s]])
            vul = (f'<div class="cnts">{"".join(V.contador_sev(cuenta[s], s) for s, _ in V.SEVERIDADES if cuenta[s])}</div>'
                   if total else V.pill("Sin vulnerabilidades", "ok"))
            r = ramas.get(c["clave"]) or {}
            if r.get("sin_soporte"):
                soporte, k_sop = V.pill(f"Sin soporte ({r['rama']})", "mal"), "sin"
            elif r:
                soporte, k_sop = V.pill(f"Hasta {r.get('fin_soporte')}", "ok"), "ok"
            else:
                soporte, k_sop = '<span class="muted">—</span>', "na"
            desact = bool(r.get("desactualizada"))
            ultima = str(r["ultima_de_rama"]) if desact and r.get("ultima_de_rama") else None
            detalle = c["detalle"]
            for raiz in self.v.cfg["deteccion"].get("rutas_proyecto") or []:
                detalle = detalle.replace(raiz.rstrip("/") + "/", "")
            tipo = c["ecosistema"] or ("Runtime" if c["tipo"] == "runtime" else c["tipo"])
            texto = f'{c["nombre"]} {c["version"]} {tipo} {c.get("app", "")} {c.get("contenedor", "")}'.lower()
            filas.append(
                f'<tr data-texto="{E(texto)}" data-vul="{"si" if total else "no"}" data-soporte="{k_sop}" '
                f'data-desact="{"si" if desact else "no"}">'
                f'<td data-v="{E(c["nombre"])}"><b>{E(c["nombre"])}</b><div class="muted peq">{E(tipo)}</div>'
                f'{self._app_txt(c, ctx)}</td>'
                f'<td data-v="{1 if ultima else 0}">{V.version_salto(c["version"], ultima)}</td>'
                f'<td data-v="{peso}">{vul}</td><td data-v="{ {"sin": 0, "ok": 1, "na": 2}[k_sop]}">{soporte}</td>'
                f'<td>{E(origenes.get(c["origen"], c["origen"]))}<div class="muted peq ruta" title="{E(c["detalle"])}">'
                f'{E(detalle[-70:])}{(" · " + E(c["contenedor"])) if c["contenedor"] else ""}</div></td>'
                f'<td class="accion">{self._celda_resolver(c)}</td></tr>')
        if filas:
            filtros = V.filtros("#t-comps", "Buscar componente, versión o contenedor", "componentes", [
                ("vul", "si", "alerta", "Con vulnerabilidades"), ("desact", "si", "reloj", "Desactualizados"),
                ("soporte", "sin", "x", "Sin soporte")])
            cabecera = (V.th("Componente y tipo") + V.th("Versión actual → última", "num")
                        + V.th("Vulnerabilidades", "num") + V.th("Soporte", "num") + V.th("Detectado por")
                        + "<th>Corrección</th>")
            cuerpo = (V.tarjeta(filtros)
                      + V.tarjeta(f'<div class="tabla"><table id="t-comps" class="ancha"><thead><tr>{cabecera}</tr></thead>'
                                  f'<tbody>{"".join(filas)}</tbody></table></div>'
                                  + V.sin_coincidencias("#t-comps", "Ningún componente coincide con estos filtros.")))
        elif self.v.en_curso:
            cuerpo = V.tarjeta(V.cargando("Analizando: los componentes aparecerán aquí en cuanto termine."))
        elif not est.get("ciclos"):
            cuerpo = V.tarjeta(V.error("Todavía no se ha completado ningún análisis. Pulsa «Analizar ahora» y, si "
                                       "vuelve a fallar, revisa los registros del contenedor."))
        else:
            cuerpo = V.tarjeta(V.vacio("No se ha detectado ningún componente. Revisa [deteccion] en la configuración.",
                                       "info"))
        return self.envolver("Componentes", cuerpo, "/componentes", ctx,
                             subtitulo=f"{len(comps)} componentes detectados. Claude solo trabaja cuando pulsas «Corregir con Claude»",
                             acciones=self._boton_resolver_app(ctx) + self._boton_analizar(),
                             refrescar=6 if self.v.en_curso and not filas else 0)

    # ------------------------------------------------------------------ correcciones
    GRUPO_PLAN = {"pendiente_aprobacion": "decidir", "analizando": "curso", "verificando": "curso",
                  "aplicando": "curso", "aplicado": "aplicado", "error": "fallo", "fallo_aplicacion": "fallo"}

    @staticmethod
    def _celda_consumo(p) -> str:
        cl = p.get("claude") or {}
        t = cl.get("total") or {}
        if not cl.get("llamadas"):
            return '<td class="num" data-v="0"><span class="muted">—</span></td>'
        d5 = (t.get("delta") or {}).get("five_hour")
        modelo = consumo.NOMBRE_MODELO.get(cl.get("modelo"), cl.get("modelo") or "")
        return (f'<td class="num" data-v="{t.get("coste_usd") or 0}"><span class="mono">{E(consumo.usd(t.get("coste_usd")))}</span>'
                f'<div class="muted peq">{E(modelo)}{(" · 5 h +" + E(consumo.pct(d5))) if d5 is not None else ""}</div></td>')

    def _tabla_planes(self, planes: list, id_: str, ctx) -> str:
        filas = []
        for p in planes:
            a = p.get("analisis") or {}
            c = p["componente"]
            destino = a.get("version_objetivo")
            salto = (V.version_salto(c["version"], destino) if destino
                     else f'<span class="mono">{E(c["version"])}</span> <span class="muted peq">sin versión objetivo</span>')
            n_ap = len(aprobados(p))
            cambios = f'{len(p["cambios"])}' + (f'<div class="muted peq">{n_ap} aprobado(s)</div>' if n_ap else "")
            href = f"/plan/{p['id']}"
            boton = V.boton("Revisar" if p["estado"] == "pendiente_aprobacion" else "Ver", "secundario", "flecha",
                            href=href, attrs='style="padding:4px 12px"')
            texto = f'{c["nombre"]} {c["version"]} {destino or ""} {c.get("app", "")} {p["id"]}'.lower()
            filas.append(
                f'<tr data-href="{E(href)}" data-texto="{E(texto)}" data-grupo="{self.GRUPO_PLAN.get(p["estado"], "otro")}">'
                f'<td data-v="{E(c["nombre"])}"><b><a href="{E(href)}">{E(c["nombre"])}</a></b>{self._app_txt(c, ctx)}</td>'
                f'<td>{salto}</td>'
                f'<td class="num" data-v="{len(p["hallazgos"])}">{len(p["hallazgos"])}</td>'
                f'<td class="num" data-v="{len(p["cambios"])}">{cambios}</td>'
                f'<td>{V.estado_verif((p.get("verificacion") or {}).get("estado"))}</td>'
                f'<td data-v="{E(p["estado"])}">{V.estado_plan(p["estado"])}</td>'
                f'{self._celda_consumo(p)}'
                f'<td data-v="{E(p.get("creado", ""))}"><span class="mono peq">{E(_hora(p.get("creado")))}</span></td>'
                f'<td class="accion">{boton}</td></tr>')
        cabecera = (V.th("Componente") + V.th("Versión actual → propuesta") + V.th("Vulns.", "num", "num")
                    + V.th("Cambios", "num", "num") + V.th("Verificación") + V.th("Estado")
                    + V.th("Consumo", "num", "num") + V.th("Creado")
                    + "<th><span class='sr'>Acción</span></th>")
        return (f'<div class="tabla"><table id="{id_}" class="ancha"><thead><tr>{cabecera}</tr></thead>'
                f'<tbody>{"".join(filas)}</tbody></table></div>')

    def _tarjeta_consumo(self, p) -> str:
        """Modelo, razonamiento, lo estimado antes de empezar y lo gastado de verdad (plan y equivalente API)."""
        cl = p["claude"]
        est, llamadas, t = cl.get("estimacion") or {}, cl.get("llamadas") or [], cl.get("total") or {}
        nombre_m = consumo.NOMBRE_MODELO.get(cl.get("modelo"), cl.get("modelo") or "—")
        nombre_e = consumo.NOMBRE_ESFUERZO.get(cl.get("esfuerzo"), cl.get("esfuerzo") or "—")
        filas = [f"<dt>Modelo</dt><dd>{E(nombre_m)} <span class='mono peq muted'>{E(cl.get('modelo') or '')}</span></dd>",
                 f"<dt>Razonamiento</dt><dd>{E(nombre_e)}</dd>"]
        barras = ""
        if llamadas:
            primera, ultima = llamadas[0], llamadas[-1]
            for k, nombre in consumo.VENTANAS.items():
                antes, despues = (primera.get("antes") or {}).get(k), (ultima.get("despues") or {}).get(k)
                if despues is not None and k in (t.get("delta") or {}):
                    antes = max(0.0, despues - t["delta"][k])
                reinicio = consumo.hora_reinicio((ultima.get("reinicio") or {}).get(k))
                barras += V.barra_uso(f"Ventana {nombre}" if k == "five_hour" else "Límite semanal", antes, despues,
                                      f"se reinicia {reinicio}" if reinicio else "")
            tk = t.get("tokens") or {}
            filas += [f"<dt>Llamadas</dt><dd>{len(llamadas)}"
                      f"{' (análisis + reintento)' if len(llamadas) > 1 else ''}</dd>",
                      f"<dt>Duración</dt><dd>{(t.get('duracion_s') or 0) / 60:.1f} min</dd>",
                      f"<dt>Tokens</dt><dd class='peq'><span class='mono'>{tk.get('entrada', 0) + tk.get('cache_escritura', 0) + tk.get('cache_lectura', 0):,}</span> de entrada "
                      f"(<span class='mono'>{tk.get('cache_lectura', 0):,}</span> de caché) · "
                      f"<span class='mono'>{tk.get('salida', 0):,}</span> de salida</dd>".replace(",", "."),
                      f"<dt>Si fuera por API</dt><dd><b class='mono'>{E(consumo.usd(t.get('coste_usd')))}</b>"
                      f" <span class='muted peq'>no se cobra: va con tu plan</span></dd>"]
        if est:
            filas.append(f"<dt>Estimado antes</dt><dd class='peq'><span class='mono'>{E(consumo.usd(est.get('coste_usd')))}</span>"
                         + "".join(f" · {nombre} +{consumo.pct(est['plan'][k]['delta'])}"
                                   for k, nombre in (("five_hour", "5 h"), ("seven_day", "semana"))
                                   if (est.get("plan") or {}).get(k, {}).get("delta") is not None) + "</dd>")
        if not llamadas:
            barras = ('<p class="muted" style="margin:0 0 12px">'
                      + ("Claude está trabajando: el consumo real aparecerá al terminar."
                         if p["estado"] in TRANSITORIOS else "No hay datos de consumo de esta ejecución.") + "</p>")
        return V.tarjeta(barras + f'<dl class="dl" style="margin-top:16px">{"".join(filas)}</dl>',
                         "Consumo de Claude", icono_nombre="pulso")

    def _tarjeta_uso_plan(self) -> str:
        """Estado actual del plan de Claude (última medición) y lo gastado por el vigilante."""
        g = self.v.gestor.consumo
        lim = g.limites()
        hist = g.datos.get("historial") or []
        if not hist and not lim["ventanas"]:
            return ""
        barras = "".join(
            V.barra_uso("Ventana de 5 horas" if k == "five_hour" else "Límite semanal", None,
                        (lim["ventanas"].get(k) or {}).get("uso"),
                        ("reiniciada desde la última medición" if (lim["ventanas"].get(k) or {}).get("reiniciada") else
                         f"se reinicia {consumo.hora_reinicio((lim['ventanas'].get(k) or {}).get('reinicio'))}"
                         if (lim["ventanas"].get(k) or {}).get("reinicio") else ""))
            for k in consumo.VENTANAS)
        hace7 = (dt.datetime.now() - dt.timedelta(days=7)).isoformat(timespec="seconds")
        semana = [h for h in hist if h.get("fecha", "") >= hace7]
        coste7 = sum(h.get("coste_usd") or 0 for h in semana)
        delta7 = sum((h.get("delta") or {}).get("seven_day", 0) for h in semana)
        medido = (_hora(dt.datetime.fromtimestamp(lim["fecha"]).isoformat(timespec="seconds"))
                  if lim.get("fecha") else "—")
        resumen = (f'<dl class="dl" style="margin-top:16px"><dt>Últimos 7 días</dt><dd>{len(semana)} ejecución(es) · '
                   f'+{consumo.pct(delta7)} del límite semanal</dd>'
                   f'<dt>Si fuera por API</dt><dd><b class="mono">{E(consumo.usd(coste7))}</b> en 7 días · '
                   f'<span class="mono">{E(consumo.usd(sum(h.get("coste_usd") or 0 for h in hist)))}</span> en total</dd>'
                   f'<dt>Medido</dt><dd>{E(medido)} <span class="muted peq">(se actualiza con cada ejecución; '
                   f'incluye tu uso de Claude fuera del vigilante)</span></dd></dl>')
        return V.tarjeta(barras + resumen, "Uso de tu plan de Claude", icono_nombre="pulso")

    def correcciones(self, ctx):
        planes = self._datos(ctx)[2]
        activos = [p for p in planes if p["estado"] in ("pendiente_aprobacion", *TRANSITORIOS)]
        historial = [p for p in planes if p not in activos]
        if not planes:
            ayuda = ("Todavía no has pedido ninguna corrección. Claude no hace nada por su cuenta: ve a Componentes y "
                     "pulsa «Corregir con Claude» en el que quieras arreglar." if claude.disponible(self.v.cfg["claude"])
                     else "Inicia sesión en Claude Code o configura CLAUDE_CODE_OAUTH_TOKEN (claude setup-token) para poder pedirle correcciones a Claude.")
            cuerpo = V.tarjeta(V.vacio(ayuda, "llave") + '<div style="text-align:center">'
                               + V.boton("Ir a Componentes", "secundario", "flecha", href="/componentes") + "</div>")
        else:
            en_curso = sum(1 for p in activos if p["estado"] in TRANSITORIOS)
            extra = (f'<span class="muted peq">{V.icono("refrescar", 14, "gira")} {en_curso} en curso: '
                     f'la página se actualiza sola</span>') if en_curso else ""
            cuerpo = V.tarjeta(self._tabla_planes(activos, "t-planes-activos", ctx) if activos
                               else V.vacio("Nada pendiente de tu decisión"),
                               f"Pendientes y en curso ({len(activos)})", extra, icono_nombre="llave")
            if historial:
                filtros = V.filtros("#t-planes", "Buscar componente, versión o plan", "correcciones", [
                    ("grupo", "aplicado", "check", "Aplicadas"), ("grupo", "fallo", "x", "Con fallo"),
                    ("grupo", "otro", "punto", "Rechazadas u obsoletas")], abajo=True)
                cuerpo += V.tarjeta(filtros + self._tabla_planes(historial, "t-planes", ctx).replace(
                    'class="tabla"', 'class="tabla tabla-sola"', 1)
                                    + V.sin_coincidencias("#t-planes", "Ninguna corrección coincide con estos filtros."),
                                    f"Historial ({len(historial)})", icono_nombre="reloj")
        explic = (f'<div class="banner banner-info">{V.icono("candado", 22)}<div><b>Cómo funciona</b><p>Claude solo trabaja cuando TÚ se lo pides, con el botón «Corregir con Claude». '
                  'Entonces propone cambios concretos y los justifica uno a uno; el vigilante los prueba en una copia con contenedores de '
                  'prueba. Tú apruebas o rechazas cada cambio (o todos). Solo entonces se aplica, con copia de seguridad '
                  'y posibilidad de revertir.</p></div></div>')
        cuerpo += self._tarjeta_uso_plan()
        return self.envolver("Correcciones", explic + cuerpo, "/correcciones", ctx,
                             subtitulo="Planes de corrección que has pedido a Claude",
                             acciones=self._boton_resolver_app(ctx),
                             refrescar=5 if any(p["estado"] in TRANSITORIOS for p in planes) else 0)

    # ------------------------------------------------------------------ detalle de un plan
    def plan(self, id_, ctx):
        p = self.v.gestor.planes.obtener(id_)
        if not p:
            return None
        a, ver, ap = p.get("analisis") or {}, p.get("verificacion") or {}, p.get("aplicacion") or {}
        ent = a.get("entendimiento") or {}
        c = p["componente"]
        abierto = p["estado"] == "pendiente_aprobacion"
        partes = [self._pasos(p)]

        # barra de decisión
        n_ap, n_pe = len(aprobados(p)), len(pendientes(p))
        n_re = sum(1 for x in p["cambios"] if x.get("decision") == "rechazado")
        if abierto and p["cambios"]:
            lista_ap = "; ".join(f'{x["n"]}. {x["titulo"]}' for x in aprobados(p))
            lista_todo = "; ".join(f'{x["n"]}. {x["titulo"]}' for x in p["cambios"])
            botones = [f'''<form method="post" action="/api/plan/{p["id"]}/todo" data-confirmar="Se rechazarán los {len(p["cambios"])}
cambios y no se aplicará nada." data-titulo="Rechazar todo" data-boton="Rechazar todo" data-tono="btn-rojo">
<input type="hidden" name="decision" value="rechazado">{V.boton("Rechazar todo", "peligro", "x")}</form>''']
            if n_ap:
                botones.append(f'''<form method="post" action="/api/plan/{p["id"]}/aplicar" data-confirmar="Se aplicarán los
{n_ap} cambio(s) aprobados en la web ({E(lista_ap, quote=True)}), con copia de seguridad previa y comprobación posterior.
Si la web no responde bien, se restaurará lo anterior automáticamente." data-titulo="Aplicar {n_ap} cambio(s)" data-boton="Aplicar ahora" data-tono="btn-ok">
{V.boton(f"Aplicar {n_ap} aprobado(s)", "ok", "play")}</form>''')
            botones.append(f'''<form method="post" action="/api/plan/{p["id"]}/todo" data-confirmar="Se aprobarán los
{len(p["cambios"])} cambios y se aplicarán ya en la web ({E(lista_todo, quote=True)}), con copia de seguridad previa." data-titulo="Aprobar todo y aplicar"
data-boton="Aprobar y aplicar"><input type="hidden" name="decision" value="aprobado">
{V.boton("Aprobar todo y aplicar", "primario", "check")}</form>''')
            partes.append(f'''<div class="decision"><div class="resumen"><span><b>{len(p["cambios"])}</b> cambios propuestos</span>
<span><b>{n_ap}</b> aprobados</span><span><b>{n_re}</b> rechazados</span><span><b>{n_pe}</b> sin decidir</span></div>
<div class="top-x">{"".join(botones)}</div></div>''')
        elif p["estado"] in ("aplicado", "fallo_aplicacion"):
            partes.append(f'''<div class="decision"><div class="resumen"><span>{V.estado_plan(p["estado"])}</span>
<span>Aplicado por <b>{E(ap.get("por", ""))}</b> el {E(_hora(ap.get("inicio")))}</span></div>
<form method="post" action="/api/plan/{p["id"]}/revertir" data-confirmar="Se restaurarán los ficheros desde la copia
de seguridad y se volverá a desplegar la versión anterior." data-titulo="Revertir cambios" data-boton="Revertir"
data-tono="btn-rojo">{V.boton("Revertir a como estaba", "peligro", "deshacer")}</form></div>''')

        if p.get("no_cubiertos"):
            partes.append(f'''<div class="banner banner-aviso">{V.icono("alerta", 22)}<div><b>La versión propuesta no corrige
todo</b><p>{E(a.get("version_objetivo", ""))} no incluye la corrección de: {E(", ".join(p["no_cubiertos"][:8]))}.
Valora una versión posterior antes de aprobar.</p></div></div>''')

        # columna principal: análisis + cambios
        fuentes = "".join(f'<li><a href="{E(f)}" target="_blank" rel="noopener">{E(f)}</a></li>'
                          for f in a.get("fuentes_consultadas", []))
        cubiertos = ", ".join(ent.get("cves_cubiertos") or [])
        analisis = V.tarjeta(f'''<p style="margin-top:0">{E(ent.get("resumen", "Claude está analizando…"))}</p>
<dl class="dl"><dt>Afecta a</dt><dd>{E(ent.get("version_afectada", "—"))}</dd>
<dt>Corregido en</dt><dd>{E(ent.get("version_corregida", "—"))}</dd>
<dt>Exposición</dt><dd>{E(ent.get("exposicion", "—"))}</dd>
<dt>Estrategia</dt><dd>{E(a.get("estrategia", "—"))}</dd>
{f"<dt>CVE principales</dt><dd class='mono peq'>{E(cubiertos)}</dd>" if cubiertos else ""}</dl>
{f'<details><summary>Fuentes consultadas</summary><div><ul>{fuentes}</ul></div></details>' if fuentes else ""}''',
                             "Qué ha entendido Claude", icono_nombre="robot")
        cambios = "".join(self._tarjeta_cambio(p, x, abierto) for x in p["cambios"])
        principal = analisis + cambios

        # columna lateral: verificación, compatibilidad, aplicación, vulnerabilidades, registro
        lateral = [V.tarjeta(self._timeline(ver.get("pasos")) + self._deprecaciones(ver) + self._previas(p),
                             "Verificación en copia", V.estado_verif(ver.get("estado")), icono_nombre="capas")]
        if p.get("claude"):
            lateral.append(self._tarjeta_consumo(p))
        compat = []
        for clave in ("compatibilidad", "compatibilidad_objetivo"):
            for aviso in (p.get(clave) or {}).get("avisos", []):
                if aviso not in compat:
                    compat.append(aviso)
        opciones = (p.get("compatibilidad") or {}).get("opciones") or {}
        nombres_op = {"minima_segura": "Mínima segura", "ultima_misma_mayor": "Última de la misma versión mayor",
                      "ultima": "Última estable", "ultima_misma_rama": "Última de la rama"}
        ops = "".join(f"<dt>{E(nombres_op.get(k, k))}</dt><dd class='mono'>{E(str(v))}</dd>" for k, v in opciones.items() if v)
        lateral.append(V.tarjeta(("".join(f'<div class="callout">{V.icono("alerta", 17)}<div>{E(x)}</div></div>'
                                          for x in compat) or '<p class="muted" style="margin:0">Sin avisos.</p>')
                                 + (f'<dl class="dl" style="margin-top:16px">{ops}</dl>' if ops else ""),
                                 "Compatibilidad (automática)", icono_nombre="capas"))
        if ap:
            r = ap.get("respaldo") or {}
            lateral.append(V.tarjeta(self._timeline(ap.get("pasos")) +
                                     (f'<p class="muted peq" style="margin:12px 0 0">Copia de seguridad: '
                                      f'<span class="mono">{E(r.get("carpeta", "—"))}</span>'
                                      f'{("<br>Imágenes: " + E(", ".join(r.get("imagenes", [])))) if r.get("imagenes") else ""}</p>'),
                                     "Aplicación", V.pill(ap.get("estado", ""), "ok" if ap.get("estado") == "aplicado"
                                                          else "mal" if "fallo" in ap.get("estado", "") else "neutro"),
                                     icono_nombre="play"))
        vulns = "".join(f'''<tr><td data-v="{ORDEN_SEVERIDAD.get(h["severidad"], 0)}">{V.sev(h["severidad"])}</td>
<td><span class="mono">{self._enlace_cve(h)}</span>{self._tags(h)}</td>
<td class="num" data-v="{h.get("cvss") or 0}">{h.get("cvss") or "—"}</td></tr>'''
                        for h in sorted(p["hallazgos"], key=lambda h: -(h.get("cvss") or 0))[:40])
        lateral.append(V.tarjeta(f'<details><summary>Ver las {len(p["hallazgos"])} vulnerabilidades</summary><div>'
                                 f'<table><thead><tr>{V.th("Gravedad", "num")}{V.th("CVE")}{V.th("CVSS", "num", "num")}</tr></thead>'
                                 f'<tbody>{vulns}</tbody></table></div></details>',
                                 "Vulnerabilidades que cubre", icono_nombre="alerta"))
        registro = "".join(f'<li><div class="tl-i">{V.icono("punto", 12)}</div><div class="tl-c"><b>{E(r["evento"])}</b>'
                           f'<p>{E(_hora(r["fecha"]))} · {E(r["por"])}</p></div></li>' for r in reversed(p["registro"]))
        lateral.append(V.tarjeta(f'<ul class="tl">{registro}</ul>', "Registro (auditoría)", icono_nombre="reloj"))

        partes.append(f'<div class="grid g2b"><div class="col">{principal}</div>'
                      f'<div class="col">{"".join(lateral)}</div></div>')
        titulo = f"{c['nombre']} {c['version']}" + (f" → {a['version_objetivo']}" if a.get("version_objetivo") else "")
        sub = (f'{V.estado_plan(p["estado"])} &nbsp; {("App <b>" + E(c["app"]) + "</b> · ") if c.get("app") else ""}'
               f'Plan {E(p["id"])} · {len(p["hallazgos"])} vulnerabilidades · '
               f'creado el {E(_hora(p["creado"]))} · <a href="/correcciones">volver a correcciones</a>')
        return self.envolver(titulo, "".join(partes), "/correcciones", ctx, subtitulo=sub,
                             refrescar=4 if p["estado"] in TRANSITORIOS else 0)

    def _pasos(self, p):
        e = p["estado"]
        ver = (p.get("verificacion") or {}).get("estado")
        ap = (p.get("aplicacion") or {}).get("estado")
        orden = ["analizando", "verificando", "pendiente_aprobacion", "aplicando"]
        idx = orden.index(e) if e in orden else 4
        def estado(i):
            if e == "error":
                return "fallo" if i == 0 else ""
            if i == 1 and ver == "fallo" and idx > 1:
                return "fallo"
            if i == 3 and e == "fallo_aplicacion":
                return "fallo"
            if i == 2 and e == "rechazado":
                return "hecho"
            if i == 3 and e in ("rechazado", "obsoleto"):
                return ""
            return "hecho" if i < idx else "actual" if i == idx else ""
        if e == "sin_cambios":
            return V.tarjeta('<div class="pasos-plan">' + "".join(
                f'<div class="paso {"hecho" if i == 0 else ""}"><div class="paso-c">{V.icono("check" if i == 0 else icono, 16)}</div>'
                f'<b>{E(t)}</b><small>{E(sub)}</small></div>' for i, (t, sub, icono) in enumerate([
                    ("Análisis", "Claude no propone cambios", "robot"), ("Verificación", "Nada que verificar", "capas"),
                    ("Tu decisión", "Nada que decidir", "candado"), ("Aplicación", "No hay cambios", "play")])) + "</div>")
        decision = {"rechazado": "Rechazado", "obsoleto": "Ya no hace falta"}.get(e)
        datos = [("Análisis", "Claude propone cambios", "robot"),
                 ("Verificación", V.ESTADOS_VERIF.get(ver, ("En una copia",))[0] if ver else "En una copia", "capas"),
                 ("Tu decisión", decision or ("Esperando" if e == "pendiente_aprobacion" else "Aprobar o rechazar"), "candado"),
                 ("Aplicación", {"aplicado": "Aplicado y comprobado", "revertido": "Revertido tras fallar",
                                 "revertido_con_problemas": "Revertido con problemas",
                                 "fallo": "No se pudo aplicar"}.get(ap, "Con copia de seguridad")
                  if e not in ("revertido",) else "Revertido a petición", "play")]
        html_ = []
        for i, (t, s, ic) in enumerate(datos):
            st = estado(i)
            sim = V.icono("check", 16) if st == "hecho" else V.icono("x", 16) if st == "fallo" else V.icono(ic, 16)
            html_.append(f'<div class="paso {st}"><div class="paso-c">{sim}</div><b>{E(t)}</b><small>{E(s)}</small></div>')
        return V.tarjeta(f'<div class="pasos-plan">{"".join(html_)}</div>')

    def _tarjeta_cambio(self, p, c, abierto):
        ver = p.get("verificacion") or {}
        vc = (ver.get("por_cambio") or {}).get(str(c["n"]), {})
        txt_v, tono_v = estado_verificacion_cambio(p, c)
        riesgo_t, riesgo_tono = V.RIESGO.get(c["riesgo_nivel"], (c["riesgo_nivel"], "neutro"))
        listas = "".join(
            f'<div><h4>{t}</h4><ul>{"".join(f"<li>{E(x)}</li>" for x in c.get(k) or [])}</ul></div>'
            if c.get(k) else f'<div><h4>{t}</h4><p class="muted peq" style="margin:0">Ninguna conocida</p></div>'
            for t, k in (("Incompatibilidades", "breaking_changes"), ("Dependencias", "dependencias"),
                         ("Deprecaciones", "deprecaciones")))
        ficheros = vc.get("ficheros") or c.get("ficheros") or []
        comandos = "".join(f'<div class="callout callout-info">{V.icono("play", 16)}<div><span class="mono">{E(x["comando"])}</span>'
                           f' terminó con código {x["codigo"]}</div></div>' for x in vc.get("comandos", []))
        diff_final = vc.get("diff_final")
        diffs = (f'<details {"open" if not abierto else ""}><summary>{V.icono("fichero", 15)}Cambios en el código '
                 f'({"verificados" if diff_final else "propuestos"}) · {len(ficheros)} fichero(s)</summary><div>'
                 f'{V.diff(diff_final or c.get("diff") or "")}</div></details>')
        if diff_final and c.get("diff") and c.get("diff").strip() != diff_final.strip():
            diffs += (f'<details><summary>{V.icono("robot", 15)}Diff original propuesto por Claude</summary>'
                      f'<div>{V.diff(c["diff"])}</div></details>')
        clase = c.get("decision") or ""
        if c.get("decision"):
            ok = c["decision"] == "aprobado"
            pie = (f'<div class="decidido {"ok" if ok else "no"}">{V.icono("check" if ok else "x", 17)}'
                   f'{"Aprobado" if ok else "Rechazado"}</div><span class="muted peq">por {E(c.get("decidido_por") or "")}'
                   f' · {E(_hora(c.get("decidido_en")))}</span>')
        elif abierto:
            pie = (f'<span class="muted peq">Decide sobre este cambio por separado</span>'
                   f'<form method="post" action="/api/plan/{p["id"]}/decidir"><input type="hidden" name="n" value="{c["n"]}">'
                   f'{V.boton("Rechazar", "peligro", "x", attrs="name=decision value=rechazado")}'
                   f'{V.boton("Aprobar", "ok", "check", attrs="name=decision value=aprobado")}</form>')
        else:
            pie = '<span class="muted peq">Sin decisión</span>'
        depende = (f'<span class="pill pill-neutro">Necesita el cambio {", ".join(map(str, c["depende_de"]))}</span>'
                   if c.get("depende_de") else "")
        return f'''<section class="card cambio {clase}"><div class="cambio-h"><div><small>Cambio {c["n"]} de {len(p["cambios"])}</small>
<h3>{E(c["titulo"])}</h3><div class="chips">{V.pill(V.TIPO_CAMBIO.get(c["tipo"], c["tipo"]), "info", False)}
{V.pill(riesgo_t, riesgo_tono)}{V.pill(txt_v, tono_v)}{depende}</div></div></div>
<div class="card-b"><div class="just"><div><h4>{V.icono("check", 14)}Qué arregla</h4><p>{E(c["que_arregla"])}</p></div>
<div><h4>{V.icono("info", 14)}Por qué es correcto</h4><p>{E(c["por_que_es_correcto"])}</p></div>
<div><h4>{V.icono("alerta", 14)}Riesgo</h4><p>{E(c["riesgo_detalle"])}</p></div></div>
<div class="compat">{listas}</div>
<div class="revertir">{V.icono("deshacer", 17)}<div><b>Cómo revertir:</b> {E(c["como_revertir"])}</div></div>
{comandos}{diffs}</div><div class="cambio-f">{pie}</div></section>'''

    @staticmethod
    def _timeline(pasos):
        if not pasos:
            return '<p class="muted" style="margin:0">Todavía no hay resultados.</p>'
        out = []
        for x in pasos:
            tono = "tl-ok" if x["ok"] else "tl-mal" if x["ok"] is False else ""
            ic = "check" if x["ok"] else "x" if x["ok"] is False else "info"
            salida = (f'<details><summary>Ver salida</summary><pre>{E(x.get("salida", ""))}</pre></details>'
                      if x.get("salida") else "")
            out.append(f'<li class="{tono}"><div class="tl-i">{V.icono(ic, 13)}</div><div class="tl-c">'
                       f'<b>{E(x["paso"])}</b><p>{E(x.get("detalle", ""))}</p>{salida}</div></li>')
        return f'<ul class="tl">{"".join(out)}</ul>'

    @staticmethod
    def _deprecaciones(ver):
        if not ver.get("deprecaciones"):
            return ""
        return ('<div style="margin-top:12px">' + "".join(
            f'<div class="callout">{V.icono("alerta", 16)}<div class="peq">{E(d)}</div></div>'
            for d in ver["deprecaciones"][:6]) + "</div>")

    def _previas(self, p):
        out = []
        intento = (p.get("verificacion") or {}).get("intento_previo")
        if intento:
            out.append(f'<details><summary>Primer intento: {E(V.ESTADOS_VERIF.get(intento["estado"], (intento["estado"],))[0])}'
                       f' (Claude lo corrigió)</summary><div>{self._timeline(intento["pasos"])}</div></details>')
        for x in p.get("verificaciones_previas") or []:
            if x:
                out.append(f'<details><summary>Verificación anterior del {E(_hora(x.get("fecha")))} '
                           f'(cambios {", ".join(map(str, x.get("cambios_verificados") or []))})</summary>'
                           f'<div>{self._timeline(x.get("pasos"))}</div></details>')
        return "".join(out)

    # ------------------------------------------------------------------ mantenimiento
    def mantenimiento(self, ctx):
        m = self.v.mant.info()
        criticos = sorted((h for h in self.v.estado.get("hallazgos", {}).values() if h["critico"]),
                          key=lambda h: (not h.get("kev"), -(h.get("cvss") or 0)))
        explotadas = sum(1 for h in criticos if h.get("kev"))
        apps = list(self._resumen_apps())
        afectadas = (f"Afecta a todas las webs que sirve este servidor ({', '.join(apps)})." if len(apps) > 1
                     else "Afecta a la web entera.")
        if m["activo"]:
            estado = (f'<div class="estado-web"><div class="ew-i ew-off">{V.icono("power", 24)}</div><div>'
                      f'<b>La web está en modo mantenimiento</b><span class="muted">{E(m.get("motivo", ""))}</span>'
                      f'<span class="muted peq">Desde {E(_hora(m.get("desde")))} · por {E(m.get("por", ""))}</span></div></div>')
            form = (f'<form method="post" action="/api/mantenimiento" data-confirmar="La web volverá a atender a los '
                    f'visitantes con normalidad. Siguen abiertas {len(criticos)} vulnerabilidad(es) crítica(s)'
                    f'{f", {explotadas} explotada(s) activamente" if explotadas else ""}." '
                    f'data-titulo="Volver a poner la web en línea" data-boton="Poner en línea">'
                    f'<input type="hidden" name="accion" value="desactivar">{V.boton("Volver a poner en línea", "ok", "pulso")}</form>')
        else:
            estado = (f'<div class="estado-web"><div class="ew-i ew-on">{V.icono("pulso", 24)}</div><div>'
                      f'<b>La web está en línea</b><span class="muted">Sirviendo con normalidad</span></div></div>')
            form = (f'<form method="post" action="/api/mantenimiento" data-confirmar="Todos los visitantes verán la página '
                    f'de mantenimiento (HTTP 503) hasta que la vuelvas a poner en línea. {afectadas} '
                    f'Hay {len(criticos)} vulnerabilidad(es) crítica(s) abierta(s)'
                    f'{f", {explotadas} explotada(s) activamente" if explotadas else ""}." data-titulo="Poner la web en '
                    f'mantenimiento" data-boton="Activar mantenimiento" data-tono="btn-rojo">'
                    f'<input type="hidden" name="accion" value="activar">{V.boton("Poner en mantenimiento", "rojo", "power")}</form>')
        filas = "".join(
            f'<tr><td data-v="{1 if h.get("kev") else 0}">{V.sev(h["severidad"])}</td>'
            f'<td><span class="mono">{self._enlace_cve(h)}</span>{self._tags(h)}</td>'
            f'<td data-v="{E(h["nombre"])}"><b>{E(h["nombre"])}</b> <span class="mono muted">{E(h["version"])}</span>'
            f'{self._app_txt(h, ctx)}</td><td class="num" data-v="{h.get("cvss") or 0}">{h.get("cvss") or "—"}</td></tr>'
            for h in criticos[:12])
        tabla = (f'<div class="tabla"><table><thead><tr>{V.th("Gravedad", "num")}{V.th("CVE")}{V.th("Componente")}'
                 f'{V.th("CVSS", "num", "num")}</tr></thead><tbody>{filas}</tbody></table></div>')
        if len(criticos) > 12:
            tabla += (f'<div class="mas">{V.boton(f"Ver las {len(criticos)} críticas", "secundario", "flecha", href="/vulnerabilidades?sev=CRITICA")}</div>')
        modo = self.v.cfg["mantenimiento"].get("modo", "manual")
        texto_modo, tono_modo = {"off": ("Desactivado", "neutro"), "manual": ("Manual: te avisa y tú decides", "info"),
                                 "auto": ("Automático ante críticas explotadas", "aviso")}.get(modo, (modo, "neutro"))
        cuerpo = (V.tarjeta(f'<div class="fila-estado">{estado}{form}</div>', "Estado", icono_nombre="power")
                  + '<div class="grid g2">'
                  + V.tarjeta(tabla if filas else V.vacio("No hay vulnerabilidades críticas abiertas"),
                              f"Vulnerabilidades críticas abiertas ({len(criticos)})",
                              V.pill(f"{explotadas} explotada(s)", "mal") if explotadas else "", icono_nombre="alerta")
                  + V.tarjeta(f'<dl class="dl"><dt>Modo</dt><dd>{V.pill(texto_modo, tono_modo)}</dd>'
                              f'<dt>Alcance</dt><dd>{E(afectadas)}</dd></dl><p class="muted" style="margin-bottom:0">'
                              'El vigilante crea un fichero bandera en un volumen compartido con el servidor web; '
                              'nginx responde 503 con una página de mantenimiento mientras exista. No se para ni se toca '
                              'ningún contenedor.</p>', "Cómo funciona", icono_nombre="info")
                  + "</div>")
        return self.envolver("Mantenimiento", cuerpo, "/mantenimiento", ctx,
                             subtitulo="Cortar el acceso a la web mientras se corrige una vulnerabilidad crítica (afecta al servidor entero, no a una app)")



def arrancar(vigilante, puerto: int, host: str | None = None, extension=None):
    """extension: objeto opcional con get(manejador, ruta, query, panel, ctx) y
    post(manejador, ruta, form) para rutas /demo/… (lo usa el modo demo).
    Devuelven (codigo, cuerpo[, tipo]) o ("redirigir", url)."""
    panel = Panel(vigilante)
    cfg_panel = vigilante.cfg["panel"]
    host = host or cfg_panel.get("host") or "0.0.0.0"
    limite = LimiteIntentos()
    cuenta = panel.cuenta

    class Manejador(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            log.debug("panel: " + fmt, *a)

        def _ip(self) -> str:
            # la cabecera del túnel/proxy solo se cree si la conexión viene de la propia red (el proxy);
            # si no, cualquiera podría cambiarla en cada intento y saltarse el bloqueo
            directa = self.client_address[0]
            try:
                local = ipaddress.ip_address(directa).is_private or ipaddress.ip_address(directa).is_loopback
            except ValueError:
                local = False
            return (self.headers.get("CF-Connecting-IP") if local else None) or directa

        # -------- sesión (cookie) o token de API (scripts)
        def _sid(self) -> str:
            return _cookie(self.headers, "pw_sesion")

        def _sesion(self) -> dict | None:
            return cuenta.sesion(self._sid())

        def _https(self) -> bool:
            return (self.headers.get("X-Forwarded-Proto") or "").lower() == "https" or \
                '"https"' in (self.headers.get("CF-Visitor") or "")

        def _cookie_sesion(self, sid: str, borrar=False) -> str:
            seguro = "; Secure" if self._https() else ""
            if borrar:
                return f"pw_sesion=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{seguro}"
            return f"pw_sesion={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200{seguro}"

        def _bloqueado(self) -> bool:
            espera = limite.restante(self._ip())
            if espera:
                cuerpo = f"Demasiados intentos. Prueba de nuevo en {espera} s.".encode()
                self.send_response(429)
                self.send_header("Retry-After", str(espera))
                self.send_header("Content-Length", str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)
                return True
            return False

        def _ctx(self, q=None, ses=None):
            q = q or {}
            conocidas = panel._resumen_apps()
            app = urllib.parse.unquote(q["app"]) if "app" in q else urllib.parse.unquote(_cookie(self.headers, "vigilante_app"))
            app = app if app in conocidas else ""
            if "app" in q:
                self._extra = [("Set-Cookie", f"vigilante_app={urllib.parse.quote(app)}; Path=/; SameSite=Strict; Max-Age=31536000")]
            return {"msg": q.get("msg", ""), "pide_token": False, "app": app,
                    "csrf": (ses or {}).get("csrf", ""), "usuario": cuenta.usuario if ses else ""}

        # -------- páginas de acceso
        def _pagina_inicial(self, error="", codigo=201):
            cuerpo = ('<form method="post" action="/configuracion-inicial">'
                      '<label class="campo"><span>Código de configuración</span><input name="codigo" required '
                      'autocomplete="off" spellcheck="false"><span class="ayuda">Está en el log del contenedor '
                      '(<code>docker compose logs vigilante</code>) y en <code>codigo-inicial.txt</code> dentro de '
                      'la carpeta de datos.</span></label>'
                      '<label class="campo"><span>Usuario</span><input name="usuario" required autocomplete="username"></label>'
                      '<label class="campo"><span>Contraseña</span><input type="password" name="clave" minlength="12" '
                      'required autocomplete="new-password"><span class="ayuda">Al menos 12 caracteres.</span></label>'
                      '<label class="campo"><span>Repite la contraseña</span><input type="password" name="clave2" '
                      'minlength="12" required autocomplete="new-password"></label>'
                      + V.boton("Crear la cuenta y entrar", "primario", "check") + '</form>')
            self._enviar(200 if codigo == 201 else codigo, V.pagina_acceso(
                "Crea tu cuenta", cuerpo, error,
                "Es la única cuenta del panel. Solo quien tenga el código del log puede crearla."))

        def _pagina_entrar(self, volver="/", error="", codigo=200):
            cuerpo = (f'<form method="post" action="/entrar"><input type="hidden" name="volver" '
                      f'value="{E(volver_seguro(volver), quote=True)}">'
                      '<label class="campo"><span>Usuario</span><input name="usuario" required autofocus '
                      'autocomplete="username"></label>'
                      '<label class="campo"><span>Contraseña</span><input type="password" name="clave" required '
                      'autocomplete="current-password"></label>'
                      + V.boton("Entrar", "primario", "flecha") + '</form>')
            self._enviar(codigo, V.pagina_acceso("Entrar", cuerpo, error))

        def _responder_ext(self, r):
            if r[0] == "redirigir":
                return self._redirigir(r[1])
            self._enviar(r[0], r[1], *(r[2:] or ["text/html; charset=utf-8"]))

        def _redirigir(self, url, cookie=None):
            self.send_response(303)
            self.send_header("Location", url)
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()

        def _enviar(self, codigo, cuerpo, tipo="text/html; charset=utf-8"):
            datos = cuerpo.encode() if isinstance(cuerpo, str) else cuerpo
            self.send_response(codigo)
            self.send_header("Content-Type", tipo)
            self.send_header("Content-Length", str(len(datos)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("Cache-Control", "no-store")
            for k, v in getattr(self, "_extra", []):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(datos)

        def _no_encontrado(self, ctx):
            cuerpo = V.tarjeta(V.vacio("Esta página no existe.", "info") +
                               f'<div style="text-align:center">{V.boton("Ir al resumen", "secundario", href="/")}</div>')
            self._enviar(404, panel.envolver("No encontrado", cuerpo, "", ctx))

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            ruta = url.path.rstrip("/") or "/"
            q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}
            if ruta == "/salud":
                return self._enviar(200, "ok", "text/plain")
            api = panel.token_ok(self.headers.get("X-Token", ""))
            if not cuenta.existe() and not api:
                if ruta == "/configuracion-inicial":
                    return self._pagina_inicial()
                return self._redirigir("/configuracion-inicial")
            if ruta in ("/configuracion-inicial", "/entrar"):
                if self._sesion() or not cuenta.existe():
                    return self._redirigir("/")
                if ruta == "/entrar":
                    return self._pagina_entrar(q.get("volver", "/"))
                return self._redirigir("/entrar")
            ses = self._sesion()
            if not ses and not api:
                if ruta.startswith("/api/"):
                    return self._enviar(401, json.dumps({"error": "sin sesión"}), "application/json")
                return self._redirigir("/entrar?volver=" + urllib.parse.quote(self.path, safe=""))
            ctx = self._ctx(q, ses)
            if ruta == "/ajustes":
                return self._redirigir("/ajustes/general")
            if ruta.startswith("/ajustes/"):
                p = panel_ajustes.pagina(panel, ctx, ruta.split("/")[2])
                return self._enviar(200, p) if p else self._no_encontrado(ctx)
            if extension and ruta.startswith("/demo"):
                return self._responder_ext(extension.get(self, ruta, q, panel, ctx))
            paginas = {"/": panel.inicio, "/vulnerabilidades": panel.vulnerabilidades,
                       "/componentes": panel.componentes, "/correcciones": panel.correcciones,
                       "/mantenimiento": panel.mantenimiento}
            if ruta in paginas:
                return self._enviar(200, paginas[ruta](ctx))
            if ruta == "/api/estado":
                return self._enviar(200, json.dumps({**vigilante.estado, "mantenimiento": vigilante.mant.info()},
                                                    ensure_ascii=False), "application/json")
            if ruta == "/api/claude/estimacion":
                return self._enviar(200, json.dumps(panel.estimacion(q), ensure_ascii=False), "application/json")
            if ruta.startswith("/plan/"):
                try:
                    p = panel.plan(ruta.split("/")[2], ctx)
                except (ValueError, IndexError):
                    p = None
                return self._enviar(200, p) if p else self._no_encontrado(ctx)
            if ruta.startswith("/api/plan/") and ruta.endswith(".json"):
                try:
                    p = vigilante.gestor.planes.obtener(ruta.split("/")[3][:-5])
                except ValueError:
                    p = None
                return self._enviar(200, json.dumps(p, ensure_ascii=False), "application/json") if p \
                    else self._enviar(404, "No existe", "text/plain")
            self._no_encontrado(ctx)

        def do_POST(self):
            ruta = urllib.parse.urlparse(self.path).path
            largo = min(int(self.headers.get("Content-Length") or 0), 20_000)
            form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(largo).decode(),
                                                               keep_blank_values=True).items()}
            self._cookie = None
            if ruta == "/configuracion-inicial":
                return self._crear_cuenta(form)
            if ruta == "/entrar":
                return self._entrar(form)
            ses = self._sesion()
            if ses:
                # CSRF: el formulario tiene que traer el token de ESTA sesión
                if not hmac.compare_digest(form.get("csrf", ""), ses["csrf"]):
                    ctx = self._ctx({"msg": "La página había caducado: vuelve a intentarlo. No se ha hecho nada."}, ses)
                    return self._enviar(403, panel.envolver("Acción no válida", V.tarjeta(V.vacio(
                        "La petición no venía de esta sesión del panel.", "candado")), "", ctx))
            elif not panel.token_ok(form.get("token") or self.headers.get("X-Token", "")):
                if ruta == "/salir":
                    return self._redirigir("/entrar", self._cookie_sesion("", borrar=True))
                return self._enviar(403, "Hace falta iniciar sesión (o el token de API).", "text/plain; charset=utf-8")
            if ruta == "/salir":
                cuenta.cerrar(self._sid())
                return self._redirigir("/entrar", self._cookie_sesion("", borrar=True))
            if ruta.startswith("/ajustes/"):
                return self._accion_ajustes(ruta, form)
            if extension and ruta.startswith("/demo"):
                return self._responder_ext(extension.post(self, ruta, form))
            if ruta.startswith("/api/plan/"):
                return self._accion_plan(ruta, form)
            if ruta == "/api/mantenimiento":
                if form.get("confirmar") != "si":
                    msg = "Falta confirmar."
                elif form.get("accion") == "activar":
                    vigilante.mant.activar("activado a mano desde el panel", quien="panel")
                    vigilante.avisador.enviar("Web en mantenimiento", "Activado a mano desde el panel.", urgente=True)
                    msg = "La web está ahora en modo mantenimiento."
                else:
                    vigilante.mant.desactivar("panel")
                    vigilante.avisador.enviar("Web de nuevo en línea", "Mantenimiento desactivado desde el panel.")
                    msg = "La web vuelve a estar en línea."
                return self._redirigir(f"/mantenimiento?msg={urllib.parse.quote(msg)}", self._cookie)
            if ruta == "/api/claude/resolver":
                # Iniciar la resolución con Claude exige una acción explícita Y la confirmación del diálogo
                por = f"panel ({self._ip()})"
                if form.get("confirmar") != "si":
                    msg = "Falta confirmar: no se ha pedido nada a Claude."
                elif form.get("app"):
                    msg = vigilante.gestor.solicitar_app(form["app"], por, form.get("modelo"), form.get("esfuerzo"))
                else:
                    msg = vigilante.gestor.solicitar_componente(form.get("clave", ""), por, form.get("modelo"),
                                                                form.get("esfuerzo"))
                return self._redirigir(f"/correcciones?msg={urllib.parse.quote(msg)}", self._cookie)
            if ruta == "/api/escanear":
                if not vigilante.en_curso:
                    threading.Thread(target=vigilante.ciclo, args=("panel",), daemon=True).start()
                msg = "Análisis en marcha: la página se actualizará sola."
                volver = urllib.parse.urlparse(self.headers.get("Referer") or "/").path or "/"
                return self._redirigir(f"{volver}?msg={urllib.parse.quote(msg)}", self._cookie)
            self._enviar(404, "No encontrado", "text/plain")

        def _crear_cuenta(self, form):
            if cuenta.existe():
                return self._redirigir("/entrar")
            if self._bloqueado():
                return
            if form.get("clave", "") != form.get("clave2", ""):
                return self._pagina_inicial("Las dos contraseñas no coinciden.", 400)
            try:
                cuenta.crear(form.get("usuario", ""), form.get("clave", ""), codigo=form.get("codigo", ""))
            except ErrorCuenta as e:
                if "código" in str(e):
                    limite.fallo(self._ip())
                return self._pagina_inicial(str(e), 400)
            limite.acierto(self._ip())
            sid = cuenta.crear_sesion(self._ip(), self.headers.get("User-Agent", ""))
            msg = urllib.parse.quote("Cuenta creada. Configura aquí los avisos (Telegram, email…).")
            return self._redirigir(f"/ajustes/avisos?msg={msg}", self._cookie_sesion(sid))

        def _entrar(self, form):
            if not cuenta.existe():
                return self._redirigir("/configuracion-inicial")
            if self._bloqueado():
                return
            volver = volver_seguro(form.get("volver", "/"))
            if not cuenta.comprobar(form.get("usuario", ""), form.get("clave", "")):
                limite.fallo(self._ip())
                log.warning("Intento de acceso fallido al panel desde %s", self._ip())
                return self._pagina_entrar(volver, "Usuario o contraseña incorrectos.", 401)
            limite.acierto(self._ip())
            sid = cuenta.crear_sesion(self._ip(), self.headers.get("User-Agent", ""))
            return self._redirigir(volver, self._cookie_sesion(sid))

        def _accion_ajustes(self, ruta, form):
            accion = ruta.split("/")[2] if ruta.count("/") >= 2 else ""
            pestana = form.get("pestana", "general")
            try:
                if accion in ("guardar", "probar"):
                    cambiados = panel.ajustes.guardar(pestana, form)
                    if "general.nombre_web" in cambiados:
                        vigilante.avisador.web = vigilante.cfg["general"]["nombre_web"]
                    msg = (f"Guardado ({len(cambiados)} cambio(s)). Ya está en uso." if cambiados
                           else "No había nada que cambiar.")
                    if accion == "probar":
                        canal = form.get("canal", "")
                        if canal == "telegram":
                            fallo = vigilante.gestor.bot.probar()
                        elif canal in ("webhook", "email"):
                            fallo = vigilante.avisador.probar(canal)
                        else:
                            fallo = "Canal desconocido."
                        msg = (f"{msg} Prueba enviada por {canal}: comprueba que ha llegado." if not fallo
                               else f"{msg} La prueba por {canal} falló: {fallo}")
                elif accion == "clave":
                    pestana = "cuenta"
                    if form.get("nueva", "") != form.get("nueva2", ""):
                        msg = "Las dos contraseñas nuevas no coinciden. No se ha cambiado nada."
                    else:
                        cuenta.cambiar_clave(form.get("actual", ""), form.get("nueva", ""), self._sid())
                        msg = "Contraseña cambiada. Las demás sesiones se han cerrado."
                elif accion == "sesiones":
                    pestana = "cuenta"
                    n = cuenta.cerrar_otras(self._sid())
                    msg = f"Se han cerrado {n} sesión(es)."
                else:
                    return self._enviar(404, "No encontrado", "text/plain")
            except (ErrorAjuste, ErrorCuenta) as e:
                msg = f"No se ha guardado: {e}"
            if pestana not in panel_ajustes.NOMBRES:
                pestana = "general"
            self._redirigir(f"/ajustes/{pestana}?msg={urllib.parse.quote(msg)}")

        def _accion_plan(self, ruta, form):
            partes = ruta.split("/")       # /api/plan/<id>/<accion>
            if len(partes) != 5:
                return self._enviar(404, "No encontrado", "text/plain")
            pid, accion = partes[3], partes[4]
            g, por = vigilante.gestor, f"panel ({self.client_address[0]})"
            try:
                if accion == "decidir":
                    msg = g.decidir(pid, int(form["n"]), form.get("decision", ""), por)
                elif accion == "todo" and form.get("decision") == "rechazado":
                    msg = (g.decidir(pid, None, "rechazado", por) if form.get("confirmar") == "si"
                           else "Falta confirmar.")
                elif accion == "todo" and form.get("decision") == "aprobado":
                    if form.get("confirmar") != "si":
                        msg = "Falta la confirmación: no se ha aprobado ni aplicado nada."
                    else:
                        g.decidir(pid, None, "aprobado", por)
                        msg = g.aplicar(pid, por)
                elif accion == "aplicar":
                    msg = g.aplicar(pid, por) if form.get("confirmar") == "si" else "Falta confirmar."
                elif accion == "revertir":
                    msg = g.revertir(pid, por) if form.get("confirmar") == "si" else "Falta confirmar."
                else:
                    return self._enviar(404, "Acción desconocida", "text/plain")
            except (KeyError, ValueError) as e:
                msg = f"Petición no válida: {e}"
            except Exception as e:  # noqa: BLE001
                log.exception("Error en acción del panel")
                msg = f"Error: {e}"
            self._redirigir(f"/plan/{urllib.parse.quote(pid)}?msg={urllib.parse.quote(msg)}", self._cookie)

    srv = ThreadingHTTPServer((host, puerto), Manejador)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log.info("Panel en http://%s:%d", host, puerto)
    return srv
