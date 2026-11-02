"""Panel web del vigilante.

Páginas: resumen, vulnerabilidades, componentes, correcciones (planes de Claude), detalle de
cada plan (aprobar / rechazar / aplicar / revertir) y modo mantenimiento.

Acceso: contraseña opcional para todo el panel (HTTP Basic) y token para las acciones. Si hay
contraseña, las acciones la aceptan en lugar del token siempre que la petición venga de la propia
página (comprobación de origen contra CSRF).
"""
from __future__ import annotations

import base64
import datetime as dt
import hmac
import json
import logging
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import claude
from . import vista as V
from .modelo import ORDEN_SEVERIDAD
from .planes import aprobados, pendientes

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
        if len(apps) > 1:
            sel = ctx.get("app", "")
            ops = f'<option value="">Todas las apps ({len(apps)})</option>' + "".join(
                f'<option value="{E(a, quote=True)}"{" selected" if a == sel else ""}>{E(a)} · {d["vulns"]} vuln.'
                f'{(", " + str(d["crit"]) + " críticas") if d["crit"] else ""}</option>' for a, d in apps.items())
            selector = f'<label class="sel"><span>App</span><select id="sel-app" aria-label="App">{ops}</select></label>'
        aviso = self.cfg.get("banner") or ""
        if aviso:
            aviso = f'<div class="aviso-demo">{aviso}</div>'
        extra_nav = self.cfg.get("nav_extra") or []
        return V.pagina(titulo, cuerpo, activo=activo, web=self.v.cfg["general"]["nombre_web"], aviso=aviso,
                        toast=ctx.get("msg", ""), badges={"/correcciones": pendientes_n,
                                                          "/vulnerabilidades": criticas},
                        extra_nav=extra_nav, dialogo_token=ctx.get("pide_token", False), selector=selector, **kw)

    def _form_resolver(self, campos: str, texto: str, etiqueta: str, tamano_pequeno=True) -> str:
        """Formulario con ventana de confirmación: el usuario inicia EXPLÍCITAMENTE la resolución con Claude."""
        pequeno = 'style="padding:6px 11px"' if tamano_pequeno else ""
        aviso = (" Se enviarán a Anthropic, a través de Claude Code, las vulnerabilidades y los ficheros de despliegue del "
                 "proyecto (nunca los .env ni los datos de la app), y consume uso de tu plan de Claude. Claude solo "
                 "propone: no se modificará nada hasta que apruebes cada cambio.")
        return (f'<form method="post" action="/api/claude/resolver" data-confirmar="{E(texto + aviso, quote=True)}" '
                f'data-titulo="Resolver con Claude" data-boton="Sí, resolver con Claude">{campos}'
                f'{V.boton(etiqueta, "secundario", "robot", attrs=pequeno)}</form>')

    def _celda_resolver(self, c: dict) -> str:
        estado, dato = self.v.gestor.estado_resolver(c)
        if estado == "plan":
            return f'<a href="/plan/{E(dato)}">Ver el plan</a>'
        if estado == "disponible":
            return self._form_resolver(f'<input type="hidden" name="clave" value="{E(c["clave"], quote=True)}">',
                                       f"Claude preparará una corrección para {c['nombre']} {c['version']}.",
                                       "Resolver con Claude")
        return f'<span class="muted peq">{E(dato) if estado != "sin_vulns" else "—"}</span>'

    def _boton_resolver_app(self, ctx) -> str:
        app = ctx.get("app", "")
        if not app:
            return ""
        n = len(self.v.gestor.candidatos_app(app))
        if not n:
            return ""
        return self._form_resolver(f'<input type="hidden" name="app" value="{E(app, quote=True)}">',
                                   f"Claude preparará correcciones para {n} componente(s) de {app} con vulnerabilidades "
                                   "importantes (una por componente).", f"Resolver {app} con Claude", False)

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

        partes.append('<div class="kpis">' + "".join([
            V.kpi("Vulnerabilidades activas", len(hs), f"en {len({h['componente'] for h in hs})} componentes"),
            V.kpi("Críticas", len(criticas), "CVSS ≥ 9, explotadas o EPSS alto", "crit"),
            V.kpi("Explotadas activamente", len(kev), "catálogo CISA KEV", "crit" if kev else ""),
            V.kpi("Componentes vigilados", len(comps), f"{len(sin_soporte)} sin soporte" if sin_soporte else "todos con soporte"),
            V.kpi("Correcciones pendientes", len(pend), "esperan tu aprobación", "acc" if pend else "ok"),
        ]) + "</div>")

        if len(apps) > 1 and not ctx.get("app"):
            tarjetas = "".join(V.app_card(a, d) for a, d in apps.items())
            partes.append(V.tarjeta(f'<div class="apps">{tarjetas}</div>', f"Apps vigiladas ({len(apps)})",
                                    '<span class="muted peq">Elige una para verla sola, o usa el selector de arriba</span>',
                                    icono_nombre="caja"))
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
                                    attrs='style="padding:5px 10px"'), icono_nombre="alerta")

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
{V.boton("Revisar", "secundario", "flecha", href=f"/plan/{p['id']}", attrs='style="padding:6px 11px"')}</div></div>'''

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
        hs = sorted(self._datos(ctx)[0],
                    key=lambda h: (not h["critico"], not h.get("kev"), -ORDEN_SEVERIDAD[h["severidad"]],
                                   -(h.get("cvss") or 0)))
        planes = {p["componente"]["clave"]: p for p in reversed(self._planes())}
        filas = []
        for h in hs:
            epss = h.get("epss")
            epss_html = (f'<div class="meter"><b>{epss:.0%}</b><span><i style="width:{max(epss * 100, 3):.0f}%"></i>'
                         f'</span></div>') if epss is not None else '<span class="muted">—</span>'
            pl = planes.get(h["componente"])
            plan = (f'<a href="/plan/{pl["id"]}">{E(V.ESTADOS_PLAN.get(pl["estado"], (pl["estado"],))[0])}</a>'
                    if pl else '<span class="muted">—</span>')
            texto = f"{h['id']} {h['nombre']} {h['version']} {h.get('app', '')} {h['resumen']}".lower()
            filas.append(f'''<tr data-sev="{h["severidad"]}" data-kev="{1 if h.get("kev") else 0}" data-texto="{E(texto)}">
<td>{V.sev(h["severidad"])}</td><td class="mono">{self._enlace_cve(h)}{self._tags(h)}<div class="muted peq">{E(h["fuente"])} · {E(h.get("publicado") or "")}</div></td>
<td><b>{E(h["nombre"])}</b><div class="muted peq">{E(h["version"])}</div>{self._app_txt(h, ctx)}</td>
<td class="num">{h.get("cvss") or "—"}</td><td class="num">{epss_html}</td>
<td class="mono">{E(", ".join(h.get("corregido_en") or []) or "—")}</td>
<td><div class="clamp muted" title="{E(h["resumen"])}">{E(h["resumen"])}</div></td><td>{plan}</td></tr>''')
        chips = "".join(f'<button class="chip" data-sev="{s}" type="button">{V.sev(s)}</button>' for s, _ in V.SEVERIDADES)
        filtros = f'''<div class="filtros"><label class="buscar">{V.icono("buscar", 16)}<input id="f-q" type="search"
placeholder="Buscar CVE, componente o texto"></label>{chips}
<button class="chip" id="f-kev" type="button">{V.icono("alerta", 14)}Solo explotadas</button>
<span class="contador" id="f-n"></span></div>'''
        boton_mas = V.boton("Mostrar más", "secundario", "flecha", attrs='id="f-mas" type="button" hidden')
        tabla = (f'<div class="tabla"><table id="t-vulns" class="ancha"><thead><tr><th>Gravedad</th><th>Identificador</th><th>Componente</th>'
                 f'<th class="num">CVSS</th><th class="num">EPSS</th><th>Corregido en</th><th>Descripción</th><th>Corrección</th>'
                 f'</tr></thead><tbody>{"".join(filas)}</tbody></table></div><div class="mas">'
                 f'{boton_mas}</div>') \
            if filas else V.vacio("Sin vulnerabilidades activas")
        cuerpo = V.tarjeta(filtros, clase="") + V.tarjeta(tabla)
        return self.envolver("Vulnerabilidades", cuerpo, "/vulnerabilidades", ctx,
                             subtitulo=f"{len(hs)} activas, ordenadas por urgencia (explotadas y críticas primero)",
                             acciones=self._boton_analizar())

    # ------------------------------------------------------------------ componentes
    def componentes(self, ctx):
        est = self.v.estado
        hs, comps, _ = self._datos(ctx)
        ramas = est.get("info_ramas", {})
        filas = []
        for c in comps:
            cuenta = {}
            for h in hs:
                if h["componente"] == c["clave"]:
                    cuenta[h["severidad"]] = cuenta.get(h["severidad"], 0) + 1
            total = sum(cuenta.values())
            mini = "".join(f'<span class="seg-{s}" style="flex:{n}" data-tip="{n} {V.NOMBRE_SEV[s].lower()}"></span>'
                           for s, _ in V.SEVERIDADES for n in [cuenta.get(s, 0)] if n)
            vul = (f'<div style="display:flex;gap:10px;align-items:center"><div class="mini">{mini}</div>'
                   f'<b class="num">{total}</b></div>') if total else V.pill("Sin vulnerabilidades", "ok")
            r = ramas.get(c["clave"]) or {}
            if r.get("sin_soporte"):
                soporte = V.pill(f"Rama {r['rama']} sin soporte", "mal")
            elif r:
                soporte = V.pill(f"Soporte hasta {r.get('fin_soporte')}", "ok")
            else:
                soporte = '<span class="muted">—</span>'
            if r.get("desactualizada"):
                soporte += f'<div class="muted peq">Última de la rama: {E(str(r.get("ultima_de_rama")))}</div>'
            origen = {"exec": "Comando en el contenedor", "env": "Variables de la imagen", "imagen": "Etiqueta de imagen",
                      "fichero": "Fichero del proyecto", "http": "Cabeceras HTTP", "manual": "Configuración"}.get(c["origen"], c["origen"])
            detalle = c["detalle"]
            for raiz in self.v.cfg["deteccion"].get("rutas_proyecto") or []:
                detalle = detalle.replace(raiz.rstrip("/") + "/", "")
            filas.append(f'''<tr><td><b>{E(c["nombre"])}</b>{self._app_txt(c, ctx)}</td><td class="mono">{E(c["version"])}</td>
<td>{E(c["ecosistema"] or ("Runtime" if c["tipo"] == "runtime" else c["tipo"]))}</td><td>{vul}</td><td>{soporte}</td>
<td>{E(origen)}<div class="muted peq" title="{E(c["detalle"])}">{E(detalle[-70:])}{(" · " + E(c["contenedor"])) if c["contenedor"] else ""}</div></td>
<td>{self._celda_resolver(c)}</td></tr>''')
        tabla = (f'<div class="tabla"><table class="ancha"><thead><tr><th>Componente</th><th>Versión</th><th>Tipo</th><th>Vulnerabilidades</th>'
                 f'<th>Soporte</th><th>Detectado por</th><th>Corrección</th></tr></thead><tbody>{"".join(filas)}</tbody></table></div>')
        return self.envolver("Componentes", V.tarjeta(tabla), "/componentes", ctx,
                             subtitulo=f"{len(comps)} componentes detectados. Claude solo trabaja cuando pulsas «Resolver con Claude»",
                             acciones=self._boton_resolver_app(ctx) + self._boton_analizar())

    # ------------------------------------------------------------------ correcciones
    def correcciones(self, ctx):
        planes = self._datos(ctx)[2]
        activos = [p for p in planes if p["estado"] in ("pendiente_aprobacion", *TRANSITORIOS)]
        historial = [p for p in planes if p not in activos]
        if not planes:
            ayuda = ("Todavía no has pedido ninguna corrección. Claude no hace nada por su cuenta: ve a Componentes y "
                     "pulsa «Resolver con Claude» en el que quieras arreglar." if claude.disponible(self.v.cfg["claude"])
                     else "Inicia sesión en Claude Code o configura CLAUDE_CODE_OAUTH_TOKEN (claude setup-token) para poder pedirle correcciones a Claude.")
            cuerpo = V.tarjeta(V.vacio(ayuda, "llave") + '<div style="text-align:center">'
                               + V.boton("Ir a Componentes", "secundario", "flecha", href="/componentes") + "</div>")
        else:
            cuerpo = V.tarjeta('<div class="lista">' + ("".join(self._item_plan(p) for p in activos)
                                                       or V.vacio("Nada pendiente")) + "</div>",
                               "Pendientes y en curso", icono_nombre="llave")
            if historial:
                cuerpo += V.tarjeta('<div class="lista">' + "".join(self._item_plan(p) for p in historial) + "</div>",
                                    "Historial", icono_nombre="reloj")
        explic = (f'<div class="banner banner-info">{V.icono("candado", 22)}<div><b>Cómo funciona</b><p>Claude solo trabaja cuando TÚ se lo pides, con el botón «Resolver con Claude». '
                  'Entonces propone cambios concretos y los justifica uno a uno; el vigilante los prueba en una copia con contenedores de '
                  'prueba. Tú apruebas o rechazas cada cambio (o todos). Solo entonces se aplica, con copia de seguridad '
                  'y posibilidad de revertir.</p></div></div>')
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
            botones = [f'''<form method="post" action="/api/plan/{p["id"]}/todo" data-confirmar="Se rechazarán los {len(p["cambios"])}
cambios y no se aplicará nada." data-titulo="Rechazar todo" data-boton="Rechazar todo" data-tono="btn-rojo">
<input type="hidden" name="decision" value="rechazado">{V.boton("Rechazar todo", "peligro", "x")}</form>''']
            if n_ap:
                botones.append(f'''<form method="post" action="/api/plan/{p["id"]}/aplicar" data-confirmar="Se aplicarán los
{n_ap} cambio(s) aprobados en la web, con copia de seguridad previa y comprobación posterior. Si la web no responde bien,
se restaurará lo anterior automáticamente." data-titulo="Aplicar {n_ap} cambio(s)" data-boton="Aplicar ahora" data-tono="btn-ok">
{V.boton(f"Aplicar {n_ap} aprobado(s)", "ok", "play")}</form>''')
            botones.append(f'''<form method="post" action="/api/plan/{p["id"]}/todo" data-confirmar="Se aprobarán los
{len(p["cambios"])} cambios y se aplicarán ya en la web, con copia de seguridad previa." data-titulo="Aprobar todo y aplicar"
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
                                 + (f'<dl class="dl" style="margin-top:14px">{ops}</dl>' if ops else ""),
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
        vulns = "".join(f'''<tr><td>{V.sev(h["severidad"])}</td><td class="mono">{self._enlace_cve(h)}{self._tags(h)}</td>
<td class="num">{h.get("cvss") or "—"}</td></tr>''' for h in sorted(p["hallazgos"], key=lambda h: -(h.get("cvss") or 0))[:40])
        lateral.append(V.tarjeta(f'<details><summary>Ver las {len(p["hallazgos"])} vulnerabilidades</summary><div>'
                                 f'<table><tbody>{vulns}</tbody></table></div></details>',
                                 "Vulnerabilidades que cubre", icono_nombre="alerta"))
        registro = "".join(f'<li><div class="tl-i">{V.icono("punto", 12)}</div><div class="tl-c"><b>{E(r["evento"])}</b>'
                           f'<p>{E(_hora(r["fecha"]))} · {E(r["por"])}</p></div></li>' for r in reversed(p["registro"]))
        lateral.append(V.tarjeta(f'<ul class="tl">{registro}</ul>', "Registro (auditoría)", icono_nombre="reloj"))

        partes.append(f'<div class="grid g2b"><div style="display:flex;flex-direction:column;gap:18px;min-width:0">{principal}</div>'
                      f'<div style="display:flex;flex-direction:column;gap:18px;min-width:0">{"".join(lateral)}</div></div>')
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
        criticos = [h for h in self.v.estado.get("hallazgos", {}).values() if h["critico"]]
        if m["activo"]:
            estado = (f'<div class="estado-web"><div class="ew-i ew-off">{V.icono("power", 26)}</div><div>'
                      f'<b>La web está en modo mantenimiento</b><span class="muted">{E(m.get("motivo", ""))} · desde '
                      f'{E(_hora(m.get("desde")))} · por {E(m.get("por", ""))}</span></div></div>')
            form = (f'<form method="post" action="/api/mantenimiento" data-confirmar="La web volverá a atender a los '
                    f'visitantes con normalidad." data-titulo="Volver a poner la web en línea" data-boton="Poner en línea">'
                    f'<input type="hidden" name="accion" value="desactivar">{V.boton("Volver a poner en línea", "ok", "pulso")}</form>')
        else:
            estado = (f'<div class="estado-web"><div class="ew-i ew-on">{V.icono("pulso", 26)}</div><div>'
                      f'<b>La web está en línea</b><span class="muted">Sirviendo con normalidad</span></div></div>')
            form = (f'<form method="post" action="/api/mantenimiento" data-confirmar="Todos los visitantes verán la página '
                    f'de mantenimiento (HTTP 503) hasta que la vuelvas a poner en línea." data-titulo="Poner la web en '
                    f'mantenimiento" data-boton="Activar mantenimiento" data-tono="btn-rojo">'
                    f'<input type="hidden" name="accion" value="activar">{V.boton("Poner en mantenimiento", "rojo", "power")}</form>')
        lista = "".join(f'<tr><td>{V.sev(h["severidad"])}</td><td class="mono">{self._enlace_cve(h)}{self._tags(h)}</td>'
                        f'<td><b>{E(h["nombre"])}</b> <span class="muted">{E(h["version"])}</span></td></tr>'
                        for h in criticos[:12])
        modo = self.v.cfg["mantenimiento"].get("modo", "manual")
        texto_modo = {"off": "desactivado", "manual": "manual: te avisa y tú decides",
                      "auto": "automático ante críticas explotadas"}.get(modo, modo)
        cuerpo = (V.tarjeta(f'<div style="display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap">'
                            f'{estado}{form}</div>', "Estado", icono_nombre="power")
                  + f'<div class="grid g2">'
                  + V.tarjeta((f'<div class="tabla"><table><tbody>{lista}</tbody></table></div>' if lista
                               else V.vacio("No hay vulnerabilidades críticas abiertas")),
                              f"Vulnerabilidades críticas abiertas ({len(criticos)})", icono_nombre="alerta")
                  + V.tarjeta(f'<p style="margin-top:0">Modo configurado: <b>{E(texto_modo)}</b>.</p><p class="muted">'
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
    usuario, clave = cfg_panel.get("usuario") or "", cfg_panel.get("clave") or ""
    limite = LimiteIntentos()

    class Manejador(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            log.debug("panel: " + fmt, *a)

        # -------- contraseña de acceso (HTTP Basic) para todo el panel, si está configurada
        def _basic_ok(self) -> bool:
            if not clave:
                return False
            cab = self.headers.get("Authorization") or ""
            if not cab.startswith("Basic "):
                return False
            try:
                u, _, c = base64.b64decode(cab[6:]).decode().partition(":")
            except ValueError:
                return False
            return hmac.compare_digest(u, usuario) and hmac.compare_digest(c, clave)

        def _ip(self) -> str:
            return self.headers.get("CF-Connecting-IP") or self.client_address[0]

        def _exigir_acceso(self) -> bool:
            if not clave:
                return True
            espera = limite.restante(self._ip())
            if espera:
                cuerpo = f"Demasiados intentos. Prueba de nuevo en {espera} s.".encode()
                self.send_response(429)
                self.send_header("Retry-After", str(espera))
                self.send_header("Content-Length", str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)
                return False
            if self._basic_ok():
                limite.acierto(self._ip())
                return True
            if self.headers.get("Authorization"):       # credenciales dadas pero incorrectas
                limite.fallo(self._ip())
            cuerpo = b"Acceso restringido"
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Vigilante", charset="UTF-8"')
            self.send_header("Content-Length", str(len(cuerpo)))
            self.end_headers()
            self.wfile.write(cuerpo)
            return False

        def _mismo_origen(self) -> bool:
            """Protección CSRF cuando la contraseña Basic sustituye al token."""
            origen = self.headers.get("Origin") or self.headers.get("Referer") or ""
            return bool(origen) and urllib.parse.urlparse(origen).netloc == self.headers.get("Host", "")

        def _ctx(self, q=None):
            q = q or {}
            pide_token = not clave and not panel.token_ok(_cookie(self.headers, "vigilante_token"))
            conocidas = panel._resumen_apps()
            app = urllib.parse.unquote(q["app"]) if "app" in q else urllib.parse.unquote(_cookie(self.headers, "vigilante_app"))
            app = app if app in conocidas else ""
            if "app" in q:
                self._extra = [("Set-Cookie", f"vigilante_app={urllib.parse.quote(app)}; Path=/; SameSite=Strict; Max-Age=31536000")]
            return {"msg": q.get("msg", ""), "pide_token": pide_token, "app": app}

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
            if not self._exigir_acceso():
                return
            ctx = self._ctx(q)
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
            largo = min(int(self.headers.get("Content-Length") or 0), 10_000)
            form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(largo).decode()).items()}
            if not self._exigir_acceso():
                return
            token = form.get("token") or self.headers.get("X-Token", "") or _cookie(self.headers, "vigilante_token")
            con_basic = not token and self._basic_ok() and self._mismo_origen()
            if not (panel.token_ok(token) or con_basic):
                ctx = {"msg": "Token incorrecto o sin configurar (VIGILANTE_PANEL_TOKEN). No se ha hecho nada.",
                       "pide_token": True}
                return self._enviar(403, panel.mantenimiento(ctx) if ruta == "/api/mantenimiento" else
                                    panel.envolver("Acceso denegado", V.tarjeta(V.vacio(
                                        "Hace falta el token del panel para hacer cambios.", "candado")), "", ctx))
            self._cookie = (f"vigilante_token={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200"
                            if token else None)
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
                    msg = vigilante.gestor.solicitar_app(form["app"], por)
                else:
                    msg = vigilante.gestor.solicitar_componente(form.get("clave", ""), por)
                return self._redirigir(f"/correcciones?msg={urllib.parse.quote(msg)}", self._cookie)
            if ruta == "/api/escanear":
                if not vigilante.en_curso:
                    threading.Thread(target=vigilante.ciclo, args=("panel",), daemon=True).start()
                msg = "Análisis en marcha: la página se actualizará sola."
                volver = urllib.parse.urlparse(self.headers.get("Referer") or "/").path or "/"
                return self._redirigir(f"{volver}?msg={urllib.parse.quote(msg)}", self._cookie)
            self._enviar(404, "No encontrado", "text/plain")

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
    log.info("Panel en http://%s:%d%s", host, puerto, " (con contraseña)" if clave else "")
    return srv
