"""Capa visual del panel: estilos, iconos SVG, componentes y plantilla de página.

Sin dependencias ni recursos externos (todo va en línea), sin emoticonos: los estados se
representan con iconos SVG + texto, nunca solo con color.

Colores de gravedad = paleta de estado (crítica / alta / media) + neutro para baja; cada
indicador de color va siempre acompañado de su etiqueta.
"""
from __future__ import annotations

import html
import re

E = html.escape

# ------------------------------------------------------------------ iconos (24x24, trazo)
_I = {
    "escudo": ['M12 3l7.5 3v5.2c0 4.6-3.1 8.6-7.5 9.8-4.4-1.2-7.5-5.2-7.5-9.8V6L12 3z', 'M9 12l2 2 4-4'],
    "resumen": ['M4 4h7v7H4z', 'M13 4h7v4h-7z', 'M13 10h7v10h-7z', 'M4 13h7v7H4z'],
    "alerta": ['M12 4l9.5 16.5h-19L12 4z', 'M12 10v4.5', 'M12 17.6v.1'],
    "caja": ['M20.5 7.5L12 3 3.5 7.5v9L12 21l8.5-4.5v-9z', 'M3.5 7.5L12 12l8.5-4.5', 'M12 12v9'],
    "llave": ['M15 7.5a4.5 4.5 0 1 1-3.4 7.4L5 21.5H2.5V19l6.6-6.6A4.5 4.5 0 0 1 15 7.5z', 'M16 9.5v.1'],
    "power": ['M12 3v8', 'M6.6 6.6a7.5 7.5 0 1 0 10.8 0'],
    "chat": ['M4 5h16v11H9l-5 4V5z', 'M8 9.5h8', 'M8 12.5h5'],
    "refrescar": ['M20 12a8 8 0 1 1-2.3-5.7', 'M20 4v5h-5'],
    "check": ['M5 12.5l4.5 4.5L19 7.5'],
    "x": ['M6.5 6.5l11 11', 'M17.5 6.5l-11 11'],
    "deshacer": ['M9 14L4 9l5-5', 'M4 9h10.5a5.5 5.5 0 0 1 0 11H11'],
    "flecha": ['M5 12h14', 'M13 6l6 6-6 6'],
    "reloj": ['M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 1 0 0-17z', 'M12 7.5V12l3 2'],
    "info": ['M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 1 0 0-17z', 'M12 11v5', 'M12 7.9v.1'],
    "externo": ['M14 4h6v6', 'M20 4l-9 9', 'M18 14v6H4V6h6'],
    "buscar": ['M11 4a7 7 0 1 0 0 14 7 7 0 1 0 0-14z', 'M20 20l-4-4'],
    "play": ['M8 5l11 7-11 7V5z'],
    "fichero": ['M14 3H6.5v18h11V6.5L14 3z', 'M14 3v3.5h3.5', 'M9 12h6', 'M9 15.5h6'],
    "candado": ['M6 11h12v9.5H6z', 'M8.5 11V8a3.5 3.5 0 0 1 7 0v3'],
    "pulso": ['M3 12h4l2.5-6.5 5 13 2.5-6.5h4'],
    "capas": ['M12 4l9 4.5-9 4.5-9-4.5L12 4z', 'M3 13l9 4.5 9-4.5'],
    "robot": ['M6 8h12v10H6z', 'M12 4v4', 'M9.5 12.5v.1', 'M14.5 12.5v.1', 'M9.5 15.5h5', 'M3.5 12v3', 'M20.5 12v3'],
    "punto": ['M12 10.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 1 0 0-3z'],
    "enviar": ['M4 12l16-7-6 16-3-7-7-2z'],
    "menos": ['M6 12h12'],
}


def icono(nombre: str, tam: int = 18, clase: str = "") -> str:
    trazos = "".join(f'<path d="{d}"/>' for d in _I.get(nombre, _I["punto"]))
    return (f'<svg class="ico {clase}" width="{tam}" height="{tam}" viewBox="0 0 24 24" fill="none" '
            f'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" '
            f'aria-hidden="true">{trazos}</svg>')


# ------------------------------------------------------------------ etiquetas
SEVERIDADES = [("CRITICA", "Crítica"), ("ALTA", "Alta"), ("MEDIA", "Media"), ("BAJA", "Baja")]
NOMBRE_SEV = dict(SEVERIDADES) | {"DESCONOCIDA": "Sin puntuar"}
ESTADOS_PLAN = {
    "analizando": ("Claude analizando", "info"), "verificando": ("Verificando en copia", "info"),
    "pendiente_aprobacion": ("Esperando tu decisión", "aviso"), "aplicando": ("Aplicando", "info"),
    "aplicado": ("Aplicado", "ok"), "fallo_aplicacion": ("Falló al aplicar", "mal"),
    "revertido": ("Revertido", "neutro"), "rechazado": ("Rechazado", "neutro"),
    "obsoleto": ("Obsoleto", "neutro"), "error": ("Error", "mal"),
    "sin_cambios": ("Sin cambios propuestos", "neutro"),
}
ESTADOS_VERIF = {"ok": ("Verificación superada", "ok"), "solo_estatica": ("Solo verificación estática", "aviso"),
                 "parcial": ("Verificación parcial", "aviso"), "fallo": ("Verificación fallida", "mal"),
                 "en_curso": ("Verificando", "info")}
RIESGO = {"bajo": ("Riesgo bajo", "ok"), "medio": ("Riesgo medio", "aviso"), "alto": ("Riesgo alto", "mal")}
TIPO_CAMBIO = {"actualizar_dependencia": "Dependencia", "actualizar_imagen": "Imagen Docker",
               "configuracion": "Configuración", "codigo": "Código", "mitigacion_temporal": "Mitigación temporal"}
ICONO_TONO = {"ok": "check", "mal": "x", "aviso": "alerta", "info": "reloj", "neutro": "punto"}


def sev(s: str) -> str:
    return f'<span class="sev sev-{E(s)}"><i></i>{E(NOMBRE_SEV.get(s, s))}</span>'


def pill(texto: str, tono: str = "neutro", con_icono=True) -> str:
    ic = icono(ICONO_TONO.get(tono, "punto"), 14) if con_icono else ""
    return f'<span class="pill pill-{tono}">{ic}{E(texto)}</span>'


def estado_plan(estado: str) -> str:
    t, tono = ESTADOS_PLAN.get(estado, (estado, "neutro"))
    return pill(t, tono)


def estado_verif(estado: str | None) -> str:
    if not estado:
        return pill("Sin verificar", "neutro")
    t, tono = ESTADOS_VERIF.get(estado, (estado, "neutro"))
    return pill(t, tono)


def boton(texto, tipo="secundario", icono_nombre=None, href=None, attrs="") -> str:
    ic = icono(icono_nombre, 16) if icono_nombre else ""
    if href:
        return f'<a class="btn btn-{tipo}" href="{E(href)}" {attrs}>{ic}<span>{E(texto)}</span></a>'
    return f'<button class="btn btn-{tipo}" {attrs}>{ic}<span>{E(texto)}</span></button>'


def tarjeta(cuerpo: str, titulo: str = "", extra: str = "", clase: str = "", icono_nombre: str = "") -> str:
    cab = ""
    if titulo or extra:
        ic = icono(icono_nombre, 18) if icono_nombre else ""
        cab = f'<div class="card-h"><h3>{ic}{E(titulo)}</h3><div class="card-x">{extra}</div></div>'
    return f'<section class="card {clase}">{cab}<div class="card-b">{cuerpo}</div></section>'


def kpi(etiqueta: str, valor, nota: str = "", tono: str = "") -> str:
    return (f'<div class="kpi {("kpi-" + tono) if tono else ""}"><div class="kpi-l">{E(etiqueta)}</div>'
            f'<div class="kpi-v">{E(str(valor))}</div><div class="kpi-n">{nota}</div></div>')


def app_card(nombre: str, d: dict, activa: bool = False) -> str:
    crit = pill(f"{d['crit']} crítica(s)", "mal") if d["crit"] else pill("Sin críticas", "ok")
    plan = (f'<span class="app-n">{pill(str(d["pend"]) + " corrección(es) pendiente(s)", "aviso")}</span>'
            if d["pend"] else "")
    cont = ", ".join(sorted(d["contenedores"]))
    return (f'<a class="app-card{" on" if activa else ""}" href="/?app={html.escape(nombre, quote=True)}">'
            f'<div class="app-h">{icono("caja", 18)}<b>{E(nombre)}</b></div>'
            f'<div class="app-k"><span><b>{d["vulns"]}</b> vulnerabilidades</span><span><b>{d["comps"]}</b> componentes</span></div>'
            f'<div class="app-p">{crit}{plan}</div><small title="{E(cont)}">{E(cont[:70]) or "sin contenedores"}</small></a>')


def vacio(texto: str, icono_nombre="check") -> str:
    return f'<div class="vacio">{icono(icono_nombre, 28)}<p>{E(texto)}</p></div>'


def diff(texto: str) -> str:
    """Diff unificado coloreado, con números de línea del fichero nuevo."""
    if not texto.strip():
        return '<p class="muted">Sin cambios en ficheros (solo comandos).</p>'
    filas = []
    for l in texto.splitlines():
        if l.startswith(("diff --git", "index ", "new file", "deleted file")):
            continue
        if l.startswith("+++ "):
            nombre = re.sub(r"^\+\+\+ (b/)?", "", l)
            filas.append(f'<div class="d-f">{icono("fichero", 14)}{E(nombre)}</div>')
            continue
        if l.startswith("--- "):
            continue
        clase = "d-a" if l.startswith("+") else "d-b" if l.startswith("-") else "d-h" if l.startswith("@@") else "d-c"
        filas.append(f'<div class="{clase}">{E(l) or "&nbsp;"}</div>')
    return f'<div class="diff">{"".join(filas)}</div>'


def barra_gravedad(cuentas: dict, total_max: int, etiqueta: str, enlace: str = "") -> str:
    """Barra horizontal apilada por gravedad (con huecos de 2px y extremos redondeados)."""
    total = sum(cuentas.values())
    segs = []
    for s, nombre in SEVERIDADES:
        n = cuentas.get(s, 0)
        if n:
            ancho = 100 * n / max(total_max, 1)
            segs.append(f'<span class="seg seg-{s}" style="width:{ancho:.2f}%" '
                        f'data-tip="{E(etiqueta)} · {nombre}: {n}"></span>')
    nombre = f'<a href="{E(enlace)}">{E(etiqueta)}</a>' if enlace else E(etiqueta)
    return (f'<div class="fila-barra"><div class="fb-n" title="{E(etiqueta)}">{nombre}</div>'
            f'<div class="fb-b">{"".join(segs)}</div><div class="fb-t">{total}</div></div>')


def leyenda_gravedad() -> str:
    return '<div class="leyenda">' + "".join(
        f'<span><i class="seg-{s}"></i>{n}</span>' for s, n in SEVERIDADES) + "</div>"


# ------------------------------------------------------------------ página
NAV = [("/", "Resumen", "resumen"), ("/vulnerabilidades", "Vulnerabilidades", "alerta"),
       ("/componentes", "Componentes", "caja"), ("/correcciones", "Correcciones", "llave"),
       ("/mantenimiento", "Mantenimiento", "power")]


def pagina(titulo: str, cuerpo: str, *, activo: str = "/", web: str = "", subtitulo: str = "",
           acciones: str = "", aviso: str = "", toast: str = "", badges: dict | None = None,
           extra_nav: list | None = None, refrescar: int = 0, dialogo_token: bool = False,
           selector: str = "") -> str:
    badges = badges or {}
    nav = []
    for href, nombre, ic in NAV + (extra_nav or []):
        b = f'<span class="nb">{badges[href]}</span>' if badges.get(href) else ""
        clase = "act" if href == activo else ""
        nav.append(f'<a class="{clase}" href="{href}">{icono(ic, 18)}<span>{E(nombre)}</span>{b}</a>')
    meta = f'<meta http-equiv="refresh" content="{refrescar}">' if refrescar else ""
    t = (f'<div class="toast" role="status">{icono("info", 18)}<span>{E(toast)}</span>'
         f'<button class="toast-x" aria-label="Cerrar">{icono("x", 16)}</button></div>') if toast else ""
    token = ('<label class="campo"><span>Token del panel</span><input type="password" id="dlg-token" '
             'autocomplete="current-password" placeholder="VIGILANTE_PANEL_TOKEN"></label>') if dialogo_token else ""
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{meta}
<title>{E(titulo)} · Vigilante</title><style>{CSS}</style></head>
<body><div class="app">
<aside class="side"><a class="marca" href="/">{icono("escudo", 26)}<span><b>Vigilante</b><small>{E(web)}</small></span></a>
<nav>{''.join(nav)}</nav>
<div class="side-pie">{icono("candado", 14)}<span>Nada se aplica sin tu aprobación</span></div></aside>
<div class="main">{aviso}
<header class="top"><div><h1>{E(titulo)}</h1>{f'<p>{subtitulo}</p>' if subtitulo else ''}</div>
<div class="top-x">{selector}{acciones}</div></header>
<main class="cont">{cuerpo}</main></div></div>
{t}<div class="tip" id="tip" hidden></div>
<dialog id="dlg"><form method="dialog" class="dlg-c"><div class="dlg-i">{icono("alerta", 22)}</div>
<h3 id="dlg-t">¿Confirmas?</h3><p id="dlg-m"></p>{token}
<div class="dlg-b"><button class="btn btn-secundario" value="no">Cancelar</button>
<button class="btn btn-primario" value="si" id="dlg-ok">Confirmar</button></div></form></dialog>
<script>{JS}</script></body></html>"""


CSS = r"""
:root{--bg:#f4f5f8;--card:#fff;--line:#e5e7ee;--line2:#eef0f4;--ink:#0f172a;--ink2:#475467;--muted:#667085;
--acc:#4338ca;--acc2:#eef0ff;--side:#0c1222;--side2:#141c31;--side-ink:#c7cde0;
--crit:#d03b3b;--alta:#ec835a;--media:#fab219;--baja:#8a94a6;--ok:#0ca30c;
--ok-t:#05660a;--ok-bg:#e8f6e8;--mal-t:#a52323;--mal-bg:#fdecec;--av-t:#8a5300;--av-bg:#fff4dc;
--inf-t:#3730a3;--inf-bg:#eef0ff;--neu-t:#475467;--neu-bg:#f0f2f6;
--sh:0 1px 2px rgba(16,24,40,.05),0 1px 3px rgba(16,24,40,.06);--r:14px}
@media (prefers-color-scheme:dark){:root{--bg:#0e121b;--card:#161b26;--line:#262d3b;--line2:#1e2431;--ink:#eef1f7;
--ink2:#b4bccb;--muted:#8a94a8;--acc:#8b93ff;--acc2:#23284a;--side:#0a0e17;--side2:#151b2b;
--ok-t:#5fd35f;--ok-bg:#132a17;--mal-t:#ff8a8a;--mal-bg:#331616;--av-t:#ffc65a;--av-bg:#2f2410;
--inf-t:#aab0ff;--inf-bg:#1f2447;--neu-t:#b4bccb;--neu-bg:#1f2533;--baja:#7d8799;
--sh:0 1px 2px rgba(0,0,0,.4)}}
*{box-sizing:border-box}html,body{margin:0}[hidden]{display:none!important}
body{font:14.5px/1.5 Inter,"Segoe UI",system-ui,-apple-system,Roboto,sans-serif;background:var(--bg);color:var(--ink);
-webkit-font-smoothing:antialiased}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.ico{flex:none;vertical-align:middle}
.app{display:flex;min-height:100vh;background:linear-gradient(to right,var(--side) 248px,var(--bg) 248px)}
.side{width:248px;flex:none;background:var(--side);color:var(--side-ink);display:flex;flex-direction:column;
position:sticky;top:0;height:100vh;padding:18px 14px}
.marca{display:flex;gap:11px;align-items:center;color:#fff;padding:6px 8px 20px;text-decoration:none!important}
.marca .ico{color:#8b93ff}.marca b{display:block;font-size:17px;letter-spacing:.2px}
.marca small{display:block;color:#8d95ab;font-size:12px;max-width:170px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.side nav{display:flex;flex-direction:column;gap:3px}
.side nav a{display:flex;align-items:center;gap:11px;padding:9px 11px;border-radius:10px;color:var(--side-ink);
font-weight:500;text-decoration:none}
.side nav a:hover{background:var(--side2);color:#fff}.side nav a.act{background:#1d2540;color:#fff}
.side nav a.act .ico{color:#8b93ff}
.nb{margin-left:auto;background:#4338ca;color:#fff;font-size:11.5px;font-weight:700;border-radius:99px;padding:1px 8px}
.side-pie{margin-top:auto;display:flex;gap:8px;align-items:center;font-size:12px;color:#8d95ab;padding:10px;
border-top:1px solid #1c2338}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.aviso-demo{background:linear-gradient(90deg,#1e1b4b,#312e81);color:#e0e3ff;padding:9px 28px;font-size:13px;
display:flex;gap:10px;align-items:center;flex-wrap:wrap}.aviso-demo a{color:#fff;font-weight:600;text-decoration:underline}
.aviso-demo b{background:#4f46e5;color:#fff;border-radius:6px;padding:1px 8px;font-size:11.5px;letter-spacing:.5px}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;padding:26px 32px 6px;flex-wrap:wrap}
.top h1{margin:0;font-size:24px;letter-spacing:-.3px}.top p{margin:4px 0 0;color:var(--muted)}
.top-x{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.cont{padding:18px 32px 60px;display:flex;flex-direction:column;gap:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--sh);min-width:0}
.card-h{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:15px 18px 0}
.card-h h3{margin:0;font-size:15px;display:flex;align-items:center;gap:9px}.card-h h3 .ico{color:var(--muted)}
.card-x{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.card-b{padding:14px 18px 18px}
.grid{display:grid;gap:18px}.g2{grid-template-columns:1.6fr 1fr}.g2b{grid-template-columns:minmax(0,1fr) 380px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:16px 18px;box-shadow:var(--sh);
position:relative;overflow:hidden}
.kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--line)}
.kpi-crit::before{background:var(--crit)}.kpi-alta::before{background:var(--alta)}.kpi-acc::before{background:var(--acc)}
.kpi-ok::before{background:var(--ok)}
.kpi-l{color:var(--muted);font-size:13px;font-weight:500}.kpi-v{font-size:30px;font-weight:650;letter-spacing:-.5px;margin-top:2px}
.kpi-n{color:var(--muted);font-size:12.5px;min-height:18px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;font:inherit;font-weight:600;font-size:13.5px;
padding:9px 15px;border-radius:10px;border:1px solid transparent;cursor:pointer;text-decoration:none!important;
transition:background .15s,border-color .15s,transform .05s;white-space:nowrap}
.btn:active{transform:translateY(1px)}
.btn-primario{background:var(--acc);color:#fff}.btn-primario:hover{background:#3730a3}
.btn-secundario{background:var(--card);color:var(--ink);border-color:var(--line)}.btn-secundario:hover{background:var(--bg)}
.btn-ok{background:#0f7b0f;color:#fff}.btn-ok:hover{background:#0b650b}
.btn-peligro{background:var(--card);color:var(--mal-t);border-color:#f1c4c4}.btn-peligro:hover{background:var(--mal-bg)}
.btn-rojo{background:#c62828;color:#fff}.btn-rojo:hover{background:#a51f1f}
.btn-sm{padding:6px 11px;font-size:13px}
.pill{display:inline-flex;align-items:center;gap:5px;font-size:12.5px;font-weight:600;padding:3px 10px 3px 8px;
border-radius:99px;white-space:nowrap}
.pill-ok{background:var(--ok-bg);color:var(--ok-t)}.pill-mal{background:var(--mal-bg);color:var(--mal-t)}
.pill-aviso{background:var(--av-bg);color:var(--av-t)}.pill-info{background:var(--inf-bg);color:var(--inf-t)}
.pill-neutro{background:var(--neu-bg);color:var(--neu-t)}
.sev{display:inline-flex;align-items:center;gap:7px;font-weight:600;font-size:13px;white-space:nowrap}
.sev i{width:9px;height:9px;border-radius:3px;display:inline-block;background:var(--baja)}
.sev-CRITICA i{background:var(--crit)}.sev-ALTA i{background:var(--alta)}.sev-MEDIA i{background:var(--media)}
.tag{display:inline-block;background:var(--neu-bg);color:var(--neu-t);border-radius:6px;padding:1px 7px;font-size:12px;
font-weight:600;margin-left:6px}.tag-kev{background:var(--mal-bg);color:var(--mal-t)}
table{border-collapse:collapse;width:100%}
th{text-align:left;font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;
padding:10px 12px;border-bottom:1px solid var(--line);white-space:nowrap;background:var(--card);position:sticky;top:0}
td{padding:11px 12px;border-bottom:1px solid var(--line2);vertical-align:top}
tr:last-child td{border-bottom:0}tbody tr:hover td{background:var(--bg)}
.num{font-variant-numeric:tabular-nums;text-align:right}table.ancha td.mono{white-space:nowrap}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.8px}
.tabla{overflow-x:auto;margin:-14px -18px -18px}.tabla table.ancha{min-width:760px}
.muted{color:var(--muted)}.peq{font-size:12.5px}.clamp{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;max-width:520px}
.meter{display:flex;align-items:center;gap:8px;justify-content:flex-end}
.meter b{font-weight:600;min-width:28px;text-align:right}.meter span{width:54px;height:6px;border-radius:99px;background:var(--line2);overflow:hidden}
.meter span i{display:block;height:100%;border-radius:99px;background:var(--muted)}
.leyenda{display:flex;gap:16px;flex-wrap:wrap;font-size:12.5px;color:var(--ink2);margin-bottom:12px}
.leyenda span{display:inline-flex;align-items:center;gap:6px}.leyenda i{width:10px;height:10px;border-radius:3px;display:inline-block}
.fila-barra{display:grid;grid-template-columns:170px 1fr 42px;gap:12px;align-items:center;padding:6px 0}
.fb-n{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:500;font-size:13.5px}.fb-n a{color:var(--ink)}
.fb-b{display:flex;gap:2px;height:14px}
.seg{height:100%;min-width:3px;cursor:default}.seg:first-child{border-radius:4px 0 0 4px}.seg:last-child{border-radius:0 4px 4px 0}
.seg:only-child{border-radius:4px}.seg:hover{filter:brightness(1.1) saturate(1.1)}
.seg-CRITICA{background:var(--crit)}.seg-ALTA{background:var(--alta)}.seg-MEDIA{background:var(--media)}.seg-BAJA{background:var(--baja)}
.fb-t{text-align:right;font-weight:600;font-variant-numeric:tabular-nums;color:var(--ink2)}
.tip{position:fixed;z-index:50;background:#0f172a;color:#fff;font-size:12.5px;padding:6px 10px;border-radius:8px;
pointer-events:none;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.banner{display:flex;gap:14px;align-items:center;padding:14px 18px;border-radius:var(--r);border:1px solid}
.banner .ico{flex:none}.banner div{flex:1}.banner b{display:block}
.banner-aviso{background:var(--av-bg);border-color:#f3dba5;color:var(--av-t)}
.banner-mal{background:var(--mal-bg);border-color:#f1c4c4;color:var(--mal-t)}
.banner-info{background:var(--inf-bg);border-color:#d6d9ff;color:var(--inf-t)}
.banner-ok{background:var(--ok-bg);border-color:#bfe5bf;color:var(--ok-t)}
.banner p{margin:2px 0 0;color:inherit;opacity:.9}
.lista{display:flex;flex-direction:column}
.item{display:flex;gap:14px;align-items:center;padding:13px 0;border-bottom:1px solid var(--line2);flex-wrap:wrap}
.item:last-child{border-bottom:0}.item-i{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;
background:var(--acc2);color:var(--acc);flex:none}.item-c{flex:1 1 220px;min-width:0}.item-c b{display:block}
.item-c small{color:var(--muted)}.item-x{display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end}
.version{display:inline-flex;align-items:center;gap:6px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.version .de{color:var(--muted);text-decoration:line-through;text-decoration-color:rgba(208,59,59,.6)}
.version .a{color:var(--ok-t);font-weight:700}
.filtros{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.buscar{display:flex;align-items:center;gap:8px;border:1px solid var(--line);border-radius:10px;padding:0 11px;background:var(--card);
min-width:260px}.buscar input{border:0;outline:0;font:inherit;padding:8px 0;background:transparent;color:var(--ink);width:100%}
.chip{font:inherit;font-size:13px;font-weight:600;padding:6px 12px;border-radius:99px;border:1px solid var(--line);
background:var(--card);color:var(--ink2);cursor:pointer;display:inline-flex;gap:7px;align-items:center}
.chip.on{background:var(--ink);color:var(--card);border-color:var(--ink)}
.chip .sev i{width:8px;height:8px}
.contador{margin-left:auto;color:var(--muted);font-size:13px}
.mas{display:flex;justify-content:center;padding:16px 0 4px}
.pasos-plan{display:grid;grid-template-columns:repeat(4,1fr);gap:0;counter-reset:p}
.paso{position:relative;padding:4px 10px 0 0}.paso::after{content:"";position:absolute;top:17px;left:40px;right:8px;height:2px;
background:var(--line)}.paso:last-child::after{display:none}
.paso-c{width:34px;height:34px;border-radius:50%;display:grid;place-items:center;border:2px solid var(--line);
background:var(--card);color:var(--muted);position:relative;z-index:1}
.paso b{display:block;margin-top:9px;font-size:13.5px}.paso small{color:var(--muted);font-size:12.5px}
.paso.hecho .paso-c{background:var(--ok);border-color:var(--ok);color:#fff}.paso.hecho::after{background:var(--ok)}
.paso.actual .paso-c{border-color:var(--acc);color:var(--acc);box-shadow:0 0 0 4px var(--acc2)}
.paso.fallo .paso-c{background:var(--crit);border-color:var(--crit);color:#fff}
.decision{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:14px;flex-wrap:wrap;justify-content:space-between;
background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:0 8px 24px rgba(16,24,40,.08);padding:14px 18px}
.decision .resumen{display:flex;gap:18px;flex-wrap:wrap;font-size:13.5px;color:var(--ink2)}.decision .resumen b{color:var(--ink)}
.decision form{display:inline}
.cambio{border-left:4px solid var(--line)}.cambio.aprobado{border-left-color:var(--ok)}.cambio.rechazado{border-left-color:var(--baja);opacity:.86}
.cambio-h{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;padding:16px 18px 0;flex-wrap:wrap}
.cambio-h small{color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.5px;font-size:11.5px}
.cambio-h h3{margin:3px 0 0;font-size:16.5px}.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}
.just{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.just div{background:var(--bg);border-radius:10px;padding:12px 14px}.just h4{margin:0 0 4px;font-size:12px;color:var(--muted);
text-transform:uppercase;letter-spacing:.4px;display:flex;gap:6px;align-items:center}.just p{margin:0}
.compat{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:12px}
.compat h4{margin:0 0 6px;font-size:12.5px;color:var(--ink2)}.compat ul{margin:0;padding-left:18px;color:var(--ink2);font-size:13.5px}
.revertir{display:flex;gap:9px;align-items:flex-start;margin-top:12px;font-size:13.5px;color:var(--ink2)}
.cambio-f{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;border-top:1px solid var(--line2);
padding:12px 18px;background:linear-gradient(var(--card),var(--bg))}
.cambio-f form{display:flex;gap:8px}
.decidido{display:flex;gap:8px;align-items:center;font-weight:600}.decidido.ok{color:var(--ok-t)}.decidido.no{color:var(--neu-t)}
details{border:1px solid var(--line);border-radius:10px;margin-top:12px;background:var(--card)}
summary{cursor:pointer;padding:10px 14px;font-weight:600;font-size:13.5px;list-style:none;display:flex;gap:8px;align-items:center}
summary::-webkit-details-marker{display:none}summary::before{content:"";width:7px;height:7px;border-right:2px solid var(--muted);
border-bottom:2px solid var(--muted);transform:rotate(-45deg);transition:transform .15s;margin-right:3px}
details[open] summary::before{transform:rotate(45deg)}details>div{padding:0 14px 14px}
.diff{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;border:1px solid var(--line);border-radius:9px;
overflow:auto;max-height:440px;background:var(--card)}
.diff div{padding:1px 12px;white-space:pre}.d-a{background:#e9f8ec;color:#11602a}.d-b{background:#fdeeee;color:#9c2222}
.d-h{background:var(--inf-bg);color:var(--inf-t)}.d-c{color:var(--ink2)}
.d-f{display:flex;gap:7px;align-items:center;background:var(--bg);font-weight:600;padding:7px 12px!important;border-top:1px solid var(--line)}
.d-f:first-child{border-top:0}
@media (prefers-color-scheme:dark){.d-a{background:#10301a;color:#8be3a4}.d-b{background:#3a1717;color:#ffaaaa}}
.tl{list-style:none;margin:0;padding:0}.tl li{display:flex;gap:11px;padding:7px 0;position:relative}
.tl li:not(:last-child)::before{content:"";position:absolute;left:10px;top:30px;bottom:-6px;width:2px;background:var(--line2)}
.tl-i{width:22px;height:22px;border-radius:50%;display:grid;place-items:center;flex:none;background:var(--neu-bg);color:var(--neu-t)}
.tl-ok .tl-i{background:var(--ok-bg);color:var(--ok-t)}.tl-mal .tl-i{background:var(--mal-bg);color:var(--mal-t)}
.tl-c{min-width:0;flex:1}.tl-c b{font-weight:600;font-size:13.5px}.tl-c p{margin:1px 0 0;color:var(--muted);font-size:12.8px;word-break:break-word}
.tl-c pre{margin:6px 0 0;background:var(--bg);border-radius:8px;padding:9px;font-size:12px;max-height:220px;overflow:auto;white-space:pre-wrap}
.tl details{margin-top:4px;border:0;background:transparent}.tl summary{padding:2px 0;font-size:12.5px;color:var(--acc)}
.dl{display:grid;grid-template-columns:auto 1fr;gap:8px 16px;margin:0}.dl dt{color:var(--muted);font-size:13px}.dl dd{margin:0}
.callout{display:flex;gap:10px;overflow-wrap:anywhere;padding:11px 13px;border-radius:10px;background:var(--av-bg);color:var(--av-t);font-size:13.5px;margin-bottom:8px}
.callout:last-child{margin-bottom:0}.callout-info{background:var(--inf-bg);color:var(--inf-t)}
.vacio{text-align:center;color:var(--muted);padding:26px 10px}.vacio .ico{color:var(--ok)}.vacio p{margin:8px 0 0}
.toast{position:fixed;right:22px;bottom:22px;z-index:60;display:flex;gap:10px;align-items:center;background:#0f172a;color:#fff;
padding:12px 14px 12px 16px;border-radius:12px;box-shadow:0 12px 32px rgba(0,0,0,.25);max-width:440px;animation:entra .25s ease-out}
.toast-x{background:transparent;border:0;color:#9aa3b8;cursor:pointer;padding:2px}@keyframes entra{from{transform:translateY(12px);opacity:0}}
dialog{border:0;border-radius:16px;padding:0;box-shadow:0 24px 60px rgba(0,0,0,.3);width:min(440px,92vw);background:var(--card);color:var(--ink)}
dialog::backdrop{background:rgba(15,23,42,.45);backdrop-filter:blur(2px)}
.dlg-c{padding:24px}.dlg-i{width:44px;height:44px;border-radius:12px;background:var(--av-bg);color:var(--av-t);display:grid;place-items:center}
.dlg-c h3{margin:14px 0 6px;font-size:17px}.dlg-c p{margin:0;color:var(--ink2)}.dlg-b{display:flex;justify-content:flex-end;gap:10px;margin-top:22px}
.campo{display:flex;flex-direction:column;gap:5px;margin-top:14px;font-size:13px;font-weight:600}
.campo input{font:inherit;padding:9px 11px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--ink)}
.sel{display:flex;align-items:center;gap:9px;font-size:13px;color:var(--muted);font-weight:600}
.sel select{font:inherit;font-weight:650;padding:9px 12px;border-radius:10px;border:1px solid var(--line);background:var(--card);
color:var(--ink);min-width:230px;max-width:100%;cursor:pointer}.sel select:focus{outline:2px solid var(--acc);outline-offset:1px}
.apps{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.app-card{display:flex;flex-direction:column;gap:10px;background:var(--card);border:1px solid var(--line);border-radius:var(--r);
padding:16px 18px;box-shadow:var(--sh);text-decoration:none!important;color:var(--ink);transition:border-color .15s,transform .1s}
.app-card:hover{border-color:var(--acc);transform:translateY(-1px)}.app-card.on{border-color:var(--acc);box-shadow:0 0 0 3px var(--acc2)}
.app-h{display:flex;gap:9px;align-items:center;font-size:15.5px}.app-h .ico{color:var(--acc)}
.app-k{display:flex;gap:16px;color:var(--ink2);font-size:13px}.app-k b{color:var(--ink);font-size:16px}
.app-p{display:flex;gap:6px;flex-wrap:wrap}.app-card small{color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.estado-web{display:flex;gap:16px;align-items:center}.ew-i{width:52px;height:52px;border-radius:14px;display:grid;place-items:center;flex:none}
.ew-on{background:var(--ok-bg);color:var(--ok-t)}.ew-off{background:var(--mal-bg);color:var(--mal-t)}
.estado-web b{font-size:17px;display:block}
.mini{display:flex;gap:2px;height:8px;width:110px}.mini span{height:100%;border-radius:2px}
@media (max-width:1100px){.g2,.g2b{grid-template-columns:1fr}.just,.compat{grid-template-columns:1fr}}
@media (max-width:860px){.app{flex-direction:column;background:var(--bg)}.side{width:auto;height:auto;position:static;padding:10px 12px;flex-direction:row;
align-items:center;gap:6px;overflow-x:auto}.marca{padding:0 10px 0 2px}.marca small,.side-pie{display:none}
.side nav{flex-direction:row}.side nav a span{display:none}.side nav a .nb{display:inline}
.top{padding:18px 16px 4px}.cont{padding:14px 16px 50px}.pasos-plan{grid-template-columns:repeat(2,1fr);row-gap:14px}
.paso::after{display:none}.fila-barra{grid-template-columns:110px 1fr 34px}.buscar{min-width:0;flex:1}.banner{flex-wrap:wrap}.banner div{flex:1 1 200px}.banner>.btn{width:100%}.aviso-demo{padding:8px 16px;font-size:12.5px}.telefono{border-width:0;border-radius:16px;height:72vh}.tg-m,.tg-k{margin-right:12px}.decision .top-x{width:100%}.decision .top-x form{flex:1}.decision .btn{width:100%}.kpi-v{font-size:26px}.top h1{font-size:21px}}
/* --- chat (Telegram simulado) --- */
.telefono{max-width:430px;margin:0 auto;border-radius:30px;border:10px solid #111827;background:#dfe7ef;overflow:hidden;
box-shadow:0 30px 60px rgba(15,23,42,.25);display:flex;flex-direction:column;height:min(78vh,820px)}
.tg-h{background:#26384d;color:#fff;display:flex;gap:11px;align-items:center;padding:12px 14px}
.tg-av{width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#6366f1,#4338ca);display:grid;place-items:center}
.tg-h b{display:block;font-size:14.5px}.tg-h small{color:#a8b6c8;font-size:12px}
.tg-chat{flex:1;overflow-y:auto;padding:14px 12px 20px;background:#dfe7ef;
background-image:radial-gradient(rgba(38,56,77,.07) 1px,transparent 1px);background-size:18px 18px}
.tg-m{background:#fff;color:#0f172a;border-radius:14px 14px 14px 4px;padding:9px 12px 6px;margin:10px 36px 4px 0;font-size:13.5px;
line-height:1.42;box-shadow:0 1px 1px rgba(0,0,0,.08);word-wrap:break-word}
.tg-m time{display:block;text-align:right;color:#8a94a6;font-size:11px;margin-top:3px}
.tg-k{display:grid;gap:4px;margin:0 36px 4px 0}.tg-k div{display:flex;gap:4px}.tg-k form{flex:1;display:flex}
.tg-k button{flex:1;font:inherit;font-size:13px;font-weight:600;border:0;border-radius:9px;padding:9px 6px;cursor:pointer;
background:rgba(38,56,77,.55);color:#fff;backdrop-filter:blur(4px)}.tg-k button:hover{background:rgba(38,56,77,.75)}
.tg-sep{text-align:center;margin:14px 0 4px}.tg-sep span{background:rgba(38,56,77,.45);color:#fff;border-radius:99px;
padding:3px 11px;font-size:12px;font-weight:600}
.tg-pie{background:#fff;padding:10px 14px;color:#8a94a6;font-size:13px;display:flex;gap:8px;align-items:center}
"""

JS = r"""
(function(){
  // Tooltips de las barras
  var tip=document.getElementById('tip');
  document.querySelectorAll('[data-tip]').forEach(function(el){
    el.addEventListener('mousemove',function(e){tip.textContent=el.dataset.tip;tip.hidden=false;
      tip.style.left=Math.min(e.clientX+14,innerWidth-tip.offsetWidth-8)+'px';tip.style.top=(e.clientY+14)+'px';});
    el.addEventListener('mouseleave',function(){tip.hidden=true;});
  });
  // Aviso flotante
  var t=document.querySelector('.toast');
  if(t){t.querySelector('.toast-x').onclick=function(){t.remove();};setTimeout(function(){t&&t.remove();},9000);
    if(history.replaceState){var u=new URL(location.href);u.searchParams.delete('msg');history.replaceState(null,'',u);}}
  // Confirmaciones: formularios con data-confirmar
  var dlg=document.getElementById('dlg'),pendiente=null;
  document.querySelectorAll('form[data-confirmar]').forEach(function(f){
    f.addEventListener('submit',function(e){
      if(f.dataset.ok){return;}
      e.preventDefault();pendiente=f;
      document.getElementById('dlg-t').textContent=f.dataset.titulo||'¿Confirmas?';
      document.getElementById('dlg-m').textContent=f.dataset.confirmar;
      var ok=document.getElementById('dlg-ok');ok.className='btn '+(f.dataset.tono||'btn-primario');
      ok.textContent=f.dataset.boton||'Confirmar';
      if(dlg.showModal){dlg.showModal();}else if(confirm(f.dataset.confirmar)){enviar('si');}
    });
  });
  function enviar(v){
    if(v!=='si'||!pendiente)return;
    var tk=document.getElementById('dlg-token');
    if(tk&&tk.value){var h=document.createElement('input');h.type='hidden';h.name='token';h.value=tk.value;pendiente.appendChild(h);}
    var c=document.createElement('input');c.type='hidden';c.name='confirmar';c.value='si';pendiente.appendChild(c);
    pendiente.dataset.ok='1';pendiente.submit();
  }
  if(dlg){dlg.addEventListener('close',function(){enviar(dlg.returnValue);});}
  // Filtros de la tabla de vulnerabilidades
  var tabla=document.getElementById('t-vulns');
  if(tabla){
    var q=document.getElementById('f-q'),chips=document.querySelectorAll('.chip[data-sev]'),kev=document.getElementById('f-kev'),
        cont=document.getElementById('f-n'),filas=tabla.querySelectorAll('tbody tr'),activas={};
    var limite=25,mas=document.getElementById('f-mas');
    function aplicar(reset){
      if(reset!==false)limite=25;
      var txt=(q.value||'').toLowerCase(),haySev=Object.keys(activas).length>0,n=0,vistas=0;
      filas.forEach(function(r){
        var ok=(!txt||r.dataset.texto.indexOf(txt)>=0)&&(!haySev||activas[r.dataset.sev])&&(!kev.classList.contains('on')||r.dataset.kev==='1');
        if(ok)n++;var ver=ok&&n<=limite;r.style.display=ver?'':'none';if(ver)vistas++;
      });
      cont.textContent=n===filas.length?filas.length+' vulnerabilidades':n+' de '+filas.length+' con estos filtros';
      if(mas){mas.hidden=vistas>=n;mas.querySelector('span').textContent='Mostrar más ('+(n-vistas)+' restantes)';}
    }
    if(mas){mas.onclick=function(){limite+=50;aplicar(false);};}
    q.addEventListener('input',function(){aplicar();});
    chips.forEach(function(c){c.onclick=function(){c.classList.toggle('on');
      if(c.classList.contains('on'))activas[c.dataset.sev]=1;else delete activas[c.dataset.sev];aplicar();};});
    kev.onclick=function(){kev.classList.toggle('on');aplicar();};
    var p=new URLSearchParams(location.search);if(p.get('q')){q.value=p.get('q');}
    if(p.get('sev')){var c=document.querySelector('.chip[data-sev="'+p.get('sev')+'"]');if(c)c.click();}
    aplicar();
  }
  // Selector de app: cambia el filtro y vuelve a una página que lo respete
  var sel=document.getElementById('sel-app');
  if(sel){sel.addEventListener('change',function(){
    var ruta=location.pathname.indexOf('/plan/')===0?'/correcciones':location.pathname;
    location.href=ruta+'?app='+encodeURIComponent(sel.value);});}
  // Chat simulado: bajar al final
  var chat=document.querySelector('.tg-chat');if(chat){var ancla=document.querySelector(location.hash||'#nada');
    chat.scrollTop=ancla&&chat.contains(ancla)?ancla.offsetTop-80:chat.scrollHeight;}
})();
"""
