"""Capa visual del panel: estilos, iconos SVG, componentes y plantilla de página.

Sin dependencias ni recursos externos (todo va en línea), sin emoticonos: los estados se
representan con iconos SVG + texto, nunca solo con color.

Colores de gravedad = paleta de estado (crítica / alta / media) + neutro para baja; cada
indicador de color va siempre acompañado de su etiqueta.
"""
from __future__ import annotations

import html
import re
import urllib.parse

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
    "sol": ['M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 1 0 0-7z', 'M12 2.5v2', 'M12 19.5v2', 'M4.6 4.6l1.4 1.4', 'M18 18l1.4 1.4',
            'M2.5 12h2', 'M19.5 12h2', 'M4.6 19.4L6 18', 'M18 6l1.4-1.4'],
    "luna": ['M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z'],
    "globo": ['M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 1 0 0-17z', 'M3.5 12h17', 'M12 3.5c2.4 2.6 3.5 5.4 3.5 8.5s-1.1 5.9-3.5 8.5c-2.4-2.6-3.5-5.4-3.5-8.5s1.1-5.9 3.5-8.5z'],
    "orden": ['M8 4v16', 'M4.5 7.5L8 4l3.5 3.5', 'M16 20V4', 'M12.5 16.5L16 20l3.5-3.5'],
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
    """Gravedad = color + forma + texto (nunca solo color)."""
    return f'<span class="sev sev-{E(s)}"><i aria-hidden="true"></i>{E(NOMBRE_SEV.get(s, s))}</span>'


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


def kpi(etiqueta: str, valor, nota: str = "", tono: str = "", href: str = "", clave: str = "") -> str:
    """Indicador del resumen; el color de la franja siempre acompaña a una etiqueta de texto."""
    etiqueta_tag, cierre = (f'a href="{E(href)}"', "a") if href else ("div", "div")
    k = f' data-k="{E(clave)}"' if clave else ""
    return (f'<{etiqueta_tag} class="kpi {("kpi-" + tono) if tono else ""}"{k}><div class="kpi-l">{E(etiqueta)}</div>'
            f'<div class="kpi-v">{E(str(valor))}</div><div class="kpi-n">{nota}</div></{cierre}>')


def contador_sev(n: int, s: str) -> str:
    """Número de vulnerabilidades de una gravedad para celdas de tabla; 0 en gris, sin color."""
    if not n:
        return '<span class="cnt cnt-0">0</span>'
    return f'<span class="cnt cnt-{s}" title="{n} {NOMBRE_SEV[s].lower()}"><i aria-hidden="true"></i>{n}</span>'


def version_salto(actual: str, ultima: str | None) -> str:
    """'8.1.2 → 8.1.31' si hay una más nueva; si no, la actual con «al día»."""
    if ultima and ultima != actual:
        return (f'<span class="version"><span class="de">{E(actual)}</span>{icono("flecha", 14)}'
                f'<span class="a">{E(ultima)}</span></span>')
    return f'<span class="mono">{E(actual)}</span> <span class="muted peq">al día</span>'


def th(texto: str, tipo: str = "texto", clase: str = "") -> str:
    """Cabecera ordenable (la ordenación la hace el JS de la página)."""
    c = f' class="{clase}"' if clase else ""
    return (f'<th{c} data-tipo="{tipo}" aria-sort="none"><button type="button" class="ord">{E(texto)}'
            f'{icono("orden", 12)}</button></th>')


def filtros(tabla: str, placeholder: str, unidad: str, chips: list[tuple[str, str, str, str]],
            abajo: bool = False) -> str:
    """Barra de búsqueda + chips para una tabla. chips = [(campo, valor, icono, texto)]: filtra las filas cuyo
    data-<campo> vale <valor>; varios chips del mismo campo se suman (O), de campos distintos se combinan (Y)."""
    ch = "".join(f'<button class="chip" type="button" data-campo="{E(c)}" data-valor="{E(v)}" aria-pressed="false">'
                 f'{icono(ic, 14)}{E(t)}</button>' for c, v, ic, t in chips)
    estilo = ' style="margin-bottom:16px"' if abajo else ""
    return (f'<div class="filtros" data-tabla="{E(tabla)}" data-unidad="{E(unidad)}"{estilo}>'
            f'<label class="buscar">{icono("buscar", 16)}<input type="search" placeholder="{E(placeholder)}" '
            f'aria-label="{E(placeholder)}"></label>{ch}<span class="contador" aria-live="polite"></span></div>')


def sin_coincidencias(tabla: str, texto: str) -> str:
    return f'<div data-vacio-de="{E(tabla)}" hidden>{vacio(texto, "buscar")}</div>'


def cargando(texto: str) -> str:
    return f'<div class="vacio vacio-carga">{icono("refrescar", 28)}<p>{E(texto)}</p></div>'


def error(texto: str) -> str:
    return f'<div class="vacio vacio-error">{icono("alerta", 28)}<p>{E(texto)}</p></div>'


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
<script>try{{var t=localStorage.getItem("pw-tema");if(t)document.documentElement.dataset.theme=t}}catch(e){{}}</script>
<title>{E(titulo)} · Patchwarden</title><link rel="icon" href="{FAVICON}"><style>{CSS}</style></head>
<body><div class="app">
<aside class="side"><a class="marca" href="/">{LOGO_SVG.format(t=30)}<span><b>Patchwarden</b><small>{E(web)}</small></span></a>
<nav>{''.join(nav)}</nav>
<button type="button" class="tema" id="tema" aria-label="Cambiar entre tema claro y oscuro">{icono("sol", 16, "t-sol")}{icono("luna", 16, "t-luna")}<span>Tema</span></button>
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


# Logo de Patchwarden (el mismo que assets/logo.svg): escudo con una tirita
LOGO_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="{t}" height="{t}" class="logo" aria-hidden="true">'
            '<defs><linearGradient id="pw-g" x1="12" y1="6" x2="52" y2="58" gradientUnits="userSpaceOnUse">'
            '<stop offset="0" stop-color="#6d6af8"/><stop offset="1" stop-color="#3b2fc9"/></linearGradient></defs>'
            '<path d="M32 4.5 53 12.2v17.6c0 13.4-8.8 24-21 29.7C19.8 53.8 11 43.2 11 29.8V12.2Z" fill="url(#pw-g)" '
            'stroke="url(#pw-g)" stroke-width="3" stroke-linejoin="round"/><g transform="rotate(-45 32 31.5)">'
            '<rect x="15" y="24.5" width="34" height="14" rx="7" fill="#fff"/>'
            '<rect x="25.5" y="24.5" width="13" height="14" fill="#dcdcff"/><g fill="#4a42dd">'
            '<circle cx="29" cy="28.5" r="1.25"/><circle cx="35" cy="28.5" r="1.25"/>'
            '<circle cx="29" cy="34.5" r="1.25"/><circle cx="35" cy="34.5" r="1.25"/></g></g></svg>')
FAVICON = "data:image/svg+xml," + urllib.parse.quote(LOGO_SVG.format(t=64))


CSS = r"""
:root{--bg:#f4f5f8;--card:#fff;--line:#e5e7ee;--line2:#eef0f4;--ink:#0f172a;--ink2:#475467;--muted:#606a7d;
--acc:#4338ca;--acc-h:#3730a3;--acc2:#eef0ff;--on-acc:#fff;--side:#0c1222;--side2:#141c31;--side-act:#1d2540;--side-ink:#c7cde0;
--side-acc:#8b93ff;--side-muted:#8d95ab;--side-line:#1c2338;--side-badge:#4338ca;--on-solid:#fff;
--demo-a:#1e1b4b;--demo-b:#312e81;--demo-ink:#e0e3ff;--demo-tag:#4f46e5;
--crit:#d03b3b;--alta:#e46f12;--media:#e3a400;--baja:#2f6fdb;--ok:#0ca30c;
--crit-t:#b42318;--alta-t:#a3500a;--media-t:#7a5800;--baja-t:#1d4fb0;
--ok-t:#05660a;--ok-bg:#e8f6e8;--ok-line:#bfe5bf;--ok-solid:#0f7b0f;--ok-solid-h:#0b650b;
--mal-t:#a52323;--mal-bg:#fdecec;--mal-line:#f1c4c4;--rojo:#c62828;--rojo-h:#a51f1f;
--av-t:#8a5300;--av-bg:#fff4dc;--av-line:#f3dba5;--inf-t:#3730a3;--inf-bg:#eef0ff;--inf-line:#d6d9ff;
--neu-t:#475467;--neu-bg:#f0f2f6;--tip-bg:#0f172a;--tip-ink:#fff;--overlay:rgba(15,23,42,.45);
--d-a-bg:#e9f8ec;--d-a-t:#11602a;--d-b-bg:#fdeeee;--d-b-t:#9c2222;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--sh:0 1px 2px rgba(16,24,40,.05),0 1px 3px rgba(16,24,40,.06);--r:12px;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0e121b;--card:#161b26;--line:#2a3140;--line2:#1f2533;--ink:#eef1f7;--ink2:#b4bccb;--muted:#939cb0;--acc:#8b93ff;--acc-h:#a3a9ff;--acc2:#23284a;--on-acc:#0e121b;--side:#0a0e17;--side2:#151b2b;--crit:#f05252;--alta:#f38a3a;--media:#f5c242;--baja:#5b9bff;--ok:#3fbf3f;--crit-t:#ff8a8a;--alta-t:#ffb07a;--media-t:#ffd66b;--baja-t:#9cc2ff;--ok-t:#5fd35f;--ok-bg:#132a17;--ok-line:#24502c;--ok-solid:#1f8f1f;--ok-solid-h:#26a326;--mal-t:#ff8a8a;--mal-bg:#331616;--mal-line:#5a2626;--rojo:#d63a3a;--rojo-h:#e85050;--av-t:#ffc65a;--av-bg:#2f2410;--av-line:#5a4518;--inf-t:#aab0ff;--inf-bg:#1f2447;--inf-line:#353d78;--neu-t:#b4bccb;--neu-bg:#1f2533;--tip-bg:#eef1f7;--tip-ink:#0f172a;--overlay:rgba(0,0,0,.6);--d-a-bg:#10301a;--d-a-t:#8be3a4;--d-b-bg:#3a1717;--d-b-t:#ffaaaa;--sh:0 1px 2px rgba(0,0,0,.4);color-scheme:dark}}
:root[data-theme="dark"]{--bg:#0e121b;--card:#161b26;--line:#2a3140;--line2:#1f2533;--ink:#eef1f7;--ink2:#b4bccb;--muted:#939cb0;--acc:#8b93ff;--acc-h:#a3a9ff;--acc2:#23284a;--on-acc:#0e121b;--side:#0a0e17;--side2:#151b2b;--crit:#f05252;--alta:#f38a3a;--media:#f5c242;--baja:#5b9bff;--ok:#3fbf3f;--crit-t:#ff8a8a;--alta-t:#ffb07a;--media-t:#ffd66b;--baja-t:#9cc2ff;--ok-t:#5fd35f;--ok-bg:#132a17;--ok-line:#24502c;--ok-solid:#1f8f1f;--ok-solid-h:#26a326;--mal-t:#ff8a8a;--mal-bg:#331616;--mal-line:#5a2626;--rojo:#d63a3a;--rojo-h:#e85050;--av-t:#ffc65a;--av-bg:#2f2410;--av-line:#5a4518;--inf-t:#aab0ff;--inf-bg:#1f2447;--inf-line:#353d78;--neu-t:#b4bccb;--neu-bg:#1f2533;--tip-bg:#eef1f7;--tip-ink:#0f172a;--overlay:rgba(0,0,0,.6);--d-a-bg:#10301a;--d-a-t:#8be3a4;--d-b-bg:#3a1717;--d-b-t:#ffaaaa;--sh:0 1px 2px rgba(0,0,0,.4);color-scheme:dark}
*{box-sizing:border-box}html,body{margin:0}[hidden]{display:none!important}
body{font:14.5px/1.5 Inter,"Segoe UI",system-ui,-apple-system,Roboto,sans-serif;background:var(--bg);color:var(--ink);
-webkit-font-smoothing:antialiased}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.ico{flex:none;vertical-align:middle}
.app{display:flex;min-height:100vh;background:linear-gradient(to right,var(--side) 248px,var(--bg) 248px)}
.side{width:248px;flex:none;background:var(--side);color:var(--side-ink);display:flex;flex-direction:column;
position:sticky;top:0;height:100vh;padding:16px 16px}
.marca{display:flex;gap:12px;align-items:center;color:var(--on-solid);padding:8px 8px 24px;text-decoration:none!important}
.marca .ico{color:var(--side-acc)}.marca .logo{flex:none}.marca b{display:block;font-size:17px;letter-spacing:.2px}
.marca small{display:block;color:var(--side-muted);font-size:12px;max-width:170px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.side nav{display:flex;flex-direction:column;gap:4px}
.side nav a{display:flex;align-items:center;gap:12px;padding:8px 12px;border-radius:8px;color:var(--side-ink);
font-weight:500;text-decoration:none}
.side nav a:hover{background:var(--side2);color:var(--on-solid)}.side nav a.act{background:var(--side-act);color:var(--on-solid)}
.side nav a.act .ico{color:var(--side-acc)}
.nb{margin-left:auto;background:var(--side-badge);color:var(--on-solid);font-size:11.5px;font-weight:700;border-radius:99px;padding:1px 8px}
.side-pie{margin-top:auto;display:flex;gap:8px;align-items:center;font-size:12px;color:var(--side-muted);padding:8px;
border-top:1px solid var(--side-line)}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.aviso-demo{background:linear-gradient(90deg,var(--demo-a),var(--demo-b));color:var(--demo-ink);padding:8px 32px;font-size:13px;
display:flex;gap:10px;align-items:center;flex-wrap:wrap}.aviso-demo a{color:var(--on-solid);font-weight:600;text-decoration:underline}
.aviso-demo b{background:var(--demo-tag);color:var(--on-solid);border-radius:6px;padding:1px 8px;font-size:11.5px;letter-spacing:.5px}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;padding:24px 32px 8px;flex-wrap:wrap}
.top h1{margin:0;font-size:24px;letter-spacing:-.3px}.top p{margin:4px 0 0;color:var(--muted)}
.top-x{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.cont{padding:16px 32px 64px;display:flex;flex-direction:column;gap:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--sh);min-width:0}
.card-h{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:16px 16px 0;flex-wrap:wrap}
.card-h h3{margin:0;font-size:15px;display:flex;align-items:center;gap:9px}.card-h h3 .ico{color:var(--muted)}
.card-x{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.card-b{padding:16px}
.grid{display:grid;gap:16px}.g2{grid-template-columns:1.6fr 1fr}.g2b{grid-template-columns:minmax(0,1fr) 380px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:16px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:16px;box-shadow:var(--sh);
position:relative;overflow:hidden;display:block;color:var(--ink);text-decoration:none!important}
.kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--line)}
.kpi-crit::before{background:var(--crit)}.kpi-alta::before{background:var(--alta)}.kpi-media::before{background:var(--media)}.kpi-acc::before{background:var(--acc)}
.kpi-ok::before{background:var(--ok)}
.kpi-l{color:var(--muted);font-size:13px;font-weight:500}.kpi-v{font-size:30px;font-weight:650;letter-spacing:-.5px;margin-top:2px}
.kpi-n{color:var(--muted);font-size:12.5px;min-height:18px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;font:inherit;font-weight:600;font-size:13.5px;
padding:8px 16px;border-radius:8px;border:1px solid transparent;cursor:pointer;text-decoration:none!important;
transition:background .15s,border-color .15s,transform .05s;white-space:nowrap}
.btn:active{transform:translateY(1px)}
.btn-primario{background:var(--acc);color:var(--on-acc)}.btn-primario:hover{background:var(--acc-h)}
.btn-secundario{background:var(--card);color:var(--ink);border-color:var(--line)}.btn-secundario:hover{background:var(--bg)}
.btn-ok{background:var(--ok-solid);color:var(--on-solid)}.btn-ok:hover{background:var(--ok-solid-h)}
.btn-peligro{background:var(--card);color:var(--mal-t);border-color:var(--mal-line)}.btn-peligro:hover{background:var(--mal-bg)}
.btn-rojo{background:var(--rojo);color:var(--on-solid)}.btn-rojo:hover{background:var(--rojo-h)}
.btn-sm{padding:4px 12px;font-size:13px}
.pill{display:inline-flex;align-items:center;gap:5px;font-size:12.5px;font-weight:600;padding:4px 8px;
border-radius:99px;white-space:nowrap}
.pill-ok{background:var(--ok-bg);color:var(--ok-t)}.pill-mal{background:var(--mal-bg);color:var(--mal-t)}
.pill-aviso{background:var(--av-bg);color:var(--av-t)}.pill-info{background:var(--inf-bg);color:var(--inf-t)}
.pill-neutro{background:var(--neu-bg);color:var(--neu-t)}
.sev{display:inline-flex;align-items:center;gap:8px;font-weight:600;font-size:13px;white-space:nowrap}
.sev i,.cnt i{width:10px;height:10px;display:inline-block;flex:none;background:var(--muted)}
.sev-CRITICA i,.cnt-CRITICA i{background:var(--crit);transform:rotate(45deg) scale(.85);border-radius:1px}
.sev-ALTA i,.cnt-ALTA i{background:var(--alta);clip-path:polygon(50% 0,100% 100%,0 100%)}
.sev-MEDIA i,.cnt-MEDIA i{background:var(--media);border-radius:2px}
.sev-BAJA i,.cnt-BAJA i{background:var(--baja);border-radius:50%}
.tag{display:inline-block;background:var(--neu-bg);color:var(--neu-t);border-radius:4px;padding:0 8px;font-size:12px;
font-weight:600;margin-left:8px}.tag-kev{background:var(--mal-bg);color:var(--mal-t)}
table{border-collapse:collapse;width:100%}
th{text-align:left;font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;
padding:8px 12px;border-bottom:1px solid var(--line);white-space:nowrap;background:var(--card);position:sticky;top:0}
td{padding:12px;border-bottom:1px solid var(--line2);vertical-align:top}
tr:last-child td{border-bottom:0}tbody tr:hover td{background:var(--bg)}
.num{font-variant-numeric:tabular-nums;text-align:right}table.ancha td.mono{white-space:nowrap}.mono{font-family:var(--mono);font-size:12.8px}
.tabla{overflow-x:auto;margin:-16px -16px -16px}.tabla.tabla-sola{margin-top:0}.tabla table.ancha{min-width:760px}
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
.tip{position:fixed;z-index:50;background:var(--tip-bg);color:var(--tip-ink);font-size:12.5px;padding:6px 10px;border-radius:8px;
pointer-events:none;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.banner{display:flex;gap:16px;align-items:center;padding:16px;border-radius:var(--r);border:1px solid}
.banner .ico{flex:none}.banner div{flex:1}.banner b{display:block}
.banner-aviso{background:var(--av-bg);border-color:var(--av-line);color:var(--av-t)}
.banner-mal{background:var(--mal-bg);border-color:var(--mal-line);color:var(--mal-t)}
.banner-info{background:var(--inf-bg);border-color:var(--inf-line);color:var(--inf-t)}
.banner-ok{background:var(--ok-bg);border-color:var(--ok-line);color:var(--ok-t)}
.banner p{margin:2px 0 0;color:inherit;opacity:.9}
.lista{display:flex;flex-direction:column}
.item{display:flex;gap:16px;align-items:center;padding:12px 0;border-bottom:1px solid var(--line2);flex-wrap:wrap}
.item:last-child{border-bottom:0}.item-i{width:40px;height:40px;border-radius:8px;display:grid;place-items:center;
background:var(--acc2);color:var(--acc);flex:none}.item-c{flex:1 1 220px;min-width:0}.item-c b{display:block}
.item-c small{color:var(--muted)}.item-x{display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end}
.version{display:inline-flex;align-items:center;gap:4px;font-family:var(--mono);font-size:13px}
.version .de{color:var(--muted);text-decoration:line-through;text-decoration-color:var(--crit)}
.version .a{color:var(--ok-t);font-weight:700}
.filtros{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.buscar{display:flex;align-items:center;gap:8px;border:1px solid var(--line);border-radius:8px;padding:0 12px;background:var(--card);
min-width:260px}.buscar input{border:0;outline:0;font:inherit;padding:8px 0;background:transparent;color:var(--ink);width:100%}
.chip{font:inherit;font-size:13px;font-weight:600;padding:4px 12px;border-radius:99px;border:1px solid var(--line);
background:var(--card);color:var(--ink2);cursor:pointer;display:inline-flex;gap:8px;align-items:center;min-height:32px}
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
.paso.hecho .paso-c{background:var(--ok);border-color:var(--ok);color:var(--on-solid)}.paso.hecho::after{background:var(--ok)}
.paso.actual .paso-c{border-color:var(--acc);color:var(--acc);box-shadow:0 0 0 4px var(--acc2)}
.paso.fallo .paso-c{background:var(--crit);border-color:var(--crit);color:var(--on-solid)}
.decision{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:16px;flex-wrap:wrap;justify-content:space-between;
background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:0 8px 24px rgba(16,24,40,.08);padding:16px}
.decision .resumen{display:flex;gap:16px;flex-wrap:wrap;font-size:13.5px;color:var(--ink2)}.decision .resumen b{color:var(--ink)}
.decision form{display:inline}
.cambio{border-left:4px solid var(--line)}.cambio.aprobado{border-left-color:var(--ok)}.cambio.rechazado{border-left-color:var(--baja);opacity:.86}
.cambio-h{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;padding:16px 16px 0;flex-wrap:wrap}
.cambio-h small{color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.5px;font-size:11.5px}
.cambio-h h3{margin:3px 0 0;font-size:16.5px}.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.just{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.just div{background:var(--bg);border-radius:8px;padding:12px 16px}.just h4{margin:0 0 4px;font-size:12px;color:var(--muted);
text-transform:uppercase;letter-spacing:.4px;display:flex;gap:6px;align-items:center}.just p{margin:0}
.compat{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:12px}
.compat h4{margin:0 0 6px;font-size:12.5px;color:var(--ink2)}.compat ul{margin:0;padding-left:18px;color:var(--ink2);font-size:13.5px}
.revertir{display:flex;gap:8px;align-items:flex-start;margin-top:12px;font-size:13.5px;color:var(--ink2)}
.cambio-f{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;border-top:1px solid var(--line2);
padding:12px 16px;background:linear-gradient(var(--card),var(--bg))}
.cambio-f form{display:flex;gap:8px}
.decidido{display:flex;gap:8px;align-items:center;font-weight:600}.decidido.ok{color:var(--ok-t)}.decidido.no{color:var(--neu-t)}
details{border:1px solid var(--line);border-radius:10px;margin-top:12px;background:var(--card)}
summary{cursor:pointer;padding:8px 16px;font-weight:600;font-size:13.5px;list-style:none;display:flex;gap:8px;align-items:center}
summary::-webkit-details-marker{display:none}summary::before{content:"";width:7px;height:7px;border-right:2px solid var(--muted);
border-bottom:2px solid var(--muted);transform:rotate(-45deg);transition:transform .15s;margin-right:3px}
details[open] summary::before{transform:rotate(45deg)}details>div{padding:0 16px 16px}
.diff{font-family:var(--mono);font-size:12.5px;border:1px solid var(--line);border-radius:9px;
overflow:auto;max-height:440px;background:var(--card)}
.diff div{padding:1px 12px;white-space:pre}.d-a{background:var(--d-a-bg);color:var(--d-a-t)}.d-b{background:var(--d-b-bg);color:var(--d-b-t)}
.d-h{background:var(--inf-bg);color:var(--inf-t)}.d-c{color:var(--ink2)}
.d-f{display:flex;gap:7px;align-items:center;background:var(--bg);font-weight:600;padding:7px 12px!important;border-top:1px solid var(--line)}
.d-f:first-child{border-top:0}
.tl{list-style:none;margin:0;padding:0}.tl li{display:flex;gap:11px;padding:7px 0;position:relative}
.tl li:not(:last-child)::before{content:"";position:absolute;left:10px;top:30px;bottom:-6px;width:2px;background:var(--line2)}
.tl-i{width:22px;height:22px;border-radius:50%;display:grid;place-items:center;flex:none;background:var(--neu-bg);color:var(--neu-t)}
.tl-ok .tl-i{background:var(--ok-bg);color:var(--ok-t)}.tl-mal .tl-i{background:var(--mal-bg);color:var(--mal-t)}
.tl-c{min-width:0;flex:1}.tl-c b{font-weight:600;font-size:13.5px}.tl-c p{margin:1px 0 0;color:var(--muted);font-size:12.8px;word-break:break-word}
.tl-c pre{margin:6px 0 0;background:var(--bg);border-radius:8px;padding:9px;font-size:12px;max-height:220px;overflow:auto;white-space:pre-wrap}
.tl details{margin-top:4px;border:0;background:transparent}.tl summary{padding:2px 0;font-size:12.5px;color:var(--acc)}
.dl{display:grid;grid-template-columns:auto 1fr;gap:8px 16px;margin:0}.dl dt{color:var(--muted);font-size:13px}.dl dd{margin:0}
.callout{display:flex;gap:8px;overflow-wrap:anywhere;padding:12px;border-radius:8px;background:var(--av-bg);color:var(--av-t);font-size:13.5px;margin-bottom:8px}
.callout:last-child{margin-bottom:0}.callout-info{background:var(--inf-bg);color:var(--inf-t)}
.vacio{text-align:center;color:var(--muted);padding:24px 8px}.vacio .ico{color:var(--ok)}.vacio p{margin:8px 0 0}
.toast{position:fixed;right:22px;bottom:22px;z-index:60;display:flex;gap:10px;align-items:center;background:var(--tip-bg);color:var(--tip-ink);
padding:12px 12px 12px 16px;border-radius:12px;box-shadow:0 12px 32px rgba(0,0,0,.25);max-width:440px;animation:entra .25s ease-out}
.toast-x{background:transparent;border:0;color:inherit;opacity:.7;cursor:pointer;padding:2px}@keyframes entra{from{transform:translateY(12px);opacity:0}}
dialog{border:0;border-radius:16px;padding:0;box-shadow:0 24px 60px rgba(0,0,0,.3);width:min(440px,92vw);background:var(--card);color:var(--ink)}
dialog::backdrop{background:var(--overlay);backdrop-filter:blur(2px)}
.dlg-c{padding:24px}.dlg-i{width:44px;height:44px;border-radius:12px;background:var(--av-bg);color:var(--av-t);display:grid;place-items:center}
.dlg-c h3{margin:14px 0 6px;font-size:17px}.dlg-c p{margin:0;color:var(--ink2)}.dlg-b{display:flex;justify-content:flex-end;gap:10px;margin-top:22px}
.campo{display:flex;flex-direction:column;gap:5px;margin-top:14px;font-size:13px;font-weight:600}
.campo input{font:inherit;padding:9px 11px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--ink)}
.sel{display:flex;align-items:center;gap:9px;font-size:13px;color:var(--muted);font-weight:600}
.sel select{font:inherit;font-weight:650;padding:9px 12px;border-radius:10px;border:1px solid var(--line);background:var(--card);
color:var(--ink);min-width:230px;max-width:100%;cursor:pointer}.sel select:focus{outline:2px solid var(--acc);outline-offset:1px}
.estado-web{display:flex;gap:16px;align-items:center}.ew-i{width:52px;height:52px;border-radius:14px;display:grid;place-items:center;flex:none}
.ew-on{background:var(--ok-bg);color:var(--ok-t)}.ew-off{background:var(--mal-bg);color:var(--mal-t)}
.estado-web b{font-size:17px;display:block}.estado-web span{display:block}
/* --- tablas ordenables, webs y detalle --- */
a.kpi:hover{border-color:var(--acc)}a.kpi:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.cnts{display:flex;gap:12px;flex-wrap:wrap}.gira{animation:gira 1.2s linear infinite}
.col{display:flex;flex-direction:column;gap:16px;min-width:0}
.fila-estado{display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap}
td span.mono{white-space:nowrap}td .ruta{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
th .ord{all:unset;cursor:pointer;display:inline-flex;align-items:center;gap:4px;font:inherit;color:inherit;text-transform:inherit;letter-spacing:inherit}
th .ord .ico{opacity:.45}th[aria-sort=ascending] .ord,th[aria-sort=descending] .ord{color:var(--ink)}
th[aria-sort=ascending] .ord .ico,th[aria-sort=descending] .ord .ico{opacity:1;color:var(--acc)}
th .ord:focus-visible,.tema:focus-visible,.btn:focus-visible,.chip:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
th.num .ord{flex-direction:row-reverse}
.cnt{display:inline-flex;align-items:center;justify-content:flex-end;gap:4px;font-weight:650;font-variant-numeric:tabular-nums;min-width:32px}
.cnt-0{color:var(--muted);font-weight:400}
.cnt-CRITICA{color:var(--crit-t)}.cnt-ALTA{color:var(--alta-t)}.cnt-MEDIA{color:var(--media-t)}.cnt-BAJA{color:var(--baja-t)}
.web-n{display:flex;flex-direction:column;gap:4px;min-width:0}.web-n b a{color:var(--ink)}
.web-n .url{display:inline-flex;gap:4px;align-items:center;color:var(--muted);font-size:12.5px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.web-n .url .ico{flex:none}
tr[data-href]{cursor:pointer}#t-webs td{vertical-align:middle}
.ficha{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px}
.ficha div{display:flex;flex-direction:column;gap:4px}.ficha dt{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.4px;font-weight:600}
.ficha dd{margin:0;font-weight:600;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.vacio-carga .ico{color:var(--acc);animation:gira 1.2s linear infinite}.vacio-error .ico{color:var(--crit)}
@keyframes gira{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.vacio-carga .ico,.gira{animation:none}}
.tema{display:flex;align-items:center;gap:12px;margin-top:8px;padding:8px 12px;border-radius:8px;border:0;background:transparent;
color:var(--side-ink);font:inherit;font-weight:500;cursor:pointer;text-align:left}.tema:hover{background:var(--side2);color:var(--on-solid)}
.t-luna{display:none}:root[data-theme=dark] .t-sol{display:none}:root[data-theme=dark] .t-luna{display:inline}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]) .t-sol{display:none}:root:not([data-theme=light]) .t-luna{display:inline}}
.filtros .buscar{flex:0 1 320px}
.mono .sans,td.mono .sans{font-family:Inter,"Segoe UI",system-ui,-apple-system,Roboto,sans-serif}.fix{color:var(--ok-t);font-weight:600}
table.ancha th{white-space:normal;vertical-align:bottom}#t-vulns .td-cve{min-width:260px;max-width:420px}#t-vulns .td-cve .clamp{margin:4px 0 2px}td.accion{min-width:168px}
.tag{font-family:Inter,"Segoe UI",system-ui,-apple-system,Roboto,sans-serif}td.accion form{margin:0}
@media (max-width:640px){
#t-webs{min-width:0!important}#t-webs thead{display:none}#t-webs,#t-webs tbody,#t-webs tr,#t-webs td{display:block}
#t-webs tr{padding:12px 16px;border-bottom:1px solid var(--line2)}#t-webs td{border:0;padding:4px 0;display:flex;justify-content:space-between;gap:12px;align-items:center}
#t-webs td::before{content:attr(data-l);color:var(--muted);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.4px}
#t-webs td.td-n::before{display:none}#t-webs .web-v{text-align:right}#t-webs td.td-n{padding-bottom:8px}
#t-webs .cnts{display:flex;gap:12px}
.filtros .buscar{flex:1 1 100%}.contador{margin-left:0;width:100%}
}
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
    try{var u=new URL(location.href);u.searchParams.delete('msg');history.replaceState(null,'',u.pathname+u.search+u.hash);}catch(e){}}
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
        cont=document.getElementById('f-n'),filas,activas={};
    var limite=25,mas=document.getElementById('f-mas');
    function aplicar(reset){
      if(reset!==false)limite=25;
      filas=tabla.querySelectorAll('tbody tr');
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
    tabla.addEventListener('ordenada',function(){aplicar(false);});
    var p=new URLSearchParams(location.search);if(p.get('q')){q.value=p.get('q');}
    if(p.get('sev')){var c=document.querySelector('.chip[data-sev="'+p.get('sev')+'"]');if(c)c.click();}
    aplicar();
  }
  // Tablas ordenables: <th data-tipo="num|texto"> y, si hace falta, data-v en la celda
  document.querySelectorAll('table th[data-tipo]').forEach(function(th){
    var b=th.querySelector('.ord');if(!b)return;
    b.addEventListener('click',function(){
      var t=th.closest('table'),cuerpo=t.tBodies[0],i=Array.prototype.indexOf.call(th.parentNode.children,th);
      var asc=th.getAttribute('aria-sort')!=='ascending';
      t.querySelectorAll('th[data-tipo]').forEach(function(x){x.setAttribute('aria-sort','none');});
      th.setAttribute('aria-sort',asc?'ascending':'descending');
      var num=th.dataset.tipo==='num';
      function v(r){var c=r.children[i];if(!c)return '';var d=c.dataset.v!==undefined?c.dataset.v:c.textContent.trim();
        return num?(parseFloat(d)||0):d.toLowerCase();}
      var rs=Array.prototype.slice.call(cuerpo.rows);
      rs.sort(function(a,b){var x=v(a),y=v(b);var c=num?x-y:x.localeCompare(y,'es',{numeric:true});return asc?c:-c;});
      rs.forEach(function(r){cuerpo.appendChild(r);});
      t.dispatchEvent(new Event('ordenada'));
    });
  });
  // Filtros genéricos de tabla: .filtros[data-tabla] con búsqueda y chips data-campo/data-valor
  document.querySelectorAll('.filtros[data-tabla]').forEach(function(f){
    var t=document.querySelector(f.dataset.tabla);if(!t)return;
    var q=f.querySelector('input[type=search]'),n=f.querySelector('.contador'),
        vacio=document.querySelector('[data-vacio-de="'+f.dataset.tabla+'"]'),sel={};
    function aplicar(){
      var txt=(q.value||'').toLowerCase(),rs=t.tBodies[0].rows,k=0;
      Array.prototype.forEach.call(rs,function(r){
        var ok=!txt||(r.dataset.texto||r.textContent.toLowerCase()).indexOf(txt)>=0;
        Object.keys(sel).forEach(function(c){if(ok&&!sel[c][r.dataset[c]])ok=false;});
        r.style.display=ok?'':'none';if(ok)k++;});
      n.textContent=k===rs.length?rs.length+' '+f.dataset.unidad:k+' de '+rs.length+' '+f.dataset.unidad;
      if(vacio)vacio.hidden=k>0;
    }
    q.addEventListener('input',aplicar);
    f.querySelectorAll('.chip[data-campo]').forEach(function(c){c.onclick=function(){
      var on=c.classList.toggle('on'),campo=c.dataset.campo;c.setAttribute('aria-pressed',on);
      sel[campo]=sel[campo]||{};if(on)sel[campo][c.dataset.valor]=1;else delete sel[campo][c.dataset.valor];
      if(!Object.keys(sel[campo]).length)delete sel[campo];aplicar();};});
    aplicar();
  });
  // Filas enteras clicables (tr[data-href]) sin pisar enlaces ni botones
  document.querySelectorAll('table').forEach(function(t){t.addEventListener('click',function(e){
    if(e.target.closest('a,button,form,input,summary'))return;var r=e.target.closest('tr[data-href]');
    if(r)location.href=r.dataset.href;});});
  // Tema claro / oscuro (por defecto, el del sistema)
  var tema=document.getElementById('tema');
  if(tema){tema.onclick=function(){
    var raiz=document.documentElement,act=raiz.dataset.theme||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');
    var nuevo=act==='dark'?'light':'dark';raiz.dataset.theme=nuevo;try{localStorage.setItem('pw-tema',nuevo);}catch(e){}};}
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
