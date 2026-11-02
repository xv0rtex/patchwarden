"""Página de Ajustes del panel: General, Avisos, Claude, Consumo, Reglas y Cuenta."""
from __future__ import annotations

import datetime as dt

from . import consumo
from . import vista as V
from .ajustes import PESTANAS, enmascarar

E = V.E

ORDEN = [("general", "General", "resumen"), ("avisos", "Avisos", "chat"), ("claude", "Claude", "robot"),
         ("consumo", "Consumo", "pulso"), ("reglas", "Reglas", "escudo"), ("cuenta", "Cuenta", "usuario")]
NOMBRES = {k: n for k, n, _ in ORDEN}
# grupo -> canal que se puede probar desde su tarjeta
PRUEBAS = {"Telegram": "telegram", "Webhook": "webhook", "Email": "email"}
ICONO_GRUPO = {"Telegram": "chat", "Webhook": "enviar", "Email": "enviar", "Acceso": "llave",
               "Valores por defecto": "robot", "Panel": "resumen", "Análisis": "reloj",
               "Cuándo es crítico": "alerta", "Avisos y excepciones": "escudo"}


def _hora(iso):
    try:
        return dt.datetime.fromisoformat(iso).strftime("%d/%m %H:%M")
    except (TypeError, ValueError):
        return iso or "—"


def pestanas(activa: str) -> str:
    return '<nav class="pestanas" aria-label="Secciones de ajustes">' + "".join(
        f'<a href="/ajustes/{k}"{" aria-current=page" if k == activa else ""}>{V.icono(ic, 16)}{E(n)}</a>'
        for k, n, ic in ORDEN) + "</nav>"


def _campo(aj, c) -> str:
    valor = aj.valor(c)
    var = aj.variable_que_fija(c)
    dis = " disabled" if var else ""
    ayuda = f'<span class="ayuda">{E(c.ayuda)}</span>' if c.ayuda else ""
    fijado = (f'<span class="fijado">{V.icono("candado", 13)}Fijado por la variable de entorno '
              f'<span class="mono">{E(var)}</span></span>') if var else ""
    nombre = E(c.id, quote=True)
    if c.tipo == "bool":
        return (f'<label class="campo campo-bool"><input type="checkbox" name="{nombre}" value="si"'
                f'{" checked" if valor else ""}{dis}><span>{E(c.etiqueta)}{ayuda}{fijado}</span></label>')
    if c.tipo == "opcion":
        ops = "".join(f'<option value="{E(v, quote=True)}"{" selected" if v == valor else ""}>{E(t)}</option>'
                      for v, t in c.opciones)
        control = f'<select name="{nombre}"{dis}>{ops}</select>'
    elif c.secreto:
        actual = enmascarar(valor)
        ph = (f"{actual} · déjalo vacío para no cambiarlo" if actual else "Sin configurar")
        borrar = (f'<label><input type="checkbox" name="{nombre}.borrar" value="si"{dis}>Quitar</label>'
                  if actual and not var else "")
        control = (f'<div class="secreto"><input type="password" name="{nombre}" autocomplete="new-password" '
                   f'placeholder="{E(ph, quote=True)}" aria-label="{E(c.etiqueta, quote=True)}"{dis}>{borrar}</div>')
    else:
        if c.tipo == "lista":
            texto, tipo, extra = ", ".join(str(x) for x in valor or []), "text", ""
        elif c.tipo in ("numero", "decimal"):
            texto, tipo = ("" if valor is None else str(valor)), "number"
            extra = (f' step="{"1" if c.tipo == "numero" else "any"}"'
                     + (f' min="{c.minimo}"' if c.minimo is not None else "")
                     + (f' max="{c.maximo}"' if c.maximo is not None else ""))
        else:
            texto, tipo, extra = str(valor or ""), "text", ""
        control = f'<input type="{tipo}" name="{nombre}" value="{E(texto, quote=True)}"{extra}{dis}>'
    return f'<label class="campo"><span>{E(c.etiqueta)}</span>{control}{ayuda}{fijado}</label>'


def _formulario(aj, pestana, titulo, campos) -> str:
    ids = ",".join(c.id for c in campos)
    cuerpo = "".join(_campo(aj, c) for c in campos)
    todos_fijados = all(aj.variable_que_fija(c) for c in campos)
    canal = PRUEBAS.get(titulo)
    probar = ""
    if canal:
        probar = V.boton("Guardar y enviar prueba", "secundario", "enviar", attrs='formaction="/ajustes/probar"')
    guardar = "" if todos_fijados else V.boton("Guardar", "primario", "check")
    form = (f'<form method="post" action="/ajustes/guardar"><input type="hidden" name="pestana" value="{E(pestana)}">'
            f'<input type="hidden" name="campos" value="{E(ids, quote=True)}">'
            f'{f"<input type=hidden name=canal value={canal}>" if canal else ""}'
            f'<div class="ajustes-g">{cuerpo}</div><div class="form-pie">{probar}{guardar}</div></form>')
    return V.tarjeta(form, titulo, icono_nombre=ICONO_GRUPO.get(titulo, "ajustes"))


def _consumo(panel) -> str:
    g = panel.v.gestor.consumo
    hist = list(reversed(g.datos.get("historial") or []))
    uso = panel._tarjeta_uso_plan()
    if not hist:
        vacio = V.tarjeta(V.vacio("Todavía no se ha usado Claude. Aquí verás cada análisis: modelo, tokens, "
                                  "cuánto gastó de tu plan y su equivalente si fuera por API.", "pulso"),
                          "Historial de uso", icono_nombre="reloj")
        return (uso or "") + vacio
    filas = []
    for h in hist[:200]:
        tk = h.get("tokens") or {}
        entrada = tk.get("entrada", 0) + tk.get("cache_escritura", 0) + tk.get("cache_lectura", 0)
        d = h.get("delta") or {}
        modelo = consumo.NOMBRE_MODELO.get(h.get("modelo"), h.get("modelo") or "—")
        esfuerzo = consumo.NOMBRE_ESFUERZO.get(h.get("esfuerzo"), h.get("esfuerzo") or "")
        plan = h.get("plan") or ""
        comp = E(h.get("componente") or "—")
        comp = f'<a href="/plan/{E(plan, quote=True)}">{comp}</a>' if plan else comp
        res = V.pill("Correcto", "ok") if h.get("ok") else V.pill("Con error", "mal")
        texto = f'{h.get("componente", "")} {h.get("app", "")} {modelo}'.lower()
        filas.append(
            f'<tr data-texto="{E(texto, quote=True)}" data-res="{"ok" if h.get("ok") else "mal"}">'
            f'<td data-v="{E(h.get("fecha", ""))}"><span class="mono peq">{E(_hora(h.get("fecha")))}</span></td>'
            f'<td data-v="{E(h.get("componente") or "")}"><b>{comp}</b>'
            + (f'<div class="muted peq">{E(h["app"])}</div>' if h.get("app") else "") + '</td>'
            f''
            f'<td>{E(modelo)}<div class="muted peq">{E(esfuerzo)} · {"reintento" if h.get("tipo") == "reintento" else "análisis"}</div></td>'
            f'<td>{res}</td>'
            f'<td class="num" data-v="{entrada + tk.get("salida", 0)}"><span class="mono">{entrada:,}</span>'
            f'<div class="muted peq">salida <span class="mono">{tk.get("salida", 0):,}</span></div></td>'.replace(",", ".")
            + f'<td class="num" data-v="{d.get("five_hour", -1)}">'
            f'{E("+" + consumo.pct(d["five_hour"])) if "five_hour" in d else "<span class=muted>—</span>"}</td>'
            f'<td class="num" data-v="{d.get("seven_day", -1)}">'
            f'{E("+" + consumo.pct(d["seven_day"])) if "seven_day" in d else "<span class=muted>—</span>"}</td>'
            f'<td class="num" data-v="{h.get("coste_usd") or 0}"><span class="mono">{E(consumo.usd(h.get("coste_usd")))}</span></td>'
            f'<td class="num" data-v="{h.get("duracion_s") or 0}"><span class="mono">{(h.get("duracion_s") or 0) / 60:.1f} min</span></td></tr>')
    cab = (V.th("Fecha") + V.th("Componente") + V.th("Modelo") + V.th("Resultado") + V.th("Tokens", "num", "num")
           + V.th("Ventana 5 h", "num", "num") + V.th("Semanal", "num", "num") + V.th("Si fuera por API", "num", "num")
           + V.th("Duración", "num", "num"))
    filtros = V.filtros("#t-consumo", "Buscar componente, app o modelo", "ejecuciones",
                        [("res", "ok", "check", "Correctas"), ("res", "mal", "x", "Con error")], abajo=True)
    tabla = (filtros + f'<div class="tabla tabla-sola"><table id="t-consumo" class="ancha"><thead><tr>{cab}</tr></thead>'
             f'<tbody>{"".join(filas)}</tbody></table></div>'
             + V.sin_coincidencias("#t-consumo", "Ninguna ejecución coincide con estos filtros."))
    total = sum(h.get("coste_usd") or 0 for h in hist)
    extra = f'<span class="muted peq">{len(hist)} ejecución(es) · <span class="mono">{E(consumo.usd(total))}</span> equivalente API</span>'
    return (uso or "") + V.tarjeta(tabla, "Historial de uso", extra, icono_nombre="reloj")


def _cuenta(panel, ctx) -> str:
    cu = panel.cuenta
    clave = (f'<form method="post" action="/ajustes/clave"><div class="form-estrecho">'
             f'<label class="campo"><span>Contraseña actual</span><input type="password" name="actual" '
             f'autocomplete="current-password" required></label>'
             f'<label class="campo"><span>Contraseña nueva</span><input type="password" name="nueva" minlength="12" '
             f'autocomplete="new-password" required><span class="ayuda">Al menos 12 caracteres.</span></label>'
             f'<label class="campo"><span>Repite la contraseña nueva</span><input type="password" name="nueva2" '
             f'minlength="12" autocomplete="new-password" required></label></div>'
             f'<div class="form-pie">{V.boton("Cambiar contraseña", "primario", "candado")}</div></form>')
    n = cu.n_sesiones()
    otras = max(0, n - 1)
    sesiones = (f'<dl class="dl"><dt>Usuario</dt><dd><b>{E(cu.usuario)}</b></dd>'
                f'<dt>Sesiones abiertas</dt><dd>{n} <span class="muted peq">(contando esta)</span></dd></dl>'
                f'<div class="form-pie">'
                + (f'<form method="post" action="/ajustes/sesiones" data-confirmar="Se cerrará la sesión en los demás '
                   f'navegadores y dispositivos ({otras}). Esta seguirá abierta." data-titulo="Cerrar las demás sesiones" '
                   f'data-boton="Cerrar sesiones">{V.boton("Cerrar las demás sesiones", "secundario", "x")}</form>'
                   if otras else "")
                + f'<form method="post" action="/salir">{V.boton("Cerrar sesión", "peligro", "salir")}</form></div>')
    return (V.tarjeta(sesiones, "Tu cuenta", icono_nombre="usuario")
            + V.tarjeta(clave, "Cambiar la contraseña", icono_nombre="candado"))


def pagina(panel, ctx, pestana: str) -> str | None:
    if pestana not in NOMBRES:
        return None
    if pestana == "consumo":
        cuerpo = _consumo(panel)
        sub = "Lo que ha gastado Claude: estado de tu plan y cada ejecución"
    elif pestana == "cuenta":
        cuerpo = _cuenta(panel, ctx)
        sub = "Usuario, contraseña y sesiones"
    else:
        titulo, grupos = PESTANAS[pestana]
        cuerpo = "".join(_formulario(panel.ajustes, pestana, t, cs) for t, cs in grupos)
        sub = {"general": "Nombre, análisis y fuentes de vulnerabilidades",
               "avisos": "Telegram, webhook y email. Los cambios valen al momento, sin reiniciar",
               "claude": "Acceso a Claude Code y valores por defecto de cada corrección",
               "reglas": "Cuándo una vulnerabilidad es crítica y de cuáles avisar"}[pestana]
        if pestana == "avisos":
            cuerpo = (f'<div class="banner banner-info">{V.icono("info", 22)}<div><p>Los botones de aprobar y aplicar '
                      'de Telegram solo responden al chat configurado (y, si los indicas, a esos usuarios).</p></div></div>'
                      + cuerpo)
    return panel.envolver(f"Ajustes · {NOMBRES[pestana]}", pestanas(pestana) + cuerpo, f"/ajustes/{pestana}", ctx,
                          subtitulo=sub)
