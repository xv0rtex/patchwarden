"""Bot de Telegram para comunicar planes y recoger aprobaciones.

- Un mensaje de cabecera por plan (qué se ha detectado, qué propone Claude, resultado de la
  verificación) con botones «Aprobar todo y aplicar» / «Rechazar todo».
- Un mensaje por cambio, con su justificación individual y botones «Aprobar» / «Rechazar».
- Cuando ya no quedan cambios por decidir: «Aplicar los N aprobados».
- Después de aplicar: resultado y botón «Revertir».

Seguridad: solo se atienden pulsaciones del chat configurado (y, si se configura, de los
usuarios autorizados). Las acciones que modifican la web («aplicar», «aprobar todo y aplicar»,
«revertir») piden una segunda confirmación.
"""
from __future__ import annotations

import html
import logging
import threading

from .http import peticion
from .planes import aprobados, pendientes

log = logging.getLogger("vigilante.telegram")
E = html.escape
RIESGO = {"bajo": "bajo", "medio": "medio", "alto": "ALTO"}
VERIF = {"ok": "superada", "solo_estatica": "solo estática (sin contenedores de pruebas)",
         "parcial": "parcial", "fallo": "FALLIDA", "en_curso": "en curso"}


class Bot:
    def __init__(self, cfg_avisos: dict, al_pulsar):
        self.token = cfg_avisos.get("telegram_token")
        self.chat = str(cfg_avisos.get("telegram_chat_id") or "")
        self.usuarios = {str(u) for u in cfg_avisos.get("telegram_usuarios") or []}
        self.api = (cfg_avisos.get("telegram_api") or "https://api.telegram.org").rstrip("/")
        self.al_pulsar = al_pulsar      # función(accion, plan_id, n, usuario) -> texto de respuesta
        self.offset = 0
        self.parar = threading.Event()

    @property
    def activo(self):
        return bool(self.token and self.chat)

    def _api(self, metodo, datos, timeout=40):
        return peticion(f"{self.api}/bot{self.token}/{metodo}", datos, timeout=timeout, reintentos=2)

    def enviar(self, texto, botones=None, silencioso=False) -> int | None:
        if not self.activo:
            return None
        datos = {"chat_id": self.chat, "text": texto[:4000], "parse_mode": "HTML",
                 "disable_web_page_preview": True, "disable_notification": silencioso}
        if botones:
            datos["reply_markup"] = {"inline_keyboard": botones}
        try:
            return self._api("sendMessage", datos)["result"]["message_id"]
        except Exception as e:  # noqa: BLE001
            log.error("Telegram sendMessage: %s", e)
            return None

    def editar(self, message_id, texto, botones=None):
        if not (self.activo and message_id):
            return
        datos = {"chat_id": self.chat, "message_id": message_id, "text": texto[:4000], "parse_mode": "HTML",
                 "disable_web_page_preview": True, "reply_markup": {"inline_keyboard": botones or []}}
        try:
            self._api("editMessageText", datos)
        except Exception as e:  # noqa: BLE001
            log.debug("Telegram editMessageText: %s", e)

    # ------------------------------------------------------------------ escucha de botones
    def arrancar(self):
        if self.activo:
            threading.Thread(target=self._bucle, daemon=True, name="telegram").start()
            log.info("Bot de Telegram escuchando botones")

    def _bucle(self):
        while not self.parar.is_set():
            try:
                r = self._api("getUpdates", {"offset": self.offset, "timeout": 25,
                                             "allowed_updates": ["callback_query"]}, timeout=40)
                for u in r.get("result", []):
                    self.offset = u["update_id"] + 1
                    if "callback_query" in u:
                        self._pulsacion(u["callback_query"])
            except Exception as e:  # noqa: BLE001
                log.debug("Telegram getUpdates: %s", e)
                self.parar.wait(5)

    def _pulsacion(self, cq):
        chat = str(((cq.get("message") or {}).get("chat") or {}).get("id", ""))
        usuario = cq.get("from") or {}
        uid = str(usuario.get("id", ""))
        quien = f"Telegram:{usuario.get('username') or usuario.get('first_name') or uid}"
        if chat != self.chat or (self.usuarios and uid not in self.usuarios):
            log.warning("Pulsación ignorada de chat %s / usuario %s (no autorizado)", chat, uid)
            self._responder(cq["id"], "No autorizado")
            return
        try:
            accion, plan_id, n = (cq.get("data") or "").split("|")
            texto = self.al_pulsar(accion, plan_id, int(n) if n else None, quien,
                                   (cq.get("message") or {}).get("message_id"))
        except Exception as e:  # noqa: BLE001
            log.exception("Error atendiendo botón")
            texto = f"Error: {e}"
        self._responder(cq["id"], texto)

    def _responder(self, cq_id, texto):
        try:
            self._api("answerCallbackQuery", {"callback_query_id": cq_id, "text": (texto or "")[:190]})
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------- textos y botones
def b(texto, accion, plan_id, n=""):
    return {"text": texto, "callback_data": f"{accion}|{plan_id}|{n}"}


def estado_verificacion_cambio(plan, c) -> str:
    ver = plan.get("verificacion") or {}
    if c["n"] not in (ver.get("cambios_verificados") or []):
        return "fuera de la última verificación (solo se verificó lo aprobado)"
    if (ver.get("por_cambio") or {}).get(str(c["n"]), {}).get("aplica"):
        return "se aplica limpio en la copia"
    return "NO se pudo preparar en la copia (ver pasos de la verificación)"


def texto_cabecera(plan, url_panel="") -> str:
    c, a, v = plan["componente"], plan.get("analisis") or {}, plan.get("verificacion") or {}
    ent = a.get("entendimiento") or {}
    criticas = sum(1 for h in plan["hallazgos"] if h.get("critico"))
    estado = {"aplicando": "APLICANDO", "aplicado": "APLICADO", "revertido": "REVERTIDO",
              "rechazado": "RECHAZADO", "fallo_aplicacion": "FALLÓ AL APLICAR", "obsoleto": "OBSOLETO"}
    lineas = [f"<b>Propuesta de corrección · {(E(c['app']) + ' · ') if c.get('app') else ''}{E(c['nombre'])} {E(c['version'])}</b>"
              + (f" · <b>{estado[plan['estado']]}</b>" if plan["estado"] in estado else ""),
              f"{len(plan['hallazgos'])} vulnerabilidad(es), {criticas} crítica(s).",
              "",
              f"<b>Qué pasa:</b> {E(ent.get('resumen', '')[:700])}",
              f"<b>Afecta a:</b> {E(ent.get('version_afectada', ''))} · <b>corregido en:</b> {E(ent.get('version_corregida', ''))}",
              f"<b>¿Expuesta?</b> {E(ent.get('exposicion', '')[:400])}",
              f"<b>Propuesta:</b> subir a {E(a.get('version_objetivo', '?'))}. {E(a.get('estrategia', '')[:400])}",
              *([f"<b>Atención:</b> {E(a.get('version_objetivo', ''))} NO corrige: {E(', '.join(plan['no_cubiertos'][:5]))}"]
                if plan.get("no_cubiertos") else []),
              "",
              f"<b>Verificación en copia de pruebas:</b> {VERIF.get(v.get('estado'), v.get('estado', '—'))}"]
    for p in (v.get("pasos") or [])[:12]:
        icono = "OK ·" if p["ok"] else ("FALLO ·" if p["ok"] is False else "·")
        lineas.append(f"{icono} {E(p['paso'])}: {E(p['detalle'][:150])}")
    if v.get("deprecaciones"):
        lineas.append(f"<b>Deprecaciones vistas:</b> {E('; '.join(v['deprecaciones'][:3])[:300])}")
    lineas += ["", f"Abajo va cada cambio con su justificación. <b>No se aplicará nada sin tu aprobación.</b>"]
    if url_panel:
        lineas.append(f"Detalle y diffs: {E(url_panel)}")
    return "\n".join(lineas)


def botones_cabecera(plan):
    if plan["estado"] != "pendiente_aprobacion":
        return []
    return [[b("Aprobar todo y aplicar", "apt", plan["id"]), b("Rechazar todo", "ret", plan["id"])]]


def texto_cambio(plan, c) -> str:
    v = ((plan.get("verificacion") or {}).get("por_cambio") or {}).get(str(c["n"]), {})
    estado_v = estado_verificacion_cambio(plan, c)
    lineas = [f"<b>Cambio {c['n']}/{len(plan['cambios'])} · {E(c['titulo'])}</b>",
              f"Tipo: {E(c['tipo'].replace('_', ' '))} · Riesgo: {RIESGO.get(c['riesgo_nivel'], c['riesgo_nivel'])}",
              f"Ficheros: {E(', '.join(v.get('ficheros') or c.get('ficheros') or []))}",
              "",
              f"<b>Qué arregla:</b> {E(c['que_arregla'][:600])}",
              f"<b>Por qué es correcto:</b> {E(c['por_que_es_correcto'][:600])}",
              f"<b>Riesgo:</b> {E(c['riesgo_detalle'][:500])}"]
    for titulo, clave in (("Incompatibilidades", "breaking_changes"), ("Dependencias", "dependencias"),
                          ("Deprecaciones", "deprecaciones")):
        if c.get(clave):
            lineas.append(f"<b>{titulo}:</b> {E('; '.join(c[clave])[:400])}")
    lineas += [f"<b>Verificación:</b> {estado_v}",
               f"<b>Cómo revertir:</b> {E(c['como_revertir'][:400])}"]
    if c.get("depende_de"):
        lineas.append(f"Necesita también: cambio(s) {', '.join(map(str, c['depende_de']))}")
    if c.get("decision"):
        icono = "APROBADO" if c["decision"] == "aprobado" else "RECHAZADO"
        lineas.append(f"\n<b>{icono}</b> por {E(c.get('decidido_por', ''))} ({E(c.get('decidido_en', ''))})")
    return "\n".join(lineas)


def botones_cambio(plan, c):
    if plan["estado"] != "pendiente_aprobacion" or c.get("decision"):
        return []
    return [[b("Aprobar", "ap", plan["id"], c["n"]), b("Rechazar", "re", plan["id"], c["n"])]]


def texto_resumen_decision(plan) -> str:
    ap, pe = aprobados(plan), pendientes(plan)
    re_ = [c for c in plan["cambios"] if c.get("decision") == "rechazado"]
    return (f"<b>{E(plan['componente']['nombre'])}: decisión registrada</b>\n"
            f"Aprobados:  {', '.join(str(c['n']) for c in ap) or 'ninguno'}\n"
            f"Rechazados:  {', '.join(str(c['n']) for c in re_) or 'ninguno'}\n"
            + (f"Sin decidir:  {', '.join(str(c['n']) for c in pe)}\n" if pe else "")
            + ("\nSe hará copia de seguridad antes de aplicar y se podrá revertir." if ap else ""))

