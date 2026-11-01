"""Canales de aviso: consola (siempre), Telegram, webhook genérico/Slack/Discord y email."""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from .http import peticion
from .modelo import Hallazgo

log = logging.getLogger("vigilante.avisos")
ICONO = {"CRITICA": "[CRÍTICA]", "ALTA": "[ALTA]", "MEDIA": "[MEDIA]", "BAJA": "[BAJA]", "DESCONOCIDA": "[?]"}


def texto_hallazgo(h: Hallazgo, url_panel: str = "", propuesta: str = "") -> str:
    lineas = [f"{ICONO.get(h.severidad, '')} {h.id}",
              f"{('App: ' + h.app + ' · ') if h.app else ''}Componente: {h.nombre} {h.version}"]
    extras = []
    if h.cvss is not None:
        extras.append(f"CVSS {h.cvss}")
    if h.kev:
        extras.append("EXPLOTADA ACTIVAMENTE (CISA KEV)")
    if h.epss is not None:
        extras.append(f"EPSS {h.epss:.0%}")
    if extras:
        lineas.append(" · ".join(extras))
    lineas.append(h.resumen[:350])
    if h.corregido_en:
        lineas.append(f"Corregido en: {', '.join(h.corregido_en)}")
    if propuesta:
        lineas.append(f"Propuesta de Claude: {propuesta}")
    if url_panel:
        lineas.append(f"Panel: {url_panel}")
    return "\n".join(lineas)


class Avisador:
    def __init__(self, cfg: dict, nombre_web: str):
        self.c, self.web = cfg, nombre_web

    def enviar(self, asunto: str, cuerpo: str, urgente: bool = False, canales=None):
        """canales=None -> todos; o una tupla de ('consola', 'telegram', 'webhook', 'email')."""
        titulo = f"[Vigilante · {self.web}] {asunto}"
        if self.c.get("consola", True) and (canales is None or "consola" in canales):
            log.warning("\n%s\n%s\n%s", "=" * 60, titulo, cuerpo)
        enviados = []
        for nombre, fn in (("telegram", self._telegram), ("webhook", self._webhook), ("email", self._email)):
            if canales is not None and nombre not in canales:
                continue
            try:
                if fn(titulo, cuerpo, urgente):
                    enviados.append(nombre)
            except Exception as e:  # noqa: BLE001 - un canal caído no debe tumbar a los demás
                log.error("Fallo enviando aviso por %s: %s", nombre, e)
        return enviados

    def _telegram(self, titulo, cuerpo, urgente):
        tok, chat = self.c.get("telegram_token"), self.c.get("telegram_chat_id")
        if not (tok and chat):
            return False
        texto = f"{titulo}\n\n{cuerpo}"[:4000]
        api = (self.c.get("telegram_api") or "https://api.telegram.org").rstrip("/")
        peticion(f"{api}/bot{tok}/sendMessage",
                 {"chat_id": chat, "text": texto, "disable_web_page_preview": True,
                  "disable_notification": not urgente})
        return True

    def _webhook(self, titulo, cuerpo, urgente):
        url = self.c.get("webhook_url")
        if not url:
            return False
        fmt = self.c.get("webhook_formato", "generico")
        if fmt == "slack":
            datos = {"text": f"*{titulo}*\n{cuerpo}"}
        elif fmt == "discord":
            datos = {"content": f"**{titulo}**\n{cuerpo}"[:1900]}
        else:
            datos = {"titulo": titulo, "texto": cuerpo, "urgente": urgente, "web": self.web}
        peticion(url, datos, json_resp=False)
        return True

    def _email(self, titulo, cuerpo, urgente):
        srv, para = self.c.get("smtp_servidor"), self.c.get("email_para")
        if not (srv and para):
            return False
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = titulo, self.c.get("email_de") or self.c.get("smtp_usuario"), para
        if urgente:
            msg["X-Priority"] = "1"
        msg.set_content(cuerpo)
        with smtplib.SMTP(srv, int(self.c.get("smtp_puerto", 587)), timeout=30) as s:
            s.starttls()
            if self.c.get("smtp_usuario"):
                s.login(self.c["smtp_usuario"], self.c.get("smtp_clave", ""))
            s.send_message(msg)
        return True
