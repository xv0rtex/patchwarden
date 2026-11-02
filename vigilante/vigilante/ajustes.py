"""Ajustes editables desde el panel.

Se guardan en <datos>/ajustes.json y se aplican sobre la configuración en este orden:

    DEFECTO  <-  vigilante.toml  <-  ajustes.json (panel)  <-  variables de entorno

Una variable de entorno siempre manda: el campo se muestra bloqueado en el panel. Los secretos nunca
vuelven al navegador (se enseñan enmascarados) y dejarlos vacíos al guardar conserva el valor actual.
"""
from __future__ import annotations

import json
import logging
import os
import threading

from . import config, consumo

log = logging.getLogger("vigilante.ajustes")

SEVERIDADES = [("CRITICA", "Crítica"), ("ALTA", "Alta"), ("MEDIA", "Media"), ("BAJA", "Baja")]


class Campo:
    def __init__(self, seccion, clave, etiqueta, tipo="texto", ayuda="", opciones=None, minimo=None, maximo=None):
        self.seccion, self.clave, self.etiqueta, self.tipo = seccion, clave, etiqueta, tipo
        self.ayuda, self.opciones, self.minimo, self.maximo = ayuda, opciones or [], minimo, maximo

    @property
    def id(self):
        return f"{self.seccion}.{self.clave}"

    @property
    def secreto(self):
        return self.tipo == "secreto"


# pestaña -> (título, [(título del grupo, [campos])])
PESTANAS = {
    "general": ("General", [
        ("Panel", [
            Campo("general", "nombre_web", "Nombre", ayuda="Aparece en el panel y en el asunto de los avisos."),
            Campo("panel", "url_publica", "URL pública del panel",
                  ayuda="Para los enlaces de los avisos, p. ej. https://patchwarden.midominio.com"),
        ]),
        ("Análisis", [
            Campo("general", "intervalo_horas", "Analizar cada (horas)", "numero", minimo=1, maximo=168,
                  ayuda="Se aplica a partir del siguiente análisis."),
            Campo("fuentes", "nvd_api_key", "Clave de la API de NVD", "secreto",
                  ayuda="Opcional. Con clave, el límite de NVD pasa de 5 a 50 peticiones cada 30 s."),
        ]),
    ]),
    "avisos": ("Avisos", [
        ("Telegram", [
            Campo("avisos", "telegram_token", "Token del bot", "secreto",
                  ayuda="Lo da @BotFather al crear el bot."),
            Campo("avisos", "telegram_chat_id", "ID del chat",
                  ayuda="El chat (o grupo) donde llegan los avisos y los botones de aprobar."),
            Campo("avisos", "telegram_usuarios", "Usuarios que pueden aprobar", "lista",
                  ayuda="IDs numéricos de Telegram separados por comas. Vacío = cualquiera del chat."),
            Campo("avisos", "recordatorio_horas", "Recordar críticas sin resolver cada (horas)", "numero",
                  minimo=1, maximo=720),
        ]),
        ("Webhook", [
            Campo("avisos", "webhook_url", "URL", ayuda="Recibe un POST JSON con cada aviso (n8n, Slack, Discord…)."),
            Campo("avisos", "webhook_formato", "Formato", "opcion",
                  opciones=[("generico", "Genérico (JSON)"), ("slack", "Slack"), ("discord", "Discord")]),
        ]),
        ("Email", [
            Campo("avisos", "smtp_servidor", "Servidor SMTP"),
            Campo("avisos", "smtp_puerto", "Puerto", "numero", minimo=1, maximo=65535),
            Campo("avisos", "smtp_usuario", "Usuario"),
            Campo("avisos", "smtp_clave", "Contraseña", "secreto"),
            Campo("avisos", "email_de", "Remitente"),
            Campo("avisos", "email_para", "Destinatario"),
        ]),
    ]),
    "claude": ("Claude", [
        ("Acceso", [
            Campo("claude", "oauth_token", "Token de Claude Code", "secreto",
                  ayuda="CLAUDE_CODE_OAUTH_TOKEN, de `claude setup-token`. Usa tu plan de Claude: "
                        "nunca se usa una clave de API. Vacío = la sesión iniciada en el equipo."),
        ]),
        ("Valores por defecto", [
            Campo("claude", "modelo", "Modelo", "opcion", opciones=[(m[0], m[1]) for m in consumo.MODELOS]),
            Campo("claude", "esfuerzo", "Razonamiento", "opcion", opciones=[(e[0], e[1]) for e in consumo.ESFUERZOS]),
            Campo("claude", "modo", "Cuándo trabaja Claude", "opcion",
                  opciones=[("a_peticion", "Solo cuando lo pido (recomendado)"),
                            ("auto", "Prepara planes solo tras cada análisis")],
                  ayuda="Incluso en automático, nada se aplica sin tu aprobación."),
            Campo("claude", "severidad_minima", "Ofrecer corrección desde", "opcion", opciones=SEVERIDADES),
            Campo("claude", "max_planes_por_solicitud", "Máximo de componentes al corregir una app entera",
                  "numero", minimo=1, maximo=30),
            Campo("claude", "max_planes_por_ciclo", "Máximo de planes automáticos por análisis", "numero",
                  minimo=0, maximo=30),
            Campo("claude", "timeout_s", "Tiempo máximo por análisis (segundos)", "numero", minimo=60, maximo=7200),
            Campo("claude", "investigar_web", "Leer changelogs y guías de migración en la web", "bool"),
            Campo("claude", "reintento_si_falla", "Si la verificación falla, dejar que Claude corrija el plan una vez",
                  "bool"),
        ]),
    ]),
    "reglas": ("Reglas", [
        ("Cuándo es crítico", [
            Campo("reglas", "cvss_critico", "CVSS a partir del cual es crítica", "decimal", minimo=0, maximo=10),
            Campo("reglas", "epss_critico", "EPSS que la hace crítica (si CVSS ≥ 7)", "decimal", minimo=0, maximo=1,
                  ayuda="Probabilidad de explotación en 30 días, de 0 a 1."),
            Campo("reglas", "kev_es_critico", "Explotada activamente (CISA KEV) = crítica", "bool"),
        ]),
        ("Avisos y excepciones", [
            Campo("reglas", "severidad_minima_aviso", "Avisar desde", "opcion", opciones=SEVERIDADES),
            Campo("reglas", "ignorar", "Vulnerabilidades ignoradas", "lista",
                  ayuda="IDs (CVE-…, GHSA-…) separados por comas: falsos positivos aceptados."),
        ]),
    ]),
}

CAMPOS = {c.id: c for _, grupos in PESTANAS.values() for _, cs in grupos for c in cs}
# (sección, clave) -> variable de entorno que la fija
_VAR_DE = {v: k for k, v in config.ENTORNO.items()}


class ErrorAjuste(ValueError):
    pass


def enmascarar(valor: str) -> str:
    valor = str(valor or "")
    if not valor:
        return ""
    return "••••" + (valor[-4:] if len(valor) >= 12 else "")


def convertir(campo: Campo, texto: str):
    texto = (texto or "").strip()
    if campo.tipo == "bool":
        return texto in ("si", "1", "on", "true")
    if campo.tipo in ("numero", "decimal"):
        try:
            v = int(texto) if campo.tipo == "numero" else float(texto.replace(",", "."))
        except ValueError:
            raise ErrorAjuste(f"«{campo.etiqueta}» tiene que ser un número.") from None
        if (campo.minimo is not None and v < campo.minimo) or (campo.maximo is not None and v > campo.maximo):
            raise ErrorAjuste(f"«{campo.etiqueta}» tiene que estar entre {campo.minimo} y {campo.maximo}.")
        return v
    if campo.tipo == "lista":
        return [x.strip() for x in texto.replace("\n", ",").split(",") if x.strip()]
    if campo.tipo == "opcion" and texto not in {o[0] for o in campo.opciones}:
        raise ErrorAjuste(f"Valor no válido para «{campo.etiqueta}».")
    if any(ord(ch) < 32 for ch in texto):
        raise ErrorAjuste(f"«{campo.etiqueta}» no puede tener saltos de línea ni caracteres de control.")
    return texto


class Ajustes:
    def __init__(self, cfg: dict, carpeta_datos: str):
        self.cfg = cfg
        self.ruta = os.path.join(carpeta_datos, "ajustes.json")
        self._l = threading.Lock()
        self.valores = leer(self.ruta)

    def variable_que_fija(self, campo: Campo) -> str:
        """Nombre de la variable de entorno que fija el campo ('' si ninguna)."""
        var = _VAR_DE.get((campo.seccion, campo.clave))
        return var if var and os.environ.get(var) else ""

    def valor(self, campo: Campo):
        return self.cfg.get(campo.seccion, {}).get(campo.clave)

    def guardar(self, pestana: str, form: dict) -> list[str]:
        """Valida y guarda los campos de una pestaña (o solo los de form['campos'], si viene: cada tarjeta
        tiene su formulario). Devuelve los ids cambiados. Aplica en caliente."""
        if pestana not in PESTANAS:
            raise ErrorAjuste("Pestaña desconocida.")
        solo = {x for x in (form.get("campos") or "").split(",") if x}
        nuevos = {}
        for _, campos in PESTANAS[pestana][1]:
            for c in campos:
                if (solo and c.id not in solo) or self.variable_que_fija(c):
                    continue
                if c.tipo == "bool":
                    v = convertir(c, form.get(c.id, ""))
                elif c.id not in form:
                    continue
                elif c.secreto:
                    if form.get(c.id + ".borrar") == "si":
                        v = ""
                    elif not form[c.id].strip():
                        continue                # vacío = conservar el secreto actual
                    else:
                        v = convertir(c, form[c.id])
                else:
                    v = convertir(c, form[c.id])
                if v != self.valor(c):
                    nuevos[c.id] = v
        if not nuevos:
            return []
        with self._l:
            for k, v in nuevos.items():
                sec, clave = k.split(".", 1)
                self.valores.setdefault(sec, {})[clave] = v
                self.cfg.setdefault(sec, {})[clave] = v      # en caliente: los módulos comparten estos dicts
            escribir(self.ruta, self.valores)
        log.info("Ajustes cambiados desde el panel: %s", ", ".join(sorted(nuevos)))
        return sorted(nuevos)


def leer(ruta: str) -> dict:
    try:
        with open(ruta) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def escribir(ruta: str, datos: dict):
    tmp = ruta + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)     # contiene secretos
    with os.fdopen(fd, "w") as f:
        json.dump(datos, f, ensure_ascii=False, indent=1)
    os.replace(tmp, ruta)


def aplicar_guardados(cfg: dict, ruta: str):
    """Para config.cargar(): pone los ajustes del panel encima del TOML (las variables de entorno van después)."""
    for sec, valores in leer(ruta).items():
        if isinstance(valores, dict):
            for clave, v in valores.items():
                if f"{sec}.{clave}" in CAMPOS:      # solo lo que el panel puede editar
                    cfg.setdefault(sec, {})[clave] = v
