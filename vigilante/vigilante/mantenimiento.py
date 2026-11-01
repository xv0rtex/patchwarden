"""Modo mantenimiento.

Mecanismo principal (no toca otros contenedores): un fichero bandera en un volumen
compartido con el servidor web. nginx/Apache comprueban si existe y, si existe,
responden 503 con la página de mantenimiento. Ver ejemplo/web/nginx/default.conf.

Alternativas configurables: ejecutar un comando o hacer POST a un webhook
(p. ej. para un balanceador, Cloudflare, Traefik…).
"""
from __future__ import annotations

import datetime as dt
import html
import json
import logging
import os
import shlex
import subprocess

from .http import peticion

log = logging.getLogger("vigilante.mantenimiento")
BANDERA = "ACTIVO"

PAGINA = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>En mantenimiento · {web}</title>
<style>*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;
font:16px/1.55 Inter,"Segoe UI",system-ui,sans-serif;color:#0f172a;
background:radial-gradient(1200px 600px at 20% -10%,#e0e7ff,transparent),radial-gradient(900px 500px at 110% 110%,#ede9fe,transparent),#f8fafc}}
main{{background:#fff;border:1px solid #e5e7ee;border-radius:20px;padding:44px 40px;max-width:480px;text-align:center;
box-shadow:0 24px 60px rgba(15,23,42,.08)}}
.i{{width:64px;height:64px;border-radius:18px;margin:0 auto 20px;display:grid;place-items:center;background:#eef0ff;color:#4338ca}}
h1{{margin:0 0 10px;font-size:26px;letter-spacing:-.3px}}p{{margin:0;color:#475467}}
.b{{display:inline-flex;align-items:center;gap:8px;margin-top:24px;font-size:13px;color:#667085;background:#f4f5f8;
border-radius:99px;padding:6px 14px}}.b i{{width:8px;height:8px;border-radius:50%;background:#fab219}}
@media (prefers-color-scheme:dark){{body{{background:#0e121b;color:#eef1f7}}main{{background:#161b26;border-color:#262d3b}}
p{{color:#b4bccb}}.i{{background:#23284a;color:#a5abff}}.b{{background:#1f2533;color:#b4bccb}}}}</style></head>
<body><main><div class="i"><svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor"
stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M15 7.5a4.5 4.5 0 1 1-3.4 7.4L5 21.5H2.5V19l6.6-6.6A4.5 4.5 0 0 1 15 7.5z"/></svg></div>
<h1>Volvemos enseguida</h1><p>{web} está en mantenimiento mientras aplicamos una actualización de seguridad.
Disculpa las molestias.</p><div class="b"><i></i>Mantenimiento programado</div></main></body></html>"""


class Mantenimiento:
    def __init__(self, cfg: dict, nombre_web: str):
        self.c, self.web = cfg, nombre_web
        self.carpeta = cfg.get("carpeta", "/mantenimiento")

    @property
    def ruta_bandera(self):
        return os.path.join(self.carpeta, BANDERA)

    def activo(self) -> bool:
        return os.path.exists(self.ruta_bandera)

    def info(self) -> dict:
        if not self.activo():
            return {"activo": False}
        try:
            return {"activo": True, **json.load(open(self.ruta_bandera))}
        except (OSError, ValueError):
            return {"activo": True}

    def preparar(self):
        """Deja la página lista aunque no se active nunca (así nginx siempre la encuentra)."""
        try:
            os.makedirs(self.carpeta, exist_ok=True)
            with open(os.path.join(self.carpeta, "mantenimiento.html"), "w") as f:
                f.write(PAGINA.format(web=html.escape(self.web)))
        except OSError as e:
            log.warning("No se puede escribir en %s: %s", self.carpeta, e)

    def activar(self, motivo: str, quien: str = "vigilante"):
        self.preparar()
        datos = {"motivo": motivo, "por": quien, "desde": dt.datetime.now().isoformat(timespec="seconds")}
        with open(self.ruta_bandera, "w") as f:
            json.dump(datos, f)
        self._acciones_extra("activar", datos)
        log.warning("MODO MANTENIMIENTO ACTIVADO: %s", motivo)

    def desactivar(self, quien: str = "panel"):
        if self.activo():
            os.remove(self.ruta_bandera)
        self._acciones_extra("desactivar", {"por": quien})
        log.warning("Modo mantenimiento desactivado por %s", quien)

    def _acciones_extra(self, accion, datos):
        if self.c.get("comando"):
            env = {**os.environ, "VIGILANTE_ACCION": accion, "VIGILANTE_MOTIVO": datos.get("motivo", "")}
            try:
                subprocess.run(shlex.split(self.c["comando"]), env=env, timeout=60, check=False)
            except Exception as e:  # noqa: BLE001
                log.error("Comando de mantenimiento falló: %s", e)
        if self.c.get("webhook"):
            try:
                peticion(self.c["webhook"], {"accion": accion, **datos}, json_resp=False)
            except Exception as e:  # noqa: BLE001
                log.error("Webhook de mantenimiento falló: %s", e)
