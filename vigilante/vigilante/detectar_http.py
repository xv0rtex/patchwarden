"""Detección pasiva desde fuera: cabeceras HTTP y metaetiqueta generator.

Es la fuente menos fiable (muchas webs ocultan la versión, que es lo recomendable),
pero sirve cuando no hay acceso a Docker ni al código.
"""
from __future__ import annotations

import logging
import re
import ssl
import urllib.request

from .catalogo import RUNTIMES
from .modelo import Componente

log = logging.getLogger("vigilante.http")

PATRONES = [
    ("Server", "nginx", RUNTIMES["nginx"]["regex"]),
    ("Server", "apache-httpd", RUNTIMES["apache-httpd"]["regex"]),
    ("Server", "php", RUNTIMES["php"]["regex"]),
    ("X-Powered-By", "php", RUNTIMES["php"]["regex"]),
    ("X-Powered-By", "tomcat", r"Tomcat[/-](\d+\.\d+\.\d+)"),
]


def detectar(url: str) -> list[Componente]:
    if not url:
        return []
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # webs internas con certificado propio
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "patchwarden/0.1"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            cab = r.headers
            html = r.read(200_000).decode(errors="replace")
    except Exception as e:  # noqa: BLE001
        log.warning("No se pudo consultar %s: %s", url, e)
        return []
    return analizar(cab, html, url)


def analizar(cab, html, url) -> list[Componente]:
    out = []
    for cabecera, rt, rx in PATRONES:
        valor = cab.get(cabecera) or ""
        m = re.search(rx, valor)
        if m and not any(c.nombre == rt for c in out):
            out.append(Componente(rt, m.group(1), "runtime", origen="http",
                                  detalle=f"{cabecera}: {valor} ({url})"))
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress (\d+\.\d+(?:\.\d+)?)', html, re.I)
    if m:
        out.append(Componente("wordpress", m.group(1), "runtime", origen="http", detalle=f"meta generator ({url})"))
    return out
