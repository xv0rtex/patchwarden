"""Cliente HTTP mínimo (solo librería estándar) con reintentos y caché en disco."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request

log = logging.getLogger("vigilante.http")
AGENTE = "vigilante-cve/0.1 (+https://github.com/)"


def peticion(url, datos=None, cabeceras=None, metodo=None, timeout=30, reintentos=3, json_resp=True):
    cab = {"User-Agent": AGENTE, "Accept": "application/json"}
    cab.update(cabeceras or {})
    cuerpo = None
    if datos is not None:
        cuerpo = json.dumps(datos).encode()
        cab.setdefault("Content-Type", "application/json")
    ultimo = None
    for intento in range(reintentos):
        try:
            req = urllib.request.Request(url, data=cuerpo, headers=cab, method=metodo)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return json.loads(raw) if json_resp else (r, raw)
        except urllib.error.HTTPError as e:
            ultimo = e
            # 403/429/503 en NVD = límite de peticiones: esperar y reintentar
            if e.code in (403, 429, 500, 502, 503, 504):
                espera = 6 * (intento + 1)
                log.warning("HTTP %s en %s, reintento en %ss", e.code, url[:90], espera)
                time.sleep(espera)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            ultimo = e
            time.sleep(3 * (intento + 1))
    raise ultimo


class Cache:
    """Caché JSON en disco con caducidad, para no machacar las APIs públicas."""

    def __init__(self, carpeta):
        self.carpeta = os.path.join(carpeta, "cache")
        os.makedirs(self.carpeta, exist_ok=True)

    def _ruta(self, clave):
        return os.path.join(self.carpeta, hashlib.sha1(clave.encode()).hexdigest() + ".json")

    def get(self, clave, max_edad_s):
        ruta = self._ruta(clave)
        try:
            if time.time() - os.path.getmtime(ruta) < max_edad_s:
                with open(ruta) as f:
                    return json.load(f)
        except (OSError, ValueError):
            pass
        return None

    def set(self, clave, valor):
        tmp = self._ruta(clave) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(valor, f)
        os.replace(tmp, self._ruta(clave))
        return valor
