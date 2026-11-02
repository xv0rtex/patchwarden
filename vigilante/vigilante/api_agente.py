"""Rutas /api/agente/* del panel central (las usan los agentes, no el navegador).

Autenticación: código de alta de un solo uso (solo en /alta) y después `Authorization: Bearer <token>`.
No usan la sesión del panel ni el token CSRF: un navegador no puede llamarlas sin el token del agente.
"""
from __future__ import annotations

import json
import logging

from .equipos_remotos import ErrorEquipo

log = logging.getLogger("vigilante.panel")
MAX_CUERPO = 8 * 1024 * 1024


def _responder(h, codigo: int, datos: dict):
    cuerpo = json.dumps(datos, ensure_ascii=False).encode()
    h.send_response(codigo)
    h.send_header("Content-Type", "application/json")
    h.send_header("Content-Length", str(len(cuerpo)))
    h.send_header("Cache-Control", "no-store")
    h.end_headers()
    h.wfile.write(cuerpo)


def _cuerpo(h) -> dict | None:
    try:
        largo = int(h.headers.get("Content-Length") or 0)
    except ValueError:
        return None
    if largo <= 0 or largo > MAX_CUERPO:
        return None
    try:
        d = json.loads(h.rfile.read(largo))
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def _equipo(h, registro) -> str | None:
    cab = h.headers.get("Authorization") or ""
    return registro.autenticar(cab[7:].strip()) if cab.startswith("Bearer ") else None


def get(h, ruta: str, registro):
    id_ = _equipo(h, registro)
    if not id_:
        return _responder(h, 401, {"error": "token de equipo no válido"})
    if ruta == "/api/agente/tareas":
        return _responder(h, 200, {"tareas": registro.tareas_para(id_)})
    _responder(h, 404, {"error": "no encontrado"})


def post(h, ruta: str, registro, limite, ip: str):
    if ruta == "/api/agente/alta":
        espera = limite.restante(ip)
        if espera:
            return _responder(h, 429, {"error": f"demasiados intentos; espera {espera} s"})
        d = _cuerpo(h) or {}
        try:
            id_, token, nombre = registro.canjear(str(d.get("codigo", "")), d.get("hostname", ""), d.get("version", ""))
        except ErrorEquipo as e:
            limite.fallo(ip)
            log.warning("Alta de equipo rechazada desde %s: %s", ip, e)
            return _responder(h, 403, {"error": str(e)})
        limite.acierto(ip)
        return _responder(h, 200, {"id": id_, "token": token, "nombre": nombre})
    id_ = _equipo(h, registro)
    if not id_:
        return _responder(h, 401, {"error": "token de equipo no válido"})
    d = _cuerpo(h)
    if d is None:
        return _responder(h, 400, {"error": "cuerpo JSON no válido o demasiado grande"})
    try:
        if ruta == "/api/agente/inventario":
            registro.guardar_inventario(id_, d)
            return _responder(h, 200, {"ok": True})
        if ruta.startswith("/api/agente/resultado/"):
            registro.resultado(id_, ruta.rsplit("/", 1)[1], d)
            return _responder(h, 200, {"ok": True})
    except ErrorEquipo as e:
        return _responder(h, 400, {"error": str(e)})
    _responder(h, 404, {"error": "no encontrado"})
