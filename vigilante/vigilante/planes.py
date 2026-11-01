"""Planes de corrección: lo que propone Claude, su verificación y las decisiones del usuario.

Un plan agrupa las vulnerabilidades de UN componente (p. ej. php 8.1.2 con 40 CVE) y contiene
uno o varios cambios. Cada cambio se aprueba o rechaza por separado (o todos en bloque).

Estados del plan:
  analizando -> verificando -> pendiente_aprobacion -> aplicando -> aplicado
                                   |                       |-> fallo_aplicacion (revertido o no)
                                   |-> rechazado            '-> revertido (a petición del usuario)
                                   '-> obsoleto (las vulnerabilidades desaparecieron solas)
  error (Claude no pudo analizar)

REGLA: nada pasa de 'pendiente_aprobacion' a 'aplicando' sin una acción explícita del
usuario (botón del panel con token o botón de Telegram de un chat autorizado).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import threading

ABIERTOS = {"analizando", "verificando", "pendiente_aprobacion", "aplicando"}
DECISIONES = {"aprobado", "rechazado"}


def ahora():
    return dt.datetime.now().isoformat(timespec="seconds")


class Planes:
    def __init__(self, carpeta_datos: str):
        self.carpeta = os.path.join(carpeta_datos, "planes")
        os.makedirs(self.carpeta, exist_ok=True)
        self.cerrojo = threading.RLock()

    # ---------------------------------------------------------------- persistencia
    def _ruta(self, id_):
        if not id_.isalnum():
            raise ValueError("id de plan no válido")
        return os.path.join(self.carpeta, f"{id_}.json")

    def obtener(self, id_) -> dict | None:
        try:
            with open(self._ruta(id_)) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def guardar(self, plan: dict):
        with self.cerrojo:
            tmp = self._ruta(plan["id"]) + ".tmp"
            with open(tmp, "w") as f:
                json.dump(plan, f, indent=1, ensure_ascii=False)
            os.replace(tmp, self._ruta(plan["id"]))

    def todos(self) -> list[dict]:
        out = []
        for f in os.listdir(self.carpeta):
            if f.endswith(".json"):
                p = self.obtener(f[:-5])
                if p:
                    out.append(p)
        return sorted(out, key=lambda p: p["creado"], reverse=True)

    def abierto_para(self, clave_componente) -> dict | None:
        return next((p for p in self.todos() if p["componente"]["clave"] == clave_componente
                     and p["estado"] in ABIERTOS), None)

    # ---------------------------------------------------------------- ciclo de vida
    def crear(self, componente: dict, hallazgos: list[dict], raiz: str) -> dict:
        plan = {
            "id": secrets.token_hex(4), "creado": ahora(), "estado": "analizando",
            "componente": componente, "raiz": raiz,
            "hallazgos": [{k: h.get(k) for k in ("id", "severidad", "cvss", "kev", "epss", "corregido_en", "resumen",
                                                  "critico")} for h in hallazgos],
            "analisis": None, "compatibilidad": None, "cambios": [], "verificacion": None,
            "aplicacion": None, "registro": [], "telegram": {},
        }
        self.evento(plan, "plan creado", "vigilante")
        return plan

    def evento(self, plan, texto, por="vigilante", guardar=True):
        plan["registro"].append({"fecha": ahora(), "evento": texto, "por": por})
        if guardar:
            self.guardar(plan)

    def decidir(self, id_, n: int | None, decision: str, por: str) -> tuple[dict, str]:
        """Aprueba/rechaza un cambio (n) o todos (n=None). Devuelve (plan, mensaje)."""
        if decision not in DECISIONES:
            raise ValueError(decision)
        with self.cerrojo:
            plan = self.obtener(id_)
            if not plan:
                raise KeyError(id_)
            if plan["estado"] != "pendiente_aprobacion":
                return plan, f"El plan está en estado «{plan['estado']}»: ya no admite decisiones."
            objetivo = plan["cambios"] if n is None else [c for c in plan["cambios"] if c["n"] == n]
            if not objetivo:
                raise KeyError(n)
            for c in objetivo:
                c.update(decision=decision, decidido_por=por, decidido_en=ahora())
            alcance = "todos los cambios" if n is None else f"cambio {n}"
            self.evento(plan, f"{alcance}: {decision}", por, guardar=False)
            if all(c.get("decision") == "rechazado" for c in plan["cambios"]):
                plan["estado"] = "rechazado"
                self.evento(plan, "plan rechazado: no se aplicará nada", por, guardar=False)
            self.guardar(plan)
            return plan, f"{alcance.capitalize()}: {decision}."


def aprobados(plan) -> list[dict]:
    return [c for c in plan["cambios"] if c.get("decision") == "aprobado"]


def pendientes(plan) -> list[dict]:
    return [c for c in plan["cambios"] if not c.get("decision")]
