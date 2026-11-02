"""Consumo de Claude: qué modelo y razonamiento se usa, cuánto se estima que costará y cuánto ha costado.

Claude Code va con tu plan de Claude, no por API, así que lo que se gasta de verdad es cupo del plan:
la ventana de 5 horas y el límite semanal. `claude -p --output-format stream-json` informa de ambos
(`rate_limit_event`: porcentaje usado y hora de reinicio) y, al terminar, de los tokens y de lo que
habría costado la misma ejecución pagando por API (`total_cost_usd`, a precio de lista).

Aquí se guarda:
- el último estado conocido de los límites del plan (para enseñarlo antes de pedir nada);
- un historial de ejecuciones (modelo, razonamiento, tokens, coste API equivalente, cuántos puntos
  de cada ventana consumió), que sirve para estimar las siguientes.

Los porcentajes del plan son aproximados: el servidor los da redondeados (1 %) y una ventana incluye
también lo que uses de Claude fuera del vigilante mientras tanto.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import statistics
import threading
import time

MODELOS = [  # (id para --model, nombre, $ por millón de tokens de entrada, $ por millón de salida)
    ("claude-opus-5-5", "Opus 5.5", 4.00, 20.00),
    ("claude-sonnet-5-5", "Sonnet 5.5", 2.00, 10.00),
    ("claude-haiku-5-5", "Haiku 5.5", 0.10, 0.50),
    ("claude-fable-5-1", "Fable 5.1", 10.00, 50.00),
]
ESFUERZOS = [("low", "Bajo"), ("medium", "Medio"), ("high", "Alto"), ("xhigh", "Muy alto"), ("max", "Máximo")]
NOMBRE_MODELO = {m[0]: m[1] for m in MODELOS}
NOMBRE_ESFUERZO = dict(ESFUERZOS)
VENTANAS = {"five_hour": "5 horas", "seven_day": "semanal"}

# Estimación sin historial: tokens que añade Claude Code (sistema, esquema, herramientas) y tokens de
# salida + razonamiento típicos por nivel. Solo se usa hasta que haya ejecuciones reales que medir.
BASE_ENTRADA = 15_000
ENTRADA_WEB = 40_000            # resultados de WebSearch/WebFetch que vuelven a entrar como contexto
SALIDA_POR_ESFUERZO = {"low": 4_000, "medium": 8_000, "high": 15_000, "xhigh": 25_000, "max": 40_000}
FRESCO_S = 15 * 60              # un estado de límites más viejo no sirve como «antes» de una ejecución
MAX_HISTORIAL = 300


def ahora_iso():
    return dt.datetime.now().isoformat(timespec="seconds")


def valido(modelo: str, esfuerzo: str) -> bool:
    return modelo in NOMBRE_MODELO and esfuerzo in NOMBRE_ESFUERZO


def _ventanas(evento: dict) -> dict:
    """rate_limit_info -> {"five_hour": {"uso": 0.45, "reinicio": epoch, "estado": "allowed"}, ...}"""
    info = evento or {}
    out = {}
    for clave, w in (info.get("unifiedWindows") or {}).items():
        if isinstance(w, dict) and isinstance(w.get("utilization"), (int, float)):
            out[clave] = {"uso": float(w["utilization"]), "reinicio": w.get("resetsAt"), "estado": w.get("status")}
    # versiones de Claude Code que solo mandan la ventana que más aprieta
    tipo = info.get("rateLimitType")
    if tipo and tipo not in out and isinstance(info.get("utilization"), (int, float)):
        out[tipo] = {"uso": float(info["utilization"]), "reinicio": info.get("resetsAt"), "estado": info.get("status")}
    return out


def limites_de(evento: dict) -> dict | None:
    v = _ventanas(evento)
    if not v:
        return None
    return {"ventanas": v, "fecha": time.time(), "estado": (evento or {}).get("status"),
            "usando_extra": bool((evento or {}).get("isUsingOverage"))}


def _vigente(ventana: dict | None) -> dict | None:
    """Si la ventana ya se reinició desde que se midió, el uso vuelve a 0."""
    if not ventana:
        return None
    if ventana.get("reinicio") and ventana["reinicio"] <= time.time():
        return {**ventana, "uso": 0.0, "reiniciada": True}
    return ventana


class Consumo:
    def __init__(self, carpeta_datos: str):
        self.ruta = os.path.join(carpeta_datos, "consumo_claude.json")
        self.cerrojo = threading.Lock()
        self.datos = {"limites": None, "historial": []}
        try:
            with open(self.ruta) as f:
                d = json.load(f)
            if isinstance(d, dict):
                self.datos.update(d)
        except (OSError, ValueError):
            pass

    def _guardar(self):
        tmp = self.ruta + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.datos, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.ruta)

    # ------------------------------------------------------------------ estado del plan
    def limites(self) -> dict:
        """Último estado conocido de cada ventana (con el uso a 0 si ya se reinició)."""
        l = self.datos.get("limites") or {}
        return {"ventanas": {k: _vigente(w) for k, w in (l.get("ventanas") or {}).items()},
                "fecha": l.get("fecha"), "usando_extra": l.get("usando_extra", False)}

    # ------------------------------------------------------------------ registro de una ejecución
    def registrar(self, plan: dict, tipo: str, uso: dict) -> dict:
        """Apunta una llamada a Claude (tipo: 'analisis' | 'reintento') en el plan y en el historial."""
        inicio, fin = uso.get("limites_inicio"), uso.get("limites_fin")
        with self.cerrojo:
            previo = self.datos.get("limites")
            # El primer rate_limit_event llega tras la primera respuesta, que ya gastó. Si hay un estado
            # reciente de la misma ventana, es mejor «antes» que ese primer evento.
            base = inicio
            if previo and inicio and time.time() - (previo.get("fecha") or 0) < FRESCO_S:
                base = {"ventanas": {k: (previo["ventanas"].get(k)
                                         if (previo["ventanas"].get(k) or {}).get("reinicio") == w.get("reinicio")
                                         and previo["ventanas"][k]["uso"] <= w["uso"] else w)
                                     for k, w in inicio["ventanas"].items()}}
            deltas = {}
            if fin:
                for k, w in fin["ventanas"].items():
                    a = (base or {}).get("ventanas", {}).get(k)
                    if a is None:
                        continue
                    # si la ventana se reinició a mitad, todo lo que marca ahora es de esta ejecución
                    deltas[k] = round(max(0.0, w["uso"] - (a["uso"] if a.get("reinicio") == w.get("reinicio") else 0.0)), 4)
                self.datos["limites"] = fin
            entrada = {
                "fecha": ahora_iso(), "plan": plan.get("id"), "tipo": tipo,
                "componente": f'{plan["componente"]["nombre"]} {plan["componente"]["version"]}',
                "app": plan["componente"].get("app") or "",
                "modelo": uso.get("modelo"), "esfuerzo": uso.get("esfuerzo"), "ok": uso.get("ok", False),
                "coste_usd": uso.get("coste_usd"), "tokens": uso.get("tokens") or {},
                "duracion_s": uso.get("duracion_s"), "turnos": uso.get("turnos"),
                "busquedas_web": uso.get("busquedas_web"), "tamano_peticion": uso.get("tamano_peticion"),
                "antes": {k: w["uso"] for k, w in ((base or {}).get("ventanas") or {}).items()},
                "despues": {k: w["uso"] for k, w in ((fin or {}).get("ventanas") or {}).items()},
                "reinicio": {k: w.get("reinicio") for k, w in ((fin or {}).get("ventanas") or {}).items()},
                "delta": deltas,
            }
            self.datos["historial"] = (self.datos.get("historial") or [])[-(MAX_HISTORIAL - 1):] + [entrada]
            self._guardar()
        cl = plan.setdefault("claude", {})
        cl.setdefault("llamadas", []).append(entrada)
        cl["total"] = total(cl["llamadas"])
        return entrada

    # ------------------------------------------------------------------ estimación previa
    def _ratio_plan(self, ventana: str) -> float | None:
        """Puntos de ventana por dólar de coste API equivalente, medidos en ejecuciones anteriores."""
        hs = [h for h in self.datos.get("historial") or []
              if h.get("coste_usd") and ventana in (h.get("delta") or {})][-30:]
        coste = sum(h["coste_usd"] for h in hs)
        if len(hs) < 1 or coste <= 0:
            return None
        return sum(h["delta"][ventana] for h in hs) / coste

    def estimar(self, modelo: str, esfuerzo: str, tamano_peticion: int, web: bool = True) -> dict:
        """Coste esperado de UNA llamada (sin el posible reintento) y su efecto en las ventanas del plan."""
        previas = [h for h in self.datos.get("historial") or []
                   if h.get("modelo") == modelo and h.get("esfuerzo") == esfuerzo and h.get("coste_usd")][-10:]
        if previas:
            # escala por el tamaño de la petición: el contexto es lo que más varía entre componentes
            factores = [h["coste_usd"] / max(1, h.get("tamano_peticion") or tamano_peticion) for h in previas]
            coste = statistics.median(factores) * max(1, tamano_peticion)
            duracion = statistics.median(h.get("duracion_s") or 0 for h in previas)
            fuente = f"media de {len(previas)} ejecución(es) anteriores con este modelo y razonamiento"
        else:
            p_in, p_out = next(((m[2], m[3]) for m in MODELOS if m[0] == modelo), (4.0, 20.0))
            entrada = BASE_ENTRADA + tamano_peticion / 3.5 + (ENTRADA_WEB if web else 0)
            salida = SALIDA_POR_ESFUERZO.get(esfuerzo, 15_000)
            # la entrada se escribe en caché (×1,25) y se relee barata en los turnos siguientes
            coste = (entrada * 1.25 * p_in + salida * p_out) / 1e6
            duracion = None
            fuente = "cálculo aproximado (aún no hay ejecuciones con este modelo y razonamiento)"
        lim = self.limites()["ventanas"]
        plan = {}
        for k in VENTANAS:
            r = self._ratio_plan(k)
            actual = (lim.get(k) or {}).get("uso")
            plan[k] = {"delta": round(coste * r, 4) if r is not None else None, "actual": actual,
                       "reinicio": (lim.get(k) or {}).get("reinicio")}
        return {"modelo": modelo, "esfuerzo": esfuerzo, "coste_usd": round(coste, 4), "duracion_s": duracion,
                "fuente": fuente, "plan": plan}


def total(llamadas: list[dict]) -> dict:
    t = {"coste_usd": 0.0, "duracion_s": 0.0, "tokens": {}, "delta": {}}
    for c in llamadas:
        t["coste_usd"] += c.get("coste_usd") or 0
        t["duracion_s"] += c.get("duracion_s") or 0
        for k, v in (c.get("tokens") or {}).items():
            t["tokens"][k] = t["tokens"].get(k, 0) + (v or 0)
        for k, v in (c.get("delta") or {}).items():
            t["delta"][k] = round(t["delta"].get(k, 0) + v, 4)
    t["coste_usd"] = round(t["coste_usd"], 4)
    return t


# ------------------------------------------------------------------ formato (panel y Telegram)
def pct(x) -> str:
    if x is None:
        return "—"
    v = x * 100
    return "<1 %" if 0 < v < 1 else f"{v:.0f} %"


def usd(x) -> str:
    if x is None:
        return "—"
    return f"{x:.3f} $" if x < 1 else f"{x:.2f} $"


def hora_reinicio(epoch) -> str:
    if not epoch:
        return ""
    d = dt.datetime.fromtimestamp(epoch)
    hoy = dt.date.today()
    if d.date() == hoy:
        return f"hoy a las {d:%H:%M}"
    if (d.date() - hoy).days == 1:
        return f"mañana a las {d:%H:%M}"
    dias = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]
    return f"el {dias[d.weekday()]} {d.day} a las {d:%H:%M}"


def texto_estimacion(est: dict, n: int = 1) -> str:
    """Una línea legible: lo que se espera gastar del plan y su equivalente en API."""
    partes = []
    for k, nombre in VENTANAS.items():
        p = est["plan"][k]
        if p["delta"] is None:
            continue
        actual = f" (ahora {pct(p['actual'])})" if p["actual"] is not None else ""
        partes.append(f"≈ +{pct(p['delta'] * n)} de la ventana {nombre}{actual}")
    plan = "; ".join(partes) if partes else "el % de tu plan se sabrá tras la primera corrección"
    return (f"{NOMBRE_MODELO.get(est['modelo'], est['modelo'])} · razonamiento "
            f"{NOMBRE_ESFUERZO.get(est['esfuerzo'], est['esfuerzo']).lower()}: {plan}. "
            f"Por API costaría ≈ {usd(est['coste_usd'] * n)}{' en total' if n > 1 else ''} "
            "(hasta el doble si la verificación falla y Claude reintenta).")
