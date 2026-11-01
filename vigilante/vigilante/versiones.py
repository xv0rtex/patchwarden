"""Comparación de versiones tolerante (suficiente para rangos NVD) y cálculo CVSS v3."""
from __future__ import annotations

import math
import re


def partes(v: str):
    v = v.lower().lstrip("v")
    trozos = re.split(r"[.\-+_]", v)
    out = []
    for t in trozos:
        m = re.match(r"(\d+)(.*)", t)
        if m:
            out.append((int(m.group(1)), m.group(2) or "~"))  # '~' ordena después de 'rc', 'beta'…
        elif t:
            out.append((-1, t))
    return out


def comparar(a: str, b: str) -> int:
    pa, pb = partes(a), partes(b)
    n = max(len(pa), len(pb))
    pa += [(0, "~")] * (n - len(pa))
    pb += [(0, "~")] * (n - len(pb))
    return (pa > pb) - (pa < pb)


def en_rango(v, desde_inc=None, desde_exc=None, hasta_inc=None, hasta_exc=None) -> bool:
    if desde_inc and comparar(v, desde_inc) < 0:
        return False
    if desde_exc and comparar(v, desde_exc) <= 0:
        return False
    if hasta_inc and comparar(v, hasta_inc) > 0:
        return False
    if hasta_exc and comparar(v, hasta_exc) >= 0:
        return False
    return True


# --- CVSS v3.x (para vectores que vienen de OSV sin puntuación) -------------------
_P = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0}, "A": {"H": 0.56, "L": 0.22, "N": 0},
}


def _redondear(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3(vector: str) -> float | None:
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        cambia = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if cambia else 0.62, "H": 0.5 if cambia else 0.27}[m["PR"]]
        iss = 1 - (1 - _P["C"][m["C"]]) * (1 - _P["I"][m["I"]]) * (1 - _P["A"][m["A"]])
        imp = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if cambia else 6.42 * iss
        expl = 8.22 * _P["AV"][m["AV"]] * _P["AC"][m["AC"]] * pr * _P["UI"][m["UI"]]
        if imp <= 0:
            return 0.0
        return _redondear(min(1.08 * (imp + expl), 10)) if cambia else _redondear(min(imp + expl, 10))
    except (KeyError, ValueError, IndexError):
        return None
