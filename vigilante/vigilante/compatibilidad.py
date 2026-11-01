"""Revisión automática de compatibilidad, antes y después de que Claude proponga.

No sustituye al análisis de Claude: le da datos objetivos para que no tenga que adivinar.
  - tipo de salto (parche / menor / mayor) y si cambia de rama en un runtime;
  - opciones de versión: mínima segura, última de la misma versión mayor, última estable;
  - requisitos de la versión de destino según el registro (Packagist: require.php,
    npm: engines.node, peerDependencies, deprecated) comparados con lo desplegado;
  - si la rama de destino de un runtime tiene soporte (endoflife.date).
"""
from __future__ import annotations

import logging
import re
import urllib.parse

from .catalogo import RUNTIMES
from .http import Cache, peticion
from .versiones import comparar, partes

log = logging.getLogger("vigilante.compat")

GUIAS_MIGRACION = {
    "php": "https://www.php.net/manual/es/migration{mayor}{menor}.php",
    "nginx": "https://nginx.org/en/CHANGES-{mayor}.{menor}",
    "tomcat": "https://tomcat.apache.org/migration-{mayor}.html",
    "node": "https://nodejs.org/en/blog/release/v{mayor}.0.0",
    "java": "https://docs.oracle.com/en/java/javase/{mayor}/migrate/",
}


# ------------------------------------------------------------------ restricciones de versión
def cumple(version: str, restriccion: str) -> bool | None:
    """Evalúa restricciones estilo Composer/npm: '^7.4 || ^8.0', '>=14', '~2.1', '8.*', '>=1.2 <2'.
    Devuelve None si no se entiende (mejor 'no sé' que un falso 'compatible')."""
    restriccion = re.sub(r"(>=|<=|>|<|==|=|\^|~)\s+", r"\1", restriccion.strip())
    if re.search(r"\d\s+-\s+\d", restriccion):   # rangos con guion de npm: no los evaluamos
        return None
    try:
        for alternativa in re.split(r"\s*\|\|?\s*", restriccion):
            if all(_cumple_simple(version, r) for r in re.split(r"[\s,]+", alternativa.strip()) if r):
                return True
        return False
    except ValueError:
        return None


def _num(v):
    return [p[0] for p in partes(v) if p[0] >= 0] or [0]


def _cumple_simple(v, r):
    r = r.lstrip("v")
    if r in ("*", "x", ""):
        return True
    m = re.fullmatch(r"(\^|~|>=|<=|>|<|=|==|!=)?v?([\d.x*]+)(?:-[\w.]+)?(?:@\w+)?", r)
    if not m:
        raise ValueError(r)
    op, base = m.group(1) or "", m.group(2)
    if "x" in base or "*" in base:  # 8.* / 8.x
        fijo = [x for x in base.split(".") if x not in ("x", "*")]
        return _num(v)[:len(fijo)] == [int(x) for x in fijo]
    if op in ("", "=", "=="):
        return comparar(v, base) == 0
    if op == "!=":
        return comparar(v, base) != 0
    if op in (">=", ">", "<=", "<"):
        c = comparar(v, base)
        return {">=": c >= 0, ">": c > 0, "<=": c <= 0, "<": c < 0}[op]
    b = _num(base)
    if op == "^":
        # ^1.2.3 -> <2.0.0 ; ^0.2.3 -> <0.3.0 ; ^0.0.3 -> <0.0.4
        i = next((k for k, x in enumerate(b) if x != 0), len(b) - 1)
        tope = b[:i] + [b[i] + 1]
    else:  # ~1.2.3 -> <1.3.0 ; ~1.2 (Composer) -> <2.0 ; ~1 -> <2.0
        tope = [b[0], b[1] + 1] if len(b) >= 3 else [b[0] + 1]
    return comparar(v, base) >= 0 and comparar(v, ".".join(map(str, tope))) < 0


def tipo_salto(actual: str, objetivo: str) -> str:
    a, o = _num(actual) + [0, 0], _num(objetivo) + [0, 0]
    if o[0] != a[0]:
        return "mayor"
    if o[1] != a[1]:
        return "menor"
    return "parche"


def _estable(v: str) -> bool:
    return not re.search(r"(alpha|beta|rc|dev|pre|next|canary)", v, re.I)


# ------------------------------------------------------------------ registros
class Registros:
    def __init__(self, cache: Cache):
        self.cache = cache

    def versiones_packagist(self, nombre) -> list[dict]:
        clave = f"packagist:{nombre}"
        d = self.cache.get(clave, 12 * 3600)
        if d is None:
            r = peticion(f"https://repo.packagist.org/p2/{nombre}.json")
            d = self.cache.set(clave, _expandir_minificado(r["packages"].get(nombre, [])))
        return d

    def versiones_npm(self, nombre) -> list[str]:
        clave = f"npm:lista:{nombre}"
        d = self.cache.get(clave, 12 * 3600)
        if d is None:
            r = peticion(f"https://registry.npmjs.org/{urllib.parse.quote(nombre, safe='@')}",
                         cabeceras={"Accept": "application/vnd.npm.install-v1+json"}, timeout=60)
            d = self.cache.set(clave, list(r.get("versions", {}).keys()))
        return d

    def manifiesto_npm(self, nombre, version) -> dict:
        clave = f"npm:{nombre}@{version}"
        d = self.cache.get(clave, 7 * 24 * 3600)
        if d is None:
            r = peticion(f"https://registry.npmjs.org/{urllib.parse.quote(nombre, safe='@')}/{version}")
            d = self.cache.set(clave, {k: r.get(k) for k in ("engines", "deprecated", "peerDependencies", "dependencies")})
        return d


def _expandir_minificado(lista):
    """Packagist p2 'composer/2.0': cada versión solo trae lo que cambia respecto a la anterior."""
    out, previo = [], {}
    for item in lista:
        actual = dict(previo)
        for k, v in item.items():
            if v == "__unset":
                actual.pop(k, None)
            else:
                actual[k] = v
        out.append({k: actual.get(k) for k in ("version", "require", "abandoned")})
        previo = actual
    return out


# ------------------------------------------------------------------ informe
def revisar(cache: Cache, comp: dict, objetivo: str, runtimes: dict[str, str]) -> dict:
    """comp: dict del componente; objetivo: versión propuesta; runtimes: {'php': '8.1.2', 'node': ...}"""
    inf = {"version_actual": comp["version"], "version_objetivo": objetivo, "avisos": [], "opciones": {},
           "datos": {}}
    if not objetivo or not objetivo[:1].isdigit():
        inf["avisos"].append("No hay una versión de destino concreta que revisar.")
        return inf
    inf["salto"] = tipo_salto(comp["version"], objetivo)
    if inf["salto"] == "mayor":
        inf["avisos"].append(f"Salto de versión MAYOR ({comp['version']} → {objetivo}): casi seguro hay "
                             "cambios incompatibles; revisar la guía de actualización.")
    eco, nombre = comp.get("ecosistema"), comp["nombre"]
    reg = Registros(cache)
    try:
        if eco == "Packagist":
            _packagist(reg, nombre, comp["version"], objetivo, runtimes, inf)
        elif eco == "npm":
            _npm(reg, nombre, comp["version"], objetivo, runtimes, inf)
        elif comp.get("tipo") == "runtime":
            _runtime(cache, nombre, comp["version"], objetivo, inf)
    except Exception as e:  # noqa: BLE001 - la revisión automática es una ayuda, no un requisito
        log.warning("Revisión de compatibilidad de %s incompleta: %s", nombre, e)
        inf["avisos"].append(f"No se pudo consultar el registro del paquete ({e}).")
    return inf


def _opciones(disponibles, actual, minima):
    estables = sorted({v for v in disponibles if _estable(v)}, key=partes)
    seguras = [v for v in estables if comparar(v, minima) >= 0]
    misma_mayor = [v for v in seguras if _num(v)[0] == _num(actual)[0]]
    return {"minima_segura": seguras[0] if seguras else None,
            "ultima_misma_mayor": misma_mayor[-1] if misma_mayor else None,
            "ultima": estables[-1] if estables else None}


def _packagist(reg, nombre, actual, objetivo, runtimes, inf):
    vers = [v for v in reg.versiones_packagist(nombre) if v.get("version")]
    norm = {v["version"].lstrip("v"): v for v in vers}
    inf["opciones"] = _opciones(norm.keys(), actual, objetivo)
    destino = norm.get(objetivo.lstrip("v"))
    if not destino:
        inf["avisos"].append(f"La versión {objetivo} no existe en Packagist.")
        return
    req = destino.get("require") or {}
    inf["datos"]["require"] = req
    if "php" in req and runtimes.get("php"):
        ok = cumple(runtimes["php"], req["php"])
        if ok is False:
            inf["avisos"].append(f"INCOMPATIBLE: {nombre} {objetivo} exige PHP {req['php']} y hay PHP {runtimes['php']}.")
        elif ok:
            inf["datos"]["php_compatible"] = True
    if destino.get("abandoned"):
        inf["avisos"].append(f"El paquete está marcado como abandonado (sustituto: {destino['abandoned']}).")
    origen = norm.get(actual.lstrip("v"))
    if origen:
        nuevos = sorted(set(req) - set(origen.get("require") or {}))
        if nuevos:
            inf["avisos"].append("La versión de destino añade dependencias: " + ", ".join(nuevos))


def _npm(reg, nombre, actual, objetivo, runtimes, inf):
    inf["opciones"] = _opciones(reg.versiones_npm(nombre), actual, objetivo)
    m = reg.manifiesto_npm(nombre, objetivo)
    inf["datos"].update({k: v for k, v in m.items() if v})
    if m.get("deprecated"):
        inf["avisos"].append(f"DEPRECADA en npm: {m['deprecated']}")
    nodo = (m.get("engines") or {}).get("node")
    if nodo and runtimes.get("node"):
        if cumple(runtimes["node"], nodo) is False:
            inf["avisos"].append(f"INCOMPATIBLE: {nombre} {objetivo} exige Node {nodo} y hay Node {runtimes['node']}.")
    if m.get("peerDependencies"):
        inf["avisos"].append("Tiene peerDependencies que comprobar: " + ", ".join(m["peerDependencies"]))


def _runtime(cache, nombre, actual, objetivo, inf):
    from .fuentes import EOL_URL
    slug = RUNTIMES.get(nombre, {}).get("eol")
    if inf.get("salto") in ("menor", "mayor") and nombre in GUIAS_MIGRACION:
        n = _num(objetivo) + [0]
        inf["avisos"].append(f"Cambio de rama de {nombre} ({actual} → {objetivo}): revisar incompatibilidades y "
                             f"deprecaciones en {GUIAS_MIGRACION[nombre].format(mayor=n[0], menor=n[1])}")
    if slug:
        ciclos = cache.get(f"eol:{slug}", 24 * 3600) or cache.set(f"eol:{slug}", peticion(f"{EOL_URL}/{slug}.json"))
        rama = next((c for c in sorted(ciclos, key=lambda c: -len(str(c["cycle"])))
                     if objetivo == str(c["cycle"]) or objetivo.startswith(str(c["cycle"]) + ".")), None)
        if rama:
            inf["datos"]["rama_destino"] = {"rama": rama["cycle"], "fin_soporte": rama.get("eol"),
                                            "ultima": rama.get("latest")}
            eol = rama.get("eol")
            import datetime as dt
            if eol is True or (isinstance(eol, str) and eol <= dt.date.today().isoformat()):
                inf["avisos"].append(f"La rama de destino {rama['cycle']} tampoco tiene soporte: elegir una rama viva.")
            inf["opciones"] = {"ultima_misma_rama": rama.get("latest")}


def no_cubiertos(hallazgos: list[dict], objetivo: str) -> list[str]:
    """IDs que la versión de destino NO corrige, según las versiones corregidas conocidas.
    Si hay correcciones en la misma rama (mayor.menor) que el destino, se exige llegar a la de esa
    rama; si no, a la mayor de todas (criterio prudente)."""
    if not objetivo or not objetivo[:1].isdigit():
        return []
    rama = _num(objetivo)[:2]
    out = []
    for h in hallazgos:
        arreglos = [f for f in h.get("corregido_en") or [] if f[:1].isdigit()]
        if not arreglos:
            continue
        misma = [f for f in arreglos if _num(f)[:2] == rama]
        necesaria = min(misma, key=partes) if misma else max(arreglos, key=partes)
        if comparar(objetivo, necesaria) < 0:
            out.append(f"{h['id']} (corregido en {necesaria})")
    return out
