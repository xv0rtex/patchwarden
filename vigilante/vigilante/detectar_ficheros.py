"""Detección de versiones leyendo el código del proyecto montado en solo lectura.

Ficheros que se entienden (los «lock» dan la versión EXACTA instalada):
  composer.lock      -> paquetes PHP (Packagist)
  package-lock.json  -> paquetes npm (v1, v2 y v3)
  yarn.lock          -> paquetes npm (yarn v1)
  pom.xml            -> dependencias Maven con versión fija (resuelve ${propiedades})
  requirements.txt   -> paquetes PyPI fijados con ==
  Gemfile.lock       -> RubyGems
  go.mod             -> módulos Go
  Dockerfile         -> runtimes de las líneas FROM (php:8.2-fpm, eclipse-temurin:17…)
  wp-includes/version.php -> versión de WordPress
"""
from __future__ import annotations

import json
import logging
import os
import re
import xml.etree.ElementTree as ET

from .catalogo import runtime_por_imagen
from .modelo import Componente

log = logging.getLogger("vigilante.ficheros")
SALTAR = {"node_modules", "vendor", ".git", "target", "build", "dist", ".venv", "venv", "__pycache__"}
MAX_PROFUNDIDAD = 4


def detectar(rutas: list[str], apps: dict[str, str] | None = None) -> list[Componente]:
    comps: list[Componente] = []
    for raiz in rutas:
        if not os.path.isdir(raiz):
            log.info("Ruta de proyecto %s no existe, se ignora", raiz)
            continue
        inicio = len(comps)
        for carpeta, subdirs, ficheros in os.walk(raiz):
            prof = carpeta[len(raiz):].count(os.sep)
            subdirs[:] = [d for d in subdirs if d not in SALTAR and prof < MAX_PROFUNDIDAD]
            nombres = set(ficheros)
            for f in ficheros:
                ruta = os.path.join(carpeta, f)
                try:
                    comps += _analizar(ruta, f, nombres)
                except Exception as e:  # noqa: BLE001 - un fichero raro no debe parar el ciclo
                    log.warning("No se pudo analizar %s: %s", ruta, e)
            if carpeta.endswith("wp-includes") and "version.php" in nombres:
                comps += _wordpress(os.path.join(carpeta, "version.php"))
        app = (apps or {}).get(raiz) or (apps or {}).get(raiz.rstrip("/")) or os.path.basename(raiz.rstrip("/"))
        for c in comps[inicio:]:
            c.app = app
    return comps


def _analizar(ruta, f, hermanos) -> list[Componente]:
    if f == "composer.lock":
        return _composer(ruta)
    if f == "package-lock.json":
        return _npm_lock(ruta)
    if f == "yarn.lock" and "package-lock.json" not in hermanos:
        return _yarn(ruta)
    if f == "pom.xml":
        return _pom(ruta)
    if re.fullmatch(r"requirements.*\.txt", f):
        return _requirements(ruta)
    if f == "Gemfile.lock":
        return _gemfile(ruta)
    if f == "go.mod":
        return _gomod(ruta)
    if f == "Dockerfile" or f.startswith("Dockerfile.") or f.endswith(".Dockerfile"):
        return _dockerfile(ruta)
    return []


def _leer(ruta):
    with open(ruta, encoding="utf-8", errors="replace") as f:
        return f.read()


def _c(nombre, version, eco, ruta):
    return Componente(nombre, version, "paquete", ecosistema=eco, origen="fichero", detalle=ruta)


def _composer(ruta):
    d = json.loads(_leer(ruta))
    out = []
    for p in d.get("packages", []) + d.get("packages-dev", []):
        v = p.get("version", "").lstrip("v")
        if p.get("name") and re.match(r"\d", v):
            out.append(_c(p["name"], v, "Packagist", ruta))
    return out


def _npm_lock(ruta):
    d = json.loads(_leer(ruta))
    out, vistos = [], set()
    if "packages" in d:  # lockfile v2/v3
        for clave, p in d["packages"].items():
            if not clave or "version" not in p or p.get("link"):
                continue
            nombre = p.get("name") or clave.split("node_modules/")[-1]
            if (nombre, p["version"]) not in vistos:
                vistos.add((nombre, p["version"]))
                out.append(_c(nombre, p["version"], "npm", ruta))
    else:  # v1
        def recorrer(deps):
            for nombre, p in (deps or {}).items():
                if (nombre, p.get("version")) not in vistos and p.get("version"):
                    vistos.add((nombre, p["version"]))
                    out.append(_c(nombre, p["version"], "npm", ruta))
                recorrer(p.get("dependencies"))
        recorrer(d.get("dependencies"))
    return out


def _yarn(ruta):
    out, actual = [], None
    for linea in _leer(ruta).splitlines(keepends=True):
        if linea and not linea[0].isspace() and linea.rstrip().endswith(":"):
            primero = linea.strip().rstrip(":").split(",")[0].strip().strip('"')
            actual = primero.rsplit("@", 1)[0] if primero.count("@") >= 1 else primero
        m = re.match(r'\s+version "?([^"\s]+)"?', linea)
        if m and actual:
            out.append(_c(actual, m.group(1), "npm", ruta))
            actual = None
    return out


def _pom(ruta):
    arbol = ET.parse(ruta)
    raiz = arbol.getroot()
    ns = {"m": raiz.tag.split("}")[0].strip("{")} if raiz.tag.startswith("{") else {}
    q = (lambda t: f"m:{t}") if ns else (lambda t: t)
    props = {}
    pr = raiz.find(q("properties"), ns)
    if pr is not None:
        for e in pr:
            props[e.tag.split("}")[-1]] = (e.text or "").strip()
    v_proy = raiz.findtext(q("version"), default="", namespaces=ns)
    props["project.version"] = v_proy
    out = []
    padre = raiz.find(q("parent"), ns)
    if padre is not None:  # p. ej. spring-boot-starter-parent fija medio ecosistema
        g, a, v = (padre.findtext(q(x), default="", namespaces=ns) for x in ("groupId", "artifactId", "version"))
        if g and a and re.match(r"\d", v):
            out.append(_c(f"{g}:{a}", v, "Maven", ruta))
    for dep in raiz.iter(f"{{{ns['m']}}}dependency" if ns else "dependency"):
        g, a, v = (dep.findtext(q(x), default="", namespaces=ns).strip() for x in ("groupId", "artifactId", "version"))
        v = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)
        if g and a and re.match(r"\d", v) and "${" not in v:
            out.append(_c(f"{g}:{a}", v, "Maven", ruta))
    return out


def _requirements(ruta):
    out = []
    for linea in _leer(ruta).splitlines(keepends=True):
        m = re.match(r"\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;#]*)", linea)
        if m:
            out.append(_c(m.group(1).lower(), m.group(2), "PyPI", ruta))
    return out


def _gemfile(ruta):
    out, en_specs = [], False
    for linea in _leer(ruta).splitlines(keepends=True):
        if linea.strip() == "specs:":
            en_specs = True
            continue
        if en_specs:
            m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([0-9][^)\s-]*)", linea)
            if m:
                out.append(_c(m.group(1), m.group(2), "RubyGems", ruta))
            elif linea.strip() == "" or not linea.startswith(" "):
                en_specs = False
    return out


def _gomod(ruta):
    out = []
    for linea in _leer(ruta).splitlines(keepends=True):
        m = re.match(r"\s*(?:require\s+)?([\w.\-]+\.[\w.\-/]+)\s+v([0-9][^\s]*)", linea)
        if m:
            out.append(_c(m.group(1), m.group(2), "Go", ruta))
    return out


def _dockerfile(ruta):
    out = []
    args = {}
    for linea in _leer(ruta).splitlines(keepends=True):
        m = re.match(r"\s*ARG\s+(\w+)=(\S+)", linea, re.I)
        if m:
            args[m.group(1)] = m.group(2)
        m = re.match(r"\s*FROM\s+(?:--\S+\s+)*(\S+)", linea, re.I)
        if m:
            img = re.sub(r"\$\{?(\w+)\}?", lambda x: args.get(x.group(1), ""), m.group(1))
            rt, v = runtime_por_imagen(img)
            if rt and v:
                out.append(Componente(rt, v, "runtime", origen="fichero", detalle=f"{ruta} (FROM {img})"))
    return out


def _wordpress(ruta):
    m = re.search(r"\$wp_version\s*=\s*'([^']+)'", _leer(ruta))
    return [Componente("wordpress", m.group(1), "runtime", origen="fichero", detalle=ruta)] if m else []
