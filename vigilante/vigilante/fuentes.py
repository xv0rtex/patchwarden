"""Fuentes de vulnerabilidades.

  NVD (NIST)       -> CVE de runtimes/servidores, buscando por CPE + versión.
  OSV.dev (Google) -> vulnerabilidades de paquetes (Packagist, npm, Maven, PyPI…).
                      Agrega GitHub Advisories, FriendsOfPHP, PyPA, RustSec, Go…
  CISA KEV         -> lista de CVE que se están explotando de verdad.
  EPSS (FIRST)     -> probabilidad de que un CVE se explote en los próximos 30 días.
  endoflife.date   -> si la rama de la versión ya no recibe parches de seguridad.
"""
from __future__ import annotations

import datetime as dt
import logging
import time
import urllib.parse

from .catalogo import RUNTIMES
from .http import Cache, peticion
from .modelo import Componente, Hallazgo, severidad_por_cvss
from .versiones import comparar, cvss3, en_rango

log = logging.getLogger("vigilante.fuentes")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EOL_URL = "https://endoflife.date/api"


# ----------------------------------------------------------------------------- NVD
class NVD:
    def __init__(self, cache: Cache, api_key: str = ""):
        self.cache, self.api_key = cache, api_key
        self.pausa = 0.7 if api_key else 6.5   # límite público: 5 peticiones / 30 s
        self._ultima = 0.0

    def _get(self, params):
        espera = self._ultima + self.pausa - time.time()
        if espera > 0:
            time.sleep(espera)
        self._ultima = time.time()
        cab = {"apiKey": self.api_key} if self.api_key else {}
        return peticion(NVD_URL + "?" + urllib.parse.urlencode(params), cabeceras=cab, timeout=60)

    def buscar(self, comp: Componente) -> list[Hallazgo]:
        info = RUNTIMES.get(comp.nombre)
        if not info:
            return []
        hallazgos: dict[str, Hallazgo] = {}
        for prefijo in info["cpe"]:
            clave = f"nvd:{prefijo}:{comp.version}"
            datos = self.cache.get(clave, 6 * 3600)
            if datos is None:
                datos, inicio = [], 0
                while True:
                    r = self._get({"virtualMatchString": f"cpe:2.3:a:{prefijo}:{comp.version}",
                                   "resultsPerPage": 2000, "startIndex": inicio})
                    datos += r.get("vulnerabilities", [])
                    inicio += r.get("resultsPerPage", 0)
                    if inicio >= r.get("totalResults", 0) or not r.get("resultsPerPage"):
                        break
                self.cache.set(clave, datos)
            for v in datos:
                h = self._a_hallazgo(v["cve"], comp, prefijo)
                if h:
                    hallazgos[h.id] = h
        return list(hallazgos.values())

    def _a_hallazgo(self, cve: dict, comp: Componente, prefijo: str) -> Hallazgo | None:
        if cve.get("vulnStatus") == "Rejected":
            return None
        # NVD a veces devuelve CVE donde el producto aparece solo como "plataforma":
        # comprobamos nosotros que haya una regla vulnerable=true que cubra NUESTRA versión.
        afecta, arreglos = False, set()
        for conf in cve.get("configurations", []):
            for nodo in conf.get("nodes", []):
                for m in nodo.get("cpeMatch", []):
                    crit = m.get("criteria", "")
                    if not m.get("vulnerable") or not crit.startswith(f"cpe:2.3:a:{prefijo}:"):
                        continue
                    vexacta = crit.split(":")[5]
                    if vexacta not in ("*", "-"):
                        ok = comparar(vexacta, comp.version) == 0
                    else:
                        ok = en_rango(comp.version, m.get("versionStartIncluding"), m.get("versionStartExcluding"),
                                      m.get("versionEndIncluding"), m.get("versionEndExcluding"))
                    if ok:
                        afecta = True
                        if m.get("versionEndExcluding"):
                            arreglos.add(m["versionEndExcluding"])
        if not afecta:
            return None
        score, sev = None, None
        met = cve.get("metrics", {})
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if met.get(k):
                prim = next((x for x in met[k] if x.get("type") == "Primary"), met[k][0])
                score = prim["cvssData"].get("baseScore")
                break
        sev = severidad_por_cvss(score)
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "es"), None) or \
            next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        return Hallazgo(
            id=cve["id"], componente=comp.clave, nombre=comp.nombre, version=comp.version,
            resumen=desc[:600], cvss=score, severidad=sev,
            kev=bool(cve.get("cisaExploitAdd")),
            corregido_en=sorted((a for a in arreglos if comparar(a, comp.version) > 0), key=_clave_version)[:3],
            referencias=[r["url"] for r in cve.get("references", [])][:5],
            fuente="NVD", publicado=cve.get("published", "")[:10],
        )


# ----------------------------------------------------------------------------- OSV
LABEL_A_SCORE = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}


class OSV:
    def __init__(self, cache: Cache):
        self.cache = cache

    def buscar(self, comps: list[Componente]) -> list[Hallazgo]:
        paquetes = [c for c in comps if c.tipo == "paquete" and c.ecosistema]
        out = []
        for i in range(0, len(paquetes), 500):
            lote = paquetes[i:i + 500]
            r = peticion(f"{OSV_URL}/querybatch", {"queries": [
                {"package": {"name": c.nombre, "ecosystem": c.ecosistema}, "version": c.version} for c in lote]})
            for comp, res in zip(lote, r.get("results", [])):
                for v in res.get("vulns", []) or []:
                    det = self._detalle(v["id"], v.get("modified", ""))
                    if det and not det.get("withdrawn"):
                        out.append(self._a_hallazgo(det, comp))
        return out

    def _detalle(self, id_, modificado):
        clave = f"osv:{id_}:{modificado}"
        d = self.cache.get(clave, 7 * 24 * 3600)
        if d is None:
            try:
                d = self.cache.set(clave, peticion(f"{OSV_URL}/vulns/{urllib.parse.quote(id_)}"))
            except Exception as e:  # noqa: BLE001
                log.warning("OSV %s: %s", id_, e)
                return None
        return d

    def _a_hallazgo(self, d: dict, comp: Componente) -> Hallazgo:
        score = None
        for s in d.get("severity", []):
            if s.get("type") == "CVSS_V3":
                score = cvss3(s["score"])
        etiqueta = (d.get("database_specific") or {}).get("severity", "").upper()
        if score is None and etiqueta in LABEL_A_SCORE:
            score = LABEL_A_SCORE[etiqueta]
        arreglos = set()
        for af in d.get("affected", []):
            if (af.get("package") or {}).get("name", "").lower() != comp.nombre.lower():
                continue
            for rango in af.get("ranges", []):
                for ev in rango.get("events", []):
                    if "fixed" in ev:
                        arreglos.add(ev["fixed"])
        # De los arreglos, interesan los que son mayores que nuestra versión
        arreglos = sorted((a for a in arreglos if comparar(a, comp.version) > 0), key=_clave_version)
        alias = [a for a in d.get("aliases", []) if a.startswith("CVE-")]
        return Hallazgo(
            id=alias[0] if alias else d["id"], componente=comp.clave, nombre=comp.nombre, version=comp.version,
            resumen=(d.get("summary") or d.get("details") or "")[:600], cvss=score,
            severidad=severidad_por_cvss(score), corregido_en=arreglos[:3],
            referencias=[r["url"] for r in d.get("references", [])][:5],
            alias=[d["id"]] + alias[1:], fuente="OSV", publicado=d.get("published", "")[:10],
        )


def _clave_version(v):
    from .versiones import partes
    return partes(v)


# ----------------------------------------------------------------------------- KEV / EPSS
def cargar_kev(cache: Cache) -> set[str]:
    d = cache.get("kev", 12 * 3600)
    if d is None:
        try:
            r = peticion(KEV_URL, timeout=60)
            d = cache.set("kev", [v["cveID"] for v in r.get("vulnerabilities", [])])
        except Exception as e:  # noqa: BLE001
            log.warning("No se pudo descargar CISA KEV: %s", e)
            return set()
    return set(d)


def cargar_epss(cache: Cache, cves: list[str]) -> dict[str, float]:
    out, pendientes = {}, []
    for c in set(cves):
        v = cache.get(f"epss:{c}", 24 * 3600)
        if v is None:
            pendientes.append(c)
        else:
            out[c] = v
    for i in range(0, len(pendientes), 80):
        lote = pendientes[i:i + 80]
        try:
            r = peticion(f"{EPSS_URL}?cve={','.join(lote)}")
        except Exception as e:  # noqa: BLE001
            log.warning("EPSS: %s", e)
            continue
        vistos = {x["cve"]: float(x["epss"]) for x in r.get("data", [])}
        for c in lote:
            out[c] = cache.set(f"epss:{c}", vistos.get(c, 0.0))
    return out


# ----------------------------------------------------------------------------- Fin de soporte
def fin_de_soporte(cache: Cache, comp: Componente) -> tuple[Hallazgo | None, dict]:
    """Devuelve (hallazgo si la rama está sin soporte, info de la rama)."""
    slug = RUNTIMES.get(comp.nombre, {}).get("eol")
    if not slug:
        return None, {}
    ciclos = cache.get(f"eol:{slug}", 24 * 3600)
    if ciclos is None:
        try:
            ciclos = cache.set(f"eol:{slug}", peticion(f"{EOL_URL}/{slug}.json"))
        except Exception as e:  # noqa: BLE001
            log.debug("endoflife %s: %s", slug, e)
            return None, {}
    # la rama más específica que encaje: '8.1' para 8.1.2, '17' para 17.0.8
    candidatos = [c for c in ciclos if comp.version == str(c["cycle"]) or comp.version.startswith(str(c["cycle"]) + ".")]
    if not candidatos:
        return None, {}
    ciclo = max(candidatos, key=lambda c: len(str(c["cycle"])))
    eol = ciclo.get("eol")
    hoy = dt.date.today().isoformat()
    sin_soporte = eol is True or (isinstance(eol, str) and eol <= hoy)
    info = {"rama": str(ciclo["cycle"]), "fin_soporte": eol, "ultima_de_rama": ciclo.get("latest"),
            "sin_soporte": sin_soporte,
            "desactualizada": bool(ciclo.get("latest")) and comparar(str(ciclo["latest"]), comp.version) > 0}
    if not sin_soporte:
        return None, info
    ultima_rama = next((str(c["cycle"]) for c in ciclos if not (c.get("eol") is True or
                        (isinstance(c.get("eol"), str) and c["eol"] <= hoy))), None)
    h = Hallazgo(
        id=f"EOL-{comp.nombre}-{ciclo['cycle']}", componente=comp.clave, nombre=comp.nombre, version=comp.version,
        resumen=(f"La rama {comp.nombre} {ciclo['cycle']} dejó de recibir parches de seguridad "
                 f"({eol if isinstance(eol, str) else 'sin fecha'}). Cualquier CVE nuevo quedará sin corregir."),
        severidad="ALTA", cvss=None, corregido_en=[f"rama {ultima_rama}"] if ultima_rama else [],
        referencias=[f"https://endoflife.date/{slug}"], fuente="endoflife.date",
    )
    return h, info
