"""Ciclo principal: detectar -> buscar -> priorizar -> avisar -> (proponer) -> (mantenimiento)."""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import threading

from . import detectar_docker, detectar_ficheros, detectar_http, fuentes
from .avisos import Avisador, texto_hallazgo
from .http import Cache
from .mantenimiento import Mantenimiento
from .versiones import partes
from .modelo import ORDEN_SEVERIDAD, PRIORIDAD_ORIGEN, Componente, Hallazgo

log = logging.getLogger("vigilante")


def ahora():
    return dt.datetime.now().isoformat(timespec="seconds")


class Vigilante:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        g = cfg["general"]
        self.datos = g["carpeta_datos"]
        os.makedirs(self.datos, exist_ok=True)
        self.cache = Cache(self.datos)
        self.avisador = Avisador(cfg["avisos"], g["nombre_web"])
        self.mant = Mantenimiento(cfg["mantenimiento"], g["nombre_web"])
        self.ruta_estado = os.path.join(self.datos, "estado.json")
        self.estado = self._cargar_estado()
        self.cerrojo = threading.Lock()
        self.en_curso = False
        self.apps_dirs: dict[str, str] = {}      # app -> carpeta de su proyecto (la rellena detectar)
        from .correcciones import Gestor
        self.gestor = Gestor(self)

    # ------------------------------------------------------------------ estado
    def _cargar_estado(self):
        try:
            return json.load(open(self.ruta_estado))
        except (OSError, ValueError):
            return {"componentes": [], "hallazgos": {}, "resueltos": [], "ciclos": [], "info_ramas": {}}

    def _guardar(self):
        tmp = self.ruta_estado + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.estado, f, indent=1, ensure_ascii=False)
        os.replace(tmp, self.ruta_estado)

    # ------------------------------------------------------------------ 1. detectar
    def detectar(self) -> list[Componente]:
        d = self.cfg["deteccion"]
        comps: list[Componente] = []
        sock = d.get("docker_socket", "")
        if d.get("docker") and (sock.startswith(("tcp://", "http://")) or os.path.exists(sock)):
            comps += detectar_docker.detectar(d)
        rutas = d.get("rutas_proyecto") or []
        # {carpeta: app}: lo configurado y lo que dicen las etiquetas de compose (solo carpetas montadas)
        apps = {**{k: v for k, v in detectar_docker.mapa_apps(d).items() if k in rutas}, **(d.get("apps") or {})}
        self.apps_dirs = {v: k for k, v in apps.items()}
        comps += detectar_ficheros.detectar(rutas, apps)
        comps += detectar_http.detectar(d.get("url_web", ""))
        for nombre, version in (d.get("manual") or {}).items():
            comps.append(Componente(nombre, str(version), "runtime", origen="manual", detalle="configuración"))
        return fusionar(comps)

    # ------------------------------------------------------------------ 2. buscar
    def buscar(self, comps: list[Componente]) -> list[Hallazgo]:
        f = self.cfg["fuentes"]
        hallazgos: list[Hallazgo] = []
        info_ramas = {}
        if f.get("nvd"):
            nvd = fuentes.NVD(self.cache, f.get("nvd_api_key", ""))
            for c in comps:
                if c.tipo == "runtime" and version_precisa(c):
                    try:
                        hallazgos += nvd.buscar(c)
                    except Exception as e:  # noqa: BLE001
                        log.error("NVD falló para %s: %s", c.clave, e)
        if f.get("osv"):
            try:
                hallazgos += fuentes.OSV(self.cache).buscar(comps)
            except Exception as e:  # noqa: BLE001
                log.error("OSV falló: %s", e)
        if f.get("fin_de_soporte"):
            for c in comps:
                if c.tipo == "runtime":
                    h, info = fuentes.fin_de_soporte(self.cache, c)
                    if info:
                        info_ramas[c.clave] = info
                    if h:
                        hallazgos.append(h)
        self.estado["info_ramas"] = info_ramas

        cves = [x for h in hallazgos for x in [h.id] + h.alias if x.startswith("CVE-")]
        kev = fuentes.cargar_kev(self.cache) if f.get("kev") else set()
        epss = fuentes.cargar_epss(self.cache, cves) if f.get("epss") and cves else {}
        r = self.cfg["reglas"]
        ignorar = set(r.get("ignorar") or [])
        app_de = {c.clave: c.app for c in comps}
        salida, vistos = [], set()
        for h in hallazgos:
            ids = [h.id] + h.alias
            if ignorar.intersection(ids) or (h.componente, h.id) in vistos:
                continue
            vistos.add((h.componente, h.id))
            h.kev = h.kev or any(i in kev for i in ids)
            h.epss = max((epss[i] for i in ids if i in epss), default=None)
            h.critico = es_critico(h, r)
            h.app = app_de.get(h.componente, "")
            if h.critico and h.severidad != "CRITICA":
                # explotada activamente o con explotación probable (EPSS) = crítica, diga lo que diga el CVSS
                h.severidad = "CRITICA"
            salida.append(h)
        return salida

    # ------------------------------------------------------------------ ciclo completo
    def ciclo(self, origen="programado"):
        with self.cerrojo:
            self.en_curso = True
            try:
                return self._ciclo(origen)
            finally:
                self.en_curso = False

    def _ciclo(self, origen):
        inicio = ahora()
        log.info("== Ciclo de vigilancia (%s) ==", origen)
        self.mant.preparar()
        comps = self.detectar()
        log.info("Detectados %d componentes (%d runtimes)", len(comps), sum(c.tipo == "runtime" for c in comps))
        for c in comps:
            if c.tipo == "runtime":
                log.info("  · %s %s  [%s: %s]", c.nombre, c.version, c.origen, c.detalle)
        hallazgos = self.buscar(comps)
        detalle_por_comp = {c.clave: c for c in comps}

        previos = self.estado.get("hallazgos", {})
        actuales, nuevos, escalados = {}, [], []
        minimo = ORDEN_SEVERIDAD[self.cfg["reglas"].get("severidad_minima_aviso", "BAJA")]
        for h in hallazgos:
            k = f"{h.componente}|{h.id}"
            reg = {**h.to_dict(), "clave": k}
            ant = previos.get(k)
            if ant:
                reg.update({x: ant[x] for x in ("primera_vez", "ultimo_aviso") if x in ant})
                if (h.kev and not ant.get("kev")) or ORDEN_SEVERIDAD[h.severidad] > ORDEN_SEVERIDAD[ant["severidad"]]:
                    escalados.append(h)
            else:
                reg["primera_vez"] = inicio
                if ORDEN_SEVERIDAD[h.severidad] >= minimo or h.critico:
                    nuevos.append(h)
            actuales[k] = reg
        resueltos = [v for k, v in previos.items() if k not in actuales]

        self.estado["componentes"] = [c.to_dict() for c in comps]
        self.estado["hallazgos"] = actuales
        self.estado["resueltos"] = ([{**v, "resuelto": inicio} for v in resueltos] + self.estado.get("resueltos", []))[:200]

        self._avisar(nuevos, escalados, resueltos, actuales)
        self._decidir_mantenimiento(nuevos + escalados)
        # Claude prepara (en segundo plano) planes de corrección que el usuario aprobará o no
        self.gestor.revisar_ciclo(nuevos + escalados, detalle_por_comp, actuales)
        self.gestor.ofrecer_resolucion(nuevos + escalados)      # solo OFRECE: Claude actúa cuando el usuario lo pide

        resumen = {"inicio": inicio, "fin": ahora(), "origen": origen, "componentes": len(comps),
                   "hallazgos": len(actuales), "nuevos": len(nuevos), "criticos": sum(v["critico"] for v in actuales.values())}
        self.estado["ciclos"] = ([resumen] + self.estado.get("ciclos", []))[:50]
        self._guardar()
        log.info("Ciclo terminado: %s", resumen)
        return resumen

    # ------------------------------------------------------------------ avisos
    def _url(self, ruta=""):
        base = self.cfg["panel"].get("url_publica", "").rstrip("/")
        return f"{base}{ruta}" if base else ""

    def _avisar(self, nuevos, escalados, resueltos, actuales):
        av = self.cfg["avisos"]
        def prop(h):
            return "Claude preparará un plan de corrección (te llegará para aprobar)" \
                if self.cfg["claude"].get("api_key") and h.critico else ""

        # primero lo que se está explotando ya (KEV), luego por CVSS y probabilidad de explotación
        criticos = sorted((h for h in nuevos + escalados if h.critico),
                          key=lambda h: (not h.kev, -(h.cvss or 0), -(h.epss or 0)))
        for h in criticos[:5]:
            extra = ""
            if self.cfg["mantenimiento"].get("modo") == "manual" and self._url():
                extra = f"\n\n¿Poner la web en mantenimiento? {self._url('/mantenimiento')}"
            self.avisador.enviar(f"URGENTE: {h.id} en {h.nombre} {h.version}",
                                 texto_hallazgo(h, self._url(), prop(h)) + extra, urgente=True)

        resto = [h for h in nuevos if not h.critico] + criticos[5:] + [h for h in escalados if not h.critico]
        if resto:
            por_comp: dict[str, list[Hallazgo]] = {}
            for h in sorted(resto, key=lambda h: -(h.cvss or 0)):
                por_comp.setdefault(f"{h.app}: {h.nombre} {h.version}" if h.app else f"{h.nombre} {h.version}", []).append(h)
            lineas = []
            for comp, hs in por_comp.items():
                arreglo = version_minima_segura(v["corregido_en"] for v in actuales.values()
                                                if v["componente"] == hs[0].componente)
                lineas.append(f"• {comp}: {len(hs)} vulnerabilidad(es)" + (f" → actualizar al menos a {arreglo}" if arreglo else ""))
                for h in hs[:3]:
                    lineas.append(f"    {h.severidad} {h.id}" + (f" (CVSS {h.cvss})" if h.cvss else ""))
                if len(hs) > 3:
                    lineas.append(f"    … y {len(hs) - 3} más")
            if self._url():
                lineas.append(f"\nDetalle completo: {self._url()}")
            self.avisador.enviar(f"{len(resto)} vulnerabilidades nuevas", "\n".join(lineas))

        if resueltos:
            self.avisador.enviar(f"{len(resueltos)} vulnerabilidades ya no aplican",
                                 "\n".join(f"- {r['id']} en {r['nombre']} {r['version']}" for r in resueltos[:20]))

        # recordatorio de críticos sin resolver
        horas = av.get("recordatorio_horas") or 0
        if horas:
            limite = (dt.datetime.now() - dt.timedelta(hours=horas)).isoformat(timespec="seconds")
            pendientes = [v for v in actuales.values() if v["critico"] and v.get("ultimo_aviso", "") < limite
                          and v["id"] not in {h.id for h in criticos}]
            if pendientes:
                self.avisador.enviar(f"Recordatorio: {len(pendientes)} críticas sin resolver",
                                     "\n".join(f"- {p['id']} en {p['nombre']} {p['version']}" for p in pendientes[:15]),
                                     urgente=True)
                for p in pendientes:
                    p["ultimo_aviso"] = ahora()
        for h in nuevos + escalados:
            actuales[f"{h.componente}|{h.id}"]["ultimo_aviso"] = ahora()

    # ------------------------------------------------------------------ mantenimiento
    def _decidir_mantenimiento(self, lista: list[Hallazgo]):
        m = self.cfg["mantenimiento"]
        if m.get("modo") != "auto" or self.mant.activo():
            return
        umbral = self.cfg["reglas"].get("epss_critico", 0.5)
        disparadores = [h for h in lista if h.critico and
                        (not m.get("solo_kev_o_epss", True) or h.kev or (h.epss or 0) >= umbral)]
        if disparadores:
            h = min(disparadores, key=lambda h: (not h.kev, -(h.cvss or 0), -(h.epss or 0)))
            motivo = f"{h.id} en {h.nombre} {h.version} (CVSS {h.cvss}, KEV {'sí' if h.kev else 'no'})"
            self.mant.activar(motivo)
            self.avisador.enviar("WEB EN MODO MANTENIMIENTO",
                                 f"Se ha activado automáticamente por {motivo}.\n"
                                 f"Desactívalo desde el panel cuando esté corregido: {self._url('/mantenimiento')}",
                                 urgente=True)


# ---------------------------------------------------------------------- utilidades
def fusionar(comps: list[Componente]) -> list[Componente]:
    """Quita duplicados. Para runtimes, si hay datos de Docker (exec/env/imagen) o manuales,
    se descartan las pistas débiles (Dockerfile del repo, cabeceras HTTP) de ese mismo runtime."""
    fuertes = {(c.app, c.nombre) for c in comps if c.tipo == "runtime" and PRIORIDAD_ORIGEN.get(c.origen, 0) >= 3}
    manuales = {c.nombre for c in comps if c.origen == "manual"}
    vistos: dict[str, Componente] = {}
    for c in sorted(comps, key=lambda c: -PRIORIDAD_ORIGEN.get(c.origen, 0)):
        if c.tipo == "runtime":
            if c.nombre in manuales and c.origen != "manual":
                continue
            if (c.app, c.nombre) in fuertes and PRIORIDAD_ORIGEN.get(c.origen, 0) < 3:
                continue
        if c.clave not in vistos:
            vistos[c.clave] = c
        elif c.contenedor and c.contenedor not in vistos[c.clave].contenedor:
            vistos[c.clave].contenedor += f", {c.contenedor}"
    return sorted(vistos.values(), key=lambda c: (c.tipo != "runtime", c.nombre))


def version_minima_segura(listas_corregido) -> str:
    """La menor versión que corrige TODAS las vulnerabilidades conocidas del componente
    (de cada CVE se toma su primera versión corregida y se queda la mayor)."""
    primeras = [lc[0] for lc in listas_corregido if lc and lc[0][:1].isdigit()]
    return max(primeras, key=partes) if primeras else ""


def version_precisa(c: Componente) -> bool:
    """'8.1' (de un FROM php:8.1) no basta para buscar CVE por versión exacta."""
    return c.version.count(".") >= 2 or c.nombre in ("postgresql", "java", "go")


def es_critico(h: Hallazgo, r: dict) -> bool:
    if h.kev and r.get("kev_es_critico", True):
        return True
    if h.cvss is not None and h.cvss >= r.get("cvss_critico", 9.0):
        return True
    return h.cvss is not None and h.cvss >= 7.0 and (h.epss or 0) >= r.get("epss_critico", 0.5)
