"""Equipos: los servidores con Docker donde están las apps vigiladas.

Todo lo que necesita tocar el servidor (leer sus contenedores y su código, verificar en una copia,
aplicar, revertir y el modo mantenimiento) pasa por un `Equipo`. El resto (CVE, avisos, Claude,
planes, panel) no sabe en qué servidor está cada app.

- `EquipoLocal`: el propio servidor donde corre este proceso. Es el modo «todo en uno» y también lo
  que usa el agente por dentro.
- `EquipoRemoto` (central + agentes): las mismas operaciones, pero se las pide al agente del equipo.

Contrato: `verificar`, `aplicar` y `revertir` reciben el plan y pueden actualizar en él SOLO los
campos de CAMPOS_DEL_EQUIPO; así un equipo remoto puede devolverlos y el central los incorpora.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os

from . import claude, detectar_docker, detectar_ficheros, detectar_http
from .aplicar import Aplicador
from .mantenimiento import Mantenimiento
from .modelo import Componente
from .verificacion import Verificador

log = logging.getLogger("vigilante.equipos")

LOCAL = ""          # id del equipo local
CAMPOS_DEL_EQUIPO = ("verificacion", "verificaciones_previas", "aplicacion")


def huella_verificacion(ver: dict | None) -> str:
    """Resumen de todo lo que el aplicador toma de una verificación (diffs, ficheros, hashes de producción).
    El agente guarda la huella de lo que él mismo verificó y no aplica nada con otra huella."""
    ver = ver or {}
    datos = {
        "cambios": sorted(int(n) for n in ver.get("cambios_verificados") or []),
        "por_cambio": {str(n): {k: r.get(k) for k in ("aplica", "diff_final", "ficheros")}
                       for n, r in sorted((ver.get("por_cambio") or {}).items())},
        "hashes": ver.get("hashes_originales") or {},
    }
    return hashlib.sha256(json.dumps(datos, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


class Equipo:
    id = LOCAL
    nombre = "Este servidor"

    def en_linea(self) -> bool:
        return True

    # ---- detección
    def detectar(self) -> list[Componente]:
        raise NotImplementedError

    @property
    def apps_dirs(self) -> dict[str, str]:
        """{app: carpeta de su proyecto} según la última detección."""
        raise NotImplementedError

    def raiz(self, comp: Componente) -> str:
        """Carpeta del proyecto del componente ('' si no hay código montado que modificar)."""
        raise NotImplementedError

    # ---- lo que necesita Claude
    def contexto(self, raiz: str, paquete: str) -> str:
        raise NotImplementedError

    def capacidades(self) -> str:
        raise NotImplementedError

    # ---- verificar / aplicar / revertir
    @property
    def solo_lectura(self) -> bool:
        raise NotImplementedError

    def verificar(self, plan: dict, numeros: list[int] | None = None) -> dict:
        raise NotImplementedError

    def aplicar(self, plan: dict, por: str) -> dict:
        raise NotImplementedError

    def revertir(self, plan: dict, por: str) -> dict:
        raise NotImplementedError

    # ---- modo mantenimiento
    @property
    def mant(self) -> Mantenimiento:
        raise NotImplementedError


class EquipoLocal(Equipo):
    def __init__(self, cfg: dict, carpeta_datos: str):
        self.cfg = cfg
        self.verificador = Verificador(cfg, carpeta_datos)
        self.aplicador = Aplicador(cfg, carpeta_datos, self.verificador)
        self._mant = Mantenimiento(cfg["mantenimiento"], cfg["general"]["nombre_web"])
        self._apps_dirs: dict[str, str] = {}

    # ---- detección
    def detectar(self) -> list[Componente]:
        """Componentes de todas las capas, sin fusionar (lo hace el motor)."""
        d = self.cfg["deteccion"]
        comps: list[Componente] = []
        sock = d.get("docker_socket", "")
        if d.get("docker") and (sock.startswith(("tcp://", "http://")) or os.path.exists(sock)):
            comps += detectar_docker.detectar(d)
        rutas = d.get("rutas_proyecto") or []
        # {carpeta: app}: lo configurado y lo que dicen las etiquetas de compose (solo carpetas montadas)
        apps = {**{k: v for k, v in detectar_docker.mapa_apps(d).items() if k in rutas}, **(d.get("apps") or {})}
        self._apps_dirs = {v: k for k, v in apps.items()}
        comps += detectar_ficheros.detectar(rutas, apps)
        comps += detectar_http.detectar(d.get("url_web", ""))
        for nombre, version in (d.get("manual") or {}).items():
            comps.append(Componente(nombre, str(version), "runtime", origen="manual", detalle="configuración"))
        return comps

    @property
    def apps_dirs(self) -> dict[str, str]:
        return self._apps_dirs

    def raiz(self, comp: Componente) -> str:
        rutas = [r for r in self.cfg["deteccion"].get("rutas_proyecto") or [] if os.path.isdir(r)]
        if comp.app and self._apps_dirs.get(comp.app) in rutas:
            return self._apps_dirs[comp.app]
        for r in rutas:
            if comp.detalle.startswith(r.rstrip("/") + "/"):
                return r
        return rutas[0] if len(rutas) == 1 else ""      # una sola app: sin ambigüedad

    # ---- lo que necesita Claude
    def contexto(self, raiz: str, paquete: str) -> str:
        return claude.contexto_ficheros(raiz, paquete)

    def capacidades(self) -> str:
        return self.verificador.capacidades()

    # ---- verificar / aplicar / revertir
    @property
    def solo_lectura(self) -> bool:
        return bool(self.cfg["aplicacion"].get("solo_lectura"))

    def verificar(self, plan: dict, numeros: list[int] | None = None) -> dict:
        return self.verificador.verificar(plan, numeros)

    def aplicar(self, plan: dict, por: str) -> dict:
        return self.aplicador.aplicar(plan, por)

    def revertir(self, plan: dict, por: str) -> dict:
        return self.aplicador.revertir(plan, por)

    # ---- modo mantenimiento
    @property
    def mant(self) -> Mantenimiento:
        return self._mant
