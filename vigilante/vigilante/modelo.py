"""Tipos de datos compartidos."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

# Prioridad de las fuentes de detección: si dos dicen cosas distintas, gana la más fiable.
PRIORIDAD_ORIGEN = {"exec": 5, "manual": 6, "env": 4, "imagen": 3, "fichero": 2, "http": 1}


@dataclass
class Componente:
    nombre: str              # nombre canónico: "php", "nginx", "guzzlehttp/guzzle"...
    version: str
    tipo: str                # "runtime" (PHP, nginx, Java…) o "paquete" (dependencias)
    ecosistema: str = ""     # para paquetes: Packagist, npm, Maven, PyPI, RubyGems, Go
    origen: str = ""         # exec | env | imagen | fichero | http | manual
    detalle: str = ""        # de dónde exactamente (contenedor, fichero…)
    contenedor: str = ""
    app: str = ""            # app (proyecto docker compose) a la que pertenece

    @property
    def clave(self) -> str:
        base = f"{self.ecosistema or self.tipo}:{self.nombre}@{self.version}"
        return f"{self.app}::{base}" if self.app else base

    def to_dict(self):
        d = asdict(self)
        d["clave"] = self.clave
        return d


@dataclass
class Hallazgo:
    id: str                          # CVE-… / GHSA-… / EOL-…
    componente: str                  # clave del componente
    nombre: str
    version: str
    resumen: str
    cvss: float | None = None
    severidad: str = "DESCONOCIDA"   # CRITICA | ALTA | MEDIA | BAJA | DESCONOCIDA
    kev: bool = False                # en el catálogo CISA de explotadas activamente
    epss: float | None = None        # probabilidad de explotación en 30 días
    corregido_en: list[str] = field(default_factory=list)
    referencias: list[str] = field(default_factory=list)
    alias: list[str] = field(default_factory=list)
    fuente: str = ""                 # NVD | OSV | endoflife.date
    publicado: str = ""
    critico: bool = False            # decisión final del motor de reglas
    app: str = ""                    # app a la que pertenece el componente

    def to_dict(self):
        return asdict(self)


def severidad_por_cvss(score: float | None) -> str:
    if score is None:
        return "DESCONOCIDA"
    if score >= 9.0:
        return "CRITICA"
    if score >= 7.0:
        return "ALTA"
    if score >= 4.0:
        return "MEDIA"
    if score > 0:
        return "BAJA"
    return "DESCONOCIDA"


ORDEN_SEVERIDAD = {"CRITICA": 4, "ALTA": 3, "MEDIA": 2, "BAJA": 1, "DESCONOCIDA": 0}
