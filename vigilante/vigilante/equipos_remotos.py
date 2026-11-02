"""Equipos remotos (lado del central): alta de agentes, tokens, inventario y tareas.

Los agentes solo hacen conexiones SALIENTES hacia el central:

    POST /api/agente/alta                 {codigo, hostname, version}   -> {id, token, nombre}
    POST /api/agente/inventario           lo que ha detectado el equipo  -> {ok}
    GET  /api/agente/tareas               long-poll (~25 s)              -> {tareas: [...]}
    POST /api/agente/resultado/<tarea>    {ok, resultado | error}

- El código de alta es de un solo uso y caduca en 1 h. El token del agente se guarda solo como hash.
- Revocar un equipo invalida su token al momento.
- `EquipoRemoto` cumple la interfaz de `Equipo` encolando tareas para el agente y esperando su respuesta.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time

from .equipos import CAMPOS_DEL_EQUIPO, Equipo
from .modelo import Componente

log = logging.getLogger("vigilante.equipos")

CADUCIDAD_ALTA_S = 3600
EN_LINEA_S = 75                 # el agente pregunta por tareas cada ~25 s
ESPERA_TAREAS_S = 25
MAX_CONTEXTO = 2_000_000        # caracteres de ficheros que puede subir un agente para Claude
NOMBRE_VALIDO = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
CAMPOS_COMPONENTE = ("nombre", "version", "tipo", "ecosistema", "origen", "detalle", "contenedor", "app")


class ErrorEquipo(Exception):
    pass


def _sha(texto: str) -> str:
    return hashlib.sha256(texto.encode()).hexdigest()


def ahora() -> float:
    return time.time()


class Registro:
    """Equipos dados de alta y su cola de tareas. Persistente en <datos>/equipos.json (0600)."""

    def __init__(self, carpeta_datos: str):
        self.ruta = os.path.join(carpeta_datos, "equipos.json")
        self._c = threading.Condition()
        datos = self._leer()
        self.equipos: dict[str, dict] = datos.get("equipos", {})
        self.altas: dict[str, dict] = datos.get("altas", {})
        self._colas: dict[str, list[dict]] = {}
        self._esperando: dict[str, dict] = {}          # tarea -> {evento, resultado, entregada}
        self._contacto: dict[str, float] = {}          # en memoria: no se escribe en cada long-poll
        self.al_cambiar = None                         # callback(id) cuando se añade o revoca un equipo

    def _leer(self) -> dict:
        try:
            with open(self.ruta) as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _guardar(self):
        ahora_ = ahora()
        self.altas = {k: a for k, a in self.altas.items() if a["caduca"] > ahora_}
        tmp = self.ruta + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"equipos": self.equipos, "altas": self.altas}, f, ensure_ascii=False)
        os.replace(tmp, self.ruta)

    # ------------------------------------------------------------------ alta, tokens, revocación
    def activos(self) -> dict[str, dict]:
        with self._c:          # reentrante (RLock): se usa también desde dentro de otras operaciones
            return {k: e for k, e in self.equipos.items() if not e.get("revocado")}

    def crear_alta(self, nombre: str) -> str:
        nombre = (nombre or "").strip().lower()
        if not NOMBRE_VALIDO.match(nombre):
            raise ErrorEquipo("El nombre del equipo solo puede tener minúsculas, números y guiones (máx. 32), "
                              "p. ej. «servidor-web-2».")
        with self._c:
            ocupados = {e["nombre"] for e in self.activos().values()} | {a["nombre"] for a in self.altas.values()
                                                                         if a["caduca"] > ahora()}
            if nombre in ocupados:
                raise ErrorEquipo(f"Ya hay un equipo (o un alta pendiente) llamado «{nombre}».")
            codigo = secrets.token_urlsafe(18)
            self.altas[_sha(codigo)] = {"nombre": nombre, "caduca": ahora() + CADUCIDAD_ALTA_S}
            self._guardar()
        log.info("Código de alta creado para el equipo «%s» (caduca en 1 h)", nombre)
        return codigo

    def canjear(self, codigo: str, hostname: str = "", version: str = "") -> tuple[str, str, str]:
        """Código de alta -> (id, token, nombre). El código deja de valer al usarse."""
        with self._c:
            alta = self.altas.pop(_sha(codigo or ""), None)
            if not alta or alta["caduca"] <= ahora():
                if alta:
                    self._guardar()
                raise ErrorEquipo("código de alta incorrecto, caducado o ya usado")
            id_ = "e" + secrets.token_hex(4)
            token = "pw_" + secrets.token_urlsafe(32)
            self.equipos[id_] = {"nombre": alta["nombre"], "token": _sha(token), "creado": ahora(),
                                 "hostname": str(hostname)[:100], "version": str(version)[:40],
                                 "inventario": None, "inventario_en": None}
            self._contacto[id_] = ahora()
            self._guardar()
        log.warning("Equipo «%s» dado de alta (%s, %s)", alta["nombre"], id_, hostname)
        if self.al_cambiar:
            self.al_cambiar(id_)
        return id_, token, alta["nombre"]

    def autenticar(self, token: str) -> str | None:
        if not token or not token.startswith("pw_"):
            return None
        h = _sha(token)
        for id_, e in self.activos().items():
            if secrets.compare_digest(e["token"], h):
                self._contacto[id_] = ahora()
                return id_
        return None

    def revocar(self, id_: str):
        with self._c:
            e = self.equipos.get(id_)
            if not e:
                raise ErrorEquipo("Ese equipo no existe.")
            e["revocado"] = ahora()
            e["token"] = ""
            for t in self._colas.pop(id_, []):          # lo pendiente ya no se entregará
                self._resolver(t["id"], {"ok": False, "error": "equipo revocado"})
            self._guardar()
            self._c.notify_all()
        log.warning("Equipo «%s» (%s) revocado", e["nombre"], id_)
        if self.al_cambiar:
            self.al_cambiar(id_)

    def en_linea(self, id_: str) -> bool:
        return ahora() - self._contacto.get(id_, 0) < EN_LINEA_S

    def ultimo_contacto(self, id_: str) -> float | None:
        return self._contacto.get(id_) or (self.equipos.get(id_) or {}).get("inventario_en")

    # ------------------------------------------------------------------ inventario
    def guardar_inventario(self, id_: str, inv: dict):
        if not isinstance(inv, dict) or not isinstance(inv.get("componentes"), list):
            raise ErrorEquipo("inventario no válido")
        limpio = {
            "componentes": [{**{k: str(c.get(k) or "") for k in CAMPOS_COMPONENTE}, "raiz": str(c.get("raiz") or "")}
                            for c in inv["componentes"][:5000] if isinstance(c, dict) and c.get("nombre")],
            "apps_dirs": {str(k): str(v) for k, v in (inv.get("apps_dirs") or {}).items()},
            "capacidades": str(inv.get("capacidades") or "")[:4000],
            "solo_lectura": bool(inv.get("solo_lectura", True)),
            "mantenimiento": inv.get("mantenimiento") if isinstance(inv.get("mantenimiento"), dict) else {},
        }
        with self._c:
            e = self.equipos[id_]
            e.update(inventario=limpio, inventario_en=ahora(), hostname=str(inv.get("hostname") or e["hostname"])[:100],
                     version=str(inv.get("version") or e["version"])[:40])
            self._guardar()
            self._c.notify_all()            # por si alguien espera un inventario nuevo (escanear)

    def esperar_inventario(self, id_: str, desde: float, timeout: float) -> bool:
        with self._c:
            return self._c.wait_for(lambda: (self.equipos.get(id_, {}).get("inventario_en") or 0) > desde, timeout)

    # ------------------------------------------------------------------ tareas
    def encolar(self, id_: str, tipo: str, datos: dict) -> str:
        tarea = {"id": secrets.token_hex(8), "tipo": tipo, "datos": datos}
        with self._c:
            if id_ not in self.activos():
                raise ErrorEquipo("el equipo no está registrado")
            self._colas.setdefault(id_, []).append(tarea)
            self._esperando[tarea["id"]] = {"evento": threading.Event(), "resultado": None, "equipo": id_,
                                            "entregada": False}
            self._c.notify_all()
        return tarea["id"]

    def tareas_para(self, id_: str, timeout: float = ESPERA_TAREAS_S) -> list[dict]:
        """Long-poll del agente: devuelve las tareas pendientes en cuanto haya alguna (o [] al agotar el tiempo)."""
        with self._c:
            self._c.wait_for(lambda: self._colas.get(id_) or id_ not in self.activos(), timeout)
            tareas = self._colas.pop(id_, [])
            for t in tareas:
                if t["id"] in self._esperando:
                    self._esperando[t["id"]]["entregada"] = True
        self._contacto[id_] = ahora()
        return tareas

    def _resolver(self, tarea_id: str, resultado: dict):
        e = self._esperando.get(tarea_id)
        if e:
            e["resultado"] = resultado
            e["evento"].set()

    def resultado(self, id_: str, tarea_id: str, resultado: dict):
        e = self._esperando.get(tarea_id)
        if not e or e["equipo"] != id_:         # un equipo no puede responder por otro
            raise ErrorEquipo("tarea desconocida")
        self._resolver(tarea_id, resultado if isinstance(resultado, dict) else {"ok": False, "error": "respuesta no válida"})

    def pedir(self, id_: str, tipo: str, datos: dict, timeout: float) -> dict:
        """Encola una tarea y espera su resultado. Lanza ErrorEquipo si no responde a tiempo o falla."""
        nombre = (self.equipos.get(id_) or {}).get("nombre", id_)
        if not self.en_linea(id_):
            raise ErrorEquipo(f"el equipo «{nombre}» está desconectado")
        tid = self.encolar(id_, tipo, datos)
        e = self._esperando[tid]
        try:
            if not e["evento"].wait(timeout):
                with self._c:
                    cola = self._colas.get(id_, [])
                    self._colas[id_] = [t for t in cola if t["id"] != tid]
                if e["entregada"]:
                    raise ErrorEquipo(f"el equipo «{nombre}» no respondió a tiempo ({tipo}); revisa su estado")
                raise ErrorEquipo(f"el equipo «{nombre}» no recogió la tarea ({tipo}): ¿está desconectado?")
            r = e["resultado"] or {}
        finally:
            self._esperando.pop(tid, None)
        if not r.get("ok"):
            raise ErrorEquipo(f"«{nombre}»: {r.get('error') or 'error desconocido'}")
        return r.get("resultado") or {}


class EquipoRemoto(Equipo):
    """Un servidor con agente. Lo detectado llega en el inventario; el resto se pide como tarea."""

    def __init__(self, registro: Registro, id_: str, cfg: dict):
        self.r, self.id, self.cfg = registro, id_, cfg

    @property
    def _e(self) -> dict:
        return self.r.equipos.get(self.id) or {}

    @property
    def nombre(self) -> str:
        return self._e.get("nombre", self.id)

    @property
    def _inv(self) -> dict:
        return self._e.get("inventario") or {}

    def en_linea(self) -> bool:
        return self.r.en_linea(self.id)

    def _app(self, app: str) -> str:
        """Las apps de un equipo remoto se muestran como «equipo/app» (no chocan con las de otros)."""
        return f"{self.nombre}/{app}" if app else self.nombre

    # ---- detección
    def detectar(self) -> list[Componente]:
        """Pide un inventario nuevo si el equipo está en línea (espera poco); si no, usa el último."""
        if self.en_linea():
            desde = self._e.get("inventario_en") or 0
            try:
                self.r.encolar(self.id, "escanear", {})
                self.r.esperar_inventario(self.id, desde, 90)
            except ErrorEquipo:
                pass
        out = []
        for c in self._inv.get("componentes", []):
            comp = Componente(**{k: c.get(k, "") for k in CAMPOS_COMPONENTE})
            comp.app, comp.equipo = self._app(comp.app), self.id
            out.append(comp)
        return out

    @property
    def apps_dirs(self) -> dict[str, str]:
        return {self._app(a): d for a, d in self._inv.get("apps_dirs", {}).items()}

    def raiz(self, comp) -> str:
        """La carpeta la decide el agente (la manda con cada componente del inventario)."""
        clave = comp.clave if isinstance(comp, Componente) else comp.get("clave")
        for c in self._inv.get("componentes", []):
            obj = Componente(**{k: c.get(k, "") for k in CAMPOS_COMPONENTE})
            obj.app, obj.equipo = self._app(obj.app), self.id
            if obj.clave == clave:
                return c.get("raiz", "")
        return ""

    # ---- lo que necesita Claude
    def contexto(self, raiz: str, paquete: str) -> str:
        r = self.r.pedir(self.id, "contexto", {"raiz": raiz, "paquete": paquete}, 180)
        return str(r.get("contexto") or "")[:MAX_CONTEXTO]

    def capacidades(self) -> str:
        return self._inv.get("capacidades") or "Solo verificación estática en una copia."

    # ---- verificar / aplicar / revertir
    @property
    def solo_lectura(self) -> bool:
        return bool(self._inv.get("solo_lectura", True))

    def _con_campos(self, plan: dict, r: dict):
        """Incorpora al plan solo los campos que un equipo puede devolver."""
        for k in CAMPOS_DEL_EQUIPO:
            if k in (r.get("plan") or {}):
                plan[k] = r["plan"][k]

    def verificar(self, plan: dict, numeros: list[int] | None = None) -> dict:
        r = self.r.pedir(self.id, "verificar", {"plan": plan, "numeros": numeros},
                         int(self.cfg.get("claude", {}).get("timeout_s", 1800)) + 600)
        return r["verificacion"]

    def aplicar(self, plan: dict, por: str) -> dict:
        from .aplicar import ErrorAplicacion
        espera = int(self.cfg["aplicacion"].get("timeout_despliegue_s", 900)) + 1800
        try:
            r = self.r.pedir(self.id, "aplicar", {"plan": plan, "por": por}, espera)
        except ErrorEquipo as e:
            if "desconectado" in str(e) or "no recogió" in str(e):
                raise ErrorAplicacion(str(e)) from None     # no llegó al equipo: no se ha tocado nada
            raise
        self._con_campos(plan, r)
        if r.get("error_aplicacion"):
            raise ErrorAplicacion(r["error_aplicacion"])
        return r["resultado"]

    def revertir(self, plan: dict, por: str) -> dict:
        from .aplicar import ErrorAplicacion
        espera = int(self.cfg["aplicacion"].get("timeout_despliegue_s", 900)) + 900
        try:
            r = self.r.pedir(self.id, "revertir", {"plan": plan, "por": por}, espera)
        except ErrorEquipo as e:
            raise ErrorAplicacion(str(e)) from None
        self._con_campos(plan, r)
        if r.get("error_aplicacion"):
            raise ErrorAplicacion(r["error_aplicacion"])
        return r["resultado"]

    # ---- modo mantenimiento (estado según el último inventario)
    @property
    def mant(self):
        return MantenimientoRemoto(self)


class MantenimientoRemoto:
    def __init__(self, eq: EquipoRemoto):
        self.eq = eq

    def info(self) -> dict:
        return self.eq._inv.get("mantenimiento") or {"activo": False}

    def activo(self) -> bool:
        return bool(self.info().get("activo"))

    def preparar(self):
        pass

    def _pedir(self, datos):
        r = self.eq.r.pedir(self.eq.id, "mantenimiento", datos, 120)
        if self.eq._inv and isinstance(r.get("info"), dict):
            self.eq._inv["mantenimiento"] = r["info"]

    def activar(self, motivo: str, quien: str = "vigilante"):
        self._pedir({"accion": "activar", "motivo": motivo, "quien": quien})

    def desactivar(self, quien: str = "panel"):
        self._pedir({"accion": "desactivar", "quien": quien})
