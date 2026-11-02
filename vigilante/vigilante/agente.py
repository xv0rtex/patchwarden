"""Agente: corre en cada servidor con Docker y trabaja para el panel central.

    python -m vigilante --agente --central https://central.ejemplo --codigo XXXX

- Solo hace conexiones SALIENTES al central (no hay que abrir puertos en el servidor).
- Detecta las versiones (igual que el modo todo en uno), sube el inventario y atiende tareas:
  escanear, contexto (ficheros para Claude), verificar, aplicar, revertir y mantenimiento.
- No tiene panel, bot ni Claude. No se fía a ciegas del central:
    * `[aplicacion] solo_lectura` es local: el central no puede saltárselo;
    * solo aplica una verificación cuya huella coincida con una que hizo ÉL MISMO;
    * al revertir usa SU registro de la copia de seguridad, no lo que diga el central;
    * la carpeta del proyecto tiene que ser una de sus `rutas_proyecto`, y el id del plan, alfanumérico;
    * los comandos de verificación siguen con la lista blanca de verificacion.comando_seguro.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .aplicar import ErrorAplicacion
from .equipos import CAMPOS_DEL_EQUIPO, EquipoLocal, huella_verificacion
from .http import AGENTE

log = logging.getLogger("vigilante.agente")
VERSION = "0.2"
MAX_VERIFICADOS = 200


class ErrorAgente(Exception):
    pass


class Revocado(Exception):
    pass


def url_permitida(url: str, permitir_http: bool = False) -> bool:
    u = urllib.parse.urlparse(url)
    if u.scheme == "https":
        return bool(u.hostname)
    return u.scheme == "http" and (permitir_http or u.hostname in ("localhost", "127.0.0.1", "::1"))


def _leer(ruta, defecto):
    try:
        with open(ruta) as f:
            return json.load(f)
    except (OSError, ValueError):
        return defecto


def _escribir(ruta, datos):
    tmp = ruta + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(datos, f, ensure_ascii=False)
    os.replace(tmp, ruta)


class Agente:
    def __init__(self, cfg: dict, equipo: EquipoLocal | None = None):
        self.cfg = cfg
        self.datos = cfg["general"]["carpeta_datos"]
        os.makedirs(self.datos, exist_ok=True)
        self.equipo = equipo or EquipoLocal(cfg, self.datos)
        self.ruta_estado = os.path.join(self.datos, "agente.json")
        self.ruta_registro = os.path.join(self.datos, "agente-registro.json")
        self.estado = _leer(self.ruta_estado, {})
        # huellas de lo verificado aquí y copias de seguridad de lo aplicado aquí, por plan
        self.registro = _leer(self.ruta_registro, {"verificados": {}, "aplicaciones": {}})
        self.cerrojo_trabajo = threading.Lock()       # verificar / aplicar / revertir, de uno en uno
        self.cerrojo_registro = threading.Lock()
        self.parar = threading.Event()
        self.revocado = False
        self._contenedores: set[str] = set()
        c = cfg.get("central") or {}
        self.central = (c.get("url") or self.estado.get("central") or "").rstrip("/")
        if not self.central:
            raise ErrorAgente("Falta la URL del panel central ([central] url o --central).")
        if not url_permitida(self.central, bool(c.get("permitir_http"))):
            raise ErrorAgente(f"La URL del central debe ser https:// ({self.central}). Solo se admite http:// con "
                              "localhost o con [central] permitir_http = true (p. ej. dentro de una VPN).")

    # ------------------------------------------------------------------ HTTP hacia el central
    def _http(self, metodo: str, ruta: str, datos=None, timeout=60, con_token=True):
        cab = {"User-Agent": f"{AGENTE} agente/{VERSION}", "Accept": "application/json"}
        if con_token:
            cab["Authorization"] = f"Bearer {self.estado.get('token', '')}"
        cuerpo = None
        if datos is not None:
            cuerpo = json.dumps(datos, ensure_ascii=False).encode()
            cab["Content-Type"] = "application/json"
        req = urllib.request.Request(self.central + ruta, data=cuerpo, headers=cab, method=metodo)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            if e.code == 401 and con_token:
                raise Revocado("el central no acepta el token de este equipo (¿revocado?)") from None
            try:
                detalle = json.loads(e.read()).get("error", "")
            except (ValueError, OSError):
                detalle = ""
            raise ErrorAgente(f"HTTP {e.code} en {ruta}: {detalle}") from None

    # ------------------------------------------------------------------ alta
    def dar_de_alta(self, codigo: str = ""):
        if self.estado.get("token") and self.estado.get("central") == self.central:
            return
        codigo = codigo or (self.cfg.get("central") or {}).get("codigo") or ""
        if not codigo:
            raise ErrorAgente("Este equipo no está dado de alta: falta el código ([central] codigo o --codigo). "
                              "Créalo en el panel central, en Ajustes › Equipos.")
        r = self._http("POST", "/api/agente/alta", {"codigo": codigo, "hostname": socket.gethostname(),
                                                    "version": VERSION}, con_token=False)
        self.estado = {"central": self.central, "id": r["id"], "token": r["token"], "nombre": r["nombre"]}
        _escribir(self.ruta_estado, self.estado)
        log.warning("Equipo dado de alta en %s como «%s»", self.central, r["nombre"])

    # ------------------------------------------------------------------ inventario
    def inventario(self) -> dict:
        from .motor import fusionar
        comps = fusionar(self.equipo.detectar())
        self._contenedores = {x.strip() for c in comps for x in (c.contenedor or "").split(",") if x.strip()}
        return {
            "version": VERSION, "hostname": socket.gethostname(),
            "componentes": [{**c.to_dict(), "raiz": self.equipo.raiz(c)} for c in comps],
            "apps_dirs": self.equipo.apps_dirs, "capacidades": self.equipo.capacidades(),
            "solo_lectura": self.equipo.solo_lectura, "mantenimiento": self.equipo.mant.info(),
        }

    def enviar_inventario(self):
        inv = self.inventario()
        self._http("POST", "/api/agente/inventario", inv, timeout=120)
        log.info("Inventario enviado: %d componentes", len(inv["componentes"]))

    # ------------------------------------------------------------------ validaciones
    def _raiz_valida(self, raiz: str) -> str:
        rutas = {os.path.realpath(r) for r in self.cfg["deteccion"].get("rutas_proyecto") or [] if os.path.isdir(r)}
        if not raiz or os.path.realpath(raiz) not in rutas:
            raise ErrorAgente(f"la carpeta «{raiz}» no es un proyecto vigilado por este equipo")
        return raiz

    def _plan_valido(self, plan: dict) -> dict:
        if not isinstance(plan, dict) or not str(plan.get("id", "")).isalnum() or len(str(plan["id"])) > 32:
            raise ErrorAgente("plan no válido")
        self._raiz_valida(plan.get("raiz", ""))
        comp = plan.get("componente") or {}
        # solo se respaldan imágenes de contenedores que este equipo ha visto
        conocidos = [x.strip() for x in (comp.get("contenedor") or "").split(",") if x.strip() in self._contenedores]
        plan["componente"] = {**comp, "contenedor": ", ".join(conocidos)}
        return plan

    def _anotar(self, tipo: str, plan_id: str, valor):
        with self.cerrojo_registro:
            d = self.registro.setdefault(tipo, {})
            if tipo == "verificados":
                d.setdefault(plan_id, [])
                if valor not in d[plan_id]:
                    d[plan_id].append(valor)
            else:
                d[plan_id] = valor
            for k in list(d)[:-MAX_VERIFICADOS]:
                del d[k]
            _escribir(self.ruta_registro, self.registro)

    # ------------------------------------------------------------------ tareas
    def atender(self, tarea: dict) -> dict:
        """Ejecuta una tarea y devuelve su resultado (lanza ErrorAgente si se rechaza)."""
        tipo, datos = tarea.get("tipo"), tarea.get("datos") or {}
        if tipo == "escanear":
            self.enviar_inventario()
            return {}
        if tipo == "contexto":
            return {"contexto": self.equipo.contexto(self._raiz_valida(datos.get("raiz", "")),
                                                     str(datos.get("paquete", "")))}
        if tipo == "mantenimiento":
            m = self.equipo.mant
            if datos.get("accion") == "activar":
                m.activar(str(datos.get("motivo", ""))[:300], str(datos.get("quien", "central"))[:80])
            elif datos.get("accion") == "desactivar":
                m.desactivar(str(datos.get("quien", "central"))[:80])
            else:
                raise ErrorAgente("acción de mantenimiento desconocida")
            return {"info": m.info()}
        if tipo in ("verificar", "aplicar", "revertir"):
            plan = self._plan_valido(datos.get("plan"))
            with self.cerrojo_trabajo:
                return getattr(self, "_" + tipo)(plan, datos)
        raise ErrorAgente(f"tarea desconocida: {tipo}")

    def _verificar(self, plan, datos):
        numeros = datos.get("numeros")
        ver = self.equipo.verificar(plan, [int(n) for n in numeros] if numeros else None)
        self._anotar("verificados", plan["id"], huella_verificacion(ver))
        return {"verificacion": ver}

    def _campos(self, plan):
        return {k: plan.get(k) for k in CAMPOS_DEL_EQUIPO}

    def _aplicar(self, plan, datos):
        if self.equipo.solo_lectura:
            raise ErrorAgente("este equipo está en modo solo propuestas ([aplicacion] solo_lectura): no aplica nada")
        huellas = (self.registro.get("verificados") or {}).get(plan["id"]) or []
        if huella_verificacion(plan.get("verificacion")) not in huellas:
            raise ErrorAgente("la verificación que manda el central no es una que haya hecho este equipo: no se aplica")
        por = str(datos.get("por", "central"))[:120]
        try:
            ap = self.equipo.aplicar(plan, por)
        except ErrorAplicacion as e:
            return {"error_aplicacion": str(e), "plan": self._campos(plan)}
        if plan.get("verificacion"):        # si se re-verificó un subconjunto, también es suya
            self._anotar("verificados", plan["id"], huella_verificacion(plan["verificacion"]))
        self._anotar("aplicaciones", plan["id"], plan.get("aplicacion"))
        return {"resultado": ap, "plan": self._campos(plan)}

    def _revertir(self, plan, datos):
        if self.equipo.solo_lectura:
            raise ErrorAgente("este equipo está en modo solo propuestas ([aplicacion] solo_lectura)")
        propia = (self.registro.get("aplicaciones") or {}).get(plan["id"])
        if not propia:
            raise ErrorAgente("este equipo no tiene registrada ninguna aplicación de ese plan")
        plan["aplicacion"] = propia             # la copia de seguridad es la que guardó él, no la del central
        try:
            r = self.equipo.revertir(plan, str(datos.get("por", "central"))[:120])
        except ErrorAplicacion as e:
            return {"error_aplicacion": str(e), "plan": self._campos(plan)}
        self._anotar("aplicaciones", plan["id"], plan.get("aplicacion"))
        return {"resultado": r, "plan": self._campos(plan)}

    def _ejecutar(self, tarea: dict):
        try:
            res = {"ok": True, "resultado": self.atender(tarea)}
        except ErrorAgente as e:
            log.warning("Tarea %s (%s) rechazada: %s", tarea.get("id"), tarea.get("tipo"), e)
            res = {"ok": False, "error": str(e)}
        except Exception as e:  # noqa: BLE001
            log.exception("Error en la tarea %s (%s)", tarea.get("id"), tarea.get("tipo"))
            res = {"ok": False, "error": f"error en el equipo: {e}"}
        for intento in range(5):
            try:
                self._http("POST", f"/api/agente/resultado/{tarea['id']}", res, timeout=120)
                return
            except Revocado:
                self.revocado = True
                self.parar.set()
                return
            except Exception as e:  # noqa: BLE001
                log.warning("No se pudo enviar el resultado de %s: %s", tarea.get("id"), e)
                self.parar.wait(5 * (intento + 1))

    # ------------------------------------------------------------------ bucles
    def _bucle_inventario(self):
        while not self.parar.is_set():
            try:
                self.enviar_inventario()
            except Revocado as e:
                log.error("%s", e)
                self.revocado = True
                self.parar.set()
                return
            except Exception as e:  # noqa: BLE001
                log.warning("No se pudo enviar el inventario: %s", e)
                self.parar.wait(60)
                continue
            self.parar.wait(float(self.cfg["general"].get("intervalo_horas", 6)) * 3600)

    def ejecutar(self):
        """Bucle principal: alta (si hace falta), inventario periódico y tareas por long-poll."""
        self.dar_de_alta()
        threading.Thread(target=self._bucle_inventario, daemon=True, name="inventario").start()
        espera = 1
        while not self.parar.is_set():
            try:
                r = self._http("GET", "/api/agente/tareas", timeout=60)
                espera = 1
                for t in r.get("tareas") or []:
                    threading.Thread(target=self._ejecutar, args=(t,), daemon=True, name=f"tarea-{t.get('tipo')}").start()
            except Revocado as e:
                log.error("%s. El agente se detiene.", e)
                self.revocado = True
                self.parar.set()
            except Exception as e:  # noqa: BLE001
                log.warning("Sin conexión con el central (%s); reintento en %d s", e, espera)
                self.parar.wait(espera)
                espera = min(espera * 2, 300)
