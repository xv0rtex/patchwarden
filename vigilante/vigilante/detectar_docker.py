"""Detección de versiones leyendo la API de Docker por el socket Unix (solo lectura).

Qué se mira de cada contenedor vigilado, de más a menos fiable:
  1. Sondas `exec` (opcional): `php -r 'echo PHP_VERSION;'`, `nginx -v`… -> versión real.
  2. Variables de entorno de la imagen: las imágenes oficiales ponen PHP_VERSION,
     NGINX_VERSION, JAVA_VERSION, NODE_VERSION, TOMCAT_VERSION…
  3. Etiqueta de la imagen: php:8.2.10-fpm -> php 8.2.10 (si no es 'latest').
"""
from __future__ import annotations

import http.client
import json
import logging
import re
import socket
import struct
import urllib.parse

from .catalogo import RUNTIMES, limpiar_version, runtime_por_imagen
from .modelo import Componente

log = logging.getLogger("vigilante.docker")


class _ConexionUnix(http.client.HTTPConnection):
    def __init__(self, ruta, timeout=20):
        super().__init__("localhost", timeout=timeout)
        self.ruta = ruta

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.ruta)


class Docker:
    def __init__(self, socket_ruta="/var/run/docker.sock"):
        self.ruta = socket_ruta

    def _conexion(self, timeout=20):
        # "tcp://docker-proxy:2375" -> proxy de solo lectura (recomendado); si no, socket Unix
        if self.ruta.startswith(("tcp://", "http://")):
            hostpuerto = self.ruta.split("://", 1)[1].rstrip("/")
            return http.client.HTTPConnection(hostpuerto, timeout=timeout)
        return _ConexionUnix(self.ruta, timeout=timeout)

    def peticion(self, metodo, ruta, datos: bytes | None = None, tipo="application/json", timeout=20):
        """Petición cruda: devuelve (código, bytes). Lanza RuntimeError si el código es >= 400."""
        c = self._conexion(timeout)
        try:
            c.request(metodo, ruta, body=datos, headers={"Content-Type": tipo, "Host": "docker"})
            r = c.getresponse()
            raw = r.read()
            if r.status >= 400:
                raise RuntimeError(f"Docker API {r.status} en {metodo} {ruta.split('?')[0]}: {raw[:300]!r}")
            return r.status, raw
        finally:
            c.close()

    def _llamar(self, metodo, ruta, cuerpo=None, crudo=False, timeout=20):
        datos = json.dumps(cuerpo).encode() if cuerpo is not None else None
        _, raw = self.peticion(metodo, ruta, datos, timeout=timeout)
        if crudo:
            return raw
        return json.loads(raw) if raw else None

    def contenedores(self, etiqueta=None):
        q = ""
        if etiqueta:
            q = "?filters=" + urllib.parse.quote(json.dumps({"label": [etiqueta]}))
        return self._llamar("GET", "/containers/json" + q)

    def inspeccionar(self, id_):
        return self._llamar("GET", f"/containers/{id_}/json")

    def ejecutar(self, id_, cmd) -> str:
        """docker exec sin TTY; devuelve stdout+stderr (java -version escribe en stderr)."""
        ex = self._llamar("POST", f"/containers/{id_}/exec",
                          {"Cmd": cmd, "AttachStdout": True, "AttachStderr": True, "Tty": False})
        raw = self._llamar("POST", f"/exec/{ex['Id']}/start", {"Detach": False, "Tty": False}, crudo=True)
        return _desmultiplexar(raw)

    def ejecutar_con_codigo(self, id_, cmd, workdir=None, env=None, timeout=900) -> tuple[int, str]:
        cfg = {"Cmd": cmd, "AttachStdout": True, "AttachStderr": True, "Tty": False}
        if workdir:
            cfg["WorkingDir"] = workdir
        if env:
            cfg["Env"] = [f"{k}={v}" for k, v in env.items()]
        ex = self._llamar("POST", f"/containers/{id_}/exec", cfg)
        raw = self._llamar("POST", f"/exec/{ex['Id']}/start", {"Detach": False, "Tty": False}, crudo=True,
                           timeout=timeout)
        codigo = (self._llamar("GET", f"/exec/{ex['Id']}/json") or {}).get("ExitCode")
        return (codigo if codigo is not None else -1), _desmultiplexar(raw)

    # ---- operaciones de escritura: solo las usa el verificador/aplicador, con su propio acceso
    def construir(self, contexto_tar: bytes, etiqueta: str, dockerfile="Dockerfile", timeout=1800) -> str:
        q = urllib.parse.urlencode({"t": etiqueta, "dockerfile": dockerfile, "rm": 1, "forcerm": 1, "pull": 1})
        _, raw = self.peticion("POST", f"/build?{q}", contexto_tar, "application/x-tar", timeout=timeout)
        lineas, error = [], None
        for l in raw.decode(errors="replace").splitlines():
            try:
                d = json.loads(l)
            except ValueError:
                continue
            if d.get("error"):
                error = d["error"]
            if d.get("stream"):
                lineas.append(d["stream"])
        salida = "".join(lineas)
        if error:
            raise RuntimeError(f"fallo al construir: {error}\n{salida[-3000:]}")
        return salida

    def descargar_imagen(self, imagen: str, timeout=900):
        nombre, _, tag = imagen.rpartition(":") if ":" in imagen.split("/")[-1] else (imagen, "", "latest")
        q = urllib.parse.urlencode({"fromImage": nombre, "tag": tag})
        _, raw = self.peticion("POST", f"/images/create?{q}", timeout=timeout)
        if b'"error"' in raw:
            raise RuntimeError(f"no se pudo descargar {imagen}: {raw[-300:]!r}")

    def crear(self, imagen, nombre=None, cmd=None, entrypoint=None, env=None, etiquetas=None, red=None,
              hosts_extra=None) -> str:
        cfg = {"Image": imagen, "Labels": etiquetas or {}, "Env": [f"{k}={v}" for k, v in (env or {}).items()],
               "HostConfig": {"ExtraHosts": hosts_extra or [], "Memory": 1024 * 1024 * 1024}}
        if cmd is not None:
            cfg["Cmd"] = cmd
        if entrypoint is not None:
            cfg["Entrypoint"] = entrypoint
        if red:
            cfg["HostConfig"]["NetworkMode"] = red
        q = "?" + urllib.parse.urlencode({"name": nombre}) if nombre else ""
        return self._llamar("POST", f"/containers/create{q}", cfg)["Id"]

    def arrancar(self, id_):
        self._llamar("POST", f"/containers/{id_}/start")

    def subir(self, id_, ruta_destino, tar_bytes: bytes):
        q = urllib.parse.urlencode({"path": ruta_destino})
        self.peticion("PUT", f"/containers/{id_}/archive?{q}", tar_bytes, "application/x-tar", timeout=120)

    def bajar(self, id_, ruta) -> bytes:
        q = urllib.parse.urlencode({"path": ruta})
        return self.peticion("GET", f"/containers/{id_}/archive?{q}", timeout=120)[1]

    def logs(self, id_) -> str:
        raw = self._llamar("GET", f"/containers/{id_}/logs?stdout=1&stderr=1&tail=400", crudo=True)
        return _desmultiplexar(raw)

    def borrar(self, id_):
        try:
            self.peticion("DELETE", f"/containers/{id_}?force=1&v=1")
        except RuntimeError as e:
            log.debug("borrar %s: %s", id_, e)

    def borrar_imagen(self, imagen):
        try:
            self.peticion("DELETE", f"/images/{urllib.parse.quote(imagen, safe='')}?force=1")
        except RuntimeError as e:
            log.debug("borrar imagen %s: %s", imagen, e)

    def etiquetar(self, imagen, repo, tag):
        q = urllib.parse.urlencode({"repo": repo, "tag": tag})
        self.peticion("POST", f"/images/{urllib.parse.quote(imagen, safe='')}/tag?{q}")

    def propio(self) -> dict | None:
        """El contenedor del propio vigilante (su hostname es el id corto)."""
        try:
            return self.inspeccionar(socket.gethostname())
        except RuntimeError:
            return None


def _desmultiplexar(raw: bytes) -> str:
    """El flujo de exec sin TTY va en tramas: [tipo,0,0,0,tamaño(4 bytes)] + datos."""
    salida, i = [], 0
    while i + 8 <= len(raw):
        tam = struct.unpack(">I", raw[i + 4:i + 8])[0]
        salida.append(raw[i + 8:i + 8 + tam])
        i += 8 + tam
    if not salida:  # no venía multiplexado
        return raw.decode(errors="replace")
    return b"".join(salida).decode(errors="replace")


def es_del_vigilante(c: dict, todos: list[dict]) -> bool:
    """El propio vigilante y su stack (proxies…) no se vigilan a sí mismos."""
    yo = socket.gethostname()
    propio = next((x for x in todos if x["Id"].startswith(yo)), None)
    etiquetas = c.get("Labels") or {}
    proyectos = {"vigilante"}
    if propio:
        proyectos.add((propio.get("Labels") or {}).get("com.docker.compose.project"))
    return (c is propio or etiquetas.get("vigilante.ignorar") == "true"
            or etiquetas.get("com.docker.compose.project") in proyectos - {None})


def elegir_contenedores(docker: Docker, cfg_det: dict) -> list[dict]:
    """Por nombre si se han configurado; si no, por etiqueta vigilante.vigilar=true;
    si no hay ninguno, el resto de contenedores del mismo proyecto docker compose."""
    todos = docker.contenedores()
    if cfg_det.get("todos"):
        return [c for c in todos if not es_del_vigilante(c, todos)]
    nombres = set(cfg_det.get("contenedores") or [])
    if nombres:
        return [c for c in todos if any(n.lstrip("/") in nombres for n in c.get("Names", []))
                or c["Id"][:12] in nombres]
    marcados = [c for c in todos if (c.get("Labels") or {}).get("vigilante.vigilar") == "true"]
    if marcados:
        return marcados
    if cfg_det.get("mismo_proyecto_compose"):
        yo = socket.gethostname()  # dentro de Docker el hostname es el id corto del contenedor
        propio = next((c for c in todos if c["Id"].startswith(yo)), None)
        if propio:
            proyecto = (propio.get("Labels") or {}).get("com.docker.compose.project")
            if proyecto:
                return [c for c in todos if c["Id"] != propio["Id"]
                        and (c.get("Labels") or {}).get("com.docker.compose.project") == proyecto]
    return []


def detectar(cfg_det: dict) -> list[Componente]:
    docker = Docker(cfg_det.get("docker_socket", "/var/run/docker.sock"))
    try:
        elegidos = elegir_contenedores(docker, cfg_det)
    except (OSError, RuntimeError) as e:
        log.warning("No se puede hablar con Docker (%s). ¿Está montado el socket?", e)
        return []
    if not elegidos:
        log.warning("No hay contenedores que vigilar: pon la etiqueta vigilante.vigilar=true "
                    "o la lista [deteccion].contenedores")
    comps: list[Componente] = []
    for c in elegidos:
        info = docker.inspeccionar(c["Id"])
        comps += componentes_de_contenedor(info, docker if cfg_det.get("exec_sondas") else None)
    return comps


def componentes_de_contenedor(info: dict, docker: Docker | None = None) -> list[Componente]:
    nombre = info.get("Name", "").lstrip("/") or info.get("Id", "")[:12]
    imagen = info.get("Config", {}).get("Image", "")
    env = dict(e.split("=", 1) for e in info.get("Config", {}).get("Env") or [] if "=" in e)
    comps = []

    # 1) variables de entorno de imágenes oficiales
    for rt, datos in RUNTIMES.items():
        for var in datos["env"]:
            v = limpiar_version(env.get(var, ""))
            if v:
                comps.append(Componente(rt, v, "runtime", origen="env",
                                        detalle=f"{var}={env[var]}", contenedor=nombre))
    # 2) etiqueta de la imagen
    rt, v = runtime_por_imagen(imagen)
    if rt and v and not any(x.nombre == rt for x in comps):
        comps.append(Componente(rt, v, "runtime", origen="imagen", detalle=imagen, contenedor=nombre))
    # 3) sondas exec (sustituyen a lo anterior si funcionan)
    if docker:
        for rt in {x.nombre for x in comps} | ({rt} if rt else set()):
            sonda = RUNTIMES.get(rt, {}).get("sonda")
            if not sonda:
                continue
            try:
                salida = docker.ejecutar(info["Id"], sonda)
            except Exception as e:  # noqa: BLE001 - la sonda es opcional
                log.debug("Sonda %s en %s falló: %s", sonda, nombre, e)
                continue
            m = re.search(RUNTIMES[rt]["regex"], salida) or re.search(r"(\d+\.\d+\.\d+)", salida)
            if m:
                comps = [x for x in comps if x.nombre != rt]
                comps.append(Componente(rt, m.group(1), "runtime", origen="exec",
                                        detalle=" ".join(sonda), contenedor=nombre))
    etiquetas = info.get("Config", {}).get("Labels") or {}
    app = etiquetas.get("com.docker.compose.project") or nombre
    for c in comps:
        c.app = app
    return comps


def mapa_apps(cfg_det: dict) -> dict[str, str]:
    """{carpeta del proyecto en el host: nombre de la app}, leído de las etiquetas de docker compose."""
    try:
        docker = Docker(cfg_det.get("docker_socket", "/var/run/docker.sock"))
        out = {}
        for c in docker.contenedores():
            et = c.get("Labels") or {}
            if et.get("com.docker.compose.project.working_dir") and et.get("com.docker.compose.project"):
                out[et["com.docker.compose.project.working_dir"]] = et["com.docker.compose.project"]
        return out
    except (OSError, RuntimeError):
        return {}
