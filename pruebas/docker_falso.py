"""Simula la API de Docker en un socket Unix para probar el vigilante sin Docker.

Contenedores «de producción» simulados: nginx:1.25.3 y php:8.1.2-fpm (con las variables de
entorno reales de las imágenes oficiales). También simula lo que usa el verificador:
build, create/start, exec (con código de salida), subir/bajar ficheros (archive), logs y
borrado. `composer update <paquete>` dentro de un contenedor de herramientas modifica de
verdad el composer.lock subido (cambia la versión del paquete), para que el verificador
tenga un lock regenerado que comparar.

Para provocar fallos: una imagen cuyo Dockerfile contenga «ROMPE» no construye, y una cuyo
FROM sea de php 9 arranca pero «php -l» falla.

Uso: python3 docker_falso.py /tmp/docker-falso.sock
"""
import io
import json
import os
import re
import socketserver
import struct
import sys
import tarfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler

CONTENEDORES = {
    "aaa111": {"Name": "/ejemplo-nginx-1", "Image": "nginx:1.25.3",
               "Env": ["PATH=/usr/bin", "NGINX_VERSION=1.25.3", "NJS_VERSION=0.8.2", "PKG_RELEASE=1~bookworm"],
               "sonda": "nginx version: nginx/1.25.3\n", "etiquetas": True,
               "puertos": [{"PrivatePort": 80, "PublicPort": 8000, "Type": "tcp"}]},
    "bbb222": {"Name": "/ejemplo-php-1", "Image": "ejemplo-php",   # imagen construida: sin etiqueta útil
               "Env": ["PHPIZE_DEPS=autoconf", "PHP_VERSION=8.1.2", "PHP_URL=https://www.php.net/x.tar.xz"],
               "sonda": "8.1.2", "etiquetas": True},
    "ccc333": {"Name": "/otra-cosa", "Image": "redis:7.2.4", "Env": ["REDIS_VERSION=7.2.4"], "sonda": ""},
}
IMAGENES = {}       # etiqueta -> {"from": ..., "dockerfile": ...}
CREADOS = {}        # id -> {"imagen", "ficheros": {ruta: bytes}, "logs": str, "corriendo": bool}
EXECS = {}
REGISTRO = []       # todas las llamadas, para que las pruebas comprueben qué se hizo
cerrojo = threading.Lock()


def _tar(ficheros: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for nombre, datos in ficheros.items():
            info = tarfile.TarInfo(nombre)
            info.size = len(datos)
            t.addfile(info, io.BytesIO(datos))
    return buf.getvalue()


def _exec(c, cmd: list) -> tuple[int, str]:
    linea = " ".join(cmd)
    imagen = c["imagen"]
    if cmd[0] == "mkdir":
        return 0, ""
    if cmd[0] == "composer":
        m = re.search(r"(?:update|require) (\S+)", linea)
        lock = c["ficheros"].get("/app/composer.lock")
        if m and lock:
            paquete = m.group(1).split(":")[0]
            d = json.loads(lock)
            for p in d.get("packages", []):
                if p["name"] == paquete:
                    p["version"] = {"twig/twig": "v3.27.0", "guzzlehttp/guzzle": "7.4.5"}.get(paquete, "9.9.9")
            c["ficheros"]["/app/composer.lock"] = json.dumps(d, indent=4).encode()
            return 0, f"Loading composer repositories\nUpgrading {paquete}\nWriting lock file\n"
        return 1, "composer.lock no encontrado"
    if cmd[0] == "npm":
        return 0, "up to date\n"
    if cmd[0] == "php":
        rompe = "9." in imagen.get("from", "")
        if "-l" in cmd:
            return (255, "PHP Parse error: syntax error") if rompe else (0, "No syntax errors detected")
        if "-v" in cmd:
            v = re.search(r"php:(\d[\w.]*)", imagen.get("from", "")) or re.search(r"(\d+\.\d+\.\d+)", imagen.get("from", ""))
            return 0, f"PHP {v.group(1) if v else '8.1.2'} (cli)\n"
        return 0, "<h1>Web de ejemplo</h1>"
    if cmd[0] == "nginx":
        return 0, "nginx: configuration file /etc/nginx/nginx.conf test is successful"
    return 0, ""


def etiquetas_de(c):
    if not c.get("etiquetas"):
        return {}
    pr = c.get("proyecto", "ejemplo")
    return {"vigilante.vigilar": "true", "com.docker.compose.project": pr,
            "com.docker.compose.project.working_dir": f"/srv/{pr}",
            "com.docker.compose.project.config_files": f"/srv/{pr}/docker-compose.yml"}


class H(BaseHTTPRequestHandler):
    puerto_http = 0         # puerto del servidor HTTP local que hace de «web de pruebas»

    def address_string(self):
        return "unix"

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        d = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(d)))
        self.end_headers()
        self.wfile.write(d)

    def _crudo(self, datos: bytes, tipo="application/octet-stream", code=200):
        self.send_response(code)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(datos)))
        self.end_headers()
        if datos:
            try:
                self.wfile.write(datos)
            except BrokenPipeError:
                pass

    def _cuerpo(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        ruta, q = url.path, urllib.parse.parse_qs(url.query)
        REGISTRO.append(("GET", ruta))
        if ruta == "/containers/json":
            def etiquetas(c):
                if not c.get("etiquetas"):
                    return {}
                return etiquetas_de(c)
            return self._json([{"Id": k * 10, "Names": [c["Name"]], "Image": c["Image"], "Labels": etiquetas(c),
                                "Ports": c.get("puertos", []),
                                "NetworkSettings": {"Networks": {"ejemplo_mi-red": {}} if c.get("etiquetas")
                                                    else {"bridge": {}}}} for k, c in CONTENEDORES.items()]
                               + [{"Id": "vig000000000", "Names": ["/vigilante-vigilante-1"], "Image": "vigilante:local",
                                   "Labels": {"com.docker.compose.project": "vigilante"}, "Ports": [],
                                   "NetworkSettings": {"Networks": {"vigilante_default": {}}}}])
        m = re.match(r"/containers/([^/]+)/(json|logs|archive)$", ruta)
        if m:
            id_, que = m.groups()
            if id_ in CREADOS:
                c = CREADOS[id_]
                if que == "json":
                    return self._json({"Id": id_, "Name": "/prueba", "Image": "sha256:prueba",
                                       "Config": {"Image": c["imagen"]["tag"], "Env": []},
                                       "State": {"Running": c["corriendo"], "ExitCode": 0,
                                                 "Health": {"Status": "healthy"}},
                                       "NetworkSettings": {"Networks": {"prueba": {"IPAddress": "127.0.0.1"}}}})
                if que == "logs":
                    t = c["logs"].encode()
                    return self._crudo(bytes([1, 0, 0, 0]) + struct.pack(">I", len(t)) + t)
                ruta_f = q["path"][0]
                if ruta_f not in c["ficheros"]:
                    return self._json({"message": "no such file"}, 404)
                return self._crudo(_tar({os.path.basename(ruta_f): c["ficheros"][ruta_f]}), "application/x-tar")
            clave = next((k for k, c in CONTENEDORES.items() if id_.startswith(k) or c["Name"].lstrip("/") == id_), None)
            if not clave:
                return self._json({"message": "no such container"}, 404)
            c = CONTENEDORES[clave]
            return self._json({"Id": clave * 10, "Name": c["Name"], "Image": f"sha256:{clave}",
                               "Config": {"Image": c["Image"], "Env": c["Env"], "Labels": etiquetas_de(c)}})
        m = re.match(r"/exec/([^/]+)/json$", ruta)
        if m:
            return self._json({"ExitCode": EXECS[m.group(1)].get("codigo", 0)})
        self._json({"message": "no"}, 404)

    def do_PUT(self):
        url = urllib.parse.urlparse(self.path)
        m = re.match(r"/containers/([^/]+)/archive$", url.path)
        REGISTRO.append(("PUT", url.path))
        if m and m.group(1) in CREADOS:
            destino = urllib.parse.parse_qs(url.query)["path"][0]
            with tarfile.open(fileobj=io.BytesIO(self._cuerpo())) as t:
                for miembro in t.getmembers():
                    if miembro.isfile():
                        CREADOS[m.group(1)]["ficheros"][os.path.join(destino, miembro.name)] = t.extractfile(miembro).read()
            return self._crudo(b"")
        self._json({"message": "no"}, 404)

    def do_DELETE(self):
        REGISTRO.append(("DELETE", self.path))
        m = re.match(r"/containers/([^/?]+)", self.path)
        if m:
            CREADOS.pop(m.group(1), None)
        self._crudo(b"", code=204)

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        ruta, q = url.path, urllib.parse.parse_qs(url.query)
        cuerpo = self._cuerpo()
        REGISTRO.append(("POST", ruta))
        if ruta == "/build":
            with tarfile.open(fileobj=io.BytesIO(cuerpo)) as t:
                df = t.extractfile(q.get("dockerfile", ["Dockerfile"])[0]).read().decode()
            if "ROMPE" in df:
                return self._crudo(b'{"stream":"Step 1/3"}\n{"error":"la construccion ha fallado (simulado)"}\n')
            desde = re.search(r"FROM\s+(\S+)", df).group(1)
            IMAGENES[q["t"][0]] = {"tag": q["t"][0], "from": desde}
            return self._crudo(f'{{"stream":"Step 1/3 : FROM {desde}\\n"}}\n{{"stream":"Successfully built\\n"}}\n'.encode())
        if ruta == "/images/create":
            nombre = f"{q['fromImage'][0]}:{q['tag'][0]}"
            IMAGENES.setdefault(nombre, {"tag": nombre, "from": nombre})
            return self._crudo(b'{"status":"Downloaded"}\n')
        m = re.match(r"/images/(.+)/tag$", ruta)
        if m:
            return self._crudo(b"", code=201)
        if ruta == "/containers/create":
            cfg = json.loads(cuerpo)
            img = IMAGENES.get(cfg["Image"]) or {"tag": cfg["Image"], "from": cfg["Image"]}
            id_ = f"prueba{len(CREADOS) + len(REGISTRO)}"
            CREADOS[id_] = {"imagen": img, "ficheros": {}, "corriendo": False,
                            "logs": "NOTICE: fpm is running\nNOTICE: ready to handle connections\n"}
            return self._json({"Id": id_}, 201)
        m = re.match(r"/containers/([^/]+)/(start|exec)$", ruta)
        if m:
            id_, que = m.groups()
            if que == "start":
                CREADOS[id_]["corriendo"] = True
                return self._crudo(b"", code=204)
            cfg = json.loads(cuerpo)
            eid = f"exec{len(EXECS)}"
            EXECS[eid] = {"contenedor": id_, "cmd": cfg["Cmd"]}
            return self._json({"Id": eid}, 201)
        m = re.match(r"/exec/([^/]+)/start$", ruta)
        if m:
            ex = EXECS[m.group(1)]
            if ex["contenedor"] in CREADOS:
                codigo, salida = _exec(CREADOS[ex["contenedor"]], ex["cmd"])
            else:  # sondas de detección sobre los contenedores «de producción»
                c = next(c for k, c in CONTENEDORES.items() if ex["contenedor"].startswith(k))
                codigo, salida = 0, c["sonda"]
            ex["codigo"] = codigo
            datos = salida.encode()
            return self._crudo(bytes([2, 0, 0, 0]) + struct.pack(">I", len(datos)) + datos,
                               "application/vnd.docker.raw-stream")
        self._json({"message": "no"}, 404)


class Servidor(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def arrancar(ruta):
    if os.path.exists(ruta):
        os.remove(ruta)
    srv = Servidor(ruta, H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    ruta = sys.argv[1]
    if os.path.exists(ruta):
        os.remove(ruta)
    Servidor(ruta, H).serve_forever()
