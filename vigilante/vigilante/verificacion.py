"""Verificación de un plan en una COPIA del proyecto, sin tocar la web.

Pasos:
  1. Copia del proyecto a /datos/pruebas/<plan>/ y repositorio git temporal en la copia.
  2. Cada cambio por orden: `git apply` de su diff y, si tiene comandos de herramienta
     (composer/npm…), ejecutarlos en un contenedor desechable con la herramienta para regenerar
     los lock. Tras cada cambio se hace commit: así cada cambio queda con su diff FINAL
     (incluidos los lock), que es exactamente lo que se aplicará si se aprueba.
  3. Comprobaciones estáticas: JSON válidos, imágenes sin `latest`, ficheros fuera de la raíz…
  4. Pruebas de humo en contenedores de pruebas (si hay acceso a Docker para pruebas): construir
     la imagen de cada servicio configurado, arrancarla, esperar al healthcheck, ejecutar
     comandos de prueba, hacer peticiones HTTP básicas y revisar los logs (errores fatales,
     deprecaciones).
  5. Si algo falla, se repiten las pruebas con la copia SIN cambios para saber si ya fallaba antes.

Seguridad: los comandos que propone Claude solo se ejecutan si pasan una lista blanca
(composer/npm/yarn/bundle/go/pip con argumentos simples), sin shell, con scripts desactivados
y dentro de un contenedor desechable. Los comandos de prueba de los servicios los pone el usuario
en la configuración, nunca Claude.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import logging
import os
import re
import shlex
import shutil
import ssl
import subprocess
import tarfile
import time
import urllib.error
import urllib.request

from .detectar_docker import Docker

log = logging.getLogger("vigilante.verificacion")

IGNORAR_COPIA = shutil.ignore_patterns(".git", "node_modules", "vendor", "target", ".venv", "__pycache__", ".env",
                                       "data", "uploads", "logs", "*.log", ".gradle", "build")
MANIFIESTOS = ["composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock",
               "Gemfile", "Gemfile.lock", "go.mod", "go.sum", "requirements.txt", "pom.xml"]
HERRAMIENTAS_DEFECTO = {"composer": "composer:2", "npm": "node:22-alpine", "yarn": "node:22-alpine",
                        "bundle": "ruby:3.3-alpine", "go": "golang:1.24-alpine", "pip": "python:3.12-slim"}
# composer update paquete --with-all-dependencies / npm install axios@1.12.0 …
PERMITIDO = re.compile(r"^(composer (update|require|install|remove)|npm (install|i|update|uninstall)|"
                       r"yarn (upgrade|add|remove)|bundle (update|lock)|go (get|mod tidy)|"
                       r"pip (install|download))( [\w@/.\-:^~=*,]+)*$")
ERRORES_FATALES = re.compile(r"(PHP Fatal error|Fatal error:|Parse error:|Uncaught |Segmentation fault|"
                             r"\[emerg\]|Exception in thread|panic:)", re.I)
DEPRECACIONES = re.compile(r"(Deprecated:|DeprecationWarning|\[DEP\d+\]|deprecated)", re.I)
GIT_ENV = {"GIT_AUTHOR_NAME": "vigilante", "GIT_AUTHOR_EMAIL": "vigilante@localhost",
           "GIT_COMMITTER_NAME": "vigilante", "GIT_COMMITTER_EMAIL": "vigilante@localhost"}


def ahora():
    return dt.datetime.now().isoformat(timespec="seconds")


def git(cwd, *args, entrada: str | None = None, comprobar=True) -> subprocess.CompletedProcess:
    # GIT_CEILING_DIRECTORIES: que git no use un repositorio de una carpeta superior (si el proyecto
    # está dentro de otro repo, las rutas del diff se interpretarían respecto a ese repo)
    entorno = {**os.environ, **GIT_ENV, "GIT_CEILING_DIRECTORIES": os.path.dirname(os.path.abspath(cwd))}
    r = subprocess.run(["git", *args], cwd=cwd, input=entrada, capture_output=True, text=True,
                       env=entorno, timeout=120)
    if comprobar and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip() or r.stdout.strip()}")
    return r


def tar_de(carpeta: str, prefijo="") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for nombre in sorted(os.listdir(carpeta)):
            if nombre == ".git":
                continue
            t.add(os.path.join(carpeta, nombre), arcname=os.path.join(prefijo, nombre) if prefijo else nombre)
    return buf.getvalue()


def tar_fichero(ruta: str, nombre: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        t.add(ruta, arcname=nombre)
    return buf.getvalue()


def sha256(ruta) -> str | None:
    try:
        with open(ruta, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def ficheros_de_diff(diff: str) -> list[str]:
    out = []
    for m in re.finditer(r"^(?:\+\+\+|---) (?:[ab]/)?(\S+)", diff, re.M):
        if m.group(1) != "/dev/null" and m.group(1) not in out:
            out.append(m.group(1))
    return out


def partir_diff(diff: str) -> list[str]:
    """Separa un diff unificado en un trozo por fichero (lo que empieza en '--- ' seguido de '+++ ')."""
    lineas = diff.splitlines(keepends=True)
    trozos, actual = [], []
    for i, l in enumerate(lineas):
        nuevo_fichero = (l.startswith("--- ") and i + 1 < len(lineas) and lineas[i + 1].startswith("+++ ")) \
            or l.startswith("diff --git")
        # '--- x' dentro de un hunk sería una línea borrada; solo parte si ya hay un hunk acumulado
        if nuevo_fichero and actual and any(x.startswith("@@") for x in actual):
            trozos.append("".join(actual))
            actual = []
        actual.append(l)
    if actual:
        trozos.append("".join(actual))
    return [t if t.endswith("\n") else t + "\n" for t in trozos if t.strip()]


def aplicar_diff(cwd: str, diff: str, solo_comprobar=False) -> str | None:
    """git apply tolerante con diffs escritos a mano (cabeceras @@ con recuentos mal hechos):
    fichero a fichero, primero tal cual y si no con --recount. Devuelve None o el error."""
    errores, modos = [], []
    trozos = partir_diff(diff)
    for t in trozos:
        for opciones in ([], ["--recount"]):
            r = git(cwd, "apply", "--check", *opciones, "-", entrada=t, comprobar=False)
            if r.returncode == 0:
                modos.append(opciones)
                break
        else:
            errores.append(r.stderr.strip())
    if errores or solo_comprobar:
        return "\n".join(errores) or None
    for t, opciones in zip(trozos, modos):
        git(cwd, "apply", *opciones, "-", entrada=t)
    return None


def comando_seguro(cmd: str) -> list[str] | None:
    """Valida un comando de herramienta y le añade las opciones que desactivan scripts."""
    cmd = " ".join(cmd.split())
    if not PERMITIDO.match(cmd):
        return None
    partes = shlex.split(cmd)
    if partes[0] == "composer":
        partes += ["--no-scripts", "--no-plugins", "--no-interaction", "--ignore-platform-req=ext-*"]
    elif partes[0] == "npm":
        partes += ["--ignore-scripts", "--package-lock-only", "--no-audit", "--no-fund"]
    elif partes[0] == "yarn":
        partes += ["--ignore-scripts", "--non-interactive"]
    return partes


class Verificador:
    def __init__(self, cfg: dict, carpeta_datos: str):
        self.cfg = cfg
        self.v = cfg.get("verificacion", {})
        self.base = os.path.join(carpeta_datos, "pruebas")
        sock = self.v.get("docker_host") or ""
        self.docker = Docker(sock) if sock and (sock.startswith(("tcp://", "http://")) or os.path.exists(sock)) \
            else None

    # ------------------------------------------------------------------ capacidades
    def capacidades(self) -> str:
        """Texto para Claude: qué se va a poder comprobar de verdad."""
        if not self.docker:
            return ("Solo verificación estática en una copia (git apply, JSON válidos). NO hay contenedores de "
                    "pruebas: los comandos_herramienta no se podrán ejecutar y los lock no se regenerarán.")
        servicios = ", ".join(s.get("nombre", "?") for s in self.v.get("servicios", [])) or "ninguno configurado"
        return ("Copia del proyecto + contenedores de pruebas. Los comandos_herramienta se ejecutan en: "
                f"{json.dumps(self.herramientas())}. Después se construyen y arrancan estos servicios con "
                f"pruebas de humo (healthcheck, comandos, HTTP): {servicios}.")

    def herramientas(self):
        return {**HERRAMIENTAS_DEFECTO, **(self.v.get("herramientas") or {})}

    # ------------------------------------------------------------------ principal
    def verificar(self, plan: dict, numeros: list[int] | None = None) -> dict:
        """Verifica los cambios `numeros` (todos si None). No toca la web."""
        cambios = [c for c in plan["cambios"] if numeros is None or c["n"] in numeros]
        cambios.sort(key=lambda c: c["n"])
        res = {"fecha": ahora(), "estado": "en_curso", "cambios_verificados": [c["n"] for c in cambios],
               "pasos": [], "por_cambio": {}, "deprecaciones": [], "hashes_originales": {},
               "con_contenedores": bool(self.docker)}
        dir_plan = os.path.join(self.base, f"{plan['id']}-{int(time.time())}")
        copia = os.path.join(dir_plan, "proyecto")
        paso = lambda nombre, ok, detalle="", salida="": res["pasos"].append(  # noqa: E731
            {"paso": nombre, "ok": ok, "detalle": detalle, "salida": salida[-4000:]})
        try:
            shutil.copytree(plan["raiz"], copia, ignore=IGNORAR_COPIA)
            git(copia, "init", "-q")
            git(copia, "add", "-A")
            git(copia, "commit", "-q", "--allow-empty", "-m", "estado actual de producción")
            paso("Copia del proyecto", True, f"{sum(len(f) for _, _, f in os.walk(copia))} ficheros copiados")

            for c in cambios:
                res["por_cambio"][str(c["n"])] = self._cambio(c, plan, copia, res, paso)

            aplicados = [n for n, r in res["por_cambio"].items() if r["aplica"]]
            self._estaticas(copia, paso)
            if self.docker and self.v.get("servicios") and aplicados:
                ok_pruebas = self._pruebas_servicios(plan, copia, res, paso, "con los cambios")
                if not ok_pruebas:
                    base = os.path.join(dir_plan, "sin_cambios")
                    shutil.copytree(plan["raiz"], base, ignore=IGNORAR_COPIA)
                    sub = {"pasos": [], "deprecaciones": []}
                    sub_paso = lambda n, ok, d="", s="": sub["pasos"].append({"paso": n, "ok": ok})  # noqa: E731
                    antes_ok = self._pruebas_servicios(plan, base, sub, sub_paso, "sin cambios")
                    paso("Comparación con la versión actual", None,
                         "La versión ACTUAL pasa las mismas pruebas: el fallo lo provocan los cambios." if antes_ok
                         else "La versión actual TAMBIÉN falla estas pruebas: el resultado no es concluyente.")
            elif not self.docker:
                paso("Pruebas en contenedor", None, "No configuradas: falta acceso a Docker para pruebas "
                                                    "([verificacion].docker_host).")
            fallos = [p for p in res["pasos"] if p["ok"] is False]
            sin_aplicar = [n for n, r in res["por_cambio"].items() if not r["aplica"]]
            if fallos and len(sin_aplicar) < len(cambios) and all(p["paso"].startswith("Cambio") for p in fallos):
                res["estado"] = "parcial"
            elif fallos:
                res["estado"] = "fallo"
            elif not self.docker or not self.v.get("servicios"):
                res["estado"] = "solo_estatica"
            else:
                res["estado"] = "ok"
        except Exception as e:  # noqa: BLE001
            log.exception("Error verificando el plan %s", plan["id"])
            paso("Error interno de la verificación", False, str(e))
            res["estado"] = "fallo"
        finally:
            if not self.v.get("conservar_copias"):
                shutil.rmtree(dir_plan, ignore_errors=True)
        res["fin"] = ahora()
        return res

    # ------------------------------------------------------------------ un cambio
    def _cambio(self, c, plan, copia, res, paso) -> dict:
        r = {"aplica": False, "diff_final": "", "ficheros": [], "comandos": [], "notas": []}
        etiqueta = f"Cambio {c['n']} ({c['titulo'][:60]})"
        diff = (c.get("diff") or "").strip()
        tocados = ficheros_de_diff(diff)
        for f in tocados:
            destino = os.path.realpath(os.path.join(copia, f))
            if not destino.startswith(os.path.realpath(copia) + os.sep) or "/.git/" in destino:
                paso(etiqueta, False, f"el diff toca una ruta fuera del proyecto: {f}")
                return r
        if diff:
            error_directo = aplicar_diff(copia, diff + "\n", solo_comprobar=True)
            if not error_directo:
                aplicar_diff(copia, diff + "\n")
            else:
                # Cada diff de Claude va contra el original: si un cambio anterior tocó el mismo fichero,
                # se intenta una fusión a tres bandas con la versión original guardada en el git de la copia.
                error = fusion_tres_bandas(copia, diff)
                if error:
                    git(copia, "checkout", "--", ".")
                    git(copia, "clean", "-fdq")
                    paso(etiqueta, False, "el diff no se puede aplicar sobre los ficheros actuales",
                         error_directo + "\n" + error)
                    return r
                r["notas"].append("aplicado con fusión a tres bandas sobre los cambios anteriores")
        for cmd in c.get("comandos_herramienta") or []:
            seguro = comando_seguro(cmd)
            if not seguro:
                paso(etiqueta, False, f"comando no permitido (lista blanca): {cmd}")
                git(copia, "checkout", "--", ".")
                git(copia, "clean", "-fdq")
                return r
            if not self.docker:
                r["notas"].append(f"No ejecutado (sin contenedores de pruebas): {cmd}")
                paso(etiqueta, False, f"hace falta ejecutar «{cmd}» para regenerar el lock y no hay contenedores "
                                      "de pruebas; no se puede preparar este cambio con garantías")
                git(copia, "checkout", "--", ".")
                git(copia, "clean", "-fdq")
                return r
            codigo, salida = self._herramienta(seguro, copia, plan)
            r["comandos"].append({"comando": " ".join(seguro), "codigo": codigo, "salida": salida[-3000:]})
            if codigo != 0:
                paso(etiqueta, False, f"«{' '.join(seguro)}» terminó con código {codigo}", salida)
                git(copia, "checkout", "--", ".")
                git(copia, "clean", "-fdq")
                return r
            res["deprecaciones"] += [l.strip() for l in salida.splitlines() if DEPRECACIONES.search(l)][:20]
        git(copia, "add", "-A")
        if not git(copia, "status", "--porcelain").stdout.strip():
            paso(etiqueta, False, "el cambio no modifica nada")
            return r
        git(copia, "commit", "-q", "-m", f"cambio {c['n']}")
        r["diff_final"] = git(copia, "diff", "--binary", "HEAD~1", "HEAD").stdout
        r["ficheros"] = git(copia, "diff", "--name-only", "HEAD~1", "HEAD").stdout.split()
        for f in r["ficheros"]:
            res["hashes_originales"].setdefault(f, sha256(os.path.join(plan["raiz"], f)))
        r["aplica"] = True
        paso(etiqueta, True, "aplicado en la copia: " + ", ".join(r["ficheros"]))
        return r

    def _herramienta(self, cmd: list[str], copia: str, plan: dict) -> tuple[int, str]:
        """Ejecuta composer/npm… en un contenedor desechable con la carpeta del manifiesto."""
        imagen = self.herramientas()[cmd[0]]
        sub = self._carpeta_manifiesto(plan, copia)
        carpeta = os.path.join(copia, sub)
        self.docker.descargar_imagen(imagen)
        cid = self.docker.crear(imagen, entrypoint=["sleep", "1800"], cmd=[],
                                etiquetas={"vigilante.prueba": plan["id"]}, red=self.v.get("red") or None)
        try:
            self.docker.arrancar(cid)
            self.docker.ejecutar_con_codigo(cid, ["mkdir", "-p", "/app"])
            self.docker.subir(cid, "/app", tar_de(carpeta))
            codigo, salida = self.docker.ejecutar_con_codigo(cid, cmd, workdir="/app",
                                                             env={"COMPOSER_ALLOW_SUPERUSER": "1", "CI": "1"})
            if codigo == 0:  # traer de vuelta solo los manifiestos y lock
                for f in MANIFIESTOS:
                    try:
                        datos = self.docker.bajar(cid, f"/app/{f}")
                    except RuntimeError:
                        continue
                    with tarfile.open(fileobj=io.BytesIO(datos)) as t:
                        miembro = t.getmembers()[0]
                        contenido = t.extractfile(miembro)
                        if contenido:
                            with open(os.path.join(carpeta, f), "wb") as fh:
                                fh.write(contenido.read())
            return codigo, salida
        finally:
            self.docker.borrar(cid)

    @staticmethod
    def _carpeta_manifiesto(plan, copia) -> str:
        """Carpeta (relativa) donde está el lock del componente; '.' si no se sabe."""
        detalle = plan["componente"].get("detalle", "")
        if detalle.startswith(plan["raiz"]):
            rel = os.path.relpath(os.path.dirname(detalle.split(" (")[0]), plan["raiz"])
            if os.path.isdir(os.path.join(copia, rel)):
                return rel
        return "."

    # ------------------------------------------------------------------ estáticas
    def _estaticas(self, copia, paso):
        cambiados = git(copia, "diff", "--name-only", "HEAD", git(copia, "rev-list", "--max-parents=0", "HEAD")
                        .stdout.strip()).stdout.split()
        problemas = []
        for f in cambiados:
            ruta = os.path.join(copia, f)
            if not os.path.exists(ruta):
                continue
            if f.endswith(".json"):
                try:
                    with open(ruta) as fh:
                        json.load(fh)
                except ValueError as e:
                    problemas.append(f"{f}: JSON no válido ({e})")
            if os.path.basename(f).startswith("Dockerfile") or re.search(r"(docker-)?compose\.ya?ml$", f):
                with open(ruta, errors="replace") as fh:
                    texto = fh.read()
                if re.search(r"(FROM\s+|image:\s*)\S+:latest\b", texto):
                    problemas.append(f"{f}: usa la etiqueta 'latest' (no reproducible)")
        if cambiados:
            paso("Comprobaciones estáticas", not problemas, "; ".join(problemas) or
                 f"{len(cambiados)} fichero(s) cambiados, sintaxis correcta")

    # ------------------------------------------------------------------ pruebas de humo
    def _pruebas_servicios(self, plan, carpeta, res, paso, etiqueta) -> bool:
        todo_ok = True
        for s in self.v.get("servicios", []):
            nombre = s.get("nombre", "servicio")
            creados, imagen_tmp = [], None
            try:
                if s.get("contexto") is not None or s.get("dockerfile"):
                    ctx = os.path.join(carpeta, s.get("contexto", "."))
                    imagen_tmp = f"vigilante-prueba/{plan['id']}-{nombre}:{int(time.time())}"
                    salida = self.docker.construir(tar_de(ctx), imagen_tmp, s.get("dockerfile", "Dockerfile"))
                    paso(f"[{etiqueta}] {nombre}: construir imagen", True, "imagen construida", salida)
                    imagen = imagen_tmp
                else:
                    imagen = imagen_de_compose(carpeta, s.get("compose", "docker-compose.yml"), nombre)
                    if not imagen:
                        paso(f"[{etiqueta}] {nombre}: imagen", False, "no encuentro la imagen del servicio en el compose")
                        todo_ok = False
                        continue
                    self.docker.descargar_imagen(imagen)
                    paso(f"[{etiqueta}] {nombre}: descargar imagen", True, imagen)
                cid = self.docker.crear(imagen, etiquetas={"vigilante.prueba": plan["id"]},
                                        red=self.v.get("red") or None, hosts_extra=s.get("hosts_extra"),
                                        env=s.get("entorno"))
                creados.append(cid)
                for origen, destino in (s.get("subir") or {}).items():
                    # se sube a «/» con la ruta completa dentro del tar: Docker crea las carpetas que falten
                    ruta = os.path.join(carpeta, origen)
                    if os.path.isdir(ruta):
                        self.docker.subir(cid, "/", tar_de(ruta, prefijo=destino.strip("/")))
                    elif os.path.isfile(ruta):
                        self.docker.subir(cid, "/", tar_fichero(ruta, destino.lstrip("/")))
                self.docker.arrancar(cid)
                ok_arranque, detalle = self._esperar(cid, int(s.get("espera_s", 60)))
                logs = self.docker.logs(cid)
                paso(f"[{etiqueta}] {nombre}: arranque", ok_arranque, detalle, logs)
                todo_ok &= ok_arranque
                if ok_arranque:
                    for cmd in s.get("comandos_prueba", []):
                        codigo, salida = self.docker.ejecutar_con_codigo(cid, shlex.split(cmd), timeout=300)
                        ok = codigo == 0 and not ERRORES_FATALES.search(salida)
                        paso(f"[{etiqueta}] {nombre}: «{cmd}»", ok, f"código {codigo}", salida)
                        res["deprecaciones"] += [l.strip() for l in salida.splitlines() if DEPRECACIONES.search(l)][:10]
                        todo_ok &= ok
                    if s.get("puerto_http"):
                        ok = self._http(cid, s, etiqueta, nombre, paso)
                        todo_ok &= ok
                    logs = self.docker.logs(cid)
                fatales = [l for l in logs.splitlines() if ERRORES_FATALES.search(l)]
                if fatales:
                    paso(f"[{etiqueta}] {nombre}: logs", False, "errores graves en los logs", "\n".join(fatales[:20]))
                    todo_ok = False
                res["deprecaciones"] += [l.strip() for l in logs.splitlines() if DEPRECACIONES.search(l)][:10]
            except Exception as e:  # noqa: BLE001
                paso(f"[{etiqueta}] {nombre}", False, str(e)[:500])
                todo_ok = False
            finally:
                for cid in creados:
                    self.docker.borrar(cid)
                if imagen_tmp:
                    self.docker.borrar_imagen(imagen_tmp)
        res["deprecaciones"] = sorted(set(res["deprecaciones"]))[:30]
        return todo_ok

    def _esperar(self, cid, espera_s) -> tuple[bool, str]:
        limite = time.time() + espera_s
        minimo = time.time() + min(8, espera_s)   # que siga vivo al menos unos segundos
        while time.time() < limite:
            st = self.docker.inspeccionar(cid).get("State", {})
            salud = (st.get("Health") or {}).get("Status")
            if not st.get("Running"):
                return False, f"el contenedor se ha parado (código {st.get('ExitCode')})"
            if salud == "healthy":
                return True, "healthcheck: healthy"
            if salud == "unhealthy":
                return False, "healthcheck: unhealthy"
            if salud is None and time.time() >= minimo:
                return True, "arrancado y en marcha (la imagen no define healthcheck)"
            time.sleep(1.5)
        return False, f"no llegó a estar sano en {espera_s} s"

    def _http(self, cid, s, etiqueta, nombre, paso) -> bool:
        redes = self.docker.inspeccionar(cid).get("NetworkSettings", {}).get("Networks", {})
        red = self.v.get("red")
        ip = (redes.get(red) or {}).get("IPAddress") if red else None
        ip = ip or next((r.get("IPAddress") for r in redes.values() if r.get("IPAddress")), None)
        if not ip:
            paso(f"[{etiqueta}] {nombre}: HTTP", False, "el contenedor no tiene IP alcanzable")
            return False
        ok_total = True
        for ruta in s.get("rutas", ["/"]):
            url = f"http://{ip}:{s['puerto_http']}{ruta}"
            codigo, cuerpo = peticion_http(url)
            ok = codigo is not None and codigo < 500 and not ERRORES_FATALES.search(cuerpo or "")
            paso(f"[{etiqueta}] {nombre}: GET {ruta}", ok, f"HTTP {codigo}", (cuerpo or "")[:1500])
            ok_total &= ok
        return ok_total


def fusion_tres_bandas(copia: str, diff: str) -> str | None:
    """Aplica `diff` sobre la versión ORIGINAL (primer commit de la copia) y fusiona el resultado
    con el estado actual mediante `git merge-file`. Devuelve None si va bien o el error."""
    import tempfile
    base = git(copia, "rev-list", "--max-parents=0", "HEAD").stdout.strip()
    tocados = ficheros_de_diff(diff)
    with tempfile.TemporaryDirectory() as tmp:
        for f in tocados:
            r = git(copia, "show", f"{base}:{f}", comprobar=False)
            if r.returncode == 0:
                os.makedirs(os.path.dirname(os.path.join(tmp, f)) or tmp, exist_ok=True)
                with open(os.path.join(tmp, f), "w") as fh:
                    fh.write(r.stdout)
        error = aplicar_diff(tmp, diff + "\n")
        if error:
            return "tampoco se aplica sobre el original: " + error
        for f in tocados:
            nuevo, actual = os.path.join(tmp, f), os.path.join(copia, f)
            if not os.path.exists(nuevo):              # el diff borra el fichero
                if os.path.exists(actual):
                    os.remove(actual)
                continue
            original = git(copia, "show", f"{base}:{f}", comprobar=False)
            if original.returncode != 0 or not os.path.exists(actual):
                os.makedirs(os.path.dirname(actual), exist_ok=True)
                shutil.copyfile(nuevo, actual)          # fichero nuevo
                continue
            base_tmp = nuevo + ".base"
            with open(base_tmp, "w") as fh:
                fh.write(original.stdout)
            m = subprocess.run(["git", "merge-file", "-p", actual, base_tmp, nuevo], capture_output=True, text=True)
            if m.returncode != 0:
                return f"conflicto al fusionar {f} con los cambios anteriores"
            with open(actual, "w") as fh:
                fh.write(m.stdout)
    return None


def peticion_http(url, timeout=15) -> tuple[int | None, str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "vigilante-prueba"}),
                                    timeout=timeout, context=ctx) as r:
            return r.status, r.read(200_000).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(50_000).decode(errors="replace")
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def imagen_de_compose(carpeta, fichero, servicio) -> str | None:
    """Saca `image:` de un servicio de docker-compose.yml sin depender de PyYAML."""
    ruta = os.path.join(carpeta, fichero)
    if not os.path.isfile(ruta):
        return None
    with open(ruta, errors="replace") as f:
        lineas = f.read().splitlines()
    dentro, sangria = False, None
    for l in lineas:
        if not l.strip() or l.lstrip().startswith("#"):
            continue
        n = len(l) - len(l.lstrip())
        if re.match(rf"\s+{re.escape(servicio)}:\s*$", l):
            dentro, sangria = True, n
            continue
        if dentro and n <= sangria:
            dentro = False
        if dentro:
            m = re.match(r"\s+image:\s*[\"']?([^\"'\s#]+)", l)
            if m:
                return m.group(1)
    return None
