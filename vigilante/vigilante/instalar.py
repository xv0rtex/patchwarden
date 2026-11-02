"""Autoconfiguración: descubre las apps que ya corren en Docker y genera la instalación del vigilante.

Lo ejecuta instalar.sh dentro de un contenedor efímero (con el socket de Docker en solo lectura
y red del host). El usuario no edita nada: de las etiquetas que docker compose pone a cada
contenedor se saca dónde está el proyecto, qué ficheros compose usa, a qué redes pertenece y qué
puertos publica.

Dos papeles (--rol):
  central  panel (dashboard) + Claude; vigila también este servidor y recibe a los agentes
  agente   cliente de un panel central: sin panel ni Claude, solo conexiones salientes

Genera en --salida:
  docker-compose.yml   el vigilante (o el agente), su proxy de Docker de solo lectura y las redes de tus apps
  vigilante.toml       configuración (rutas de los proyectos, puerto, modo)
  .env                 secretos (central: contraseña del panel, Telegram, Claude; agente: URL y código de alta)
  desplegar.sh         solo con --permitir-aplicar: redespliega la app aprobada
Es idempotente: al ejecutarlo otra vez conserva contraseñas y claves y refresca el descubrimiento.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shlex
import socket
import sys

from .detectar_docker import Docker, es_del_vigilante

C = "com.docker.compose.project"
CWD = "com.docker.compose.project.working_dir"
CFG = "com.docker.compose.project.config_files"
REDES_ESPECIALES = {"bridge", "host", "none"}
CLAVES_ENV = ["TELEGRAM_TOKEN", "TELEGRAM_CHAT_ID", "CLAUDE_CODE_OAUTH_TOKEN", "NVD_API_KEY",
              "VIGILANTE_PANEL_USUARIO", "VIGILANTE_PANEL_CLAVE", "VIGILANTE_PANEL_TOKEN", "VIGILANTE_PUERTO"]
CLAVES_ENV_AGENTE = ["VIGILANTE_CENTRAL", "VIGILANTE_CODIGO", "VIGILANTE_CENTRAL_PERMITIR_HTTP"]
IMAGEN = {"central": "vigilante:local", "agente": "vigilante-agente:local"}
PROYECTO = {"central": "vigilante", "agente": "vigilante-agente"}


def q(texto) -> str:
    """Cadena YAML/TOML entre comillas (JSON es un subconjunto válido de ambos)."""
    return json.dumps(str(texto), ensure_ascii=False)


def leer_env(ruta) -> dict:
    out = {}
    try:
        for l in open(ruta, encoding="utf-8"):
            if "=" in l and not l.lstrip().startswith("#"):
                k, _, v = l.rstrip("\n").partition("=")
                out[k.strip()] = v
    except OSError:
        pass
    return out


def puerto_libre(inicio: int, ocupados: set[int]) -> int:
    for p in range(inicio, inicio + 200):
        if p in ocupados:
            continue
        s = socket.socket()
        try:
            s.bind(("0.0.0.0", p))
            return p
        except OSError:
            continue
        finally:
            s.close()
    raise SystemExit("No encuentro un puerto libre cerca de %d" % inicio)


def ip_local() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "IP-DEL-SERVIDOR"
    finally:
        s.close()


def descubrir(docker: Docker, solo: set[str]) -> dict:
    todos = docker.contenedores()
    cands = [c for c in todos if not es_del_vigilante(c, todos)]
    if solo:
        cands = [c for c in cands if any(n.lstrip("/") in solo for n in c.get("Names", []))
                 or (c.get("Labels") or {}).get(C) in solo]
    proyectos: dict[str, dict] = {}
    redes: list[str] = []
    publicados: set[int] = set()
    objetivo = None
    objetivos: dict[str, tuple] = {}          # proyecto -> (contenedor, puerto interno)
    for c in cands:
        et = c.get("Labels") or {}
        nombre = c["Names"][0].lstrip("/") if c.get("Names") else c["Id"][:12]
        for n in (c.get("NetworkSettings") or {}).get("Networks", {}):
            if n not in REDES_ESPECIALES and n not in redes:
                redes.append(n)
        for pt in c.get("Ports") or []:
            if pt.get("PublicPort"):
                publicados.add(int(pt["PublicPort"]))
                if pt.get("Type", "tcp") == "tcp":
                    if objetivo is None:
                        objetivo = (nombre, int(pt["PrivatePort"]), int(pt["PublicPort"]))
                    objetivos.setdefault(et.get(C, nombre), (nombre, int(pt["PrivatePort"]), int(pt["PublicPort"])))
        if et.get(CWD):
            p = proyectos.setdefault(et.get(C, nombre), {"dir": et[CWD], "ficheros": [], "contenedores": []})
            p["contenedores"].append(nombre)
            for f in (et.get(CFG) or "").split(","):
                if f and f not in p["ficheros"]:
                    p["ficheros"].append(f)
    sin_proyecto = [c["Names"][0].lstrip("/") for c in cands if not (c.get("Labels") or {}).get(CWD)]
    return {"contenedores": cands, "proyectos": proyectos, "redes": redes, "publicados": publicados,
            "objetivo": objetivo, "objetivos": objetivos, "sin_proyecto": sin_proyecto}


def _escribir_env(a, env: dict):
    ruta = os.path.join(a.salida, ".env")
    with open(ruta, "w") as f:
        f.write("# Generado por el instalador. Se conserva al volver a ejecutarlo o al actualizar.\n")
        f.writelines(f"{k}={v}\n" for k, v in env.items())
    os.chmod(ruta, 0o600)


def _env_agente(a, previo: dict) -> dict:
    env = {k: previo.get(k, "") for k in CLAVES_ENV_AGENTE}
    for k in CLAVES_ENV_AGENTE:
        if os.environ.get(k):
            env[k] = os.environ[k]
    if getattr(a, "central", ""):
        env["VIGILANTE_CENTRAL"] = a.central.rstrip("/")
    if getattr(a, "codigo", ""):
        env["VIGILANTE_CODIGO"] = a.codigo
    if getattr(a, "permitir_http", False):
        env["VIGILANTE_CENTRAL_PERMITIR_HTTP"] = "1"
    if not env["VIGILANTE_CENTRAL"]:
        raise SystemExit("Falta la URL del panel central (--central https://...).")
    return env


def generar(a, d: dict, previo: dict) -> dict:
    os.makedirs(a.salida, exist_ok=True)
    rol = getattr(a, "rol", "central")
    agente = rol == "agente"
    if agente:
        a.tunel = False
        env = _env_agente(a, previo)
        puerto = 0
        _escribir_env(a, env)
    else:
        env, puerto = _env_central(a, d, previo)
    dirs, toml = _toml(a, d, puerto, agente)
    open(os.path.join(a.salida, "vigilante.toml"), "w").write("\n".join(toml) + "\n")
    open(os.path.join(a.salida, "docker-compose.yml"), "w").write("\n".join(_compose(a, d, dirs, puerto, rol)))
    if a.permitir_aplicar:
        _desplegar_sh(a, d)
    if agente:
        return {"rol": rol, "central": env["VIGILANTE_CENTRAL"], "alta": bool(env["VIGILANTE_CODIGO"])}
    return {"rol": rol, "puerto": puerto, "url": env["VIGILANTE_PANEL_URL"], "usuario": env["VIGILANTE_PANEL_USUARIO"],
            "clave": env["VIGILANTE_PANEL_CLAVE"], "telegram": bool(env["TELEGRAM_TOKEN"] and env["TELEGRAM_CHAT_ID"]),
            "claude": bool(env["CLAUDE_CODE_OAUTH_TOKEN"])}


def _env_central(a, d: dict, previo: dict):
    puerto = int(previo.get("VIGILANTE_PUERTO") or a.puerto or 0) or puerto_libre(8090, d["publicados"])
    env = {k: previo.get(k, "") for k in CLAVES_ENV}
    for k in ("TELEGRAM_TOKEN", "TELEGRAM_CHAT_ID", "CLAUDE_CODE_OAUTH_TOKEN", "NVD_API_KEY"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    env["VIGILANTE_PANEL_USUARIO"] = env["VIGILANTE_PANEL_USUARIO"] or "admin"
    env["VIGILANTE_PANEL_CLAVE"] = env["VIGILANTE_PANEL_CLAVE"] or secrets.token_urlsafe(12)
    env["VIGILANTE_PANEL_TOKEN"] = env["VIGILANTE_PANEL_TOKEN"] or secrets.token_urlsafe(24)
    env["VIGILANTE_PUERTO"] = str(puerto)
    # la URL pública (p. ej. la del túnel) se conserva si ya existía
    env["VIGILANTE_PANEL_URL"] = previo.get("VIGILANTE_PANEL_URL") if (a.tunel and previo.get("VIGILANTE_PANEL_URL")) \
        else f"http://{'127.0.0.1' if a.local else ip_local()}:{puerto}"
    _escribir_env(a, env)
    return env, puerto


def _toml(a, d: dict, puerto: int, agente: bool):
    dirs = sorted({p["dir"] for p in d["proyectos"].values()})
    nombre_web = ", ".join(sorted(d["proyectos"])[:3]) or socket.gethostname()
    objetivo = d["objetivo"]

    toml = [f"[general]\nnombre_web = {q(nombre_web)}\n",
            "[deteccion]\ndocker = true\ntodos = true\nexec_sondas = false",
            "rutas_proyecto = [" + ", ".join(q(x) for x in dirs) + "]\n",
            "[deteccion.apps]\n" + "".join(f"{q(p['dir'])} = {q(n)}\n" for n, p in sorted(d["proyectos"].items())),
            "[mantenimiento]\nmodo = \"off\"\n",
            "[panel]\nactivo = false\n" if agente else f"[panel]\npuerto = {puerto}\n",
            f"[aplicacion]\nsolo_lectura = {'false' if a.permitir_aplicar else 'true'}"]
    if objetivo:
        toml.append(f"url_salud = {q(f'http://{objetivo[0]}:{objetivo[1]}')}")
    if a.permitir_aplicar:
        toml.append('comando_despliegue = "/desplegar.sh"\nrollback_automatico = true')
    salud = [f"{q(d['proyectos'][n]['dir'])} = {q(f'http://{o[0]}:{o[1]}')}" for n, o in sorted(d["objetivos"].items())
             if n in d["proyectos"]]
    if salud:
        toml.append("\n[aplicacion.salud]\n" + "\n".join(salud))
    return dirs, toml


def _compose(a, d: dict, dirs: list[str], puerto: int, rol: str) -> list[str]:
    agente = rol == "agente"
    modo = "rw" if a.permitir_aplicar else "ro"
    servicio = "agente" if agente else "vigilante"
    bind = "127.0.0.1:" if a.local else ""
    y = ["# Generado por el instalador del vigilante. No hace falta editarlo: vuelve a ejecutar instalar.sh.",
         f"name: {PROYECTO[rol]}", "", "services:",
         "  docker-proxy:                      # solo lectura: listar e inspeccionar contenedores",
         "    image: tecnativa/docker-socket-proxy:latest", "    restart: unless-stopped",
         "    environment: { CONTAINERS: 1, POST: 0 }",
         '    volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]', ""]
    if a.permitir_aplicar:
        y += ["  docker-proxy-pruebas:              # con escritura: construir y desplegar tras tu aprobacion",
              "    image: tecnativa/docker-socket-proxy:latest", "    restart: unless-stopped",
              "    environment: { CONTAINERS: 1, IMAGES: 1, BUILD: 1, EXEC: 1, NETWORKS: 1, VOLUMES: 1, POST: 1,"
              " DELETE: 1, ALLOW_START: 1, ALLOW_STOP: 1, ALLOW_RESTARTS: 1 }",
              '    volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]', ""]
    y += [f"  {servicio}:", f"    image: {IMAGEN[rol]}", "    restart: unless-stopped", "    env_file: .env",
          "    environment:", '      DOCKER_HOST: "tcp://docker-proxy:2375"']
    if not agente:
        y.append(f"      VIGILANTE_PANEL_PUERTO: {q(puerto)}")
    if a.permitir_aplicar:
        y.append('      VIGILANTE_DOCKER_PRUEBAS: "tcp://docker-proxy-pruebas:2375"')
        if d["redes"]:
            y.append(f"      VIGILANTE_RED_PRUEBAS: {q(d['redes'][0])}")
    y += ["    depends_on: [docker-proxy]" if not a.permitir_aplicar else
          "    depends_on: [docker-proxy, docker-proxy-pruebas]", "    volumes:",
          '      - "./vigilante.toml:/config/vigilante.toml:ro"', "      - datos:/datos"]
    y += [f"      - {q(f'{x}:{x}:{modo}')}" for x in dirs]
    if a.permitir_aplicar:
        y.append('      - "./desplegar.sh:/desplegar.sh:ro"')
    if a.tunel:
        y_tunel = ["  cloudflared:                       # túnel rápido y gratuito: da una URL https temporal",
                   "    image: cloudflare/cloudflared:latest", "    restart: unless-stopped",
                   f"    command: tunnel --no-autoupdate --url http://vigilante:{puerto}",
                   "    depends_on: [vigilante]", ""]
    if not agente:          # el agente no abre puertos: solo conexiones salientes al central
        y.append(f'    ports: ["{bind}{puerto}:{puerto}"]')
    y += ["    networks: [" + ", ".join(["default"] + [f"r{i}" for i in range(len(d["redes"]))]) + "]", ""]
    y += ["networks:"] if d["redes"] else []
    for i, r in enumerate(d["redes"]):
        y += [f"  r{i}:", "    external: true", f"    name: {q(r)}"]
    if a.tunel:       # los servicios van antes que `networks:`; se insertan tras el bloque del vigilante
        i = y.index("networks:") if "networks:" in y else len(y)
        y[i:i] = y_tunel
    y += ["", "volumes:", "  datos:", ""]
    return y


def _desplegar_sh(a, d: dict):
    sh = ["#!/bin/sh", "# Generado por el instalador. Redespliega la app indicada tras una aprobación.",
          "set -e", 'H="tcp://docker-proxy-pruebas:2375"', 'case "$VIGILANTE_RAIZ" in']
    for nombre, p in sorted(d["proyectos"].items()):
        ficheros = " ".join(f"-f {shlex.quote(f)}" for f in p["ficheros"])
        sh.append(f'  {shlex.quote(p["dir"])}) exec docker -H "$H" compose -p {shlex.quote(nombre)} '
                  f'--project-directory {shlex.quote(p["dir"])} {ficheros} up -d --build ;;')
    sh += ['  *) echo "app desconocida: $VIGILANTE_RAIZ" >&2; exit 1 ;;', "esac", ""]
    ruta = os.path.join(a.salida, "desplegar.sh")
    open(ruta, "w").write("\n".join(sh))
    os.chmod(ruta, 0o755)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vigilante.instalar")
    ap.add_argument("--salida", required=True)
    ap.add_argument("--rol", choices=["central", "agente"], default="central")
    ap.add_argument("--central", default="", help="agente: URL del panel central")
    ap.add_argument("--codigo", default="", help="agente: código de alta de un solo uso")
    ap.add_argument("--permitir-http", action="store_true", help="agente: aceptar http:// (p. ej. en una VPN)")
    ap.add_argument("--puerto", type=int, default=0)
    ap.add_argument("--local", action="store_true", help="panel solo en 127.0.0.1")
    ap.add_argument("--permitir-aplicar", action="store_true")
    ap.add_argument("--tunel", action="store_true", help="publicar el panel con un túnel rápido de cloudflared")
    ap.add_argument("--solo", default="", help="nombres de contenedor o proyecto, separados por comas")
    a = ap.parse_args(argv)
    ruta = os.environ.get("DOCKER_HOST") or "/var/run/docker.sock"
    if ruta.startswith("unix://"):
        ruta = ruta[7:]
    d = descubrir(Docker(ruta), {x.strip() for x in a.solo.split(",") if x.strip()})
    r = generar(a, d, leer_env(os.path.join(a.salida, ".env")))

    print("== Lo que he encontrado ==")
    for n, p in sorted(d["proyectos"].items()):
        print(f"  app {n}: {p['dir']}  ({', '.join(p['contenedores'])})")
    if d["sin_proyecto"]:
        print(f"  contenedores sueltos (sin docker compose): {', '.join(d['sin_proyecto'])}")
    if d["objetivo"]:
        print(f"  comprobación de la web tras aplicar cambios: http://{d['objetivo'][0]}:{d['objetivo'][1]}")
    if not d["contenedores"]:
        print("  AVISO: no hay contenedores en marcha que vigilar. Arranca tus apps y vuelve a ejecutar el instalador.")
    if r["rol"] == "agente":
        print(f"  papel: agente del panel central {r['central']} (sin panel propio; solo conexiones salientes)")
    print(f"  modo: {'puede APLICAR cambios (siempre con tu aprobación)' if a.permitir_aplicar else 'solo avisa y propone (no modifica nada)'}")
    print("RESULTADO " + json.dumps(r))


if __name__ == "__main__":
    sys.exit(main())
