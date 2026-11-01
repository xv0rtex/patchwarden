"""Aplicación y marcha atrás de los cambios APROBADOS por el usuario.

Solo se llega aquí desde una acción explícita del usuario (panel con token o botón de Telegram
de un chat autorizado). Orden:
  1. Comprobar que hay cambios aprobados, que sus dependencias también lo están y que lo que se
     va a aplicar es exactamente lo verificado (si el usuario aprobó solo una parte, se vuelve a
     verificar esa parte antes).
  2. Comprobar que los ficheros de producción no han cambiado desde la verificación.
  3. Copia de seguridad: ficheros afectados (tar.gz) + etiqueta de respaldo de las imágenes que
     están corriendo ahora.
  4. Aplicar los diffs finales (`git apply`) en el proyecto.
  5. Desplegar (comando o webhook configurados) y comprobar la web (HTTP).
  6. Si la comprobación falla y `rollback_automatico` está activo, restaurar lo anterior.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import shlex
import subprocess
import tarfile
import time

from .detectar_docker import Docker
from .http import peticion
from .planes import aprobados
from .verificacion import ERRORES_FATALES, git, peticion_http, sha256

log = logging.getLogger("vigilante.aplicar")


def ahora():
    return dt.datetime.now().isoformat(timespec="seconds")


class ErrorAplicacion(Exception):
    pass


class Aplicador:
    def __init__(self, cfg: dict, carpeta_datos: str, verificador):
        self.cfg = cfg
        self.a = cfg.get("aplicacion", {})
        self.respaldos = os.path.join(carpeta_datos, "respaldos")
        os.makedirs(self.respaldos, exist_ok=True)
        self.verificador = verificador
        sock = cfg.get("verificacion", {}).get("docker_host") or ""
        self.docker = Docker(sock) if sock else None

    # ------------------------------------------------------------------ comprobaciones previas
    @staticmethod
    def comprobar_decisiones(plan: dict) -> list[dict]:
        """Comprobaciones rápidas: estado, que haya aprobados y que sus dependencias lo estén."""
        if plan["estado"] not in ("pendiente_aprobacion", "aplicando"):
            raise ErrorAplicacion(f"el plan está en estado «{plan['estado']}»")
        elegidos = aprobados(plan)
        if not elegidos:
            raise ErrorAplicacion("no hay ningún cambio aprobado")
        numeros = {c["n"] for c in elegidos}
        for c in elegidos:
            faltan = [d for d in c.get("depende_de") or [] if d not in numeros]
            if faltan:
                raise ErrorAplicacion(f"el cambio {c['n']} depende de {faltan}, que no están aprobados")
        return elegidos

    def preparar(self, plan: dict) -> list[dict]:
        elegidos = self.comprobar_decisiones(plan)
        numeros = {c["n"] for c in elegidos}
        ver = plan.get("verificacion") or {}
        verificados = {int(n) for n, r in (ver.get("por_cambio") or {}).items() if r.get("aplica")}
        if set(ver.get("cambios_verificados") or []) != numeros or not numeros <= verificados:
            # se aprobó un subconjunto distinto de lo verificado: se verifica justo eso
            log.info("Re-verificando el plan %s con los cambios %s", plan["id"], sorted(numeros))
            ver = self.verificador.verificar(plan, sorted(numeros))
            plan.setdefault("verificaciones_previas", []).append(plan.get("verificacion"))
            plan["verificacion"] = ver
            if ver["estado"] not in ("ok", "solo_estatica"):
                raise ErrorAplicacion("la verificación de los cambios aprobados ha fallado; no se aplica nada")
        for c in elegidos:
            if not ver["por_cambio"].get(str(c["n"]), {}).get("aplica"):
                raise ErrorAplicacion(f"el cambio {c['n']} no se pudo preparar en la verificación")
        for f, h in (ver.get("hashes_originales") or {}).items():
            if sha256(os.path.join(plan["raiz"], f)) != h:
                raise ErrorAplicacion(f"{f} ha cambiado en producción desde la verificación; hay que volver a "
                                      "verificar antes de aplicar")
        return elegidos

    # ------------------------------------------------------------------ aplicar
    def aplicar(self, plan: dict, por: str) -> dict:
        elegidos = self.preparar(plan)
        ver = plan["verificacion"]
        diff = "".join(ver["por_cambio"][str(c["n"])]["diff_final"] for c in sorted(elegidos, key=lambda c: c["n"]))
        ficheros = sorted({f for c in elegidos for f in ver["por_cambio"][str(c["n"])]["ficheros"]})
        ap = {"inicio": ahora(), "por": por, "cambios": [c["n"] for c in elegidos], "ficheros": ficheros,
              "pasos": [], "estado": "aplicando"}
        paso = lambda n, ok, d="": ap["pasos"].append({"paso": n, "ok": ok, "detalle": d, "fecha": ahora()})  # noqa
        plan["aplicacion"] = ap

        ap["respaldo"] = self._respaldar(plan, ficheros)
        paso("Copia de seguridad", True, f"{len(ficheros)} fichero(s) en {os.path.basename(ap['respaldo']['carpeta'])}"
             + (f"; imágenes etiquetadas: {', '.join(ap['respaldo']['imagenes'])}" if ap["respaldo"]["imagenes"] else ""))

        raiz = plan["raiz"]
        chequeo = git(raiz, "apply", "--check", "--binary", "-", entrada=diff, comprobar=False)
        if chequeo.returncode != 0:
            paso("Aplicar cambios", False, chequeo.stderr.strip())
            ap["estado"] = "fallo"
            return ap
        git(raiz, "apply", "--binary", "-", entrada=diff)
        paso("Aplicar cambios", True, ", ".join(ficheros))
        if self.a.get("git_commit") and os.path.isdir(os.path.join(raiz, ".git")):
            git(raiz, "add", *ficheros)
            r = git(raiz, "commit", "-q", "-m", f"vigilante: {plan['componente']['nombre']} → "
                    f"{(plan.get('analisis') or {}).get('version_objetivo', '')} (plan {plan['id']}, aprobado por {por})",
                    comprobar=False)
            paso("Commit en git", r.returncode == 0, r.stderr.strip() or "hecho")

        ok_despliegue, detalle = self._desplegar(plan, "aplicar")
        paso("Desplegar", ok_despliegue, detalle)
        ok_salud, detalle_salud = self._comprobar_web(plan) if ok_despliegue else (False, "no se desplegó")
        paso("Comprobar la web", ok_salud, detalle_salud)

        if ok_despliegue and ok_salud:
            ap["estado"] = "aplicado"
        elif self.a.get("rollback_automatico", True):
            r = self.revertir(plan, "rollback automático (falló la comprobación tras aplicar)", interno=True)
            ap["estado"] = "revertido" if r["ok"] else "revertido_con_problemas"
        else:
            ap["estado"] = "fallo"
        ap["fin"] = ahora()
        return ap

    def _respaldar(self, plan, ficheros) -> dict:
        carpeta = os.path.join(self.respaldos, f"{plan['id']}-{dt.datetime.now():%Y%m%d-%H%M%S}")
        os.makedirs(carpeta)
        existentes = [f for f in ficheros if os.path.exists(os.path.join(plan["raiz"], f))]
        with tarfile.open(os.path.join(carpeta, "ficheros.tar.gz"), "w:gz") as t:
            for f in existentes:
                t.add(os.path.join(plan["raiz"], f), arcname=f)
        imagenes = []
        if self.docker and self.a.get("respaldo_imagenes", True):
            for nombre in {x.strip() for x in (plan["componente"].get("contenedor") or "").split(",") if x.strip()} | \
                    set(self.a.get("contenedores") or []):
                try:
                    img = self.docker.inspeccionar(nombre)["Image"]
                    tag = f"{plan['id']}-{nombre}"[:120]
                    self.docker.etiquetar(img, "vigilante-respaldo", tag)
                    imagenes.append(f"vigilante-respaldo:{tag}")
                except Exception as e:  # noqa: BLE001
                    log.warning("No se pudo etiquetar la imagen de %s: %s", nombre, e)
        meta = {"fecha": ahora(), "ficheros": existentes, "nuevos": sorted(set(ficheros) - set(existentes)),
                "imagenes": imagenes}
        with open(os.path.join(carpeta, "respaldo.json"), "w") as f:
            json.dump(meta, f, indent=1)
        return {"carpeta": carpeta, **meta}

    # ------------------------------------------------------------------ revertir
    def revertir(self, plan: dict, por: str, interno=False) -> dict:
        ap = plan.get("aplicacion") or {}
        resp = ap.get("respaldo")
        if not resp:
            raise ErrorAplicacion("no hay copia de seguridad de este plan")
        if not interno and plan["estado"] not in ("aplicado", "fallo_aplicacion"):
            raise ErrorAplicacion(f"no se puede revertir un plan en estado «{plan['estado']}»")
        raiz = plan["raiz"]
        with tarfile.open(os.path.join(resp["carpeta"], "ficheros.tar.gz")) as t:
            for m in t.getmembers():
                destino = os.path.realpath(os.path.join(raiz, m.name))
                if not destino.startswith(os.path.realpath(raiz) + os.sep):
                    raise ErrorAplicacion(f"ruta sospechosa en el respaldo: {m.name}")
            try:
                t.extractall(raiz, filter="data")
            except TypeError:          # Python < 3.11.4: rutas ya validadas arriba
                t.extractall(raiz)
        for f in resp.get("nuevos", []):  # ficheros que creó el cambio
            try:
                os.remove(os.path.join(raiz, f))
            except OSError:
                pass
        pasos = ap.setdefault("pasos", [])
        pasos.append({"paso": "Restaurar ficheros", "ok": True, "detalle": por, "fecha": ahora()})
        ok_d, det_d = self._desplegar(plan, "revertir")
        pasos.append({"paso": "Desplegar versión anterior", "ok": ok_d, "detalle": det_d, "fecha": ahora()})
        ok_s, det_s = self._comprobar_web(plan) if ok_d else (False, "no se desplegó")
        pasos.append({"paso": "Comprobar la web", "ok": ok_s, "detalle": det_s, "fecha": ahora()})
        ap["revertido"] = {"fecha": ahora(), "por": por, "ok": ok_d and ok_s}
        if resp.get("imagenes") and not (ok_d and ok_s):
            pasos.append({"paso": "Imágenes de respaldo", "ok": None, "fecha": ahora(),
                          "detalle": "Para volver a la imagen exacta anterior: " + ", ".join(resp["imagenes"])})
        return {"ok": ok_d and ok_s, "detalle": det_s}

    # ------------------------------------------------------------------ despliegue y salud
    def _desplegar(self, plan, accion) -> tuple[bool, str]:
        env = {"VIGILANTE_PLAN": plan["id"], "VIGILANTE_ACCION": accion,
               "VIGILANTE_COMPONENTE": plan["componente"]["nombre"], "VIGILANTE_RAIZ": plan["raiz"]}
        if self.a.get("comando_despliegue"):
            try:
                r = subprocess.run(shlex.split(self.a["comando_despliegue"]), cwd=plan["raiz"],
                                   env={**os.environ, **env}, capture_output=True, text=True,
                                   timeout=int(self.a.get("timeout_despliegue_s", 900)))
            except Exception as e:  # noqa: BLE001
                return False, f"no se pudo ejecutar el despliegue: {e}"
            salida = (r.stdout + r.stderr).strip()[-1500:]
            return r.returncode == 0, f"código {r.returncode}. {salida}"
        if self.a.get("webhook_despliegue"):
            try:
                peticion(self.a["webhook_despliegue"], {"accion": accion, **env}, json_resp=False, timeout=120)
                return True, "webhook de despliegue llamado"
            except Exception as e:  # noqa: BLE001
                return False, f"webhook de despliegue falló: {e}"
        return True, ("ficheros actualizados; no hay despliegue automático configurado: "
                      "reconstruye/reinicia el servicio tú (p. ej. docker compose up -d --build)")

    def _comprobar_web(self, plan: dict | None = None) -> tuple[bool, str]:
        por_app = self.a.get("salud") or {}
        base = ((por_app.get((plan or {}).get("raiz", "")) or self.a.get("url_salud")
                 or self.cfg["deteccion"].get("url_web") or "")).rstrip("/")
        if not base:
            return True, "no hay URL configurada para comprobar ([aplicacion].url_salud)"
        rutas = self.a.get("rutas_salud") or ["/"]
        limite = time.time() + int(self.a.get("espera_s", 120))
        ultimo = ""
        while True:
            resultados = [(r, *peticion_http(base + r)) for r in rutas]
            malos = [(r, c) for r, c, cuerpo in resultados
                     if c is None or c >= 500 or ERRORES_FATALES.search(cuerpo or "")]
            ultimo = ", ".join(f"{r} → {c}" for r, c, _ in resultados)
            if not malos:
                return True, f"la web responde bien: {ultimo}"
            if time.time() > limite:
                return False, f"la web no responde bien tras {self.a.get('espera_s', 120)} s: {ultimo}"
            time.sleep(5)
