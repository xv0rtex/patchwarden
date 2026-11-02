"""Punto de entrada.

  python -m vigilante              -> servicio: ciclo al arrancar y cada N horas + panel
  python -m vigilante --una-vez    -> un ciclo y salir (cron, CI)
  python -m vigilante --detectar   -> solo enseña qué versiones detecta (sin consultar CVE)
"""
import argparse
import json
import logging
import signal
import sys
import threading

from . import config, panel
from .motor import Vigilante


def main():
    ap = argparse.ArgumentParser(prog="vigilante")
    ap.add_argument("-c", "--config", help="ruta al vigilante.toml")
    ap.add_argument("--una-vez", action="store_true", help="hacer un ciclo y salir")
    ap.add_argument("--detectar", action="store_true", help="solo detectar versiones")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", stream=sys.stdout)
    cfg = config.cargar(a.config)
    v = Vigilante(cfg)

    if a.detectar:
        print(json.dumps([c.to_dict() for c in v.detectar()], indent=1, ensure_ascii=False))
        return
    if a.una_vez:
        r = v.ciclo("manual")
        v.gestor.cola.join()          # esperar a que terminen los planes de corrección
        sys.exit(2 if r["criticos"] else 0)

    v.gestor.arrancar_bot()
    if cfg["panel"].get("activo"):
        panel.arrancar(v, int(cfg["panel"].get("puerto", 8080)))
    parar = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: parar.set())
    signal.signal(signal.SIGINT, lambda *_: parar.set())
    while not parar.is_set():
        try:
            v.ciclo()
        except Exception:  # noqa: BLE001 - el servicio debe seguir vivo
            logging.exception("Error en el ciclo; se reintentará en el siguiente")
        # se lee en cada vuelta: se puede cambiar desde Ajustes sin reiniciar
        parar.wait(float(cfg["general"].get("intervalo_horas", 6)) * 3600)


if __name__ == "__main__":
    main()
