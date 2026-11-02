"""Punto de entrada.

  python -m vigilante              -> servicio: ciclo al arrancar y cada N horas + panel
  python -m vigilante --una-vez    -> un ciclo y salir (cron, CI)
  python -m vigilante --detectar   -> solo enseña qué versiones detecta (sin consultar CVE)
  python -m vigilante --agente --central https://central --codigo XXXX
                                   -> agente de este servidor para un panel central
"""
import argparse
import datetime as dt
import json
import logging
import signal
import sys
import threading

from . import config, panel
from .motor import Vigilante, fusionar


def main():
    ap = argparse.ArgumentParser(prog="vigilante")
    ap.add_argument("-c", "--config", help="ruta al vigilante.toml")
    ap.add_argument("--una-vez", action="store_true", help="hacer un ciclo y salir")
    ap.add_argument("--detectar", action="store_true", help="solo detectar versiones")
    ap.add_argument("--agente", action="store_true", help="funcionar como agente de un panel central")
    ap.add_argument("--central", help="URL del panel central (agente)")
    ap.add_argument("--codigo", help="código de alta de un solo uso (agente)")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", stream=sys.stdout)
    cfg = config.cargar(a.config)
    if a.agente:
        return agente_main(cfg, a)
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
    parar.wait(espera_inicial(v, cfg))
    while not parar.is_set():
        try:
            v.ciclo()
        except Exception:  # noqa: BLE001 - el servicio debe seguir vivo
            logging.exception("Error en el ciclo; se reintentará en el siguiente")
        # se lee en cada vuelta: se puede cambiar desde Ajustes sin reiniciar
        parar.wait(float(cfg["general"].get("intervalo_horas", 6)) * 3600)


def espera_inicial(v, cfg) -> float:
    """Segundos hasta el primer ciclo. Tras un reinicio (p. ej. al actualizar) no se repite el análisis si
    el último es más reciente que el intervalo y en este servidor se detecta exactamente lo mismo."""
    ciclos = v.estado.get("ciclos") or []
    if not ciclos:
        return 0
    try:
        hace = (dt.datetime.now() - dt.datetime.fromisoformat(ciclos[0]["fin"])).total_seconds()
        resto = float(cfg["general"].get("intervalo_horas", 6)) * 3600 - hace
        if resto <= 0:
            return 0
        antes = {c["clave"] for c in v.estado.get("componentes", []) if not c.get("equipo")}
        ahora = {c.clave for c in fusionar(v.local.detectar())}
    except Exception:  # noqa: BLE001 - ante la duda, se analiza
        return 0
    if ahora != antes:
        return 0
    logging.info("Último análisis hace %d min y nada ha cambiado en este servidor: el siguiente, en %d min",
                 hace // 60, resto // 60)
    return resto


def agente_main(cfg, a):
    from .agente import Agente, ErrorAgente
    if a.central:
        cfg["central"]["url"] = a.central
    if a.codigo:
        cfg["central"]["codigo"] = a.codigo
    try:
        ag = Agente(cfg)
        signal.signal(signal.SIGTERM, lambda *_: ag.parar.set())
        signal.signal(signal.SIGINT, lambda *_: ag.parar.set())
        ag.ejecutar()
    except ErrorAgente as e:
        logging.error("%s", e)
        sys.exit(1)
    sys.exit(3 if ag.revocado else 0)      # 3: el central ya no acepta este equipo


if __name__ == "__main__":
    main()
