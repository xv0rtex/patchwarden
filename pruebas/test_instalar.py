"""Instalador: configuración del panel central y del agente, y arranque sin repetir un análisis reciente."""
import argparse
import datetime as dt
import os
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vigilante"))

from vigilante import instalar  # noqa: E402
from vigilante.__main__ import espera_inicial  # noqa: E402
from vigilante.modelo import Componente  # noqa: E402

DESCUBIERTO = {
    "contenedores": [{"Id": "a"}], "redes": ["web_default"], "publicados": {8000},
    "proyectos": {"web": {"dir": "/srv/web", "ficheros": ["/srv/web/compose.yml"], "contenedores": ["web-nginx-1"]}},
    "objetivo": ("web-nginx-1", 80, 8000), "objetivos": {"web": ("web-nginx-1", 80, 8000)}, "sin_proyecto": [],
}


def args(salida, **kw):
    base = dict(salida=salida, rol="central", central="", codigo="", permitir_http=False, puerto=0, local=False,
                permitir_aplicar=False, tunel=False, solo="")
    base.update(kw)
    return argparse.Namespace(**base)


class Generar(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def leer(self, nombre):
        return open(os.path.join(self.dir, nombre)).read()

    def test_central_conserva_claves(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_OAUTH_TOKEN": "tok"}):
            r = instalar.generar(args(self.dir, puerto=8091), DESCUBIERTO, {})
        self.assertEqual(r["rol"], "central")
        self.assertTrue(r["claude"])
        compose = self.leer("docker-compose.yml")
        self.assertIn("name: vigilante\n", compose)
        self.assertIn("image: vigilante:local", compose)
        self.assertIn('ports: ["8091:8091"]', compose)
        # volver a ejecutarlo (actualizar) conserva contraseña y tokens aunque no se vuelvan a dar
        previo = instalar.leer_env(os.path.join(self.dir, ".env"))
        r2 = instalar.generar(args(self.dir), DESCUBIERTO, previo)
        self.assertEqual(r2["clave"], r["clave"])
        self.assertEqual(r2["puerto"], 8091)
        self.assertEqual(instalar.leer_env(os.path.join(self.dir, ".env"))["CLAUDE_CODE_OAUTH_TOKEN"], "tok")

    def test_agente_sin_panel_ni_puertos_ni_claude(self):
        r = instalar.generar(args(self.dir, rol="agente", central="https://central.ejemplo/", codigo="ABC123",
                                  tunel=True), DESCUBIERTO, {})
        self.assertEqual(r, {"rol": "agente", "central": "https://central.ejemplo", "alta": True})
        compose = self.leer("docker-compose.yml")
        self.assertIn("name: vigilante-agente\n", compose)
        self.assertIn("image: vigilante-agente:local", compose)
        self.assertNotIn("ports:", compose)
        self.assertNotIn("cloudflared", compose)
        self.assertIn('"/srv/web:/srv/web:ro"', compose)
        cfg = tomllib.loads(self.leer("vigilante.toml"))
        self.assertFalse(cfg["panel"]["activo"])
        self.assertTrue(cfg["aplicacion"]["solo_lectura"])
        env = instalar.leer_env(os.path.join(self.dir, ".env"))
        self.assertEqual(env["VIGILANTE_CENTRAL"], "https://central.ejemplo")
        self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", env)
        self.assertEqual(os.stat(os.path.join(self.dir, ".env")).st_mode & 0o777, 0o600)
        # al actualizar no hace falta repetir la URL ni el código
        r2 = instalar.generar(args(self.dir, rol="agente"), DESCUBIERTO, env)
        self.assertEqual(r2["central"], "https://central.ejemplo")

    def test_agente_sin_central_falla(self):
        with self.assertRaises(SystemExit):
            instalar.generar(args(self.dir, rol="agente"), DESCUBIERTO, {})

    def test_agente_con_aplicar_y_http(self):
        instalar.generar(args(self.dir, rol="agente", central="http://10.0.0.2:8090", codigo="X",
                              permitir_http=True, permitir_aplicar=True), DESCUBIERTO, {})
        self.assertIn("docker-proxy-pruebas", self.leer("docker-compose.yml"))
        self.assertTrue(os.path.exists(os.path.join(self.dir, "desplegar.sh")))
        self.assertEqual(instalar.leer_env(os.path.join(self.dir, ".env"))["VIGILANTE_CENTRAL_PERMITIR_HTTP"], "1")


class EsperaInicial(unittest.TestCase):
    def vigilante(self, hace_min, claves_guardadas, detectados):
        fin = (dt.datetime.now() - dt.timedelta(minutes=hace_min or 0)).isoformat(timespec="seconds")
        v = mock.Mock()
        v.estado = {"ciclos": [{"fin": fin}] if hace_min is not None else [],
                    "componentes": [{"clave": c} for c in claves_guardadas] + [{"clave": "x~remoto", "equipo": "x"}]}
        v.local.detectar.return_value = detectados
        return v

    cfg = {"general": {"intervalo_horas": 6}}
    php = Componente("php", "8.2.1", "runtime", app="web")

    def test_reciente_y_sin_cambios_espera(self):
        v = self.vigilante(30, [self.php.clave], [self.php])
        self.assertAlmostEqual(espera_inicial(v, self.cfg), 5.5 * 3600, delta=60)

    def test_cambio_de_version_analiza_ya(self):
        v = self.vigilante(30, [self.php.clave], [Componente("php", "8.2.2", "runtime", app="web")])
        self.assertEqual(espera_inicial(v, self.cfg), 0)

    def test_antiguo_o_sin_ciclos_analiza_ya(self):
        self.assertEqual(espera_inicial(self.vigilante(7 * 60, [self.php.clave], [self.php]), self.cfg), 0)
        self.assertEqual(espera_inicial(self.vigilante(None, [], []), self.cfg), 0)


if __name__ == "__main__":
    unittest.main()
