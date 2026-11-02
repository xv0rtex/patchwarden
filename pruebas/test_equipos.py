"""Todo lo que toca un servidor pasa por su Equipo (sin red ni Docker)."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vigilante"))

from vigilante import config  # noqa: E402
from vigilante.equipos import LOCAL, Equipo  # noqa: E402
from vigilante.modelo import Componente  # noqa: E402
from vigilante.motor import Vigilante  # noqa: E402


class EquipoFalso(Equipo):
    def __init__(self, id_):
        self.id, self.llamadas = id_, []

    def detectar(self):
        self.llamadas.append("detectar")
        c = Componente("php", "8.1.2", "runtime", origen="docker_env", detalle="x", app="web")
        c.equipo = self.id
        return [c]

    @property
    def apps_dirs(self):
        return {"web": f"/proyectos/{self.id}"}

    def raiz(self, comp):
        return f"/proyectos/{self.id}"

    def contexto(self, raiz, paquete):
        self.llamadas.append(("contexto", raiz, paquete))
        return "x" * 10

    @property
    def solo_lectura(self):
        return True


class Enrutado(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        cfg = config.cargar("/no/existe.toml")
        cfg["general"]["carpeta_datos"] = self.tmp
        cfg["deteccion"].update(docker=False, rutas_proyecto=[])
        self.v = Vigilante(cfg)
        self.otro = EquipoFalso("otro")
        self.v.equipos["otro"] = self.otro

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_detectar_recorre_todos_los_equipos(self):
        comps = self.v.detectar()
        self.assertEqual(self.otro.llamadas, ["detectar"])
        self.assertIn("php", {c.nombre for c in comps})
        self.assertEqual(self.v.apps_dirs.get("web"), "/proyectos/otro")

    def test_el_gestor_usa_el_equipo_del_componente(self):
        g = self.v.gestor
        comp = {"clave": "web::runtime:php@8.1.2", "nombre": "php", "version": "8.1.2", "tipo": "runtime",
                "detalle": "x", "app": "web", "equipo": "otro"}
        self.assertIs(g.equipo_de(comp), self.otro)
        self.assertIs(g.equipo_de({"componente": comp}), self.otro)
        self.assertIs(g.equipo_de({"nombre": "x"}), self.v.equipos[LOCAL])
        self.assertIsNone(g.equipo_de({**comp, "equipo": "no-existe"}))
        self.assertEqual(g._tamano_peticion(comp), 10 + 3000)   # contexto + base sin vulnerabilidades
        self.assertIn(("contexto", "/proyectos/otro", "php"), self.otro.llamadas)

    def test_aplicar_respeta_solo_lectura_del_equipo(self):
        g = self.v.gestor
        comp = {"clave": "web::runtime:php@8.1.2", "nombre": "php", "version": "8.1.2", "tipo": "runtime",
                "app": "web", "equipo": "otro"}
        plan = g.planes.crear(comp, [], "/proyectos/otro")
        self.assertIn("solo propuestas", g.aplicar(plan["id"], "test"))
        plan["componente"]["equipo"] = "no-existe"
        g.planes.guardar(plan)
        self.assertIn("ya no está registrado", g.aplicar(plan["id"], "test"))


if __name__ == "__main__":
    unittest.main()
