"""Registro de equipos del central y reglas del agente (sin red ni Docker)."""
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vigilante"))

from vigilante import equipos_remotos as er  # noqa: E402
from vigilante.agente import url_permitida  # noqa: E402
from vigilante.equipos import huella_verificacion  # noqa: E402


class RegistroEquipos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.r = er.Registro(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_alta_de_un_solo_uso_y_token_con_hash(self):
        codigo = self.r.crear_alta("srv-1")
        id_, token, nombre = self.r.canjear(codigo, "host", "0.2")
        self.assertEqual(nombre, "srv-1")
        self.assertEqual(self.r.autenticar(token), id_)
        with self.assertRaises(er.ErrorEquipo):
            self.r.canjear(codigo)
        texto = open(self.r.ruta).read()
        self.assertNotIn(token, texto)
        self.assertNotIn(codigo, texto)
        self.assertEqual(os.stat(self.r.ruta).st_mode & 0o777, 0o600)
        self.assertEqual(er.Registro(self.tmp).autenticar(token), id_, "persiste")

    def test_alta_caducada_y_nombres(self):
        codigo = self.r.crear_alta("srv-1")
        next(iter(self.r.altas.values()))["caduca"] = time.time() - 1
        with self.assertRaises(er.ErrorEquipo):
            self.r.canjear(codigo)
        for malo in ("con espacio", "-empieza", "x" * 40, "../x"):
            with self.assertRaises(er.ErrorEquipo):
                self.r.crear_alta(malo)
        self.r.crear_alta("srv-2")
        with self.assertRaises(er.ErrorEquipo):
            self.r.crear_alta("srv-2")

    def test_revocar(self):
        id_, token, _ = self.r.canjear(self.r.crear_alta("srv-1"))
        self.r.revocar(id_)
        self.assertIsNone(self.r.autenticar(token))
        self.assertNotIn(id_, self.r.activos())
        self.assertIsNone(self.r.autenticar("pw_inventado"))

    def test_tareas_ida_y_vuelta(self):
        id_, _, _ = self.r.canjear(self.r.crear_alta("srv-1"))
        otro, _, _ = self.r.canjear(self.r.crear_alta("srv-2"))

        def agente():
            for t in self.r.tareas_para(id_, timeout=5):
                with self.assertRaises(er.ErrorEquipo):          # otro equipo no puede responder por él
                    self.r.resultado(otro, t["id"], {"ok": True, "resultado": {"x": "falso"}})
                self.r.resultado(id_, t["id"], {"ok": True, "resultado": {"eco": t["datos"]["n"]}})
        threading.Thread(target=agente).start()
        self.assertEqual(self.r.pedir(id_, "prueba", {"n": 7}, 5), {"eco": 7})

        threading.Thread(target=lambda: [self.r.resultado(id_, t["id"], {"ok": False, "error": "no"})
                                         for t in self.r.tareas_para(id_, timeout=5)]).start()
        with self.assertRaisesRegex(er.ErrorEquipo, "no"):
            self.r.pedir(id_, "prueba", {}, 5)

    def test_desconectado_y_sin_respuesta(self):
        id_, _, _ = self.r.canjear(self.r.crear_alta("srv-1"))
        self.r._contacto[id_] = 0
        with self.assertRaisesRegex(er.ErrorEquipo, "desconectado"):
            self.r.pedir(id_, "prueba", {}, 1)
        self.r._contacto[id_] = time.time()
        with self.assertRaisesRegex(er.ErrorEquipo, "no recogió"):
            self.r.pedir(id_, "prueba", {}, 0.3)
        self.assertEqual(self.r._colas.get(id_), [], "la tarea no recogida se retira de la cola")

    def test_inventario_se_limpia(self):
        id_, _, _ = self.r.canjear(self.r.crear_alta("srv-1"))
        with self.assertRaises(er.ErrorEquipo):
            self.r.guardar_inventario(id_, {"componentes": "no"})
        self.r.guardar_inventario(id_, {"componentes": [{"nombre": "php", "version": "8.1.2", "tipo": "runtime",
                                                         "raiz": "/p", "extra": "<script>"}, {"sin": "nombre"}]})
        inv = self.r.equipos[id_]["inventario"]
        self.assertEqual(len(inv["componentes"]), 1)
        self.assertNotIn("extra", inv["componentes"][0])
        self.assertTrue(inv["solo_lectura"], "si el agente no lo dice, se supone solo propuestas")
        eq = er.EquipoRemoto(self.r, id_, {})
        self.r._contacto[id_] = 0       # desconectado: usa el último inventario sin pedir uno nuevo
        c = eq.detectar()[0]
        self.assertEqual((c.app, c.equipo), ("srv-1", id_))
        self.assertEqual(eq.raiz(c), "/p")


class Agente(unittest.TestCase):
    def test_url_del_central(self):
        self.assertTrue(url_permitida("https://central.ejemplo"))
        self.assertTrue(url_permitida("http://127.0.0.1:8080"))
        self.assertFalse(url_permitida("http://central.ejemplo"))
        self.assertTrue(url_permitida("http://central.ejemplo", permitir_http=True))
        self.assertFalse(url_permitida("ftp://central.ejemplo"))

    def test_huella_cubre_diffs_y_hashes(self):
        ver = {"cambios_verificados": [1], "por_cambio": {"1": {"aplica": True, "diff_final": "a", "ficheros": ["f"],
                                                                 "salida": "da igual"}},
               "hashes_originales": {"f": "h"}}
        h = huella_verificacion(ver)
        self.assertEqual(h, huella_verificacion({**ver, "pasos": ["otro"]}), "lo que no se usa al aplicar no cuenta")
        for cambio in ({"diff_final": "b"}, {"ficheros": ["g"]}, {"aplica": False}):
            otro = {**ver, "por_cambio": {"1": {**ver["por_cambio"]["1"], **cambio}}}
            self.assertNotEqual(h, huella_verificacion(otro))
        self.assertNotEqual(h, huella_verificacion({**ver, "hashes_originales": {"f": "x"}}))


if __name__ == "__main__":
    unittest.main()
