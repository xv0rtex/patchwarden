"""Pruebas sin red: python3 -m unittest discover -s pruebas"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vigilante"))

from vigilante.catalogo import limpiar_version, runtime_por_imagen  # noqa: E402
from vigilante.detectar_docker import _desmultiplexar, componentes_de_contenedor  # noqa: E402
from vigilante.detectar_ficheros import detectar  # noqa: E402
from vigilante.detectar_http import analizar  # noqa: E402
from vigilante.modelo import Componente, Hallazgo  # noqa: E402
from vigilante.motor import es_critico, fusionar, version_minima_segura  # noqa: E402
from vigilante.versiones import comparar, cvss3, en_rango  # noqa: E402

EJEMPLO = os.path.join(os.path.dirname(__file__), "..", "ejemplo", "web", "app")


class Versiones(unittest.TestCase):
    def test_comparar(self):
        self.assertEqual(comparar("8.1.2", "8.1.10"), -1)
        self.assertEqual(comparar("1.25", "1.25.0"), 0)
        self.assertEqual(comparar("2.0.0-rc1", "2.0.0"), -1)

    def test_rango(self):
        self.assertTrue(en_rango("8.1.2", desde_inc="8.1.0", hasta_exc="8.1.3"))
        self.assertFalse(en_rango("8.1.3", desde_inc="8.1.0", hasta_exc="8.1.3"))

    def test_cvss3(self):
        self.assertEqual(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)

    def test_minima_segura(self):
        self.assertEqual(version_minima_segura([["8.1.3"], ["8.1.29"], ["8.1.8"], []]), "8.1.29")


class Deteccion(unittest.TestCase):
    def test_imagenes(self):
        self.assertEqual(runtime_por_imagen("php:8.2.10-fpm-alpine"), ("php", "8.2.10"))
        self.assertEqual(runtime_por_imagen("docker.io/library/nginx:1.25.3"), ("nginx", "1.25.3"))
        self.assertEqual(runtime_por_imagen("eclipse-temurin:17.0.8_7-jre"), ("java", "17.0.8"))
        self.assertEqual(runtime_por_imagen("nginx:latest"), ("nginx", None))
        self.assertEqual(limpiar_version("jdk-17.0.8+7"), "17.0.8")

    def test_contenedor(self):
        info = {"Name": "/web", "Config": {"Image": "mi-imagen", "Env": ["PHP_VERSION=8.3.4", "TOMCAT_VERSION=10.1.20"]}}
        nombres = {(c.nombre, c.version) for c in componentes_de_contenedor(info)}
        self.assertEqual(nombres, {("php", "8.3.4"), ("tomcat", "10.1.20")})

    def test_desmultiplexar(self):
        trama = bytes([2, 0, 0, 0, 0, 0, 0, 5]) + b"hola\n"
        self.assertEqual(_desmultiplexar(trama), "hola\n")

    def test_ficheros(self):
        comps = detectar([EJEMPLO], {EJEMPLO: "tienda"})
        claves = {c.clave for c in comps}
        self.assertIn("tienda::Packagist:guzzlehttp/guzzle@7.4.0", claves)
        self.assertIn("tienda::Packagist:twig/twig@3.3.7", claves)
        self.assertIn("tienda::npm:lodash@4.17.15", claves)
        self.assertIn("tienda::runtime:php@8.1.2", claves)   # del FROM del Dockerfile
        self.assertEqual({c.app for c in comps}, {"tienda"})
        self.assertEqual({c.app for c in detectar([EJEMPLO])}, {"app"})   # sin mapa: nombre de la carpeta

    def test_http(self):
        cab = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"}
        html = '<meta name="generator" content="WordPress 6.2.1" />'
        r = {(c.nombre, c.version) for c in analizar(cab, html, "http://x")}
        self.assertEqual(r, {("nginx", "1.18.0"), ("php", "7.4.3"), ("wordpress", "6.2.1")})

    def test_apps_distintas_no_se_mezclan(self):
        comps = [Componente("php", "8.1.2", "runtime", origen="env", app="blog"),
                 Componente("php", "8.1.2", "runtime", origen="env", app="tienda"),
                 Componente("php", "8.1", "runtime", origen="fichero", app="blog")]   # pista débil de blog
        r = {(c.app, c.nombre, c.version) for c in fusionar(comps)}
        self.assertEqual(r, {("blog", "php", "8.1.2"), ("tienda", "php", "8.1.2")})

    def test_contenedor_toma_app_del_proyecto(self):
        info = {"Name": "/db", "Config": {"Image": "mysql:8.0.30", "Env": ["MYSQL_VERSION=8.0.30"],
                                          "Labels": {"com.docker.compose.project": "tienda"}}}
        self.assertEqual({c.app for c in componentes_de_contenedor(info)}, {"tienda"})
        info["Config"]["Labels"] = {}
        self.assertEqual({c.app for c in componentes_de_contenedor(info)}, {"db"})   # suelto: su nombre

    def test_fusionar(self):
        comps = [Componente("php", "8.1", "runtime", origen="fichero"),
                 Componente("php", "8.1.2", "runtime", origen="env", contenedor="php"),
                 Componente("nginx", "1.18.0", "runtime", origen="http")]
        r = {(c.nombre, c.version) for c in fusionar(comps)}
        self.assertEqual(r, {("php", "8.1.2"), ("nginx", "1.18.0")})


class Reglas(unittest.TestCase):
    R = {"cvss_critico": 9.0, "epss_critico": 0.5, "kev_es_critico": True}

    def h(self, **kw):
        return Hallazgo(id="CVE-1", componente="x", nombre="x", version="1", resumen="", **kw)

    def test_reglas(self):
        self.assertTrue(es_critico(self.h(cvss=9.8), self.R))
        self.assertTrue(es_critico(self.h(cvss=5.0, kev=True), self.R))
        self.assertTrue(es_critico(self.h(cvss=7.5, epss=0.6), self.R))
        self.assertFalse(es_critico(self.h(cvss=7.5, epss=0.1), self.R))


class Correcciones(unittest.TestCase):
    def test_restricciones(self):
        from vigilante.compatibilidad import cumple, tipo_salto
        self.assertTrue(cumple("8.1.2", "^7.4 || ^8.0"))
        self.assertFalse(cumple("8.1.2", ">=8.2"))
        self.assertTrue(cumple("16.0.0", ">= 14"))
        self.assertIsNone(cumple("1.0", "1.0 - 2.0"))
        self.assertEqual(tipo_salto("0.21.0", "1.12.0"), "mayor")

    def test_lista_blanca(self):
        from vigilante.verificacion import comando_seguro
        self.assertIn("--no-scripts", comando_seguro("composer update twig/twig --with-all-dependencies"))
        self.assertIn("--ignore-scripts", comando_seguro("npm install axios@1.12.0"))
        for malo in ("composer update x; rm -rf /", "curl http://x | sh", "npm install x && whoami",
                     "composer update $(id)", "bash -c 'x'"):
            self.assertIsNone(comando_seguro(malo), malo)

    def test_partir_diff(self):
        from vigilante.verificacion import partir_diff
        d = ("--- /dev/null\n+++ b/a.txt\n@@ -0,0 +1 @@\n+hola\n"
             "--- a/b.txt\n+++ b/b.txt\n@@ -1 +1 @@\n-x\n+y\n")
        self.assertEqual(len(partir_diff(d)), 2)
        # una línea borrada que empieza por '---' no parte el diff
        d2 = "--- a/c.md\n+++ b/c.md\n@@ -1,2 +1 @@\n---- separador\n texto\n"
        self.assertEqual(len(partir_diff(d2)), 1)

    def test_claude_por_defecto_solo_a_peticion(self):
        from vigilante import config
        cfg = config.cargar("/no/existe.toml")
        self.assertEqual(cfg["claude"]["modo"], "a_peticion")        # nunca trabaja solo si no se pide
        self.assertTrue(config.DEFECTO["aplicacion"]["rollback_automatico"])

    def test_limite_de_intentos(self):
        from vigilante.panel import LimiteIntentos
        l = LimiteIntentos(maximo=3, bloqueo_s=60)
        for _ in range(2):
            l.fallo("1.1.1.1", ahora=100)
        self.assertEqual(l.restante("1.1.1.1", ahora=100), 0)       # aún puede intentarlo
        l.fallo("1.1.1.1", ahora=100)
        self.assertEqual(l.restante("1.1.1.1", ahora=110), 50)      # bloqueada
        self.assertEqual(l.restante("2.2.2.2", ahora=110), 0)       # otras IP no
        self.assertEqual(l.restante("1.1.1.1", ahora=161), 0)       # el bloqueo caduca
        l.fallo("3.3.3.3", ahora=0); l.acierto("3.3.3.3"); l.fallo("3.3.3.3", ahora=0); l.fallo("3.3.3.3", ahora=0)
        self.assertEqual(l.restante("3.3.3.3", ahora=1), 0)         # un acierto reinicia la cuenta

    def test_decisiones(self):
        import tempfile
        from vigilante.planes import Planes, aprobados
        with tempfile.TemporaryDirectory() as tmp:
            pl = Planes(tmp)
            p = pl.crear({"clave": "x", "nombre": "x", "version": "1"}, [], tmp)
            p["cambios"] = [{"n": 1}, {"n": 2}]
            p["estado"] = "pendiente_aprobacion"
            pl.guardar(p)
            pl.decidir(p["id"], 1, "aprobado", "yo")
            p, _ = pl.decidir(p["id"], 2, "rechazado", "yo")
            self.assertEqual([c["n"] for c in aprobados(p)], [1])
            p, _ = pl.decidir(p["id"], None, "rechazado", "yo")
            self.assertEqual(p["estado"], "rechazado")
            _, msg = pl.decidir(p["id"], 1, "aprobado", "yo")      # ya no admite decisiones
            self.assertIn("ya no admite", msg)


if __name__ == "__main__":
    unittest.main()
