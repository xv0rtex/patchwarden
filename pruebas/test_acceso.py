"""Login de la cuenta única, sesiones, CSRF y Ajustes (sin red ni Docker)."""
import http.cookiejar
import os
import re
import shutil
import socket
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vigilante"))

from vigilante import ajustes, config, panel, usuarios  # noqa: E402
from vigilante.motor import Vigilante  # noqa: E402


class Cuenta(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.c = usuarios.Cuenta(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_crear_exige_codigo_y_clave_larga(self):
        codigo = self.c.codigo_inicial()
        with self.assertRaises(usuarios.ErrorCuenta):
            self.c.crear("ana", "una-clave-larga-1", codigo="malo")
        with self.assertRaises(usuarios.ErrorCuenta):
            self.c.crear("ana", "corta", codigo=codigo)
        self.c.crear("ana", "una-clave-larga-1", codigo=codigo)
        self.assertTrue(self.c.existe())
        self.assertFalse(os.path.exists(self.c.ruta_codigo), "el código se borra al usarse")
        with self.assertRaises(usuarios.ErrorCuenta):
            self.c.crear("otro", "una-clave-larga-2", codigo=codigo)

    def test_clave_con_scrypt_y_comprobacion(self):
        self.c.crear("ana", "una-clave-larga-1", validar=True)
        texto = open(self.c.ruta).read()
        self.assertNotIn("una-clave-larga-1", texto)
        self.assertEqual(os.stat(self.c.ruta).st_mode & 0o777, 0o600)
        self.assertTrue(self.c.comprobar("ana", "una-clave-larga-1"))
        self.assertFalse(self.c.comprobar("ana", "otra-clave-larga"))
        self.assertFalse(self.c.comprobar("eva", "una-clave-larga-1"))
        # se recarga desde disco
        self.assertTrue(usuarios.Cuenta(self.tmp).comprobar("ana", "una-clave-larga-1"))

    def test_sesiones_y_cambio_de_clave(self):
        self.c.crear("ana", "una-clave-larga-1")
        a, b = self.c.crear_sesion(), self.c.crear_sesion()
        self.assertIsNotNone(self.c.sesion(a))
        self.assertNotIn(a, open(self.c.ruta_sesiones).read(), "en disco solo el hash de la sesión")
        self.c.cambiar_clave("una-clave-larga-1", "otra-clave-larga-2", sesion_actual=a)
        self.assertIsNotNone(self.c.sesion(a), "la sesión desde la que se cambia sigue abierta")
        self.assertIsNone(self.c.sesion(b), "las demás se cierran")
        with self.assertRaises(usuarios.ErrorCuenta):
            self.c.cambiar_clave("mal", "otra-clave-larga-3")
        self.c.cerrar(a)
        self.assertIsNone(self.c.sesion(a))


class Ajustes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = config.cargar("/no/existe.toml")
        self.cfg["general"]["carpeta_datos"] = self.tmp
        self.a = ajustes.Ajustes(self.cfg, self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("TELEGRAM_CHAT_ID", None)
        os.environ.pop("VIGILANTE_DATOS", None)

    def test_guardar_valida_y_aplica_en_caliente(self):
        cambiados = self.a.guardar("reglas", {"reglas.cvss_critico": "8,5", "reglas.ignorar": "CVE-1, CVE-2",
                                              "reglas.kev_es_critico": "si"})
        self.assertIn("reglas.cvss_critico", cambiados)
        self.assertEqual(self.cfg["reglas"]["cvss_critico"], 8.5)
        self.assertEqual(self.cfg["reglas"]["ignorar"], ["CVE-1", "CVE-2"])
        with self.assertRaises(ajustes.ErrorAjuste):
            self.a.guardar("reglas", {"reglas.cvss_critico": "11"})
        with self.assertRaises(ajustes.ErrorAjuste):
            self.a.guardar("claude", {"claude.modelo": "no-existe"})

    def test_solo_campos_del_formulario(self):
        self.a.guardar("claude", {"campos": "claude.modelo", "claude.modelo": self.cfg["claude"]["modelo"]})
        self.assertTrue(self.cfg["claude"]["investigar_web"], "una casilla de otra tarjeta no se toca")

    def test_secretos(self):
        self.a.guardar("avisos", {"avisos.telegram_token": "123456:ABCDEFGHIJKL"})
        self.assertEqual(self.cfg["avisos"]["telegram_token"], "123456:ABCDEFGHIJKL")
        self.a.guardar("avisos", {"avisos.telegram_token": "  "})
        self.assertEqual(self.cfg["avisos"]["telegram_token"], "123456:ABCDEFGHIJKL", "vacío = conservar")
        self.assertEqual(ajustes.enmascarar("123456:ABCDEFGHIJKL"), "••••IJKL")
        self.assertEqual(ajustes.enmascarar("corto"), "••••")
        self.a.guardar("avisos", {"avisos.telegram_token": "", "avisos.telegram_token.borrar": "si"})
        self.assertEqual(self.cfg["avisos"]["telegram_token"], "")
        self.assertEqual(os.stat(self.a.ruta).st_mode & 0o777, 0o600)
        with self.assertRaises(ajustes.ErrorAjuste):
            self.a.guardar("avisos", {"avisos.telegram_chat_id": "1\nX-Inyectado: si"})

    def test_precedencia_entorno_panel_fichero(self):
        self.a.guardar("avisos", {"avisos.telegram_chat_id": "111", "avisos.webhook_url": "https://x.example"})
        os.environ["VIGILANTE_DATOS"] = self.tmp
        os.environ["TELEGRAM_CHAT_ID"] = "999"
        cfg = config.cargar("/no/existe.toml")
        self.assertEqual(cfg["avisos"]["webhook_url"], "https://x.example", "panel por encima del fichero")
        self.assertEqual(cfg["avisos"]["telegram_chat_id"], "999", "la variable de entorno manda")
        a = ajustes.Ajustes(cfg, self.tmp)
        campo = ajustes.CAMPOS["avisos.telegram_chat_id"]
        self.assertEqual(a.variable_que_fija(campo), "TELEGRAM_CHAT_ID")
        a.guardar("avisos", {"avisos.telegram_chat_id": "222"})
        self.assertEqual(cfg["avisos"]["telegram_chat_id"], "999", "un campo fijado no se cambia desde el panel")


def _puerto_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SinRedireccion(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class PanelHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cfg = config.cargar("/no/existe.toml")
        cfg["general"]["carpeta_datos"] = cls.tmp
        cfg["deteccion"].update(docker=False, rutas_proyecto=[])
        cfg["avisos"]["consola"] = False
        cfg["panel"]["token"] = "token-api"
        cls.v = Vigilante(cfg)
        cls.puerto = _puerto_libre()
        cls.srv = panel.arrancar(cls.v, cls.puerto, "127.0.0.1")
        cls.base = f"http://127.0.0.1:{cls.puerto}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.tarro = http.cookiejar.CookieJar()
        self.nav = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.tarro), SinRedireccion)

    def pedir(self, ruta, datos=None, cabeceras=None):
        cuerpo = urllib.parse.urlencode(datos).encode() if datos is not None else None
        req = urllib.request.Request(self.base + ruta, data=cuerpo, headers=cabeceras or {})
        try:
            r = self.nav.open(req)
            return r.status, r.headers, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode()

    def csrf(self, ruta="/ajustes/general"):
        html = self.pedir(ruta)[2]
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def test_recorrido(self):
        # 1. sin cuenta: todo lleva a la configuración inicial, salvo con el token de API
        c, h, _ = self.pedir("/")
        self.assertEqual((c, h["Location"]), (303, "/configuracion-inicial"))
        self.assertEqual(self.pedir("/", cabeceras={"X-Token": "token-api"})[0], 200)
        # 2. crear la cuenta: código incorrecto no; correcto sí, y entra
        self.assertEqual(self.pedir("/configuracion-inicial", {"codigo": "x", "usuario": "ana",
                                                               "clave": "una-clave-larga-1",
                                                               "clave2": "una-clave-larga-1"})[0], 400)
        codigo = open(os.path.join(self.tmp, "codigo-inicial.txt")).read().strip()
        c, h, _ = self.pedir("/configuracion-inicial", {"codigo": codigo, "usuario": "ana",
                                                        "clave": "una-clave-larga-1", "clave2": "una-clave-larga-1"})
        self.assertEqual(c, 303)
        self.assertIn("HttpOnly", h["Set-Cookie"])
        self.assertIn("SameSite=Strict", h["Set-Cookie"])
        c, _, html = self.pedir("/ajustes/avisos")
        self.assertEqual(c, 200)
        self.assertIn("Telegram", html)
        # 3. CSRF: sin el token de la sesión no se guarda nada
        c, _, _ = self.pedir("/ajustes/guardar", {"pestana": "reglas", "reglas.cvss_critico": "8"})
        self.assertEqual(c, 403)
        self.assertEqual(self.v.cfg["reglas"]["cvss_critico"], 9.0)
        c, h, _ = self.pedir("/ajustes/guardar", {"pestana": "reglas", "campos": "reglas.cvss_critico",
                                                  "reglas.cvss_critico": "8", "csrf": self.csrf()})
        self.assertEqual(c, 303)
        self.assertEqual(self.v.cfg["reglas"]["cvss_critico"], 8.0)
        # 4. el secreto no vuelve al navegador
        self.pedir("/ajustes/guardar", {"pestana": "avisos", "campos": "avisos.telegram_token",
                                        "avisos.telegram_token": "123456:SECRETOSECRETO", "csrf": self.csrf()})
        html = self.pedir("/ajustes/avisos")[2]
        self.assertNotIn("123456:SECRETOSECRETO", html)
        self.assertIn("••••RETO", html)
        # 5. salir y volver a entrar; contraseña mala = 401; redirección abierta no
        self.pedir("/salir", {"csrf": self.csrf()})
        c, h, _ = self.pedir("/correcciones")
        self.assertEqual(c, 303)
        self.assertTrue(h["Location"].startswith("/entrar?volver="))
        self.assertEqual(self.pedir("/entrar", {"usuario": "ana", "clave": "mala-mala-mala"})[0], 401)
        c, h, _ = self.pedir("/entrar", {"usuario": "ana", "clave": "una-clave-larga-1", "volver": "//malo.example"})
        self.assertEqual((c, h["Location"]), (303, "/"))
        self.assertEqual(self.pedir("/componentes")[0], 200)

    def test_z_bloqueo_tras_intentos_fallidos(self):      # tras test_recorrido: ya hay cuenta
        ip = "10.9.9.9"
        for _ in range(10):
            self.pedir("/entrar", {"usuario": "x", "clave": "y"}, {"CF-Connecting-IP": ip})
        self.assertEqual(self.pedir("/entrar", {"usuario": "x", "clave": "y"}, {"CF-Connecting-IP": ip})[0], 429)


if __name__ == "__main__":
    unittest.main()
