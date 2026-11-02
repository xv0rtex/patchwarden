"""APIs falsas para probar el flujo completo sin clave ni bot real.

- ClaudeFalso: un ejecutable que imita a `claude -p --output-format json`: devuelve un plan de
  corrección en `structured_output` y guarda argumentos, entrada y entorno de cada ejecución.
- TelegramFalso: simula la Bot API (sendMessage, editMessageText, getUpdates,
  answerCallbackQuery). Las pruebas «pulsan» botones con pulsar().
- WebFalsa: la web desplegada; se puede poner a responder 500 para probar el rollback.
"""
import json
import os
import queue
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PLAN_PHP = {
    "entendimiento": {
        "resumen": "PHP 8.1.2 tiene 40 vulnerabilidades corregidas en versiones posteriores; varias permiten "
                   "ejecución de código (CVE-2024-4577, explotada activamente en PHP-CGI) y la rama 8.1 ya no "
                   "recibe parches.",
        "version_afectada": "8.1.0 – 8.1.33 (y toda la rama 8.1, sin soporte)",
        "version_corregida": "8.2.29 (rama 8.2 con soporte de seguridad)",
        "exposicion": "La web usa php-fpm detrás de nginx (no PHP-CGI), así que CVE-2024-4577 no es explotable "
                      "tal cual, pero el resto sí aplica.",
        "cves_cubiertos": ["CVE-2024-4577", "CVE-2021-21708", "CVE-2023-3824"],
    },
    "version_objetivo": "8.2.29",
    "estrategia": "Pasar a la imagen oficial php:8.2.29-fpm (la 8.1 no tiene soporte) y ocultar la versión de PHP.",
    "cambios": [
        {"n": 1, "tipo": "actualizar_imagen", "titulo": "Imagen base php:8.1.2-fpm → php:8.2.29-fpm",
         "ficheros": ["web/app/Dockerfile"],
         "diff": "--- a/web/app/Dockerfile\n+++ b/web/app/Dockerfile\n@@ -1,4 +1,4 @@\n"
                 " # Imagen PHP de la web (versión antigua a propósito para la demo)\n-FROM php:8.1.2-fpm\n"
                 "+FROM php:8.2.29-fpm\n WORKDIR /var/www/html\n COPY public/ /var/www/html/\n",
         "comandos_herramienta": [],
         "que_arregla": "Las 40 vulnerabilidades de PHP 8.1.2, incluidas las 3 explotadas activamente.",
         "por_que_es_correcto": "8.2.29 es la versión más baja con soporte que incluye todas las correcciones; "
                                "la 8.1 está fuera de soporte desde el 31-12-2025.",
         "riesgo_nivel": "medio", "riesgo_detalle": "Cambio de rama 8.1 → 8.2: hay deprecaciones (propiedades "
                                                    "dinámicas, utf8_encode) que pueden generar avisos.",
         "breaking_changes": ["Las propiedades dinámicas están deprecadas", "utf8_encode/utf8_decode deprecadas"],
         "dependencias": ["guzzlehttp/guzzle 7.4 es compatible con PHP 8.2"],
         "deprecaciones": ["${var} dentro de cadenas está deprecado"],
         "como_revertir": "Volver a FROM php:8.1.2-fpm y reconstruir la imagen (o usar la imagen de respaldo).",
         "depende_de": []},
        {"n": 2, "tipo": "configuracion", "titulo": "Ocultar la versión de PHP (expose_php = Off)",
         "ficheros": ["web/app/php/seguridad.ini", "web/app/Dockerfile"],
         "diff": "--- /dev/null\n+++ b/web/app/php/seguridad.ini\n@@ -0,0 +1,2 @@\n"
                 "+; Ocultar la versión de PHP en las cabeceras\n+expose_php = Off\n"
                 "--- a/web/app/Dockerfile\n+++ b/web/app/Dockerfile\n@@ -2,3 +2,4 @@\n"
                 " FROM php:8.1.2-fpm\n WORKDIR /var/www/html\n COPY public/ /var/www/html/\n"
                 "+COPY php/seguridad.ini /usr/local/etc/php/conf.d/seguridad.ini\n",
         "comandos_herramienta": [],
         "que_arregla": "Deja de anunciar «X-Powered-By: PHP/8.x», lo que dificulta a un atacante elegir exploit.",
         "por_que_es_correcto": "Es la recomendación de php.ini-production; no cambia el comportamiento de la app.",
         "riesgo_nivel": "bajo", "riesgo_detalle": "Ninguno funcional; solo deja de enviarse una cabecera.",
         "breaking_changes": [], "dependencias": [], "deprecaciones": [],
         "como_revertir": "Borrar seguridad.ini y la línea COPY del Dockerfile.",
         "depende_de": []},
    ],
    "pruebas_recomendadas": ["Cargar la portada", "Revisar el log de php-fpm por avisos de deprecación"],
    "fuentes_consultadas": ["https://www.php.net/manual/es/migration82.php", "https://www.php.net/ChangeLog-8.php"],
}

def _plan_guzzle(bueno: bool):
    contexto = '"guzzlehttp/guzzle": "^7.4",' if bueno else '"guzzlehttp/guzzle": "^7.3",'   # el malo no encaja
    return {
        "entendimiento": {"resumen": "Guzzle 7.4.0 filtra cabeceras Authorization/Cookie en redirecciones.",
                          "version_afectada": "< 7.4.5", "version_corregida": "7.4.5",
                          "exposicion": "Sí, si se siguen redirecciones a otros dominios.",
                          "cves_cubiertos": ["CVE-2022-31090", "CVE-2022-31091"]},
        "version_objetivo": "7.4.5",
        "estrategia": "Subir a 7.4.5 (parche dentro de 7.4).",
        "cambios": [{"n": 1, "tipo": "actualizar_dependencia", "titulo": "guzzlehttp/guzzle 7.4.0 → 7.4.5",
                     "ficheros": ["web/app/composer.json", "web/app/composer.lock"],
                     "diff": "--- a/web/app/composer.json\n+++ b/web/app/composer.json\n@@ -4,3 +4,3 @@\n"
                             f"     \"php\": \"^8.1\",\n-    {contexto}\n+    \"guzzlehttp/guzzle\": \"^7.4.5\",\n"
                             "     \"twig/twig\": \"^3.3\"\n",
                     "comandos_herramienta": ["composer update guzzlehttp/guzzle --with-all-dependencies"],
                     "que_arregla": "Fuga de credenciales en redirecciones.", "por_que_es_correcto": "Parche oficial.",
                     "riesgo_nivel": "bajo", "riesgo_detalle": "Versión de parche.", "breaking_changes": [],
                     "dependencias": [], "deprecaciones": [], "como_revertir": "Restaurar composer.json/lock.",
                     "depende_de": []}],
        "pruebas_recomendadas": [], "fuentes_consultadas": []}


PLAN_TWIG = {
    "entendimiento": {
        "resumen": "Twig 3.3.7 permite inyección de código PHP mediante nombres de plantilla en {% use %} "
                   "(CVE-2026-46633) y tiene fallos de sandbox.",
        "version_afectada": "< 3.26.0", "version_corregida": "3.27.0",
        "exposicion": "Solo si los nombres de plantilla vienen de entrada del usuario; aun así conviene actualizar.",
        "cves_cubiertos": ["CVE-2026-46633", "CVE-2024-45411"],
    },
    "version_objetivo": "3.27.0",
    "estrategia": "Actualizar twig/twig dentro de la versión mayor 3 (sin cambios incompatibles anunciados).",
    "cambios": [
        {"n": 1, "tipo": "actualizar_dependencia", "titulo": "twig/twig 3.3.7 → 3.27.0",
         "ficheros": ["web/app/composer.json", "web/app/composer.lock"],
         "diff": "--- a/web/app/composer.json\n+++ b/web/app/composer.json\n@@ -4,6 +4,6 @@\n"
                 "     \"php\": \"^8.1\",\n     \"guzzlehttp/guzzle\": \"^7.4\",\n-    \"twig/twig\": \"^3.3\"\n"
                 "+    \"twig/twig\": \"^3.27\"\n   }\n }\n",
         "comandos_herramienta": ["composer update twig/twig --with-all-dependencies"],
         "que_arregla": "Las 16 vulnerabilidades de Twig, incluida la inyección de código (CVSS 9.5).",
         "por_que_es_correcto": "3.27.0 es la primera versión que corrige todas; misma versión mayor y exige "
                                "PHP >= 8.1, que es lo desplegado.",
         "riesgo_nivel": "bajo", "riesgo_detalle": "Versión menor dentro de 3.x; Twig mantiene compatibilidad.",
         "breaking_changes": [], "dependencias": ["symfony/polyfill-mbstring se mantiene"],
         "deprecaciones": ["Twig 3.x marca como deprecado el filtro spaceless"],
         "como_revertir": "Restaurar composer.json y composer.lock y ejecutar composer install.",
         "depende_de": []},
    ],
    "pruebas_recomendadas": ["Renderizar las plantillas principales"],
    "fuentes_consultadas": ["https://github.com/twigphp/Twig/blob/3.x/CHANGELOG"],
}


def _servidor(manejador):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), manejador)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        d = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(d)))
        self.end_headers()
        self.wfile.write(d)

    def _leer(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")


# ------------------------------------------------------------------------- Claude
def cli_falsa(registro):
    """Lo que ejecuta el `claude` falso: registra la llamada y responde como `claude -p`."""
    texto = sys.stdin.read()
    if "- guzzlehttp/guzzle 7.4.0" in texto:      # 1ª vez mal; al corregir, bien
        plan = _plan_guzzle(bueno="FALLADO" in texto)
    elif "- php 8.1.2" in texto:
        plan = PLAN_PHP
    elif "- twig/twig 3.3.7" in texto:
        plan = PLAN_TWIG
    else:
        plan = {**PLAN_TWIG, "cambios": [], "estrategia": "sin propuesta"}
    with open(registro, "a") as f:
        f.write(json.dumps({"args": sys.argv[1:], "entrada": texto, "entorno": dict(os.environ)}) + "\n")
    print(json.dumps({"type": "result", "subtype": "success", "is_error": False, "structured_output": plan}))


class ClaudeFalso:
    def __init__(self):
        carpeta = tempfile.mkdtemp(prefix="claude-falso-")
        self.registro = os.path.join(carpeta, "peticiones.jsonl")
        self.comando = os.path.join(carpeta, "claude")
        with open(self.comando, "w") as f:
            f.write(f"#!{sys.executable}\nimport sys\n"
                    f"sys.path.insert(0, {os.path.dirname(os.path.abspath(__file__))!r})\n"
                    f"import apis_falsas\napis_falsas.cli_falsa({self.registro!r})\n")
        os.chmod(self.comando, 0o755)

    @property
    def peticiones(self):
        if not os.path.exists(self.registro):
            return []
        with open(self.registro) as f:
            return [json.loads(linea) for linea in f]


# ------------------------------------------------------------------------- Telegram
class TelegramFalso:
    def __init__(self, chat_id="1234"):
        self.chat_id = chat_id
        self.mensajes = {}          # message_id -> {"text", "botones"}
        self.orden = []
        self.respuestas = []        # textos de answerCallbackQuery
        self.cola = queue.Queue()
        self.n = 0
        padre = self

        class M(_Base):
            def do_POST(self):
                metodo = self.path.rsplit("/", 1)[-1]
                d = self._leer()
                if metodo == "sendMessage":
                    padre.n += 1
                    padre.mensajes[padre.n] = {"text": d["text"], "html": d.get("parse_mode") == "HTML",
                                               "botones": (d.get("reply_markup") or {}).get("inline_keyboard", [])}
                    padre.orden.append(padre.n)
                    return self._json({"ok": True, "result": {"message_id": padre.n}})
                if metodo == "editMessageText":
                    padre.mensajes[d["message_id"]] = {"text": d["text"], "html": d.get("parse_mode") == "HTML",
                                                       "botones": (d.get("reply_markup") or {}).get("inline_keyboard", [])}
                    return self._json({"ok": True, "result": True})
                if metodo == "answerCallbackQuery":
                    padre.respuestas.append(d.get("text", ""))
                    return self._json({"ok": True, "result": True})
                if metodo == "getUpdates":
                    try:
                        u = padre.cola.get(timeout=1.5)
                        return self._json({"ok": True, "result": [u]})
                    except queue.Empty:
                        return self._json({"ok": True, "result": []})
                self._json({"ok": False}, 404)

        self.srv, self.url = _servidor(M)

    def pulsar(self, message_id, callback_data, chat=None, usuario=99):
        self.n += 1
        self.cola.put({"update_id": 1000 + self.n, "callback_query": {
            "id": f"cq{self.n}", "data": callback_data, "from": {"id": usuario, "username": "demo"},
            "message": {"message_id": message_id, "chat": {"id": int(chat or self.chat_id)}}}})

    def buscar(self, texto) -> list[int]:
        return [i for i in self.orden if texto in self.mensajes[i]["text"]]

    def boton(self, message_id, texto_boton) -> str:
        for fila in self.mensajes[message_id]["botones"]:
            for b in fila:
                if texto_boton in b["text"]:
                    return b["callback_data"]
        raise KeyError(f"no hay botón «{texto_boton}» en el mensaje {message_id}")

    def esperar(self, condicion, segundos=30):
        limite = time.time() + segundos
        while time.time() < limite:
            if condicion():
                return True
            time.sleep(0.3)
        return False


# ------------------------------------------------------------------------- web
class WebFalsa:
    """Responde 500 mientras exista el fichero `rota` (el despliegue de prueba lo crea/borra)."""
    def __init__(self, rota=None):
        self.rota = rota
        padre = self

        class M(_Base):
            def do_GET(self):
                padre.ok = not (padre.rota and os.path.exists(padre.rota))
                codigo = 200 if padre.ok else 500
                cuerpo = b"<h1>Web de ejemplo</h1>" if padre.ok else b"PHP Fatal error: Uncaught Error"
                self.send_response(codigo)
                self.send_header("Content-Length", str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)

        self.srv, self.url = _servidor(M)
        self.puerto = self.srv.server_address[1]
