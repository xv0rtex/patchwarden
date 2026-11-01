"""Catálogo de runtimes/servidores conocidos: cómo reconocerlos y cómo buscarlos en NVD.

Cada entrada dice:
  env      -> variables de entorno que ponen las imágenes oficiales de Docker Hub
  imagenes -> nombres de imagen (php, nginx, eclipse-temurin…)
  cpe      -> prefijos CPE 2.3 de NVD (vendor:product) para buscar CVE por versión
  eol      -> producto en endoflife.date
  sonda    -> comando para preguntar la versión dentro del contenedor (opcional)
  regex    -> cómo sacar la versión de la salida de la sonda / cabecera HTTP
"""
import re

RUNTIMES = {
    "php": {
        "env": ["PHP_VERSION"], "imagenes": ["php", "bitnami/php-fpm"],
        "cpe": ["php:php"], "eol": "php",
        "sonda": ["php", "-r", "echo PHP_VERSION;"], "regex": r"PHP/?\s*(\d+\.\d+\.\d+)",
    },
    "nginx": {
        "env": ["NGINX_VERSION"], "imagenes": ["nginx", "nginxinc/nginx-unprivileged"],
        "cpe": ["f5:nginx", "nginx:nginx"], "eol": "nginx",
        "sonda": ["nginx", "-v"], "regex": r"nginx/(\d+\.\d+\.\d+)",
    },
    "apache-httpd": {
        "env": ["HTTPD_VERSION"], "imagenes": ["httpd"],
        "cpe": ["apache:http_server"], "eol": "apache-http-server",
        "sonda": ["httpd", "-v"], "regex": r"Apache/(\d+\.\d+\.\d+)",
    },
    "tomcat": {
        "env": ["TOMCAT_VERSION"], "imagenes": ["tomcat"],
        "cpe": ["apache:tomcat"], "eol": "tomcat",
        "sonda": None, "regex": r"Apache Tomcat/(\d+\.\d+\.\d+)",
    },
    "java": {
        # eclipse-temurin pone JAVA_VERSION=jdk-17.0.8+7 ; openjdk pone JAVA_VERSION=17.0.2
        "env": ["JAVA_VERSION"], "imagenes": ["openjdk", "eclipse-temurin", "amazoncorretto"],
        "cpe": ["oracle:openjdk"], "eol": "eclipse-temurin",
        "sonda": ["java", "-version"], "regex": r"(?:jdk-|version \")?(\d+(?:\.\d+){1,2})",
    },
    "node": {
        "env": ["NODE_VERSION"], "imagenes": ["node"],
        "cpe": ["nodejs:node.js"], "eol": "nodejs",
        "sonda": ["node", "-v"], "regex": r"v?(\d+\.\d+\.\d+)",
    },
    "python": {
        "env": ["PYTHON_VERSION"], "imagenes": ["python"],
        "cpe": ["python:python"], "eol": "python",
        "sonda": ["python3", "--version"], "regex": r"Python (\d+\.\d+\.\d+)",
    },
    "ruby": {
        "env": ["RUBY_VERSION"], "imagenes": ["ruby"],
        "cpe": ["ruby-lang:ruby"], "eol": "ruby",
        "sonda": ["ruby", "-v"], "regex": r"ruby (\d+\.\d+\.\d+)",
    },
    "go": {
        "env": ["GOLANG_VERSION"], "imagenes": ["golang"],
        "cpe": ["golang:go"], "eol": "go", "sonda": None, "regex": r"go(\d+\.\d+(?:\.\d+)?)",
    },
    "mysql": {
        "env": ["MYSQL_VERSION"], "imagenes": ["mysql"],
        "cpe": ["oracle:mysql"], "eol": "mysql",
        "sonda": ["mysqld", "--version"], "regex": r"Ver (\d+\.\d+\.\d+)",
    },
    "mariadb": {
        "env": ["MARIADB_VERSION"], "imagenes": ["mariadb"],
        "cpe": ["mariadb:mariadb"], "eol": "mariadb",
        "sonda": ["mariadbd", "--version"], "regex": r"(\d+\.\d+\.\d+)-MariaDB",
    },
    "postgresql": {
        "env": ["PG_VERSION"], "imagenes": ["postgres"],
        "cpe": ["postgresql:postgresql"], "eol": "postgresql",
        "sonda": ["postgres", "--version"], "regex": r"(\d+\.\d+)",
    },
    "redis": {
        "env": ["REDIS_VERSION"], "imagenes": ["redis"],
        "cpe": ["redis:redis"], "eol": "redis",
        "sonda": ["redis-server", "--version"], "regex": r"v=(\d+\.\d+\.\d+)",
    },
    "wordpress": {
        "env": ["WORDPRESS_VERSION"], "imagenes": ["wordpress"],
        "cpe": ["wordpress:wordpress"], "eol": "wordpress",
        "sonda": None, "regex": r"WordPress (\d+\.\d+(?:\.\d+)?)",
    },
}

_VERSION = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def limpiar_version(texto: str) -> str | None:
    """'jdk-17.0.8+7' -> '17.0.8', '8.2.10-fpm-alpine' -> '8.2.10', 'latest' -> None."""
    if not texto:
        return None
    m = _VERSION.search(texto)
    return m.group(1) if m else None


def runtime_por_imagen(imagen: str):
    """'docker.io/library/php:8.2.10-fpm' -> ('php', '8.2.10')."""
    ref = imagen.split("@")[0]
    nombre, _, etiqueta = ref.rpartition(":") if ":" in ref.split("/")[-1] else (ref, "", "")
    base = nombre.split("/")
    corto = base[-1]
    con_org = "/".join(base[-2:]) if len(base) >= 2 else corto
    for rt, info in RUNTIMES.items():
        if corto in info["imagenes"] or con_org in info["imagenes"]:
            return rt, limpiar_version(etiqueta)
    return None, None
