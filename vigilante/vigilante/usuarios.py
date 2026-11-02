"""Cuenta única del panel y sesiones.

- La cuenta (usuario + contraseña) se crea en el primer arranque desde /configuracion-inicial, que pide un
  código de un solo uso impreso en el log y guardado en <datos>/codigo-inicial.txt: así nadie que llegue
  antes que tú al panel recién instalado puede quedarse con él. Si la configuración trae
  [panel] usuario/clave, la cuenta se crea con ellos (migración desde la contraseña HTTP Basic).
- La contraseña se guarda con scrypt y sal; nunca en claro.
- Sesiones: id aleatorio en una cookie HttpOnly; en disco solo se guarda su hash. Cada sesión tiene su
  token CSRF, que va en un campo oculto de cada formulario.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time

log = logging.getLogger("vigilante.usuarios")

DURACION_SESION_S = 12 * 3600
MIN_CLAVE = 12
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}


def _hash_clave(clave: str, sal: bytes, n: int, r: int, p: int) -> str:
    return hashlib.scrypt(clave.encode(), salt=sal, n=n, r=r, p=p, dklen=32, maxmem=64 * 1024 * 1024).hex()


def _sha(texto: str) -> str:
    return hashlib.sha256(texto.encode()).hexdigest()


def _escribir(ruta: str, datos: dict, modo=0o600):
    tmp = ruta + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, modo)
    with os.fdopen(fd, "w") as f:
        json.dump(datos, f, ensure_ascii=False, indent=1)
    os.replace(tmp, ruta)


class ErrorCuenta(Exception):
    pass


def validar_clave(clave: str, usuario: str = "") -> None:
    if len(clave) < MIN_CLAVE:
        raise ErrorCuenta(f"La contraseña debe tener al menos {MIN_CLAVE} caracteres.")
    if usuario and clave.lower() == usuario.lower():
        raise ErrorCuenta("La contraseña no puede ser igual que el usuario.")


class Cuenta:
    def __init__(self, carpeta_datos: str):
        self.ruta = os.path.join(carpeta_datos, "cuenta.json")
        self.ruta_sesiones = os.path.join(carpeta_datos, "sesiones.json")
        self.ruta_codigo = os.path.join(carpeta_datos, "codigo-inicial.txt")
        self._l = threading.Lock()
        self.datos = self._leer(self.ruta) or {}
        self.sesiones: dict[str, dict] = self._leer(self.ruta_sesiones) or {}

    @staticmethod
    def _leer(ruta):
        try:
            with open(ruta) as f:
                d = json.load(f)
            return d if isinstance(d, dict) else None
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------ cuenta
    def existe(self) -> bool:
        return bool(self.datos.get("usuario") and self.datos.get("hash"))

    @property
    def usuario(self) -> str:
        return self.datos.get("usuario", "")

    def codigo_inicial(self) -> str:
        """Código para crear la cuenta (se genera una vez y se guarda hasta que se use)."""
        try:
            with open(self.ruta_codigo) as f:
                codigo = f.read().strip()
            if codigo:
                return codigo
        except OSError:
            pass
        codigo = "-".join(secrets.token_hex(3) for _ in range(3))
        fd = os.open(self.ruta_codigo, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(codigo + "\n")
        return codigo

    def crear(self, usuario: str, clave: str, codigo: str | None = None, validar=True):
        """Crea la cuenta. Con codigo != None exige el código inicial (alta desde el panel)."""
        usuario = usuario.strip()
        with self._l:
            if self.existe():
                raise ErrorCuenta("La cuenta ya existe.")
            if codigo is not None and not hmac.compare_digest(codigo.strip(), self.codigo_inicial()):
                raise ErrorCuenta("El código de configuración no es correcto. Está en el log del contenedor "
                                  "y en codigo-inicial.txt dentro de la carpeta de datos.")
            if not usuario or len(usuario) > 64:
                raise ErrorCuenta("Indica un nombre de usuario (máximo 64 caracteres).")
            if validar:
                validar_clave(clave, usuario)
            self._poner_clave(usuario, clave)
            try:
                os.remove(self.ruta_codigo)
            except OSError:
                pass
        log.info("Cuenta del panel creada para «%s»", usuario)

    def _poner_clave(self, usuario: str, clave: str):
        sal = secrets.token_bytes(16)
        self.datos = {"usuario": usuario, "sal": sal.hex(), **SCRYPT,
                      "hash": _hash_clave(clave, sal, **SCRYPT), "cambiada": int(time.time())}
        _escribir(self.ruta, self.datos)

    def comprobar(self, usuario: str, clave: str) -> bool:
        d = self.datos
        if not self.existe():
            return False
        calculado = _hash_clave(clave, bytes.fromhex(d["sal"]), d.get("n", SCRYPT["n"]), d.get("r", 8), d.get("p", 1))
        # se compara también el usuario en tiempo constante (y siempre se calcula el hash)
        return hmac.compare_digest(calculado, d["hash"]) & hmac.compare_digest(usuario.strip(), d["usuario"])

    def cambiar_clave(self, actual: str, nueva: str, sesion_actual: str | None = None):
        if not self.comprobar(self.usuario, actual):
            raise ErrorCuenta("La contraseña actual no es correcta.")
        validar_clave(nueva, self.usuario)
        with self._l:
            self._poner_clave(self.usuario, nueva)
        self.cerrar_otras(sesion_actual)      # quien tuviera la contraseña vieja queda fuera

    # ------------------------------------------------------------------ sesiones
    def _guardar_sesiones(self):
        ahora = time.time()
        self.sesiones = {k: s for k, s in self.sesiones.items() if s.get("caduca", 0) > ahora}
        _escribir(self.ruta_sesiones, self.sesiones)

    def crear_sesion(self, ip: str = "", agente: str = "") -> str:
        sid = secrets.token_urlsafe(32)
        with self._l:
            self.sesiones[_sha(sid)] = {"csrf": secrets.token_urlsafe(24), "creada": int(time.time()),
                                        "caduca": int(time.time()) + DURACION_SESION_S,
                                        "ip": ip, "agente": agente[:120]}
            self._guardar_sesiones()
        return sid

    def sesion(self, sid: str) -> dict | None:
        if not sid or not self.existe():
            return None
        s = self.sesiones.get(_sha(sid))
        if not s or s.get("caduca", 0) <= time.time() or s.get("creada", 0) < self.datos.get("cambiada", 0):
            return None
        return s

    def cerrar(self, sid: str):
        with self._l:
            if self.sesiones.pop(_sha(sid or ""), None) is not None:
                self._guardar_sesiones()

    def cerrar_otras(self, sid: str | None) -> int:
        conservar = _sha(sid) if sid else None
        with self._l:
            n = sum(1 for k in self.sesiones if k != conservar)
            self.sesiones = {k: s for k, s in self.sesiones.items() if k == conservar}
            if conservar in self.sesiones:      # tras cambiar la clave, la sesión actual sigue valiendo
                self.sesiones[conservar]["creada"] = int(time.time())
            self._guardar_sesiones()
        return n

    def n_sesiones(self) -> int:
        """Sesiones que siguen valiendo (sin caducar y abiertas después del último cambio de contraseña)."""
        ahora, cambiada = time.time(), self.datos.get("cambiada", 0)
        return sum(1 for s in self.sesiones.values() if s.get("caduca", 0) > ahora and s.get("creada", 0) >= cambiada)
