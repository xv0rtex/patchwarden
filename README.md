# Vigilante de vulnerabilidades para webs en Docker

Contenedor que corre junto a una web desplegada, detecta las versiones (PHP, nginx, Java,
Tomcat, Node… y dependencias de Composer/npm/Maven/PyPI…), las cruza con **NVD, OSV.dev, CISA KEV,
EPSS y endoflife.date**, **avisa siempre** y puede poner la web en **modo mantenimiento**.

Si hay clave de Anthropic, puedes **pedirle a Claude** que prepare los cambios que lo corrigen, cada uno con su
justificación (qué arregla, por qué es correcto, qué riesgo tiene y cómo revertirlo) y su revisión
de compatibilidad. El vigilante los **verifica en una copia** con contenedores de prueba.
**Claude nunca actúa por su cuenta**: solo trabaja cuando pulsas «Resolver con Claude» (en el panel, con una
ventana de confirmación que explica qué se envía a Anthropic, o en Telegram, con doble confirmación). El
vigilante únicamente te lo ofrece cuando detecta algo importante. Y **nada se aplica sin tu aprobación**: apruebas o rechazas cada cambio (o todos) desde Telegram o
el panel, y solo entonces se aplica, con copia de seguridad previa, comprobación de la web y
rollback.

- Diseño completo: [`docs/DISENO.md`](docs/DISENO.md) (y `docs/DISENO.pdf`)
- Código: [`vigilante/`](vigilante/)
- Ejemplo listo para `docker compose`: [`ejemplo/`](ejemplo/)
- Pruebas: `python3 -m unittest discover -s pruebas` y `python3 pruebas/prueba_flujo.py`
  (flujo completo con Docker, Claude y Telegram simulados; necesita `pip install anthropic`).
  Opcional: `pruebas/prueba_navegador.py` prueba la interfaz en Chromium (Playwright).
- Capturas de la interfaz: [`capturas/`](capturas/)

## Instalación en un servidor con Docker (sin configurar nada)

```bash
curl -fsSL https://raw.githubusercontent.com/USUARIO/vigilante-cve/main/instalar.sh | bash
```

El script descarga el vigilante, **descubre solo las apps que ya corren en Docker**, elige un puerto
libre, genera la configuración y una contraseña, y lo arranca. Al final imprime la URL del panel, el
usuario y la contraseña. Pregunta (y se puede saltar con Intro) por el token de Telegram y la clave de
Anthropic.

- Por defecto **solo avisa y propone**: monta tus proyectos en solo lectura y no puede modificar nada.
- `--permitir-aplicar`: permite aplicar cambios (siempre con tu aprobación, con copia de seguridad y rollback).
- `--puerto N`, `--local` (panel solo en 127.0.0.1), `--solo NOMBRE` (vigilar solo una app o proyecto).
- **Varias apps en el mismo servidor:** cada proyecto de docker compose es una *app*. El panel tiene un
  desplegable arriba para ver una app o todas, con sus propias vulnerabilidades, componentes y correcciones.
- Volver a ejecutarlo actualiza el vigilante, refresca las apps descubiertas y conserva tus claves.
- `--tunel`: publica el panel en internet con un **túnel rápido de cloudflared** (gratis, sin cuenta ni
  dominio). Al terminar imprime la URL `https://….trycloudflare.com` y, si hay Telegram, te la envía. El panel
  siempre pide usuario y contraseña, y bloquea 5 minutos a quien falle 10 veces. La URL **cambia si se reinicia
  el túnel**: `bash instalar.sh --url` la muestra. Para algo permanente, usa tu dominio con Cloudflare Tunnel o una VPN.
- **Claude a petición**: con la clave de Anthropic puesta, el panel muestra «Resolver con Claude» en cada componente
  con vulnerabilidades (y «Resolver <app> con Claude» al elegir una app), y Telegram te ofrece un botón cuando
  aparece algo importante. No se llama a la API hasta que lo pides y confirmas. Para el modo antiguo (que prepare
  planes solo tras cada análisis) existe `[claude] modo = "auto"`, pero no es el valor por defecto.
- `--parar` y `--desinstalar`.
- Quien publique el proyecto solo tiene que poner su URL de GitHub en la variable `REPO` de `instalar.sh`.

## Arranque rápido (con el ejemplo)

```bash
cd ejemplo
cp .env.ejemplo .env      # rellena Telegram, ANTHROPIC_API_KEY, token del panel… (todo opcional)
docker compose up -d --build
docker compose logs -f vigilante
# Web:   http://localhost:8000
# Panel: http://localhost:8080
```

Lanza `docker compose` **desde la carpeta `ejemplo/`**: el proyecto se monta en la misma ruta que
en el host (`${PWD}`), para que el despliegue de cambios aprobados funcione desde el vigilante.

**Permisos.** El ejemplo trae dos proxies del socket de Docker:
- uno de **solo lectura** para detectar versiones;
- otro **con escritura** para las pruebas y el despliegue.

El segundo equivale casi a root sobre el servidor. Lo más seguro es:
- quitarlo y verificar en otro equipo (`VIGILANTE_DOCKER_PRUEBAS=tcp://equipo-pruebas:2375`);
- desplegar con tu CI/CD (`[aplicacion].webhook_despliegue`);
- montar el código en solo lectura.

## Añadirlo a una web que ya tienes

1. Copia la carpeta `vigilante/` junto a tu `docker-compose.yml`.
2. Añade los servicios `docker-proxy` y `vigilante` del ejemplo y la etiqueta
   `vigilante.vigilar: "true"` a los contenedores de tu web.
3. Monta tu código (para leer `composer.lock`, `package-lock.json`, `pom.xml`…). En solo lectura
   si no quieres que el vigilante aplique nada; en ese caso solo propone y verifica.
4. Describe en `[[verificacion.servicios]]` cómo construir y probar cada servicio, y en
   `[aplicacion]` cómo desplegar y dónde comprobar la web.
5. Para el modo mantenimiento, comparte el volumen `mantenimiento` con nginx y añade las líneas
   de `ejemplo/web/nginx/default.conf`.

## Demo (todo simulado, accesible desde fuera)

```bash
bash demo/arrancar.sh     # panel en :8090 + túnel cloudflared; imprime URL, usuario y contraseña
bash demo/parar.sh        # lo para todo
```

La demo usa Docker, Claude y Telegram **simulados** (los de `pruebas/`), sin claves ni accesos reales.
El panel pide contraseña (HTTP Basic) porque la URL del túnel es pública. En `/demo` se ve el
«Telegram» con los botones del bot (aprobar, rechazar, aplicar, revertir) y un botón para reiniciar
la demo. Si cloudflared no funciona, el script sirve la carpeta del proyecto con
`python3 -m http.server` en `0.0.0.0:8091`.

## Sin Docker (para probar)

```bash
cd vigilante
python3 -m vigilante -c ../ejemplo/vigilante.toml --detectar   # solo ver qué detecta
python3 -m vigilante -c mi.toml --una-vez                       # un ciclo (sale con código 2 si hay críticas)
python3 -m vigilante -c mi.toml                                 # servicio + panel
```

En `pruebas/docker_falso.py` hay un simulador de la API de Docker para probar la detección
sin Docker.
