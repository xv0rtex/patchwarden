# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Patchwarden (internal/package name: `vigilante`) is a container that runs next to Docker-deployed websites, detects the software versions they run, checks them against NVD / OSV.dev / CISA KEV / EPSS / endoflife.date, alerts (panel, Telegram, webhook, email), and — only when the user explicitly asks — has Claude Code propose a fix that is verified in a copy and applied only after explicit approval.

Code, identifiers, config keys, UI text and docs are in **Spanish**; only the README is in English. Keep new code in Spanish to match. `docs/DISENO.md` is the full design document (detection layers, criticality rules, fix flow, security model) — read it before changing the fix/apply pipeline.

## Commands

All Python is stdlib-only (Python 3.12, uses `tomllib`); there are no pip dependencies, no build step and no linter config. `git` is required at runtime.

```bash
# Run (from vigilante/)
cd vigilante
python3 -m vigilante -c ../ejemplo/vigilante.toml --detectar   # only print detected components (no CVE lookups)
python3 -m vigilante -c my.toml --una-vez                       # one cycle; exit code 2 if any critical
python3 -m vigilante -c my.toml                                 # service: cycle every N hours + panel + Telegram bot
python3 -m vigilante --agente --central https://panel --codigo X # agent for a central panel (code from Ajustes › Equipos)

# Tests (from repo root)
python3 -m unittest discover -s pruebas                         # offline unit tests (test_basico, test_acceso, test_equipos, test_agente, test_instalar)
python3 -m unittest pruebas.test_basico.Versiones.test_comparar # single test (run from repo root)
python3 pruebas/prueba_flujo.py                                 # end-to-end fix flow; uses REAL NVD/OSV/registries (network), fake Docker/Claude/Telegram, writes to /tmp/vig-flujo, panel on :8097
PRUEBA_AGENTE=1 python3 pruebas/prueba_flujo.py                 # same flow with central + agent over HTTP (/tmp/vig-flujo-agente, :8098)
DEMO_CLAVE=... python3 pruebas/prueba_navegador.py              # Playwright UI test against a running demo (see file header)

# Simulated demo (fake Docker/Claude/Telegram)
bash demo/arrancar.sh    # panel on :8090 + tunnel; /demo shows the fake Telegram bot; includes a 2nd server «srv-madrid» with a real agent
bash demo/parar.sh

# Example site
cd ejemplo && cp .env.ejemplo .env && docker compose up -d --build   # site :8000, panel :8080 — must run from ejemplo/
```

Tests import the package via `sys.path.insert(0, "../vigilante")`, so the import root is `vigilante/` (the outer folder), not the repo root.

## Architecture

Entry point `vigilante/vigilante/__main__.py` → `config.cargar()` → `motor.Vigilante` (or `agente.Agente` with `--agente`).

**Config** (`config.py`): `DEFECTO` dict of defaults ← merged with the TOML file (`-c` or `$VIGILANTE_CONFIG`, default `/config/vigilante.toml`) ← `<datos>/ajustes.json` (values edited in the panel's *Ajustes*, `ajustes.py`) ← overridden by env vars listed in `ENTORNO` (env wins). New config keys must be added to `DEFECTO` (the default's type drives env-var conversion); to make one editable in the panel, add a `Campo` to `ajustes.PESTANAS`. Edits are applied live by mutating the shared `cfg` dicts, so modules should read config at use time rather than copying it in `__init__`.

**Equipos (servers)** (`equipos.py`, `equipos_remotos.py`): everything that touches a server — detection, project folder, file context for Claude, verify/apply/revert, maintenance — goes through an `Equipo`. `EquipoLocal` wraps the local code (all-in-one mode, and what the agent uses internally); `EquipoRemoto` turns each call into a task for an agent (`Registro`: one-time registration codes, hashed tokens, inventory, long-poll task queue; HTTP routes in `api_agente.py`). `Componente.equipo` namespaces keys (`<equipo>~<app>::…`) and remote apps display as `equipo-name/app`. An equipo may only return `CAMPOS_DEL_EQUIPO` into a plan. The agent (`agente.py`) must not trust the central: it only applies verifications whose `huella_verificacion` it recorded itself, reverts from its own backup record, validates project folder and plan id, and honours its local `solo_lectura` — keep those checks (see DISENO §9.3).

**Detection → findings cycle** (`motor.py`):
- `detectar()` gathers `Componente`s (`modelo.py`) from several layers: `detectar_docker.py` (Docker API over Unix socket or TCP proxy: image env vars, image tags, optional `exec` probes), `detectar_ficheros.py` (lockfiles, pom.xml, Dockerfile FROM, WordPress), `detectar_http.py` (headers), and `[deteccion.manual]`. `fusionar()` dedupes, keeping the most reliable layer. `catalogo.py` maps runtimes to env vars, image names, NVD CPEs and endoflife slugs.
- `buscar()` queries `fuentes.py` (disk-cached, rate-limit aware) — NVD for runtimes (by CPE, with local version-range filtering via `versiones.py`), OSV for packages — and enriches with KEV/EPSS/EOL. Imprecise versions (e.g. `php 8.1`) only get EOL checks, not CVE lookups.
- `es_critico()` applies `[reglas]` (KEV, CVSS ≥ 9, or CVSS ≥ 7 + EPSS ≥ 0.5). `_avisar()` sends only new/escalated/resolved findings via `avisos.py` / `telegram.py`; state persists in the data folder (`carpeta_datos`, `/datos`). `mantenimiento.py` writes the `ACTIVO` flag file that nginx checks to serve 503.
- Each docker compose project is an "app"; components, plans and panel views are scoped per app.

**Fix pipeline** (`correcciones.Gestor` orchestrates; panel and Telegram call the same `Gestor` methods):
1. User requests a fix (`solicitar_componente` / `solicitar_app`) → a plan (`planes.py`: states, per-change decisions, audit log) is queued to a worker thread. `[claude] modo = "auto"` exists but is not the default — Claude must never run without a user request.
2. `compatibilidad.py` gathers objective data (jump type, Packagist/npm constraints, EOL branches, which CVEs the target version doesn't fix).
3. `claude.py` runs `claude -p` with `--json-schema` structured output, only `WebSearch`/`WebFetch` tools, in an empty dir. The env is built from an allowlist (`ENTORNO_PERMITIDO`) so `ANTHROPIC_API_KEY` is never passed — auth is `CLAUDE_CODE_OAUTH_TOKEN` or a claude.ai subscription login only (Console logins are rejected). Never send `.env` files or app data.
4. `verificacion.py` copies the project to `/datos/pruebas/<plan>/`, `git apply`s each change (with `git merge-file` for overlaps), runs whitelisted tool commands (composer/npm/yarn/bundle/go/pip, no shell metacharacters, scripts disabled) in throwaway containers, then user-defined smoke tests. On failure, Claude gets one retry with the error output.
5. After approval, `aplicar.py`: pre-checks (exactly the verified subset, production file hashes unchanged), backup (tar + tag of running image), `git apply`, deploy command or webhook, HTTP health check, automatic rollback on failure.

**Panel** (`panel.py` = `ThreadingHTTPServer` routes/actions/auth; `vista.py` = inline CSS/SVG icons/HTML templates; `panel_ajustes.py` = Ajustes tabs). No external assets, no emoji, states always icon + text (never color alone). Auth (`usuarios.py`): single account with login (scrypt, session cookie, 12 h); first run goes to `/configuracion-inicial`, which needs the one-time code from the log unless `[panel] usuario/clave` bootstrap it. Every POST form gets the session's CSRF token injected by `Panel.envolver` (`con_csrf`); `[panel] token` is only an API token for scripts (`X-Token`). Lockout after 10 failed logins per IP; `CF-Connecting-IP` is only trusted from local/private peers. `/api/agente/*` uses agent bearer tokens, not sessions.

**Install / update** (`instalar.sh` → `vigilante/instalar.py --rol central|agente`): interactive menu (install dashboard or agent; if installed: update, update + rediscover apps, change tokens, stop/start, uninstall). Discovers running compose apps, generates config/compose (read-only `docker-proxy`, optional write-capable `docker-proxy-pruebas` with `--permitir-aplicar`). Images: `central/Dockerfile` → `vigilante:local` (with Claude Code), `agente/Dockerfile` → `vigilante-agente:local` (no Claude); both built from the repo root. Update keeps `.env`, `vigilante.toml` and the data volume, and rolls back to `:anterior` if the new image doesn't start.

## Test doubles

`pruebas/docker_falso.py` (fake Docker API), `pruebas/apis_falsas.py` (fake `claude` executable + Telegram Bot API), and `demo/demo.py` reuse these. If you change the Claude CLI invocation, Docker API calls or Telegram calls, update the fakes too. `prueba_flujo.py` asserts that `ANTHROPIC_API_KEY` never reaches Claude Code and that the project is untouched until approval — keep those invariants.

# UI y diseño

Producto: panel privado para monitorizar versiones de webs desplegadas,
ver vulnerabilidades activas y lanzar su corrección con Claude.
Prioridad: claridad y rapidez de lectura sobre decoración.

Estructura
- Vista general: resumen (webs totales, con vulnerabilidades críticas/altas, desactualizadas).
- Tabla de webs: nombre, URL, versión actual vs última, estado, nº de vulns por severidad, último escaneo.
- Detalle de web: lista de vulnerabilidades (CVE, severidad, componente, versión afectada, versión con fix) y botón "Corregir con Claude".

Diseño
- Tema oscuro y claro, sobrio. Fuente sans legible + monoespaciada solo para versiones, CVE y comandos.
- Color con significado, nunca decorativo: crítica=rojo, alta=naranja, media=amarillo, baja=azul, ok=verde.
  La severidad nunca se indica solo con color: añadir texto o icono.
- Tablas densas pero con buen espaciado, ordenables y filtrables. Estados vacíos, de carga y de error en cada vista.
- Acciones destructivas o que modifican código siempre con confirmación y resumen de cambios.
- Espaciado en múltiplos de 4/8px, variables CSS para todos los colores.
- Responsive: probar en 390px y 1440px. Contraste AA.
