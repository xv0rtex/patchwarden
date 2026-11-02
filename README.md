<p align="center">
  <img src="assets/logo.svg" width="128" height="128" alt="Patchwarden logo">
</p>

<h1 align="center">Patchwarden</h1>

<p align="center">
  <b>Finds vulnerable software in your Docker sites. Prepares the fix. You approve it.</b>
</p>

<p align="center">
  <img alt="Python 3.12" src="https://img.shields.io/badge/python-3.12-4338ca">
  <img alt="Runs on Docker" src="https://img.shields.io/badge/runs%20on-Docker-4338ca">
  <img alt="Fixes with Claude Code" src="https://img.shields.io/badge/fixes%20with-Claude%20Code-4338ca">
</p>

---

Patchwarden is a small container that runs next to your websites. It works out which software
versions they use, checks them against public vulnerability databases, warns you when something
is at risk and, when you ask, gets Claude to prepare a tested fix. **Nothing changes on your server
until you approve it.**

<p align="center">
  <img src="assets/dashboard.png" alt="Patchwarden dashboard" width="900">
</p>

## What it does

1. **Finds what you run.** It detects PHP, nginx, Java, Tomcat, Node and more, plus your
   Composer, npm, Maven and PyPI dependencies, from your containers and project files.
2. **Checks it.** It cross-checks every version against **NVD, OSV.dev, CISA KEV, EPSS and
   endoflife.date**, and puts first what attackers are already exploiting.
3. **Warns you.** In the web dashboard and, if you want, on Telegram, by webhook or by email.
   It can also put your site into **maintenance mode**.
4. **Fixes on request.** Click *Resolver con Claude* (“Resolve with Claude”) and Claude prepares the changes. Each one
   explains what it fixes, why it is correct, how risky it is and how to undo it.
5. **Tests before you decide.** Patchwarden applies the changes to a copy of your project and
   runs it in test containers.
6. **Applies only what you approve.** You approve or reject each change from the dashboard or
   Telegram. It takes a backup, checks that the site is still up and rolls back if it is not.

> **Claude never acts on its own.** It only works when you click the button and confirm, and it
> only proposes. It has no terminal and no access to your files.

## Install on a server

On a Linux server with Docker:

```bash
curl -fsSL https://raw.githubusercontent.com/xv0rtex/patchwarden/main/instalar.sh | bash
```

The script downloads Patchwarden, **finds the apps already running in Docker**, picks a free
port, writes the configuration and a password, and starts everything. At the end it prints the
dashboard URL, the username and the password. It also asks for a Telegram bot token and a
Claude Code token; both are optional, and you can press Enter to skip them.

| Option | What it does |
|---|---|
| *(none)* | Watches and proposes only: your projects are mounted read-only |
| `--permitir-aplicar` | Allows approved changes to be applied (with backup and rollback) |
| `--puerto N` | Dashboard port |
| `--local` | Dashboard only on `127.0.0.1` |
| `--solo NAME` | Watches a single app or project |
| `--tunel` | Publishes the dashboard through a free Cloudflare quick tunnel |
| `--url` | Shows the current tunnel URL |
| `--parar` / `--desinstalar` | Stops / removes Patchwarden |

Running the script again updates Patchwarden, refreshes the discovered apps and keeps your
settings. Each Docker Compose project counts as an *app*, and the dashboard lets you view one or
all of them.

## Fixes with Claude Code (no API billing)

Fixes use **Claude Code with your Claude subscription** (Pro, Max or higher), not the pay-as-you-go
API. On the computer where you use Claude, create a token:

```bash
claude setup-token
```

Put it in the `.env` file as `CLAUDE_CODE_OAUTH_TOKEN`, or paste it when the installer asks.

- Each fix uses part of your plan's usage limits.
- Any `ANTHROPIC_API_KEY` in the environment is deliberately ignored, so you are never billed per use.
- Claude runs in an empty folder, with only web search and web fetch (to read changelogs and
  upgrade guides). It cannot run commands or open your files.
- Patchwarden sends the vulnerabilities and deployment files (`composer.json`, `Dockerfile`, nginx
  config…), never `.env` files or app data. The confirmation window tells you this before anything
  is sent.
- The token is for **your own** use. If someone else installs Patchwarden, they should use their own
  Claude account.

Without a token, Patchwarden still detects and warns; it just does not prepare fixes.

## Try it with the example

```bash
cd ejemplo
cp .env.ejemplo .env      # Telegram, CLAUDE_CODE_OAUTH_TOKEN, dashboard token… (all optional)
docker compose up -d --build
# Website:   http://localhost:8000
# Dashboard: http://localhost:8080
```

Run `docker compose` **from the `ejemplo/` folder**: the project is mounted at the same path as on
the host, so approved changes can be deployed from inside the container.

## Security model

- **Read-only by default.** Patchwarden only reads the Docker API through a proxy that allows
  listing and inspecting containers.
- **Writing is opt-in.** Testing and deploying need a second Docker proxy with write access,
  which is close to root on the server. Safer alternatives: run the tests on another machine
  (`VIGILANTE_DOCKER_PRUEBAS=tcp://test-host:2375`), deploy through your own CI/CD
  (`[aplicacion].webhook_despliegue`), and mount your code read-only.
- **Every change needs your approval**, with a backup first and an automatic rollback if the
  site stops responding.
- The dashboard always asks for a username and password, and locks out an address for 5 minutes
  after 10 failed attempts.

## Add it to an existing site

1. Copy the `vigilante/` folder next to your `docker-compose.yml`.
2. Add the `docker-proxy` and `vigilante` services from the example, and the label
   `vigilante.vigilar: "true"` to your site's containers.
3. Mount your code (to read `composer.lock`, `package-lock.json`, `pom.xml`…). Mount it read-only
   if you only want proposals.
4. Describe in `[[verificacion.servicios]]` how to build and test each service, and in
   `[aplicacion]` how to deploy and where to check the site.
5. For maintenance mode, share the `mantenimiento` volume with nginx and add the lines from
   `ejemplo/web/nginx/default.conf`.

## Demo

A fully simulated demo (Docker, Claude and Telegram are fake, nothing real is touched):

```bash
bash demo/arrancar.sh     # dashboard on :8090 plus a tunnel; prints URL, user and password
bash demo/parar.sh        # stops everything
```

Visit `/demo` to see the simulated Telegram bot with its approve, reject, apply and revert buttons.

## Run without Docker

```bash
cd vigilante
python3 -m vigilante -c ../ejemplo/vigilante.toml --detectar   # just show what it detects
python3 -m vigilante -c my.toml --una-vez                       # one cycle (exit code 2 if critical)
python3 -m vigilante -c my.toml                                 # service + dashboard
```

## Tests

```bash
python3 -m unittest discover -s pruebas    # unit tests
python3 pruebas/prueba_flujo.py            # full flow with simulated Docker, Claude Code and Telegram
```

`pruebas/prueba_navegador.py` tests the dashboard in Chromium (needs Playwright).

## Project layout

| Path | Contents |
|---|---|
| [`vigilante/`](vigilante/) | The service: detection, sources, dashboard, Claude Code integration |
| [`ejemplo/`](ejemplo/) | A PHP + nginx site ready for `docker compose` |
| [`demo/`](demo/) | The simulated demo |
| [`pruebas/`](pruebas/) | Tests and simulators |
| [`docs/DISENO.md`](docs/DISENO.md) | Full design document |

> The dashboard, notifications, configuration keys and design document are currently in Spanish.
