# Panel central (dashboard): vigila este servidor, recibe a los agentes y prepara correcciones con Claude.
# Se construye desde la raíz del repositorio:  docker build -f central/Dockerfile -t vigilante:local .
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# git: aplicar y comparar diffs en las copias de prueba y en el proyecto
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates curl bash \
    && rm -rf /var/lib/apt/lists/*
# Claude Code: propone las correcciones con tu plan de Claude (CLAUDE_CODE_OAUTH_TOKEN), sin API
ENV PATH="/root/.local/bin:$PATH" DISABLE_AUTOUPDATER=1
RUN curl -fsSL https://claude.ai/install.sh | bash -s stable && claude --version
# Cliente de Docker + plugin compose: solo para el comando de despliegue tras una aprobación
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:27-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
WORKDIR /app
COPY vigilante/vigilante/ ./vigilante/
COPY vigilante/vigilante.ejemplo.toml /config/vigilante.toml
ARG VERSION=desconocida
ENV VIGILANTE_VERSION=$VERSION
VOLUME ["/datos", "/mantenimiento"]
EXPOSE 8080 8090
HEALTHCHECK --interval=1m --timeout=5s CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/salud' % os.environ.get('VIGILANTE_PANEL_PUERTO','8080'))" || exit 1
CMD ["python", "-m", "vigilante"]
