# Agente (cliente): corre en cada servidor y trabaja para el panel central.
# Solo conexiones salientes, sin panel y sin Claude Code (Claude solo corre en el central).
# Se construye desde la raíz del repositorio:  docker build -f agente/Dockerfile -t vigilante-agente:local .
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# git: aplicar y comparar diffs en las copias de prueba y en el proyecto
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates bash \
    && rm -rf /var/lib/apt/lists/*
# Cliente de Docker + plugin compose: solo para el comando de despliegue tras una aprobación
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:27-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
WORKDIR /app
COPY vigilante/vigilante/ ./vigilante/
ARG VERSION=desconocida
ENV VIGILANTE_VERSION=$VERSION
VOLUME ["/datos", "/mantenimiento"]
CMD ["python", "-m", "vigilante", "--agente"]
