FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# git: aplicar y comparar diffs en las copias de prueba y en el proyecto
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Cliente de Docker + plugin compose: solo para el comando de despliegue tras una aprobación
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:27-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vigilante/ ./vigilante/
COPY vigilante.ejemplo.toml /config/vigilante.toml
VOLUME ["/datos", "/mantenimiento"]
EXPOSE 8080 8090
HEALTHCHECK --interval=1m --timeout=5s CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/salud' % os.environ.get('VIGILANTE_PANEL_PUERTO','8080'))" || exit 1
CMD ["python", "-m", "vigilante"]
