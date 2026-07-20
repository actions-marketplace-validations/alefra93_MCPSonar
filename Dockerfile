# mcpsonar — protocol-aware health checks for MCP servers.
# Build:  docker build -t mcpsonar .
# Run:    docker run --rm -p 8675:8675 -v "$PWD/config.yaml:/config/config.yaml:ro" mcpsonar
FROM python:3.13-slim

# No .pyc files, unbuffered logs (so container logs stream immediately).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install the package (hatchling reads README.md + LICENSE referenced in pyproject.toml).
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

# The SQLite DB lives here; docker-compose mounts a named volume so it survives restarts.
ENV MCPSONAR_DB=/data/mcpsonar.db
VOLUME ["/data"]

# Dashboard / Prometheus /metrics port.
EXPOSE 8675

# Bind to 0.0.0.0 so the dashboard is reachable from outside the container.
# Servers are added from the UI (or seeded with --config); no config file is required.
ENTRYPOINT ["mcpsonar"]
CMD ["run", "--host", "0.0.0.0", "--port", "8675"]
