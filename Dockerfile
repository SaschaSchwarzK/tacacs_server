############
# Builder  #
############
FROM python:3.13-slim AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml poetry.lock ./
# Install Poetry and the export plugin to generate requirements.txt
RUN pip install --no-cache-dir poetry poetry-plugin-export \
 && poetry export -f requirements.txt -o req.txt --without-hashes

# Create a virtualenv under /opt/venv and install deps
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir -r req.txt

# Install the package into the venv
COPY . .
RUN /opt/venv/bin/pip install --no-cache-dir .

###########
# Runner  #
###########
FROM python:3.13-slim AS run

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH

WORKDIR /app

# Install tini and curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
      tini curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and runtime dirs
RUN useradd -r -m app \
 && mkdir -p /app/data /app/logs /app/config \
 && chown -R app:app /app

# Copy venv from builder
COPY --from=build /opt/venv /opt/venv

# Provide container-friendly default config
COPY config/tacacs.container.ini /app/config/tacacs.container.ini

USER app

# Expose ports for both ACA (5049/8080) and ACI (49, 1812/udp, 1813/udp)
EXPOSE 5049/tcp 8080/tcp 49/tcp 1812/udp 1813/udp

# Healthcheck against liveness endpoint
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["tini","--"]
CMD ["tacacs-server","--config","/app/config/tacacs.container.ini"]
