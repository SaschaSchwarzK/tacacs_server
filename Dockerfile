############
# Builder  #
############
FROM python:3.13-slim AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System build deps for native wheels fallback (e.g., bcrypt)
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml poetry.lock ./
# Install Poetry and the export plugin to generate requirements.txt
ENV POETRY_NO_INTERACTION=1
RUN pip install --no-cache-dir poetry poetry-plugin-export \
 && poetry lock \
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
    PATH=/opt/venv/bin:$PATH \
    TACACS_CONFIG=/app/config/tacacs.container.ini

WORKDIR /app

# Install tini/curl for healthchecks and runtime libs for bcrypt (libffi)
RUN apt-get update && apt-get install -y --no-install-recommends \
      tini curl libffi8 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (uid 1000) and runtime dirs
RUN useradd -r -u 1000 -m app \
 && mkdir -p /app/data /app/logs /app/config /var/run/tacacs \
 && chown -R 1000:1000 /app /var/run/tacacs

# Copy venv from builder
COPY --from=build /opt/venv /opt/venv

# Provide container-friendly default config
COPY config/tacacs.container.ini /app/config/tacacs.container.ini

USER app

# Expose ports for both Azure ACA (8049/8080) and Azure ACI (8049/tcp, 1812/udp, 1813/udp)
EXPOSE 8049/tcp 8080/tcp 1812/udp 1813/udp

# Healthcheck against liveness endpoint
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://127.0.0.1:8080/health || exit 1

# Default CMD runs startup orchestration (can be overridden with --skip-startup-orchestration)
ENTRYPOINT ["tini","--"]
CMD ["tacacs-server"]
