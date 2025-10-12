FROM python:3.13-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
ENV PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1
ARG POETRY_VERSION=2.0.0
RUN pip install "poetry==${POETRY_VERSION}"

# Copy project files
COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false \
    && poetry install --only main --no-interaction --no-ansi

# Copy application
COPY tacacs_server/ ./tacacs_server/
COPY config/ ./config/

# Create directories
RUN adduser --disabled-password --gecos "" appuser \
    && mkdir -p data logs \
    && chown -R appuser:appuser /app

# Expose ports
EXPOSE 49/tcp 1812/udp 1813/udp 8080/tcp

# Run server
USER appuser
# Note: Binding to privileged ports (<1024) as non-root requires CAP_NET_BIND_SERVICE
# Configure via docker run/compose: --cap-add NET_BIND_SERVICE
CMD ["python", "-m", "tacacs_server.main", "--config", "config/tacacs.conf"]
