FROM python:3.13-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry

# Copy project files
COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false \
    && poetry install --no-dev --no-interaction --no-ansi

# Copy application
COPY tacacs_server/ ./tacacs_server/
COPY config/ ./config/

# Create directories
RUN mkdir -p data logs

# Expose ports
EXPOSE 49 1812 1813 8080

# Run server
CMD ["python", "-m", "tacacs_server.main", "--config", "config/tacacs.conf"]