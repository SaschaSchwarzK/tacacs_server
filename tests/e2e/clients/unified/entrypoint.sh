#!/bin/sh
set -euo pipefail

MODE=${MODE:-tacacs} # tacacs|radius
HOST=${HOST:-127.0.0.1}
PORT=${PORT:-49}
SECRET=${SECRET:-TacacsSecret123!}
USERNAME=${USERNAME:-admin}
PASSWORD=${PASSWORD:-password}

echo "[unified-client] mode=$MODE host=$HOST port=$PORT user=$USERNAME"

exec python /app/client.py --mode "$MODE" --host "$HOST" --port "$PORT" --secret "$SECRET" --username "$USERNAME" --password "$PASSWORD"

