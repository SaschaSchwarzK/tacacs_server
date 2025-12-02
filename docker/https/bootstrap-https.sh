#!/bin/bash
set -e

echo "=== TACACS+ HTTPS Bootstrap ==="

: "${CUSTOMER_ID:?CUSTOMER_ID required}"
# Normalize Azure connection string envs if provided (optional; startup orchestration will skip Azure if unset)
if [ -n "${AZURE_CONNECTION_STRING}" ]; then
  export AZURE_CONNECTION_STRING
elif [ -n "${AZURE_STORAGE_CONNECTION_STRING}" ]; then
  export AZURE_CONNECTION_STRING="${AZURE_STORAGE_CONNECTION_STRING}"
fi

STORAGE_CONTAINER="${STORAGE_CONTAINER:-tacacs-data}"
CONFIG_BLOB="${CUSTOMER_ID}/config.ini"
BACKUP_PREFIX="${CUSTOMER_ID}/backups/"
LOCAL_CONFIG="/app/config/tacacs.runtime.ini"

echo "Customer: ${CUSTOMER_ID}"

# Fetch certificate (Key Vault or self-signed fallback)
echo "Fetching/generating certificate..."
python3 /app/fetch_cert.py
CERT_STATUS=$?

if [ $CERT_STATUS -ne 0 ]; then
    echo "ERROR: Certificate generation failed completely"
    export SKIP_WEB_ADMIN=1
else
    echo "✓ Certificate ready"
fi

# Export env variables
[ -n "${ADMIN_PASSWORD}" ] && export ADMIN_PASSWORD
[ -n "${API_TOKEN}" ] && export API_TOKEN
export AZURE_STORAGE_CONNECTION_STRING
export AZURE_STORAGE_CONTAINER="${STORAGE_CONTAINER}"
export AZURE_BACKUP_PATH="${BACKUP_PREFIX}"
export AZURE_CONFIG_PATH="${CUSTOMER_ID}"
export AZURE_CONFIG_FILE="config.ini"

echo "Backup configuration:"
echo "  Container: ${STORAGE_CONTAINER}"
echo "  Prefix: ${BACKUP_PREFIX}"

# Start Caddy if web admin enabled
if [ "${SKIP_WEB_ADMIN}" != "1" ]; then
    echo "Starting Caddy on port 8443..."
    # Use 'caddy run' so the background PID corresponds to the actual server
    caddy run --config /app/Caddyfile --adapter caddyfile &
    CADDY_PID=$!
    
    # Wait briefly and perform a lightweight liveness check
    sleep 3
    if ! kill -0 "$CADDY_PID" 2>/dev/null; then
        echo "ERROR: Caddy background process is not running"
        export SKIP_WEB_ADMIN=1
    else
        echo "✓ Caddy process started (PID ${CADDY_PID})"
    fi
fi

# Run startup orchestration to restore backups/download config (uses env vars)
echo "Running startup orchestration..."
CONFIG_PATH=$(/opt/venv/bin/python - <<'PY'
from tacacs_server.startup import run_startup_orchestration
try:
    print(run_startup_orchestration())
except Exception as e:
    import sys
    print(f"ERROR: Startup orchestration failed: {e}", file=sys.stderr)
    print("/app/config/tacacs.runtime.ini", file=sys.stdout)
PY
)

# Start TACACS (with or without web admin) using orchestrated config path
echo "Starting TACACS+ server with config ${CONFIG_PATH}..."
if [ "${SKIP_WEB_ADMIN}" = "1" ]; then
    echo "⚠ Caddy/HTTPS disabled - starting TACACS/RADIUS with internal web admin only (port 8080)"
    exec tacacs-server --config "${CONFIG_PATH}"
else
    echo "✓ Starting TACACS/RADIUS + Web Admin"
    exec tacacs-server --config "${CONFIG_PATH}"
fi
