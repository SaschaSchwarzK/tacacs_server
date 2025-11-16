#!/bin/bash
set -e

echo "=== TACACS+ HTTPS Bootstrap ==="

: "${CUSTOMER_ID:?CUSTOMER_ID required}"
: "${AZURE_STORAGE_CONNECTION_STRING:?AZURE_STORAGE_CONNECTION_STRING required}"

STORAGE_CONTAINER="${STORAGE_CONTAINER:-tacacs-data}"
CONFIG_BLOB="${CUSTOMER_ID}/config.ini"
BACKUP_PREFIX="${CUSTOMER_ID}/backups/"
LOCAL_CONFIG="/app/config/tacacs.runtime.ini"

echo "Customer: ${CUSTOMER_ID}"

# Download config from customer folder
echo "Downloading config from ${STORAGE_CONTAINER}/${CONFIG_BLOB}..."
python3 -c "
from azure.storage.blob import BlobServiceClient
import os, sys, shutil

try:
    blob_client = BlobServiceClient.from_connection_string(
        os.environ['AZURE_STORAGE_CONNECTION_STRING']
    ).get_blob_client('${STORAGE_CONTAINER}', '${CONFIG_BLOB}')
    
    with open('${LOCAL_CONFIG}', 'wb') as f:
        f.write(blob_client.download_blob().readall())
    print('✓ Config downloaded from ${CONFIG_BLOB}')
except Exception as e:
    print(f'✗ Config failed: {e}')
    print('Using default config from image')
    shutil.copy('/app/config/tacacs.ini', '${LOCAL_CONFIG}')
"

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
export BACKUP_AZURE_CONTAINER="${STORAGE_CONTAINER}"
export BACKUP_AZURE_PREFIX="${BACKUP_PREFIX}"

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

# Start TACACS (with or without web admin)
echo "Starting TACACS+ server..."
if [ "${SKIP_WEB_ADMIN}" = "1" ]; then
    echo "⚠ Caddy/HTTPS disabled - starting TACACS/RADIUS with internal web admin only (port 8080)"
    exec tacacs-server --config "${LOCAL_CONFIG}"
else
    echo "✓ Starting TACACS/RADIUS + Web Admin"
    exec tacacs-server --config "${LOCAL_CONFIG}"
fi

