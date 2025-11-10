#!/usr/bin/env sh
set -eu

# Default storage path
AZURITE_WORKSPACE=${AZURITE_WORKSPACE:-/workspace}
mkdir -p "$AZURITE_WORKSPACE"
chmod 0777 "$AZURITE_WORKSPACE" || true

LOG_DIR=/var/log/azurite
mkdir -p "$LOG_DIR"
chmod 0777 "$LOG_DIR" || true

echo "Starting Azurite with workspace=$AZURITE_WORKSPACE" >&2

# Health probe script (lightweight)
cat > /usr/local/bin/azurite-health <<'EOF'
#!/usr/bin/env sh
host=127.0.0.1
port=${1:-10000}
timeout=${2:-1}
nc -z -w "$timeout" "$host" "$port" >/dev/null 2>&1
EOF
chmod +x /usr/local/bin/azurite-health

# Run Azurite (blob, queue, table) storing data in workspace, with debug log
exec azurite \
  --silent \
  --location "$AZURITE_WORKSPACE" \
  --debug "$LOG_DIR/debug.log" \
  --blobHost 0.0.0.0 --queueHost 0.0.0.0 --tableHost 0.0.0.0

