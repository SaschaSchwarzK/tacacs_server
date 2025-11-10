#!/usr/bin/env sh
set -eu

# Run a temporary sshd in DEBUG mode on an alternate port and attempt a single SSH auth
# Prints the captured debug log to stdout for troubleshooting.

PORT=${PROBE_PORT:-2222}
LOG=${PROBE_LOG:-/var/log/sshd_probe.log}
MODE=${1:-key}
USER=${SFTP_USER:-testuser}
HOST=127.0.0.1

echo "[probe] Starting sshd debug on port $PORT (mode=$MODE)" >&2
:
> "$LOG"

# Validate base config
/usr/sbin/sshd -t || true

# Launch debug sshd on alternate port in background
sh -c "/usr/sbin/sshd -D -e -p $PORT -o LogLevel=DEBUG3 -f /etc/ssh/sshd_config" 2>"$LOG" &
PID=$!
sleep 0.5

# Attempt one SSH auth using key if available
if [ "$MODE" = "key" ]; then
  if [ -f "/export/${USER}_id_rsa" ]; then
    KEY="/export/${USER}_id_rsa"
  elif [ -f "/export/${USER}_id_ed25519" ]; then
    KEY="/export/${USER}_id_ed25519"
  else
    echo "[probe] No private key found under /export for user $USER" >&2
    KEY=""
  fi
  if [ -n "$KEY" ]; then
    ssh -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$KEY" "$USER@$HOST" true || true
  fi
fi

# Give sshd time to log and then stop it
sleep 1
kill "$PID" 2>/dev/null || true
sleep 0.2

echo "[probe] === begin sshd debug log ===" >&2
cat "$LOG"
echo "[probe] === end sshd debug log ===" >&2

