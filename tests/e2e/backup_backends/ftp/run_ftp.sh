#!/usr/bin/env bash
set -euo pipefail

IMAGE=${IMAGE:-tiny-ftp-sftp}
CONTAINER_NAME=${CONTAINER_NAME:-ftp}
CONTEXT_DIR="$(cd "$(dirname "$0")" && pwd)"

FTP_USER=${FTP_USER:-testuser}
FTP_PASS=${FTP_PASS:-password}
SFTP_USER=${SFTP_USER:-$FTP_USER}
SFTP_PASS=${SFTP_PASS:-$FTP_PASS}
EXPORT_DIR_HOST=${EXPORT_DIR_HOST:-"$CONTEXT_DIR/export"}

CONFIG_VOL=${CONFIG_VOL:-ftp-config}
DATA_VOL=${DATA_VOL:-ftp-data}

FTP_PORT=${FTP_PORT:-21}
# Default SFTP host port to 2222 to avoid conflicts with local sshd
SFTP_PORT=${SFTP_PORT:-2222}
PASV_MIN=${PASV_MIN:-30000}
PASV_MAX=${PASV_MAX:-30009}

# Control whether to publish ports to the host (useful for container-to-container tests)
PUBLISH=${PUBLISH:-1}

echo "Building image: $IMAGE"
docker build -t "$IMAGE" "$CONTEXT_DIR"

mkdir -p "$EXPORT_DIR_HOST"

DETACH=${DETACH:-0}
REMOVE=${REMOVE:-1}

echo "Starting container: $CONTAINER_NAME"
RUN_ARGS=( --name "$CONTAINER_NAME" )
if [[ "$DETACH" == "1" ]]; then
  RUN_ARGS+=( -d )
fi
if [[ "$REMOVE" == "1" && "$DETACH" != "1" ]]; then
  RUN_ARGS+=( --rm )
fi

PORT_ARGS=()
if [[ "$PUBLISH" == "1" ]]; then
  PORT_ARGS+=(
    -p "$FTP_PORT":21
    -p "$SFTP_PORT":22
    -p "$PASV_MIN"-"$PASV_MAX":"$PASV_MIN"-"$PASV_MAX"/tcp
  )
fi

exec docker run "${RUN_ARGS[@]}" \
  -e FTP_USER="$FTP_USER" \
  -e FTP_PASS="$FTP_PASS" \
  -e SFTP_USER="$SFTP_USER" \
  -e SFTP_PASS="$SFTP_PASS" \
  -e FTP_PASV_MIN_PORT="$PASV_MIN" \
  -e FTP_PASV_MAX_PORT="$PASV_MAX" \
  -e FTP_WATCHDOG=1 \
  "${PORT_ARGS[@]}" \
  -v "$DATA_VOL":/data \
  -v "$CONFIG_VOL":/etc/vsftpd \
  -v "$EXPORT_DIR_HOST":/export \
  "$IMAGE"
