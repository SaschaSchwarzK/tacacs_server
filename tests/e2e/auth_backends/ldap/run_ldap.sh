#!/usr/bin/env bash
set -euo pipefail

# Simple helper to build and run the LDAP test container.
# Usage:
#   ./run_ldap.sh               # build + run, keep any existing volumes
#   WIPE=1 ./run_ldap.sh        # wipe volumes before run (destructive)

IMAGE=${IMAGE:-tiny-openldap}
CONTAINER_NAME=${CONTAINER_NAME:-ldap}
CONTEXT_DIR="$(cd "$(dirname "$0")" && pwd)"

# LDAP settings
LDAP_DOMAIN=${LDAP_DOMAIN:-example.org}
LDAP_ORGANIZATION=${LDAP_ORGANIZATION:-"Example Inc."}
LDAP_ADMIN_PASSWORD=${LDAP_ADMIN_PASSWORD:-secret}

# Volumes
CONFIG_VOL=${CONFIG_VOL:-ldap-config}
DATA_VOL=${DATA_VOL:-ldap-data}

# Ports
LDAP_PORT=${LDAP_PORT:-389}
LDAPS_PORT=${LDAPS_PORT:-636}
TLS_DIR_DEFAULT="$CONTEXT_DIR/tls"
TLS_DIR=${TLS_DIR:-$TLS_DIR_DEFAULT}

echo "Building image: $IMAGE"
docker build -t "$IMAGE" "$CONTEXT_DIR"

if [[ "${WIPE:-0}" == "1" ]]; then
  echo "Wiping volumes: $CONFIG_VOL, $DATA_VOL"
  docker volume rm -f "$CONFIG_VOL" "$DATA_VOL" >/dev/null 2>&1 || true
fi

# Ensure volumes exist
docker volume create "$CONFIG_VOL" >/dev/null
docker volume create "$DATA_VOL" >/dev/null

echo "Starting container: $CONTAINER_NAME"

RUN_ARGS=(
  --name "$CONTAINER_NAME" --rm
  -e LDAP_DOMAIN="$LDAP_DOMAIN" \
  -e LDAP_ORGANIZATION="$LDAP_ORGANIZATION" \
  -e LDAP_ADMIN_PASSWORD="$LDAP_ADMIN_PASSWORD" \
  -e LDAP_TLS_ENABLE=true \
  -p "$LDAP_PORT":389 \
  -p "$LDAPS_PORT":636 \
  -v "$DATA_VOL":/var/lib/openldap/openldap-data \
  -v "$CONFIG_VOL":/etc/openldap/slapd.d \
  -v "$CONTEXT_DIR"/bootstrap:/bootstrap:ro
)

# If host certs exist, mount to override the built-in ones
if [[ -d "$TLS_DIR" && -f "$TLS_DIR/cert.pem" && -f "$TLS_DIR/key.pem" ]]; then
  echo "Using host-provided TLS certs from $TLS_DIR"
  RUN_ARGS+=( -v "$TLS_DIR":/tls:ro )
fi

exec docker run "${RUN_ARGS[@]}" "$IMAGE"
