#!/usr/bin/env bash
set -euo pipefail

IMAGE=${IMAGE:-tacacs-azurite}
CONTAINER_NAME=${CONTAINER_NAME:-azurite}
WORKDIR=${WORKDIR:-$(pwd)}
DATA_DIR=${DATA_DIR:-"$WORKDIR/export"}

mkdir -p "$DATA_DIR"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Building $IMAGE..." >&2
  docker build -t "$IMAGE" "${WORKDIR}"
fi

echo "Running $CONTAINER_NAME from $IMAGE..." >&2
exec docker run --rm -it \
  --name "$CONTAINER_NAME" \
  -p 10000:10000 -p 10001:10001 -p 10002:10002 \
  -v "$DATA_DIR":/workspace \
  "$IMAGE"

