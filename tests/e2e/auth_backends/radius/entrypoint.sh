#!/bin/sh
set -e

# Alpine path for FreeRADIUS configuration
RADDB=/etc/raddb

# Ensure directories exist
mkdir -p "$RADDB"

# Bootstrap users into the active 'files' authorize list used by default site
AUTHZ_DIR="$RADDB/mods-config/files"
AUTHZ_FILE="$AUTHZ_DIR/authorize"
if [ -f /bootstrap/users ]; then
  mkdir -p "$AUTHZ_DIR"
  # Prepend a marker and our test users so they take precedence
  {
    echo "# --- BEGIN E2E USERS ---"
    cat /bootstrap/users
    echo "# --- END E2E USERS ---"
    echo
  } >> "$AUTHZ_FILE"
fi

# Minimal clients.conf: accept any client with test secret 'radsecret'
cat > "$RADDB/clients.conf" <<'CONF'
client test {
  ipaddr = 0.0.0.0/0
  secret = radsecret
  nas_identifier = e2e-nas
}
CONF

# Ensure proper permissions
chmod 600 "$RADDB/clients.conf" || true

# Run FreeRADIUS in foreground with debug for easier logs
exec radiusd -f -l stdout -xx
