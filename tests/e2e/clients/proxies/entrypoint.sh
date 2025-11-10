#!/bin/sh
set -euo pipefail

BACKEND_HOST=${BACKEND_HOST:-tacacs}

# Generate HAProxy config with the provided backend host
cat > /tmp/haproxy.cfg <<EOF
global
    daemon
    maxconn 256
    # Log to stdout so test harness can capture proxy activity
    log stdout format raw local0

defaults
    mode tcp
    log global
    option tcplog
    option dontlognull
    timeout connect 5s
    timeout client  1m
    timeout server  1m

resolvers docker
    parse-resolv-conf
    resolve_retries 3
    timeout resolve 1s
    timeout retry   1s
    hold other      10s
    hold refused    10s
    hold nx         10s
    hold timeout    10s
    hold valid      10s

frontend tacacs_in
    bind *:5049
    default_backend tacacs_out

backend tacacs_out
    balance roundrobin
    server backend1 ${BACKEND_HOST}:5049 send-proxy-v2 check resolvers docker resolve-prefer ipv4 init-addr libc,none
EOF

# Run haproxy in debug/verbose so logs go to stdout for the test harness
exec haproxy -f /tmp/haproxy.cfg -db -V
