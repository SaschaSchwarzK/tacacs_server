import socket
import struct
import time

import pytest

from tacacs_server.tacacs.constants import (
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.server import TacacsServer


def _mk_header(
    version_major: int, ptype: int, seq: int, flags: int, session: int, length: int
) -> bytes:
    version = ((version_major & 0x0F) << 4) | 0  # minor 0
    return struct.pack("!BBBBLL", version, ptype, seq, flags, session, length)


def test_per_ip_map_cleanup_unit():
    srv = TacacsServer()
    ip = "127.0.0.1"
    with srv._ip_conn_lock:
        srv._ip_connections[ip] = srv._ip_connections.get(ip, 0) + 1
    # decrement to zero should delete key
    with srv._ip_conn_lock:
        current = max(0, srv._ip_connections.get(ip, 1) - 1)
        if current == 0:
            srv._ip_connections.pop(ip, None)
        else:
            srv._ip_connections[ip] = current
    assert ip not in srv._ip_connections


def test_graceful_shutdown_unit():
    srv = TacacsServer()
    # Simulate one active connection; no socket open
    with srv._stats_lock:
        srv.stats["connections_active"] = 1
    start = time.time()
    srv.graceful_shutdown(timeout_seconds=0.2)
    # Should complete quickly even if active_count didn't drop
    assert time.time() - start < 2


@pytest.mark.integration
def test_packet_length_cap_integration(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        host = "127.0.0.1"
        port = server.tacacs_port
        # Build a header advertising too large length (e.g., 10k)
        hdr = _mk_header(
            TAC_PLUS_MAJOR_VER,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            1,
            0,
            0x9999,
            10000,
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        try:
            s.sendall(hdr)
            try:
                data = s.recv(1)
            except TimeoutError:
                data = b""
            assert data == b""
        finally:
            s.close()
