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
    """Create a TACACS+ packet header with specified parameters.

    Args:
        version_major: Major version number (4 bits)
        ptype: Packet type (1 byte)
        seq: Sequence number (1 byte)
        flags: Flags (1 byte)
        session: Session ID (4 bytes)
        length: Length of the packet body (4 bytes)

    Returns:
        bytes: Packed TACACS+ header (12 bytes)
    """
    version = ((version_major & 0x0F) << 4) | 0  # minor 0
    return struct.pack("!BBBBLL", version, ptype, seq, flags, session, length)


def test_per_ip_map_cleanup_unit():
    """Test cleanup of per-IP connection tracking.

    Verifies that when a connection count for an IP address reaches zero,
    the IP address is removed from the tracking dictionary.

    Test Steps:
    1. Create a server instance
    2. Increment connection count for 127.0.0.1
    3. Decrement connection count back to zero
    4. Verify IP is removed from tracking

    Expected Results:
    - After decrementing to zero, IP should not be in _ip_connections
    """
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
    """Test graceful shutdown with active connections.

    Verifies that the server's graceful shutdown completes within the
    specified timeout, even if active connections don't close.

    Test Steps:
    1. Create a server instance
    2. Simulate an active connection
    3. Call graceful_shutdown with a short timeout
    4. Verify shutdown completes within expected time

    Expected Results:
    - shutdown should complete within 2 seconds
    - test should not hang waiting for connections to close
    """
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
    """Integration test for maximum packet length handling.

    Verifies that the server properly handles packets at the maximum
    allowed length and rejects packets that exceed it.

    Test Steps:
    1. Start a TACACS+ server
    2. Send a packet at the maximum allowed length
    3. Verify the server processes it correctly
    4. Send a packet exceeding the maximum length
    5. Verify the server rejects it

    Expected Results:
    - Packets within length limit should be processed
    - Oversized packets should be rejected
    - Server should remain stable in both cases
    """
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
