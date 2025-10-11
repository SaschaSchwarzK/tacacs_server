import socket
import struct

import pytest

from tacacs_server.tacacs.constants import TAC_PLUS_HEADER_SIZE


def _connect(host: str, port: int, timeout: float = 2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def test_malformed_short_header_dropped(live_server):
    s = _connect(
        live_server["host"], live_server["port"]
    )  # pragma: no cover - relies on fixture
    try:
        s.sendall(b"\x00\x00")  # Too short
        with pytest.raises((socket.timeout, ConnectionError, OSError)):
            s.recv(1)
    finally:
        s.close()


def test_oversized_length_header_dropped(live_server):
    s = _connect(live_server["host"], live_server["port"])  # pragma: no cover
    try:
        # version, type, seq, flags, session_id, length (too big)
        header = struct.pack("!BBBBII", 0xC0, 0x01, 1, 0, 1234, 100000)
        assert len(header) == TAC_PLUS_HEADER_SIZE
        s.sendall(header)
        try:
            data = s.recv(1)
            # Server should close the socket or not respond
            assert data == b""
        except (TimeoutError, ConnectionError, OSError):
            pass
    finally:
        s.close()
