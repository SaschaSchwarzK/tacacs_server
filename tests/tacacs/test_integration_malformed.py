import socket
import struct

from tacacs_server.tacacs.constants import (
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)


def _mk_header(
    version_major: int, ptype: int, seq: int, flags: int, session: int, length: int
) -> bytes:
    # major field is 4 bits; mask to ensure byte-sized version
    version = ((version_major & 0x0F) << 4) | 0
    return struct.pack("!BBBBLL", version, ptype, seq, flags, session, length)


def _send_and_expect_drop(host: str, port: int, header: bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    s.connect((host, port))
    try:
        s.sendall(header)
        try:
            data = s.recv(1)
        except TimeoutError:
            data = b""
        assert data == b""
    finally:
        s.close()


def test_bad_version_drop(tacacs_server):
    host = tacacs_server["host"]
    port = tacacs_server["port"]
    # Use an invalid major (0x0E) within 4-bit bounds
    bad = _mk_header(0x0E, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, 0x1, 0)
    _send_and_expect_drop(host, port, bad)


def test_bad_type_drop(tacacs_server):
    host = tacacs_server["host"]
    port = tacacs_server["port"]
    bad = _mk_header(TAC_PLUS_MAJOR_VER, 0xFF, 1, 0, 0x2, 0)
    _send_and_expect_drop(host, port, bad)


def test_even_sequence_drop(tacacs_server):
    host = tacacs_server["host"]
    port = tacacs_server["port"]
    bad = _mk_header(
        TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 2, 0, 0x3, 0
    )
    _send_and_expect_drop(host, port, bad)
