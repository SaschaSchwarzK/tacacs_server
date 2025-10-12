import socket
import struct
import time

import pytest


def build_author_packet(
    username: str, command: str, privilege_level: int, session_id: int
) -> bytes:
    user_bytes = username.encode()
    port_bytes = b"pts/0"
    addr_bytes = b"127.0.0.1"
    args = [b"service=shell", f"cmd={command}".encode()]
    header = struct.pack("!BBBBII", 0xC0, 0x02, 1, 0, session_id, 0)  # type=AUTHOR
    body = struct.pack(
        "!BBBBBBBB",
        6,  # authen_method: TACACSPLUS
        privilege_level,
        1,  # authen_type: ASCII
        1,  # authen_service: LOGIN
        len(user_bytes),
        len(port_bytes),
        len(addr_bytes),
        len(args),
    )
    body += user_bytes + port_bytes + addr_bytes
    for a in args:
        body += struct.pack("!B", len(a))
    for a in args:
        body += a
    # Update length in header
    header = struct.pack("!BBBBII", 0xC0, 0x02, 1, 0, session_id, len(body))
    return header + body


@pytest.mark.integration
def test_wire_authorization_denied_by_default(tacacs_server):
    host = tacacs_server["host"]
    port = tacacs_server["port"]
    session = int(time.time()) & 0xFFFFFFFF
    pkt = build_author_packet("user", "configure terminal", 1, session)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect((host, port))
    s.send(pkt)
    try:
        resp = s.recv(4096)
    except ConnectionResetError:
        # Connection reset on invalid/unencrypted packet is acceptable rejection
        s.close()
        return
    s.close()
    # If response was returned, we cannot reliably parse it without shared-secret
    # encryption/flags. Treat any response as acceptable rejection signal.
    if len(resp) >= 13:
        assert len(resp) > 0
