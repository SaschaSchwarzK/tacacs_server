import hashlib
import socket
import struct
import threading

import pytest

from tacacs_server.auth.radius_auth import RADIUSAuthBackend


class _RadiusAcceptServer:
    """Minimal RADIUS server that immediately Access-Accepts with groups."""

    def __init__(self, secret: str = "testing123", expected_password: str = "password123456"):
        self.secret = secret.encode("utf-8")
        self.expected_password = expected_password
        self.host = "127.0.0.1"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except Exception:
            pass
        self._thread.join(timeout=2)

    def _decrypt_password(self, encrypted: bytes, request_auth: bytes) -> str:
        out = b""
        prev = request_auth
        for i in range(0, len(encrypted), 16):
            block = encrypted[i : i + 16]
            md5 = hashlib.md5(self.secret + prev, usedforsecurity=False).digest()
            out += bytes(a ^ b for a, b in zip(block, md5))
            prev = block
        return out.rstrip(b"\x00").decode("utf-8", errors="ignore")

    def _attr(self, attr_type: int, value: bytes) -> bytes:
        return struct.pack("!BB", attr_type, 2 + len(value)) + value

    def _send_accept(
        self, identifier: int, request_auth: bytes, addr: tuple[str, int]
    ) -> None:
        attrs = self._attr(11, b"netops")
        length = 20 + len(attrs)
        header = struct.pack("!BBH", 2, identifier, length)
        resp_auth = hashlib.md5(
            header + request_auth + attrs + self.secret, usedforsecurity=False
        ).digest()
        packet = header + resp_auth + attrs
        try:
            self.sock.sendto(packet, addr)
        except OSError:
            return

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 20:
                continue
            identifier = data[1]
            request_auth = data[4:20]
            attrs = self._parse_attributes(data)
            password = ""
            if 2 in attrs:
                password = self._decrypt_password(attrs[2][0], request_auth)

            if password == self.expected_password:
                self._send_accept(identifier, request_auth, addr)

    def _parse_attributes(self, packet: bytes) -> dict[int, list[bytes]]:
        attrs: dict[int, list[bytes]] = {}
        offset = 20
        total_len = struct.unpack("!H", packet[2:4])[0]
        while offset + 2 <= total_len:
            attr_type = packet[offset]
            attr_len = packet[offset + 1]
            if attr_len < 2 or offset + attr_len > total_len:
                break
            val = packet[offset + 2 : offset + attr_len]
            attrs.setdefault(attr_type, []).append(val)
            offset += attr_len
        return attrs


@pytest.fixture
def radius_accept_server():
    srv = _RadiusAcceptServer()
    srv.start()
    try:
        yield srv
    finally:
        srv.stop()


@pytest.mark.integration
def test_radius_mfa_disabled_does_not_strip_suffix(radius_accept_server):
    """Ensure trailing digits are not stripped when MFA is disabled."""
    backend = RADIUSAuthBackend(
        {
            "radius_server": radius_accept_server.host,
            "radius_port": radius_accept_server.port,
            "radius_secret": "testing123",
            "mfa_enabled": False,
            "mfa_otp_digits": 6,
        }
    )

    # With MFA disabled, the full password (including digits) should be sent/accepted
    assert backend.authenticate("testuser", "password123456")
    attrs = backend.get_user_attributes("testuser")
    assert attrs.get("groups") == ["netops"]
