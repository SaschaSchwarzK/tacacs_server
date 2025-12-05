import hashlib
import socket
import struct
import threading

import pytest

from tacacs_server.auth.radius_auth import RADIUSAuthBackend


class _RadiusMFAServer:
    """Minimal RADIUS server that enforces an MFA challenge (OTP or push)."""

    def __init__(self, secret: str = "testing123"):
        self.secret = secret.encode("utf-8")
        self.host = "127.0.0.1"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._pending_states: set[bytes] = set()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self.sock.close()
        except Exception:
            pass
        self._thread.join(timeout=2)

    def _decrypt_password(self, encrypted: bytes, request_auth: bytes) -> str:
        """Decrypt User-Password using RADIUS algorithm."""
        out = b""
        prev = request_auth
        for i in range(0, len(encrypted), 16):
            block = encrypted[i : i + 16]
            md5 = hashlib.md5(self.secret + prev, usedforsecurity=False).digest()
            out += bytes(a ^ b for a, b in zip(block, md5))
            prev = block
        return out.rstrip(b"\x00").decode("utf-8", errors="ignore")

    def _parse_attributes(self, packet: bytes) -> dict[int, list[bytes]]:
        attrs: dict[int, list[bytes]] = {}
        offset = 20
        while offset + 2 <= len(packet):
            attr_type = packet[offset]
            attr_len = packet[offset + 1]
            if attr_len < 2 or offset + attr_len > len(packet):
                break
            value = packet[offset + 2 : offset + attr_len]
            attrs.setdefault(attr_type, []).append(value)
            offset += attr_len
        return attrs

    def _send_response(
        self,
        code: int,
        identifier: int,
        request_auth: bytes,
        addr: tuple[str, int],
        state: bytes | None = None,
    ) -> None:
        attrs = b""
        if state:
            attrs += struct.pack("!BB", 24, 2 + len(state)) + state

        length = 20 + len(attrs)
        header = struct.pack("!BBH", code, identifier, length)
        resp_auth = hashlib.md5(
            header + request_auth + attrs + self.secret, usedforsecurity=False
        ).digest()
        packet = header + resp_auth + attrs
        try:
            self.sock.sendto(packet, addr)
        except OSError:
            return

    def _handle_request(self, packet: bytes, addr: tuple[str, int]) -> None:
        if len(packet) < 20:
            return
        code = packet[0]
        if code != 1:  # Access-Request only
            return
        identifier = packet[1]
        request_auth = packet[4:20]
        attrs = self._parse_attributes(packet)
        state_vals = attrs.get(24, [])
        password = ""
        if 2 in attrs:
            password = self._decrypt_password(attrs[2][0], request_auth)

        # First leg -> issue Access-Challenge with state token
        if not state_vals:
            state = f"state-{identifier}".encode()
            self._pending_states.add(state)
            self._send_response(11, identifier, request_auth, addr, state=state)
            return

        state = state_vals[0]
        if state not in self._pending_states:
            self._send_response(3, identifier, request_auth, addr)
            return

        # Challenge response: accept OTP 123456 or push (empty password)
        if password == "123456" or password == "":
            self._send_response(2, identifier, request_auth, addr)
        else:
            self._send_response(3, identifier, request_auth, addr)

    def _serve(self) -> None:
        while not self._stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                self._handle_request(data, addr)
            except Exception:
                continue


@pytest.fixture
def radius_mfa_server():
    server = _RadiusMFAServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.mark.integration
def test_radius_mfa_otp_flow(radius_mfa_server):
    """Test RADIUS MFA with OTP appended to password."""
    backend = RADIUSAuthBackend(
        {
            "radius_server": radius_mfa_server.host,
            "radius_port": radius_mfa_server.port,
            "radius_secret": "testing123",
            "mfa_enabled": True,
            "mfa_otp_digits": 6,
        }
    )

    # Should succeed with valid OTP
    assert backend.authenticate("testuser", "password123456")


@pytest.mark.integration
def test_radius_mfa_push_flow(radius_mfa_server):
    """Test RADIUS MFA with push keyword."""
    backend = RADIUSAuthBackend(
        {
            "radius_server": radius_mfa_server.host,
            "radius_port": radius_mfa_server.port,
            "radius_secret": "testing123",
            "mfa_enabled": True,
            "mfa_push_keyword": "push",
        }
    )

    # Simulate push approval (keyword without separator)
    assert backend.authenticate("testuser", "passwordpush")
