import hashlib
import socket
import struct
import threading

from tacacs_server.auth.radius_auth import RADIUSAuthBackend


def _attr(attr_type: int, value: bytes) -> bytes:
    return struct.pack("!BB", attr_type, 2 + len(value)) + value


def test_authenticate_caches_radius_groups():
    """Access-Accept response should cache RADIUS groups for authorization."""
    secret = b"secret123"

    # Spin up a tiny UDP RADIUS responder
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.settimeout(1.0)
    host, port = srv_sock.getsockname()
    stop = threading.Event()

    def _serve():
        while not stop.is_set():
            try:
                data, addr = srv_sock.recvfrom(4096)
            except TimeoutError:
                continue
            except BlockingIOError:
                continue
            except OSError:
                break
            if len(data) < 20:
                continue
            identifier = data[1]
            request_auth = data[4:20]

            attrs = _attr(11, b"netops") + _attr(25, b"group:ops")
            length = 20 + len(attrs)
            header = struct.pack("!BBH", 2, identifier, length)  # Access-Accept
            resp_auth = hashlib.md5(
                header + request_auth + attrs + secret, usedforsecurity=False
            ).digest()
            packet = header + resp_auth + attrs
            srv_sock.sendto(packet, addr)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()

    backend = RADIUSAuthBackend(
        {
            "radius_server": host,
            "radius_port": port,
            "radius_secret": secret.decode(),
            "radius_timeout": 1,
            "radius_retries": 1,
        }
    )

    try:
        assert backend.authenticate("alice", "pw")
        attrs = backend.get_user_attributes("alice")
        assert set(attrs.get("groups", [])) == {"netops", "ops"}
    finally:
        stop.set()
        try:
            srv_sock.close()
        except Exception:
            pass
        t.join(timeout=2)


def test_authenticate_rejects_invalid_authenticator():
    """Access-Accept with wrong authenticator should be ignored."""
    secret = b"secret123"

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.settimeout(1.0)
    host, port = srv_sock.getsockname()
    stop = threading.Event()

    def _serve():
        while not stop.is_set():
            try:
                data, addr = srv_sock.recvfrom(4096)
            except TimeoutError:
                continue
            except BlockingIOError:
                continue
            except OSError:
                break
            if len(data) < 20:
                continue
            identifier = data[1]
            # Deliberately use wrong authenticator (zeros)
            attrs = _attr(11, b"netops")
            length = 20 + len(attrs)
            header = struct.pack("!BBH", 2, identifier, length)
            bad_resp_auth = b"\x00" * 16
            packet = header + bad_resp_auth + attrs
            try:
                srv_sock.sendto(packet, addr)
            except OSError:
                break

    t = threading.Thread(target=_serve, daemon=True)
    t.start()

    backend = RADIUSAuthBackend(
        {
            "radius_server": host,
            "radius_port": port,
            "radius_secret": secret.decode(),
            "radius_timeout": 0.5,
            "radius_retries": 1,
        }
    )

    try:
        assert backend.authenticate("bob", "pw") is False
        attrs = backend.get_user_attributes("bob")
        assert attrs.get("groups") == []
    finally:
        stop.set()
        try:
            srv_sock.close()
        except Exception:
            pass
        t.join(timeout=2)
