"""
RADIUS auto-registration tests

Verifies that unknown RADIUS clients are auto-created as devices when enabled,
and not created (strict deny) when disabled.
"""

from __future__ import annotations

import hashlib
import socket
import struct
import os


def _make_request_authenticator() -> bytes:
    return os.urandom(16)


def _radius_auth(host: str, port: int, secret: str, username: str, password: str) -> tuple[bool, str]:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        code = 1  # Access-Request
        identifier = 1
        request_auth = _make_request_authenticator()

        attrs = b""
        # User-Name
        u = username.encode()
        attrs += struct.pack("!BB", 1, 2 + len(u)) + u
        # User-Password (RFC 2865 obfuscation)
        p = password.encode()
        if len(p) % 16:
            p += b"\x00" * (16 - len(p) % 16)
        enc = b""
        c = request_auth
        sec = secret.encode()
        for i in range(0, len(p), 16):
            blk = p[i : i + 16]
            md5 = hashlib.md5(sec + c, usedforsecurity=False).digest()
            eblk = bytes(a ^ b for a, b in zip(blk, md5))
            enc += eblk
            c = eblk
        attrs += struct.pack("!BB", 2, 2 + len(enc)) + enc
        # NAS-IP-Address
        attrs += struct.pack("!BB", 4, 6) + socket.inet_aton("127.0.0.1")

        length = 20 + len(attrs)
        pkt = struct.pack("!BBH", code, identifier, length) + request_auth + attrs
        sock.sendto(pkt, (host, port))
        resp, _ = sock.recvfrom(4096)
        if len(resp) < 20:
            return False, "invalid"
        resp_code = resp[0]
        return (resp_code == 2), ("Accept" if resp_code == 2 else "Reject" if resp_code == 3 else str(resp_code))
    except Exception as e:
        return False, f"error: {e}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def test_radius_autoregistration_enabled(server_factory):
    # Prepare default group with RADIUS secret so the auto-registered device can be used
    server = server_factory(
        config={"auth_backends": "local", "radius_share_backends": "true"},
        enable_radius=True,
    )

    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.devices.store import DeviceStore

    us = LocalUserService(str(server.auth_db))
    us.create_user("ruser1", password="Passw0rd!", privilege_level=15)

    ds = DeviceStore(str(server.devices_db))
    ds.ensure_group("default", description="Default", metadata={"radius_secret": "radsecret"})

    with server:
        # No devices pre-configured; first request triggers auto-registration
        ok, _ = _radius_auth("127.0.0.1", server.radius_auth_port, "radsecret", "ruser1", "Passw0rd!")
        # Regardless of auth outcome, device should now exist
        rec = ds.find_device_for_ip("127.0.0.1")
        assert rec is not None, "Auto-registered RADIUS client device expected"


def test_radius_autoregistration_disabled(server_factory):
    server = server_factory(
        config={
            "auth_backends": "local",
            "radius_share_backends": "true",
            "devices": {"auto_register": "false"},
        },
        enable_radius=True,
    )

    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.devices.store import DeviceStore

    us = LocalUserService(str(server.auth_db))
    us.create_user("ruser2", password="Passw0rd!", privilege_level=15)

    ds = DeviceStore(str(server.devices_db))
    ds.ensure_group("default", description="Default", metadata={"radius_secret": "radsecret"})

    with server:
        ok, _ = _radius_auth("127.0.0.1", server.radius_auth_port, "radsecret", "ruser2", "Passw0rd!")
        # Auto-registration disabled: device must not be created
        rec = ds.find_device_for_ip("127.0.0.1")
        assert rec is None, "Device must not be created when auto_register=false"
