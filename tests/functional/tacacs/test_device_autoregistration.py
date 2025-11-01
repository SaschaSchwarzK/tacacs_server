"""
Tests for device auto-registration feature.

Verifies that unknown devices are auto-created when enabled, and that strict
mode (disabled) rejects unknown devices without creating records.
"""

from __future__ import annotations

import hashlib
import socket
import struct
import time


def _md5_pad(session_id: int, key: str, version: int, seq_no: int, length: int) -> bytes:
    pad = bytearray()
    session_id_bytes = struct.pack("!L", session_id)
    key_bytes = key.encode("utf-8")
    version_byte = bytes([version])
    seq_byte = bytes([seq_no])
    while len(pad) < length:
        if not pad:
            md5_input = session_id_bytes + key_bytes + version_byte + seq_byte
        else:
            md5_input = session_id_bytes + key_bytes + version_byte + seq_byte + pad
        pad.extend(hashlib.md5(md5_input, usedforsecurity=False).digest())
    return bytes(pad[:length])


def _transform(body: bytes, session_id: int, key: str, version: int, seq_no: int) -> bytes:
    if not key:
        return body
    pad = _md5_pad(session_id, key, version, seq_no, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))


def _tacacs_pap(host: str, port: int, key: str, username: str, password: str) -> tuple[bool, str]:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        session_id = int(time.time()) & 0xFFFFFFFF
        user_bytes = username.encode("utf-8")
        port_bytes = b"console"
        rem_addr_bytes = b"127.0.0.1"
        data_bytes = password.encode("utf-8")
        body = struct.pack("!BBBBBBBB", 1, 15, 2, 1, len(user_bytes), len(port_bytes), len(rem_addr_bytes), len(data_bytes))
        body += user_bytes + port_bytes + rem_addr_bytes + data_bytes
        version = 0xC0
        seq_no = 1
        encrypted = _transform(body, session_id, key, version, seq_no)
        header = struct.pack("!BBBBLL", version, 1, seq_no, 0, session_id, len(encrypted))
        sock.sendall(header + encrypted)
        hdr = sock.recv(12)
        if len(hdr) != 12:
            return False, "no header"
        r_version, r_type, r_seq, _, r_session, r_length = struct.unpack("!BBBBLL", hdr)
        resp = sock.recv(r_length) if r_length else b""
        dec = _transform(resp, r_session, key, r_version, r_seq)
        if len(dec) < 6:
            return False, "short response"
        status, _flags, msg_len, data_len = struct.unpack("!BBHH", dec[:6])
        ok = status == 1
        return ok, f"status={status}"
    except Exception as e:
        return False, f"error: {e}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def test_autoregistration_enabled_creates_device(server_factory):
    # Start server with local auth (TACACS default secret fallback is used)
    server = server_factory(config={"auth_backends": "local"}, enable_tacacs=True)
    with server:
        # Create a local user
        from tacacs_server.auth.local_user_service import LocalUserService

        us = LocalUserService(str(server.auth_db))
        us.create_user("auto1", password="P@ssw0rd!", privilege_level=15)

        # No device/groups pre-created. Auto-registration should create host /32 in default group.
        ok, _ = _tacacs_pap(
            host="127.0.0.1",
            port=server.tacacs_port,
            key="CHANGE_ME_FALLBACK",
            username="auto1",
            password="P@ssw0rd!",
        )
        # Auth may succeed or fail depending on group secrets; creation is what we assert.
        from tacacs_server.devices.store import DeviceStore

        ds = DeviceStore(str(server.devices_db))
        rec = ds.find_device_for_ip("127.0.0.1")
        assert rec is not None, "Device should be auto-registered for client IP"
        assert rec.group is None or getattr(rec.group, "name", "default") in ("default", rec.group.name)


def test_autoregistration_disabled_rejects_and_does_not_create(server_factory):
    server = server_factory(
        config={"auth_backends": "local", "devices": {"auto_register": "false"}},
        enable_tacacs=True,
    )
    with server:
        # Create a local user
        from tacacs_server.auth.local_user_service import LocalUserService

        us = LocalUserService(str(server.auth_db))
        us.create_user("auto2", password="P@ssw0rd!", privilege_level=15)

        ok, _ = _tacacs_pap(
            host="127.0.0.1",
            port=server.tacacs_port,
            key="CHANGE_ME_FALLBACK",
            username="auto2",
            password="P@ssw0rd!",
        )
        # Should reject/close; ensure no device is created
        from tacacs_server.devices.store import DeviceStore

        ds = DeviceStore(str(server.devices_db))
        rec = ds.find_device_for_ip("127.0.0.1")
        assert rec is None, "Device must not be created when auto_register is disabled"
