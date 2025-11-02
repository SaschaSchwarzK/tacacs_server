"""Fixed encryption tests - adapts to new log format"""

import hashlib
import socket
import struct
import time

import pytest

from tacacs_server.tacacs.constants import (
    TAC_PLUS_FLAGS,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)


def _md5_pad(
    session_id: int, key: str, version: int, seq_no: int, length: int
) -> bytes:
    pad = bytearray()
    sid = struct.pack("!L", session_id)
    key_b = key.encode("utf-8")
    ver_b = bytes([version])
    seq_b = bytes([seq_no])
    while len(pad) < length:
        if not pad:
            data = sid + key_b + ver_b + seq_b
        else:
            data = sid + key_b + ver_b + seq_b + pad
        pad.extend(hashlib.md5(data, usedforsecurity=False).digest())
    return bytes(pad[:length])


def _xor_body(body: bytes, session_id: int, key: str, version: int, seq: int) -> bytes:
    if not key:
        return body
    pad = _md5_pad(session_id, key, version, seq, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))


def _mk_header(
    version_major: int, ptype: int, seq: int, flags: int, session: int, length: int
) -> bytes:
    version = ((version_major & 0x0F) << 4) | 0
    return struct.pack("!BBBBLL", version, ptype, seq, flags, session, length)


def _mk_auth_body(username: str, password: str) -> bytes:
    user_b = username.encode("utf-8")
    port_b = b"console"
    rem_b = b"127.0.0.1"
    data_b = password.encode("utf-8")
    return (
        struct.pack(
            "!BBBBBBBB", 1, 15, 2, 1, len(user_b), len(port_b), len(rem_b), len(data_b)
        )
        + user_b
        + port_b
        + rem_b
        + data_b
    )


def _setup_device_and_user(server, username: str, password: str, secret: str) -> None:
    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.devices.store import DeviceStore

    users = LocalUserService(str(server.auth_db))
    users.create_user(username, password=password, privilege_level=15)
    store = DeviceStore(str(server.devices_db))
    store.ensure_group(
        "default", description="Default group", metadata={"tacacs_secret": secret}
    )
    store.ensure_device(name="test-device", network="127.0.0.1", group="default")


def _auth_once(
    host: str,
    port: int,
    secret: str,
    username: str,
    password: str,
    *,
    session_id: int,
    seq: int,
    flags: int = 0,
) -> tuple[bool, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    version = ((TAC_PLUS_MAJOR_VER & 0x0F) << 4) | 0
    try:
        s.connect((host, port))
        body = _mk_auth_body(username, password)
        enc = (
            body
            if (flags & TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG)
            else _xor_body(body, session_id, secret, version, seq)
        )
        hdr = _mk_header(
            TAC_PLUS_MAJOR_VER,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            seq,
            int(flags),
            session_id,
            len(enc),
        )
        s.sendall(hdr + enc)
        rh = s.recv(12)
        if len(rh) != 12:
            return False, "no response"
        rver, rtype, rseq, rflags, rsess, rlen = struct.unpack("!BBBBLL", rh)
        rb = s.recv(rlen) if rlen else b""
        if len(rb) < rlen:
            return False, "truncated"
        resp = (
            rb
            if (rflags & TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG)
            else _xor_body(rb, rsess, secret, rver, rseq)
        )
        if len(resp) < 6:
            return False, "short"
        status, _flags, msg_len, data_len = struct.unpack("!BBHH", resp[:6])
        ok = status == 1
        return ok, f"status={status}"
    finally:
        try:
            s.close()
        except Exception:
            pass


def _auth_on_socket(
    sock: socket.socket,
    secret: str,
    username: str,
    password: str,
    *,
    session_id: int,
    seq: int,
    flags: int = 0,
) -> tuple[bool, int]:
    version = ((TAC_PLUS_MAJOR_VER & 0x0F) << 4) | 0
    body = _mk_auth_body(username, password)
    enc = (
        body
        if (flags & TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG)
        else _xor_body(body, session_id, secret, version, seq)
    )
    hdr = _mk_header(
        TAC_PLUS_MAJOR_VER,
        TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq,
        int(flags),
        session_id,
        len(enc),
    )
    sock.sendall(hdr + enc)
    rh = sock.recv(12)
    if len(rh) != 12:
        return False, 0
    rver, rtype, rseq, rflags, rsess, rlen = struct.unpack("!BBBBLL", rh)
    rb = sock.recv(rlen) if rlen else b""
    if len(rb) < rlen:
        return False, rseq
    resp = (
        rb
        if (rflags & TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG)
        else _xor_body(rb, rsess, secret, rver, rseq)
    )
    if len(resp) < 6:
        return False, rseq
    status, _flags, msg_len, data_len = struct.unpack("!BBHH", resp[:6])
    return status == 1, rseq


@pytest.mark.integration
def test_encryption_with_special_characters_secret(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        secret = "a!@#$%^&*()_+-=[]{}|;:'\",.<>/?~` complicated"
        _setup_device_and_user(server, "specuser", "SpecPass1", secret)
        ok, msg = _auth_once(
            "127.0.0.1",
            server.tacacs_port,
            secret,
            "specuser",
            "SpecPass1",
            session_id=(int(time.time()) & 0xFFFFFFFF),
            seq=1,
        )
        assert ok, f"Auth should succeed with special-char secret: {msg}"


@pytest.mark.integration
def test_encryption_with_very_long_secret(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        secret = ("long-SECRET-🛡️-" * 30)[:320]
        assert len(secret) > 256
        _setup_device_and_user(server, "longuser", "LongPass1", secret)
        ok, msg = _auth_once(
            "127.0.0.1",
            server.tacacs_port,
            secret,
            "longuser",
            "LongPass1",
            session_id=(int(time.time()) & 0xFFFFFFFF),
            seq=1,
        )
        assert ok, f"Auth should succeed with very long secret: {msg}"


@pytest.mark.integration
def test_encryption_with_non_ascii_secret(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        secret = "пароль-秘密-كلمةالسر-şifre-密钥-🔑"
        _setup_device_and_user(server, "uniuser", "UniPass1", secret)
        ok, msg = _auth_once(
            "127.0.0.1",
            server.tacacs_port,
            secret,
            "uniuser",
            "UniPass1",
            session_id=(int(time.time()) & 0xFFFFFFFF),
            seq=1,
        )
        assert ok, f"Auth should succeed with non-ASCII secret: {msg}"


@pytest.mark.integration
def test_mixed_encrypted_unencrypted_sessions(server_factory):
    server = server_factory(
        enable_tacacs=True, config={"security": {"encryption_required": "false"}}
    )
    with server:
        secret = "allow-plain"
        _setup_device_and_user(server, "plainuser", "PlainPass1", secret)
        sess1 = int(time.time()) & 0xFFFFFFFF
        sess2 = (int(time.time()) + 1) & 0xFFFFFFFF
        ok1, _ = _auth_once(
            "127.0.0.1",
            server.tacacs_port,
            secret,
            "plainuser",
            "PlainPass1",
            session_id=sess1,
            seq=1,
        )
        ok2, _ = _auth_once(
            "127.0.0.1",
            server.tacacs_port,
            secret,
            "plainuser",
            "PlainPass1",
            session_id=sess2,
            seq=1,
            flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        )
        assert ok1 and ok2, (
            "Both encrypted and unencrypted auth should succeed when not required"
        )
        time.sleep(0.1)
        logs = server.get_logs()
        # Updated: look for JSON event markers or username references
        auth_events = logs.count('"event"') + logs.count("plainuser")
        assert auth_events >= 2, "Expected two authentication events"


@pytest.mark.integration
def test_encryption_key_rotation_session_cache(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        secret1 = "rotate-ONE-KEY"
        _setup_device_and_user(server, "rotuser", "RotPass1", secret1)
        host, port = "127.0.0.1", server.tacacs_port
        sess = int(time.time()) & 0xFFFFFFFF
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        try:
            ok1, _ = _auth_on_socket(
                sock, secret1, "rotuser", "RotPass1", session_id=sess, seq=1
            )
            assert ok1, "First auth with S1 should pass"
            from tacacs_server.devices.store import DeviceStore

            store = DeviceStore(str(server.devices_db))
            store.ensure_group(
                "default",
                description="Default group",
                metadata={"tacacs_secret": "rotate-TWO-KEY"},
            )
            secret2 = "rotate-TWO-KEY"
            ok2, _ = _auth_on_socket(
                sock, secret1, "rotuser", "RotPass1", session_id=sess, seq=3
            )
            if ok2:
                ok3, _ = _auth_on_socket(
                    sock, secret2, "rotuser", "RotPass1", session_id=sess, seq=5
                )
                assert not ok3, (
                    "Expected new secret rejected if old still cached for session"
                )
            else:
                ok3, _ = _auth_on_socket(
                    sock, secret2, "rotuser", "RotPass1", session_id=sess, seq=5
                )
                assert not ok3, (
                    "Expected new secret also rejected mid-session when old was rejected"
                )
                ok_new, _ = _auth_once(
                    host,
                    port,
                    secret2,
                    "rotuser",
                    "RotPass1",
                    session_id=((sess + 12345) & 0xFFFFFFFF),
                    seq=1,
                )
                assert ok_new, (
                    "Expected new secret to succeed on a fresh session after rotation"
                )
        finally:
            try:
                sock.close()
            except Exception:
                pass
        time.sleep(0.1)
        logs = server.get_logs()
        # Updated: count JSON events or username mentions
        auth_events = logs.count('"event"') + logs.count("rotuser")
        assert auth_events >= 2
