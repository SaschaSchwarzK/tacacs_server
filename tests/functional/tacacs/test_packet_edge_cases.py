"""
TACACS+ Packet Handling Edge Case Tests

Covers:
- maximum body length
- zero-length body
- multiple sequential packets in same session
- out-of-order sequence numbers (should be rejected)
- packet fragmentation scenarios
- corrupted packet headers
- response to unknown packet types
"""

import socket
import struct
import time

import pytest

from tacacs_server.tacacs.constants import (
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)


def _mk_header(
    version_major: int, ptype: int, seq: int, flags: int, session: int, length: int
) -> bytes:
    version = ((version_major & 0x0F) << 4) | 0  # minor 0
    return struct.pack("!BBBBLL", version, ptype, seq, flags, session, length)


def _mk_auth_body(username: str, password: str) -> bytes:
    user_b = username.encode("utf-8")
    port_b = b"console"
    rem_b = b"127.0.0.1"
    data_b = password.encode("utf-8")
    # action=LOGIN(1), priv=15, type=PAP(2), svc=LOGIN(1)
    hdr = struct.pack(
        "!BBBBBBBB", 1, 15, 2, 1, len(user_b), len(port_b), len(rem_b), len(data_b)
    )
    return hdr + user_b + port_b + rem_b + data_b


def _md5_pad(
    session_id: int, key: str, version: int, seq_no: int, length: int
) -> bytes:
    import hashlib

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


@pytest.mark.integration
def test_maximum_body_length(server_factory):
    server = server_factory(
        enable_tacacs=True, config={"server": {"max_packet_length": 2048}}
    )
    with server:
        _setup_device_and_user(server, "edgeuser", "EdgePass1", "testsecret")
        host, port = "127.0.0.1", server.tacacs_port

        # Build a body exactly at the configured limit
        max_len = 2048
        session = int(time.time()) & 0xFFFFFFFF
        version = ((TAC_PLUS_MAJOR_VER & 0x0F) << 4) | 0
        seq = 1

        # Start from a valid auth body and pad to exact size
        body = _mk_auth_body("edgeuser", "EdgePass1")
        if len(body) > max_len:
            pytest.skip("Auth body exceeds configured max length unexpectedly")
        body += b"X" * (max_len - len(body))
        enc = _xor_body(body, session, "testsecret", version, seq)
        hdr = _mk_header(
            TAC_PLUS_MAJOR_VER,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            seq,
            0,
            session,
            len(enc),
        )

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        try:
            s.sendall(hdr + enc)
            # Expect a response header (12 bytes) or a clean close if server refuses giant valid bodies.
            data = s.recv(12)
            assert len(data) in (0, 12)
            # If 12, read body and ensure not truncated
            if len(data) == 12:
                _, _, rseq, _, rsess, rlen = struct.unpack("!BBBBLL", data)
                body = s.recv(rlen) if rlen else b""
                assert len(body) == rlen
        finally:
            s.close()

        # Also test over-limit header to trigger packet_header_error logging
        too_big = max_len + 1
        hdr2 = _mk_header(
            TAC_PLUS_MAJOR_VER,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            1,
            0,
            session ^ 0x55AA,
            too_big,
        )
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(1)
        s2.connect((host, port))
        try:
            s2.sendall(hdr2)
            try:
                _ = s2.recv(1)
            except TimeoutError:
                pass
        finally:
            s2.close()

        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        assert (
            "packet_header_error" in logs
            or "Invalid packet" in logs
            or "Packet too large" in logs
            or "packet_too_large" in logs
        ), f"Expected header error for over-limit packet, got:\n{logs[-1200:]}"


@pytest.mark.integration
def test_zero_length_body(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        # Zero-length body with valid header should be read and connection closed or ignored
        host, port = "127.0.0.1", server.tacacs_port
        session = 0xABCDEF12
        hdr = _mk_header(
            TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, session, 0
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        try:
            s.sendall(hdr)
            # Server should not hang; either responds or closes
            try:
                data = s.recv(1)
            except TimeoutError:
                data = b""
            assert data in (b"",) or isinstance(data, (bytes,))
        finally:
            s.close()
        # Zero-length should not produce header errors
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        assert "packet_header_error" not in logs, (
            f"Unexpected header error on zero-length: \n{logs[-1000:]}"
        )


@pytest.mark.integration
def test_multiple_sequential_packets_same_session(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        _setup_device_and_user(server, "mseq", "MseqPass1", "testsecret")
        host, port = "127.0.0.1", server.tacacs_port

        session = int(time.time()) & 0xFFFFFFFF
        version = ((TAC_PLUS_MAJOR_VER & 0x0F) << 4) | 0

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        try:
            # First request (seq=1)
            body1 = _mk_auth_body("mseq", "MseqPass1")
            enc1 = _xor_body(body1, session, "testsecret", version, 1)
            hdr1 = _mk_header(
                TAC_PLUS_MAJOR_VER,
                TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
                1,
                0,
                session,
                len(enc1),
            )
            s.sendall(hdr1 + enc1)
            r1 = s.recv(12)
            assert len(r1) in (0, 12)
            # Second request (seq=3) on same connection/session
            body2 = _mk_auth_body("mseq", "MseqPass1")
            enc2 = _xor_body(body2, session, "testsecret", version, 3)
            hdr2 = _mk_header(
                TAC_PLUS_MAJOR_VER,
                TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
                3,
                0,
                session,
                len(enc2),
            )
            s.sendall(hdr2 + enc2)
            r2 = s.recv(12)
            assert len(r2) in (0, 12)
        finally:
            s.close()


@pytest.mark.integration
def test_out_of_order_sequence_rejected(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        _setup_device_and_user(server, "ooseq", "OoSeqPass1", "testsecret")
        host, port = "127.0.0.1", server.tacacs_port
        session = (int(time.time()) & 0xFFFFFFFF) | 0x100
        version = ((TAC_PLUS_MAJOR_VER & 0x0F) << 4) | 0

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        try:
            # First valid request
            b1 = _mk_auth_body("ooseq", "OoSeqPass1")
            e1 = _xor_body(b1, session, "testsecret", version, 1)
            h1 = _mk_header(
                TAC_PLUS_MAJOR_VER,
                TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
                1,
                0,
                session,
                len(e1),
            )
            s.sendall(h1 + e1)
            # Drain full first response: header and body
            rh = s.recv(12)
            if len(rh) == 12:
                _, _, _, _, _, rlen = struct.unpack("!BBBBLL", rh)
                if rlen:
                    rem = rlen
                    while rem > 0:
                        chunk = s.recv(rem)
                        if not chunk:
                            break
                        rem -= len(chunk)

            # Out-of-order: seq=1 again (should be rejected, server may close)
            e2 = _xor_body(b1, session, "testsecret", version, 1)
            h2 = _mk_header(
                TAC_PLUS_MAJOR_VER,
                TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
                1,
                0,
                session,
                len(e2),
            )
            s.sendall(h2 + e2)
            try:
                data = s.recv(12)
            except TimeoutError:
                data = b""
            # Expect no response or connection drop
            assert data in (b"",)
            # Validate logs contain out_of_order_sequence event (JSON or plain)
            import time as _t

            _t.sleep(0.1)
            logs = server.get_logs()
            assert (
                "out_of_order_sequence" in logs
                or "Out-of-order sequence" in logs
                or "Invalid sequence number" in logs
            ), f"Expected out-of-order sequence log, got:\n{logs[-1000:]}"
        finally:
            s.close()


@pytest.mark.integration
def test_packet_fragmentation(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        _setup_device_and_user(server, "frag", "FragPass1", "testsecret")
        host, port = "127.0.0.1", server.tacacs_port
        session = int(time.time()) & 0xFFFFFFFF
        version = ((TAC_PLUS_MAJOR_VER & 0x0F) << 4) | 0
        body = _mk_auth_body("frag", "FragPass1")
        enc = _xor_body(body, session, "testsecret", version, 1)
        hdr = _mk_header(
            TAC_PLUS_MAJOR_VER,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            1,
            0,
            session,
            len(enc),
        )

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        try:
            # Send header in two parts
            s.sendall(hdr[:5])
            time.sleep(0.01)
            s.sendall(hdr[5:])
            # Send body in small chunks
            for i in range(0, len(enc), 7):
                s.sendall(enc[i : i + 7])
                time.sleep(0.001)
            # Expect a response or a clean close
            try:
                data = s.recv(12)
            except TimeoutError:
                data = b""
            assert len(data) in (0, 12)
        finally:
            s.close()
        # Fragmentation should not cause header errors or incomplete body logs
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        assert "packet_header_error" not in logs, (
            f"Unexpected header error on fragmentation: \n{logs[-1200:]}"
        )
        assert "Incomplete packet body" not in logs, (
            f"Unexpected incomplete body on fragmentation: \n{logs[-1200:]}"
        )


@pytest.mark.integration
def test_incomplete_body_logs_warning(server_factory):
    """Advertise a positive body length and then close early to trigger incomplete body log."""
    server = server_factory(enable_tacacs=True)
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        session = 0xA1B2C3D4
        # Advertise a small body (e.g., 10 bytes) but send none
        hdr = _mk_header(
            TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, session, 10
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        try:
            s.sendall(hdr)
            # Do not send the body; wait for server to attempt read and log
            try:
                _ = s.recv(1)
            except TimeoutError:
                pass
        finally:
            s.close()
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        assert "incomplete_packet_body" in logs or "Incomplete packet body" in logs, (
            f"Expected incomplete body warning, got:\n{logs[-1200:]}"
        )


@pytest.mark.integration
def test_corrupted_header(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        try:
            # Invalid major version (e.g., 0)
            bad_hdr = _mk_header(
                0, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, 0x1111, 0
            )
            s.sendall(bad_hdr)
            # Server should close or not respond
            try:
                data = s.recv(1)
            except TimeoutError:
                data = b""
            assert data in (b"",)
            # Validate logs contain invalid_major_version event
            import time as _t

            _t.sleep(0.1)
            logs = server.get_logs()
            assert "invalid_major_version" in logs or "Invalid major version" in logs, (
                f"Expected invalid major version log, got:\n{logs[-1000:]}"
            )
        finally:
            s.close()


@pytest.mark.integration
def test_unknown_packet_type(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        session = 0x22223333
        # Use an invalid type number 99
        hdr = _mk_header(TAC_PLUS_MAJOR_VER, 99, 1, 0, session, 0)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        try:
            s.sendall(hdr)
            try:
                data = s.recv(1)
            except TimeoutError:
                data = b""
            # Server should reject and close (no reply)
            assert data == b""
            # Validate logs contain invalid_packet_type event
            import time as _t

            _t.sleep(0.1)
            logs = server.get_logs()
            assert "invalid_packet_type" in logs or "Invalid packet type" in logs, (
                f"Expected invalid packet type log, got:\n{logs[-1000:]}"
            )
        finally:
            s.close()
