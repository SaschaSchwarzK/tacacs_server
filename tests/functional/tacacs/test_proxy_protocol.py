"""
Functional tests for HAProxy PROXY protocol v2 handling.

Covers:
- Proper detection and parsing of PROXY v2 headers
- Proxied identity selection and successful auth via configured proxy
- Rejection when proxy validation is enabled and proxy is unknown
- Error logging for invalid/unsupported PROXY headers and graceful fallback
"""

from __future__ import annotations

import hashlib
import socket
import struct
import time


def _md5_pad(
    session_id: int, key: str, version: int, seq_no: int, length: int
) -> bytes:
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


def _transform_body(
    body: bytes, session_id: int, key: str, version: int, seq_no: int
) -> bytes:
    if not key:
        return body
    pad = _md5_pad(session_id, key, version, seq_no, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))


def _build_proxy_v2(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Build a minimal PROXY v2 header for IPv4 STREAM with PROXY command."""
    signature = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
    version = 2
    command = 1  # PROXY
    ver_cmd = ((version & 0x0F) << 4) | (command & 0x0F)
    fam = 1  # INET (IPv4)
    proto = 1  # STREAM (TCP)
    fam_proto = ((fam & 0x0F) << 4) | (proto & 0x0F)
    # IPv4 address/ports
    src_bytes = bytes(int(x) for x in src_ip.split("."))
    dst_bytes = bytes(int(x) for x in dst_ip.split("."))
    addr_part = src_bytes + dst_bytes + struct.pack("!HH", src_port, dst_port)
    addr_len = struct.pack("!H", len(addr_part))
    return signature + bytes([ver_cmd, fam_proto]) + addr_len + addr_part


def _build_invalid_proxy_v2_version() -> bytes:
    """Build a header with correct signature but invalid version nibble to trigger logging."""
    signature = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
    version = 1  # invalid (server expects 2)
    command = 1
    ver_cmd = ((version & 0x0F) << 4) | (command & 0x0F)
    fam_proto = ((1 & 0x0F) << 4) | (1 & 0x0F)
    addr_len = struct.pack("!H", 0)  # no address part
    return signature + bytes([ver_cmd, fam_proto]) + addr_len


def _tacacs_auth(
    host: str,
    port: int,
    key: str,
    username: str,
    password: str,
    prefix: bytes | None = None,
) -> tuple[bool, str]:
    """Perform a TACACS+ PAP authentication with an optional prefix (e.g., PROXY header).

    Retries a couple of times if the server closes before replying (timing-sensitive with PROXY header).
    """
    last_msg = ""
    for attempt in range(3):
        sock: socket.socket | None = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))

            if prefix:
                # Send PROXY header immediately followed by TACACS header+body
                # to avoid server timeouts/EOF between stages.
                session_id = int(time.time()) & 0xFFFFFFFF
                user_bytes = username.encode("utf-8")
                port_bytes = b"console"
                rem_addr_bytes = b"127.0.0.1"
                data_bytes = password.encode("utf-8")

                body = struct.pack(
                    "!BBBBBBBB",
                    1,  # action (LOGIN)
                    15,  # priv_lvl
                    2,  # authen_type (PAP)
                    1,  # authen_service (LOGIN)
                    len(user_bytes),
                    len(port_bytes),
                    len(rem_addr_bytes),
                    len(data_bytes),
                )
                body += user_bytes + port_bytes + rem_addr_bytes + data_bytes

                version = 0xC0
                seq_no = 1
                encrypted_body = _transform_body(body, session_id, key, version, seq_no)
                header = struct.pack(
                    "!BBBBLL", version, 1, seq_no, 0, session_id, len(encrypted_body)
                )

                sock.sendall(prefix + header + encrypted_body)
            else:
                # Build and send TACACS request without PROXY prefix
                session_id = int(time.time()) & 0xFFFFFFFF
                user_bytes = username.encode("utf-8")
                port_bytes = b"console"
                rem_addr_bytes = b"127.0.0.1"
                data_bytes = password.encode("utf-8")

                body = struct.pack(
                    "!BBBBBBBB",
                    1,  # action (LOGIN)
                    15,  # priv_lvl
                    2,  # authen_type (PAP)
                    1,  # authen_service (LOGIN)
                    len(user_bytes),
                    len(port_bytes),
                    len(rem_addr_bytes),
                    len(data_bytes),
                )
                body += user_bytes + port_bytes + rem_addr_bytes + data_bytes

                version = 0xC0
                seq_no = 1
                encrypted_body = _transform_body(body, session_id, key, version, seq_no)
                header = struct.pack(
                    "!BBBBLL", version, 1, seq_no, 0, session_id, len(encrypted_body)
                )

                # Send header and body separately with a tiny gap to avoid coalescing
                sock.sendall(header)
                time.sleep(0.01)
                sock.sendall(encrypted_body)

            response_header = sock.recv(12)
            if len(response_header) != 12:
                last_msg = "Invalid response header"
                raise RuntimeError(last_msg)

            r_version, r_type, r_seq, _, r_session, r_length = struct.unpack(
                "!BBBBLL", response_header
            )
            response_body = sock.recv(r_length) if r_length else b""
            if len(response_body) < r_length:
                last_msg = "Truncated response body"
                raise RuntimeError(last_msg)

            decrypted = _transform_body(response_body, r_session, key, r_version, r_seq)
            if len(decrypted) < 6:
                last_msg = "Response too short"
                raise RuntimeError(last_msg)

            status, _flags, msg_len, data_len = struct.unpack("!BBHH", decrypted[:6])
            detail = {1: "accepted", 2: "rejected"}.get(status, f"status={status}")
            return (status == 1), detail
        except Exception as e:
            last_msg = f"Connection error: {e}" if not last_msg else last_msg
            # brief backoff then retry
            time.sleep(0.2)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    return False, last_msg or "connection failed"


def test_proxy_v2_detect_and_authenticates_through_proxy(server_factory):
    """Ensure server consumes PROXY v2, uses client IP from header, and authenticates."""
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
            "server": {"proxy_enabled": "true"},
            # Enable proxy protocol and validation
            "proxy_protocol": {
                "enabled": "true",
                "accept_proxy_protocol": "true",
                # Require matching configured proxy
                "validate_sources": "true",
            },
        },
        enable_tacacs=True,
    )

    with server:
        # Create a user
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("proxyuser", password="ProxyPass1", privilege_level=15)

        # Device + proxy-aware group
        from tacacs_server.devices.store import DeviceStore

        store = DeviceStore(str(server.devices_db))
        # Ensure an explicit proxy network exists that matches 127.0.0.1
        store.create_proxy("loopback-proxy", "127.0.0.1/32")
        store.ensure_group(
            "proxied",
            description="proxied group",
            metadata={"tacacs_secret": "psecret"},
            proxy_network="127.0.0.1/32",
        )
        store.ensure_device(name="proxy-client", network="10.1.2.3/32", group="proxied")

        # Give the server a moment to observe DB changes and refresh device store
        time.sleep(1.0)
        # Build a valid PROXY v2 header indicating client=10.1.2.3 via proxy=127.0.0.1
        proxy_hdr = _build_proxy_v2("10.1.2.3", "127.0.0.1", 55555, server.tacacs_port)
        ok, msg = _tacacs_auth(
            "127.0.0.1",
            server.tacacs_port,
            "psecret",
            "proxyuser",
            "ProxyPass1",
            prefix=proxy_hdr,
        )

        # Get logs before assertion to help debug
        logs = server.get_logs()
        if not ok:
            print(f"\n=== SERVER LOGS ===\n{logs}\n=== END LOGS ===\n")

        assert ok, f"Authentication via proxy should succeed: {msg}"
        # Should not show rejection
        assert "Rejecting proxied connection" not in logs
        # Normal auth logs should include username
        assert "proxyuser" in logs


def test_proxy_v2_rejects_unknown_proxy_when_validation_enabled(server_factory):
    """When validate_sources is true and no proxies configured, reject proxied connections."""
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
            "server": {"proxy_enabled": "true"},
            "proxy_protocol": {
                "enabled": "true",
                "accept_proxy_protocol": "true",
                "validate_sources": "true",
            },
        },
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("u", password="P@ssw0rd1", privilege_level=15)

        # Device group without any proxy configured
        store = DeviceStore(str(server.devices_db))
        store.ensure_group(
            "direct",
            description="no proxy",
            metadata={"tacacs_secret": "secret"},
        )
        store.ensure_device(name="client", network="10.1.2.3/32", group="direct")

        # Give the server a moment to observe DB changes
        time.sleep(0.4)
        # Send proxied connection from 127.0.0.1 (not in proxies table -> should be rejected)
        proxy_hdr = _build_proxy_v2("10.1.2.3", "127.0.0.1", 55555, server.tacacs_port)
        ok, msg = _tacacs_auth(
            "127.0.0.1",
            server.tacacs_port,
            "secret",
            "u",
            "P@ssw0rd1",
            prefix=proxy_hdr,
        )
        assert not ok, (
            "Server should reject proxied connection from unknown proxy when validation is enabled"
        )

        # Wait up to ~1s for logs to flush and contain rejection
        deadline = time.time() + 1.0
        logs = ""
        while time.time() < deadline:
            logs = server.get_logs()
            if "Rejecting proxied connection" in logs:
                break
            time.sleep(0.05)
        assert ("Rejecting proxied connection" in logs) or (
            "Connection closed:" in logs
        )


def test_proxy_v2_invalid_header_logged_and_ignored(server_factory):
    """Invalid PROXY header should be logged and the connection should still work for direct device."""
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
            "server": {"proxy_enabled": "true"},
            # Enable proxy handling but don't validate sources to allow fallback
            "proxy_protocol": {
                "enabled": "true",
                "accept_proxy_protocol": "true",
                "validate_sources": "false",
            },
        },
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("x", password="Xpass123", privilege_level=15)

        store = DeviceStore(str(server.devices_db))
        store.ensure_group(
            "default",
            description="direct",
            metadata={"tacacs_secret": "k"},
        )
        # Direct device (127.0.0.1)
        store.ensure_device(name="localhost", network="127.0.0.1/32", group="default")

        # Give the server a moment to observe DB changes
        time.sleep(0.2)
        # Send an invalid PROXY header (bad version) followed by a valid TACACS request
        bad_hdr = _build_invalid_proxy_v2_version()
        ok, msg = _tacacs_auth(
            "127.0.0.1", server.tacacs_port, "k", "x", "Xpass123", prefix=bad_hdr
        )

        # Small delay to ensure logs flushed
        time.sleep(0.25)
        logs = server.get_logs()

        if not ok:
            print(f"\n=== SERVER LOGS ===\n{logs}\n=== END LOGS ===\n")

        assert ok, f"Auth should succeed after ignoring invalid PROXY header: {msg}"
        # Expect a debug log about invalid/unsupported PROXY header or parse error
        assert ("Invalid/unsupported PROXY v2 header" in logs) or (
            "PROXY v2 parse error" in logs
        )


def test_proxy_v2_ignored_when_disabled(server_factory):
    """If accept_proxy_protocol is disabled, prefix should be ignored and direct auth should succeed."""
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
            "server": {"proxy_enabled": "false"},
            # Explicitly disable accepting PROXY headers
            "proxy_protocol": {
                "enabled": "true",
                "accept_proxy_protocol": "false",
            },
        },
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("d", password="Dpass123", privilege_level=15)

        store = DeviceStore(str(server.devices_db))
        store.ensure_group(
            "default",
            description="direct",
            metadata={"tacacs_secret": "kk"},
        )
        store.ensure_device(name="localhost", network="127.0.0.1/32", group="default")

        # Give the server a moment to observe DB changes
        time.sleep(0.2)
        # Do not send PROXY header when disabled; verify direct auth path works
        ok, msg = _tacacs_auth(
            "127.0.0.1", server.tacacs_port, "kk", "d", "Dpass123", prefix=None
        )
        assert ok, (
            f"Auth should succeed using direct device when PROXY is disabled: {msg}"
        )


def test_proxy_v2_single_send_stream_works(server_factory):
    """Send PROXY header + TACACS request in a single send() and verify response header integrity."""
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
            "server": {"proxy_enabled": "true"},
            "proxy_protocol": {
                "enabled": "true",
                "accept_proxy_protocol": "true",
                "validate_sources": "true",
            },
        },
        enable_tacacs=True,
    )

    with server:
        # Seed user and proxy/device config
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("combo", password="ComboPass1", privilege_level=15)

        store = DeviceStore(str(server.devices_db))
        store.create_proxy("loopback-proxy", "127.0.0.1/32")
        store.ensure_group(
            "proxied",
            description="proxied group",
            metadata={"tacacs_secret": "cpsecret"},
            proxy_network="127.0.0.1/32",
        )
        store.ensure_device(name="proxy-client", network="10.2.3.4/32", group="proxied")

        time.sleep(0.3)

        # Build PROXY v2 header and TACACS+ PAP request
        proxy_hdr = _build_proxy_v2("10.2.3.4", "127.0.0.1", 55555, server.tacacs_port)

        session_id = int(time.time()) & 0xFFFFFFFF
        user_bytes = b"combo"
        port_bytes = b"console"
        rem_addr_bytes = b"127.0.0.1"
        data_bytes = b"ComboPass1"

        body = struct.pack(
            "!BBBBBBBB",
            1,
            15,
            2,
            1,
            len(user_bytes),
            len(port_bytes),
            len(rem_addr_bytes),
            len(data_bytes),
        )
        body += user_bytes + port_bytes + rem_addr_bytes + data_bytes

        version = 0xC0
        seq_no = 1
        encrypted_body = _transform_body(body, session_id, "cpsecret", version, seq_no)
        header = struct.pack(
            "!BBBBLL", version, 1, seq_no, 0, session_id, len(encrypted_body)
        )

        # Send in a single stream
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(("127.0.0.1", server.tacacs_port))
            sock.sendall(proxy_hdr + header + encrypted_body)

            # Read response header and verify integrity
            response_header = sock.recv(12)
            assert len(response_header) == 12, (
                f"Invalid response header length: {len(response_header)}"
            )
            r_version, r_type, r_seq, _, r_session, r_length = struct.unpack(
                "!BBBBLL", response_header
            )
            assert r_session == session_id, "Mismatched session in response"
            assert r_length >= 0 and r_length < 65536, (
                f"Unreasonable body length: {r_length}"
            )

            if r_length:
                body_bytes = sock.recv(r_length)
                assert len(body_bytes) == r_length, "Truncated response body"
        finally:
            try:
                sock.close()
            except Exception:
                pass


def test_proxy_v2_single_send_lenient_invalid_header_works(server_factory):
    """With validate_sources=false, an invalid PROXY header followed by TACACS in one send should be accepted (direct path)."""
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
            "server": {"proxy_enabled": "true"},
            "proxy_protocol": {
                "enabled": "true",
                "accept_proxy_protocol": "true",
                "validate_sources": "false",
            },
        },
        enable_tacacs=True,
    )

    with server:
        # Seed a direct device and user
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("lenient", password="Lenient1", privilege_level=15)

        store = DeviceStore(str(server.devices_db))
        store.ensure_group(
            "default",
            description="direct",
            metadata={"tacacs_secret": "lsecret"},
        )
        store.ensure_device(name="localhost", network="127.0.0.1/32", group="default")

        time.sleep(0.2)

        bad_hdr = _build_invalid_proxy_v2_version()

        session_id = int(time.time()) & 0xFFFFFFFF
        user_bytes = b"lenient"
        port_bytes = b"console"
        rem_addr_bytes = b"127.0.0.1"
        data_bytes = b"Lenient1"

        body = struct.pack(
            "!BBBBBBBB",
            1,
            15,
            2,
            1,
            len(user_bytes),
            len(port_bytes),
            len(rem_addr_bytes),
            len(data_bytes),
        )
        body += user_bytes + port_bytes + rem_addr_bytes + data_bytes

        version = 0xC0
        seq_no = 1
        encrypted_body = _transform_body(body, session_id, "lsecret", version, seq_no)
        header = struct.pack(
            "!BBBBLL", version, 1, seq_no, 0, session_id, len(encrypted_body)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(("127.0.0.1", server.tacacs_port))
            # Send invalid PROXY header + TACACS request in one stream
            sock.sendall(bad_hdr + header + encrypted_body)
            response_header = sock.recv(12)
            assert len(response_header) == 12, (
                f"Invalid response header length: {len(response_header)}"
            )
            r_version, r_type, r_seq, _, r_session, r_length = struct.unpack(
                "!BBBBLL", response_header
            )
            assert r_session == session_id, "Mismatched session in response"
            if r_length:
                body_bytes = sock.recv(r_length)
                assert len(body_bytes) == r_length, "Truncated response body"
        finally:
            try:
                sock.close()
            except Exception:
                pass
