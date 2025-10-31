"""
TACACS+ PAP authentication against a real server (no mocks):
- Unencrypted mode (UNENCRYPTED_FLAG set)
- Encrypted mode (default XOR stream with shared secret)

Reads values from the generated config file to locate the auth/devices DB paths
and exercises the wire protocol directly. Seeds minimal state (user + device
group secret + loopback device) so the authentication can succeed.
"""

from __future__ import annotations

import configparser
import socket
import struct
import time

from tacacs_server.auth.local_user_service import LocalUserService
from tacacs_server.devices.store import DeviceStore
from tacacs_server.tacacs.constants import (
    TAC_PLUS_AUTHEN_ACTION,
    TAC_PLUS_AUTHEN_STATUS,
    TAC_PLUS_AUTHEN_SVC,
    TAC_PLUS_AUTHEN_TYPE,
    TAC_PLUS_FLAGS,
    TAC_PLUS_HEADER_SIZE,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.packet import TacacsPacket


def _read_exact(sock: socket.socket, length: int, timeout: float = 3.0) -> bytes:
    """Read exactly 'length' bytes from socket with timeout.

    Args:
        sock: Connected socket to read from
        length: Number of bytes to read
        timeout: Socket timeout in seconds

    Returns:
        bytes: Data read from socket

    Raises:
        socket.timeout: If read operation times out
    """
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _mk_auth_start_body(username: str, password: str) -> bytes:
    """Create TACACS+ authentication start packet body for PAP.

    Args:
        username: Username for authentication
        password: Password for authentication

    Returns:
        bytes: Packed authentication start body
    """
    user_b = username.encode()
    port_b = b""
    rem_b = b""
    data_b = password.encode()
    head = struct.pack(
        "!BBBBBBBB",
        TAC_PLUS_AUTHEN_ACTION.TAC_PLUS_AUTHEN_LOGIN,
        1,  # privilege
        TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
        TAC_PLUS_AUTHEN_SVC.TAC_PLUS_AUTHEN_SVC_LOGIN,
        len(user_b),
        len(port_b),
        len(rem_b),
        len(data_b),
    )
    return head + user_b + port_b + rem_b + data_b


def _seed_state(server) -> tuple[str, str, int]:
    """Initialize test environment with test user and device configuration.

    Creates a test user, device group, and loopback device for authentication testing.

    Args:
        server: Test server instance

    Returns:
        tuple: (username, password, port) for testing
    """
    """Create user and device group + loopback device. Returns (username, password, port)."""
    # Read paths from the generated config file (no mocks)
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(server.config_path)
    auth_db = cfg.get("auth", "local_auth_db", fallback=str(server.auth_db))
    devices_db = cfg.get("devices", "database", fallback=str(server.devices_db))

    # Seed required state
    username = "apitestuser"
    password = "ApiTestPass1!"
    usvc = LocalUserService(auth_db)
    try:
        usvc.create_user(username, password=password, privilege_level=1)
    except Exception:
        pass

    store = DeviceStore(devices_db)
    # Ensure group secret matches the test TACACS secret
    store.ensure_group(
        "dg-plain",
        description="TACACS auth test",
        metadata={"tacacs_secret": "testing123"},
    )
    store.ensure_device(name="loopback", network="127.0.0.1", group="dg-plain")
    return username, password, server.tacacs_port


def _try_auth_unencrypted(host: str, port: int, username: str, password: str) -> bool:
    """Attempt unencrypted TACACS+ PAP authentication.

    Tests the authentication flow when UNENCRYPTED_FLAG is set.

    Args:
        host: Server hostname or IP
        port: Server port
        username: Username for authentication
        password: Password for authentication

    Returns:
        bool: True if authentication was successful, False otherwise
    """
    """Attempt unencrypted PAP auth. Returns True if PASS."""
    session_id = int(time.time()) & 0xFFFFFFFF
    pkt = TacacsPacket(
        version=(TAC_PLUS_MAJOR_VER << 4) | 0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        session_id=session_id,
        length=0,
        body=_mk_auth_start_body(username, password),
    )
    full = pkt.pack("")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        s.sendall(full)
        hdr = _read_exact(s, TAC_PLUS_HEADER_SIZE)
        if len(hdr) != TAC_PLUS_HEADER_SIZE:
            return False
        header = TacacsPacket.unpack_header(hdr)
        body = _read_exact(s, header.length)
        if len(body) != header.length:
            return False
        return body[0] == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _try_auth_encrypted(
    host: str, port: int, username: str, password: str, secret: str = "testing123"
) -> bool:
    """Attempt encrypted TACACS+ PAP authentication.

    Tests the authentication flow with XOR encryption using shared secret.

    Args:
        host: Server hostname or IP
        port: Server port
        username: Username for authentication
        password: Password for authentication
        secret: Shared secret for encryption (default: "testing123")

    Returns:
        bool: True if authentication was successful, False otherwise
    """
    """Attempt encrypted PAP auth. Returns True if PASS."""
    session_id = int(time.time()) & 0xFFFFFFFF
    pkt = TacacsPacket(
        version=(TAC_PLUS_MAJOR_VER << 4) | 0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        flags=0,
        session_id=session_id,
        length=0,
        body=_mk_auth_start_body(username, password),
    )
    full = pkt.pack(secret)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        s.sendall(full)
        hdr = _read_exact(s, TAC_PLUS_HEADER_SIZE)
        if len(hdr) != TAC_PLUS_HEADER_SIZE:
            return False
        header = TacacsPacket.unpack_header(hdr)
        body = _read_exact(s, header.length)
        if len(body) != header.length:
            return False
        # Decrypt response body
        import hashlib as _hashlib

        def _md5_pad(
            sess_id: int, secret: str, version: int, seq_no: int, length: int
        ) -> bytes:
            pad = bytearray()
            sid = struct.pack("!L", sess_id)
            sec = secret.encode("utf-8")
            ver = bytes([(TAC_PLUS_MAJOR_VER << 4) | 0])
            seq = bytes([header.seq_no])
            while len(pad) < length:
                md5_in = sid + sec + ver + seq + (pad if pad else b"")
                pad.extend(_hashlib.md5(md5_in, usedforsecurity=False).digest())
            return bytes(pad[:length])

        pad = _md5_pad(
            header.session_id,
            secret,
            (TAC_PLUS_MAJOR_VER << 4) | 0,
            header.seq_no,
            len(body),
        )
        dec = bytes(a ^ b for a, b in zip(body, pad))
        return dec[0] == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def test_auth_pap_respects_encryption_required(server_factory):
    """Test TACACS+ PAP authentication respects encryption requirements.

    Verifies that:
    1. Authentication fails when encryption is required but not used
    2. Authentication succeeds with proper encryption
    3. Server enforces encryption policy correctly

    Test Steps:
    1. Start server with encryption required
    2. Attempt unencrypted authentication (should fail)
    3. Attempt encrypted authentication (should succeed)
    4. Verify authentication results match expectations

    Expected Result:
    - Unencrypted attempts should be rejected when encryption is required
    - Properly encrypted authentication should succeed
    - Server should log appropriate security events
    """
    # Two scenarios: encryption_required=false (allow unencrypted), true (reject unencrypted)
    for require_enc in (False, True):
        server = server_factory(
            config={
                "auth": {"backends": "local"},
                "encryption_required": str(require_enc).lower(),
            },
            enable_tacacs=True,
        )
        with server:
            username, password, port = _seed_state(server)
            host = "127.0.0.1"
            unenc_ok = _try_auth_unencrypted(host, port, username, password)
            enc_ok = _try_auth_encrypted(
                host, port, username, password, secret="testing123"
            )
            if require_enc:
                # Unencrypted must be rejected and a log message emitted
                assert not unenc_ok, (
                    "Unencrypted auth should be rejected when encryption_required=true"
                )
                logs = server.get_logs().lower()
                assert (
                    "unencrypted tacacs+ not permitted" in logs
                    or "rejecting unencrypted tacacs+ auth" in logs
                ), "Expected rejection message in logs"
                assert enc_ok, (
                    "Encrypted auth should succeed when encryption_required=true"
                )
            else:
                assert unenc_ok, (
                    "Unencrypted auth should succeed when encryption_required=false"
                )
                assert enc_ok, (
                    "Encrypted auth should also succeed when encryption_required=false"
                )
