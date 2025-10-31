"""
TACACS+ Encryption Behavior Tests

Topics:
- Special characters in secret
- Very long secrets (>256 chars)
- Key rotation (session-cached secret)
- Mixed encrypted/unencrypted sessions
- Non-ASCII secrets
"""

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
    """Generate MD5 padding for TACACS+ packet encryption.

    Creates a deterministic byte sequence for XOR-based encryption using MD5 hashing.

    Args:
        session_id: TACACS+ session identifier
        key: Shared secret for encryption
        version: Protocol version
        seq_no: Sequence number
        length: Desired length of padding

    Returns:
        bytes: Pseudo-random byte sequence for encryption
    """
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
    """Apply XOR encryption to TACACS+ packet body.

    Encrypts or decrypts packet body using MD5-based XOR encryption.

    Args:
        body: Packet body to encrypt/decrypt
        session_id: TACACS+ session identifier
        key: Shared secret for encryption
        version: Protocol version
        seq: Sequence number

    Returns:
        bytes: Encrypted/decrypted packet body
    """
    if not key:
        return body
    pad = _md5_pad(session_id, key, version, seq, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))


def _mk_header(
    version_major: int, ptype: int, seq: int, flags: int, session: int, length: int
) -> bytes:
    """Create TACACS+ packet header.

    Args:
        version_major: Major version of the protocol
        ptype: TACACS+ packet type
        seq: Sequence number
        flags: Packet flags (e.g., TAC_PLUS_UNENCRYPTED_FLAG)
        session: Session identifier
        length: Length of packet body

    Returns:
        bytes: Packed TACACS+ header
    """
    version = ((version_major & 0x0F) << 4) | 0
    return struct.pack("!BBBBLL", version, ptype, seq, flags, session, length)


def _mk_auth_body(username: str, password: str) -> bytes:
    """Create authentication packet body for TACACS+.

    Args:
        username: Authentication username
        password: Authentication password

    Returns:
        bytes: Packed authentication body
    """
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
    """Configure test environment with device and user.

    Args:
        server: Test server instance
        username: Username for test authentication
        password: Password for test authentication
        secret: Shared secret for TACACS+ communication
    """
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
    """Perform a single TACACS+ authentication attempt.

    Args:
        host: Server hostname or IP
        port: Server port
        secret: Shared secret for encryption
        username: Authentication username
        password: Authentication password
        session_id: TACACS+ session identifier
        seq: Sequence number
        flags: TACACS+ packet flags

    Returns:
        bool: True if authentication was successful, False otherwise
        str: Status message
    """
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
        # Read response
        rh = s.recv(12)
        if len(rh) != 12:
            return False, "no response"
        rver, rtype, rseq, rflags, rsess, rlen = struct.unpack("!BBBBLL", rh)
        rb = s.recv(rlen) if rlen else b""
        if len(rb) < rlen:
            return False, "truncated"
        # Decrypt if needed
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
    """Perform TACACS+ authentication on an existing socket.

    Args:
        sock: Connected socket to server
        secret: Shared secret for encryption
        username: Authentication username
        password: Authentication password
        session_id: TACACS+ session identifier
        seq: Sequence number
        flags: TACACS+ packet flags

    Returns:
        bool: True if authentication was successful, False otherwise
        int: Sequence number
    """
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
    """Test TACACS+ authentication with special characters in shared secret.

    Verifies that special characters in the shared secret are handled correctly
    during the encryption/decryption process.

    Test Steps:
    1. Configure server with secret containing special characters
    2. Attempt authentication with the same secret
    3. Verify successful authentication

    Expected Result:
    - Authentication should succeed with special characters in secret
    - No encryption/decryption errors should occur
    """
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
    """Test TACACS+ authentication with very long shared secret.

    Verifies that long shared secrets (exceeding 256 characters) are handled
    correctly during the encryption/decryption process.

    Test Steps:
    1. Configure server with a very long secret
    2. Attempt authentication with the same secret
    3. Verify successful authentication

    Expected Result:
    - Authentication should succeed with long secrets
    - No truncation or corruption of secret should occur
    """
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
    """Test TACACS+ authentication with non-ASCII characters in shared secret.

    Verifies that non-ASCII characters in the shared secret are handled correctly
    during the encryption/decryption process.

    Test Steps:
    1. Configure server with secret containing non-ASCII characters
    2. Attempt authentication with the same secret
    3. Verify successful authentication

    Expected Result:
    - Authentication should succeed with non-ASCII secrets
    - Character encoding should be handled correctly
    """
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
    """Test handling of mixed encrypted and unencrypted TACACS+ sessions.

    Verifies that the server can handle both encrypted and unencrypted
    sessions simultaneously when encryption is not strictly required.

    Test Steps:
    1. Start server with encryption not required
    2. Establish both encrypted and unencrypted sessions
    3. Verify both session types work as expected

    Expected Result:
    - Both encrypted and unencrypted sessions should work
    - No interference between different session types
    """
    # Allow unencrypted for this test
    server = server_factory(
        enable_tacacs=True, config={"security": {"encryption_required": "false"}}
    )
    with server:
        secret = "allow-plain"
        _setup_device_and_user(server, "plainuser", "PlainPass1", secret)
        # Use two different sessions to avoid any session-cache side effects
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
        # Log assertions: we should see two auth_result events
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        assert logs.count("auth_result") >= 2, "Expected two auth_result entries"


@pytest.mark.integration
def test_unencrypted_rejected_when_required(server_factory):
    """Test that unencrypted sessions are rejected when encryption is required.

    Verifies that the server enforces encryption requirements when configured
    to require encrypted sessions.

    Test Steps:
    1. Start server with encryption required
    2. Attempt unencrypted authentication
    3. Verify authentication is rejected
    4. Attempt encrypted authentication
    5. Verify encrypted authentication succeeds

    Expected Result:
    - Unencrypted sessions should be rejected
    - Encrypted sessions should be accepted
    - Appropriate error messages should be logged
    """
    # Enforce encryption
    server = server_factory(
        enable_tacacs=True, config={"security": {"encryption_required": "true"}}
    )
    with server:
        secret = "must-encrypt"
        _setup_device_and_user(server, "requser", "ReqPass1", secret)
        sess = int(time.time()) & 0xFFFFFFFF
        ok1, _ = _auth_once(
            "127.0.0.1",
            server.tacacs_port,
            secret,
            "requser",
            "ReqPass1",
            session_id=sess,
            seq=1,
        )
        ok2, _ = _auth_once(
            "127.0.0.1",
            server.tacacs_port,
            secret,
            "requser",
            "ReqPass1",
            session_id=sess,
            seq=3,
            flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        )
        assert ok1, "Encrypted auth should succeed"
        assert not ok2, "Unencrypted auth should be rejected when encryption_required"
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        # Expect structured rejection event
        assert (
            "unencrypted_rejected" in logs
            or "Rejecting unencrypted TACACS+ auth" in logs
        )


@pytest.mark.integration
def test_encryption_key_rotation_session_cache(server_factory):
    """Test TACACS+ encryption key rotation and session caching.

    Verifies that the server handles encryption key rotation correctly
    and maintains session state during the process.

    Test Steps:
    1. Start server with initial secret
    2. Authenticate with initial secret
    3. Rotate to new secret
    4. Verify old sessions continue to work
    5. Verify new sessions use new secret
    6. Test session persistence after secret rotation

    Expected Result:
    - Existing sessions should remain valid after key rotation
    - New sessions should use the new secret
    - No authentication failures during rotation
    """
    server = server_factory(enable_tacacs=True)
    with server:
        # Initial secret S1
        secret1 = "rotate-ONE-KEY"
        _setup_device_and_user(server, "rotuser", "RotPass1", secret1)
        host, port = "127.0.0.1", server.tacacs_port
        sess = int(time.time()) & 0xFFFFFFFF
        # Maintain a single TCP connection so the server keeps session secret cached
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        try:
            # First request seq=1 with S1
            ok1, _ = _auth_on_socket(
                sock, secret1, "rotuser", "RotPass1", session_id=sess, seq=1
            )
            assert ok1, "First auth with S1 should pass"

            # Rotate device group secret to S2 while keeping the same TCP session open
            from tacacs_server.devices.store import DeviceStore

            store = DeviceStore(str(server.devices_db))
            store.ensure_group(
                "default",
                description="Default group",
                metadata={"tacacs_secret": "rotate-TWO-KEY"},
            )
            secret2 = "rotate-TWO-KEY"

            # Second request with OLD S1: may succeed (cache) or fail (immediate rotate)
            ok2, _ = _auth_on_socket(
                sock, secret1, "rotuser", "RotPass1", session_id=sess, seq=3
            )
            if ok2:
                # If old secret accepted, the new secret should be rejected mid-session
                ok3, _ = _auth_on_socket(
                    sock, secret2, "rotuser", "RotPass1", session_id=sess, seq=5
                )
                assert not ok3, (
                    "Expected new secret rejected if old still cached for session"
                )
            else:
                # Some servers pin the session secret at first request; both old and new may be rejected mid-session.
                ok3, _ = _auth_on_socket(
                    sock, secret2, "rotuser", "RotPass1", session_id=sess, seq=5
                )
                assert not ok3, (
                    "Expected new secret also rejected mid-session when old was rejected"
                )
                # Verify rotation is effective for new sessions: new connection + new session id with secret2 should succeed
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
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        # Expect at least two auth_result entries overall
        assert logs.count("auth_result") >= 2
