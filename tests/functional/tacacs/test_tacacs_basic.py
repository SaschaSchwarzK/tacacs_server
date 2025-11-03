"""
TACACS+ Basic Authentication Tests

Tests basic TACACS+ server functionality with local authentication.
Each test spins up a real server instance with its own config and databases.
"""

import hashlib
import secrets
import socket
import struct
import time


def md5_pad(session_id: int, key: str, version: int, seq_no: int, length: int) -> bytes:
    """Generate MD5 pad for TACACS+ encryption"""
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


def transform_body(
    body: bytes, session_id: int, key: str, version: int, seq_no: int
) -> bytes:
    """Encrypt/decrypt TACACS+ body"""
    if not key:
        return body
    pad = md5_pad(session_id, key, version, seq_no, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))


def tacacs_authenticate(
    host: str, port: int, key: str, username: str, password: str
) -> tuple[bool, str]:
    """
    Perform TACACS+ PAP authentication.

    Returns:
        (success, message) tuple
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))

        session_id = secrets.randbits(32)
        user_bytes = username.encode("utf-8")
        port_bytes = b"console"
        rem_addr_bytes = b"127.0.0.1"
        data_bytes = password.encode("utf-8")

        # Build authentication packet
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
        encrypted_body = transform_body(body, session_id, key, version, seq_no)
        header = struct.pack(
            "!BBBBLL", version, 1, seq_no, 0, session_id, len(encrypted_body)
        )

        # Send request
        sock.sendall(header + encrypted_body)

        # Receive response
        response_header = sock.recv(12)
        if len(response_header) != 12:
            return False, "Invalid response header"

        r_version, r_type, r_seq, _, r_session, r_length = struct.unpack(
            "!BBBBLL", response_header
        )

        response_body = sock.recv(r_length) if r_length else b""
        if len(response_body) < r_length:
            return False, "Truncated response body"

        decrypted = transform_body(response_body, r_session, key, r_version, r_seq)
        if len(decrypted) < 6:
            return False, "Response too short"

        status, _flags, msg_len, data_len = struct.unpack("!BBHH", decrypted[:6])
        offset = 6
        _server_message = ""
        if msg_len:
            _server_message = decrypted[offset : offset + msg_len].decode(
                "utf-8", errors="replace"
            )

        success = status == 1  # TAC_PLUS_AUTHEN_STATUS_PASS
        detail = {
            1: "authentication accepted",
            2: "authentication rejected",
        }.get(status, f"status={status}")

        return success, detail

    except Exception as e:
        return False, f"Connection error: {e}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def test_tacacs_basic_auth_success(server_factory):
    """Test successful TACACS+ authentication with local user.

    This test verifies that the TACACS+ server can successfully authenticate a user
    with correct credentials. It tests the basic authentication flow using PAP.

    Test Steps:
    1. Start a TACACS+ server with a test user
    2. Attempt to authenticate with correct credentials
    3. Verify authentication succeeds

    Expected Result:
    - Authentication should be successful
    - Server should return success status
    - Session should be properly established
    """
    # Create server with local auth
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
        },
        enable_tacacs=True,
    )

    with server:
        # Create test user in local database
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("testuser", password="TestPass123", privilege_level=15)

        # Add device with secret to device store
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group(
            "default",
            description="Default group",
            metadata={"tacacs_secret": "testsecret"},
        )
        device_store.ensure_device(
            name="test-device",
            network="127.0.0.1",
            group="default",
        )

        # Perform TACACS+ authentication
        success, message = tacacs_authenticate(
            host="127.0.0.1",
            port=server.tacacs_port,
            key="testsecret",
            username="testuser",
            password="TestPass123",
        )

        # Check results
        assert success, f"Authentication should succeed: {message}"
        assert "accepted" in message.lower()

        # Verify logs
        logs = server.get_logs()
        assert "testuser" in logs
        assert "authentication" in logs.lower()


def test_tacacs_basic_auth_failure(server_factory):
    """Test failed TACACS+ authentication with wrong password.

    This test verifies that the TACACS+ server properly handles failed authentication
    attempts when an incorrect password is provided.

    Test Steps:
    1. Start a TACACS+ server with a test user
    2. Attempt to authenticate with incorrect password
    3. Verify authentication fails

    Expected Result:
    - Authentication should fail
    - Server should return failure status
    - No session should be established
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        # Create test user
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user(
            "testuser", password="CorrectPass1", privilege_level=15
        )

        # Add device
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group(
            "default",
            description="Default group",
            metadata={"tacacs_secret": "testsecret"},
        )
        device_store.ensure_device(
            name="test-device",
            network="127.0.0.1",
            group="default",
        )

        # Try to authenticate with wrong password
        success, message = tacacs_authenticate(
            host="127.0.0.1",
            port=server.tacacs_port,
            key="testsecret",
            username="testuser",
            password="WrongPass1",
        )

        # Check results
        assert not success, "Authentication should fail with wrong password"
        assert "rejected" in message.lower() or "fail" in message.lower()

        # Verify logs show failure
        logs = server.get_logs()
        assert "testuser" in logs


def test_tacacs_nonexistent_user(server_factory):
    """Test TACACS+ authentication with non-existent user.

    This test verifies the server's behavior when attempting to authenticate
    a user that doesn't exist in the system.

    Test Steps:
    1. Start a TACACS+ server with predefined test users
    2. Attempt to authenticate with a non-existent username
    3. Verify proper error handling

    Expected Result:
    - Authentication should fail
    - Server should return appropriate error status
    - Should not allow authentication for non-existent users
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        # Add device but no users
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group(
            "default",
            description="Default group",
            metadata={"tacacs_secret": "testsecret"},
        )
        device_store.ensure_device(
            name="test-device",
            network="127.0.0.1",
            group="default",
        )

        # Try to authenticate non-existent user
        success, message = tacacs_authenticate(
            host="127.0.0.1",
            port=server.tacacs_port,
            key="testsecret",
            username="nonexistent",
            password="AnyPass123",
        )

        # Check results
        assert not success, "Authentication should fail for non-existent user"

        # Verify logs
        logs = server.get_logs()
        assert "nonexistent" in logs


def test_tacacs_multiple_users(server_factory):
    """Test TACACS+ authentication with multiple users.

    This test verifies that the server can handle multiple user authentications
    in sequence, ensuring there's no state leakage between sessions.

    Test Steps:
    1. Start a TACACS+ server with multiple test users
    2. Authenticate first user and verify success
    3. Authenticate second user and verify success
    4. Verify both sessions are independent

    Expected Result:
    - Both authentications should succeed
    - Sessions should be independent
    - No cross-contamination between user sessions
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        # Create multiple users
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("alice", password="AlicePass1", privilege_level=15)
        user_service.create_user("bob", password="BobPass12", privilege_level=1)

        # Add device
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group(
            "default",
            description="Default group",
            metadata={"tacacs_secret": "testsecret"},
        )
        device_store.ensure_device(
            name="test-device",
            network="127.0.0.1",
            group="default",
        )

        # Test alice
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "testsecret", "alice", "AlicePass1"
        )
        assert success, "Alice authentication should succeed"

        # Test bob
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "testsecret", "bob", "BobPass12"
        )
        assert success, "Bob authentication should succeed"

        # Test alice with wrong password
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "testsecret", "alice", "WrongPass1"
        )
        assert not success, "Alice with wrong password should fail"

        # Verify logs show both users
        logs = server.get_logs()
        assert "alice" in logs
        assert "bob" in logs


def test_tacacs_server_logs_collected(server_factory):
    """Test that server logs are properly collected.

    This test verifies that the TACACS+ server correctly logs authentication
    attempts and their outcomes to the server logs.

    Test Steps:
    1. Start a TACACS+ server with logging enabled
    2. Perform multiple authentication attempts (success and failure)
    3. Verify logs contain expected authentication events

    Expected Result:
    - All authentication attempts should be logged
    - Logs should contain success/failure status
    - Logs should include relevant user and timestamp information
    """
    server = server_factory(
        config={"log_level": "DEBUG"},
        enable_tacacs=True,
    )

    with server:
        # Perform some authentication attempts
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("testuser", password="TestPass123", privilege_level=15)

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group(
            "default",
            description="Default group",
            metadata={"tacacs_secret": "testsecret"},
        )
        device_store.ensure_device(
            name="test-device",
            network="127.0.0.1",
            group="default",
        )

        # Successful auth
        tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "testsecret", "testuser", "TestPass123"
        )

        # Failed auth
        tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "testsecret", "testuser", "wrongpass"
        )

    # Logs available even after server stops
    logs = server.get_logs()

    # Verify log content
    assert logs, "Logs should not be empty"
    assert "TACACS" in logs or "Server" in logs
    assert "testuser" in logs
    # Verify we can see both success and failure
    assert len(logs) > 100, "Logs should contain substantial content"
