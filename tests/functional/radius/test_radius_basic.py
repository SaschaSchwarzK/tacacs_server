"""
RADIUS Server Tests

Tests RADIUS authentication with real server instances.
Each test creates its own isolated server with temporary resources.
"""

import hashlib
import socket
import struct


def make_request_authenticator() -> bytes:
    """Generate a random 16-byte Request Authenticator"""
    import os

    return os.urandom(16)


def radius_authenticate(
    host: str,
    port: int,
    secret: str,
    username: str,
    password: str,
) -> tuple[bool, str]:
    """
    Perform RADIUS Access-Request authentication.

    Returns:
        (success, message) tuple
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        # Build RADIUS packet
        code = 1  # Access-Request
        identifier = 1
        request_auth = make_request_authenticator()

        # Attributes
        attributes = b""

        # User-Name (Type 1)
        username_bytes = username.encode()
        attributes += struct.pack("!BB", 1, 2 + len(username_bytes)) + username_bytes

        # User-Password (Type 2) - encrypted with Request Authenticator
        password_bytes = password.encode()
        # Pad password to multiple of 16
        if len(password_bytes) % 16:
            password_bytes += b"\x00" * (16 - len(password_bytes) % 16)

        # XOR with MD5(secret + Request Authenticator)
        encrypted_pass = b""
        c = request_auth
        for i in range(0, len(password_bytes), 16):
            b_i = password_bytes[i : i + 16]
            hash_val = hashlib.md5(secret.encode() + c, usedforsecurity=False).digest()
            encrypted_chunk = bytes(a ^ b for a, b in zip(b_i, hash_val))
            encrypted_pass += encrypted_chunk
            c = encrypted_chunk

        attributes += struct.pack("!BB", 2, 2 + len(encrypted_pass)) + encrypted_pass

        # NAS-IP-Address (Type 4)
        nas_ip = socket.inet_aton("127.0.0.1")
        attributes += struct.pack("!BB", 4, 6) + nas_ip

        # Build packet
        length = 20 + len(attributes)
        packet = (
            struct.pack("!BBH", code, identifier, length) + request_auth + attributes
        )

        # Send request
        sock.sendto(packet, (host, port))

        # Receive response
        response, _ = sock.recvfrom(4096)

        if len(response) < 20:
            return False, "Invalid response"

        resp_code = response[0]

        if resp_code == 2:  # Access-Accept
            return True, "Access-Accept"
        elif resp_code == 3:  # Access-Reject
            return False, "Access-Reject"
        else:
            return False, f"Unknown response code: {resp_code}"

    except TimeoutError:
        return False, "Request timeout"
    except Exception as e:
        return False, f"Connection error: {e}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def test_radius_basic_auth_success(server_factory):
    """Test successful RADIUS authentication with local user"""
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
            "radius_share_backends": "true",
        },
        enable_tacacs=False,
        enable_radius=True,
    )

    # Create user and client BEFORE starting server so RADIUS loads clients at setup
    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.devices.store import DeviceStore

    user_service = LocalUserService(str(server.auth_db))
    user_service.create_user("radiususer", password="RadiusPass123", privilege_level=15)
    device_store = DeviceStore(str(server.devices_db))
    device_store.ensure_group(
        "default", description="Default group", metadata={"radius_secret": "radsecret"}
    )
    device_store.ensure_device(
        name="radius-client",
        network="127.0.0.1",
        group="default",
    )

    with server:
        # Perform RADIUS authentication
        success, message = radius_authenticate(
            host="127.0.0.1",
            port=server.radius_auth_port,
            secret="radsecret",
            username="radiususer",
            password="RadiusPass123",
        )

        # Check results
        assert success, f"RADIUS authentication should succeed: {message}"
        assert "Accept" in message

        # Verify logs
        logs = server.get_logs()
        assert "radiususer" in logs or "RADIUS" in logs


def test_radius_auth_failure(server_factory):
    """Test failed RADIUS authentication with wrong password"""
    server = server_factory(
        config={
            "auth_backends": "local",
            "radius_share_backends": "true",
        },
        enable_radius=True,
    )

    # Prepare before start
    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.devices.store import DeviceStore

    user_service = LocalUserService(str(server.auth_db))
    user_service.create_user("radiususer", password="CorrectPass1", privilege_level=15)
    device_store = DeviceStore(str(server.devices_db))
    device_store.ensure_group(
        "default", description="Default group", metadata={"radius_secret": "radsecret"}
    )
    device_store.ensure_device(
        name="radius-client",
        network="127.0.0.1",
        group="default",
    )

    with server:
        # Try with wrong password
        success, message = radius_authenticate(
            host="127.0.0.1",
            port=server.radius_auth_port,
            secret="radsecret",
            username="radiususer",
            password="WrongPass1",
        )

        # Check results
        assert not success, "Authentication should fail with wrong password"
        assert "Reject" in message

        # Verify logs
        logs = server.get_logs()
        assert "radiususer" in logs or "RADIUS" in logs


def test_radius_with_tacacs_shared_backend(server_factory):
    """Test RADIUS with shared TACACS+ authentication backend"""
    server = server_factory(
        config={
            "auth_backends": "local",
            "radius_share_backends": "true",
            "radius_share_accounting": "true",
        },
        enable_tacacs=True,
        enable_radius=True,
    )

    # Prepare before start
    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.devices.store import DeviceStore

    user_service = LocalUserService(str(server.auth_db))
    user_service.create_user("shareduser", password="SharedPass1", privilege_level=15)
    device_store = DeviceStore(str(server.devices_db))
    device_store.ensure_group(
        "default",
        description="Default group",
        metadata={"radius_secret": "sharedsecret"},
    )
    device_store.ensure_device(
        name="shared-device",
        network="127.0.0.1",
        group="default",
    )

    with server:
        # Test RADIUS authentication
        success, message = radius_authenticate(
            host="127.0.0.1",
            port=server.radius_auth_port,
            secret="sharedsecret",
            username="shareduser",
            password="SharedPass1",
        )

        assert success, f"RADIUS authentication should succeed: {message}"

        # Verify logs show RADIUS activity
        logs = server.get_logs()
        assert "RADIUS" in logs or "shareduser" in logs


def test_radius_multiple_clients(server_factory):
    """Test RADIUS with multiple client devices"""
    server = server_factory(
        config={
            "auth_backends": "local",
            "radius_share_backends": "true",
        },
        enable_radius=True,
    )

    # Prepare before start
    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.devices.store import DeviceStore

    user_service = LocalUserService(str(server.auth_db))
    user_service.create_user("user1", password="Passw0rd1", privilege_level=15)
    user_service.create_user("user2", password="Passw0rd2", privilege_level=15)
    device_store = DeviceStore(str(server.devices_db))
    device_store.ensure_group(
        "default", description="Default group", metadata={"radius_secret": "secret1"}
    )
    device_store.ensure_device(
        name="client1",
        network="127.0.0.1",
        group="default",
    )

    with server:
        # Test authentication from client1
        success, _ = radius_authenticate(
            "127.0.0.1", server.radius_auth_port, "secret1", "user1", "Passw0rd1"
        )
        assert success, "User1 authentication should succeed"

        success, _ = radius_authenticate(
            "127.0.0.1", server.radius_auth_port, "secret1", "user2", "Passw0rd2"
        )
        assert success, "User2 authentication should succeed"

        # Verify logs
        logs = server.get_logs()
        assert "user1" in logs or "user2" in logs or "RADIUS" in logs


def test_radius_server_logs_collected(server_factory):
    """Test that RADIUS server logs are properly collected"""
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
        },
        enable_radius=True,
    )

    with server:
        # Create user and client
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("testuser", password="TestPass123", privilege_level=15)

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group(
            "default",
            description="Default group",
            metadata={"radius_secret": "testsecret"},
        )
        device_store.ensure_device(
            name="test-client",
            network="127.0.0.1",
            group="default",
        )

        import time

        time.sleep(0.5)

        # Perform authentication attempts
        radius_authenticate(
            "127.0.0.1",
            server.radius_auth_port,
            "testsecret",
            "testuser",
            "TestPass123",
        )
        radius_authenticate(
            "127.0.0.1", server.radius_auth_port, "testsecret", "testuser", "wrongpass"
        )

    # Get logs after server stops
    logs = server.get_logs()

    # Verify log content
    assert logs, "Logs should not be empty"
    assert len(logs) > 100, "Logs should contain substantial content"
    # RADIUS logs should mention the protocol or user
    assert "RADIUS" in logs or "testuser" in logs or "radius" in logs.lower()


def test_radius_disabled_by_config(server_factory):
    """Test that RADIUS is properly disabled when not enabled in config"""
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
        enable_radius=False,  # Explicitly disabled
    )

    with server:
        # RADIUS ports should not be set
        assert server.radius_auth_port is None
        assert server.radius_acct_port is None

        # Verify logs don't mention RADIUS startup
        logs = server.get_logs()
        # Should not see RADIUS server starting
        assert "RADIUS server configured" not in logs or "RADIUS" not in logs
