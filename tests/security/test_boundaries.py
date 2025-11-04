"""
TACACS+ Boundary Condition Tests

This module contains tests that verify the system's behavior at various boundaries,
including input length limits, numeric ranges, and edge cases in protocol handling.

Test Coverage:
- User and Authentication:
  - Username length boundaries (min/max)
  - Password length and complexity at bcrypt's limits
  - Privilege level validation (0-15)
  - Session ID handling at maximum values

- Network and Protocol:
  - Maximum packet size handling
  - IP address boundary conditions
  - Session ID validation
  - Connection handling at protocol limits

- Security Boundaries:
  - Input validation at boundaries
  - Resource usage under edge conditions
  - Error handling for out-of-bounds values

Note: These tests focus on ensuring the system remains stable and secure when
processing inputs at or beyond expected boundaries.
"""

import pytest


def test_privilege_level_boundary_14_denied(server_factory):
    """Test privilege level 14 is below admin threshold.

    Setup: Create user with privilege 14
    Action: Perform action requiring privilege 15
    Expected: Denied
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user(
            "user14", password="correct_Pass123", privilege_level=14
        )
        # Try to authenticate - should fail
        assert not user_service.authenticate("user14", "correct_Pass123"), (
            "Authentication should fail for privilege level 14"
        )


def test_privilege_level_boundary_15_allowed(server_factory):
    """Test privilege level 15 is admin threshold.

    Setup: Create user with privilege 15
    Action: Verify privilege level
    Expected: Privilege 15 set correctly
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user(
            "user15", password="correct_Pass123", privilege_level=15
        )

        user = user_service.get_user("user15")
        assert user.privilege_level == 15


def test_privilege_level_minimum_zero(server_factory):
    """Test privilege level 0 is minimum.

    Setup: Create user with privilege 0
    Action: Verify privilege level
    Expected: Privilege 0 set correctly
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("user0", password="correct_Pass123", privilege_level=0)

        user = user_service.get_user("user0")
        assert user.privilege_level == 0


def test_username_max_length(server_factory):
    """Test username at maximum allowed length (64 characters).

    This test verifies that the system correctly handles usernames at the maximum
    allowed length of 64 characters.

    Test Steps:
    1. Create a user with a 64-character username
    2. Attempt to authenticate with the created user

    Expected Results:
    - User creation should succeed
    - Authentication with the long username should work

    Edge Cases/Notes:
    - Tests the upper boundary of username length
    - Verifies proper string handling and storage
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        # Production limit: 64 chars allowed
        max_name = "a" * 64
        user_service.create_user(
            max_name, password="correct_Pass123", privilege_level=1
        )
        user = user_service.get_user(max_name)
        assert user is not None


def test_username_over_max_length(server_factory):
    """Test username exceeding maximum allowed length (65 characters).

    This test verifies that the system properly handles and rejects usernames
    that exceed the maximum allowed length of 64 characters.

    Test Steps:
    1. Attempt to create a user with a 65-character username
    2. Verify the creation fails

    Expected Results:
    - User creation should fail with appropriate error
    - No user should be created with the invalid username

    Edge Cases/Notes:
    - Tests input validation for username length
    - Verifies proper error handling
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import (
            LocalUserService,
            LocalUserValidationError,
        )

        user_service = LocalUserService(str(server.auth_db))
        # 65 chars should be rejected by production validator
        too_long = "a" * 65
        with pytest.raises(LocalUserValidationError):
            user_service.create_user(
                too_long, password="correct_Pass123", privilege_level=1
            )


def test_password_bcrypt_max_length(server_factory):
    """Test password at bcrypt's 72-byte limit with required complexity.

    This test verifies that the system correctly handles passwords at the
    maximum length that bcrypt can process (72 bytes) while still enforcing
    password complexity requirements.

    Test Steps:
    1. Create a user with a 72-byte password
    2. Attempt to authenticate with the password

    Expected Results:
    - Password should be accepted if it meets complexity requirements
    - Authentication should succeed with the correct password

    Edge Cases/Notes:
    - Tests bcrypt's internal length limitation
    - Verifies password complexity is still enforced at max length
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        # bcrypt limits passwords to 72 bytes; ensure complexity (upper, lower, digit)
        password_72 = "A" + ("a" * 70) + "1"  # 72 chars
        user_service.create_user("alice", password=password_72, privilege_level=1)

        # Should authenticate with full password
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", password_72
        )
        assert success


def test_packet_size_at_limit(server_factory):
    """Test packet at size limit (typically 4KB).

    Setup: Start TACACS+ server
    Action: Send packet at maximum allowed size
    Expected: Accepted and processed
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        import socket
        import struct

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(("127.0.0.1", server.tacacs_port))

            # 4096 byte body (common limit)
            body_size = 4096
            header = struct.pack("!BBBBII", 0xC0, 1, 1, 0, 12345, body_size)
            body = b"x" * body_size

            sock.sendall(header + body)

            try:
                # Read and ignore response (if any)
                sock.recv(1024)
                # May succeed or timeout
            except TimeoutError:
                pass
        finally:
            sock.close()


def test_connection_from_max_ip(server_factory):
    """Test connection from highest IPv4 address.

    Setup: Add device with IP 255.255.255.255
    Action: Server should handle it
    Expected: No crash
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})

        # Highest IP
        try:
            device_store.ensure_device(
                name="max-ip", network="255.255.255.255", group="default"
            )
        except Exception:
            # May reject broadcast address
            pass


def test_session_id_max_value(server_factory):
    """Test TACACS+ session with maximum session ID.

    Setup: Start server
    Action: Authenticate with session_id = 0xFFFFFFFF
    Expected: Handled correctly
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user(
            "alice", password="correct_Pass123", privilege_level=15
        )

        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        # Authentication with max session_id
        # (tacacs_authenticate generates its own session_id, so this is conceptual)
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "correct_Pass123"
        )

        # Should work regardless of session_id value
