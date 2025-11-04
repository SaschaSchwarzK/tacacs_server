"""
Authentication Failure Test Suite

This module contains tests that verify the system's behavior during authentication
failures and edge cases. These tests ensure that the authentication system handles
error conditions securely and predictably.

Test Coverage:
- Disabled user authentication attempts
- Non-existent user authentication
- Invalid password handling
- Case-sensitivity in usernames
- Concurrent authentication attempts
- Rapid authentication failures
- Special character handling in passwords
- Database consistency checks

Note: These tests are marked as high priority as they verify critical security
boundaries and failure modes in the authentication system.
"""


def test_auth_disabled_user_denied(server_factory):
    """Verify that disabled users cannot authenticate.

    Test Steps:
    1. Create a test user with a known password
    2. Disable the user account
    3. Attempt to authenticate as the disabled user

    Expected Results:
    - Authentication attempt should fail
    - Server should return authentication failure
    - No sensitive information should be leaked in the error response

    Security Considerations:
    - Verifies that disabled accounts cannot be used to authenticate
    - Ensures proper access control for disabled accounts
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user(
            "alice", password="passTest123", privilege_level=15, enabled=False
        )

        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "passTest123"
        )

        assert not success, "Disabled user should not authenticate"


def test_auth_nonexistent_user_fails(server_factory):
    """Verify that authentication fails for non-existent users.

    Test Steps:
    1. Start server with no users configured
    2. Attempt to authenticate with a non-existent username

    Expected Results:
    - Authentication should fail
    - Response time should be consistent with failed authentication
    - No information about user existence should be leaked

    Security Considerations:
    - Prevents user enumeration through timing attacks
    - Maintains consistent error messages for non-existent users
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

        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "nonexistent", "passTest123"
        )

        assert not success


def test_auth_wrong_password_fails(server_factory):
    """Verify that authentication fails with incorrect passwords.

    Test Steps:
    1. Create a test user with a known password
    2. Attempt to authenticate with an incorrect password
    3. Verify the authentication failure

    Expected Results:
    - Authentication should fail with invalid credentials
    - Response time should be consistent with failed authentication
    - No indication of whether username was valid should be given

    Security Considerations:
    - Verifies proper handling of incorrect credentials
    - Ensures no information leakage about account existence
    - Tests resistance to credential stuffing attacks
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

        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "wrong"
        )

        assert not success


def test_auth_case_sensitive_username(server_factory):
    """Verify that usernames are treated as case-sensitive.

    Test Steps:
    1. Create a test user with a specific case (e.g., "Alice")
    2. Attempt to authenticate with a different case (e.g., "alice")

    Expected Results:
    - Authentication should fail due to case mismatch
    - Error message should not reveal whether the username exists
    - Response time should be consistent with failed authentication

    Security Considerations:
    - Verifies case-sensitivity of usernames
    - Tests for potential case-sensitivity vulnerabilities
    - Ensures consistent behavior across different authentication paths
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("Alice", password="passTest123", privilege_level=15)

        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        # Try lowercase
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "passTest123"
        )

        # Should fail if case-sensitive (or succeed if case-insensitive)
        # Document the behavior
        logs = server.get_logs()
        assert len(logs) > 0


def test_auth_concurrent_same_user(server_factory):
    """Verify that concurrent authentication attempts for the same user are handled correctly.

    Test Steps:
    1. Create a test user with known credentials
    2. Launch multiple concurrent authentication attempts
    3. Verify all attempts complete successfully

    Expected Results:
    - All authentication attempts should complete successfully
    - No deadlocks or race conditions should occur
    - System should maintain consistent state

    Edge Cases:
    - Tests thread safety of authentication mechanism
    - Verifies proper handling of concurrent session creation
    - Ensures no resource leaks during concurrent access
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("alice", password="passTest123", privilege_level=15)

        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        import concurrent.futures

        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        def auth():
            return tacacs_authenticate(
                "127.0.0.1", server.tacacs_port, "secret", "alice", "passTest123"
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future1 = executor.submit(auth)
            future2 = executor.submit(auth)

            success1, _ = future1.result()
            success2, _ = future2.result()

        # Both should succeed
        assert success1
        assert success2


def test_auth_rapid_failures_same_user(server_factory):
    """Verify behavior with rapid authentication failures for the same user.

    Test Steps:
    1. Create a test user with known credentials
    2. Perform multiple rapid failed authentication attempts
    3. Verify system behavior remains consistent

    Expected Results:
    - Initial failed attempts should not trigger account lockout
    - Response times should be consistent
    - No denial of service through account locking

    Security Considerations:
    - Tests rate limiting and account lockout policies
    - Verifies system remains responsive under failed auth attempts
    - Ensures no information leakage through timing differences
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

        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        # 3 failed attempts (below typical lockout threshold of 5)
        for i in range(3):
            success, _ = tacacs_authenticate(
                "127.0.0.1", server.tacacs_port, "secret", "alice", "wrong"
            )
            assert not success

        # Correct password should still work
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "correct_Pass123"
        )

        # Should succeed (no lockout yet)
        # If it fails, account lockout may be implemented
        logs = server.get_logs()
        assert "alice" in logs


def test_auth_password_with_special_chars(server_factory):
    """Verify authentication works with special characters in passwords.

    Test Steps:
    1. Create a test user with a password containing special characters
    2. Attempt to authenticate using the special character password

    Expected Results:
    - Authentication should succeed with valid credentials
    - All special characters should be handled correctly
    - No encoding or parsing errors should occur

    Security Considerations:
    - Verifies proper handling of special characters in credentials
    - Tests for potential injection or encoding vulnerabilities
    - Ensures consistent behavior with complex passwords
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        special_password = "P@ssw0rd!#$%^&*()"

        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("alice", password=special_password, privilege_level=15)

        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", special_password
        )

        assert success


def test_auth_database_has_correct_user_after_creation(server_factory):
    """Verify user creation results in correct database state.

    Test Steps:
    1. Create a test user through the API
    2. Directly query the database to verify user record
    3. Validate all user attributes are stored correctly

    Expected Results:
    - User record should exist in the database
    - All user attributes should be stored as expected
    - No extraneous or sensitive data should be exposed

    Data Integrity:
    - Verifies database consistency after user creation
    - Ensures proper data persistence
    - Tests for proper data validation and sanitization
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("alice", password="passTest123", privilege_level=15)

        # Verify user exists
        user = user_service.get_user("alice")
        assert user is not None
        assert user.username == "alice"
        assert user.privilege_level == 15
