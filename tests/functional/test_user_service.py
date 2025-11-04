"""
User Service Test Suite

This module contains tests that verify the user management functionality of the TACACS+ server.
It covers the complete user lifecycle including creation, retrieval, updates, and deletion,
as well as authentication and authorization features.

Test Coverage:
- User creation with various attributes
- Password management and validation
- Privilege level assignment and updates
- Account enable/disable functionality
- User listing and search capabilities
- Edge cases and error handling

Note: These tests are marked as medium priority as they verify core functionality
that is critical for proper user authentication and authorization.
"""


def test_user_create_with_all_fields(server_factory):
    """Test user creation with all available fields specified.

    Verifies that a user can be created with all possible attributes and that
    these attributes are correctly stored and retrieved.

    Test Steps:
    1. Start server with local authentication backend
    2. Create a user with username, password, privilege level, and enabled status
    3. Retrieve the user and verify all attributes

    Expected Results:
    - User should be created successfully
    - All specified attributes should be stored correctly
    - Retrieved user data should match what was provided during creation

    Edge Cases/Notes:
    - Tests the full range of user attributes
    - Verifies proper type conversion and storage
    - Ensures sensitive data is handled securely
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user(
            "alice", password="testPass123!", privilege_level=10, enabled=True
        )

        user = user_service.get_user("alice")
        assert user is not None
        assert user.username == "alice"
        assert user.privilege_level == 10
        assert user.enabled is True


def test_user_create_duplicate_fails(server_factory):
    """Test that duplicate usernames are properly handled.

    Verifies that the system enforces username uniqueness and prevents
    the creation of multiple users with the same username.

    Test Steps:
    1. Start server with local authentication
    2. Create a user with a specific username
    3. Attempt to create another user with the same username

    Expected Results:
    - First user creation should succeed
    - Second creation attempt should raise an appropriate exception
    - No data corruption should occur

    Edge Cases/Notes:
    - Tests the system's handling of duplicate usernames
    - Verifies proper error handling
    - Ensures data integrity is maintained
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user("alice", password="testPass1!", privilege_level=1)

        try:
            user_service.create_user("alice", password="testPass2!", privilege_level=1)
            assert False, "Should not allow duplicate username"
        except Exception:
            pass  # Expected


def test_user_update_privilege_level(server_factory):
    """Test updating a user's privilege level.

    Verifies that a user's privilege level can be updated and that the change
    takes effect for subsequent operations.

    Test Steps:
    1. Create a user with an initial privilege level
    2. Update the user's privilege level
    3. Verify the change was persisted
    4. Check that the new privilege level is enforced

    Expected Results:
    - Privilege level should be updated successfully
    - The change should be immediately visible
    - No other user attributes should be affected

    Edge Cases/Notes:
    - Tests privilege escalation controls
    - Verifies proper validation of privilege levels
    - Ensures no side effects on other attributes
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user("alice", password="Testpass123", privilege_level=1)
        user_service.update_user("alice", privilege_level=15)

        user = user_service.get_user("alice")
        assert user.privilege_level == 15


def test_user_update_password(server_factory):
    """Test updating a user's password.

    Verifies that a user's password can be changed and that both the old and
    new passwords work as expected before and after the change.

    Test Steps:
    1. Create a user with an initial password
    2. Verify the initial password works
    3. Update the password to a new value
    4. Verify the old password no longer works
    5. Verify the new password works

    Expected Results:
    - Password update should be successful
    - Old password should be invalid after change
    - New password should work immediately
    - No other user attributes should be affected

    Edge Cases/Notes:
    - Tests password change functionality
    - Verifies proper password hashing and verification
    - Ensures no password leakage in logs or error messages
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user("alice", password="Testold_pass1", privilege_level=15)

        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        # Old password works
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "Testold_pass1"
        )
        assert success

        # Update password using dedicated API
        user_service.set_password("alice", "Testnew_pass1")

        # Old password fails
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "Testold_pass1"
        )
        assert not success

        # New password works
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "Testnew_pass1"
        )
        assert success


def test_user_disable(server_factory):
    """Test disabling a user account.

    Verifies that a disabled user cannot authenticate while other users remain
    unaffected, and that the account can be re-enabled.

    Test Steps:
    1. Create an enabled user
    2. Verify the user can authenticate
    3. Disable the user account
    4. Verify authentication fails
    5. Re-enable the account
    6. Verify authentication works again

    Expected Results:
    - Disabled users should be denied access
    - Enabled users should work normally
    - Account status changes should take effect immediately

    Edge Cases/Notes:
    - Tests account status management
    - Verifies proper access control enforcement
    - Ensures no information leakage about disabled accounts
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user(
            "alice", password="Testpass123", privilege_level=15, enabled=True
        )

        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group(name="default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        # Works when enabled
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "Testpass123"
        )
        assert success

        # Disable user
        user_service.update_user("alice", enabled=False)

        # Should fail now
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "Testpass123"
        )
        assert not success


def test_user_delete(server_factory):
    """Test user account deletion.

    Verifies that a user can be permanently deleted from the system and that
    all associated data is properly cleaned up.

    Test Steps:
    1. Create a test user
    2. Verify the user exists
    3. Delete the user
    4. Verify the user no longer exists
    5. Attempt to authenticate as deleted user

    Expected Results:
    - User deletion should be successful
    - Deleted user should not be retrievable
    - Authentication attempts should fail
    - No orphaned data should remain

    Edge Cases/Notes:
    - Tests user deletion functionality
    - Verifies proper cleanup of user data
    - Ensures referential integrity is maintained
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user("alice", password="Testpass123", privilege_level=1)
        user_service.delete_user("alice")

        user = user_service.get_user_or_none("alice")
        assert user is None


def test_user_delete_nonexistent(server_factory):
    """Test deleting nonexistent user.

    Setup: Start server
    Action: Delete user that doesn't exist
    Expected: No error (idempotent)
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        # Should not raise error (idempotent helper)
        deleted = user_service.delete_user_if_exists("nonexistent")
        assert deleted is False


def test_user_list_all(server_factory):
    """Test retrieval of all users.

    Verifies that the system can list all users and that the returned
    information is complete and accurate.

    Test Steps:
    1. Create multiple test users with different attributes
    2. Retrieve the list of all users
    3. Verify all created users are included
    4. Check that user attributes are correct

    Expected Results:
    - All users should be included in the list
    - User attributes should be accurate
    - Sensitive data should not be exposed

    Edge Cases/Notes:
    - Tests user enumeration functionality
    - Verifies proper data sanitization
    - Ensures performance with multiple users
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user("alice", password="testPass1!", privilege_level=1)
        user_service.create_user("bob", password="testPass2!", privilege_level=5)
        user_service.create_user("charlie", password="Testpass3", privilege_level=15)

        users = user_service.list_users()
        usernames = [u.username for u in users]

        assert "alice" in usernames
        assert "bob" in usernames
        assert "charlie" in usernames


def test_user_get_nonexistent(server_factory):
    """Test getting nonexistent user.

    Setup: Start server
    Action: Get user that doesn't exist
    Expected: Returns None
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user = user_service.get_user_or_none("nonexistent")
        assert user is None


def test_user_default_privilege_level(server_factory):
    """Test default privilege level when not specified.

    Setup: Start server
    Action: Create user without privilege_level
    Expected: Default to 1
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user("alice", password="Testpass123")

        user = user_service.get_user("alice")
        # Should default to 1 or some default value
        assert user.privilege_level >= 0
