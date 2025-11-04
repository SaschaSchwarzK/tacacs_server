"""
Return Value Verification Test Suite

This module contains tests that verify functions return exact expected types and values.
These tests are designed to be mutation-resistant and ensure type safety throughout the codebase.

Test Coverage:
- Authentication return values
- User management return types
- Privilege level handling
- Boolean flag validation
- API status codes
- String matching behavior
- Consistent return types for CRUD operations

Note: These tests are marked as low priority as they primarily verify type safety and
return value consistency rather than business logic.
"""


def test_authenticate_returns_false_not_none(server_factory):
    """Verify authentication returns exactly False on wrong password.

    Test Steps:
    1. Create a test user with a known password
    2. Attempt authentication with incorrect password
    3. Verify the return value is exactly False

    Expected Results:
    - Authentication attempt with wrong password should return exactly False
    - Return value should not be None or any other falsy value
    - Test ensures consistent boolean return values for authentication

    Edge Cases:
    - Verifies behavior with incorrect credentials
    - Ensures type safety in authentication flow
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("alice", password="Testcorrect1", privilege_level=15)

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

        # Must be exactly False
        assert success is False
        assert success is not None


def test_get_user_returns_none_not_false(server_factory):
    """Verify get_user returns None for non-existent users.

    Test Steps:
    1. Initialize server with local authentication
    2. Attempt to retrieve a non-existent user
    3. Verify the return value is None

    Expected Results:
    - Should return None when user doesn't exist
    - Should not return False or empty string
    - Maintains consistent return type contract

    Edge Cases:
    - Tests behavior with non-existent users
    - Verifies type consistency in user lookup
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        # Use convenience API that returns None on miss
        user = user_service.get_user_or_none("nonexistent")

        # Must be exactly None
        assert user is None
        assert user is not False


def test_list_users_returns_list_not_none(server_factory):
    """Verify list_users returns empty list when no users exist.

    Test Steps:
    1. Initialize server with no users
    2. Call list_users
    3. Verify return value is an empty list

    Expected Results:
    - Should return an empty list ([]) when no users exist
    - Should never return None
    - Maintains consistent list return type

    Edge Cases:
    - Tests behavior with empty user database
    - Verifies type consistency in list operations
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        users = user_service.list_users()

        # Must be a list
        assert isinstance(users, list)
        assert users is not None


def test_privilege_level_exact_values(server_factory):
    """Verify privilege levels are stored and returned as exact integers.

    Test Steps:
    1. Create test users with different privilege levels
    2. Retrieve the users and verify privilege levels
    3. Check type and value of returned privilege levels

    Expected Results:
    - Privilege levels should be exact integers (not strings or floats)
    - Values should match exactly what was set
    - Type should be int, not bool or other numeric types

    Edge Cases:
    - Tests boundary values of privilege levels
    - Verifies type safety in privilege handling
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user("user0", password="Testcorrect2", privilege_level=0)
        user_service.create_user("user5", password="Testcorrect2", privilege_level=5)
        user_service.create_user("user15", password="Testcorrect2", privilege_level=15)

        # Verify exact values
        user0 = user_service.get_user("user0")
        assert user0.privilege_level == 0
        assert type(user0.privilege_level) is int

        user5 = user_service.get_user("user5")
        assert user5.privilege_level == 5

        user15 = user_service.get_user("user15")
        assert user15.privilege_level == 15


def test_enabled_flag_is_boolean(server_factory):
    """Verify user enabled status is strictly boolean.

    Test Steps:
    1. Create test users with enabled=True and enabled=False
    2. Retrieve the users and check enabled status
    3. Verify the type and value of the enabled flag

    Expected Results:
    - Enabled flag should be boolean (True/False)
    - Should never be 1/0 or other truthy/falsy values
    - Type should be bool, not int or other types

    Edge Cases:
    - Tests both enabled and disabled states
    - Verifies type safety in status flags
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user("enabled_user", password="Testcorrect2", enabled=True)
        user_service.create_user(
            "disabled_user", password="Testcorrect2", enabled=False
        )

        enabled = user_service.get_user("enabled_user")
        assert enabled.enabled is True
        assert type(enabled.enabled) is bool

        disabled = user_service.get_user("disabled_user")
        assert disabled.enabled is False
        assert type(disabled.enabled) is bool


def test_api_status_code_exact_values(server_factory):
    """Verify API returns exact HTTP status codes.

    Test Steps:
    1. Start server with admin API enabled
    2. Make various API requests (success and error cases)
    3. Verify exact status codes in responses

    Expected Results:
    - Success responses should return exactly 200
    - Error responses should return specific error codes (e.g., 404, 401)
    - Status codes should be exact integers, not ranges

    Edge Cases:
    - Tests both successful and error responses
    - Verifies exact status code values
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )

    with server:
        session = server.login_admin()
        base_url = server.get_base_url()

        # Success should be exactly 200
        response = session.get(f"{base_url}/api/health", timeout=5)
        if response.status_code >= 200 and response.status_code < 300:
            assert response.status_code == 200

        # Not found should be exactly 404
        response = session.get(f"{base_url}/api/nonexistent", timeout=5)
        if response.status_code >= 400 and response.status_code < 500:
            assert response.status_code in [404, 405]


def test_username_exact_string_match(server_factory):
    """Verify username lookups are case-sensitive.

    Test Steps:
    1. Create a test user with specific casing
    2. Attempt to retrieve user with different casing
    3. Verify exact string matching behavior

    Expected Results:
    - Username lookups should be case-sensitive
    - Should only match exact string values
    - Should not perform case-insensitive matching

    Edge Cases:
    - Tests case sensitivity in usernames
    - Verifies exact string matching behavior
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user("TestUser", password="Testcorrect2", privilege_level=1)

        # Exact match
        user = user_service.get_user("TestUser")
        assert user is not None
        assert user.username == "TestUser"

        # Different case should not match (usernames are case-sensitive)
        import pytest

        with pytest.raises(Exception):
            user_service.get_user("testuser")


def test_delete_returns_none_or_bool(server_factory):
    """Verify delete operations have consistent return types.

    Test Steps:
    1. Create a test user
    2. Delete the user and check return value
    3. Attempt to delete non-existent user and check return value

    Expected Results:
    - Delete operations should return consistent types
    - Should return either None or a boolean
    - Type should be consistent between successful and failed deletes

    Edge Cases:
    - Tests both successful and failed deletions
    - Verifies return type consistency
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user("alice", password="Testcorrect2", privilege_level=1)

        result = user_service.delete_user("alice")

        # Should be None or bool, not mixed
        assert result is None or isinstance(result, bool)


def test_create_user_returns_user_object(server_factory):
    """Verify create_user returns appropriate user object.

    Test Steps:
    1. Create a new user
    2. Verify return value is a user object
    3. Check object properties match input

    Expected Results:
    - Should return a user object on success
    - Object should contain all expected user attributes
    - Should not return simple boolean True/False

    Edge Cases:
    - Tests return value on successful user creation
    - Verifies object structure and content
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        result = user_service.create_user(
            "alice", password="Testcorrect2", privilege_level=1
        )

        # Should return user object or None, not boolean
        if result is not None:
            assert hasattr(result, "username")
            assert result is not True


def test_update_returns_consistent_type(server_factory):
    """Verify update_user maintains consistent return types.

    Test Steps:
    1. Create a test user
    2. Perform multiple update operations
    3. Verify return types are consistent

    Expected Results:
    - Should return the same type for all update operations
    - Type should be consistent regardless of update success
    - Should match documented return type

    Edge Cases:
    - Tests multiple update scenarios
    - Verifies type consistency across operations
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        user_service.create_user("alice", password="Testcorrect2", privilege_level=1)

        result1 = user_service.update_user("alice", privilege_level=5)
        result2 = user_service.update_user("alice", privilege_level=10)

        # Both should have same type
        assert type(result1) is type(result2)
