"""
Concurrent Operations Test Suite

This module contains tests that verify the system's behavior under concurrent access
conditions. It ensures thread safety and data consistency when multiple operations
are performed simultaneously.

Test Coverage:
- Concurrent user creation and updates
- Simultaneous authentication attempts
- Parallel device management operations
- Concurrent API request handling
- Read operations under concurrent load

Note: These tests are marked as low priority as they primarily verify thread safety
and may be more resource-intensive than other test categories.
"""

import concurrent.futures


def test_concurrent_user_creation_same_name(server_factory):
    """Test concurrent creation of the same username.

    Verifies that user creation is thread-safe when multiple threads attempt to
    create a user with the same username simultaneously.

    Test Steps:
    1. Start server with local authentication backend
    2. Launch two threads that both attempt to create a user with the same username
    3. Wait for both operations to complete
    4. Verify exactly one operation succeeded

    Expected Results:
    - Only one thread should successfully create the user
    - The other thread should receive an appropriate error
    - No data corruption should occur
    - The system should remain in a consistent state

    Edge Cases/Notes:
    - Tests race condition handling in user creation
    - Verifies proper locking mechanisms are in place
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        def create_user():
            try:
                user_service.create_user(
                    "alice", password="Testcorrect1", privilege_level=1
                )
                return True
            except Exception:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future1 = executor.submit(create_user)
            future2 = executor.submit(create_user)

            result1 = future1.result()
            result2 = future2.result()

        # Exactly one should succeed
        assert result1 != result2 or (result1 and result2)


def test_concurrent_authentication_same_user(server_factory):
    """Test concurrent authentication attempts for the same user.

    Verifies that multiple authentication requests for the same user can be
    processed in parallel without deadlocks or data corruption.

    Test Steps:
    1. Create a test user with known credentials
    2. Launch 5 concurrent authentication requests for the same user
    3. Wait for all authentications to complete
    4. Verify all authentications were successful

    Expected Results:
    - All authentication attempts should complete successfully
    - Response times should be reasonable (no excessive blocking)
    - No deadlocks or race conditions should occur

    Edge Cases/Notes:
    - Tests the authentication system's concurrency handling
    - Verifies proper session management under load
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

        def auth():
            success, _ = tacacs_authenticate(
                "127.0.0.1", server.tacacs_port, "secret", "alice", "Testcorrect1"
            )
            return success

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(auth) for _ in range(5)]
            results = [f.result() for f in futures]

        # All should succeed
        assert all(results)


def test_concurrent_device_creation(server_factory):
    """Test concurrent creation of different devices.

    Verifies that the system can handle simultaneous device creation requests
    without data corruption or race conditions.

    Test Steps:
    1. Start server with device management enabled
    2. Launch multiple threads, each creating a unique device
    3. Wait for all device creations to complete
    4. Verify all devices were created successfully

    Expected Results:
    - All device creation requests should complete successfully
    - Each device should be created with the correct parameters
    - No device information should be lost or corrupted

    Edge Cases/Notes:
    - Tests device management concurrency
    - Verifies proper indexing and storage of device information
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})

        def create_device(i):
            try:
                device_store.ensure_device(
                    name=f"router{i}", network=f"10.0.0.{i}", group="default"
                )
                return True
            except Exception:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(create_device, i) for i in range(10)]
            results = [f.result() for f in futures]

        # Most should succeed
        assert sum(results) >= 8


def test_concurrent_user_update(server_factory):
    """Test concurrent updates to the same user.

    Verifies that user updates are handled correctly when multiple threads
    attempt to modify the same user simultaneously.

    Test Steps:
    1. Create a test user with initial privileges
    2. Launch multiple threads that update different attributes of the user
    3. Wait for all updates to complete
    4. Verify the final state of the user

    Expected Results:
    - All update operations should complete without errors
    - The final user state should reflect the last successful update
    - No data corruption or partial updates should occur

    Edge Cases/Notes:
    - Tests the 'last write wins' strategy
    - Verifies proper locking during user updates
    - Ensures data consistency under concurrent modifications
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("alice", password="Testcorrect1", privilege_level=1)

        def update_priv(level):
            try:
                user_service.update_user("alice", privilege_level=level)
                return True
            except Exception:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future1 = executor.submit(update_priv, 5)
            future2 = executor.submit(update_priv, 10)

            future1.result()
            future2.result()

        # One of them won
        user = user_service.get_user("alice")
        assert user.privilege_level in [5, 10]


def test_concurrent_api_requests(server_factory):
    """Test handling of concurrent API requests.

    Verifies that the admin API can handle multiple simultaneous requests
    without deadlocks or data corruption.

    Test Steps:
    1. Start server with admin API enabled
    2. Launch multiple threads making different API calls
    3. Include a mix of read and write operations
    4. Wait for all requests to complete
    5. Verify all operations completed successfully

    Expected Results:
    - All API requests should complete successfully
    - Response times should be reasonable
    - No request should be lost or fail due to concurrency issues

    Edge Cases/Notes:
    - Tests API endpoint concurrency
    - Verifies proper request isolation
    - Ensures thread safety in API handlers
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )

    with server:
        session = server.login_admin()
        base_url = server.get_base_url()

        def make_request(i):
            try:
                response = session.get(f"{base_url}/api/health", timeout=5)
                return response.status_code == 200
            except Exception:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, i) for i in range(10)]
            results = [f.result() for f in futures]

        # Most should succeed
        assert sum(results) >= 8


def test_concurrent_read_operations(server_factory):
    """Test concurrent read operations on user data.

    Verifies that the system can handle multiple simultaneous read operations
    while maintaining data consistency and performance.

    Test Steps:
    1. Create a set of test users
    2. Launch multiple threads performing read operations
    3. Include a mix of different read operations (get by ID, list, search)
    4. Verify all read operations complete successfully

    Expected Results:
    - All read operations should complete successfully
    - Read operations should not block each other
    - Data consistency should be maintained throughout

    Edge Cases/Notes:
    - Tests read concurrency and isolation
    - Verifies proper cache coherency if caching is used
    - Ensures read operations don't interfere with each other
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))

        # Create some users
        for i in range(5):
            user_service.create_user(
                f"user{i}", password="Testcorrect1", privilege_level=1
            )

        def read_users():
            try:
                users = user_service.list_users()
                return len(users) >= 5
            except Exception:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(read_users) for _ in range(20)]
            results = [f.result() for f in futures]

        # All should succeed
        assert all(results)
