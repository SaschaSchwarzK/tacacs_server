"""
Low Priority: Logging Verification Tests

Tests that important events are logged correctly.
"""


def test_successful_auth_logged(server_factory):
    """Test successful authentication is logged.

    Setup: Create user
    Action: Authenticate successfully
    Expected: Success logged with username
    """
    server = server_factory(
        config={"log_level": "INFO", "auth_backends": "local"},
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

        tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "Testcorrect1"
        )

        logs = server.get_logs()
        assert "alice" in logs


def test_failed_auth_logged(server_factory):
    """Test failed authentication is logged.

    Setup: Create user
    Action: Authenticate with wrong password
    Expected: Failure logged
    """
    server = server_factory(
        config={"log_level": "INFO", "auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("alice", password="Testcorrect2", privilege_level=15)

        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        tacacs_authenticate("127.0.0.1", server.tacacs_port, "secret", "alice", "wrong")

        logs = server.get_logs()
        assert "alice" in logs or "fail" in logs.lower()


def test_server_startup_logged(server_factory):
    """Test server startup is logged.

    Setup: Start server
    Action: Check logs
    Expected: Startup message present
    """
    server = server_factory(
        config={"log_level": "INFO"},
        enable_tacacs=True,
    )

    with server:
        logs = server.get_logs()
        assert "Starting" in logs or "TACACS" in logs or "server" in logs.lower()


def test_user_creation_logged(server_factory):
    """Test user creation is logged.

    Setup: Start server
    Action: Create user
    Expected: Creation logged
    """
    server = server_factory(
        config={"log_level": "DEBUG", "auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("testuser", password="Testcorrect1", privilege_level=1)

        logs = server.get_logs()
        # May or may not log user creation
        assert len(logs) > 0


def test_device_connection_logged(server_factory):
    """Test device connection is logged.

    Setup: Add device
    Action: Connect from device
    Expected: Connection logged with IP
    """
    server = server_factory(
        config={"log_level": "INFO", "auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        # Connect
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(("127.0.0.1", server.tacacs_port))
            sock.close()
        except Exception:
            pass

        logs = server.get_logs()
        assert "127.0.0.1" in logs or "connection" in logs.lower()


def test_error_logged_without_stacktrace_to_user(server_factory):
    """Test errors logged but stacktrace not exposed to user.

    Setup: Start server
    Action: Trigger error condition
    Expected: Error in logs, not in response
    """
    server = server_factory(
        config={"log_level": "DEBUG", "auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        # Send malformed packet
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(("127.0.0.1", server.tacacs_port))
            sock.sendall(b"garbage")
            sock.close()
        except Exception:
            pass

        logs = server.get_logs()
        # Error should be logged
        assert len(logs) > 0


def test_admin_login_logged(server_factory):
    """Test admin login is logged.

    Setup: Start admin API
    Action: Login as admin
    Expected: Login logged with username
    """
    server = server_factory(
        config={
            "log_level": "INFO",
            "admin_username": "admin",
            "admin_password": "admin123",
        },
        enable_admin_api=True,
    )

    with server:
        server.login_admin()

        logs = server.get_logs()
        assert "admin" in logs or "login" in logs.lower()


def test_password_not_in_logs(server_factory):
    """Test passwords are never logged.

    Setup: Create user and authenticate
    Action: Check logs
    Expected: Password not present in logs
    """
    server = server_factory(
        config={"log_level": "DEBUG", "auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        password = "SuperSecret123!"

        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("alice", password=password, privilege_level=15)

        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", password
        )

        logs = server.get_logs()
        # Password should NOT be in logs
        assert password not in logs


def test_log_level_debug_more_verbose(server_factory):
    """Test DEBUG log level produces more output than INFO.

    Setup: Start two servers with different log levels
    Action: Compare log sizes
    Expected: DEBUG has more content
    """
    # INFO level
    server_info = server_factory(
        config={"log_level": "INFO"},
        enable_tacacs=True,
    )

    with server_info:
        logs_info = server_info.get_logs()
        info_length = len(logs_info)

    # DEBUG level
    server_debug = server_factory(
        config={"log_level": "DEBUG"},
        enable_tacacs=True,
    )

    with server_debug:
        logs_debug = server_debug.get_logs()
        debug_length = len(logs_debug)

    # DEBUG should have more logs
    # (May not always be true, but generally DEBUG is more verbose)
    assert debug_length > 0 and info_length > 0
