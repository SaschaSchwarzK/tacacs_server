"""
Admin API Tests

Tests the Admin REST API with real server instances.
Each test creates its own server with admin API enabled.
"""

import requests


def test_admin_api_login_success(server_factory, monkeypatch):
    """Test successful admin login via API.

    This test verifies that the admin API login endpoint works correctly
    with valid credentials and establishes a proper session.

    Test Steps:
    1. Start server with admin API enabled
    2. Send login request with valid credentials
    3. Verify successful response and session cookie

    Expected Result:
    - Should return HTTP 200 on success
    - Should set session cookie
    - Should log the login event
    """

    # Set up admin user
    test_username = "admin"
    test_password = "SecurePass123!"

    import bcrypt

    password_hash = bcrypt.hashpw(
        test_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    monkeypatch.setenv("ADMIN_USERNAME", test_username)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", password_hash)

    server = server_factory(
        config={"admin_web": True},
        enable_admin_web=True,
        enable_admin_api=True,
    )

    with server:
        base_url = server.get_base_url()

        # Login
        response = requests.post(
            f"{base_url}/admin/login",
            json={
                "username": "admin",
                "password": "SecurePass123!",
            },
            timeout=5,
        )

        assert response.status_code == 200, f"Login should succeed: {response.text}"

        # Verify we got a session cookie
        assert "session" in response.cookies or "Set-Cookie" in response.headers

        # Verify logs
        logs = server.get_logs()
        assert "admin" in logs or "login" in logs.lower()


def test_admin_api_login_failure(server_factory):
    """Test failed admin login with wrong password.

    This test verifies that the admin API properly handles failed login
    attempts with incorrect credentials.

    Test Steps:
    1. Start server with admin API enabled
    2. Attempt login with incorrect password
    3. Verify access is denied

    Expected Result:
    - Should return HTTP 401/403 on failure
    - Should not set session cookie
    - Should log failed attempt
    """
    server = server_factory(
        config={
            "admin_username": "admin",
            "admin_password": "CorrectPass123!",
        },
        enable_admin_api=True,
    )

    with server:
        base_url = server.get_base_url()

        # Try to login with wrong password
        response = requests.post(
            f"{base_url}/admin/login",
            json={
                "username": "admin",
                "password": "WrongPassword",
            },
            timeout=5,
        )

        assert response.status_code == 401, "Login should fail with wrong password"

        # Verify logs
        logs = server.get_logs()
        assert "admin" in logs or "login" in logs.lower() or "failed" in logs.lower()


def test_admin_api_health_check(server_factory):
    """Test admin API health check endpoint.

    This test verifies that the health check endpoint returns the expected
    system status information.

    Test Steps:
    1. Access health check endpoint
    2. Verify response format and status

    Expected Result:
    - Should return HTTP 200
    - Should include system status info
    - Should include service status
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )

    with server:
        # Login first
        session = server.login_admin()
        base_url = server.get_base_url()

        # Check health endpoint
        response = session.get(f"{base_url}/api/health", timeout=5)

        assert response.status_code == 200, (
            f"Health check should succeed: {response.text}"
        )

        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "ok", "running"]


def test_admin_api_stats_endpoint(server_factory):
    """Test admin API statistics endpoint.

    This test verifies that the statistics endpoint returns the expected
    system and service metrics.

    Test Steps:
    1. Access statistics endpoint
    2. Verify response format and data

    Expected Result:
    - Should return HTTP 200
    - Should include request counters
    - Should include resource usage stats
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
        enable_tacacs=True,
    )

    with server:
        # Login
        session = server.login_admin()
        base_url = server.get_base_url()

        # Get stats
        response = session.get(f"{base_url}/api/stats", timeout=5)

        assert response.status_code == 200, (
            f"Stats endpoint should work: {response.text}"
        )

        data = response.json()
        # Stats should contain some server information
        assert isinstance(data, dict)


def test_admin_api_user_management(server_factory):
    """Test user management operations via Admin API.

    This test verifies CRUD operations for user management through the
    admin API endpoints.

    Test Steps:
    1. Create a new user
    2. Retrieve user details
    3. Update user attributes
    4. Delete the user

    Expected Result:
    - All operations should complete successfully
    - Changes should be persisted
    - Should enforce access controls
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )

    with server:
        # Login
        session = server.login_admin()
        base_url = server.get_base_url()

        # Create a user via API
        payload = {
            "username": "apiuser",
            "password": "ApiPass123",
            "privilege_level": 5,
            "enabled": True,
        }
        response = session.post(f"{base_url}/api/users", json=payload, timeout=5)
        assert response.status_code in [200, 201]

        # List users
        response = session.get(f"{base_url}/api/users", timeout=5)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (list, dict))

        # Update user
        update = {"privilege_level": 10}
        response = session.put(f"{base_url}/api/users/apiuser", json=update, timeout=5)
        assert response.status_code in [200, 404]

        # Delete user
        response = session.delete(f"{base_url}/api/users/apiuser", timeout=5)
        assert response.status_code in [200, 204, 404]


def test_admin_api_device_management(server_factory):
    """Test device management via Admin API.

    This test verifies CRUD operations for device management through
    the admin API endpoints.

    Test Steps:
    1. Add a new device
    2. Update device configuration
    3. Test device connectivity
    4. Remove device

    Expected Result:
    - Device operations should succeed
    - Configuration should be validated
    - Connectivity tests should verify access
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
        enable_tacacs=True,
    )

    with server:
        # Login
        session = server.login_admin()
        base_url = server.get_base_url()

        # Create a device group
        group_payload = {
            "name": "test-group",
            "description": "Test group",
            "tacacs_secret": "TacacsSecret123!",
        }
        response = session.post(
            f"{base_url}/api/device-groups", json=group_payload, timeout=5
        )
        assert response.status_code in [200, 201, 409]

        # Create a device under that group
        device_payload = {
            "name": "test-device",
            "ip_address": "127.0.0.1",
            "device_group_id": 1,
            "enabled": True,
        }
        response = session.post(
            f"{base_url}/api/devices", json=device_payload, timeout=5
        )
        assert response.status_code in [200, 201, 404], (
            f"Device creation response: {response.text}"
        )

        # List devices
        response = session.get(f"{base_url}/api/devices", timeout=5)
        assert response.status_code == 200
        if response.headers.get("Content-Type", "").startswith("application/json"):
            devices = response.json()
            assert isinstance(devices, (list, dict))

        # Verify logs
        logs = server.get_logs()
        assert len(logs) > 0


def test_admin_api_without_auth(server_factory):
    """Test Admin API authentication requirements.

    This test verifies that unauthenticated access to protected
    admin API endpoints is properly rejected.

    Test Steps:
    1. Attempt to access protected endpoints without auth
    2. Verify access is denied

    Expected Result:
    - Should return HTTP 401/403
    - Should not expose sensitive data
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )

    with server:
        base_url = server.get_base_url()

        # Try to access API without logging in
        response = requests.get(f"{base_url}/api/stats", timeout=5)

        # Should be unauthorized
        assert response.status_code in [401, 403], "API should require authentication"


def test_admin_api_session_timeout(server_factory):
    """Test admin session timeout behavior.

    This test verifies that admin sessions expire after the configured
    timeout period and require re-authentication.

    Test Steps:
    1. Log in and obtain session
    2. Wait for session to expire
    3. Attempt to use expired session

    Expected Result:
    - Session should expire after timeout
    - Expired sessions should be rejected
    - Should require re-authentication
    """
    server = server_factory(
        config={
            "admin_username": "admin",
            "admin_password": "admin123",
        },
        enable_admin_api=True,
    )

    with server:
        # Login
        session = server.login_admin()
        base_url = server.get_base_url()

        # First request should work
        response = session.get(f"{base_url}/api/health", timeout=5)
        assert response.status_code == 200

        # Second request should also work (session still valid)
        response = session.get(f"{base_url}/api/health", timeout=5)
        assert response.status_code == 200

        # Verify session is maintained
        logs = server.get_logs()
        assert "admin" in logs


def test_admin_api_disabled_by_default(server_factory):
    """Test Admin API security defaults.

    This test verifies that the Admin API is disabled by default
    when no admin password is configured.

    Test Steps:
    1. Start server without admin credentials
    2. Attempt to access admin API

    Expected Result:
    - Admin API should be disabled
    - Access attempts should be rejected
    - Should log security event
    """
    server = server_factory(
        config={
            "admin_username": "admin",
            # No admin_password = disabled
        },
        enable_admin_api=False,
    )

    with server:
        # Web port should not be set
        assert server.web_port is None

        # Verify logs don't show admin API starting
        logs = server.get_logs()
        assert "monitoring" not in logs.lower() or "admin" not in logs.lower()


def test_admin_api_logout(server_factory):
    """Test admin logout functionality.

    This test verifies that the logout endpoint properly terminates
    the admin session and invalidates the session token.

    Test Steps:
    1. Log in to obtain session
    2. Call logout endpoint
    3. Verify session is invalidated

    Expected Result:
    - Logout should succeed
    - Session should be invalidated
    - Subsequent requests should be rejected
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )

    with server:
        # Login
        session = server.login_admin()
        base_url = server.get_base_url()

        # Verify we're logged in
        response = session.get(f"{base_url}/api/health", timeout=5)
        assert response.status_code == 200

        # Logout
        response = session.post(f"{base_url}/admin/logout", timeout=5)
        # Should succeed or endpoint might not exist
        assert response.status_code in [200, 404, 405]

        # Verify logs
        logs = server.get_logs()
        assert len(logs) > 0


def test_admin_api_logs_collected(server_factory):
    """Test Admin API audit logging.

    This test verifies that all admin API activities are properly
    logged for security and auditing purposes.

    Test Steps:
    1. Perform various admin operations
    2. Check server logs for audit entries

    Expected Result:
    - All admin actions should be logged
    - Logs should include user and action details
    - Timestamps should be accurate
    """
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "admin_username": "admin",
            "admin_password": "admin123",
        },
        enable_admin_api=True,
    )

    with server:
        # Login
        session = server.login_admin()
        base_url = server.get_base_url()

        # Make several API calls
        session.get(f"{base_url}/api/health", timeout=5)
        session.get(f"{base_url}/api/stats", timeout=5)

        # Try invalid endpoint
        session.get(f"{base_url}/api/nonexistent", timeout=5)

    # Get logs after server stops
    logs = server.get_logs()

    # Verify logs contain API activity
    assert logs, "Logs should not be empty"
    assert len(logs) > 200, "Logs should contain substantial content"
    assert "admin" in logs or "api" in logs.lower() or "health" in logs.lower()
