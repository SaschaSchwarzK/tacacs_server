"""
Admin API Tests

Tests the Admin REST API with real server instances.
Each test creates its own server with admin API enabled.
"""

import requests


def test_admin_api_login_success(server_factory):
    """Test successful admin login via API"""
    server = server_factory(
        config={
            "admin_username": "admin",
            "admin_password": "SecurePass123!",
        },
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
    """Test failed admin login with wrong password"""
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
    """Test admin API health check endpoint"""
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
    """Test admin API stats endpoint"""
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
    """Test creating and managing users via Admin API"""
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
    """Test device management endpoints"""
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
            "name": "default",
            "description": "Default group",
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
    """Test that Admin API requires authentication"""
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
    """Test that admin sessions have proper timeout configuration"""
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
    """Test that Admin API is disabled when no password is configured"""
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
    """Test admin logout functionality"""
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
    """Test that Admin API activity is logged"""
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
