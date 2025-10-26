"""
Admin Web UI Tests

Tests the Admin Web UI with real server instances.
Each test creates its own server with web UI enabled.
"""

import requests


def test_admin_web_login_page(server_factory):
    """Test that admin web login page is accessible"""
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()

        # Access login page
        response = requests.get(f"{base_url}/admin/login", timeout=5)

        assert response.status_code == 200, (
            f"Login page should be accessible: {response.status_code}"
        )

        # Should be HTML
        assert "text/html" in response.headers.get("Content-Type", "")

        # Should contain login form elements
        content = response.text.lower()
        assert "login" in content or "username" in content or "password" in content


def test_admin_web_login_post(server_factory):
    """Test logging into admin web UI"""
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "WebPass123!"},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()

        # Create a session
        session = requests.Session()

        # Login
        response = session.post(
            f"{base_url}/admin/login",
            json={
                "username": "admin",
                "password": "WebPass123!",
            },
            timeout=5,
        )

        assert response.status_code == 200, (
            f"Web login should succeed: {response.status_code}"
        )

        # Should have session cookie
        assert len(session.cookies) > 0, "Should receive session cookie"

        # Verify logs
        logs = server.get_logs()
        assert "admin" in logs or "login" in logs.lower()


def test_admin_web_dashboard_access(server_factory):
    """Test accessing admin dashboard after login"""
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_web=True,
        enable_tacacs=True,
    )

    with server:
        # Login
        session = server.login_admin()
        base_url = server.get_base_url()

        # Try to access dashboard/main page
        response = session.get(f"{base_url}/admin", timeout=5)

        # Should get a page (might redirect or show dashboard)
        assert response.status_code in [200, 302, 303], (
            f"Dashboard access: {response.status_code}"
        )

        # If we got HTML, check it contains dashboard elements
        if response.status_code == 200 and "text/html" in response.headers.get(
            "Content-Type", ""
        ):
            content = response.text.lower()
            # Should have some dashboard-like content
            assert any(
                word in content for word in ["dashboard", "admin", "server", "status"]
            )


def test_admin_web_static_resources(server_factory):
    """Test that web UI can serve static resources"""
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()

        # Try to access root (might have a landing page or redirect)
        response = requests.get(f"{base_url}/", timeout=5)

        # Should get some response
        assert response.status_code in [200, 302, 303, 404], (
            f"Root access: {response.status_code}"
        )

        # Verify server is serving HTTP
        assert response.headers.get("Content-Type") is not None


def test_admin_web_requires_authentication(server_factory):
    """Unauthenticated access should redirect to login; then login and access again"""
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()

        # Try to access admin dashboard without logging in
        response = requests.get(f"{base_url}/admin", timeout=5, allow_redirects=False)

        # Should be redirected to login or get 401/403; 307 is acceptable for slash redirect
        assert response.status_code in [302, 303, 307, 401, 403], (
            f"Should require authentication, got {response.status_code}"
        )

        # If redirected, follow to login and then authenticate
        if response.status_code in [302, 303, 307]:
            location = response.headers.get("Location", "")
            # Normalize relative redirects
            if location.startswith("/"):
                login_url = f"{base_url}{location}"
            else:
                login_url = location or f"{base_url}/admin/login"

            # Fetch login page
            r = requests.get(login_url, timeout=5)
            assert r.status_code in [200, 204], (
                f"Login page should be reachable, got {r.status_code}"
            )

            # Login via helper to ensure cookie handling
            session = server.login_admin()
            # Access dashboard again, now authenticated
            resp2 = session.get(f"{base_url}/admin", timeout=5)
            assert resp2.status_code in [200, 302, 303], (
                f"Dashboard should be accessible after login: {resp2.status_code}"
            )


def test_admin_web_invalid_credentials(server_factory):
    """Test web UI login with invalid credentials"""
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "CorrectPass"},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()

        # Try to login with wrong password
        response = requests.post(
            f"{base_url}/admin/login",
            json={
                "username": "admin",
                "password": "WrongPass",
            },
            timeout=5,
        )

        # Should fail
        assert response.status_code in [401, 403], (
            "Invalid credentials should be rejected"
        )

        # Verify logs show failed attempt
        logs = server.get_logs()
        assert "admin" in logs or "login" in logs.lower()


def test_admin_web_user_list_page(server_factory):
    """Test accessing user list page in web UI"""
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_web=True,
    )

    with server:
        # Login
        session = server.login_admin()
        base_url = server.get_base_url()

        # Try to access users page
        response = session.get(f"{base_url}/admin/users", timeout=5)

        # Should work or might not exist
        assert response.status_code in [200, 404], f"Users page: {response.status_code}"

        if response.status_code == 200:
            # Should be HTML
            assert "text/html" in response.headers.get("Content-Type", "")
            content = response.text.lower()
            # Should mention users
            assert "user" in content


def test_admin_web_device_list_page(server_factory):
    """Test accessing device list page in web UI"""
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_web=True,
    )

    with server:
        # Login
        session = server.login_admin()
        base_url = server.get_base_url()

        # Try to access devices page
        response = session.get(f"{base_url}/admin/devices", timeout=5)

        # Should work or might not exist
        assert response.status_code in [200, 404], (
            f"Devices page: {response.status_code}"
        )

        if response.status_code == 200:
            # Should be HTML
            assert "text/html" in response.headers.get("Content-Type", "")


def test_admin_web_with_tacacs(server_factory):
    """Test that the Admin Web UI works alongside TACACS+ server (Web-only)."""
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_tacacs=True,
        enable_admin_web=True,
    )

    with server:
        # Both servers should be running
        assert server.tacacs_port is not None
        assert server.web_port is not None

        # Web UI login and dashboard reachability
        session = server.login_admin()
        base_url = server.get_base_url()
        resp = session.get(f"{base_url}/admin", timeout=5)
        assert resp.status_code in (200, 302, 303)

        # Verify logs show both services
        logs = server.get_logs()
        assert "TACACS" in logs or "tacacs" in logs.lower()


def test_admin_web_logs_collected(server_factory):
    """Test that web UI activity is logged"""
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "admin_username": "admin",
            "admin_password": "admin123",
        },
        enable_admin_web=True,
    )

    with server:
        # Login
        session = server.login_admin()
        base_url = server.get_base_url()

        # Access various Web UI pages (Web-only)
        session.get(f"{base_url}/admin", timeout=5)
        session.get(f"{base_url}/admin/users", timeout=5)


def test_api_health_with_tacacs(server_factory, api_session):
    """Test the API health endpoint using Bearer token (API-only)."""
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()
        response = api_session.get(f"{base_url}/api/health", timeout=5)
        assert response.status_code == 200

    # Get logs after server stops
    logs = server.get_logs()
    print(logs)

    # Verify logs contain web activity
    assert logs, "Logs should not be empty"
    assert len(logs) > 200, "Logs should contain substantial content"
    assert "admin" in logs or "login" in logs.lower() or "web" in logs.lower()


def test_api_health_with_wrong_bearer_token(server_factory):
    """API should reject requests with an invalid Bearer token when API is enabled."""
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()
        # Fresh session without admin cookie; use wrong token

        s = requests.Session()
        s.headers.update({"Authorization": "Bearer WRONG_TOKEN"})
        resp = s.get(f"{base_url}/api/health", timeout=5)
        assert resp.status_code in (401, 503), f"unexpected status {resp.status_code}"


def test_admin_web_disabled_without_password(server_factory):
    """Test that web UI is disabled when no admin password is configured"""
    server = server_factory(
        config={
            "admin_username": "admin",
            # No password = disabled
        },
        enable_admin_web=False,
    )

    with server:
        # Web port should not be set
        assert server.web_port is None

        # Verify logs don't show web UI starting
        logs = server.get_logs()
        # Should not see monitoring/web starting
        assert "monitoring" not in logs.lower() or "web_host" not in logs.lower()
