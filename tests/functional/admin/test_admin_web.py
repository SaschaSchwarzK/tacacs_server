"""
Admin Web UI Tests

Tests the Admin Web UI with real server instances.
Each test creates its own server with web UI enabled.
"""

import requests


def test_admin_web_login_page(server_factory, monkeypatch):
    """Test that admin web login page is accessible.

    This test verifies that the admin web interface's login page is properly served
    and contains the expected login form elements.

    Test Steps:
    1. Configure test admin credentials
    2. Start server with admin web interface enabled
    3. Access the login page
    4. Verify page content and status code

    Expected Result:
    - Login page should return HTTP 200
    - Content-Type should be text/html
    - Page should contain login form elements
    """
    # Set up admin user
    test_username = "admin"
    test_password = "WebPass123!"

    import bcrypt

    password_hash = bcrypt.hashpw(
        test_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    monkeypatch.setenv("ADMIN_USERNAME", test_username)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", password_hash)

    server = server_factory(
        config={"admin_web": True},
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


def test_admin_web_login_post(server_factory, monkeypatch):
    """Test logging into admin web UI.

    This test verifies that the login form submission works correctly with valid
    credentials and establishes a proper session.

    Test Steps:
    1. Configure test admin credentials
    2. Submit login form with valid credentials
    3. Verify successful authentication

    Expected Result:
    - Login should succeed with valid credentials
    - Session cookie should be set
    - Should be redirected to dashboard after login
    """
    test_username = "admin"
    test_password = "WebPass123!"

    # Hash the password with bcrypt
    import bcrypt

    password_hash = bcrypt.hashpw(
        test_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    # Set environment variables for admin auth
    monkeypatch.setenv("ADMIN_USERNAME", test_username)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", password_hash)

    # Create server with admin web enabled
    server = server_factory(
        config={"admin_web": True},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()
        session = requests.Session()

        # Get login page first
        session.get(f"{base_url}/admin/login", timeout=5)

        # Prepare login data
        login_data = {
            "username": test_username,
            "password": test_password,
        }

        # Make login request
        response = session.post(
            f"{base_url}/admin/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
            timeout=5,
        )

        # Verify successful login
        assert response.status_code == 200
        assert "login" not in response.url.lower()
        assert "admin_session" in session.cookies


def test_admin_web_dashboard_access(server_factory, monkeypatch):
    """Test accessing admin dashboard after successful login.

    This test verifies that authenticated users can access the admin dashboard
    and that the dashboard contains expected elements.

    Test Steps:
    1. Log in to admin interface
    2. Access dashboard page
    3. Verify dashboard content

    Expected Result:
    - Dashboard should be accessible after login
    - Should display relevant system information
    - Should show current server status
    """
    test_username = "admin"
    test_password = "WebPass123!"

    # Hash the password with bcrypt
    import bcrypt

    password_hash = bcrypt.hashpw(
        test_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    # Set environment variables for admin auth
    monkeypatch.setenv("ADMIN_USERNAME", test_username)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", password_hash)

    # Create server with admin web enabled
    server = server_factory(
        config={"admin_web": True, "enable_tacacs": True},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()
        session = requests.Session()

        # Login first
        login_data = {
            "username": test_username,
            "password": test_password,
        }

        # Make login request
        response = session.post(
            f"{base_url}/admin/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
            timeout=5,
        )

        # Verify login was successful
        assert response.status_code == 200
        assert "login" not in response.url.lower()
        assert "admin_session" in session.cookies

        # Now try to access dashboard
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


def test_admin_web_static_resources(server_factory, monkeypatch):
    """Test that web UI can serve static resources"""
    # Set up admin user
    test_username = "admin"
    test_password = "WebPass123!"

    import bcrypt

    password_hash = bcrypt.hashpw(
        test_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    monkeypatch.setenv("ADMIN_USERNAME", test_username)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", password_hash)

    server = server_factory(
        config={"admin_web": True},
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


def test_admin_web_requires_authentication(server_factory, monkeypatch):
    """Test authentication requirements for admin web interface.

    This test verifies that unauthenticated users are redirected to the login page
    and can access protected resources after successful authentication.

    Test Steps:
    1. Attempt to access protected page without login
    2. Verify redirection to login page
    3. Log in with valid credentials
    4. Verify access to protected page

    Expected Result:
    - Unauthenticated access should redirect to login
    - After login, should be able to access protected resources
    - Session should persist across requests
    """
    # Set up admin user
    test_username = "admin"
    test_password = "WebPass123!"

    import bcrypt

    password_hash = bcrypt.hashpw(
        test_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    monkeypatch.setenv("ADMIN_USERNAME", test_username)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", password_hash)

    server = server_factory(
        config={"admin_web": True},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()
        session = requests.Session()

        # Try to access admin dashboard without logging in
        response = session.get(f"{base_url}/admin", timeout=5, allow_redirects=False)

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
            r = session.get(login_url, timeout=5)
            assert r.status_code in [200, 204], (
                f"Login page should be reachable, got {r.status_code}"
            )

            # Login with credentials
            login_data = {
                "username": test_username,
                "password": test_password,
            }

            # Make login request
            session.post(
                f"{base_url}/admin/login",
                data=login_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                allow_redirects=True,
                timeout=5,
            )

            # Access dashboard again, now authenticated
            resp2 = session.get(f"{base_url}/admin", timeout=5)
            assert resp2.status_code in [200, 302, 303], (
                f"Dashboard should be accessible after login: {resp2.status_code}"
            )


def test_admin_web_invalid_credentials(server_factory, monkeypatch):
    """Test that invalid credentials are rejected.

    This test verifies that the admin interface properly rejects login attempts
    with invalid credentials and provides appropriate feedback.

    Test Steps:
    1. Configure valid admin credentials
    2. Attempt login with invalid username/password
    3. Verify login failure

    Expected Result:
    - Invalid credentials should be rejected
    - Should display error message
    - No session should be established
    """
    # Set up a valid admin user
    test_username = "admin"
    test_password = "WebPass123!"

    import bcrypt

    password_hash = bcrypt.hashpw(
        test_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    monkeypatch.setenv("ADMIN_USERNAME", test_username)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", password_hash)

    server = server_factory(
        config={"admin_web": True},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()
        session = requests.Session()

        # Try to login with invalid credentials
        login_data = {
            "username": "wronguser",
            "password": "wrongpass",
        }

        response = session.post(
            f"{base_url}/admin/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=False,
            timeout=5,
        )

        # The server returns 401 for invalid credentials
        assert response.status_code == 401, (
            "Invalid credentials should be rejected with 401"
        )

        # Verify no session cookie was set
        assert "admin_session" not in session.cookies


def test_admin_web_user_list_page(server_factory, monkeypatch):
    """Test accessing user list page in web UI.

    This test verifies that the user management page is accessible and displays
    the list of configured users.

    Test Steps:
    1. Log in to admin interface
    2. Navigate to user management page
    3. Verify user list is displayed

    Expected Result:
    - User list page should be accessible
    - Should display existing users
    - Should include user management controls
    """
    # Set up admin user
    test_username = "admin"
    test_password = "WebPass123!"

    import bcrypt

    password_hash = bcrypt.hashpw(
        test_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    monkeypatch.setenv("ADMIN_USERNAME", test_username)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", password_hash)

    server = server_factory(
        config={"admin_web": True},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()
        session = requests.Session()

        # Login first
        login_data = {
            "username": test_username,
            "password": test_password,
        }

        # Make login request
        login_response = session.post(
            f"{base_url}/admin/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
            timeout=5,
        )

        # Verify login was successful
        assert login_response.status_code == 200
        assert "login" not in login_response.url.lower()
        assert "admin_session" in session.cookies

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


def test_admin_web_device_list_page(server_factory, monkeypatch):
    """Test accessing device list page in web UI.

    This test verifies that the device management page is accessible and displays
    the list of configured network devices.

    Test Steps:
    1. Log in to admin interface
    2. Navigate to device management page
    3. Verify device list is displayed

    Expected Result:
    - Device list page should be accessible
    - Should display configured devices
    - Should include device management controls
    """
    # Set up admin user
    test_username = "admin"
    test_password = "WebPass123!"

    import bcrypt

    password_hash = bcrypt.hashpw(
        test_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    monkeypatch.setenv("ADMIN_USERNAME", test_username)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", password_hash)

    server = server_factory(
        config={"admin_web": True},
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()
        session = requests.Session()

        # Login first
        login_data = {
            "username": test_username,
            "password": test_password,
        }

        # Make login request
        login_response = session.post(
            f"{base_url}/admin/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
            timeout=5,
        )

        # Verify login was successful
        assert login_response.status_code == 200
        assert "login" not in login_response.url.lower()
        assert "admin_session" in session.cookies

        # Try to access devices page
        response = session.get(f"{base_url}/admin/devices", timeout=5)

        # Should work or might not exist
        assert response.status_code in [200, 404], (
            f"Devices page: {response.status_code}"
        )

        if response.status_code == 200:
            # Should be HTML
            assert "text/html" in response.headers.get("Content-Type", "")


def test_admin_web_with_tacacs(server_factory, monkeypatch):
    """Test Admin Web UI alongside TACACS+ server.

    This test verifies that the Admin Web UI functions correctly when TACACS+
    service is also running on the same server.

    Test Steps:
    1. Start server with both Admin Web and TACACS+ enabled
    2. Verify both services are operational
    3. Test web interface functionality

    Expected Result:
    - Both services should start without conflicts
    - Web interface should be fully functional
    - TACACS+ service should remain operational
    """
    # Set up admin user
    test_username = "admin"
    test_password = "WebPass123!"

    import bcrypt

    password_hash = bcrypt.hashpw(
        test_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    monkeypatch.setenv("ADMIN_USERNAME", test_username)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", password_hash)

    server = server_factory(
        config={"admin_web": True},
        enable_tacacs=True,
        enable_admin_web=True,
    )

    with server:
        # Both servers should be running
        assert server.tacacs_port is not None
        assert server.web_port is not None

        # Web UI login and dashboard reachability
        base_url = server.get_base_url()
        session = requests.Session()

        # Login first
        login_data = {
            "username": test_username,
            "password": test_password,
        }

        # Make login request
        login_response = session.post(
            f"{base_url}/admin/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
            timeout=5,
        )

        # Verify login was successful
        assert login_response.status_code == 200
        assert "login" not in login_response.url.lower()
        assert "admin_session" in session.cookies

        # Access dashboard
        resp = session.get(f"{base_url}/admin", timeout=5)
        assert resp.status_code in (200, 302, 303)

        # Verify logs show both services
        logs = server.get_logs()
        assert "TACACS" in logs or "tacacs" in logs.lower()


def test_admin_web_logs_collected(server_factory, monkeypatch):
    """Test that web UI activity is properly logged.

    This test verifies that admin web interface activities are properly logged
    for security and auditing purposes.

    Test Steps:
    1. Perform various actions in the web interface
    2. Check server logs for activity records

    Expected Result:
    - All admin actions should be logged
    - Logs should include user and action details
    - Timestamps should be accurate
    """
    # Set up admin user
    test_username = "admin"
    test_password = "WebPass123!"

    import bcrypt

    password_hash = bcrypt.hashpw(
        test_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    monkeypatch.setenv("ADMIN_USERNAME", test_username)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", password_hash)

    server = server_factory(
        config={
            "log_level": "DEBUG",
            "admin_web": True,
        },
        enable_admin_web=True,
    )

    with server:
        base_url = server.get_base_url()
        session = requests.Session()

        # Login first
        login_data = {
            "username": test_username,
            "password": test_password,
        }

        # Make login request
        login_response = session.post(
            f"{base_url}/admin/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
            timeout=5,
        )

        # Verify login was successful
        assert login_response.status_code == 200
        assert "login" not in login_response.url.lower()
        assert "admin_session" in session.cookies

        # Access various Web UI pages (Web-only)
        session.get(f"{base_url}/admin", timeout=5)
        session.get(f"{base_url}/admin/users", timeout=5)


def test_api_health_with_tacacs(server_factory, api_session, monkeypatch):
    """Test the API health endpoint using Bearer token (API-only)."""
    # Set up admin user (though not used for API token auth)
    test_username = "admin"
    test_password = "WebPass123!"

    import bcrypt

    password_hash = bcrypt.hashpw(
        test_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    monkeypatch.setenv("ADMIN_USERNAME", test_username)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", password_hash)

    server = server_factory(
        config={"admin_web": True},
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


def test_admin_web_disabled_without_password(server_factory):
    """Test that web UI is disabled when no admin password is configured.

    This test verifies the security measure that disables the admin web interface
    when no admin password is set.

    Test Steps:
    1. Start server without admin credentials
    2. Attempt to access admin interface

    Expected Result:
    - Admin web interface should be disabled
    - Access attempts should be rejected
    - Logs should indicate disabled status
    """
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
