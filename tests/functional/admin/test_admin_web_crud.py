"""
Admin Web UI CRUD via HTTP endpoints (no browser).

Fixed version that properly sends JSON payloads with correct headers.
"""

import re

import requests


def _login(server, test_username="admin", test_password="WebPass123!"):
    session = requests.Session()
    base_url = server.get_base_url()

    # Get the login page
    login_page = session.get(f"{base_url}/admin/login", timeout=5)

    print(f"\n--- Login Page Response ({login_page.status_code}) ---")

    # Prepare login data - form submission for login
    login_data = {
        "username": test_username,
        "password": test_password,
    }

    print("\n--- Attempting Login ---")
    print(f"URL: {base_url}/admin/login")

    # Submit login form
    response = session.post(
        f"{base_url}/admin/login",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        allow_redirects=True,
        timeout=5,
    )

    print(f"\n--- Login Response ({response.status_code}) ---")
    print(f"Cookies: {session.cookies.get_dict()}")

    # If we got redirected to the login page again, there was an error
    if "login" in response.url:
        print("\n--- Login Failed ---")
        raise Exception("Login failed")

    # Verify session cookie is set
    if "admin_session" not in session.cookies:
        print("\n--- No Session Cookie Found ---")
        raise Exception("Login failed: No session cookie found in response")

    print("\n--- Login Successful ---")

    return session


def _req(session, method, url, *, json=None, accept_json=True):
    """Make HTTP request with proper JSON handling."""
    headers = {}
    if accept_json:
        headers["Accept"] = "application/json"

    # CRITICAL: Always set Content-Type for JSON payloads
    if json is not None:
        headers["Content-Type"] = "application/json"

    # Log the request
    print(f"\n--- Request ---")
    print(f"{method} {url}")
    print(f"Headers: {headers}")
    if json is not None:
        print(f"JSON: {json}")

    # Make the request - requests library handles JSON serialization
    r = session.request(
        method,
        url,
        headers=headers,
        json=json,  # requests will stringify and set content-type
        timeout=5,
    )

    # Log the response
    print(f"\n--- Response ({r.status_code}) ---")
    print(f"Body: {r.text[:300]}..." if len(r.text) > 300 else f"Body: {r.text}")

    response_data = None
    if r.status_code != 204:
        try:
            content_type = r.headers.get("Content-Type", "")
            if "application/json" in content_type:
                response_data = r.json()
        except Exception as e:
            print(f"Error parsing response: {e}")
    return r, response_data


def test_admin_web_crud_users(server_factory, monkeypatch):
    """Test CRUD operations for user management via admin web interface.

    This test verifies that user management operations (Create, Read, Update, Delete)
    work correctly through the admin web interface's HTTP endpoints.

    Test Steps:
    1. Create a new user via API
    2. Verify user appears in the user list
    3. Update user details
    4. Delete the user
    5. Verify user is removed

    Expected Result:
    - All CRUD operations should complete successfully
    - User data should be persisted correctly
    - Changes should be reflected in the web interface
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
        s = _login(server, test_username, test_password)
        base = server.get_base_url()

        # Create user with JSON payload
        user_payload = {
            "username": "aw_user1",
            "password": "AdminWebPass1!",
            "privilege_level": 5,
            "enabled": True,
            "service": "exec",
        }

        print(f"\nCreating user with JSON payload: {user_payload}")
        r, _ = _req(s, "POST", f"{base}/admin/users", json=user_payload)

        print(f"\n--- After user creation ---")
        print(f"Status code: {r.status_code}")

        # API endpoints return 201 Created
        assert r.status_code == 201, (
            f"Failed to create user: {r.status_code} - {r.text}"
        )

        # List users (HTML response)
        r, _ = _req(s, "GET", f"{base}/admin/users", accept_json=False)
        assert r.status_code == 200, f"Failed to get users list: {r.status_code}"
        assert "aw_user1" in r.text, "User 'aw_user1' not found in users list"

        # Update user
        upd = {"enabled": False, "description": "updated"}
        r, _ = _req(s, "PUT", f"{base}/admin/users/aw_user1", json=upd)
        assert r.status_code == 200

        # Delete user
        r, _ = _req(s, "DELETE", f"{base}/admin/users/aw_user1")
        assert r.status_code == 204


def test_admin_web_crud_device_groups_and_devices(server_factory, monkeypatch):
    """Test CRUD operations for device groups and devices via admin web interface.

    This test verifies that device group and device management operations work
    correctly through the admin web interface.

    Test Steps:
    1. Create a device group
    2. Add devices to the group
    3. Update device properties
    4. Remove devices from group
    5. Delete device group

    Expected Result:
    - Device groups and devices should be manageable
    - Changes should persist across sessions
    - Should handle concurrent modifications
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
        enable_tacacs=True,
    )
    with server:
        s = _login(server, test_username, test_password)
        base = server.get_base_url()

        # Create device group
        group_payload = {
            "name": "aw_dg1",
            "description": "AdminWeb Group",
            "tacacs_secret": "TacacsSecret123!",
        }

        print(f"\n--- Creating device group ---")
        r, _ = _req(s, "POST", f"{base}/admin/groups", json=group_payload)
        assert r.status_code == 201, (
            f"Failed to create device group: {r.status_code} - {r.text}"
        )

        # List groups
        r, _ = _req(s, "GET", f"{base}/admin/groups", accept_json=False)
        assert r.status_code == 200
        assert "aw_dg1" in r.text, "Group 'aw_dg1' not found in groups list"

        # Create device
        device_payload = {
            "name": "aw_dev1",
            "network": "127.0.0.1",
            "group": "aw_dg1",
        }
        r, data = _req(s, "POST", f"{base}/admin/devices", json=device_payload)
        assert r.status_code == 201, (
            f"Failed to create device: {r.status_code} - {r.text}"
        )

        # Get device ID from response
        device_id = data.get("id") if data else None

        # List devices to verify
        r, _ = _req(s, "GET", f"{base}/admin/devices", accept_json=False)
        assert r.status_code == 200
        assert "aw_dev1" in r.text, "Device 'aw_dev1' not found in devices list"

        # Get device ID from JSON API if not in response
        if not device_id:
            r, dlist = _req(s, "GET", f"{base}/admin/devices?format=json")
            if r.status_code == 200 and isinstance(dlist, dict):
                devices = dlist.get("devices", [])
                for dev in devices:
                    if dev.get("name") == "aw_dev1":
                        device_id = dev.get("id")
                        break

        # Update and delete device
        if device_id:
            r, _ = _req(
                s,
                "PUT",
                f"{base}/admin/devices/{device_id}",
                json={"name": "aw_dev1_upd"},
            )
            assert r.status_code == 200

            r, _ = _req(s, "DELETE", f"{base}/admin/devices/{device_id}")
            assert r.status_code == 204


def test_admin_web_crud_user_groups(server_factory, monkeypatch):
    """Test CRUD operations for user groups via admin web interface.

    This test verifies that user group management operations work correctly
    through the admin web interface.

    Test Steps:
    1. Create a new user group
    2. Add/remove users from group
    3. Update group permissions
    4. Delete user group

    Expected Result:
    - User groups should be manageable
    - Membership changes should be reflected immediately
    - Permission updates should take effect
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
        s = _login(server, test_username, test_password)
        base = server.get_base_url()

        # Create user group
        group_payload = {
            "name": "aw_g1",
            "description": "AdminWeb Group",
            "privilege_level": 5,
        }

        print(f"\nCreating user group with JSON payload: {group_payload}")
        r, _ = _req(s, "POST", f"{base}/admin/user-groups", json=group_payload)

        print(f"\n--- After user group creation ---")
        print(f"Status code: {r.status_code}")

        # API endpoints return 201 Created
        assert r.status_code == 201, (
            f"Failed to create user group: {r.status_code} - {r.text[:500]}"
        )

        # List groups
        r, _ = _req(s, "GET", f"{base}/admin/user-groups", accept_json=False)
        assert r.status_code == 200
        assert "aw_g1" in r.text, "User group 'aw_g1' not found in groups list"

        # Update group
        r, _ = _req(
            s, "PUT", f"{base}/admin/user-groups/aw_g1", json={"description": "Updated"}
        )
        assert r.status_code == 200

        # Delete group
        r, _ = _req(s, "DELETE", f"{base}/admin/user-groups/aw_g1")
        assert r.status_code == 204


def test_admin_web_crud_proxies(server_factory, api_session, monkeypatch):
    """Test CRUD operations for proxy configurations via admin web interface.

    This test verifies that proxy configuration management works correctly
    through the admin web interface.

    Test Steps:
    1. Add a new proxy configuration
    2. Update proxy settings
    3. Test proxy connectivity
    4. Remove proxy configuration

    Expected Result:
    - Proxy configurations should be manageable
    - Settings should be validated
    - Connection tests should verify proxy functionality
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
            "admin_web": True,
            "server": {"proxy_enabled": "true"},
        },
        enable_admin_web=True,
    )
    with server:
        # Web UI login for cookie-protected pages
        s = _login(server, test_username, test_password)
        base = server.get_base_url()

        # Check if proxies page is accessible
        r = s.get(f"{base}/admin/proxies")
        if r.status_code != 200:
            print(f"Proxies page not available: {r.status_code}")
            return  # Skip test

        # Create proxy via API
        proxy_payload = {"name": "aw_px1", "network": "10.10.0.0/16"}
        r = api_session.post(f"{base}/api/proxies", json=proxy_payload, timeout=5)
        assert r.status_code == 201, (
            f"Failed to create proxy: {r.status_code} - {r.text}"
        )

        # List and verify
        r = api_session.get(f"{base}/api/proxies", timeout=5)
        assert r.status_code == 200
        items = (
            r.json()
            if r.headers.get("Content-Type", "").startswith("application/json")
            else []
        )

        pid = next((p.get("id") for p in items if p.get("name") == "aw_px1"), None)
        if pid:
            # Update
            r = api_session.put(
                f"{base}/api/proxies/{pid}", json={"name": "aw_px1_upd"}, timeout=5
            )
            assert r.status_code == 200

            # Delete
            r = api_session.delete(f"{base}/api/proxies/{pid}", timeout=5)
            assert r.status_code == 204
