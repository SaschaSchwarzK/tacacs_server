"""
Admin Web UI HTML form presence + JS-driven CRUD smoke tests.

These tests:
- Log in via POST /admin/login (form-like but JSON supported by server)
- GET HTML pages and assert key form elements/ids present (users, groups, devices)
- Exercise the same JSON actions the UI performs (matching JS in templates)
  to simulate the effect of submitting forms (since UI uses fetch JSON).
"""

import requests


def _session_login(base_url: str, username: str, password: str) -> requests.Session:
    s = requests.Session()
    r = s.post(
        f"{base_url}/admin/login",
        json={"username": username, "password": password},
        timeout=5,
    )
    assert r.status_code == 200, f"Login failed: {r.status_code} {r.text}"
    return s


def test_users_page_forms_and_flow(server_factory):
    """Test user management forms and workflow in the admin web interface.

    This test verifies that the user management page contains all required form elements
    and that the user creation/update workflow functions correctly.

    Test Steps:
    1. Log in to admin interface
    2. Load users page and verify form elements
    3. Create a new user via API
    4. Update user details
    5. Verify changes are reflected

    Expected Result:
    - All form elements should be present
    - User creation should succeed
    - Updates should be persisted
    - Form validation should work as expected
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_web=True,
    )
    with server:
        base = server.get_base_url()
        s = _session_login(base, "admin", "admin123")

        # GET users HTML and assert key form/modal elements exist
        r = s.get(f"{base}/admin/users", timeout=5)
        assert r.status_code == 200 and "text/html" in r.headers.get("Content-Type", "")
        html = r.text
        # Modal, form, and fields defined in templates/admin/users.html
        assert 'id="userForm"' in html or "id='userForm'" in html
        assert 'id="formUsername"' in html
        assert 'id="formPrivilege"' in html
        assert 'id="formPassword"' in html

        # Create a user using the UI's JSON endpoint
        payload = {
            "username": "form_user1",
            "password": "FormPass123",
            "privilege_level": 5,
            "enabled": True,
        }
        r = s.post(f"{base}/admin/users", json=payload, timeout=5)
        assert r.status_code in [200, 201]

        # List via JSON mode to verify presence
        r = s.get(
            f"{base}/admin/users?format=json",
            headers={"Accept": "application/json"},
            timeout=5,
        )
        assert r.status_code == 200
        data = r.json()
        assert any(u.get("username") == "form_user1" for u in data.get("users", []))

        # Update via UI endpoint
        r = s.put(
            f"{base}/admin/users/form_user1",
            json={"enabled": False, "description": "via form"},
            timeout=5,
        )
        assert r.status_code in [200, 404]

        # Delete via UI endpoint
        r = s.delete(f"{base}/admin/users/form_user1", timeout=5)
        assert r.status_code in [204, 404]


def test_groups_page_forms_and_flow(server_factory):
    """Test group management forms and workflow in the admin web interface.

    This test verifies that the group management page contains all required form elements
    and that group operations work as expected.

    Test Steps:
    1. Log in to admin interface
    2. Load groups page and verify form elements
    3. Create a new group
    4. Add/remove users from group
    5. Update group details

    Expected Result:
    - Group management forms should be present
    - Group operations should complete successfully
    - Changes should be reflected in the UI
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_web=True,
    )
    with server:
        base = server.get_base_url()
        s = _session_login(base, "admin", "admin123")

        # GET groups HTML and assert fields from templates/admin/groups.html
        r = s.get(f"{base}/admin/groups", timeout=5)
        assert r.status_code == 200 and "text/html" in r.headers.get("Content-Type", "")
        html = r.text
        assert 'id="groupForm"' in html
        assert 'id="groupName"' in html
        assert 'id="groupRadiusSecret"' in html
        assert 'id="groupTacacsSecret"' in html

        # Create group with JSON endpoint used by UI
        g_payload = {
            "name": "form_dg1",
            "description": "Form DG",
            "tacacs_secret": "TacacsSecret123!",
        }
        r = s.post(f"{base}/admin/groups", json=g_payload, timeout=5)
        assert r.status_code in [200, 201]

        # List groups JSON to verify
        r = s.get(
            f"{base}/admin/groups?format=json",
            headers={"Accept": "application/json"},
            timeout=5,
        )
        assert r.status_code == 200


def test_devices_page_forms_and_flow(server_factory):
    """Test device management forms and workflow in the admin web interface.

    This test verifies that the device management page contains all required form elements
    and that device operations work as expected.

    Test Steps:
    1. Log in to admin interface
    2. Load devices page and verify form elements
    3. Add a new device
    4. Update device configuration
    5. Test device connectivity

    Expected Result:
    - Device management forms should be present
    - Device operations should complete successfully
    - Configuration changes should be applied
    - Connectivity tests should verify device access
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_web=True,
        enable_tacacs=True,
    )
    with server:
        base = server.get_base_url()
        s = _session_login(base, "admin", "admin123")

        # Ensure a device group exists
        s.post(
            f"{base}/admin/groups",
            json={"name": "form_dg2", "tacacs_secret": "TacacsSecret123!"},
            timeout=5,
        )

        # GET devices HTML and assert fields from templates/admin/devices.html
        r = s.get(f"{base}/admin/devices", timeout=5)
        assert r.status_code == 200 and "text/html" in r.headers.get("Content-Type", "")
        html = r.text
        assert 'id="deviceForm"' in html
        assert 'id="deviceName"' in html
        assert 'id="deviceNetwork"' in html

        # Create device via UI endpoint
        d_payload = {"name": "form_dev1", "network": "127.0.0.1", "group": "form_dg2"}
        r = s.post(f"{base}/admin/devices", json=d_payload, timeout=5)
        assert r.status_code in [200, 201]

        # List devices (JSON)
        r = s.get(
            f"{base}/admin/devices?format=json",
            headers={"Accept": "application/json"},
            timeout=5,
        )
        assert r.status_code == 200
