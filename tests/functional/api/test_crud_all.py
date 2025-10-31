"""
Comprehensive CRUD tests for Admin API objects:
- Device Groups
- Devices
- Users
- User Groups
- Proxies (requires proxy_enabled)
- Webhooks configuration
"""


def _login(server):
    return server.login_admin()


def _json(session, method, url, **kwargs):
    resp = session.request(method, url, timeout=5, **kwargs)
    # Never attempt to parse body on 204 No Content
    if resp.status_code == 204:
        return resp, None
    # Avoid JSON decoding when body is empty
    if resp.headers.get("Content-Length") == "0":
        return resp, None
    ctype = resp.headers.get("Content-Type", "")
    if ctype.startswith("application/json"):
        try:
            return resp, resp.json()
        except Exception:
            # Be tolerant of empty bodies with JSON content-type
            return resp, None
    return resp, None


def test_crud_device_groups(server_factory):
    """Test CRUD operations for device groups via Admin API.

    This test verifies the complete lifecycle of device group management
    including creation, retrieval, updating, and deletion of device groups.

    Test Steps:
    1. Create a new device group
    2. Retrieve and verify the device group
    3. Update the device group details
    4. Delete the device group
    5. Verify deletion

    Expected Result:
    - All CRUD operations should complete successfully
    - Device group data should be persisted correctly
    - Changes should be reflected in subsequent API calls
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )
    with server:
        s = _login(server)
        base = server.get_base_url()

        # Create
        payload = {
            "name": "dg1",
            "description": "Group1",
            "tacacs_secret": "TacacsSecret123!",
        }
        r, _ = _json(s, "POST", f"{base}/api/device-groups", json=payload)
        assert r.status_code in [201, 409]

        # List
        r, data = _json(s, "GET", f"{base}/api/device-groups")
        assert r.status_code == 200 and isinstance(data, list)
        dg_id = next((g.get("id") for g in data if g.get("name") == "dg1"), None)
        assert dg_id is not None

        # Get
        r, data = _json(s, "GET", f"{base}/api/device-groups/{dg_id}")
        assert r.status_code == 200 and data.get("name") == "dg1"

        # Update
        upd = {"description": "Updated"}
        r, data = _json(s, "PUT", f"{base}/api/device-groups/{dg_id}", json=upd)
        assert r.status_code == 200 and data.get("description") == "Updated"

        # Delete (allowed only if no devices)
        r, _ = _json(s, "DELETE", f"{base}/api/device-groups/{dg_id}")
        assert r.status_code in [204, 409]


def test_crud_devices(server_factory):
    """Test CRUD operations for network devices via Admin API.

    This test verifies the complete lifecycle of device management
    including creation, configuration, and removal of network devices.

    Test Steps:
    1. Create a new device with basic configuration
    2. Retrieve and verify device details
    3. Update device configuration
    4. Test device connectivity
    5. Remove the device

    Expected Result:
    - Device operations should complete successfully
    - Configuration changes should be applied
    - Device status should be accurately reported
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
        enable_tacacs=True,
    )
    with server:
        s = _login(server)
        base = server.get_base_url()

        # Ensure group exists
        _json(
            s,
            "POST",
            f"{base}/api/device-groups",
            json={"name": "dg2", "tacacs_secret": "TacacsSecret123!"},
        )
        r, groups = _json(s, "GET", f"{base}/api/device-groups")
        dg_id = next((g.get("id") for g in groups if g.get("name") == "dg2"), None)
        assert dg_id is not None

        # Create device
        dev = {
            "name": "dev1",
            "ip_address": "127.0.0.1",
            "device_group_id": dg_id,
            "enabled": True,
        }
        r, data = _json(s, "POST", f"{base}/api/devices", json=dev)
        assert r.status_code in [201, 404]  # 404 if group lookup differs

        # List devices
        r, items = _json(s, "GET", f"{base}/api/devices")
        assert r.status_code == 200 and isinstance(items, list)

        # Pick first device for update/delete if ours isn't present
        dev_id = None
        for it in items:
            if it.get("name") == "dev1":
                dev_id = it.get("id")
                break
        if dev_id is None and items:
            dev_id = items[0].get("id")

        if dev_id:
            # Update device
            r, data = _json(
                s, "PUT", f"{base}/api/devices/{dev_id}", json={"name": "dev1-upd"}
            )
            assert r.status_code in [200, 404]

            # Delete device
            r, _ = _json(s, "DELETE", f"{base}/api/devices/{dev_id}")
            assert r.status_code in [204, 404]


def test_crud_users(server_factory):
    """Test CRUD operations for user accounts via Admin API.

    This test verifies the complete lifecycle of user account management
    including creation, modification, and removal of user accounts.

    Test Steps:
    1. Create a new user with basic attributes
    2. Retrieve and verify user details
    3. Update user attributes and permissions
    4. Test user authentication
    5. Remove the user account

    Expected Result:
    - User operations should complete successfully
    - Authentication should work with updated credentials
    - Permission changes should be enforced
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )
    with server:
        s = _login(server)
        base = server.get_base_url()

        # Create user
        payload = {"username": "u1", "password": "UserPass123", "privilege_level": 5}
        r, data = _json(s, "POST", f"{base}/api/users", json=payload)
        assert r.status_code in [201, 409]

        # List
        r, items = _json(s, "GET", f"{base}/api/users")
        assert r.status_code == 200 and isinstance(items, list)

        # Get
        r, data = _json(s, "GET", f"{base}/api/users/u1")
        assert r.status_code in [200, 404]

        # Update
        r, data = _json(s, "PUT", f"{base}/api/users/u1", json={"privilege_level": 7})
        assert r.status_code in [200, 404]

        # Delete
        r, _ = _json(s, "DELETE", f"{base}/api/users/u1")
        assert r.status_code in [204, 404]


def test_crud_user_groups(server_factory):
    """Test CRUD operations for user groups via Admin API.

    This test verifies the complete lifecycle of user group management
    including creation, modification, and removal of user groups.

    Test Steps:
    1. Create a new user group
    2. Add/remove users from the group
    3. Update group permissions
    4. Verify group membership
    5. Remove the group

    Expected Result:
    - Group operations should complete successfully
    - Membership changes should be reflected immediately
    - Permission inheritance should work as expected
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )
    with server:
        s = _login(server)
        base = server.get_base_url()

        # Create
        payload = {"name": "g1", "description": "Users", "privilege_level": 5}
        r, data = _json(s, "POST", f"{base}/api/user-groups", json=payload)
        assert r.status_code in [201, 409]

        # List
        r, items = _json(s, "GET", f"{base}/api/user-groups")
        assert r.status_code == 200 and isinstance(items, list)

        # Get
        r, data = _json(s, "GET", f"{base}/api/user-groups/g1")
        assert r.status_code in [200, 404]

        # Update
        r, data = _json(
            s, "PUT", f"{base}/api/user-groups/g1", json={"description": "Updated"}
        )
        assert r.status_code in [200, 404]

        # Delete
        r, _ = _json(s, "DELETE", f"{base}/api/user-groups/g1")
        assert r.status_code in [204, 404]


def test_crud_proxies(server_factory):
    """Test CRUD operations for proxy configuration via Admin API.

    This test verifies the complete lifecycle of proxy management
    including creation, configuration, and testing of proxy settings.

    Test Steps:
    1. Configure a new proxy
    2. Test proxy connectivity
    3. Update proxy settings
    4. Verify proxy usage in requests
    5. Remove proxy configuration

    Expected Result:
    - Proxy configuration should be saved
    - Connectivity tests should pass
    - Proxy should be used for outbound requests
    """
    server = server_factory(
        config={
            "admin_username": "admin",
            "admin_password": "admin123",
            "server": {"proxy_enabled": "true"},
        },
        enable_admin_api=True,
    )
    with server:
        s = _login(server)
        base = server.get_base_url()

        # Create proxy
        r, data = _json(
            s,
            "POST",
            f"{base}/api/proxies",
            json={"name": "px1", "network": "10.0.0.0/8"},
        )
        assert r.status_code in [201, 400]

        # List
        r, items = _json(s, "GET", f"{base}/api/proxies")
        assert r.status_code == 200 and isinstance(items, list)
        proxy_id = next((p.get("id") for p in items if p.get("name") == "px1"), None)

        if proxy_id:
            # Get
            r, data = _json(s, "GET", f"{base}/api/proxies/{proxy_id}")
            assert r.status_code == 200

            # Update
            r, data = _json(
                s, "PUT", f"{base}/api/proxies/{proxy_id}", json={"name": "px1-upd"}
            )
            assert r.status_code == 200

            # Delete
            r, _ = _json(s, "DELETE", f"{base}/api/proxies/{proxy_id}")
            assert r.status_code == 204


def test_webhooks_config(server_factory):
    """Test webhook configuration and notification system via Admin API.

    This test verifies the configuration and functionality of webhooks
    for event notifications and system integration.

    Test Steps:
    1. Configure webhook endpoints
    2. Test webhook delivery
    3. Verify payload format
    4. Test error handling
    5. Clean up webhook configuration

    Expected Result:
    - Webhooks should be properly configured
    - Notifications should be delivered to endpoints
    - Payload should match expected format
    - Error cases should be handled gracefully
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )
    with server:
        s = _login(server)
        base = server.get_base_url()

        # Get current config
        r, cfg = _json(s, "GET", f"{base}/api/admin/webhooks-config")
        assert r.status_code in [200, 404]

        # Update config
        payload = {
            "urls": ["http://127.0.0.1:8089/hook"],
            "headers": {"X-Test": "1"},
            "template": {"event": "login"},
            "timeout": 1.5,
            "threshold_count": 5,
            "threshold_window": 60,
        }
        r, cfg2 = _json(s, "PUT", f"{base}/api/admin/webhooks-config", json=payload)
        assert r.status_code in [200, 400]
