# Test Suite Overview

This suite uses real server subprocesses with isolated resources (config, DBs, ports, logs). Tests are configuration‑driven with no mocks. Use markers to run subsets.

## Server Instance Factory

The `server_factory` fixture creates isolated instances:

```python
def test_example(server_factory):
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
        },
        enable_tacacs=True,
        enable_radius=False,
        enable_admin_api=True,
        enable_admin_web=True,
    )
    
    with server:
        # Server is running with isolated resources
        # - Temporary config at: server.config_path
        # - Logs at: server.log_path
        # - Auth DB at: server.auth_db
        
        # Perform tests...
        logs = server.get_logs()
```

## Component Control

Tests explicitly enable/disable components:

- `enable_tacacs`: TACACS+ server on temporary port
- `enable_radius`: RADIUS server on temporary ports
- `enable_admin_api`: Admin REST API
- `enable_admin_web`: Admin Web UI

Components are **disabled by default** based on configuration:
- **Admin API/Web**: Disabled if no `admin_password` in config
- **RADIUS**: Disabled if `radius.enabled = false` in config

## Configuration

Each test creates its own config file from a dict:

```python
server = server_factory(
    config={
        "log_level": "INFO",
        "auth_backends": "local",
        "admin_username": "testadmin",
        "admin_password": "TestPass123!",
        "encryption_required": "false",
        # Custom sections
        "ldap": {
            "server": "ldap://test.example.com",
            "base_dn": "dc=test,dc=com",
        },
    },
    enable_tacacs=True,
)
```

## Credentials

Only credentials use environment variables (passed to subprocess):
- `OKTA_API_TOKEN`: Okta authentication
- `LDAP_BIND_PASSWORD`: LDAP bind password

All other configuration comes from the config file.

## Layout

```
tests/
  unit/
  integration/
    rate_limit/
    tacacs/
    admin/
  functional/
    webhooks/
  security/
  chaos/
  conftest.py
  README.md, QUICK_START.md
```

Highlights
- Rate limiters: `tests/integration/rate_limit/` (TACACS/RADIUS/web, logs + behavior)
- Command authorization (TACACS): `tests/integration/tacacs/test_command_authorization.py` (allow/deny + Prometheus counters + logs)
- Webhooks:
  - Admin API CRUD (no network): `tests/integration/admin/test_webhooks_api.py`
  - E2E delivery with local HTTP servers: `tests/functional/webhooks/test_webhook_delivery.py` (may skip in restricted envs)
  - Deterministic delivery without networking: `tests/functional/webhooks/test_webhook_utils_delivery.py` (injected transport)
- Security checks: `tests/security/`
- Chaos experiments: `tests/chaos/test_chaos.py` (opt‑in)

## Running Tests

```bash
# Run everything
pytest -q

# Run specific file
pytest tests/integration/tacacs/test_command_authorization.py -v

# Run specific test
pytest tests/integration/tacacs/test_command_authorization.py::test_tacacs_authorization_logs_and_status -v

# Integration only
pytest -m integration -v

# Show server output on console
pytest -s -v

# Short tracebacks, show logs on failure
pytest --tb=short -v

# Parallel (if pytest‑xdist installed)
pytest -n auto -q
```

## Example Tests

### Basic TACACS+ Authentication

```python
def test_tacacs_auth(server_factory):
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        # Create user
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("testuser", password="testpass", privilege_level=15)
        
        # Add device
        from tacacs_server.devices.store import DeviceStore
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", description="Default")
        device_store.add_device(
            name="test-device",
            address="127.0.0.1",
            secret="testsecret",
            group="default",
        )
        
        # Authenticate
        success, msg = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, 
            "testsecret", "testuser", "testpass"
        )
        
        assert success, f"Auth should succeed: {msg}"
        
        # Check logs
        logs = server.get_logs()
        assert "testuser" in logs
```

### RADIUS with Shared Backend

```python
def test_radius_shared_backend(server_factory):
    server = server_factory(
        config={
            "auth_backends": "local",
            "radius_share_backends": "true",
        },
        enable_tacacs=True,
        enable_radius=True,
    )
    
    with server:
        # Setup user
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("raduser", password="radpass", privilege_level=15)
        
        # Add device (works for both TACACS and RADIUS)
        from tacacs_server.devices.store import DeviceStore
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", description="Default")
        device_store.add_device(
            name="shared-device",
            address="127.0.0.1",
            secret="sharedsecret",
            group="default",
        )
        
        import time
        time.sleep(0.5)  # Let RADIUS pick up client config
        
        # Test RADIUS authentication
        success, msg = radius_authenticate(
            "127.0.0.1", server.radius_auth_port,
            "sharedsecret", "raduser", "radpass"
        )
        
        assert success, f"RADIUS auth should succeed: {msg}"
        
        # Check logs
        logs = server.get_logs()
        assert "RADIUS" in logs or "raduser" in logs
```

### Admin API with Authentication

```python
def test_admin_api_user_crud(server_factory):
    server = server_factory(
        config={
            "admin_username": "admin",
            "admin_password": "SecurePass123!",
        },
        enable_admin_api=True,
    )
    
    with server:
        # Login
        session = server.login_admin()
        base_url = server.get_base_url()
        
        # Create user via API
        response = session.post(
            f"{base_url}/api/users",
            json={
                "username": "apiuser",
                "password": "ApiPass123!",
                "privilege_level": 15,
            },
            timeout=5,
        )
        
        # Check response
        if response.status_code in [200, 201]:
            # List users
            response = session.get(f"{base_url}/api/users", timeout=5)
            assert response.status_code == 200
            users = response.json()
            assert any(u.get("username") == "apiuser" for u in users)
        
        # Check logs
        logs = server.get_logs()
        assert "admin" in logs or "api" in logs.lower()
```

### Full Stack Integration

```python
def test_all_components(server_factory):
    server = server_factory(
        config={
            "auth_backends": "local",
            "admin_username": "admin",
            "admin_password": "admin123",
        },
        enable_tacacs=True,
        enable_radius=True,
        enable_admin_api=True,
        enable_admin_web=True,
    )
    
    with server:
        # Setup
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore
        
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("fulluser", password="fullpass", privilege_level=15)
        
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", description="Default")
        device_store.add_device(
            name="full-device",
            address="127.0.0.1",
            secret="fullsecret",
            group="default",
        )
        
        import time
        time.sleep(0.5)
        
        # Test TACACS+
        success = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port,
            "fullsecret", "fulluser", "fullpass"
        )
        assert success, "TACACS+ should work"
        
        # Test Admin Web/API
        session = server.login_admin()
        response = session.get(f"{server.get_base_url()}/api/health", timeout=5)
        assert response.status_code == 200, "Admin API should work"
        
        # Verify logs show all components
        logs = server.get_logs()
        assert "TACACS" in logs or "tacacs" in logs.lower()
        assert "RADIUS" in logs or "radius" in logs.lower()
        assert "admin" in logs or "monitoring" in logs.lower()
```

## Log Collection

Every test automatically collects server logs:

```python
def test_with_log_inspection(server_factory):
    server = server_factory(
        config={"log_level": "DEBUG"},
        enable_tacacs=True,
    )
    
    with server:
        # Do something...
        pass
    
    # After server stops, logs are still available
    logs = server.get_logs()
    
    # Inspect logs
    assert "Server ready" in logs
    assert len(logs) > 100
    
    # Look for specific events
    if "error" in logs.lower():
        print("Errors found in logs:")
        for line in logs.split('\n'):
            if "error" in line.lower():
                print(f"  {line}")
```

## Temporary Resources

All resources are temporary and isolated:

```python
with server:
    # Paths to temporary resources
    print(f"Config: {server.config_path}")
    print(f"Logs: {server.log_path}")
    print(f"Auth DB: {server.auth_db}")
    print(f"Devices DB: {server.devices_db}")
    print(f"TACACS Port: {server.tacacs_port}")
    print(f"Web Port: {server.web_port}")
```

Resources are automatically cleaned up after tests complete.

## Testing Optional Components

Components can be selectively enabled/disabled:

```python
# Only TACACS+
server = server_factory(
    enable_tacacs=True,
    enable_radius=False,
    enable_admin_api=False,
    enable_admin_web=False,
)

# Only Admin API (no TACACS+)
server = server_factory(
    config={"admin_username": "admin", "admin_password": "pass"},
    enable_tacacs=False,
    enable_admin_api=True,
)

# TACACS+ and RADIUS
server = server_factory(
    enable_tacacs=True,
    enable_radius=True,
)

# Everything
server = server_factory(
    config={"admin_username": "admin", "admin_password": "pass"},
    enable_tacacs=True,
    enable_radius=True,
    enable_admin_api=True,
    enable_admin_web=True,
)
```

## Debugging Failed Tests

When a test fails, inspect the logs:

```python
def test_something(server_factory):
    server = server_factory(
        config={"log_level": "DEBUG"},
        enable_tacacs=True,
    )
    
    try:
        with server:
            # Test code...
            pass
    except AssertionError:
        # Print logs on failure
        print("\n=== SERVER LOGS ===")
        print(server.get_logs())
        raise
```

Or use pytest's built-in capture:

```bash
# Show stdout/stderr on failure
pytest tests_new/ -s

# Show full traceback
pytest tests_new/ --tb=long

# Stop on first failure
pytest tests_new/ -x
```

## Best Practices

1. **Always use context manager**: `with server:` ensures cleanup
2. **Wait for async operations**: Add `time.sleep(0.5)` after device changes for RADIUS
3. **Check logs**: Always inspect logs to verify expected behavior
4. **Isolate tests**: Each test should create its own server instance
5. **Test one thing**: Keep tests focused on a single feature
6. **Use descriptive names**: Test names should clearly describe what they test
7. **Add assertions for logs**: Verify logs contain expected activity

## Migration from Old Tests

Old test (with mocks):
```python
def test_old_way(mock_server):
    mock_server.authenticate.return_value = True
    result = client.auth("user", "pass")
    assert result
```

New test (real server):
```python
def test_new_way(server_factory):
    server = server_factory(enable_tacacs=True)
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("user", password="pass", privilege_level=15)
        
        # Real authentication
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port,
            "secret", "user", "pass"
        )
        assert success
        
        # Verify in logs
        logs = server.get_logs()
        assert "user" in logs
```

## Advantages

1. **Real behavior**: Tests actual server code, not mocks
2. **Catch integration issues**: Real servers expose real bugs
3. **Isolated**: Each test has its own resources
4. **Debuggable**: Logs available for every test
5. **Maintainable**: No mock setup/maintenance
6. **Confidence**: Tests prove the system actually works

## Next Steps

To add more tests:

1. Create a new test file in `tests_new/`
2. Use `server_factory` fixture
3. Enable needed components
4. Create config as needed
5. Test real functionality
6. Check logs for verification

Example template:

```python
"""
Description of test module
"""

def test_new_feature(server_factory):
    """Test description"""
    server = server_factory(
        config={
            # Config here
        },
        enable_tacacs=True,  # As needed
    )
    
    with server:
        # Setup
        # ...
        
        # Test
        # ...
        
        # Verify
        logs = server.get_logs()
        assert "expected" in logs
```
