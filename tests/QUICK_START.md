# Quick Start Guide

## Run Tests

```bash
# Everything quick
pytest -q

# Integration only
pytest -m integration -v

# Chaos (opt‑in)
pytest tests/chaos/test_chaos.py -m chaos -v

# Webhooks CRUD (admin API)
pytest tests/integration/admin/test_webhooks_api.py -v

# Webhooks E2E delivery (uses local HTTP servers; may skip in restricted envs)
pytest tests/functional/webhooks/test_webhook_delivery.py -v -m functional

# Webhooks delivery with injected transport (no networking required)
pytest tests/functional/webhooks/test_webhook_utils_delivery.py -v -m functional
```

## Understanding Test Output

### Successful Test
```
test_tacacs_basic.py::test_tacacs_basic_auth_success PASSED [100%]
```

### Failed Test with Logs
```
test_tacacs_basic.py::test_tacacs_basic_auth_success FAILED [100%]

________________________________ test_tacacs_basic_auth_success _________________________________

server_factory = <function server_factory at 0x...>

    def test_tacacs_basic_auth_success(server_factory):
        server = server_factory(
            config={"log_level": "DEBUG", "auth_backends": "local"},
            enable_tacacs=True,
        )
        
        with server:
>           assert success, f"Authentication should succeed: {message}"
E           AssertionError: Authentication should succeed: Connection error: ...

# Check server logs
logs = server.get_logs()
# Will show what went wrong
```

## Writing Your First Test

Create `tests/unit/test_my_feature.py`:

```python
"""
My Feature Tests
"""

def test_my_feature(server_factory):
    """Test description"""
    # Create server with needed components
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
        },
        enable_tacacs=True,
    )
    
    # Start server
    with server:
        # Setup: Create users, devices, etc.
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("myuser", password="mypass", privilege_level=15)
        
        from tacacs_server.devices.store import DeviceStore
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", description="Default group")
        device_store.ensure_device(name="my-device", network="127.0.0.1", group="default")
        
        # Test: Perform your test operation
        # ... your test code here ...
        
        # Verify: Check logs and results
        logs = server.get_logs()
        assert "myuser" in logs, "User activity should be logged"
        assert "success" in logs.lower() or "authenticated" in logs.lower()
```

Run it:
```bash
pytest tests/unit/test_my_feature.py -v -s
```

## Common Test Patterns

### Pattern 1: Test Successful Operation
```python
def test_feature_works(server_factory):
    server = server_factory(enable_tacacs=True)
    
    with server:
        # Setup
        setup_test_data(server)
        
        # Execute
        result = perform_operation()
        
        # Verify
        assert result.success
        logs = server.get_logs()
        assert "expected behavior" in logs
```

### Pattern 2: Test Failure Condition
```python
def test_feature_fails_correctly(server_factory):
    server = server_factory(enable_tacacs=True)
    
    with server:
        # Don't setup required data
        
        # Execute - should fail
        result = perform_operation()
        
        # Verify failure is handled correctly
        assert not result.success
        logs = server.get_logs()
        assert "error" in logs.lower() or "failed" in logs.lower()
```

### Pattern 3: Test Multiple Scenarios
```python
def test_multiple_users(server_factory):
    server = server_factory(enable_tacacs=True)
    
    with server:
        # Setup multiple users
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        
        users = [
            ("alice", "alicepass"),
            ("bob", "bobpass"),
            ("charlie", "charliepass"),
        ]
        
        for username, password in users:
            user_service.create_user(username, password=password, privilege_level=15)
        
        # Add device
        from tacacs_server.devices.store import DeviceStore
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", description="Default")
        device_store.add_device(
            name="test-device",
            address="127.0.0.1",
            secret="secret",
            group="default",
        )
        
        # Test each user
        for username, password in users:
            success, _ = tacacs_authenticate(
                "127.0.0.1", server.tacacs_port,
                "secret", username, password
            )
            assert success, f"{username} should authenticate"
        
        # Verify all users in logs
        logs = server.get_logs()
        for username, _ in users:
            assert username in logs
```

## Debugging Tips

### Tip 1: Enable DEBUG Logging
```python
server = server_factory(
    config={"log_level": "DEBUG"},  # More verbose logs
    enable_tacacs=True,
)
```

### Tip 2: Print Logs on Failure
```python
def test_with_debug(server_factory):
    server = server_factory(enable_tacacs=True)
    
    try:
        with server:
            # Test code
            pass
    except Exception as e:
        print("\n=== SERVER LOGS ===")
        print(server.get_logs())
        print("===================\n")
        raise
```

### Tip 3: Check Server Ports
```python
with server:
    print(f"TACACS+ Port: {server.tacacs_port}")
    print(f"Web Port: {server.web_port}")
    print(f"RADIUS Auth Port: {server.radius_auth_port}")
```

### Tip 4: Inspect Temporary Files
```python
with server:
    print(f"Config file: {server.config_path}")
    print(f"Log file: {server.log_path}")
    print(f"Auth DB: {server.auth_db}")
    
    # Read config
    print("\n=== CONFIG ===")
    print(server.config_path.read_text())
```

### Tip 5: Use pytest's -s Flag
```bash
# Show print statements during test
pytest test_my_feature.py -s
```

## Testing Different Components

### TACACS+ Only
```python
def test_tacacs_only(server_factory):
    server = server_factory(
        enable_tacacs=True,
        enable_radius=False,
        enable_admin_api=False,
    )
    # ... test TACACS+ ...
```

### RADIUS Only
```python
def test_radius_only(server_factory):
    server = server_factory(
        enable_tacacs=False,
        enable_radius=True,
    )
    # ... test RADIUS ...
```

### Admin API Only
```python
def test_admin_api_only(server_factory):
    server = server_factory(
        config={
            "admin_username": "admin",
            "admin_password": "admin123",
        },
        enable_admin_api=True,
    )
    
    with server:
        session = server.login_admin()
        # ... test API ...
```

### All Components
```python
def test_everything(server_factory):
    server = server_factory(
        config={
            "admin_username": "admin",
            "admin_password": "admin123",
        },
        enable_tacacs=True,
        enable_radius=True,
        enable_admin_api=True,
        enable_admin_web=True,
    )
    # ... test integration ...
```

## Next Steps

1. **Read the full README**: `tests_new/README.md`
2. **Study existing tests**: Look at test files for examples
3. **Write your own tests**: Start with simple tests and build up
4. **Run tests frequently**: Verify changes don't break functionality

## Getting Help

- **Check logs**: Always inspect `server.get_logs()` when debugging
- **Read test code**: Existing tests show best practices
- **Use verbose mode**: `pytest -v` shows more detail
- **Enable debug logs**: `config={"log_level": "DEBUG"}`
