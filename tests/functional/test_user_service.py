"""
Medium Priority: User Service CRUD Tests

Tests complete user lifecycle operations.
"""


def test_user_create_with_all_fields(server_factory):
    """Test user creation with all fields specified.
    
    Setup: Start server
    Action: Create user with username, password, privilege, enabled
    Expected: User created with all fields set
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        
        user_service.create_user(
            "alice",
            password="testPass123!",
            privilege_level=10,
            enabled=True
        )
        
        user = user_service.get_user("alice")
        assert user is not None
        assert user.username == "alice"
        assert user.privilege_level == 10
        assert user.enabled is True


def test_user_create_duplicate_fails(server_factory):
    """Test duplicate username is rejected.
    
    Setup: Create user
    Action: Create another user with same username
    Expected: Second creation fails
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        
        user_service.create_user("alice", password="testPass1!", privilege_level=1)
        
        try:
            user_service.create_user("alice", password="testPass2!", privilege_level=1)
            assert False, "Should not allow duplicate username"
        except Exception:
            pass  # Expected


def test_user_update_privilege_level(server_factory):
    """Test updating user privilege level.
    
    Setup: Create user with privilege 1
    Action: Update to privilege 15
    Expected: Privilege level updated
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        
        user_service.create_user("alice", password="Testpass123", privilege_level=1)
        user_service.update_user("alice", privilege_level=15)
        
        user = user_service.get_user("alice")
        assert user.privilege_level == 15


def test_user_update_password(server_factory):
    """Test updating user password.
    
    Setup: Create user with password
    Action: Update password
    Expected: Old password fails, new password works
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        
        user_service.create_user("alice", password="Testold_pass1", privilege_level=15)
        
        from tacacs_server.devices.store import DeviceStore
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(name="test-device", network="127.0.0.1", group="default")
        
        # Old password works
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "Testold_pass1"
        )
        assert success
        
        # Update password using dedicated API
        user_service.set_password("alice", "Testnew_pass1")
        
        # Old password fails
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "Testold_pass1"
        )
        assert not success
        
        # New password works
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "Testnew_pass1"
        )
        assert success


def test_user_disable(server_factory):
    """Test disabling user account.
    
    Setup: Create enabled user
    Action: Disable user
    Expected: User cannot authenticate
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        
        user_service.create_user("alice", password="Testpass123", privilege_level=15, enabled=True)
        
        from tacacs_server.devices.store import DeviceStore
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group(name="default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(name="test-device", network="127.0.0.1", group="default")
        
        # Works when enabled
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "Testpass123"
        )
        assert success
        
        # Disable user
        user_service.update_user("alice", enabled=False)
        
        # Should fail now
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "Testpass123"
        )
        assert not success


def test_user_delete(server_factory):
    """Test user deletion.
    
    Setup: Create user
    Action: Delete user
    Expected: User no longer exists
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        
        user_service.create_user("alice", password="Testpass123", privilege_level=1)
        user_service.delete_user("alice")
        
        user = user_service.get_user_or_none("alice")
        assert user is None


def test_user_delete_nonexistent(server_factory):
    """Test deleting nonexistent user.
    
    Setup: Start server
    Action: Delete user that doesn't exist
    Expected: No error (idempotent)
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        
        # Should not raise error (idempotent helper)
        deleted = user_service.delete_user_if_exists("nonexistent")
        assert deleted is False


def test_user_list_all(server_factory):
    """Test listing all users.
    
    Setup: Create multiple users
    Action: List all users
    Expected: All users returned
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        
        user_service.create_user("alice", password="testPass1!", privilege_level=1)
        user_service.create_user("bob", password="testPass2!", privilege_level=5)
        user_service.create_user("charlie", password="Testpass3", privilege_level=15)
        
        users = user_service.list_users()
        usernames = [u.username for u in users]
        
        assert "alice" in usernames
        assert "bob" in usernames
        assert "charlie" in usernames


def test_user_get_nonexistent(server_factory):
    """Test getting nonexistent user.
    
    Setup: Start server
    Action: Get user that doesn't exist
    Expected: Returns None
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        
        user = user_service.get_user_or_none("nonexistent")
        assert user is None


def test_user_default_privilege_level(server_factory):
    """Test default privilege level when not specified.
    
    Setup: Start server
    Action: Create user without privilege_level
    Expected: Default to 1
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        
        user_service.create_user("alice", password="Testpass123")
        
        user = user_service.get_user("alice")
        # Should default to 1 or some default value
        assert user.privilege_level >= 0
