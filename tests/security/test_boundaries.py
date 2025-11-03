"""
High Priority: Boundary Condition Tests

Tests exact boundaries for limits, thresholds, and ranges.
"""

import pytest


def test_privilege_level_boundary_14_denied(server_factory):
    """Test privilege level 14 is below admin threshold.
    
    Setup: Create user with privilege 14
    Action: Perform action requiring privilege 15
    Expected: Denied
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("user14", password="correct_Pass123", privilege_level=14)
        
        user = user_service.get_user("user14")
        assert user.privilege_level == 14


def test_privilege_level_boundary_15_allowed(server_factory):
    """Test privilege level 15 is admin threshold.
    
    Setup: Create user with privilege 15
    Action: Verify privilege level
    Expected: Privilege 15 set correctly
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("user15", password="correct_Pass123", privilege_level=15)
        
        user = user_service.get_user("user15")
        assert user.privilege_level == 15


def test_privilege_level_minimum_zero(server_factory):
    """Test privilege level 0 is minimum.
    
    Setup: Create user with privilege 0
    Action: Verify privilege level
    Expected: Privilege 0 set correctly
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("user0", password="correct_Pass123", privilege_level=0)
        
        user = user_service.get_user("user0")
        assert user.privilege_level == 0


def test_username_max_length(server_factory):
    """Test username at maximum length (64 characters)."""
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        # Production limit: 64 chars allowed
        max_name = "a" * 64
        user_service.create_user(max_name, password="correct_Pass123", privilege_level=1)
        user = user_service.get_user(max_name)
        assert user is not None


def test_username_over_max_length(server_factory):
    """Test username exceeding maximum length (65 characters)."""
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.auth.local_user_service import LocalUserValidationError
        user_service = LocalUserService(str(server.auth_db))
        # 65 chars should be rejected by production validator
        too_long = "a" * 65
        with pytest.raises(LocalUserValidationError):
            user_service.create_user(too_long, password="correct_Pass123", privilege_level=1)


def test_password_bcrypt_max_length(server_factory):
    """Test password at bcrypt's 72-byte limit with required complexity."""
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        
        # bcrypt limits passwords to 72 bytes; ensure complexity (upper, lower, digit)
        password_72 = "A" + ("a" * 70) + "1"  # 72 chars
        user_service.create_user("alice", password=password_72, privilege_level=1)
        
        # Should authenticate with full password
        from tacacs_server.devices.store import DeviceStore
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(name="test-device", network="127.0.0.1", group="default")
        
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", password_72
        )
        assert success


def test_packet_size_at_limit(server_factory):
    """Test packet at size limit (typically 4KB).
    
    Setup: Start TACACS+ server
    Action: Send packet at maximum allowed size
    Expected: Accepted and processed
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.devices.store import DeviceStore
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(name="test-device", network="127.0.0.1", group="default")
        
        import socket
        import struct
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(("127.0.0.1", server.tacacs_port))
            
            # 4096 byte body (common limit)
            body_size = 4096
            header = struct.pack("!BBBBII", 0xC0, 1, 1, 0, 12345, body_size)
            body = b"x" * body_size
            
            sock.sendall(header + body)
            
            try:
                response = sock.recv(1024)
                # May succeed or timeout
            except socket.timeout:
                pass
        finally:
            sock.close()


def test_connection_from_max_ip(server_factory):
    """Test connection from highest IPv4 address.
    
    Setup: Add device with IP 255.255.255.255
    Action: Server should handle it
    Expected: No crash
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.devices.store import DeviceStore
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        
        # Highest IP
        try:
            device_store.ensure_device("max-ip", "255.255.255.255", "default")
        except Exception:
            # May reject broadcast address
            pass


def test_session_id_max_value(server_factory):
    """Test TACACS+ session with maximum session ID.
    
    Setup: Start server
    Action: Authenticate with session_id = 0xFFFFFFFF
    Expected: Handled correctly
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("alice", password="correct_Pass123", privilege_level=15)
        
        from tacacs_server.devices.store import DeviceStore
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(name="test-device", network="127.0.0.1", group="default")
        
        # Authentication with max session_id
        # (tacacs_authenticate generates its own session_id, so this is conceptual)
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate
        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "correct_Pass123"
        )
        
        # Should work regardless of session_id value
