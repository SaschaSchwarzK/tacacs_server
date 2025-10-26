"""
Full Stack Integration Tests

Tests all server components working together.
Each test spins up a complete server with all features enabled.
"""

import hashlib
import socket
import struct
import time


def tacacs_authenticate(
    host: str, port: int, key: str, username: str, password: str
) -> bool:
    """Helper to perform TACACS+ authentication"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))

        session_id = int(time.time()) & 0xFFFFFFFF
        user_bytes = username.encode("utf-8")
        port_bytes = b"console"
        rem_addr_bytes = b"127.0.0.1"
        data_bytes = password.encode("utf-8")

        def md5_pad(sess_id: int, k: str, ver: int, seq: int, length: int) -> bytes:
            pad = bytearray()
            sid_bytes = struct.pack("!L", sess_id)
            k_bytes = k.encode("utf-8")
            v_byte = bytes([ver])
            s_byte = bytes([seq])
            while len(pad) < length:
                if not pad:
                    md5_in = sid_bytes + k_bytes + v_byte + s_byte
                else:
                    md5_in = sid_bytes + k_bytes + v_byte + s_byte + pad
                pad.extend(hashlib.md5(md5_in, usedforsecurity=False).digest())
            return bytes(pad[:length])

        def transform(body: bytes, sess_id: int, k: str, ver: int, seq: int) -> bytes:
            if not k:
                return body
            pad = md5_pad(sess_id, k, ver, seq, len(body))
            return bytes(a ^ b for a, b in zip(body, pad))

        body = struct.pack(
            "!BBBBBBBB",
            1,
            15,
            2,
            1,
            len(user_bytes),
            len(port_bytes),
            len(rem_addr_bytes),
            len(data_bytes),
        )
        body += user_bytes + port_bytes + rem_addr_bytes + data_bytes

        version = 0xC0
        seq_no = 1
        encrypted_body = transform(body, session_id, key, version, seq_no)
        header = struct.pack(
            "!BBBBLL", version, 1, seq_no, 0, session_id, len(encrypted_body)
        )

        sock.sendall(header + encrypted_body)

        response_header = sock.recv(12)
        if len(response_header) != 12:
            return False

        r_ver, r_type, r_seq, _, r_sess, r_len = struct.unpack(
            "!BBBBLL", response_header
        )
        response_body = sock.recv(r_len) if r_len else b""

        if len(response_body) < r_len:
            return False

        decrypted = transform(response_body, r_sess, key, r_ver, r_seq)
        if len(decrypted) < 6:
            return False

        status = decrypted[0]
        return status == 1  # TAC_PLUS_AUTHEN_STATUS_PASS

    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def test_full_stack_all_components(server_factory):
    """Test all components working together in a single server"""
    server = server_factory(
        config={
            "log_level": "INFO",
            "auth_backends": "local",
            "admin_username": "admin",
            "admin_password": "FullStack123!",
        },
        enable_tacacs=True,
        enable_radius=True,
        enable_admin_api=True,
        enable_admin_web=True,
    )

    with server:
        # Setup: Create users and devices
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user(
            "stackuser", password="StackPass123", privilege_level=15
        )

        device_store = DeviceStore(str(server.devices_db))
        # Set TACACS secret on the device group (secrets are group-scoped)
        device_store.ensure_group(
            "default",
            description="Default group",
            metadata={"tacacs_secret": "stacksecret"},
        )
        # Add device to the group
        device_store.ensure_device(
            name="stack-device",
            network="127.0.0.1",
            group="default",
        )

        time.sleep(0.5)

        # Test 1: TACACS+ Authentication
        tacacs_success = tacacs_authenticate(
            "127.0.0.1",
            server.tacacs_port,
            "stacksecret",
            "stackuser",
            "StackPass123",
        )
        assert tacacs_success, "TACACS+ authentication should work"

        # Test 2: Admin Web Login
        web_session = server.login_admin()
        assert web_session, "Admin web login should work"

        # Test 3: Admin API Health Check
        base_url = server.get_base_url()
        response = web_session.get(f"{base_url}/api/health", timeout=5)
        assert response.status_code == 200, "Admin API health check should work"

        # Test 4: Verify all services in logs
        logs = server.get_logs()
        assert "TACACS" in logs or "tacacs" in logs.lower(), (
            "TACACS logs should be present"
        )
        assert "RADIUS" in logs or "radius" in logs.lower(), (
            "RADIUS logs should be present"
        )
        assert "admin" in logs or "monitoring" in logs.lower(), (
            "Admin logs should be present"
        )


def test_tacacs_and_admin_api_interaction(server_factory):
    """Test TACACS+ server with Admin API management"""
    server = server_factory(
        config={
            "auth_backends": "local",
            "admin_username": "admin",
            "admin_password": "admin123",
        },
        enable_tacacs=True,
        enable_admin_api=True,
    )

    with server:
        # Setup initial user via database
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("user1", password="Passw0rd1", privilege_level=15)

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group(
            "default",
            description="Default group",
            metadata={"tacacs_secret": "secret1"},
        )
        device_store.ensure_device(
            name="device1",
            network="127.0.0.1",
            group="default",
        )

        # Test TACACS+ authentication
        success = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret1", "user1", "Passw0rd1"
        )
        assert success, "Initial TACACS+ auth should work"

        # Admin API create a second user
        session = server.login_admin()
        base_url = server.get_base_url()
        response = session.post(
            f"{base_url}/api/users",
            json={
                "username": "user2",
                "password": "Passw0rd2",
                "privilege_level": 10,
            },
            timeout=5,
        )
        assert response.status_code in [200, 201], (
            f"Admin API user creation failed: {response.text}"
        )

        # Verify both users can authenticate
        success = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret1", "user2", "Passw0rd2"
        )
        assert success, "New user should authenticate via TACACS+"

        # Verify logs reflect activity
        logs = server.get_logs()
        assert "user1" in logs or "user2" in logs


def test_multiple_server_instances_isolation(server_factory, tmp_path):
    """Ensure multiple server instances remain isolated"""
    # Create two separate work directories
    work_dir1 = tmp_path / "server1"
    work_dir2 = tmp_path / "server2"
    work_dir1.mkdir()
    work_dir2.mkdir()

    from tests.conftest import ServerInstance

    # Create two servers with different configs
    server1 = ServerInstance(
        work_dir=work_dir1,
        config={"admin_username": "admin1", "admin_password": "Passw0rd1"},
        enable_tacacs=True,
    )

    server2 = ServerInstance(
        work_dir=work_dir2,
        config={"admin_username": "admin2", "admin_password": "Passw0rd2"},
        enable_tacacs=True,
    )

    with server1:
        with server2:
            # Both servers should have different ports
            assert server1.tacacs_port != server2.tacacs_port

            # Both should have separate config files
            assert server1.config_path != server2.config_path
            assert server1.config_path.exists()
            assert server2.config_path.exists()

            # Both should have separate databases
            assert server1.auth_db != server2.auth_db

            # Both should have separate logs
            assert server1.log_path != server2.log_path

            # Verify both are running
            logs1 = server1.get_logs()
            logs2 = server2.get_logs()

            assert len(logs1) > 0
            assert len(logs2) > 0

            # Logs should be independent
            assert logs1 != logs2


def test_server_restart_preserves_data(server_factory):
    """Test that restarting server preserves database data"""
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    # First run: Create user
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user(
            "persistent", password="PersistPass123", privilege_level=15
        )

        # Verify database file exists
        assert server.auth_db.exists()

    # Server stopped, database should still exist
    assert server.auth_db.exists()

    # Second run: User should still exist
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user = user_service.get_user("persistent")
        assert user is not None, "User should persist across restarts"
        # LocalUserRecord object exposes attributes
        assert getattr(user, "username", None) == "persistent"


def test_component_enable_disable_combinations(server_factory):
    """Test various combinations of enabled/disabled components"""
    # Test 1: Only TACACS+
    server = server_factory(
        enable_tacacs=True,
        enable_radius=False,
        enable_admin_api=False,
        enable_admin_web=False,
    )

    with server:
        assert server.tacacs_port is not None
        assert server.radius_auth_port is None
        assert server.web_port is None
        logs = server.get_logs()
        assert "TACACS" in logs or "tacacs" in logs.lower()

    # Test 2: Only RADIUS
    server = server_factory(
        enable_tacacs=False,
        enable_radius=True,
        enable_admin_api=False,
        enable_admin_web=False,
    )

    with server:
        # TACACS+ runs and must have a dedicated port even when only RADIUS is enabled
        assert server.tacacs_port is not None
        assert server.radius_auth_port is not None
        assert server.web_port is None

    # Test 3: Only Admin API (TACACS+ may still start depending on defaults)
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_tacacs=False,
        enable_radius=False,
        enable_admin_api=True,
        enable_admin_web=False,
    )

    with server:
        # Some builds may still start TACACS+ with default config; don't assert on its port
        assert server.radius_auth_port is None
        assert server.web_port is not None

        session = server.login_admin()
        response = session.get(f"{server.get_base_url()}/api/health", timeout=5)
        assert response.status_code == 200


def test_logs_contain_all_activity(server_factory):
    """Test that logs capture all server activity comprehensively"""
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
            "admin_username": "admin",
            "admin_password": "AdminPass123",
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
        user_service.create_user("logtest", password="LogPass123", privilege_level=15)

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group(
            "default",
            description="Default group",
            metadata={"tacacs_secret": "logsecret"},
        )
        device_store.ensure_device(
            name="log-device",
            network="127.0.0.1",
            group="default",
        )

        time.sleep(0.5)

        # Perform various activities
        # 1. TACACS+ auth
        tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "logsecret", "logtest", "LogPass123"
        )

        # 2. Admin login
        session = server.login_admin()
        # 3. API calls
        base_url = server.get_base_url()
        session.get(f"{base_url}/api/health", timeout=5)
        session.get(f"{base_url}/api/stats", timeout=5)
        # 4. Web page access
        session.get(f"{base_url}/admin", timeout=5)

    # Collect logs after server stops
    logs = server.get_logs()

    # Verify comprehensive logging
    assert logs, "Logs should not be empty"
    assert len(logs) > 500, "Logs should contain substantial content with DEBUG level"

    # Check for various activities
    log_lower = logs.lower()
    assert "logtest" in logs or "authentication" in log_lower, (
        "Auth activity should be logged"
    )
    assert "admin" in logs or "login" in log_lower, "Admin activity should be logged"
    assert "health" in log_lower or "api" in log_lower or "stats" in log_lower, (
        "API calls should be logged"
    )
