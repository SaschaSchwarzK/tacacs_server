"""Fixed full stack integration tests"""
import hashlib
import socket
import struct
import time

def tacacs_authenticate(host: str, port: int, key: str, username: str, password: str) -> bool:
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
        body = struct.pack("!BBBBBBBB", 1, 15, 2, 1, len(user_bytes), len(port_bytes), len(rem_addr_bytes), len(data_bytes))
        body += user_bytes + port_bytes + rem_addr_bytes + data_bytes
        version = 0xC0
        seq_no = 1
        encrypted_body = transform(body, session_id, key, version, seq_no)
        header = struct.pack("!BBBBLL", version, 1, seq_no, 0, session_id, len(encrypted_body))
        sock.sendall(header + encrypted_body)
        response_header = sock.recv(12)
        if len(response_header) != 12:
            return False
        r_ver, r_type, r_seq, _, r_sess, r_len = struct.unpack("!BBBBLL", response_header)
        response_body = sock.recv(r_len) if r_len else b""
        if len(response_body) < r_len:
            return False
        decrypted = transform(response_body, r_sess, key, r_ver, r_seq)
        if len(decrypted) < 6:
            return False
        status = decrypted[0]
        return status == 1
    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

def test_full_stack_all_components(server_factory):
    # Updated: ensure admin credentials match what server_factory expects
    server = server_factory(
        config={
            "log_level": "INFO",
            "auth_backends": "local",
            "admin": {"username": "admin", "password": "FullStack123!"}
        },
        enable_tacacs=True,
        enable_radius=True,
        enable_admin_api=True,
        enable_admin_web=True,
    )
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("stackuser", password="StackPass123", privilege_level=15)
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", description="Default group", metadata={"tacacs_secret": "stacksecret"})
        device_store.ensure_device(name="stack-device", network="127.0.0.1", group="default")
        time.sleep(0.5)
        tacacs_success = tacacs_authenticate("127.0.0.1", server.tacacs_port, "stacksecret", "stackuser", "StackPass123")
        assert tacacs_success, "TACACS+ authentication should work"
        web_session = server.login_admin()
        assert web_session, "Admin web login should work"
        base_url = server.get_base_url()
        response = web_session.get(f"{base_url}/api/health", timeout=5)
        assert response.status_code == 200, "Admin API health check should work"
        logs = server.get_logs()
        assert "TACACS" in logs or "tacacs" in logs.lower(), "TACACS logs should be present"
        assert "RADIUS" in logs or "radius" in logs.lower(), "RADIUS logs should be present"
        assert "admin" in logs or "monitoring" in logs.lower(), "Admin logs should be present"

def test_tacacs_and_admin_api_interaction(server_factory):
    server = server_factory(
        config={"auth_backends": "local", "admin": {"username": "admin", "password": "admin123"}},
        enable_tacacs=True,
        enable_admin_api=True,
    )
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("user1", password="Passw0rd1", privilege_level=15)
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", description="Default group", metadata={"tacacs_secret": "secret1"})
        device_store.ensure_device(name="device1", network="127.0.0.1", group="default")
        success = tacacs_authenticate("127.0.0.1", server.tacacs_port, "secret1", "user1", "Passw0rd1")
        assert success, "Initial TACACS+ auth should work"
        session = server.login_admin()
        base_url = server.get_base_url()
        response = session.post(f"{base_url}/api/users", json={"username": "user2", "password": "Passw0rd2", "privilege_level": 10}, timeout=5)
        assert response.status_code in [200, 201], f"Admin API user creation failed: {response.text}"
        success = tacacs_authenticate("127.0.0.1", server.tacacs_port, "secret1", "user2", "Passw0rd2")
        assert success, "New user should authenticate via TACACS+"
        logs = server.get_logs()
        assert "user1" in logs or "user2" in logs

def test_multiple_server_instances_isolation(server_factory, tmp_path):
    work_dir1 = tmp_path / "server1"
    work_dir2 = tmp_path / "server2"
    work_dir1.mkdir()
    work_dir2.mkdir()
    from tests.conftest import ServerInstance
    server1 = ServerInstance(work_dir=work_dir1, config={"admin": {"username": "admin1", "password": "Passw0rd1"}}, enable_tacacs=True)
    server2 = ServerInstance(work_dir=work_dir2, config={"admin": {"username": "admin2", "password": "Passw0rd2"}}, enable_tacacs=True)
    with server1:
        with server2:
            assert server1.tacacs_port != server2.tacacs_port
            assert server1.config_path != server2.config_path
            assert server1.config_path.exists()
            assert server2.config_path.exists()
            assert server1.auth_db != server2.auth_db
            assert server1.log_path != server2.log_path
            logs1 = server1.get_logs()
            logs2 = server2.get_logs()
            assert len(logs1) > 0
            assert len(logs2) > 0
            assert logs1 != logs2

def test_server_restart_preserves_data(server_factory):
    server = server_factory(config={"auth_backends": "local"}, enable_tacacs=True)
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("persistent", password="PersistPass123", privilege_level=15)
        assert server.auth_db.exists()
    assert server.auth_db.exists()
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))
        user = user_service.get_user("persistent")
        assert user is not None, "User should persist across restarts"
        assert getattr(user, "username", None) == "persistent"

def test_component_enable_disable_combinations(server_factory):
    server = server_factory(enable_tacacs=True, enable_radius=False, enable_admin_api=False, enable_admin_web=False)
    with server:
        assert server.tacacs_port is not None
        assert server.radius_auth_port is None
        assert server.web_port is None
        logs = server.get_logs()
        assert "TACACS" in logs or "tacacs" in logs.lower()
    server = server_factory(enable_tacacs=False, enable_radius=True, enable_admin_api=False, enable_admin_web=False)
    with server:
        assert server.tacacs_port is not None
        assert server.radius_auth_port is not None
        assert server.web_port is None
    server = server_factory(config={"admin": {"username": "admin", "password": "admin123"}}, enable_tacacs=False, enable_radius=False, enable_admin_api=True, enable_admin_web=False)
    with server:
        assert server.radius_auth_port is None
        assert server.web_port is not None
        session = server.login_admin()
        response = session.get(f"{server.get_base_url()}/api/health", timeout=5)
        assert response.status_code == 200

def test_logs_contain_all_activity(server_factory):
    server = server_factory(
        config={
            "log_level": "DEBUG",
            "auth_backends": "local",
            "admin": {"username": "admin", "password": "AdminPass123"}
        },
        enable_tacacs=True,
        enable_radius=True,
        enable_admin_api=True,
        enable_admin_web=True,
    )
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore
        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("logtest", password="LogPass123", privilege_level=15)
        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", description="Default group", metadata={"tacacs_secret": "logsecret"})
        device_store.ensure_device(name="log-device", network="127.0.0.1", group="default")
        time.sleep(0.5)
        tacacs_authenticate("127.0.0.1", server.tacacs_port, "logsecret", "logtest", "LogPass123")
        session = server.login_admin()
        base_url = server.get_base_url()
        session.get(f"{base_url}/api/health", timeout=5)
        session.get(f"{base_url}/api/stats", timeout=5)
        session.get(f"{base_url}/admin", timeout=5)
    logs = server.get_logs()
    assert logs, "Logs should not be empty"
    assert len(logs) > 500, "Logs should contain substantial content with DEBUG level"
    log_lower = logs.lower()
    assert "logtest" in logs or "authentication" in log_lower, "Auth activity should be logged"
    assert "admin" in logs or "login" in log_lower, "Admin activity should be logged"
    assert "health" in log_lower or "api" in log_lower or "stats" in log_lower, "API calls should be logged"
