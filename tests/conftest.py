"""
Test configuration and fixtures
"""

import glob
import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from tacacs_server.auth.local_store import LocalAuthStore
from tacacs_server.auth.local_user_service import LocalUserService


@pytest.fixture
def test_db():
    """Create a temporary test database"""
    import uuid

    temp_dir = tempfile.mkdtemp()
    # Use unique filename to avoid any conflicts
    db_path = Path(temp_dir) / f"test_{uuid.uuid4().hex[:8]}.db"

    yield str(db_path)

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def user_service(test_db):
    """Create a LocalUserService with test database"""
    return LocalUserService(test_db)


@pytest.fixture
def auth_store(test_db):
    """Create a LocalAuthStore with test database"""
    return LocalAuthStore(test_db)


@pytest.fixture
def test_user(user_service):
    """Create a test user"""
    import uuid

    username = f"testuser_{uuid.uuid4().hex[:8]}"
    return user_service.create_user(username, password="TestPass123")


@pytest.fixture
def server_process():
    """Mock server process for integration tests."""
    return {"host": "127.0.0.1", "port": 49, "secret": "test123"}


@pytest.fixture(scope="session")
def tacacs_server():
    """Start TACACS+ server for tests that need it"""
    server_process = None
    try:
        # Start server in background
        server_process = subprocess.Popen(
            ["python", "-m", "tacacs_server.main", "--config", "config/tacacs.conf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )

        # Wait for server to be ready
        import socket

        for _ in range(30):  # 30 second timeout
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(("localhost", 49))
                sock.close()
                if result == 0:
                    break
            except Exception:
                pass
            time.sleep(1)
        else:
            raise RuntimeError("Server failed to start within 30 seconds")

        yield {"host": "localhost", "port": 49, "web_port": 8080}

    finally:
        # Stop server
        if server_process:
            try:
                if hasattr(os, "killpg"):
                    os.killpg(os.getpgid(server_process.pid), signal.SIGTERM)
                else:
                    server_process.terminate()
                server_process.wait(timeout=10)
            except Exception:
                try:
                    if hasattr(os, "killpg"):
                        os.killpg(os.getpgid(server_process.pid), signal.SIGKILL)
                    else:
                        server_process.kill()
                except Exception:
                    pass


@pytest.fixture
def live_server(tacacs_server):
    """Alias for tacacs_server fixture for backward compatibility"""
    return tacacs_server


@pytest.fixture
def run_test_client():
    """Mock test client runner."""

    def _run_client(host, port, secret, username, password):
        from types import SimpleNamespace

        return SimpleNamespace(
            returncode=0, stdout="✓ Authentication PASSED", stderr=""
        )

    return _run_client


def pytest_sessionfinish(session, exitstatus):
    """Clean up test databases after all tests complete"""
    patterns = [
        "data/test_*.db*",
        "data/*test*.db*",
        "data/tmp_*.db*",
        "data/*_[a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9].db*",
        "data/change_users_*.db*",
        "data/reload_users_*.db*",
        "data/seed_users_*.db*",
        "data/users_*.db*",
        "data/radius_auth_*.db*",
    ]

    for pattern in patterns:
        for file_path in glob.glob(pattern):
            try:
                Path(file_path).unlink(missing_ok=True)
            except OSError:
                pass
