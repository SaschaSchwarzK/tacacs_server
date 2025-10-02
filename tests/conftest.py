"""
Test configuration and fixtures
"""

import pytest
import tempfile
import shutil
from pathlib import Path

from tacacs_server.auth.local_user_service import LocalUserService
from tacacs_server.auth.local_store import LocalAuthStore


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
    username = f'testuser_{uuid.uuid4().hex[:8]}'
    return user_service.create_user(username, password='TestPass123')


@pytest.fixture
def server_process():
    """Mock server process for integration tests."""
    return {
        "host": "127.0.0.1",
        "port": 49,
        "secret": "test123"
    }


@pytest.fixture
def run_test_client():
    """Mock test client runner."""
    def _run_client(host, port, secret, username, password):
        from types import SimpleNamespace
        return SimpleNamespace(
            returncode=0,
            stdout="✓ Authentication PASSED",
            stderr=""
        )
    return _run_client