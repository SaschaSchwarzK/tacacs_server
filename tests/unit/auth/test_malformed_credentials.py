"""Unit tests for local authentication edge cases."""
import pytest
from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.auth.local_user_service import LocalUserService


@pytest.fixture
def test_db(tmp_path) -> str:
    """Provide an isolated SQLite path for local auth tests."""
    return str(tmp_path / "local_auth.db")


class TestMalformedCredentials:
    """Test handling of malformed input."""
    
    def test_empty_username(self, test_db):
        """Test authentication with empty username."""
        service = LocalUserService(test_db)
        backend = LocalAuthBackend(test_db, service=service)
        result = backend.authenticate("", "Password123")
        assert result is False
    
    def test_empty_password(self, test_db):
        """Test authentication with empty password."""
        service = LocalUserService(test_db)
        service.create_user("testuser", password="Password123")
        backend = LocalAuthBackend(test_db, service=service)
        result = backend.authenticate("testuser", "")
        assert result is False
    
    def test_sql_injection_attempt(self, test_db):
        """Test protection against SQL injection."""
        service = LocalUserService(test_db)
        backend = LocalAuthBackend(test_db, service=service)
        result = backend.authenticate("admin' OR '1'='1", "Password123")
        assert result is False
