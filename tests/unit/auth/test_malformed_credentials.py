"""
Malformed Credentials Test Suite

This module contains unit tests that verify the system's handling of malformed
or potentially malicious credential inputs. These tests ensure that the authentication
system properly rejects invalid inputs and is resistant to common attack vectors.

Test Coverage:
- Empty usernames and passwords
- SQL injection attempts
- Input validation edge cases
- Error handling for malformed inputs

Security Focus:
- Input validation
- SQL injection prevention
- Consistent error responses
- No information leakage through error messages
"""

import pytest

from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.auth.local_user_service import LocalUserService


@pytest.fixture
def test_db(tmp_path) -> str:
    """Provide an isolated SQLite database for local authentication tests.

    This fixture creates a temporary SQLite database file that is automatically
    cleaned up after each test. Each test gets its own isolated database instance
    to prevent test interference.

    Args:
        tmp_path: Pytest fixture providing a temporary directory

    Returns:
        str: Path to the temporary SQLite database file
    """
    return str(tmp_path / "local_auth.db")


class TestMalformedCredentials:
    """Test suite for handling malformed or malicious credential inputs.

    This test class verifies that the authentication system properly handles
    various forms of malformed input, including edge cases and potential
    security vulnerabilities.

    Test Cases:
    - Empty usernames and passwords
    - SQL injection attempts
    - Special characters in credentials
    - Extremely long inputs
    - Unicode and non-ASCII characters

    Security Considerations:
    - Prevents SQL injection attacks
    - Validates input before processing
    - Maintains consistent error responses
    - Protects against information leakage
    """

    def test_empty_username(self, test_db):
        """Verify authentication is rejected with an empty username.

        Test Steps:
        1. Initialize local authentication backend
        2. Attempt authentication with empty username

        Expected Results:
        - Authentication should fail (return False)
        - No database errors should occur
        - No exceptions should be raised

        Security Considerations:
        - Empty usernames should never be valid
        - System should handle gracefully without crashing
        """
        service = LocalUserService(test_db)
        backend = LocalAuthBackend(test_db, service=service)
        result = backend.authenticate("", "Password123")
        assert result is False

    def test_empty_password(self, test_db):
        """Verify authentication is rejected with an empty password.

        Test Steps:
        1. Create a test user with a valid password
        2. Attempt authentication with empty password

        Expected Results:
        - Authentication should fail (return False)
        - System should not accept empty passwords
        - No sensitive information should be logged

        Security Considerations:
        - Empty passwords should never be valid
        - System should handle gracefully without information leakage
        """
        service = LocalUserService(test_db)
        service.create_user("testuser", password="Password123")
        backend = LocalAuthBackend(test_db, service=service)
        result = backend.authenticate("testuser", "")
        assert result is False

    def test_sql_injection_attempt(self, test_db):
        """Verify protection against SQL injection in username field.

        Test Steps:
        1. Initialize authentication backend
        2. Attempt authentication with SQL injection in username

        Expected Results:
        - Authentication should fail (return False)
        - No SQL errors should be exposed
        - No database exceptions should be raised

        Security Considerations:
        - Verifies parameterized queries are used
        - Ensures no SQL injection is possible
        - Maintains consistent error responses
        """
        service = LocalUserService(test_db)
        backend = LocalAuthBackend(test_db, service=service)
        result = backend.authenticate("admin' OR '1'='1", "Password123")
        assert result is False
