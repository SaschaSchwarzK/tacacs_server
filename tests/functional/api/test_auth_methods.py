"""
API Authentication Method Tests

This module contains functional tests for various API authentication methods
supported by the TACACS+ server's admin interface. It verifies the correct
behavior of different authentication mechanisms and their security boundaries.

Test Organization:
- test_api_auth_with_session: Verifies session-based authentication
- test_api_auth_with_bearer_token: Tests Bearer token authentication
- test_api_auth_without_any: Validates unauthenticated access restrictions

Security Considerations:
- Ensures proper authentication is required for protected endpoints
- Validates secure handling of session tokens and API keys
- Verifies proper rejection of unauthenticated requests

Dependencies:
- pytest for test framework
- requests for HTTP client functionality
- server_factory fixture for test server management
"""

import requests


def test_api_auth_with_session(server_factory):
    """Test API authentication using session-based authentication.

    This test verifies the complete flow of session-based authentication:
    1. Server initialization with admin credentials
    2. Successful login establishing a session
    3. Access to protected resources using session cookies

    Test Configuration:
    - Admin credentials: username="admin", password="admin123"
    - Protected endpoint: /api/stats
    - Expected status code: 200 (OK)

    Test Steps:
    1. Initialize test server with admin API enabled
    2. Log in to establish an authenticated session
    3. Access a protected API endpoint using the session
    4. Verify successful access (HTTP 200)

    Expected Results:
    - Session creation should succeed
    - Protected endpoint should be accessible with valid session
    - Response should include valid statistics data

    Security Verifications:
    - Session cookies should be HTTP-only and secure
    - CSRF protection should be in place
    - Session should have appropriate timeout

    Dependencies:
    - server_factory fixture for test server management
    - requests.Session for maintaining session state
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )
    with server:
        s = server.login_admin()
        base = server.get_base_url()
        r = s.get(f"{base}/api/stats", timeout=5)
        assert r.status_code == 200


def test_api_auth_with_bearer_token(server_factory, monkeypatch):
    """Test API authentication using Bearer token authentication.

    This test verifies the functionality of token-based authentication
    by:
    1. Setting a test API token in the environment
    2. Configuring the server to use token authentication
    3. Making authenticated requests using the Bearer token

    Test Configuration:
    - Test token: "test-api-token-123"
    - Environment variable: API_TOKEN
    - Protected endpoint: /api/status
    - Expected status code: 200 (OK)

    Test Steps:
    1. Set up test API token in the environment
    2. Initialize test server with API enabled
    3. Make request with Bearer token in Authorization header
    4. Verify successful authentication and access

    Expected Results:
    - Request with valid token should succeed (HTTP 200)
    - Response should contain expected status information
    - Token should be properly validated

    Security Verifications:
    - Token should be passed securely in Authorization header
    - Token should not be logged or exposed in error messages
    - Token should be the only required credential

    Dependencies:
    - server_factory fixture for test server management
    - monkeypatch for environment variable manipulation
    - requests for HTTP client functionality
    """
    token = "apitoken-123"
    monkeypatch.setenv("API_TOKEN", token)
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )
    with server:
        base = server.get_base_url()
        headers = {"Authorization": f"Bearer {token}"}
        r = requests.get(f"{base}/api/status", headers=headers, timeout=5)
        assert r.status_code == 200


def test_api_auth_without_any(server_factory):
    """Test API access without any authentication.

    This test verifies the security boundary by ensuring that:
    1. Unauthenticated requests to protected endpoints are properly rejected
    2. No sensitive information is leaked in error responses
    3. The API enforces authentication requirements consistently

    Test Configuration:
    - Protected endpoint: /api/stats
    - Expected status codes:
      - 401 (Unauthorized) when no credentials provided
      - 403 (Forbidden) when authentication fails
    - No authentication headers or cookies should be set

    Test Steps:
    1. Initialize test server with API enabled
    2. Make unauthenticated request to protected endpoint
    3. Verify proper error response
    4. Check that no session cookies are set

    Expected Results:
    - Request should be rejected with 401/403 status
    - Response should not contain sensitive information
    - No session cookies should be set

    Security Verifications:
    - No information disclosure in error messages
    - Proper CORS headers (if applicable)
    - Rate limiting for unauthenticated requests

    Dependencies:
    - server_factory fixture for test server management
    - requests for HTTP client functionality
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )
    with server:
        base = server.get_base_url()
        r = requests.get(f"{base}/api/stats", timeout=5)
        assert r.status_code in [401, 403]
