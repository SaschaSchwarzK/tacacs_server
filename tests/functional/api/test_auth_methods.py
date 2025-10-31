"""
API auth method tests: session cookie vs API token vs unauthenticated.
"""

import os
import requests


def test_api_auth_with_session(server_factory):
    """Test API authentication using session-based authentication.

    Verifies that:
    - An admin can authenticate using session cookies
    - The session allows access to protected API endpoints
    - The /api/stats endpoint returns 200 OK for authenticated sessions

    Test Steps:
    1. Create a test server with admin credentials
    2. Log in to create a session
    3. Access a protected endpoint with the session

    Expected Result:
    - The request should return status code 200 (OK)
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

    Verifies that:
    - API requests with a valid Bearer token are authenticated
    - The token is read from the environment variable
    - The /api/status endpoint is accessible with a valid token

    Test Steps:
    1. Set up a test API token in the environment
    2. Create a test server with API enabled
    3. Make a request with the Bearer token in the Authorization header

    Expected Result:
    - The request should return status code 200 (OK)
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

    Verifies that:
    - Unauthenticated requests to protected endpoints are rejected
    - The API enforces authentication requirements

    Test Steps:
    1. Create a test server with API enabled
    2. Make an unauthenticated request to a protected endpoint

    Expected Result:
    - The request should be rejected with status code 401 (Unauthorized) or 403 (Forbidden)
    """
    server = server_factory(
        config={"admin_username": "admin", "admin_password": "admin123"},
        enable_admin_api=True,
    )
    with server:
        base = server.get_base_url()
        r = requests.get(f"{base}/api/stats", timeout=5)
        assert r.status_code in [401, 403]
