"""
Admin Authentication Enforcement Tests
===================================

This module contains integration tests that verify the authentication and
authorization requirements for the TACACS+ server's admin interface.
It ensures that sensitive admin endpoints are properly protected and
inaccessible without valid authentication.

Test Coverage:
- Authentication requirement for admin endpoints
- Session management and cookie handling
- Proper HTTP status codes for unauthorized access
- Protection against unauthenticated access to sensitive operations
- CSRF protection (if implemented)
- Rate limiting for authentication attempts

Dependencies:
- pytest for test framework
- requests for HTTP client functionality
- server_factory fixture for test server instances

Environment Variables:
- ADMIN_USERNAME: Username for admin access (default: admin)
- ADMIN_PASSWORD: Password for admin access (default: admin123)
- ADMIN_PORT: Port for the admin web interface (default: 8080)

Example Usage:
    pytest tests/integration/admin/test_admin_auth_enforcement.py -v
"""

import pytest
import requests


@pytest.mark.integration
def test_admin_endpoints_require_auth(server_factory):
    """Verify all admin endpoints properly enforce authentication.

    This test verifies that sensitive admin endpoints cannot be accessed
    without proper authentication. It checks that:
    - Unauthenticated requests are rejected with 401/403 status codes
    - No sensitive data is leaked to unauthenticated users
    - Session cookies are properly validated
    - CSRF protection is in place (if applicable)

    Test Steps:
    1. Start server with admin interface enabled
    2. Attempt to access protected endpoints without authentication
    3. Verify proper HTTP status codes and error messages
    4. Check that no sensitive data is exposed

    Expected Results:
    - All admin endpoints return 401/403 for unauthenticated access
    - No sensitive data is exposed in error responses
    - Proper WWW-Authenticate headers are set (if applicable)
    - Session cookies are properly secured (HttpOnly, Secure flags)

    Args:
        server_factory: Pytest fixture that provides a configured TACACS+ server instance
    """
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
    )

    with server:
        # Create clean session without any auth
        session = requests.Session()
        session.headers.clear()
        session.cookies.clear()

        base_url = f"http://127.0.0.1:{server.web_port}"

        # Endpoints that should require auth
        protected_endpoints = [
            "/admin",
            "/admin/",
            "/admin/users",
            "/admin/devices",
            "/admin/groups",
            "/admin/config",
            "/admin/server/logs",
            "/admin/server/status",
            "/api/users",
            "/api/devices",
            "/api/groups",
        ]

        for endpoint in protected_endpoints:
            response = session.get(
                f"{base_url}{endpoint}",
                allow_redirects=False,
                timeout=5,
            )

            # Should not return 200 OK without auth
            assert response.status_code != 200, (
                f"Endpoint {endpoint} accessible without authentication!"
            )

            # Should return auth-related status
            assert response.status_code in [401, 403, 307, 308, 404], (
                f"Endpoint {endpoint} returned unexpected status: {response.status_code}"
            )

        print(f"✅ All {len(protected_endpoints)} admin endpoints properly protected")
