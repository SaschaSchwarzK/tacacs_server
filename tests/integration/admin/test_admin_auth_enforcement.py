import pytest
import requests


@pytest.mark.integration
def test_admin_endpoints_require_auth(server_factory):
    """Verify all admin endpoints properly enforce authentication.

    This test explicitly verifies that admin endpoints cannot be accessed
    without proper authentication, even in test environments.
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
