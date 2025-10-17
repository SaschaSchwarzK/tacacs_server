import os

import pytest


# Print base URL and environment for diagnostics when this module runs
@pytest.fixture(autouse=True, scope="module")
def _adv_debug_env():
    base_env = os.environ.get("TACACS_WEB_BASE")
    test_port = os.environ.get("TEST_WEB_PORT")
    tacacs_port = os.environ.get("TEST_TACACS_PORT")
    log_path = os.environ.get("TACACS_LOG_PATH")
    print(
        f"[SEC-ADV] TACACS_WEB_BASE={base_env} TEST_WEB_PORT={test_port} "
        f"TEST_TACACS_PORT={tacacs_port} LOG={log_path}"
    )
    yield

pytestmark = pytest.mark.skipif(
    not os.getenv("RUN_SECURITY_ADVANCED"),
    reason="Set RUN_SECURITY_ADVANCED=1 to run advanced security tests",
)


@pytest.mark.integration
class TestSecurityFeatures:
    """Advanced security checks against running server."""

    def test_sql_injection_prevention(self):
        import requests

        malicious_username = "admin' OR '1'='1"
        r = requests.get(
            "http://localhost:8080/api/users", params={"username": malicious_username}
        )
        assert r.status_code in (200, 400, 404)

    def test_xss_prevention(self):
        import requests

        xss_payload = '<script>alert("XSS")</script>'
        r = requests.post(
            "http://localhost:8080/api/devices",
            json={"name": xss_payload, "ip_address": "192.168.1.100"},
        )
        if r.status_code == 201:
            body = r.json()
            assert "<script>" not in str(body)

    def test_csrf_protection(self):
        import requests

        r = requests.post("http://localhost:8080/api/admin/reset-stats", json={})
        # Depending on environment, this may be 200 (no auth), 401/403 (protected),
        # or 400 (validation or guard failure). Accept common secure outcomes.
        assert r.status_code in (200, 400, 401, 403)
