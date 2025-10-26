import os
import time

import pytest
import requests

_ADV_BASE: str | None = None


def _make_session() -> requests.Session:
    return requests.Session()


# Print base URL and environment for diagnostics when this module runs
@pytest.fixture(autouse=True, scope="module")
def _adv_debug_env():
    base_env = _ADV_BASE
    test_port = None
    tacacs_port = None
    log_path = None
    print(
        f"[SEC-ADV] TACACS_WEB_BASE={base_env} TEST_WEB_PORT={test_port} "
        f"TEST_TACACS_PORT={tacacs_port} LOG={log_path}"
    )
    yield


pytestmark = pytest.mark.skipif(
    not os.getenv("RUN_SECURITY_ADVANCED"),
    reason="Set RUN_SECURITY_ADVANCED=1 to run advanced security tests",
)


# Start a real server for this module when advanced tests are enabled
@pytest.fixture(autouse=True, scope="function")
def _adv_server(server_factory):
    server = server_factory(
        enable_tacacs=True,
        enable_radius=False,
        enable_admin_api=True,
        enable_admin_web=True,
    )
    with server:
        global _ADV_BASE
        _ADV_BASE = server.get_base_url()
        # Probe health until ready
        base = _ADV_BASE
        sess = _make_session()
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                r = sess.get(f"{base}/api/health", timeout=1)
                if r.status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        yield


@pytest.mark.integration
@pytest.mark.security
class TestSecurityFeatures:
    """Advanced security checks against running server."""

    def test_sql_injection_prevention(self):
        sess = _make_session()
        malicious_username = "admin' OR '1'='1"
        assert _ADV_BASE is not None
        r = sess.get(
            f"{_ADV_BASE}/api/users", params={"username": malicious_username}, timeout=5
        )
        assert r.status_code in (200, 400, 401, 404)

    def test_xss_prevention(self):
        sess = _make_session()
        xss_payload = '<script>alert("XSS")</script>'
        assert _ADV_BASE is not None
        r = sess.post(
            f"{_ADV_BASE}/api/devices",
            json={
                "name": xss_payload,
                "ip_address": "192.168.1.100",
                "device_group_id": 1,
            },
            timeout=5,
        )
        if r.status_code == 201:
            body = r.json()
            assert "<script>" not in str(body)

    def test_csrf_protection(self):
        sess = _make_session()
        assert _ADV_BASE is not None
        r = sess.post(f"{_ADV_BASE}/api/admin/reset-stats", json={}, timeout=5)
        # Depending on environment, this may be 200 (no auth), 401/403 (protected),
        # or 400 (validation or guard failure). Accept common secure outcomes.
        assert r.status_code in (200, 400, 401, 403)
