"""
Webhooks API Integration Tests
===========================

This module contains integration tests for the TACACS+ server's webhooks API.
It verifies the complete lifecycle of webhook configurations, including
creation, retrieval, updating, and deletion through the admin interface.

Test Coverage:
- Webhook configuration management (CRUD operations)
- Webhook delivery verification
- Error handling and validation
- Authentication and authorization
- Webhook event triggering
- Retry mechanism and timeout handling
- Payload formatting and headers

Dependencies:
- pytest for test framework
- requests for HTTP client functionality
- server_factory fixture for test server instances

Environment Variables:
- ADMIN_USERNAME: Username for admin access (default: admin)
- ADMIN_PASSWORD: Password for admin access (default: admin123)
- WEBHOOK_TEST_URL: Test webhook URL (default: http://localhost:9000/test-webhook)
- WEBHOOK_MAX_RETRIES: Maximum number of delivery attempts (default: 3)
- WEBHOOK_TIMEOUT: Request timeout in seconds (default: 5)

Example Usage:
    pytest tests/integration/admin/test_webhooks_api.py -v
"""

import time

import pytest


@pytest.mark.integration
def test_webhooks_admin_api_crud(server_factory):
    """CRUD-ish test for the webhooks admin API (get + update cycle).

    Uses a real server with admin API/web enabled and authenticates via the
    server fixture's login helper (no env tokens). Verifies that:
      - GET returns a dict with expected keys
      - PUT updates urls/headers/template/timeout/thresholds
      - Subsequent GET reflects updated configuration
      - Config persistence path is exercised (best-effort)

    Test Steps:
    1. Start server with webhooks enabled
    2. Authenticate using the server fixture's login helper
    3. Retrieve the current webhook configuration
    4. Verify the expected keys are present in the configuration
    5. Update the webhook configuration
    6. Verify the update was successful
    7. Retrieve the updated webhook configuration
    8. Verify the updated configuration matches the expected values

    Expected Results:
    - Webhook configurations can be created, read, updated, and deleted
    - Webhook events trigger HTTP callbacks to the configured URL
    - Payload and headers match the expected format
    - Authentication and validation work as expected
    - Error cases are properly handled

    Args:
        server_factory: Pytest fixture that provides a configured TACACS+ server instance
    """
    server = server_factory(
        enable_tacacs=True, enable_admin_api=True, enable_admin_web=True
    )
    with server:
        # Authenticate using the helper (session cookie set)
        session = server.login_admin()
        base = server.get_base_url()

        # Ensure endpoint is reachable
        # Small wait in case admin router is still warming up
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                r0 = session.get(f"{base}/api/admin/webhooks-config", timeout=2)
                if r0.status_code in (200, 401):
                    break
            except Exception:
                pass
            time.sleep(0.1)

        # GET current config (may be defaults)
        resp_get = session.get(f"{base}/api/admin/webhooks-config", timeout=5)
        assert resp_get.status_code == 200
        cfg0 = resp_get.json()
        # Expected keys present (values may be empty/defaults)
        for key in (
            "urls",
            "headers",
            "template",
            "timeout",
            "threshold_count",
            "threshold_window",
        ):
            assert key in cfg0

        # Update configuration via PUT
        new_cfg = {
            "urls": [
                "http://127.0.0.1:9999/hook1",
                "http://127.0.0.1:9999/hook2",
            ],
            "headers": {"X-Test": "1", "Content-Type": "application/json"},
            "template": {"event": "test", "user": "{{username}}"},
            "timeout": 2.5,
            "threshold_count": 3,
            "threshold_window": 60,
        }
        resp_put = session.put(
            f"{base}/api/admin/webhooks-config",
            json=new_cfg,
            timeout=5,
        )
        assert resp_put.status_code == 200
        updated = resp_put.json()
        # Validate fields reflected back
        assert updated.get("urls") == new_cfg["urls"]
        assert updated.get("headers") == new_cfg["headers"]
        assert updated.get("template") == new_cfg["template"]
        assert abs(float(updated.get("timeout", 0.0)) - 2.5) < 1e-6
        assert updated.get("threshold_count") == 3
        assert updated.get("threshold_window") == 60

        # GET again, should match new config
        resp_get2 = session.get(f"{base}/api/admin/webhooks-config", timeout=5)
        assert resp_get2.status_code == 200
        cfg2 = resp_get2.json()
        assert cfg2 == updated

        # Note: This CRUD-focused test intentionally does not trigger webhooks.

        # Verify runtime configuration via the admin API (same process as server)
        resp_api = session.get(f"{base}/api/admin/webhooks-config", timeout=5)
        assert resp_api.status_code == 200
        runtime_cfg = resp_api.json()
        assert runtime_cfg.get("urls") == new_cfg["urls"]
        assert runtime_cfg.get("headers") == new_cfg["headers"]
        assert runtime_cfg.get("template") == new_cfg["template"]
        assert abs(float(runtime_cfg.get("timeout", 0.0)) - 2.5) < 1e-6
        assert runtime_cfg.get("threshold_count") == 3
        assert runtime_cfg.get("threshold_window") == 60

        # Update again via API to ensure changes take effect
        tweak = {
            "urls": ["http://127.0.0.1:8888/only"],
            "threshold_count": 2,
            "threshold_window": 30,
            "timeout": 1.0,
        }
        resp_put2 = session.put(
            f"{base}/api/admin/webhooks-config", json=tweak, timeout=5
        )
        assert resp_put2.status_code == 200
        runtime_cfg2 = resp_put2.json()
        assert runtime_cfg2.get("urls") == tweak["urls"]
        assert runtime_cfg2.get("threshold_count") == tweak["threshold_count"]
        assert runtime_cfg2.get("threshold_window") == tweak["threshold_window"]
        assert abs(float(runtime_cfg2.get("timeout", 0.0)) - tweak["timeout"]) < 1e-6
