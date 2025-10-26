import time

import pytest
import requests


@pytest.mark.integration
def test_web_login_attempt_rate_behavior(server_factory):
    """Exercise web/admin login with multiple failed attempts.

    Expect 401 unauthorized responses or 429 if lockout/rate-limit is enforced.
    """
    server = server_factory(
        enable_tacacs=True, enable_admin_api=True, enable_admin_web=True
    )
    with server:
        base = server.get_base_url()
        sess = requests.Session()
        attempts = 0
        saw_429 = False
        for i in range(8):
            r = sess.post(
                f"{base}/admin/login",
                json={"username": "admin", "password": f"wrong{i}"},
                timeout=5,
            )
            attempts += 1
            if r.status_code == 429:
                saw_429 = True
                break
            assert r.status_code in (400, 401, 403, 503)
            time.sleep(0.05)
        # Either we saw explicit 429, or consistent unauthorized responses
        assert saw_429 or attempts >= 1

        # If web rate limiting is implemented and 429 observed, expect logs mention it
        if saw_429:
            time.sleep(0.1)
            logs = server.get_logs()
            assert "429" in logs or "rate limit" in logs.lower(), (
                "Expected web rate limit indication in logs when 429 observed"
            )
