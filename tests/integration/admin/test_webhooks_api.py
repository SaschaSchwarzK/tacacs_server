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

        # Validate persistence to tacacs.conf (after runtime tweak below, the
        # timeout/thresholds will reflect the latest values)
        import configparser
        import json as _json

        parser = configparser.ConfigParser(interpolation=None)
        parser.read(server.config_path)
        assert parser.has_section("webhooks"), "webhooks section missing in config file"
        wh_section = parser["webhooks"]

        # urls stored as comma-separated string
        urls_raw = wh_section.get("urls", "")
        urls_list = [u.strip() for u in urls_raw.split(",") if u.strip()]
        assert urls_list == new_cfg["urls"]

        # headers/template stored as JSON
        headers_json = wh_section.get("headers_json", "{}")
        template_json = wh_section.get("template_json", "{}")
        try:
            headers_parsed = _json.loads(headers_json) if headers_json else {}
        except Exception:
            headers_parsed = {}
        try:
            template_parsed = _json.loads(template_json) if template_json else {}
        except Exception:
            template_parsed = {}
        assert headers_parsed == new_cfg["headers"]
        assert template_parsed == new_cfg["template"]

        # Numeric fields (reflect the most recent PUT we performed)
        expected_timeout = new_cfg["timeout"]
        expected_tc = new_cfg["threshold_count"]
        expected_tw = new_cfg["threshold_window"]
        assert abs(float(wh_section.get("timeout", "0")) - expected_timeout) < 1e-6
        assert int(wh_section.get("threshold_count", "0")) == expected_tc
        assert int(wh_section.get("threshold_window", "0")) == expected_tw
