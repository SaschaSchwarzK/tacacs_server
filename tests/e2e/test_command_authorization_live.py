import pytest
import requests


@pytest.mark.integration
def test_live_command_authorization_admin_api(tacacs_server):
    base = f"http://{tacacs_server['host']}:{tacacs_server['web_port']}"
    s = requests.Session()

    # Login
    try:
        hh = s.get(f"{base}/api/health", timeout=5)
        print(f"[ADMIN-DEBUG] /api/health -> {hh.status_code} {(hh.text or '')[:160]}")
    except Exception as e:
        print(f"[ADMIN-DEBUG] health check failed: {e}")
    try:
        cfg = s.get(f"{base}/api/admin/config", timeout=5)
        print(
            f"[ADMIN-DEBUG] /api/admin/config -> {cfg.status_code} {(cfg.text or '')[:200]}"
        )
    except Exception as e:
        print(f"[ADMIN-DEBUG] admin config fetch failed: {e}")

    r = s.post(
        f"{base}/admin/login",
        json={"username": "admin", "password": "AdminPass123!"},
        timeout=5,
    )
    if r.status_code not in (200, 303):
        try:
            logs = s.get(f"{base}/api/admin/logs", params={"lines": 200}, timeout=5)
            print(
                f"[ADMIN-DEBUG] login failed: {r.status_code} {r.text[:200]} /api/admin/logs -> {logs.status_code} {(logs.text or '')[:600]}"
            )
        except Exception as e:
            print(f"[ADMIN-DEBUG] fetching logs failed: {e}")
    assert r.status_code in (200, 303), r.text

    # Update settings: default deny
    r2 = s.put(
        f"{base}/api/command-authorization/settings",
        json={"default_action": "deny"},
        timeout=5,
    )
    assert r2.status_code == 200, r2.text
    assert r2.json().get("default_action") == "deny"

    # Add a permit rule for show
    r3 = s.post(
        f"{base}/api/command-authorization/rules",
        json={
            "action": "permit",
            "match_type": "prefix",
            "pattern": "show ",
            "min_privilege": 1,
        },
        timeout=5,
    )
    assert r3.status_code == 200, r3.text

    # Verify rule exists
    r4 = s.get(f"{base}/api/command-authorization/rules", timeout=5)
    assert r4.status_code == 200
    rules = r4.json().get("rules", [])
    assert any(rule.get("pattern") == "show " for rule in rules)
