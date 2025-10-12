import pytest
import requests


@pytest.mark.integration
def test_admin_login_and_access_admin_api(tacacs_server):
    base = f"http://{tacacs_server['host']}:{tacacs_server['web_port']}"

    s = requests.Session()

    # Login via JSON to get session cookie
    r = s.post(
        f"{base}/admin/login",
        json={"username": "admin", "password": "AdminPass123!"},
        timeout=5,
    )
    assert r.status_code in (200, 303), r.text

    # Access an admin-protected API endpoint using the session
    r2 = s.get(f"{base}/admin/webhooks-config", timeout=5)
    assert r2.status_code == 200, r2.text
    data = r2.json()
    assert isinstance(data, dict)

    # Update admin-only config and verify persistence
    new_payload = {
        "urls": ["https://example.test/webhook"],
        "headers": {"X-Test": "1"},
        "template": {"event": "{{event}}"},
        "timeout": 1.5,
        "threshold_count": 2,
        "threshold_window": 30,
    }
    r3 = s.put(f"{base}/admin/webhooks-config", json=new_payload, timeout=5)
    assert r3.status_code == 200, r3.text
    updated = r3.json()
    assert updated.get("urls") == new_payload["urls"]
    assert updated.get("headers", {}).get("X-Test") == "1"
