import json
import os

import requests


def _admin_headers():
    token = os.environ.get("API_TOKEN", "test-token")
    return {
        "X-API-Token": token,
        "Content-Type": "application/json",
    }


def test_update_server_tuning_and_verify(tacacs_server):
    web_port = tacacs_server["web_port"]
    base = f"http://127.0.0.1:{web_port}"
    # Update client_timeout only (should apply without restart for new connections)
    payload = {"server": {"client_timeout": "12"}}
    r = requests.put(
        base + "/api/admin/config",
        headers=_admin_headers(),
        data=json.dumps(payload),
        timeout=3,
    )
    assert r.status_code == 200
    # Fetch config view as JSON
    r2 = requests.get(
        base + "/admin/config?format=json", headers=_admin_headers(), timeout=3
    )
    assert r2.status_code == 200
    doc = r2.json()
    cfg = doc.get("configuration", {})
    server = cfg.get("server", {})
    # Must reflect updated value as string or numeric depending on serialization
    assert str(server.get("client_timeout")) in ("12", "12.0")
