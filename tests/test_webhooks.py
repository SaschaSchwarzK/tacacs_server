from fastapi import FastAPI
from fastapi.testclient import TestClient


def create_admin_app():
    from tacacs_server.web.admin.routers import admin_router
    from tacacs_server.web.monitoring import set_admin_auth_dependency

    app = FastAPI()
    # Disable admin auth for tests
    set_admin_auth_dependency(None)
    app.include_router(admin_router, include_in_schema=False)
    return app


def test_webhooks_config_put_get_roundtrip():
    app = create_admin_app()
    client = TestClient(app)

    payload = {
        "urls": ["https://example.test/hook1", "https://example.test/hook2"],
        "headers": {"Authorization": "Bearer TEST"},
        "template": {"event": "{{event}}", "u": "{{username}}"},
        "timeout": 2.5,
        "threshold_count": 3,
        "threshold_window": 30,
    }
    r = client.put("/admin/webhooks-config", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["urls"] == payload["urls"]
    assert data["headers"]["Authorization"] == "Bearer TEST"
    assert data["template"]["u"] == "{{username}}"
    assert data["timeout"] == payload["timeout"]
    assert data["threshold_count"] == payload["threshold_count"]
    assert data["threshold_window"] == payload["threshold_window"]

    r2 = client.get("/admin/webhooks-config")
    assert r2.status_code == 200
    data2 = r2.json()
    # Reflects runtime (same process) config
    assert data2["urls"] == payload["urls"]


def test_admin_webhooks_page_renders():
    app = create_admin_app()
    client = TestClient(app)
    r = client.get("/admin/webhooks")
    assert r.status_code == 200
    text = r.text
    # Should include title and fields from the template
    assert "Webhook & Threshold Configuration" in text
    assert "Webhook URLs" in text
    assert "Headers (JSON)" in text


def test_webhook_threshold_triggers(monkeypatch):
    # Patch notify to capture calls without network
    from tacacs_server.utils import webhook as wh

    captured = []

    def fake_notify(event, payload):
        captured.append((event, payload))

    monkeypatch.setattr(wh, "notify", fake_notify)

    # Configure threshold to 2 within 60s
    wh.set_webhook_config(
        urls=[],
        headers={},
        template={},
        timeout=1.0,
        threshold_count=2,
        threshold_window=60,
    )

    # Use deterministic time
    times = [1000.0, 1005.0]

    def fake_now():
        return times.pop(0)

    wh.record_event("auth_failure", key="userA", now_func=fake_now)
    assert captured == []
    wh.record_event("auth_failure", key="userA", now_func=fake_now)

    # Should have triggered once with threshold_exceeded
    assert len(captured) == 1
    evt, payload = captured[0]
    assert evt == "threshold_exceeded"
    assert payload["event"] == "auth_failure"
    assert payload["key"] == "userA"
    assert payload["count"] >= 2
