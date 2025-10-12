from fastapi import FastAPI
from fastapi.testclient import TestClient


def build_app():
    from tacacs_server.authorization.command_authorization import (
        ActionType,
        CommandAuthorizationEngine,
    )
    from tacacs_server.authorization.command_authorization import (
        router as cmd_router,
    )
    from tacacs_server.web.monitoring import (
        set_admin_auth_dependency,
        set_command_engine,
    )

    # Disable admin auth for API tests
    set_admin_auth_dependency(None)
    engine = CommandAuthorizationEngine()
    engine.default_action = ActionType.DENY
    set_command_engine(engine)

    app = FastAPI()
    app.include_router(cmd_router)
    return app


def test_rules_crud_and_settings_persist(monkeypatch):
    from tacacs_server.web.monitoring import get_command_engine

    app = build_app()
    client = TestClient(app)

    # Create a rule
    r = client.post(
        "/api/command-authorization/rules",
        json={
            "action": "permit",
            "match_type": "prefix",
            "pattern": "show ",
            "min_privilege": 1,
        },
    )
    assert r.status_code == 200, r.text

    # List rules
    r2 = client.get("/api/command-authorization/rules")
    assert r2.status_code == 200
    data = r2.json()
    assert any(rule["pattern"] == "show " for rule in data.get("rules", []))

    # Update default action
    r3 = client.put(
        "/api/command-authorization/settings", json={"default_action": "permit"}
    )
    assert r3.status_code == 200
    assert r3.json()["default_action"] == "permit"

    # Validate engine reflects change
    engine = get_command_engine()
    assert engine is not None
    assert engine.default_action.value == "permit"
