from __future__ import annotations

import configparser

from tacacs_server.config.validators import validate_change


def _make_minimal_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg["server"] = {
        "host": "0.0.0.0",
        "port": "49",
        "log_level": "INFO",
        "max_connections": "50",
        "socket_timeout": "30",
    }
    cfg["auth"] = {
        "backends": "local",
        "local_auth_db": "data/local_auth.db",
        "require_all_backends": "false",
        "local_auth_cache_ttl_seconds": "60",
        "backend_timeout": "2.0",
    }
    cfg["security"] = {
        "max_auth_attempts": "3",
        "auth_timeout": "300",
        "encryption_required": "true",
        "allowed_clients": "",
        "denied_clients": "",
        "rate_limit_requests": "60",
        "rate_limit_window": "60",
        "max_connections_per_ip": "20",
    }
    cfg["command_authorization"] = {
        "default_action": "deny",
        "rules_json": "[]",
        "response_mode": "pass_add",
        "privilege_check_order": "before",
    }
    return cfg


def test_privilege_check_order_invalid_value_rejected():
    cfg = _make_minimal_config()

    ok, issues = validate_change(
        cfg,
        section="command_authorization",
        key="privilege_check_order",
        value="invalid-order",
    )

    assert not ok
    assert any("privilege_check_order must be one of" in msg for msg in issues), (
        f"Expected privilege_check_order validation error, got: {issues}"
    )
