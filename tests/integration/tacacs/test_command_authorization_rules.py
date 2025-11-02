import json

import pytest


def _server_with_rules(server_factory, rules: list[dict], default_action: str = "deny"):
    return server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={
            "command_authorization": {
                "default_action": default_action,
                "rules_json": json.dumps(rules),
            }
        },
    )


def _check(
    sess,
    base_url: str,
    command: str,
    privilege: int = 15,
    user_groups=None,
    device_group=None,
) -> tuple[bool, str]:
    payload = {
        "command": command,
        "privilege_level": privilege,
        "user_groups": user_groups or ["netops"],
        "device_group": device_group or "core",
    }
    r = sess.post(
        f"{base_url}/api/command-authorization/check", json=payload, timeout=5
    )
    if r.status_code != 200:
        return False, f"http {r.status_code}"
    data = r.json()
    return bool(data.get("authorized")), data.get("reason", "")


@pytest.mark.integration
def test_rule_with_regex_capturing_groups(server_factory):
    # Permit 'show interface <name>' using capturing group
    rules = [
        {
            "action": "permit",
            "match_type": "regex",
            "pattern": r"^show\s+interface\s+(\S+)$",
        }
    ]
    server = _server_with_rules(server_factory, rules)
    with server:
        sess = server.login_admin()
        base = server.get_base_url()
        allowed, _ = _check(sess, base, "show interface Gi0/1")
        denied, _ = _check(sess, base, "show interfaces Gi0/1")
        assert allowed is True
        assert denied is False


@pytest.mark.integration
def test_rule_case_insensitive_matching(server_factory):
    # Use inline (?i) to enable case-insensitive regex
    rules = [
        {
            "action": "permit",
            "match_type": "regex",
            "pattern": r"(?i)^configure terminal$",
        }
    ]
    server = _server_with_rules(server_factory, rules)
    with server:
        sess = server.login_admin()
        base = server.get_base_url()
        ok1, _ = _check(sess, base, "configure terminal")
        ok2, _ = _check(sess, base, "ConFiGuRe TeRmInAl")
        no3, _ = _check(sess, base, "configure term")
        assert ok1 and ok2
        assert not no3


@pytest.mark.integration
def test_rule_priority_ordering_first_match_wins(server_factory):
    # Two rules both match 'show running-config'; first is permit, second denies
    rules_permit_first = [
        {"action": "permit", "match_type": "prefix", "pattern": "show "},
        {
            "action": "deny",
            "match_type": "regex",
            "pattern": r"^show\s+running-config$",
        },
    ]
    server = _server_with_rules(server_factory, rules_permit_first)
    with server:
        sess = server.login_admin()
        base = server.get_base_url()
        ok, reason = _check(sess, base, "show running-config")
        assert ok is True, f"Expected permit by first rule, got: {reason}"

    # Now reverse order: deny first should win
    rules_deny_first = list(reversed(rules_permit_first))
    server2 = _server_with_rules(server_factory, rules_deny_first)
    with server2:
        sess = server2.login_admin()
        base = server2.get_base_url()
        ok, reason = _check(sess, base, "show running-config")
        assert ok is False, f"Expected deny by first rule, got: {reason}"


@pytest.mark.integration
def test_rule_with_wildcard_patterns(server_factory):
    # Wildcard pattern: allow 'copy <anything> tftp <anything>'
    rules = [{"action": "permit", "match_type": "wildcard", "pattern": "copy * tftp *"}]
    server = _server_with_rules(server_factory, rules)
    with server:
        sess = server.login_admin()
        base = server.get_base_url()
        ok1, _ = _check(sess, base, "copy running-config tftp 10.0.0.1")
        ok2, _ = _check(sess, base, "copy startup-config tftp 192.168.1.10")
        no3, _ = _check(sess, base, "copy tftp running-config 10.0.0.1")
        assert ok1 and ok2
        assert not no3


@pytest.mark.integration
def test_multiple_matching_rules_precedence(server_factory):
    # Multiple rules match 'debug ip icmp'; ensure first match wins
    rules = [
        {"action": "deny", "match_type": "regex", "pattern": r"^debug\s+ip\s+icmp$"},
        {"action": "permit", "match_type": "prefix", "pattern": "debug "},
    ]
    server = _server_with_rules(server_factory, rules)
    with server:
        sess = server.login_admin()
        base = server.get_base_url()
        ok, reason = _check(sess, base, "debug ip icmp")
        assert ok is False, f"Expected deny by first matching rule, got: {reason}"


@pytest.mark.integration
def test_rule_with_command_aliases_via_regex(server_factory):
    # Simulate aliases using regex alternation: 'show' or 'display'
    rules = [
        {
            "action": "permit",
            "match_type": "regex",
            "pattern": r"^(show|display)\s+version$",
        }
    ]
    server = _server_with_rules(server_factory, rules)
    with server:
        sess = server.login_admin()
        base = server.get_base_url()
        ok1, _ = _check(sess, base, "show version")
        ok2, _ = _check(sess, base, "display version")
        no3, _ = _check(sess, base, "show versions")
        assert ok1 and ok2
        assert not no3
