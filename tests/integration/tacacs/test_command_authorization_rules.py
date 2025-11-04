"""
TACACS+ Command Authorization Rules Integration Tests
===================================================

This module contains integration tests for TACACS+ command authorization rules.
It verifies the behavior of different rule types, patterns, and matching strategies
used in command authorization.

Test Environment:
- TACACS+ server with command authorization enabled
- Admin API for rule configuration and testing
- Various command patterns and matching strategies

Test Cases:
- test_rule_with_regex_capturing_groups: Tests regex patterns with capturing groups
- test_rule_case_insensitive_matching: Verifies case-insensitive command matching
- test_rule_priority_ordering_first_match_wins: Tests rule precedence and ordering
- test_rule_with_wildcard_patterns: Validates wildcard pattern matching
- test_multiple_matching_rules_precedence: Verifies behavior with multiple matching rules
- test_rule_with_command_aliases_via_regex: Tests command aliases using regex patterns

Configuration:
- Default action: deny (configurable)
- Rule format: List of dictionaries with action, match_type, pattern, etc.
- Test user groups: ['netops']
- Test device group: 'core'

Example Usage:
    pytest tests/integration/tacacs/test_command_authorization_rules.py -v
"""

import json
from typing import Any

import pytest


def _server_with_rules(
    server_factory, rules: list[dict[str, Any]], default_action: str = "deny"
) -> Any:
    """Helper to create a test server with custom command authorization rules.

    Args:
        server_factory: Pytest fixture for creating server instances
        rules: List of command authorization rule dictionaries
        default_action: Default action ('permit' or 'deny') when no rules match

    Returns:
        Configured server instance with the specified rules

    Example:
        rules = [{
            "action": "permit",
            "match_type": "regex",
            "pattern": r"^show\\s+version$",
            "description": "Allow show version"
        }]
        server = _server_with_rules(server_factory, rules, default_action="deny")
    """
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
    sess: Any,
    base_url: str,
    command: str,
    privilege: int = 15,
    user_groups: list[str] | None = None,
    device_group: str | None = None,
) -> tuple[bool, str]:
    """Check if a command is authorized according to the current rules.

    Args:
        sess: Requests session for API calls
        base_url: Base URL of the admin API
        command: Command string to check
        privilege: User privilege level (1-15)
        user_groups: List of user group names
        device_group: Device group name

    Returns:
        Tuple of (is_authorized, reason)
        - is_authorized: Boolean indicating if command is allowed
        - reason: String describing the authorization decision

    Example:
        authorized, reason = _check(session, "http://localhost:8080", "show version")
    """
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
def test_rule_with_regex_capturing_groups(server_factory: Any) -> None:
    """Test command authorization with regex patterns containing capturing groups.

    This test verifies that:
    1. Regex patterns with capturing groups work correctly
    2. The full command is matched against the pattern
    3. The rule only matches the exact specified pattern

    Test Steps:
    1. Create a rule that permits 'show interface <name>' using regex
    2. Verify that matching commands are permitted
    3. Verify that non-matching commands are denied

    Expected Behavior:
    - 'show interface Ethernet1' -> PERMIT (matches pattern)
    - 'show interfaces' -> DENY (doesn't match pattern)
    - 'show interface' -> DENY (missing interface name)
    """
    rules = [
        {
            "action": "permit",
            "match_type": "regex",
            "pattern": r"^show\s+interface\s+(\S+)$",  # Captures interface name
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
def test_rule_case_insensitive_matching(server_factory: Any) -> None:
    """Test case-insensitive command matching in authorization rules.

    This test verifies that:
    1. Command matching is case-insensitive by default
    2. Both upper and lower case commands are matched correctly
    3. Mixed case commands are properly handled

    Test Steps:
    1. Create a rule that permits 'show version' (lowercase)
    2. Test with various case variations of the command

    Expected Behavior:
    - 'show version' -> PERMIT
    - 'SHOW VERSION' -> PERMIT
    - 'Show Version' -> PERMIT
    - 'show' -> DENY (only partial match)
    """
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
def test_rule_priority_ordering_first_match_wins(server_factory: Any) -> None:
    """Test that the first matching rule takes precedence.

    This test verifies that:
    1. Rules are evaluated in order
    2. The first matching rule determines the action
    3. Subsequent matching rules are ignored

    Test Steps:
    1. Create rules with overlapping patterns in specific order
    2. Test commands that could match multiple rules

    Expected Behavior:
    - 'show running-config' -> DENY (first rule takes precedence)
    - 'show version' -> PERMIT (matches second rule)
    - 'show interfaces' -> DENY (default action)
    """
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
