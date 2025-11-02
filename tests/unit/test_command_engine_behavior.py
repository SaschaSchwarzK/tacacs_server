import pytest

from tacacs_server.authorization.command_authorization import (
    ActionType,
    CommandAuthorizationEngine,
    CommandMatchType,
)


def _norm_rules(rules: list[dict]) -> list[dict]:
    # Normalize export by removing volatile fields like id for stable compare
    cleaned = []
    for r in rules:
        r = dict(r)
        r.pop("id", None)
        cleaned.append(r)
    return cleaned


def test_default_action_behavior_permit_vs_deny():
    eng = CommandAuthorizationEngine()
    # Default is DENY when no rules match
    allowed, reason, attrs, mode = eng.authorize_command(
        "show version", privilege_level=1
    )
    assert allowed is False
    assert "Default action" in (reason or "")
    # Flip default action to PERMIT
    eng.default_action = ActionType.PERMIT
    allowed2, reason2, attrs2, mode2 = eng.authorize_command(
        "show version", privilege_level=1
    )
    assert allowed2 is True
    assert "permit" in (reason2 or "").lower()


def test_export_import_cycle_preserves_rules_order_and_fields():
    eng = CommandAuthorizationEngine()
    eng.add_rule(
        action=ActionType.PERMIT,
        match_type=CommandMatchType.REGEX,
        pattern=r"^show\\s+interfaces$",
        min_privilege=1,
        max_privilege=15,
        description="interfaces ro",
        user_groups=["ops"],
        device_groups=["dc"],
        response_mode="pass_repl",
        attrs={"role": "ro", "context": "netops"},
    )
    eng.add_rule(
        action=ActionType.DENY,
        match_type=CommandMatchType.PREFIX,
        pattern="reload",
        min_privilege=0,
        max_privilege=15,
        description="block reload",
    )
    exported = eng.export_config()
    # Import into a fresh engine and export again
    eng2 = CommandAuthorizationEngine()
    eng2.load_from_config(exported)
    reexported = eng2.export_config()
    # Compare normalized lists (ignore rule ids)
    assert _norm_rules(exported) == _norm_rules(reexported)


def test_privilege_checks_interact_with_rules():
    eng = CommandAuthorizationEngine()
    eng.default_action = ActionType.DENY
    eng.add_rule(
        action=ActionType.PERMIT,
        match_type=CommandMatchType.PREFIX,
        pattern="configure ",
        min_privilege=15,
        max_privilege=15,
        description="allow config at priv15",
    )
    # At priv 15 allowed
    allowed, reason, *_ = eng.authorize_command(
        "configure terminal", privilege_level=15
    )
    assert allowed is True
    # At lower priv denied (rule won’t match, default deny)
    allowed2, reason2, *_ = eng.authorize_command(
        "configure terminal", privilege_level=5
    )
    assert allowed2 is False


@pytest.mark.parametrize("cmd", ["", "   ", "\t\n"])
def test_empty_or_malformed_commands_default_to_policy(cmd):
    eng = CommandAuthorizationEngine()
    # default DENY
    allowed, reason, *_ = eng.authorize_command(cmd, privilege_level=1)
    assert allowed is False
    # If default PERMIT is desired, flip and verify
    eng.default_action = ActionType.PERMIT
    allowed2, _, *_ = eng.authorize_command(cmd, privilege_level=1)
    assert allowed2 is True


def test_multiple_user_groups_any_match_logic():
    eng = CommandAuthorizationEngine()
    eng.add_rule(
        action=ActionType.PERMIT,
        match_type=CommandMatchType.PREFIX,
        pattern="show ",
        min_privilege=1,
        max_privilege=15,
        user_groups=["network", "ops"],
    )
    allowed, reason, *_ = eng.authorize_command(
        "show ip int brief",
        privilege_level=5,
        user_groups=["dev", "ops"],
        device_group=None,
    )
    assert allowed is True
    # No overlap -> rule should not match -> default deny
    allowed2, *_ = eng.authorize_command(
        "show ip int brief",
        privilege_level=5,
        user_groups=["dev", "qa"],
        device_group=None,
    )
    assert allowed2 is False
