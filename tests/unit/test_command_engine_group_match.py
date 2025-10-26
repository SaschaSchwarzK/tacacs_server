from tacacs_server.authorization.command_authorization import (
    ActionType,
    CommandAuthorizationEngine,
    CommandMatchType,
)


def test_rule_matches_when_any_user_group_overlaps():
    eng = CommandAuthorizationEngine()
    eng.add_rule(
        action=ActionType.PERMIT,
        match_type=CommandMatchType.PREFIX,
        pattern="show ",
        min_privilege=1,
        max_privilege=15,
        user_groups=["admin", "ops"],
    )
    allowed, reason, attrs, mode = eng.authorize_command(
        "show version",
        privilege_level=5,
        user_groups=["ops", "readonly"],
        device_group=None,
    )
    assert allowed is True
    assert mode is None  # not set on rule
