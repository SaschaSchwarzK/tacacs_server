from tacacs_server.authorization.command_authorization import (
    ActionType,
    CommandAuthorizationEngine,
    CommandMatchType,
    CommandRuleTemplates,
)


def test_engine_permit_prefix_and_deny_default():
    engine = CommandAuthorizationEngine()
    engine.default_action = ActionType.DENY
    engine.add_rule(
        action=ActionType.PERMIT,
        match_type=CommandMatchType.PREFIX,
        pattern="show ",
        min_privilege=1,
    )
    ok, reason = engine.authorize_command("show ip int", privilege_level=1)
    assert ok is True
    nok, _ = engine.authorize_command("configure terminal", privilege_level=15)
    assert nok is False


def test_engine_regex_and_wildcard():
    engine = CommandAuthorizationEngine()
    engine.default_action = ActionType.DENY
    engine.add_rule(
        action=ActionType.PERMIT,
        match_type=CommandMatchType.REGEX,
        pattern=r"^interface .*",
        min_privilege=15,
    )
    ok, _ = engine.authorize_command("interface Gig0/1", privilege_level=15)
    assert ok is True
    engine.add_rule(
        action=ActionType.DENY,
        match_type=CommandMatchType.WILDCARD,
        pattern="reload*",
        min_privilege=0,
        max_privilege=15,
    )
    nok, _ = engine.authorize_command("reload now", privilege_level=15)
    assert nok is False


def test_templates_load():
    engine = CommandAuthorizationEngine()
    engine.load_from_config(CommandRuleTemplates.cisco_read_only())
    ok, _ = engine.authorize_command("show version", privilege_level=1)
    assert ok is True
