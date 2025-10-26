from tacacs_server.authorization.command_authorization import (
    ActionType,
    CommandAuthorizationEngine,
    CommandMatchType,
)


def test_rule_attribute_export_import_roundtrip():
    eng = CommandAuthorizationEngine()
    # Add rule with attrs and response_mode
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
    exported = eng.export_config()
    assert isinstance(exported, list) and len(exported) == 1
    rule = exported[0]
    assert rule.get("response_mode") == "pass_repl"
    assert rule.get("attrs") == {"role": "ro", "context": "netops"}

    # Now import into a fresh engine and verify properties preserved
    eng2 = CommandAuthorizationEngine()
    eng2.load_from_config(exported)
    assert len(eng2.rules) == 1
    r2 = eng2.rules[0]
    assert r2.response_mode == "pass_repl"
    assert r2.attrs == {"role": "ro", "context": "netops"}
