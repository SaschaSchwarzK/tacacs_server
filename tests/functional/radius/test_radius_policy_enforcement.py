"""Policy enforcement tests for RADIUS using shared policy helpers."""

from tacacs_server.utils.policy import PolicyContext, evaluate_policy


def _ctx(device_group=None, allowed=None, user_groups=None, fallback=1):
    return PolicyContext(
        device_group_name=device_group,
        allowed_user_groups=allowed or [],
        user_groups=user_groups or [],
        fallback_privilege=fallback,
    )


def test_user_group_policy_allowed_and_privilege_assignment():
    lookup = {"netops": 15, "users": 1}.__getitem__
    ctx = _ctx(device_group="routers", allowed=["netops"], user_groups=["netops"])
    result = evaluate_policy(ctx, lookup)
    assert result.allowed is True
    assert result.privilege_level == 15


def test_device_group_policy_denial_message():
    ctx = _ctx(
        device_group="switches", allowed=["ops"], user_groups=["guests"], fallback=5
    )
    result = evaluate_policy(ctx, lambda g: None)
    assert result.allowed is False
    assert "switches" in result.denial_message
    assert result.privilege_level == 5  # fallback retained on denial


def test_okta_group_based_access_control():
    # Treat Okta-provided groups like any user group
    ctx = _ctx(allowed=["OktaAdmins"], user_groups=["OktaAdmins"])
    result = evaluate_policy(ctx, lambda g: 7 if g == "OktaAdmins" else None)
    assert result.allowed is True
    assert result.privilege_level == 7


def test_fallback_privilege_used_when_no_lookup_hits():
    ctx = _ctx(allowed=[], user_groups=["users"], fallback=3)
    result = evaluate_policy(ctx, lambda g: None)
    assert result.allowed is True
    assert result.privilege_level == 3


def test_multiple_matching_groups_uses_highest_privilege():
    lookup = {"ops": 5, "admins": 15}.__getitem__
    ctx = _ctx(allowed=["ops", "admins"], user_groups=["ops", "admins"])
    result = evaluate_policy(ctx, lookup)
    assert result.allowed is True
    assert result.privilege_level == 15


def test_allowed_user_groups_filtering():
    """Only groups present in allowed list should be considered."""
    lookup_calls = []

    def _lookup(group):
        lookup_calls.append(group)
        return {"ops": 5, "eng": 10}.get(group)

    ctx = _ctx(allowed=["ops"], user_groups=["ops", "eng"])
    result = evaluate_policy(ctx, _lookup)
    assert result.allowed is True
    assert result.privilege_level == 5
    # Ensure non-allowed group was ignored or not looked up
    assert "eng" not in lookup_calls or result.privilege_level == 5
