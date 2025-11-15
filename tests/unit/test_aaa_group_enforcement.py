from __future__ import annotations

from typing import Any

from tacacs_server.auth.base import AuthenticationBackend
from tacacs_server.tacacs.handlers import AAAHandlers


class _FakeBackend(AuthenticationBackend):
    def __init__(self, name: str, groups_by_user: dict[str, set[str]]):
        super().__init__(name)
        self._groups_by_user = groups_by_user

    def authenticate(self, username: str, password: str, **kwargs: Any) -> bool:
        # Authentication always succeeds; AAAHandlers will enforce groups.
        return True

    def get_user_attributes(self, username: str) -> dict[str, Any]:
        # No additional attributes needed for these tests.
        return {}

    def get_user_groups(self, username: str) -> list[str]:
        groups = self._groups_by_user.get(username, set())
        return [str(g).lower() for g in groups]


class _FakeGroupRecord:
    def __init__(self, okta_group: str | None, metadata: dict[str, Any] | None = None):
        self.okta_group = okta_group
        self.metadata = metadata or {}


class _FakeLocalUserGroupService:
    def __init__(self, mapping: dict[str, _FakeGroupRecord]):
        self._mapping = mapping

    def get_group(self, name: str) -> _FakeGroupRecord:
        if name not in self._mapping:
            raise KeyError(name)
        return self._mapping[name]


class _FakeDeviceGroup:
    def __init__(self, name: str, allowed_user_groups: list[str]):
        self.name = name
        self.allowed_user_groups = allowed_user_groups


class _FakeDevice:
    def __init__(self, name: str, group: _FakeDeviceGroup | None = None):
        self.name = name
        self.group = group
        self.ip = "192.0.2.1"


def _build_handlers(
    backend_name: str,
    groups_by_user: dict[str, set[str]],
    allowed_user_groups: list[str],
):
    backend = _FakeBackend(backend_name, groups_by_user)
    handlers = AAAHandlers([backend], db_logger=None)
    group_records = {
        "admins": _FakeGroupRecord("okta-admins"),
        "ops": _FakeGroupRecord("okta-ops"),
    }
    handlers.set_local_user_group_service(_FakeLocalUserGroupService(group_records))
    device_group = _FakeDeviceGroup("dg1", allowed_user_groups)
    device = _FakeDevice("device1", device_group)
    return handlers, device


def test_group_enforcement_allows_when_groups_intersect_okta() -> None:
    handlers, device = _build_handlers(
        "okta",
        {"alice": {"okta-admins"}},
        allowed_user_groups=["admins"],
    )
    allowed, reason = handlers._enforce_device_group_policy("okta", "alice", device)
    assert allowed is True
    assert reason is None


def test_group_enforcement_denies_when_no_intersection_okta() -> None:
    handlers, device = _build_handlers(
        "okta",
        {"alice": {"okta-other"}},
        allowed_user_groups=["admins"],
    )
    allowed, reason = handlers._enforce_device_group_policy("okta", "alice", device)
    assert allowed is False
    assert reason == "group_not_allowed"


def test_group_enforcement_noop_when_no_allowed_user_groups() -> None:
    handlers, device = _build_handlers(
        "okta",
        {"alice": {"okta-admins"}},
        allowed_user_groups=[],
    )
    allowed, reason = handlers._enforce_device_group_policy("okta", "alice", device)
    assert allowed is True
    assert reason is None


def test_group_enforcement_ldap_mapping_uses_ldap_group_field() -> None:
    handlers, device = _build_handlers(
        "ldap",
        {"alice": {"ldap-admins"}},
        allowed_user_groups=["admins"],
    )
    allowed, reason = handlers._enforce_device_group_policy("ldap", "alice", device)
    assert allowed is True
    assert reason is None


def test_group_enforcement_radius_mapping_uses_metadata_radius_group() -> None:
    handlers, device = _build_handlers(
        "radius",
        {"alice": {"radius-admins"}},
        allowed_user_groups=["admins"],
    )
    # Override group records with radius-specific metadata mapping
    handlers.local_user_group_service._mapping["admins"] = _FakeGroupRecord(
        okta_group=None
    )
    handlers.local_user_group_service._mapping["admins"].metadata["radius_group"] = (
        "radius-admins"
    )
    allowed, reason = handlers._enforce_device_group_policy("radius", "alice", device)
    assert allowed is True
    assert reason is None


def test_group_enforcement_local_mapping_uses_group_name() -> None:
    handlers, device = _build_handlers(
        "local",
        {"alice": {"admins"}},
        allowed_user_groups=["admins"],
    )
    allowed, reason = handlers._enforce_device_group_policy("local", "alice", device)
    assert allowed is True
    assert reason is None
