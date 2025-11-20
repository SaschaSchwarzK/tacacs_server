import hashlib
from pathlib import Path

import pytest

from tacacs_server.auth.base import AuthenticationBackend
from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.auth.local_models import LocalUserGroupRecord, LocalUserRecord
from tacacs_server.auth.local_store import LocalAuthStore
from tacacs_server.auth.local_user_group_service import (
    LocalUserGroupExists,
    LocalUserGroupNotFound,
    LocalUserGroupService,
    LocalUserGroupValidationError,
)
from tacacs_server.auth.local_user_service import (
    LocalUserExists,
    LocalUserNotFound,
    LocalUserService,
    LocalUserValidationError,
)


class SimpleBackend(AuthenticationBackend):
    """Minimal backend implementation used for base-class testing."""

    def __init__(self):
        super().__init__("simple")
        self._users = {
            "alice": {"groups": ["ops"], "privilege_level": 5},
        }

    def authenticate(self, username, password, **kwargs):
        return username == password

    def get_user_attributes(self, username):
        if username not in self._users:
            return {}
        return dict(self._users[username])


@pytest.fixture
def local_store(tmp_path: Path):
    store = LocalAuthStore(tmp_path / "local_auth.db")
    yield store
    store.close()


@pytest.fixture
def local_user_service(local_store):
    svc = LocalUserService(db_path=local_store.db_path, store=local_store)
    yield svc


def test_authentication_backend_common_methods():
    backend = SimpleBackend()
    assert backend.authenticate("foo", "foo")
    assert not backend.authenticate("foo", "bar")
    assert "ops" in backend.get_user_groups("alice")
    assert backend.get_privilege_level("alice") == 5
    assert backend.validate_user("alice")
    assert not backend.validate_user("unknown")
    assert str(backend).startswith("SimpleBackend(")


def test_local_models_conversion():
    user = LocalUserRecord(
        username="carl", groups=["ops", "admin"], privilege_level=2, description="desc"
    )
    as_payload = user.to_dict()
    assert "password" in as_payload and "privilege_level" in as_payload
    from_dict = LocalUserRecord.from_dict("carl", as_payload)
    assert from_dict.username == "carl"

    group = LocalUserGroupRecord(
        name="ops",
        description="Ops team",
        metadata={"foo": "bar"},
        ldap_group="cn=ops",
        okta_group="ops",
        radius_group="ops",
        privilege_level=3,
    )
    grp_payload = group.to_dict()
    assert grp_payload["privilege_level"] == 3
    roundtrip = LocalUserGroupRecord.from_dict("ops", grp_payload)
    assert roundtrip.privilege_level == 3


def test_local_auth_store_user_and_group_operations(local_store):
    user = LocalUserRecord(username="bob", password="plain", privilege_level=4)
    inserted = local_store.insert_user(user)
    assert inserted.username == "bob"
    assert local_store.get_user("bob") is not None
    listed = local_store.list_users()
    assert any(u.username == "bob" for u in listed)

    updated = local_store.update_user(
        "bob", privilege_level=5, groups=["ops"], enabled=False, description="new"
    )
    assert updated and updated.privilege_level == 5
    password_set = local_store.set_user_password(
        "bob", password=None, password_hash="a" * 64
    )
    assert password_set and password_set.password_hash == "a" * 64
    assert local_store.delete_user("bob")

    group = LocalUserGroupRecord(name="admins", metadata={"foo": "bar"})
    stored_group = local_store.insert_group(group)
    assert stored_group.name == "admins"
    bumped = local_store.update_group(
        "admins", description="desc", metadata={"foo": "baz"}, ldap_group="cn=others"
    )
    assert bumped and bumped.metadata["foo"] == "baz"
    assert "admins" in [g.name for g in local_store.list_groups()]
    assert local_store.delete_group("admins")

    assert LocalAuthStore._load_list('["a"]') == ["a"]
    assert LocalAuthStore._load_list("bad") == []
    assert LocalAuthStore._load_dict('{"a":1}') == {"a": 1}
    assert LocalAuthStore._load_dict("bad") == {}
    assert LocalAuthStore._parse_datetime("2020-01-01T00:00:00") is not None


def test_local_user_service_basic_workflow(monkeypatch, local_user_service):
    svc = local_user_service
    user = svc.create_user("dave", password="Str0ngPwd1")
    assert user.username == "dave"
    assert svc.get_user("dave").username == "dave"
    assert svc.get_user_or_none("missing") is None

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    with pytest.raises(LocalUserExists):
        svc.create_user("dave", password="Str0ngPwd1")
    svc.update_user("dave", enabled=False, groups=["ops"])
    assert not svc.get_user("dave").enabled

    with pytest.raises(LocalUserValidationError):
        svc.set_password("dave", "short")

    with pytest.raises(LocalUserNotFound):
        svc.set_password("missing", "Str0ngPwd1")

    svc.set_password("dave", "Str0ngPwd1")
    assert svc.verify_user_password("dave", "Str0ngPwd1")
    assert not svc.verify_user_password("dave", "wrong")

    legacy = hashlib.sha256(b"Str0ngPwd1").hexdigest()
    svc.store.set_user_password("dave", password=None, password_hash=legacy)
    assert svc.verify_user_password("dave", "Str0ngPwd1")

    with pytest.raises(LocalUserValidationError):
        LocalUserService._resolve_password("StrongPwd1", "a" * 64)
    with pytest.raises(LocalUserValidationError):
        LocalUserService._resolve_password(None, None)
    with pytest.raises(LocalUserValidationError):
        LocalUserService._validate_privilege(99)
    with pytest.raises(LocalUserValidationError):
        LocalUserService._validate_service("")
    with pytest.raises(LocalUserValidationError):
        LocalUserService._validate_list(["ok", ""], "groups")
    with pytest.raises(LocalUserValidationError):
        LocalUserService._validate_safe_path("", "data")

    svc.delete_user("dave")
    assert not svc.delete_user_if_exists("dave")
    svc.reload()


def test_local_user_group_service_crud(tmp_path: Path):
    store = LocalAuthStore(tmp_path / "groups.db")
    try:
        service = LocalUserGroupService(store=store)
        grp = service.create_group("admins", metadata={"foo": "bar"}, privilege_level=2)
        assert grp.metadata["foo"] == "bar"
        with pytest.raises(LocalUserGroupExists):
            service.create_group("admins")
        patched = service.update_group(
            "admins", description="desc", metadata={"foo": "baz"}
        )
        assert patched.metadata["foo"] == "baz"
        assert "admins" in [g.name for g in service.list_groups()]
        assert service.delete_group("admins")
        with pytest.raises(LocalUserGroupNotFound):
            service.delete_group("admins")
        with pytest.raises(LocalUserGroupValidationError):
            LocalUserGroupService._validate_metadata("bad")
        with pytest.raises(LocalUserGroupValidationError):
            service.create_group("", metadata={})
    finally:
        store.close()


def test_local_auth_backend_flows(tmp_path: Path):
    store = LocalAuthStore(tmp_path / "backend.db")
    try:
        svc = LocalUserService(db_path=store.db_path, store=store)
        svc.create_user("emma", password="Str0ngPwd2")
        backend = LocalAuthBackend(service=svc, cache_ttl_seconds=1)
        assert backend.authenticate("emma", "Str0ngPwd2")
        assert not backend.authenticate("emma", "bad")
        svc.update_user("emma", enabled=False)
        assert not backend.authenticate("emma", "Str0ngPwd2")
        svc.update_user("emma", enabled=True)
        assert backend.add_user("fred", "Str0ngPwd3")
        assert backend.get_stats()["total_users"] >= 2
        assert backend.change_password("emma", "Str0ngPwd2", "Str0ngPwd3")
        assert not backend.change_password("emma", "wrong", "Str0ngPwd3")
        assert backend.remove_user("fred")
        assert not backend.remove_user("fred")
        backend._get_user("emma")
        assert "emma" in backend._user_cache
        backend.invalidate_user_cache("emma")
        assert "emma" not in backend._user_cache
        assert backend.reload_users()
        attrs = backend.get_user_attributes("emma")
        assert "password" not in attrs
        assert backend.get_stats()["total_users"] >= 1
    finally:
        store.close()
