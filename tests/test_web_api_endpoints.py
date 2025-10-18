"""Integration-style tests for FastAPI routers under tacacs_server/web/api."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tacacs_server.auth.local_user_group_service import (
    LocalUserGroupExists,
    LocalUserGroupNotFound,
    LocalUserGroupValidationError,
)
from tacacs_server.auth.local_user_service import (
    LocalUserExists,
    LocalUserNotFound,
    LocalUserValidationError,
)
from tacacs_server.devices.service import (
    DeviceNotFound,
    DeviceValidationError,
    GroupNotFound,
)
from tacacs_server.web.api import device_groups as device_groups_module
from tacacs_server.web.api import devices as devices_module
from tacacs_server.web.api import usergroups as usergroups_module
from tacacs_server.web.api import users as users_module


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class FakeDeviceService:
    def __init__(self) -> None:
        self.devices = [
            {
                "id": 1,
                "name": "router-1",
                "ip_address": "192.0.2.1",
                "network": "192.0.2.0/30",
                "device_group_id": 10,
                "device_group_name": "core",
                "enabled": True,
                "metadata": {},
                "created_at": _now_iso(),
                "updated_at": None,
            }
        ]
        self.device_groups = [
            {
                "id": 10,
                "name": "core",
                "description": "Core devices",
                "tacacs_secret_set": True,
                "radius_secret_set": False,
                "allowed_user_groups": [1],
                "device_count": 1,
                "created_at": _now_iso(),
                "tacacs_profile": {},
                "radius_profile": {},
            }
        ]
        self.next_device_id = 2
        self.next_group_id = 11

    # Device endpoints -------------------------------------------------
    def get_devices(self, *_, **__) -> list[dict]:
        return list(self.devices)

    def get_device_by_id(self, device_id: int) -> dict | None:
        return next((d for d in self.devices if d["id"] == device_id), None)

    def create_device_from_dict(self, **payload) -> dict:
        if payload.get("device_group_id") not in {g["id"] for g in self.device_groups}:
            raise GroupNotFound("group missing")
        record = {
            "id": self.next_device_id,
            "name": payload["name"],
            "ip_address": payload["ip_address"],
            "network": payload.get("ip_address", ""),
            "device_group_id": payload.get("device_group_id"),
            "device_group_name": next(
                (
                    g["name"]
                    for g in self.device_groups
                    if g["id"] == payload.get("device_group_id")
                ),
                None,
            ),
            "enabled": payload.get("enabled", True),
            "metadata": payload.get("metadata") or {},
            "created_at": _now_iso(),
            "updated_at": None,
        }
        self.devices.append(record)
        self.next_device_id += 1
        return record

    def update_device_from_dict(self, device_id: int, **payload) -> dict:
        record = self.get_device_by_id(device_id)
        if record is None:
            raise DeviceNotFound("missing device")
        record = dict(record)
        for key, value in payload.items():
            if key == "ip_address":
                record["ip_address"] = value
                record["network"] = value
            elif key == "metadata" and value is None:
                record["metadata"] = {}
            elif key is not None and value is not None:
                record[key] = value
        record["updated_at"] = _now_iso()
        # replace stored copy
        for idx, existing in enumerate(self.devices):
            if existing["id"] == device_id:
                self.devices[idx] = record
                break
        return record

    def delete_device(self, device_id: int) -> None:
        for idx, record in enumerate(self.devices):
            if record["id"] == device_id:
                del self.devices[idx]
                return
        raise DeviceNotFound("missing device")

    # Device group endpoints -------------------------------------------
    def get_device_groups(self, *_, **__) -> list[dict]:
        return list(self.device_groups)

    def get_device_group_by_id(self, group_id: int) -> dict | None:
        return next((g for g in self.device_groups if g["id"] == group_id), None)

    def create_device_group(self, **payload) -> dict:
        if not payload.get("name"):
            raise DeviceValidationError("Group name required")
        record = {
            "id": self.next_group_id,
            "name": payload["name"],
            "description": payload.get("description"),
            "tacacs_secret_set": bool(payload.get("tacacs_secret")),
            "radius_secret_set": bool(payload.get("radius_secret")),
            "allowed_user_groups": [
                int(v) for v in (payload.get("allowed_user_groups") or [])
            ],
            "device_count": 0,
            "created_at": _now_iso(),
            "tacacs_profile": {},
            "radius_profile": {},
        }
        self.device_groups.append(record)
        self.next_group_id += 1
        return record

    def update_device_group(self, group_id: int, **payload) -> dict:
        record = self.get_device_group_by_id(group_id)
        if record is None:
            raise DeviceValidationError("Group missing")
        record = dict(record)
        for key in ("name", "description"):
            if payload.get(key) is not None:
                record[key] = payload[key]
        if payload.get("tacacs_secret") is not None:
            record["tacacs_secret_set"] = bool(payload["tacacs_secret"])
        if payload.get("radius_secret") is not None:
            record["radius_secret_set"] = bool(payload["radius_secret"])
        if payload.get("allowed_user_groups") is not None:
            record["allowed_user_groups"] = [
                int(v) for v in payload["allowed_user_groups"]
            ]
        record["updated_at"] = _now_iso()
        for idx, existing in enumerate(self.device_groups):
            if existing["id"] == group_id:
                self.device_groups[idx] = record
                break
        return record

    def delete_device_group(self, group_id: int) -> None:
        for idx, record in enumerate(self.device_groups):
            if record["id"] == group_id:
                del self.device_groups[idx]
                return
        raise DeviceValidationError("Group missing")


class FakeUserService:
    def __init__(self) -> None:
        self.password_updates: list[tuple[str, str]] = []
        self._users: dict[str, SimpleNamespace] = {
            "alice": SimpleNamespace(
                id=1,
                username="alice",
                privilege_level=1,
                service="exec",
                groups=["admins"],
                enabled=True,
                description=None,
                created_at=_now_iso(),
                updated_at=None,
            )
        }
        self._next_id = 2

    def list_users(self) -> list[SimpleNamespace]:
        return list(self._users.values())

    def get_user(self, username: str) -> SimpleNamespace:
        try:
            return self._users[username]
        except KeyError as exc:
            raise LocalUserNotFound(username) from exc

    def create_user(self, username: str, **payload) -> SimpleNamespace:
        if username in self._users:
            raise LocalUserExists(username)
        record = SimpleNamespace(
            id=self._next_id,
            username=username,
            privilege_level=payload.get("privilege_level", 1),
            service=payload.get("service", "exec"),
            # shell_command removed
            groups=payload.get("groups", []),
            enabled=payload.get("enabled", True),
            description=payload.get("description"),
            created_at=_now_iso(),
            updated_at=None,
        )
        self._users[username] = record
        self._next_id += 1
        return record

    def update_user(self, username: str, **payload) -> SimpleNamespace:
        record = self.get_user(username)
        for key, value in payload.items():
            if value is not None and hasattr(record, key):
                setattr(record, key, value)
        record.updated_at = _now_iso()
        return record

    def set_password(self, username: str, password: str) -> SimpleNamespace:
        record = self.get_user(username)
        if not password:
            raise LocalUserValidationError("Password required")
        self.password_updates.append((username, password))
        record.updated_at = _now_iso()
        return record

    def delete_user(self, username: str) -> None:
        if username not in self._users:
            raise LocalUserNotFound(username)
        del self._users[username]


class FakeUserGroupService:
    def __init__(self) -> None:
        self._groups: dict[str, SimpleNamespace] = {
            "admins": SimpleNamespace(
                id=1,
                name="admins",
                description="Administrators",
                privilege_level=15,
                metadata={"source": "local"},
                ldap_group=None,
                okta_group=None,
                created_at=_now_iso(),
                updated_at=None,
            )
        }
        self._next_id = 2

    def list_groups(self) -> list[SimpleNamespace]:
        return list(self._groups.values())

    def get_group(self, name: str) -> SimpleNamespace:
        try:
            return self._groups[name]
        except KeyError as exc:
            raise LocalUserGroupNotFound(name) from exc

    def create_group(
        self,
        name: str,
        *,
        description: str | None = None,
        metadata: dict | None = None,
        ldap_group: str | None = None,
        okta_group: str | None = None,
        privilege_level: int = 1,
    ) -> SimpleNamespace:
        if name in self._groups:
            raise LocalUserGroupExists(name)
        if privilege_level < 0 or privilege_level > 15:
            raise LocalUserGroupValidationError("Invalid privilege level")
        record = SimpleNamespace(
            id=self._next_id,
            name=name,
            description=description,
            privilege_level=privilege_level,
            metadata=metadata or {},
            ldap_group=ldap_group,
            okta_group=okta_group,
            created_at=_now_iso(),
            updated_at=None,
        )
        self._groups[name] = record
        self._next_id += 1
        return record

    def update_group(self, name: str, **payload) -> SimpleNamespace:
        record = self.get_group(name)
        if "privilege_level" in payload:
            level = payload["privilege_level"]
            if level is None or level < 0 or level > 15:
                raise LocalUserGroupValidationError("Invalid privilege level")
            record.privilege_level = level
        if "description" in payload and payload["description"] is not None:
            record.description = payload["description"]
        if "metadata" in payload and payload["metadata"] is not None:
            record.metadata = payload["metadata"]
        if "ldap_group" in payload:
            record.ldap_group = payload["ldap_group"]
        if "okta_group" in payload:
            record.okta_group = payload["okta_group"]
        record.updated_at = _now_iso()
        return record

    def delete_group(self, name: str) -> None:
        if name not in self._groups:
            raise LocalUserGroupNotFound(name)
        del self._groups[name]


@pytest.fixture
def api_client(monkeypatch):
    app = FastAPI()
    device_service = FakeDeviceService()
    user_service = FakeUserService()
    user_group_service = FakeUserGroupService()

    monkeypatch.setattr(devices_module, "get_device_service", lambda: device_service)
    monkeypatch.setattr(
        device_groups_module, "get_device_service", lambda: device_service
    )
    monkeypatch.setattr(users_module, "get_user_service", lambda: user_service)
    monkeypatch.setattr(
        usergroups_module, "get_group_service", lambda: user_group_service
    )
    monkeypatch.setattr(usergroups_module, "_get_user_service", lambda: user_service)

    app.include_router(devices_module.router)
    app.include_router(device_groups_module.router)
    app.include_router(users_module.router)
    app.include_router(usergroups_module.router)

    client = TestClient(app)
    client.device_service = device_service  # type: ignore[attr-defined]
    client.user_service = user_service  # type: ignore[attr-defined]
    client.user_group_service = user_group_service  # type: ignore[attr-defined]
    return client


# Device API tests ----------------------------------------------------


def test_list_devices_returns_items(api_client):
    response = api_client.get("/api/devices")
    assert response.status_code == 200
    data = response.json()
    assert data and data[0]["name"] == "router-1"


def test_get_device_not_found_returns_404(api_client):
    response = api_client.get("/api/devices/999")
    assert response.status_code == 404


def test_create_device_handles_group_error(api_client, monkeypatch):
    fake_service = api_client.device_service

    def raise_group_not_found(**_):
        raise GroupNotFound("missing")

    monkeypatch.setattr(fake_service, "create_device_from_dict", raise_group_not_found)
    payload = {"name": "r2", "ip_address": "198.51.100.1", "device_group_id": 99}
    response = api_client.post("/api/devices", json=payload)
    assert response.status_code == 400


def test_update_device_returns_404_when_missing(api_client):
    payload = {"name": "updated"}
    response = api_client.put("/api/devices/999", json=payload)
    assert response.status_code == 404


def test_delete_device_success(api_client):
    # add another device to delete without touching existing fixture
    record = api_client.device_service.create_device_from_dict(
        name="router-2",
        ip_address="198.51.100.2",
        device_group_id=10,
        enabled=True,
        metadata={},
    )
    response = api_client.delete(f"/api/devices/{record['id']}")
    assert response.status_code == 204


def test_delete_device_not_found(api_client):
    response = api_client.delete("/api/devices/12345")
    assert response.status_code == 404


# Device group API tests ---------------------------------------------


def test_list_device_groups_returns_items(api_client):
    response = api_client.get("/api/device-groups")
    assert response.status_code == 200
    data = response.json()
    assert data and data[0]["name"] == "core"


def test_get_device_group_not_found(api_client):
    response = api_client.get("/api/device-groups/999")
    assert response.status_code == 404


def test_create_device_group_validation_error(api_client, monkeypatch):
    fake_service = api_client.device_service

    def raise_validation(**_):
        raise DeviceValidationError("bad group")

    monkeypatch.setattr(fake_service, "create_device_group", raise_validation)
    payload = {
        "name": "bad-group",
        "description": "bad",
        "tacacs_secret": "TacacsSecret123!",
    }
    response = api_client.post("/api/device-groups", json=payload)
    assert response.status_code == 400


def test_delete_device_group_conflict(api_client):
    group = api_client.device_service.get_device_group_by_id(10)
    group["device_count"] = 2
    response = api_client.delete("/api/device-groups/10")
    assert response.status_code == 409
    group["device_count"] = 1  # reset for other tests


def test_update_device_group_handles_service_error(api_client, monkeypatch):
    fake_service = api_client.device_service

    def raise_validation(group_id: int, **_):
        raise DeviceValidationError(f"invalid {group_id}")

    monkeypatch.setattr(fake_service, "update_device_group", raise_validation)
    payload = {"description": "updated"}
    response = api_client.put("/api/device-groups/10", json=payload)
    assert response.status_code == 400


def test_delete_device_group_success(api_client):
    group = api_client.device_service.create_device_group(name="tmp")
    response = api_client.delete(f"/api/device-groups/{group['id']}")
    assert response.status_code == 204


# User API tests -----------------------------------------------------


def test_list_users_returns_items(api_client):
    response = api_client.get("/api/users")
    assert response.status_code == 200
    assert response.json()[0]["username"] == "alice"


def test_get_user_not_found(api_client, monkeypatch):
    fake_service = api_client.user_service

    def raise_not_found(username: str):
        raise LocalUserNotFound(username)

    monkeypatch.setattr(fake_service, "get_user", raise_not_found)
    response = api_client.get("/api/users/unknown")
    assert response.status_code == 404


def test_create_user_conflict(api_client, monkeypatch):
    fake_service = api_client.user_service

    def raise_exists(username: str, **_):
        raise LocalUserExists(username)

    monkeypatch.setattr(fake_service, "create_user", raise_exists)
    payload = {
        "username": "alice",
        "password": "Secret123!",
        "privilege_level": 1,
        "service": "exec",
        "groups": [],
        "enabled": True,
    }
    response = api_client.post("/api/users", json=payload)
    assert response.status_code == 409


def test_update_user_sets_password(api_client):
    payload = {"password": "NewSecret789!"}
    response = api_client.put("/api/users/alice", json=payload)
    assert response.status_code == 200
    assert api_client.user_service.password_updates[-1] == ("alice", "NewSecret789!")


def test_delete_user_not_found(api_client, monkeypatch):
    fake_service = api_client.user_service

    def raise_not_found(username: str):
        raise LocalUserNotFound(username)

    monkeypatch.setattr(fake_service, "delete_user", raise_not_found)
    response = api_client.delete("/api/users/missing")
    assert response.status_code == 404


# User group API tests -----------------------------------------------


def test_list_user_groups_adds_member_counts(api_client):
    response = api_client.get("/api/user-groups")
    assert response.status_code == 200
    data = response.json()
    assert data[0]["member_count"] == 1


def test_get_user_group_not_found(api_client, monkeypatch):
    fake_service = api_client.user_group_service

    def raise_not_found(name: str):
        raise LocalUserGroupNotFound(name)

    monkeypatch.setattr(fake_service, "get_group", raise_not_found)
    response = api_client.get("/api/user-groups/unknown")
    assert response.status_code == 404


def test_create_user_group_validation_error(api_client, monkeypatch):
    fake_service = api_client.user_group_service

    def raise_validation(*_, **__):
        raise LocalUserGroupValidationError("invalid")

    monkeypatch.setattr(fake_service, "create_group", raise_validation)
    payload = {"name": "ops", "privilege_level": 10}
    response = api_client.post("/api/user-groups", json=payload)
    assert response.status_code == 400


def test_update_user_group_not_found(api_client, monkeypatch):
    fake_service = api_client.user_group_service

    def raise_not_found(name: str, **_):
        raise LocalUserGroupNotFound(name)

    monkeypatch.setattr(fake_service, "update_group", raise_not_found)
    response = api_client.put("/api/user-groups/ghost", json={"description": "d"})
    assert response.status_code == 404


def test_delete_user_group_not_found(api_client, monkeypatch):
    fake_service = api_client.user_group_service

    def raise_not_found(name: str):
        raise LocalUserGroupNotFound(name)

    monkeypatch.setattr(fake_service, "delete_group", raise_not_found)
    response = api_client.delete("/api/user-groups/unknown")
    assert response.status_code == 404
