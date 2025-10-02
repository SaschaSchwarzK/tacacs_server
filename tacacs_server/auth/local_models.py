"""Shared dataclasses for local authentication records."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LocalUserRecord:
    """In-memory representation of a local user entry."""

    username: str
    privilege_level: int = 1
    service: str = "exec"
    shell_command: list[str] = field(default_factory=lambda: ["show"])
    groups: list[str] = field(default_factory=lambda: ["users"])
    enabled: bool = True
    description: str | None = None
    password: str | None = None
    password_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "password": self.password,
            "password_hash": self.password_hash,
            "privilege_level": self.privilege_level,
            "service": self.service,
            "shell_command": list(self.shell_command),
            "groups": list(self.groups),
            "enabled": self.enabled,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, username: str, payload: dict[str, Any]) -> LocalUserRecord:
        return cls(
            username=username,
            privilege_level=int(payload.get("privilege_level", 1)),
            service=str(payload.get("service", "exec")),
            shell_command=list(payload.get("shell_command", ["show"])),
            groups=list(payload.get("groups", ["users"])),
            enabled=bool(payload.get("enabled", True)),
            description=payload.get("description"),
            password=payload.get("password"),
            password_hash=payload.get("password_hash"),
        )


@dataclass
class LocalUserGroupRecord:
    """In-memory representation of a local user group."""

    name: str
    description: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    ldap_group: str | None = None
    okta_group: str | None = None
    privilege_level: int = 1

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "description": self.description,
            "metadata": self.metadata,
            "privilege_level": self.privilege_level,
        }
        if self.ldap_group is not None:
            payload["ldap_group"] = self.ldap_group
        if self.okta_group is not None:
            payload["okta_group"] = self.okta_group
        return payload

    @classmethod
    def from_dict(cls, name: str, payload: dict[str, Any]) -> LocalUserGroupRecord:
        return cls(
            name=name,
            description=payload.get("description"),
            metadata=payload.get("metadata") or {},
            ldap_group=payload.get("ldap_group"),
            okta_group=payload.get("okta_group"),
            privilege_level=int(payload.get("privilege_level", 1)),
        )
