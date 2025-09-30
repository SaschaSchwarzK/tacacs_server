"""Shared dataclasses for local authentication records."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LocalUserRecord:
    """In-memory representation of a local user entry."""

    username: str
    privilege_level: int = 1
    service: str = "exec"
    shell_command: List[str] = field(default_factory=lambda: ["show"])
    groups: List[str] = field(default_factory=lambda: ["users"])
    enabled: bool = True
    description: Optional[str] = None
    password: Optional[str] = None
    password_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
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
    def from_dict(cls, username: str, payload: Dict[str, Any]) -> "LocalUserRecord":
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
    description: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    ldap_group: Optional[str] = None
    okta_group: Optional[str] = None
    privilege_level: int = 1

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
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
    def from_dict(cls, name: str, payload: Dict[str, Any]) -> "LocalUserGroupRecord":
        return cls(
            name=name,
            description=payload.get("description"),
            metadata=payload.get("metadata") or {},
            ldap_group=payload.get("ldap_group"),
            okta_group=payload.get("okta_group"),
            privilege_level=int(payload.get("privilege_level", 1)),
        )
