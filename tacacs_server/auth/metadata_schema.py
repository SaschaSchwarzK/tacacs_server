"""Pydantic schemas for user group metadata validation."""

import ipaddress
from typing import Any

from pydantic import BaseModel, Field, field_validator


class CiscoVSAConfig(BaseModel):
    """Cisco VSA configuration."""

    avpairs: list[dict[str, str]] = Field(default_factory=list)
    timeout: int | None = Field(None, ge=0, le=86400)

    @field_validator("avpairs")
    @classmethod
    def validate_avpairs(cls, v: list[dict[str, str]]) -> list[dict[str, str]]:
        for item in v:
            if "key" not in item or "value" not in item:
                raise ValueError("Each avpair must have 'key' and 'value'")
            key = item["key"]
            if ":" not in key:
                raise ValueError(f"Cisco AVPair key must contain ':' (got: {key})")
        return v


class JuniperVSAConfig(BaseModel):
    """Juniper VSA configuration."""

    local_user_name: str | None = None
    user_permissions: list[str] = Field(default_factory=list)


class FortinetVSAConfig(BaseModel):
    """Fortinet VSA configuration."""

    group_names: list[str] = Field(default_factory=list)


class PfSenseVSAConfig(BaseModel):
    """pfSense/OPNsense VSA configuration."""

    client_ip_override: str | None = None

    @field_validator("client_ip_override")
    @classmethod
    def validate_ip(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {v}") from exc
        return v


class PaloAltoVSAConfig(BaseModel):
    """Palo Alto VSA configuration."""

    user_role: str | None = None


class AristaVSAConfig(BaseModel):
    """Arista VSA configuration."""

    privilege_level: int = Field(default=1, ge=0, le=15)


class RADIUSVSAConfig(BaseModel):
    """RADIUS vendor-specific attributes configuration."""

    cisco: CiscoVSAConfig | None = None
    juniper: JuniperVSAConfig | None = None
    fortinet: FortinetVSAConfig | None = None
    pfsense: PfSenseVSAConfig | None = None
    palo_alto: PaloAltoVSAConfig | None = None
    arista: AristaVSAConfig | None = None


class SessionTimeoutsConfig(BaseModel):
    """Session timeout configuration."""

    idle_timeout: int | None = Field(None, ge=0, le=86400)
    session_timeout: int | None = Field(None, ge=0, le=86400)


class UserGroupMetadata(BaseModel):
    """User group metadata schema with validation."""

    model_config = {"extra": "allow"}

    schema_version: str = "1.0"
    privilege_level: int = Field(default=1, ge=0, le=15)
    radius_vsa: RADIUSVSAConfig = Field(default_factory=lambda: RADIUSVSAConfig())
    session_timeouts: SessionTimeoutsConfig = Field(
        default_factory=lambda: SessionTimeoutsConfig(
            idle_timeout=None, session_timeout=None
        )
    )
    custom_attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, v: str) -> str:
        if v not in {"1.0"}:
            raise ValueError(f"Unsupported schema version: {v}")
        return v


def validate_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize user group metadata.

    Args:
        metadata: Raw metadata dictionary

    Returns:
        Validated metadata as dictionary

    Raises:
        ValueError: If metadata is invalid
    """
    validated = UserGroupMetadata(**metadata)
    return validated.model_dump(exclude_none=True)
