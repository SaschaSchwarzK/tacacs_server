"""Pydantic schema for TACACS+ configuration validation."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ServerConfigSchema(BaseModel):
    model_config = ConfigDict(extra="ignore")
    host: str = Field(..., description="Server bind host")
    port: int = Field(..., ge=1, le=65535, description="Server TCP port")
    # secret_key removed - secrets are now per-device group
    log_level: str = Field(default="INFO")
    max_connections: int = Field(default=50, ge=1)
    socket_timeout: int = Field(default=30, ge=1)
    accept_proxy_protocol: bool = Field(
        default=True, description="Accept HAProxy PROXY v2 headers"
    )
    # Optional instance name (for display/metadata)
    instance_name: str | None = Field(default=None)

    @field_validator("instance_name")
    @classmethod
    def _validate_instance_name(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not re.fullmatch(r"[A-Za-z0-9_-]+", v):
            raise ValueError(
                "instance_name must be alphanumeric with hyphens/underscores only"
            )
        return v


class AuthConfigSchema(BaseModel):
    backends: str = Field(..., description="Comma separated backend list")
    local_auth_db: str = Field(..., description="SQLite DB path")
    require_all_backends: bool = Field(default=False)
    local_auth_cache_ttl_seconds: int = Field(default=60, ge=0, le=3600)
    backend_timeout: float = Field(default=2.0, ge=0.1, le=30.0)


class SecurityConfigSchema(BaseModel):
    max_auth_attempts: int = Field(default=3, ge=0)
    auth_timeout: int = Field(default=300, ge=0)
    encryption_required: bool = Field(default=True)
    allowed_clients: str = Field(default="")
    denied_clients: str = Field(default="")


class LdapConfigSchema(BaseModel):
    server: str
    base_dn: str
    user_attribute: str = Field(default="uid")
    bind_dn: str = Field(default="")
    bind_password: str = Field(default="")
    use_tls: bool = Field(default=False)
    timeout: int = Field(default=10, ge=0)


class OktaConfigSchema(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)
    org_url: str
    # Accept either 'api_token' or legacy 'token'
    api_token: str | None = Field(default=None, alias="token")
    verify_tls: bool = Field(default=True)
    timeout: int = Field(default=10, ge=0)


class TacacsConfigSchema(BaseModel):
    server: ServerConfigSchema
    auth: AuthConfigSchema
    security: SecurityConfigSchema
    ldap: LdapConfigSchema | None = None
    okta: OktaConfigSchema | None = None
    backup: BackupConfigSchema | None = None
    # Optional remote source URL – HTTPS only, no localhost/private IPs
    source_url: str | None = None

    @field_validator("auth")
    @classmethod
    def backends_not_empty(cls, value: AuthConfigSchema) -> AuthConfigSchema:
        backends = [
            entry.strip() for entry in value.backends.split(",") if entry.strip()
        ]
        if not backends:
            raise ValueError("At least one authentication backend must be configured")
        return value

    @model_validator(mode="after")
    def _cross_field_validation(self) -> TacacsConfigSchema:
        # If LDAP backend is configured, ldap section must be present
        try:
            backends = [
                entry.strip().lower()
                for entry in (self.auth.backends or "").split(",")
                if entry.strip()
            ]
            if "ldap" in backends and self.ldap is None:
                raise ValueError("LDAP backend selected but [ldap] section is missing")
        except Exception:
            pass
        # Validate source_url constraints
        if self.source_url:
            if not self.source_url.lower().startswith("https://"):
                raise ValueError("source_url must use HTTPS")
            # Block localhost/private
            if re.search(
                r"^(https://)?(localhost|127\.0\.0\.1)\b",
                self.source_url,
                re.IGNORECASE,
            ):
                raise ValueError("source_url must not point to localhost")
        return self


def validate_config_file(payload: dict) -> TacacsConfigSchema:
    """Validate configuration payload with Pydantic schema."""

    return TacacsConfigSchema(**payload)


class BackupConfigSchema(BaseModel):
    """Backup configuration schema."""

    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    create_on_startup: bool = False
    temp_directory: str = "data/backup_temp"
    encryption_enabled: bool = False
    default_retention_days: int = Field(ge=1, le=3650, default=30)
    default_retention_strategy: str = Field(default="simple")
    compression_level: int = Field(default=6, ge=1, le=9)

    # GFS configuration
    gfs_keep_daily: int = Field(default=7, ge=1)
    gfs_keep_weekly: int = Field(default=4, ge=1)
    gfs_keep_monthly: int = Field(default=12, ge=1)
    gfs_keep_yearly: int = Field(default=3, ge=0)

    @field_validator("default_retention_strategy")
    @classmethod
    def validate_strategy(cls, v: str) -> str:
        valid = ["simple", "gfs", "hanoi"]
        if v not in valid:
            raise ValueError(f"Strategy must be one of: {valid}")
        return v
