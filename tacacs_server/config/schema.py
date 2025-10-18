"""Pydantic schema for TACACS+ configuration validation."""

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ServerConfigSchema(BaseModel):
    model_config = ConfigDict(extra="ignore")
    host: str = Field(..., description="Server bind host")
    port: int = Field(..., ge=1, le=65535, description="Server TCP port")
    # secret_key removed - secrets are now per-device group
    log_level: str = Field(default="INFO")
    max_connections: int = Field(default=50, ge=1)
    socket_timeout: int = Field(default=30, ge=1)


class AuthConfigSchema(BaseModel):
    backends: str = Field(..., description="Comma separated backend list")
    local_auth_db: str = Field(..., description="SQLite DB path")
    require_all_backends: bool = Field(default=False)


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
    org_url: str
    token: str
    timeout: int = Field(default=10, ge=0)


class TacacsConfigSchema(BaseModel):
    server: ServerConfigSchema
    auth: AuthConfigSchema
    security: SecurityConfigSchema
    ldap: LdapConfigSchema | None = None
    okta: OktaConfigSchema | None = None

    @field_validator("auth")
    @classmethod
    def backends_not_empty(cls, value: AuthConfigSchema) -> AuthConfigSchema:
        backends = [
            entry.strip() for entry in value.backends.split(",") if entry.strip()
        ]
        if not backends:
            raise ValueError("At least one authentication backend must be configured")
        return value


def validate_config_file(payload: dict) -> TacacsConfigSchema:
    """Validate configuration payload with Pydantic schema."""

    return TacacsConfigSchema(**payload)
