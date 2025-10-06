"""
Enhanced Pydantic Models with OpenAPI Documentation

Location: tacacs_server/web/api_models.py

Complete model definitions for all API endpoints.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, EmailStr, Field, validator

# ============================================================================
# Enums
# ============================================================================


class UserStatus(str, Enum):
    """User account status"""

    active = "active"
    disabled = "disabled"
    locked = "locked"


class DeviceStatus(str, Enum):
    """Device status"""

    enabled = "enabled"
    disabled = "disabled"
    maintenance = "maintenance"


class AuthBackendType(str, Enum):
    """Authentication backend types"""

    local = "local"
    ldap = "ldap"
    okta = "okta"


# ============================================================================
# User Models
# ============================================================================


class UserBase(BaseModel):
    """Base user model with common fields"""

    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Unique username",
        example="jsmith",
    )
    email: EmailStr = Field(
        ..., description="User email address", example="jsmith@example.com"
    )
    privilege_level: int = Field(
        default=1, ge=0, le=15, description="TACACS+ privilege level", example=5
    )
    enabled: bool = Field(
        default=True, description="Account enabled status", example=True
    )


class UserCreate(UserBase):
    """Model for creating a new user"""

    password: str = Field(
        ..., min_length=8, description="User password", example="SecurePass123!"
    )
    groups: list[int] | None = Field(
        default=[], description="User group IDs", example=[1, 2]
    )

    @validator("password")
    def validate_password_strength(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v):
            raise ValueError("Password must contain special character")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "username": "jsmith",
                "password": "SecurePass123!",
                "email": "jsmith@example.com",
                "privilege_level": 5,
                "enabled": True,
                "groups": [1, 2],
            }
        }


class UserUpdate(BaseModel):
    """Model for updating user details"""

    email: EmailStr | None = Field(
        None, description="Updated email", example="new@example.com"
    )
    privilege_level: int | None = Field(
        None, ge=0, le=15, description="Updated privilege", example=10
    )
    enabled: bool | None = Field(
        None, description="Enable/disable account", example=False
    )
    groups: list[int] | None = Field(
        None, description="Updated group IDs", example=[1, 3]
    )
    password: str | None = Field(
        None, min_length=8, description="New password", example="NewPass456!"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "email": "updated@example.com",
                "privilege_level": 10,
                "enabled": True,
            }
        }


class UserResponse(UserBase):
    """Model for user responses"""

    id: int = Field(..., description="Unique user ID", example=1)
    groups: list[str] = Field(
        default=[], description="User group names", example=["admins"]
    )
    created_at: datetime = Field(
        ..., description="Creation timestamp", example="2024-01-01T12:00:00Z"
    )
    updated_at: datetime | None = Field(
        None, description="Last update", example="2024-01-15T14:30:00Z"
    )
    last_login: datetime | None = Field(
        None, description="Last login", example="2024-01-20T09:15:00Z"
    )

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "username": "jsmith",
                "email": "jsmith@example.com",
                "privilege_level": 5,
                "enabled": True,
                "groups": ["admins"],
                "created_at": "2024-01-01T12:00:00Z",
                "updated_at": "2024-01-15T14:30:00Z",
                "last_login": "2024-01-20T09:15:00Z",
            }
        }


# ============================================================================
# Device Models
# ============================================================================


class DeviceBase(BaseModel):
    """Base device model"""

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Device name",
        example="router-01",
    )
    ip_address: str = Field(..., description="Device IP or CIDR", example="192.168.1.1")
    device_group_id: int = Field(..., description="Device group ID", example=1)
    enabled: bool = Field(default=True, description="Device enabled", example=True)
    metadata: dict[str, Any] | None = Field(
        default={},
        description="Custom metadata",
        example={"location": "DC-A", "model": "Cisco-7200"},
    )


class DeviceCreate(DeviceBase):
    """Model for creating a new device"""

    class Config:
        json_schema_extra = {
            "example": {
                "name": "router-01",
                "ip_address": "192.168.1.1",
                "device_group_id": 1,
                "enabled": True,
                "metadata": {
                    "location": "Datacenter-A",
                    "rack": "R12",
                    "model": "Cisco-7200",
                },
            }
        }


class DeviceUpdate(BaseModel):
    """Model for updating device details"""

    name: str | None = Field(
        None,
        min_length=1,
        max_length=100,
        description="Updated name",
        example="router-01-new",
    )
    ip_address: str | None = Field(
        None, description="Updated IP", example="192.168.1.2"
    )
    device_group_id: int | None = Field(None, description="New group", example=2)
    enabled: bool | None = Field(None, description="Enable/disable", example=False)
    metadata: dict[str, Any] | None = Field(
        None, description="Updated metadata", example={"location": "DC-B"}
    )


class DeviceResponse(DeviceBase):
    """Model for device responses"""

    id: int = Field(..., description="Unique device ID", example=1)
    device_group_name: str = Field(
        ..., description="Device group name", example="Core-Routers"
    )
    created_at: datetime = Field(
        ..., description="Creation timestamp", example="2024-01-01T12:00:00Z"
    )
    updated_at: datetime | None = Field(
        None, description="Last update", example="2024-01-15T14:30:00Z"
    )
    last_seen: datetime | None = Field(
        None, description="Last authentication", example="2024-01-20T09:15:00Z"
    )

    class Config:
        from_attributes = True


# ============================================================================
# Device Group Models
# ============================================================================


class DeviceGroupBase(BaseModel):
    """Base device group model"""

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Group name",
        example="Core-Routers",
    )
    description: str | None = Field(
        None, description="Group description", example="All core routers"
    )


class DeviceGroupCreate(DeviceGroupBase):
    """Model for creating device group"""

    tacacs_secret: str = Field(
        ..., min_length=8, description="TACACS+ secret", example="TacacsSecret123!"
    )
    radius_secret: str | None = Field(
        None, min_length=8, description="RADIUS secret", example="RadiusSecret123!"
    )
    allowed_user_groups: list[int] | None = Field(
        default=[], description="Allowed user groups", example=[1, 2]
    )

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Core-Routers",
                "description": "All core network routers",
                "tacacs_secret": "TacacsSecret123!",
                "radius_secret": "RadiusSecret123!",
                "allowed_user_groups": [1, 2],
            }
        }


class DeviceGroupUpdate(BaseModel):
    """Model for updating device group"""

    name: str | None = Field(
        None,
        min_length=1,
        max_length=100,
        description="Updated name",
        example="Core-Routers-New",
    )
    description: str | None = Field(
        None, description="Updated description", example="Updated description"
    )
    tacacs_secret: str | None = Field(
        None, min_length=8, description="New TACACS+ secret", example="NewSecret123!"
    )
    radius_secret: str | None = Field(
        None, min_length=8, description="New RADIUS secret", example="NewRadius123!"
    )
    allowed_user_groups: list[int] | None = Field(
        None, description="Updated groups", example=[1, 2, 3]
    )


class DeviceGroupResponse(DeviceGroupBase):
    """Model for device group responses"""

    id: int = Field(..., description="Unique group ID", example=1)
    tacacs_secret_set: bool = Field(
        ..., description="TACACS+ secret configured", example=True
    )
    radius_secret_set: bool = Field(
        ..., description="RADIUS secret configured", example=True
    )
    allowed_user_groups: list[int] = Field(
        default=[], description="Allowed user groups", example=[1, 2]
    )
    device_count: int = Field(..., description="Number of devices", example=5)
    created_at: datetime = Field(
        ..., description="Creation timestamp", example="2024-01-01T12:00:00Z"
    )

    class Config:
        from_attributes = True


# ============================================================================
# Status and Health Models
# ============================================================================


class ServerStatus(BaseModel):
    """Server status response"""

    status: str = Field(..., description="Server status", example="running")
    uptime_seconds: float = Field(..., description="Uptime in seconds", example=86400.5)
    version: str = Field(..., description="Server version", example="1.0.0")
    tacacs: dict[str, Any] = Field(
        ...,
        description="TACACS+ statistics",
        example={"enabled": True, "port": 49, "active_connections": 5},
    )
    radius: dict[str, Any] = Field(
        ...,
        description="RADIUS statistics",
        example={"enabled": True, "auth_port": 1812},
    )


class ConnectionStats(BaseModel):
    """Connection statistics"""

    active: int = Field(..., description="Active connections", example=0)
    total: int = Field(..., description="Total connections", example=0)


class AuthenticationStats(BaseModel):
    """Authentication statistics"""

    requests: int = Field(..., description="Total authentication requests", example=0)
    successes: int = Field(..., description="Successful authentications", example=0)
    failures: int = Field(..., description="Failed authentications", example=0)
    success_rate: float = Field(..., description="Success rate percentage", example=0.0)


class AuthorizationStats(BaseModel):
    """Authorization statistics"""

    requests: int = Field(..., description="Total authorization requests", example=0)
    successes: int = Field(..., description="Successful authorizations", example=0)
    failures: int = Field(..., description="Failed authorizations", example=0)
    success_rate: float = Field(..., description="Success rate percentage", example=0.0)


class AccountingStats(BaseModel):
    """Accounting statistics"""

    requests: int = Field(..., description="Total accounting requests", example=0)
    successes: int = Field(..., description="Successful accounting records", example=0)
    failures: int = Field(..., description="Failed accounting records", example=0)


class MemoryStats(BaseModel):
    """Memory usage statistics"""

    rss_mb: float = Field(..., description="Resident set size in MB", example=65.56)
    vms_mb: float = Field(
        ..., description="Virtual memory size in MB", example=401729.02
    )
    percent: float = Field(..., description="Memory usage percentage", example=0.4)


class RADIUSAuthStats(BaseModel):
    """RADIUS authentication statistics"""

    requests: int = Field(..., description="Total RADIUS auth requests", example=0)
    accepts: int = Field(..., description="Access-Accept responses", example=0)
    rejects: int = Field(..., description="Access-Reject responses", example=0)
    success_rate: float = Field(..., description="Success rate percentage", example=0.0)


class RADIUSAcctStats(BaseModel):
    """RADIUS accounting statistics"""

    requests: int = Field(
        ..., description="Total RADIUS accounting requests", example=0
    )
    responses: int = Field(..., description="Accounting responses sent", example=0)


class RADIUSStats(BaseModel):
    """RADIUS server statistics"""

    enabled: bool = Field(..., description="RADIUS server enabled", example=True)
    running: bool = Field(..., description="RADIUS server running", example=True)
    authentication: RADIUSAuthStats = Field(
        ..., description="RADIUS authentication statistics"
    )
    accounting: RADIUSAcctStats = Field(..., description="RADIUS accounting statistics")
    clients: int = Field(
        ..., description="Number of configured RADIUS clients", example=3
    )
    invalid_packets: int = Field(..., description="Invalid packets received", example=0)


class DetailedServerStatus(BaseModel):
    """Detailed server status response"""

    status: str = Field(
        ..., description="Server status (running, stopped, starting)", example="running"
    )
    uptime: float = Field(..., description="Server uptime in seconds", example=22.42)
    connections: ConnectionStats = Field(..., description="Connection statistics")
    authentication: AuthenticationStats = Field(
        ..., description="TACACS+ authentication statistics"
    )
    authorization: AuthorizationStats = Field(
        ..., description="TACACS+ authorization statistics"
    )
    accounting: AccountingStats = Field(
        ..., description="TACACS+ accounting statistics"
    )
    memory: MemoryStats = Field(..., description="Memory usage statistics")
    timestamp: str = Field(
        ..., description="Status timestamp", example="2025-10-04T17:26:55.876784"
    )
    radius: RADIUSStats = Field(..., description="RADIUS server statistics")

    class Config:
        schema_extra = {
            "example": {
                "status": "running",
                "uptime": 22.42,
                "connections": {"active": 0, "total": 0},
                "authentication": {
                    "requests": 0,
                    "successes": 0,
                    "failures": 0,
                    "success_rate": 0.0,
                },
                "authorization": {
                    "requests": 0,
                    "successes": 0,
                    "failures": 0,
                    "success_rate": 0.0,
                },
                "accounting": {"requests": 0, "successes": 0, "failures": 0},
                "memory": {"rss_mb": 65.56, "vms_mb": 401729.02, "percent": 0.4},
                "timestamp": "2025-10-04T17:26:55.876784",
                "radius": {
                    "enabled": True,
                    "running": True,
                    "authentication": {
                        "requests": 0,
                        "accepts": 0,
                        "rejects": 0,
                        "success_rate": 0.0,
                    },
                    "accounting": {"requests": 0, "responses": 0},
                    "clients": 3,
                    "invalid_packets": 0,
                },
            }
        }


class HealthCheck(BaseModel):
    """Health check response"""

    status: str = Field(..., description="Health status", example="healthy")
    checks: dict[str, bool] = Field(
        ...,
        description="Component health",
        example={"database": True, "tacacs_server": True},
    )
    timestamp: datetime = Field(
        ..., description="Check timestamp", example="2024-01-01T12:00:00Z"
    )


class AuthBackendHealth(BaseModel):
    """Authentication backend health"""

    name: str = Field(..., description="Backend name", example="local")
    available: bool = Field(..., description="Backend availability", example=True)
    last_check: datetime | None = Field(
        None, description="Last health check", example="2024-01-01T12:00:00Z"
    )


class DatabaseHealth(BaseModel):
    """Database health status"""

    status: str = Field(..., description="Database status", example="healthy")
    records_today: int = Field(..., description="Records created today", example=0)


class MemoryUsage(BaseModel):
    """Memory usage statistics"""

    rss_mb: float = Field(..., description="Resident set size in MB", example=64.56)
    vms_mb: float = Field(
        ..., description="Virtual memory size in MB", example=401591.02
    )
    percent: float = Field(..., description="Memory usage percentage", example=0.39)


class DetailedHealthCheck(BaseModel):
    """Detailed health check response"""

    status: str = Field(..., description="Overall health status", example="healthy")
    uptime_seconds: float = Field(
        ..., description="Server uptime in seconds", example=4.19
    )
    active_connections: int = Field(
        ..., description="Number of active connections", example=0
    )
    auth_backends: list[AuthBackendHealth] = Field(
        ..., description="Authentication backend status"
    )
    database_status: DatabaseHealth = Field(..., description="Database health")
    memory_usage: MemoryUsage = Field(..., description="Memory usage statistics")

    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "uptime_seconds": 4.19,
                "active_connections": 0,
                "auth_backends": [
                    {"name": "local", "available": True, "last_check": None}
                ],
                "database_status": {"status": "healthy", "records_today": 0},
                "memory_usage": {"rss_mb": 64.56, "vms_mb": 401591.02, "percent": 0.39},
            }
        }


class BackendStats(BaseModel):
    """Backend statistics"""

    name: str = Field(..., description="Backend name", example="local")
    type: str = Field(..., description="Backend type", example="LocalAuthBackend")
    available: bool = Field(..., description="Backend availability", example=True)
    stats: dict[str, Any] = Field(
        ...,
        description="Backend-specific statistics",
        example={"total_users": 5, "enabled_users": 5},
    )


class DatabaseStats(BaseModel):
    """Database statistics"""

    period_days: int = Field(..., description="Statistics period in days", example=30)
    total_records: int = Field(..., description="Total records in period", example=0)
    unique_users: int = Field(..., description="Unique users in period", example=0)


class SessionDurationStats(BaseModel):
    """Session duration statistics"""

    avg_duration_seconds: float = Field(
        ..., description="Average session duration", example=3600.0
    )
    min_duration_seconds: float = Field(
        ..., description="Minimum session duration", example=60.0
    )
    max_duration_seconds: float = Field(
        ..., description="Maximum session duration", example=7200.0
    )
    completed_sessions: int = Field(
        ..., description="Number of completed sessions", example=10
    )


class ActiveSessionDetail(BaseModel):
    """Active session details"""

    session_id: int = Field(..., description="Session ID", example=12345)
    username: str = Field(..., description="Username", example="jsmith")
    acct_type: str | None = Field(None, description="Accounting type", example="start")
    start_time: int = Field(
        ..., description="Session start timestamp", example=1704374400
    )
    duration_seconds: int = Field(
        ..., description="Current session duration", example=3600
    )
    device_ip: str = Field(..., description="Device IP address", example="192.168.1.1")
    created_at: str = Field(
        ..., description="Record creation timestamp", example="2024-01-01T12:00:00"
    )


class SessionStats(BaseModel):
    """Session statistics"""

    active_sessions: int = Field(
        ..., description="Number of active sessions", example=5
    )
    total_sessions: int = Field(
        ..., description="Total sessions in period", example=100
    )
    duration_stats: SessionDurationStats = Field(
        ..., description="Session duration statistics"
    )
    recent_active: list[ActiveSessionDetail] = Field(
        default=[], description="Recent active sessions"
    )
    error: str | None = Field(None, description="Error message if unavailable")

    class Config:
        extra = "allow"


class DetailedStats(BaseModel):
    """Detailed server statistics response"""

    server: DetailedServerStatus = Field(
        ..., description="Server status and statistics"
    )
    backends: list[BackendStats] = Field(
        ..., description="Authentication backend statistics"
    )
    database: DatabaseStats = Field(..., description="Database statistics")
    sessions: SessionStats = Field(..., description="Active session statistics")

    class Config:
        schema_extra = {
            "example": {
                "server": {
                    "status": "running",
                    "uptime": 11.93,
                    "connections": {"active": 0, "total": 0},
                    "authentication": {
                        "requests": 0,
                        "successes": 0,
                        "failures": 0,
                        "success_rate": 0,
                    },
                    "authorization": {
                        "requests": 0,
                        "successes": 0,
                        "failures": 0,
                        "success_rate": 0,
                    },
                    "accounting": {"requests": 0, "successes": 0, "failures": 0},
                    "memory": {"rss_mb": 66.02, "vms_mb": 402003.02, "percent": 0.4},
                    "timestamp": "2025-10-04T17:56:46.085295",
                    "radius": {
                        "enabled": True,
                        "running": True,
                        "authentication": {
                            "requests": 0,
                            "accepts": 0,
                            "rejects": 0,
                            "success_rate": 0,
                        },
                        "accounting": {"requests": 0, "responses": 0},
                        "clients": 3,
                        "invalid_packets": 0,
                    },
                },
                "backends": [
                    {
                        "name": "local",
                        "type": "LocalAuthBackend",
                        "available": True,
                        "stats": {"total_users": 5, "enabled_users": 5},
                    }
                ],
                "database": {"period_days": 30, "total_records": 0, "unique_users": 0},
                "sessions": {"active_sessions": 0, "total_sessions": 0},
            }
        }


class LocalBackendStats(BaseModel):
    """Local backend specific statistics"""

    total_users: int = Field(..., description="Total number of users", example=5)
    enabled_users: int = Field(..., description="Number of enabled users", example=5)


class LDAPBackendStats(BaseModel):
    """LDAP backend specific statistics"""

    server_url: str = Field(
        ..., description="LDAP server URL", example="ldap://localhost:389"
    )
    base_dn: str = Field(
        ..., description="Base DN", example="ou=people,dc=example,dc=com"
    )
    connection_status: str = Field(
        ..., description="Connection status", example="connected"
    )
    last_sync: str | None = Field(
        None, description="Last sync timestamp", example="2024-01-01T12:00:00Z"
    )


class OktaBackendStats(BaseModel):
    """Okta backend specific statistics"""

    domain: str = Field(..., description="Okta domain", example="example.okta.com")
    api_status: str = Field(..., description="API connection status", example="healthy")
    rate_limit_remaining: int | None = Field(
        None, description="API rate limit remaining", example=1000
    )


class AuthBackendInfo(BaseModel):
    """Authentication backend information"""

    name: str = Field(..., description="Backend name", example="local")
    type: str = Field(..., description="Backend type", example="LocalAuthBackend")
    available: bool = Field(
        ..., description="Backend availability status", example=True
    )
    stats: dict[str, Any] = Field(
        ...,
        description="Backend-specific statistics",
        example={"total_users": 5, "enabled_users": 5},
    )

    class Config:
        schema_extra = {
            "example": {
                "name": "local",
                "type": "LocalAuthBackend",
                "available": True,
                "stats": {"total_users": 5, "enabled_users": 5},
            }
        }


# Type alias for the response (List of backends)
BackendsResponse = list[AuthBackendInfo]


class SessionDurationStats(BaseModel):
    """Session duration statistics"""

    avg_duration_seconds: float = Field(
        ..., description="Average session duration in seconds", example=3600.0
    )
    min_duration_seconds: float = Field(
        ..., description="Minimum session duration in seconds", example=60.0
    )
    max_duration_seconds: float = Field(
        ..., description="Maximum session duration in seconds", example=7200.0
    )
    completed_sessions: int = Field(
        ..., description="Number of completed sessions", example=10
    )

    class Config:
        schema_extra = {
            "example": {
                "avg_duration_seconds": 3600.0,
                "min_duration_seconds": 60.0,
                "max_duration_seconds": 7200.0,
                "completed_sessions": 10,
            }
        }


class ActiveSessionDetail(BaseModel):
    """Active session details"""

    session_id: int = Field(..., description="Session ID", example=12345)
    username: str = Field(..., description="Username", example="jsmith")
    acct_type: str | None = Field(None, description="Accounting type", example="start")
    start_time: int = Field(
        ..., description="Session start timestamp (Unix epoch)", example=1704374400
    )
    duration_seconds: int = Field(
        ..., description="Current session duration in seconds", example=3600
    )
    device_ip: str = Field(..., description="Device IP address", example="192.168.1.1")
    created_at: str = Field(
        ..., description="Record creation timestamp", example="2024-01-01T12:00:00"
    )

    class Config:
        schema_extra = {
            "example": {
                "session_id": 12345,
                "username": "jsmith",
                "acct_type": "start",
                "start_time": 1704374400,
                "duration_seconds": 3600,
                "device_ip": "192.168.1.1",
                "created_at": "2024-01-01T12:00:00",
            }
        }


class SessionsResponse(BaseModel):
    """Active sessions response"""

    active_sessions: int = Field(
        ..., description="Number of currently active sessions", example=0
    )
    total_sessions: int = Field(
        ..., description="Total sessions in the period", example=0
    )
    duration_stats: SessionDurationStats = Field(
        ..., description="Session duration statistics"
    )
    recent_active: list[ActiveSessionDetail] = Field(
        default=[], description="List of recent active sessions (up to 5)"
    )

    class Config:
        schema_extra = {
            "example": {
                "active_sessions": 2,
                "total_sessions": 100,
                "duration_stats": {
                    "avg_duration_seconds": 3600.0,
                    "min_duration_seconds": 60.0,
                    "max_duration_seconds": 7200.0,
                    "completed_sessions": 98,
                },
                "recent_active": [
                    {
                        "session_id": 12345,
                        "username": "jsmith",
                        "acct_type": "start",
                        "start_time": 1704374400,
                        "duration_seconds": 3600,
                        "device_ip": "192.168.1.1",
                        "created_at": "2024-01-01T12:00:00",
                    }
                ],
            }
        }


# ============================================================================
# Authentication Models
# ============================================================================


class LoginRequest(BaseModel):
    """Admin login request"""

    username: str = Field(..., description="Admin username", example="admin")
    password: str = Field(..., description="Admin password", example="admin123")

    class Config:
        json_schema_extra = {"example": {"username": "admin", "password": "admin123"}}


class LoginResponse(BaseModel):
    """Login response"""

    success: bool = Field(..., description="Login success", example=True)
    message: str = Field(
        ..., description="Response message", example="Login successful"
    )
    session_id: str | None = Field(
        None, description="Session ID", example="sess_abc123"
    )


class AuthBackendStatus(BaseModel):
    """Authentication backend status"""

    name: str = Field(..., description="Backend name", example="ldap")
    type: AuthBackendType = Field(..., description="Backend type", example="ldap")
    enabled: bool = Field(..., description="Backend enabled", example=True)
    healthy: bool = Field(..., description="Backend healthy", example=True)
    response_time_ms: float | None = Field(
        None, description="Response time", example=45.5
    )
    last_check: datetime = Field(
        ..., description="Last check", example="2024-01-01T12:00:00Z"
    )


# ============================================================================
# Accounting Models
# ============================================================================


class AccountingRecord(BaseModel):
    """Accounting record response"""

    id: int = Field(..., description="Record ID", example=1)
    username: str = Field(..., description="Username", example="jsmith")
    device_ip: str = Field(..., description="Device IP", example="192.168.1.1")
    service: str = Field(..., description="Service type", example="tacacs")
    action: str = Field(..., description="Action", example="login")
    status: str = Field(..., description="Status", example="success")
    timestamp: datetime = Field(
        ..., description="Timestamp", example="2024-01-01T12:00:00Z"
    )
    details: dict[str, Any] | None = Field(
        None, description="Additional details", example={"privilege_level": 15}
    )

    class Config:
        from_attributes = True


class AccountingRecordDetail(BaseModel):
    """Detailed accounting record"""

    id: int = Field(..., description="Record ID", example=1)
    session_id: int = Field(..., description="Session ID", example=12345)
    username: str = Field(..., description="Username", example="jsmith")
    acct_type: str = Field(
        ..., description="Accounting type (start, stop, update)", example="start"
    )
    start_time: int | None = Field(
        None, description="Session start timestamp (Unix epoch)", example=1704374400
    )
    stop_time: int | None = Field(
        None, description="Session stop timestamp (Unix epoch)", example=1704378000
    )
    bytes_in: int | None = Field(None, description="Bytes received", example=1024000)
    bytes_out: int | None = Field(None, description="Bytes sent", example=2048000)
    attributes: dict[str, Any] | None = Field(
        None,
        description="Additional attributes (device_ip, etc.)",
        example={"device_ip": "192.168.1.1", "port": "tty1"},
    )
    created_at: str = Field(
        ..., description="Record creation timestamp", example="2024-01-01T12:00:00"
    )

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": 1,
                "session_id": 12345,
                "username": "jsmith",
                "acct_type": "start",
                "start_time": 1704374400,
                "stop_time": None,
                "bytes_in": 1024000,
                "bytes_out": 2048000,
                "attributes": {"device_ip": "192.168.1.1", "port": "tty1"},
                "created_at": "2024-01-01T12:00:00",
            }
        }


class AccountingResponse(BaseModel):
    """Accounting records response"""

    records: list[AccountingRecordDetail] = Field(
        ..., description="List of accounting records"
    )
    count: int = Field(..., description="Number of records returned", example=0)
    period_hours: int = Field(..., description="Time period in hours", example=24)

    class Config:
        schema_extra = {
            "example": {
                "records": [
                    {
                        "id": 1,
                        "session_id": 12345,
                        "username": "jsmith",
                        "acct_type": "start",
                        "start_time": 1704374400,
                        "stop_time": None,
                        "bytes_in": 0,
                        "bytes_out": 0,
                        "attributes": {"device_ip": "192.168.1.1"},
                        "created_at": "2024-01-01T12:00:00",
                    }
                ],
                "count": 1,
                "period_hours": 24,
            }
        }


# ============================================================================
# Pagination Models
# ============================================================================


class PaginatedResponse(BaseModel):
    """Generic paginated response"""

    items: list[Any] = Field(..., description="List of items")
    total: int = Field(..., description="Total items", example=100)
    page: int = Field(..., description="Current page", example=1)
    page_size: int = Field(..., description="Items per page", example=50)
    total_pages: int = Field(..., description="Total pages", example=2)


# ============================================================================
# Error Models
# ============================================================================


class ErrorResponse(BaseModel):
    """Standard error response"""

    error: str = Field(..., description="Error message", example="Resource not found")
    details: str | None = Field(
        None, description="Error details", example="Device with ID 123 not found"
    )
    timestamp: datetime = Field(
        ..., description="Error timestamp", example="2024-01-01T12:00:00Z"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "error": "Resource not found",
                "details": "Device with ID 123 does not exist",
                "timestamp": "2024-01-01T12:00:00Z",
            }
        }


class ValidationError(BaseModel):
    """Validation error response"""

    error: str = Field(..., description="Error message", example="Validation failed")
    validation_errors: list[dict[str, Any]] = Field(
        ...,
        description="Validation errors",
        example=[{"field": "username", "message": "Too short"}],
    )
    timestamp: datetime = Field(
        ..., description="Error timestamp", example="2024-01-01T12:00:00Z"
    )


# ============================================================================
# User Group Models
# ============================================================================


class UserGroupBase(BaseModel):
    """Base user group model"""

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Group name",
        example="network-admins",
    )
    description: str | None = Field(
        None, description="Group description", example="Network administrators"
    )
    privilege_level: int = Field(
        default=1, ge=0, le=15, description="Default privilege", example=15
    )


class UserGroupCreate(UserGroupBase):
    """Model for creating user group"""

    allowed_device_groups: list[int] | None = Field(
        default=[], description="Allowed device groups", example=[1, 2]
    )

    class Config:
        json_schema_extra = {
            "example": {
                "name": "network-admins",
                "description": "Network administrators",
                "privilege_level": 15,
                "allowed_device_groups": [1, 2],
            }
        }


class UserGroupResponse(UserGroupBase):
    """Model for user group responses"""

    id: int = Field(..., description="Group ID", example=1)
    allowed_device_groups: list[int] = Field(
        default=[], description="Allowed groups", example=[1, 2]
    )
    member_count: int = Field(..., description="Number of members", example=10)
    created_at: datetime = Field(
        ..., description="Creation timestamp", example="2024-01-01T12:00:00Z"
    )

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "name": "network-admins",
                "description": "Network administrators",
                "privilege_level": 15,
                "allowed_device_groups": [1, 2],
                "member_count": 10,
                "created_at": "2024-01-01T12:00:00Z",
            }
        }


# ============================================================================
# Statistics Models
# ============================================================================


class ServerStatistics(BaseModel):
    """Detailed server statistics"""

    uptime_seconds: float = Field(..., description="Uptime", example=86400.5)
    cpu_percent: float = Field(..., description="CPU usage", example=25.5)
    memory_percent: float = Field(..., description="Memory usage", example=45.2)
    active_connections: int = Field(..., description="Active connections", example=10)
    total_requests: int = Field(..., description="Total requests", example=10000)
    requests_per_second: float = Field(..., description="Current RPS", example=15.5)
    authentication_stats: dict[str, Any] = Field(
        ..., description="Auth statistics", example={"total": 1000, "success": 985}
    )


# ============================================================================
# Export list
# ============================================================================

__all__ = [
    "UserStatus",
    "DeviceStatus",
    "AuthBackendType",
    "UserBase",
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    "DeviceBase",
    "DeviceCreate",
    "DeviceUpdate",
    "DeviceResponse",
    "DeviceGroupBase",
    "DeviceGroupCreate",
    "DeviceGroupUpdate",
    "DeviceGroupResponse",
    "ServerStatus",
    "HealthCheck",
    "LoginRequest",
    "LoginResponse",
    "AuthBackendStatus",
    "AccountingRecord",
    "PaginatedResponse",
    "ErrorResponse",
    "ValidationError",
    "UserGroupBase",
    "UserGroupCreate",
    "UserGroupResponse",
    "ServerStatistics",
    "AuthBackendHealth",
    "DatabaseHealth",
    "MemoryUsage",
    "DetailedHealthCheck",
    "ConnectionStats",
    "AuthenticationStats",
    "AuthorizationStats",
    "AccountingStats",
    "MemoryStats",
    "RADIUSAuthStats",
    "RADIUSAcctStats",
    "RADIUSStats",
    "DetailedServerStatus",
    "AuthBackendHealth",
    "DatabaseHealth",
    "MemoryUsage",
    "DetailedHealthCheck",
    "BackendStats",
    "DatabaseStats",
    "SessionStats",
    "DetailedStats",
    "LocalBackendStats",
    "LDAPBackendStats",
    "OktaBackendStats",
    "AuthBackendInfo",
    "BackendsResponse",
    "SessionDurationStats",
    "ActiveSessionDetail",
    "SessionsResponse",
    "AccountingRecordDetail",
    "AccountingResponse",
]
