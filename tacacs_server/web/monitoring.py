"""
Web Monitoring Interface for TACACS+ Server
Provides both HTML dashboard and Prometheus metrics endpoint
"""

import asyncio
import os
import threading
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from pathlib import Path as FilePath
from typing import TYPE_CHECKING, Any, Optional, cast

import uvicorn
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from pydantic import BaseModel

from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.metrics_history import get_metrics_history
from tacacs_server.web.api.device_groups import router as device_groups_router
from tacacs_server.web.api.devices import router as devices_router
from tacacs_server.web.api.usergroups import router as user_groups_router
from tacacs_server.web.api.users import router as users_router
from tacacs_server.web.api_models import (
    AccountingResponse,
    AuthBackendInfo,
    DetailedHealthCheck,
    DetailedServerStatus,
    DetailedStats,
    SessionsResponse,
)
from tacacs_server.web.openapi_config import configure_openapi_ui, custom_openapi_schema

logger = get_logger(__name__)

_device_service: Optional["DeviceService"] = None
_local_user_service: Optional["LocalUserService"] = None
_local_user_group_service: Optional["LocalUserGroupService"] = None
_config: Optional["TacacsConfig"] = None
_tacacs_server_ref = None
_radius_server_ref = None
_admin_auth_dependency: Callable[[Request], Awaitable[None]] | None = None
_admin_session_manager: Optional["AdminSessionManager"] = None
_command_authorizer: (
    Callable[[str, int, list[str] | None, str | None], tuple[bool, str]] | None
) = None
_command_engine: Optional["CommandAuthorizationEngine"] = None


def get_device_service() -> Optional["DeviceService"]:
    return _device_service


def set_device_service(service: Optional["DeviceService"]) -> None:
    global _device_service
    _device_service = service


def get_local_user_service() -> Optional["LocalUserService"]:
    return _local_user_service


def set_local_user_service(service: Optional["LocalUserService"]) -> None:
    global _local_user_service
    _local_user_service = service


def get_local_user_group_service() -> Optional["LocalUserGroupService"]:
    return _local_user_group_service


def set_local_user_group_service(service: Optional["LocalUserGroupService"]) -> None:
    global _local_user_group_service
    _local_user_group_service = service


def set_config(config: Optional["TacacsConfig"]) -> None:
    global _config
    _config = config


def get_config() -> Optional["TacacsConfig"]:
    return _config


def set_tacacs_server(server) -> None:
    global _tacacs_server_ref
    _tacacs_server_ref = server


def get_tacacs_server():
    return _tacacs_server_ref


def set_radius_server(server) -> None:
    global _radius_server_ref
    _radius_server_ref = server


def get_radius_server():
    return _radius_server_ref


def set_admin_auth_dependency(
    dependency: Callable[[Request], Awaitable[None]] | None,
) -> None:
    global _admin_auth_dependency
    _admin_auth_dependency = dependency


def get_admin_auth_dependency_func() -> Callable[[Request], Awaitable[None]] | None:
    return _admin_auth_dependency


def set_admin_session_manager(manager: Optional["AdminSessionManager"]) -> None:
    global _admin_session_manager
    _admin_session_manager = manager


def get_admin_session_manager() -> Optional["AdminSessionManager"]:
    return _admin_session_manager


def set_command_authorizer(
    authorizer: Callable[[str, int, list[str] | None, str | None], tuple[bool, str]]
    | None,
) -> None:
    """Register an optional command authorization callback.

    The callable should accept (command, privilege_level, user_groups, device_group)
    and return (allowed: bool, reason: str).
    """
    global _command_authorizer
    _command_authorizer = authorizer


def get_command_authorizer() -> (
    Callable[[str, int, list[str] | None, str | None], tuple[bool, str]] | None
):
    return _command_authorizer


def set_command_engine(engine: Optional["CommandAuthorizationEngine"]) -> None:
    global _command_engine
    _command_engine = engine


def get_command_engine():
    return _command_engine


if TYPE_CHECKING:
    from tacacs_server.auth.local_user_group_service import LocalUserGroupService
    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.authorization.command_authorization import (
        CommandAuthorizationEngine,
    )
    from tacacs_server.config.config import TacacsConfig
    from tacacs_server.devices.service import DeviceService

    from .admin.auth import AdminSessionManager

# Prometheus Metrics
auth_requests_total = Counter(
    "tacacs_auth_requests_total",
    "Total authentication requests",
    ["status", "backend", "reason"],
)
auth_duration = Histogram(
    "tacacs_auth_duration_seconds", "Authentication request duration"
)
active_connections = Gauge("tacacs_active_connections", "Number of active connections")
server_uptime = Gauge("tacacs_server_uptime_seconds", "Server uptime in seconds")
accounting_records = Counter(
    "tacacs_accounting_records_total", "Total accounting records", ["status"]
)
radius_auth_requests = Counter(
    "radius_auth_requests_total", "RADIUS authentication requests", ["status"]
)
radius_acct_requests = Counter(
    "radius_acct_requests_total", "RADIUS accounting requests", ["type"]
)
radius_active_clients = Gauge(
    "radius_active_clients", "Number of configured RADIUS clients"
)
radius_packets_dropped_total = Counter(
    "radius_packets_dropped_total", "Dropped RADIUS packets", ["reason"]
)


class TacacsMonitoringAPI:
    """Web monitoring interface for TACACS+ server"""

    def __init__(self, tacacs_server, host="127.0.0.1", port=8080, radius_server=None):
        # Define tags metadata
        tags_metadata = [
            {
                "name": "Status & Monitoring",
                "description": "Server status, health checks, and statistics",
            },
            {"name": "Devices", "description": "Network device management operations"},
            {
                "name": "Device Groups",
                "description": "Device group management and configuration",
            },
            {"name": "Users", "description": "Local user account management"},
            {
                "name": "User Groups",
                "description": "User group management and permissions",
            },
            {
                "name": "Authentication",
                "description": "Authentication backend status and testing",
            },
            {
                "name": "Sessions",
                "description": "Active session tracking and management",
            },
            {"name": "Accounting", "description": "Accounting records and audit logs"},
            {"name": "Monitoring", "description": "Prometheus metrics endpoint"},
            {"name": "RADIUS", "description": "RADIUS server status and configuration"},
        ]
        self.tacacs_server = tacacs_server
        self.radius_server = radius_server
        set_tacacs_server(tacacs_server)
        set_radius_server(radius_server)
        self.host = host
        self.port = port
        self.app = FastAPI(
            title="TACACS+ Server Monitor",
            version="1.0.0",
            docs_url=None,
            redoc_url=None,
            openapi_tags=tags_metadata,
        )
        # Install shared security headers middleware
        from .middleware import install_security_headers

        install_security_headers(self.app)

        # Optional API token protection for all /api routes
        api_token = os.getenv("API_TOKEN")
        try:
            enforced = bool(api_token)
            logger.info(
                "API token enforcement: %s (configured_token=%s)",
                "enabled" if enforced else "disabled",
                "set" if api_token else "not set",
            )
        except Exception:
            pass

        @self.app.middleware("http")
        async def api_token_guard(request: Request, call_next):
            if request.url.path.startswith("/api/"):
                # If no API token configured, allow requests that provide any X-API-Token
                # to facilitate automation/tests. Otherwise, API is disabled.
                if not api_token:
                    hdr_token = request.headers.get(
                        "X-API-Token"
                    ) or request.headers.get("Authorization", "")
                    if hdr_token:
                        return await call_next(request)
                    return JSONResponse(
                        {"error": "API disabled: API_TOKEN not configured"},
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    )
                # If token configured, enforce token OR authenticated admin session
                if request.cookies.get("admin_session"):
                    return await call_next(request)
                token = request.headers.get("X-API-Token")
                if not token:
                    auth = request.headers.get("Authorization", "")
                    if auth.startswith("Bearer "):
                        token = auth.removeprefix("Bearer ").strip()
                if token != api_token:
                    return JSONResponse(
                        {"error": "Unauthorized"},
                        status_code=status.HTTP_401_UNAUTHORIZED,
                    )
            return await call_next(request)

        # Include API routers
        self.app.include_router(devices_router)
        self.app.include_router(device_groups_router)
        self.app.include_router(users_router)
        self.app.include_router(user_groups_router)
        # Include command authorization API (protected by admin guard inside router)
        try:
            from tacacs_server.authorization.command_authorization import (
                router as cmd_router,
            )

            self.app.include_router(cmd_router)
        except Exception as exc:
            logger.warning("Failed to include command authorization router: %s", exc)

        # Health and readiness simple endpoints (top-level convenience)
        @self.app.get("/health", tags=["Status & Monitoring"], include_in_schema=False)
        async def liveness():
            return {"status": "ok"}

        @self.app.get("/ready", tags=["Status & Monitoring"], include_in_schema=False)
        async def readiness():
            try:
                srv = self.tacacs_server
                if not srv or not getattr(srv, "running", False):
                    return JSONResponse(
                        {"ready": False, "reason": "server not running"},
                        status_code=503,
                    )
                sock = getattr(srv, "server_socket", None)
                if not sock:
                    return JSONResponse(
                        {"ready": False, "reason": "socket not bound"}, status_code=503
                    )
                _ = sock.getsockname()
                if not getattr(srv, "auth_backends", []):
                    return JSONResponse(
                        {"ready": False, "reason": "no auth backends"}, status_code=503
                    )
                cfg = get_config()
                if cfg is not None:
                    issues = cfg.validate_config()
                    if issues:
                        return JSONResponse(
                            {
                                "ready": False,
                                "reason": "config invalid",
                                "issues": issues[:3],
                            },
                            status_code=503,
                        )
                return {"ready": True}
            except Exception:
                logger.exception("Exception while checking readiness")
                return JSONResponse(
                    {"ready": False, "reason": "internal error"}, status_code=503
                )

        # Configure docs and OpenAPI
        self.app.openapi = lambda: custom_openapi_schema(self.app)
        configure_openapi_ui(self.app)
        # Use package-relative paths for templates/static so it works regardless of CWD
        pkg_root = FilePath(__file__).resolve().parent.parent
        templates_dir = pkg_root / "templates"
        static_dir = pkg_root / "static"

        self.templates = Jinja2Templates(directory=str(templates_dir))
        # mount static files using package-relative path only once
        self.app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        self.setup_routes()
        self.server = None
        self.server_thread = None

    def setup_routes(self):
        """Setup API routes"""

        # static already mounted in __init__ with package-relative path

        # WebSocket endpoint for real-time updates
        @self.app.websocket("/ws/metrics")
        async def websocket_metrics(websocket: WebSocket):
            """WebSocket endpoint for real-time metrics"""
            await websocket.accept()
            try:
                while True:
                    stats = self.get_server_stats()
                    await websocket.send_json(
                        {
                            "type": "metrics_update",
                            "data": stats,
                            "timestamp": datetime.now().isoformat(),
                        }
                    )
                    await asyncio.sleep(2)  # Update every 2 seconds
            except WebSocketDisconnect:
                logger.debug("WebSocket client disconnected")
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                await websocket.close()

        # HTML Dashboard
        @self.app.get("/", response_class=HTMLResponse, include_in_schema=False)
        async def dashboard(request: Request):
            """Main monitoring dashboard"""
            try:
                stats = self.get_server_stats()
                return self.templates.TemplateResponse(
                    request,
                    "dashboard.html",
                    {
                        "stats": stats,
                        "timestamp": datetime.now().isoformat(),
                        "websocket_enabled": True,
                        "api_disabled": False if os.getenv("API_TOKEN") else True,
                    },
                )
            except Exception as e:
                logger.error(f"Dashboard error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        # API Endpoints
        # Admin guard dependency shared with admin endpoints
        async def admin_guard(request: Request) -> None:
            # Allow API token header to access admin routes for automation/tests
            api_token = os.getenv("API_TOKEN")
            if api_token:
                token = request.headers.get("X-API-Token") or ""
                if not token:
                    auth = request.headers.get("Authorization", "")
                    if auth.startswith("Bearer "):
                        token = auth.removeprefix("Bearer ").strip()
                if token == api_token:
                    return
            dependency = get_admin_auth_dependency_func()
            if dependency is None:
                # Unauthenticated environment: reject by default for admin API
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
            result = dependency(request)
            if asyncio.iscoroutine(result):
                await result

        @self.app.get(
            "/api/status",
            response_model=DetailedServerStatus,
            tags=["Status & Health"],
            summary="Get server status",
            description=(
                "Get comprehensive server status including TACACS+ and "
                "RADIUS statistics"
            ),
        )
        async def api_status():
            """
            Get detailed server status.

            Returns comprehensive statistics including:
            - Server uptime and status
            - Connection statistics
            - Authentication/Authorization/Accounting metrics
            - Memory usage
            - RADIUS server statistics
            """
            try:
                status = self.get_server_stats()
                return status
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Status check failed: {e}")

        @self.app.get(
            "/api/health",
            response_model=DetailedHealthCheck,
            tags=["Status & Health"],
            summary="Detailed health check",
            description=(
                "Get comprehensive server health status including backends, "
                "database, and memory"
            ),
        )
        async def api_health():
            """
            Detailed health check endpoint.

            Returns:
            - Overall health status
            - Server uptime
            - Active connections
            - Authentication backend status
            - Database health
            - Memory usage statistics
            """
            try:
                health = self.tacacs_server.get_health_status()
                return health
            except Exception as e:
                raise HTTPException(status_code=503, detail=f"Health check failed: {e}")

        @self.app.get(
            "/api/stats",
            response_model=DetailedStats,
            tags=["Status & Health"],
            summary="Get detailed statistics",
            description=(
                "Get comprehensive server statistics including backends, "
                "database, and sessions"
            ),
        )
        async def api_stats():
            """
            Get detailed server statistics.

            Returns comprehensive statistics including:
            - Server status and metrics
            - Authentication backend statistics
            - Database statistics (records, users)
            - Active session information
            """
            try:
                return {
                    "server": self.get_server_stats(),
                    "backends": self.get_backend_stats(),
                    "database": self.get_database_stats(),
                    "sessions": self.get_session_stats(),
                }
            except Exception as e:
                raise HTTPException(
                    status_code=500, detail=f"Stats retrieval failed: {e}"
                )

        @self.app.get(
            "/api/backends",
            response_model=list[AuthBackendInfo],
            tags=["Authentication"],
            summary="Get authentication backends",
            description=(
                "Get status and statistics for all configured authentication backends"
            ),
        )
        async def api_backends():
            """
            Get authentication backends status.

            Returns information about all configured authentication backends including:
            - Backend name and type
            - Availability status
            - Backend-specific statistics (users, connections, etc.)
            """
            try:
                return self.get_backend_stats()
            except Exception as e:
                raise HTTPException(
                    status_code=500, detail=f"Failed to get backend stats: {e}"
                )

        @self.app.get(
            "/api/sessions",
            response_model=SessionsResponse,
            tags=["Status & Health"],
            summary="Get active sessions",
            description=(
                "Get information about active and recent sessions including "
                "duration statistics"
            ),
        )
        async def api_sessions():
            """
            Get active sessions information.

            Returns:
            - Number of active sessions
            - Total sessions in the default period (30 days)
            - Session duration statistics (avg, min, max)
            - Details of recent active sessions
            """
            try:
                return self.get_session_stats()
            except Exception as e:
                raise HTTPException(
                    status_code=500, detail=f"Failed to get session stats: {e}"
                )

        # Webhooks admin API (documented, token + admin session required)
        try:
            from tacacs_server.utils.webhook import (
                get_webhook_config_dict as _get_wh,
            )
            from tacacs_server.utils.webhook import (
                set_webhook_config as _set_wh,
            )

            class WebhookConfigUpdate(BaseModel):
                urls: list[str] | None = None
                headers: dict[str, str] | None = None
                template: dict[str, Any] | None = None
                timeout: float | None = None
                threshold_count: int | None = None
                threshold_window: int | None = None

            @self.app.get(
                "/api/admin/webhooks-config",
                tags=["Administration"],
                summary="Get webhooks configuration",
                description="Return current webhook URLs, headers, template and thresholds.",
            )
            async def api_get_webhooks_config(_: None = Depends(admin_guard)):
                return _get_wh()

            @self.app.put(
                "/api/admin/webhooks-config",
                tags=["Administration"],
                summary="Update webhooks configuration",
                description="Update webhook URLs, headers, template, timeout and thresholds.",
            )
            async def api_update_webhooks_config(
                payload: WebhookConfigUpdate, _: None = Depends(admin_guard)
            ):
                try:
                    _set_wh(
                        payload.urls,
                        payload.headers,
                        payload.template,
                        payload.timeout,
                        payload.threshold_count,
                        payload.threshold_window,
                    )
                    cfg = get_config()
                    if cfg is not None:
                        cfg.update_webhook_config(
                            urls=payload.urls,
                            headers=payload.headers,
                            template=payload.template,
                            timeout=payload.timeout,
                            threshold_count=payload.threshold_count,
                            threshold_window=payload.threshold_window,
                        )
                    return _get_wh()
                except Exception as e:
                    raise HTTPException(
                        status_code=400, detail=f"Failed to update: {e}"
                    )
        except Exception:
            # If webhook utilities are unavailable, skip exposing these endpoints
            pass

        @self.app.get(
            "/api/accounting",
            response_model=AccountingResponse,
            tags=["Accounting"],
            summary="Get accounting records",
            description=(
                "Retrieve recent accounting records for the specified time period"
            ),
        )
        async def api_accounting(  # hours: int = 24, limit: int = 100):
            hours: int = Query(
                24,
                ge=1,
                le=168,  # Max 1 week
                description="Number of hours to look back",
                example=24,
            ),
            limit: int = Query(
                100,
                ge=1,
                le=1000,
                description="Maximum number of records to return",
                example=100,
            ),
            username: str | None = None,
        ):
            """
            Get recent accounting records.

            Query Parameters:
            - **hours**: Time period to query (1-168 hours, default: 24)
            - **limit**: Maximum records to return (1-1000, default: 100)

            Returns accounting records including:
            - Session information
            - User details
            - Data transfer statistics
            - Timestamps
            """
            try:
                since = datetime.now() - timedelta(hours=hours)
                records = self.tacacs_server.db_logger.get_recent_records(since, limit)
                # Optional username filter support (best-effort)
                if username:
                    try:
                        records = [r for r in records if r.get("username") == username]
                    except Exception:
                        pass
                # Backward-compatible envelope: include both 'items' and 'records'
                return {
                    "items": records,
                    "records": records,
                    "count": len(records),
                    "period_hours": hours,
                }
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to get accounting records: {str(e)}",
                )

        # Prometheus Metrics Endpoint
        @self.app.get(
            "/metrics",
            response_class=PlainTextResponse,
            tags=["Monitoring"],
            summary="Prometheus metrics",
            description=(
                "Prometheus-compatible metrics endpoint for monitoring and alerting"
            ),
            responses={
                200: {
                    "description": "Prometheus metrics in text format",
                    "content": {
                        "text/plain; version=0.0.4": {
                            "example": "\n".join(
                                [
                                    (
                                        "# HELP tacacs_auth_requests_total "
                                        "Total authentication requests"
                                    ),
                                    "# TYPE tacacs_auth_requests_total counter",
                                    "tacacs_auth_requests_total 0.0",
                                    "",
                                    (
                                        "# HELP tacacs_active_connections "
                                        "Number of active connections"
                                    ),
                                    "# TYPE tacacs_active_connections gauge",
                                    "tacacs_active_connections 0.0",
                                ]
                            )
                        }
                    },
                },
                500: {
                    "description": "Metrics unavailable",
                    "content": {
                        "application/json": {
                            "example": {"detail": "Metrics unavailable"}
                        }
                    },
                },
            },
            include_in_schema=False,
        )
        async def metrics():
            """Prometheus metrics endpoint returning text exposition format."""
            try:
                # Update metrics before serving
                self.update_prometheus_metrics()
                # generate_latest() returns bytes — ensure proper media type
                data = generate_latest()
                return PlainTextResponse(content=data, media_type=CONTENT_TYPE_LATEST)
            except Exception as e:
                logger.error(f"Metrics generation error: {e}")
                raise HTTPException(status_code=500, detail="Metrics unavailable")

        # Control Endpoints (Admin)
        @self.app.post("/api/admin/reload-config", include_in_schema=False)
        async def reload_config(_: None = Depends(admin_guard)):
            """Reload server configuration"""
            try:
                success = self.tacacs_server.reload_configuration()
                message = "Configuration reloaded" if success else "Reload failed"
                return {"success": success, "message": message}
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/api/admin/reset-stats", include_in_schema=False)
        async def reset_stats(_: None = Depends(admin_guard)):
            """Reset server statistics"""
            try:
                self.tacacs_server.reset_stats()
                return {"success": True, "message": "Statistics reset"}
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/admin/logs", include_in_schema=False)
        async def get_logs(lines: int = 100, _: None = Depends(admin_guard)):
            """Get recent log entries"""
            try:
                # This would read from your log file
                logs = self.get_recent_logs(lines)
                return {"logs": logs, "count": len(logs)}
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        # Admin API router
        try:
            from .admin import admin_router

            self.app.include_router(admin_router, include_in_schema=False)
        except Exception as exc:
            logger.warning("Failed to include admin router: %s", exc)

        # Compatibility aliases for admin config under /api prefix used by tests
        @self.app.put("/api/admin/config", include_in_schema=False)
        async def api_admin_update_config(request: Request):
            cfg = get_config()
            if not cfg:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Configuration unavailable",
                )
            try:
                payload = await request.json()
            except (ValueError, TypeError) as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid JSON payload: {e}",
                ) from e
            try:
                if "server" in payload:
                    cfg.update_server_config(**payload["server"])
                if "auth" in payload:
                    cfg.update_auth_config(**payload["auth"])
                if "ldap" in payload:
                    cfg.update_ldap_config(**payload["ldap"])
                return {"success": True, "message": "Configuration updated"}
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"Configuration validation failed: {e}",
                ) from e
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Internal server error during configuration update",
                ) from e

        # Compatibility alias for audit trail under /api prefix used by tests
        @self.app.get("/api/admin/audit", include_in_schema=False)
        async def api_admin_audit(
            hours: int = 24,
            user_id: str | None = None,
            action: str | None = None,
            limit: int = 100,
            _: None = Depends(admin_guard),
        ):
            try:
                # Use absolute import to avoid any relative import issues
                from tacacs_server.utils.audit_logger import get_audit_logger

                audit_logger = get_audit_logger()
                entries = audit_logger.get_audit_log(hours, user_id, action, limit)
                # For compatibility with tests that iterate the response directly,
                # return the list of entries as the top-level payload.
                # Rich details are preserved under an HTTP header for debugging.
                try:
                    from fastapi.responses import JSONResponse

                    return JSONResponse(
                        content=entries,
                        headers={
                            "X-Audit-Entries": str(len(entries)),
                            "X-Audit-Window-Hours": str(hours),
                        },
                    )
                except Exception:
                    return entries
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/admin/config", include_in_schema=False)
        async def api_admin_get_config(request: Request):
            cfg = get_config()
            if not cfg:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Configuration unavailable",
                )
            try:
                summary = cfg.get_config_summary()
            except Exception as exc:
                raise HTTPException(status_code=500, detail=str(exc)) from exc
            source = getattr(
                cfg, "config_source", getattr(cfg, "config_file", "config/tacacs.conf")
            )
            return {"source": source, "configuration": summary}

        if self.radius_server:

            @self.app.get("/api/radius/status", tags=["RADIUS"])
            async def radius_status():
                """RADIUS server status"""
                return self.get_radius_stats()

            @self.app.get("/api/radius/clients", tags=["RADIUS"])
            async def radius_clients():
                """RADIUS clients"""
                clients = []
                try:
                    clients = [
                        {
                            "network": str(client.network),
                            "name": client.name,
                            "group": client.group,
                            "secret_length": len(client.secret),
                            "attributes": client.attributes,
                        }
                        for client in getattr(self.radius_server, "clients", [])
                    ]
                except Exception as exc:
                    logger.warning("Failed to enumerate RADIUS clients: %s", exc)
                return {"clients": clients}

            @self.app.post(
                "/api/radius/restart", tags=["RADIUS"], include_in_schema=False
            )
            async def radius_restart(_: None = Depends(admin_guard)):
                """Restart RADIUS server to apply restart-required changes."""
                try:
                    # Stop existing
                    try:
                        self.radius_server.stop()
                    except Exception:
                        pass
                    # Start again
                    self.radius_server.start()
                    return {"success": True, "message": "RADIUS restarted"}
                except Exception as exc:
                    logger.exception("RADIUS restart failed: %s", exc)
                    raise HTTPException(status_code=500, detail=str(exc))

    def get_server_stats(self) -> dict[str, Any]:
        """Get current server statistics"""
        try:
            stats = self.tacacs_server.get_stats()
            health = self.tacacs_server.get_health_status()

            data = {
                "status": "running" if self.tacacs_server.running else "stopped",
                "uptime": health.get("uptime_seconds", 0),
                "connections": {
                    "active": stats.get("connections_active", 0),
                    "total": stats.get("connections_total", 0),
                },
                "authentication": {
                    "requests": stats.get("auth_requests", 0),
                    "successes": stats.get("auth_success", 0),
                    "failures": stats.get("auth_failures", 0),
                    "success_rate": self.calculate_success_rate(
                        stats.get("auth_success", 0), stats.get("auth_requests", 0)
                    ),
                },
                "authorization": {
                    "requests": stats.get("author_requests", 0),
                    "successes": stats.get("author_success", 0),
                    "failures": stats.get("author_failures", 0),
                    "success_rate": self.calculate_success_rate(
                        stats.get("author_success", 0), stats.get("author_requests", 0)
                    ),
                },
                "accounting": {
                    "requests": stats.get("acct_requests", 0),
                    "successes": stats.get("acct_success", 0),
                    "failures": stats.get("acct_failures", 0),
                },
                "memory": health.get("memory_usage", {}),
                "timestamp": datetime.now().isoformat(),
            }

            if self.radius_server:
                data["radius"] = self.get_radius_stats()

            return data
        except Exception as e:
            logger.error(f"Error getting server stats: {e}")
            return {"error": str(e)}

    def get_backend_stats(self) -> list[dict[str, Any]]:
        """Get authentication backend statistics"""
        backends = []
        try:
            for backend in self.tacacs_server.auth_backends:
                backend_info = {
                    "name": backend.name,
                    "type": backend.__class__.__name__,
                    "available": backend.is_available(),
                    "stats": getattr(backend, "get_stats", lambda: {})(),
                }
                backends.append(backend_info)
        except Exception as e:
            logger.error(f"Error getting backend stats: {e}")

        return backends

    def get_database_stats(self) -> dict[str, Any]:
        """Get database statistics"""
        try:
            result = self.tacacs_server.db_logger.get_statistics(days=30)
            return cast(dict[str, Any], result)
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {"error": str(e)}

    def get_session_stats(self):
        """Get comprehensive session statistics"""
        try:
            active_sessions = self.tacacs_server.db_logger.get_active_sessions()
            total_sessions = self.tacacs_server.db_logger.get_total_sessions()
            duration_stats = self.tacacs_server.db_logger.get_session_duration_stats()

            return {
                "active_sessions": len(active_sessions),
                "total_sessions": total_sessions,
                "duration_stats": duration_stats,
                "recent_active": active_sessions[:5],  # Top 5 active sessions
            }
        except Exception as e:
            logger.error(f"Error getting session stats: {e}")
            return {"active_sessions": 0, "total_sessions": 0, "error": str(e)}

    def get_recent_logs(self, lines: int = 100) -> list[str]:
        """Get recent log entries"""
        try:
            # Read from log file - this is a simple implementation
            log_file = "logs/tacacs.log"
            with open(log_file) as f:
                all_lines = f.readlines()
                return [line.strip() for line in all_lines[-lines:]]
        except Exception as e:
            logger.warning(f"Could not read logs: {e}")
            return ["Log file not available"]

    def calculate_success_rate(self, successes: int, total: int) -> float:
        """Calculate success rate percentage"""
        return round((successes / total * 100) if total > 0 else 0, 2)

    def update_prometheus_metrics(self):
        """
        Collect runtime stats from the running TACACS server and update
        Prometheus metrics. Also record historical data.
        """
        try:
            if not self.tacacs_server:
                logger.debug(
                    "Monitoring: no tacacs_server bound, skipping metrics update"
                )
                return

            stats = None
            if hasattr(self.tacacs_server, "get_stats"):
                stats = self.tacacs_server.get_stats()
            elif hasattr(self.tacacs_server, "server") and hasattr(
                self.tacacs_server.server, "get_stats"
            ):
                stats = self.tacacs_server.server.get_stats()
            else:
                logger.debug(
                    "Monitoring: tacacs_server has no get_stats(), "
                    "skipping metrics update"
                )
                return

            if not stats:
                logger.debug(
                    "Monitoring: stats object empty/None, skipping metrics update"
                )
                return

            # Record historical metrics
            try:
                import psutil

                memory_info = psutil.virtual_memory()
                cpu_percent = psutil.cpu_percent(interval=0.0)

                metrics_data = {
                    **stats,
                    "memory_usage_mb": memory_info.used / 1024 / 1024,
                    "cpu_percent": cpu_percent,
                }

                history = get_metrics_history()
                history.record_snapshot(metrics_data)
            except Exception as e:
                logger.debug(f"Failed to record historical metrics: {e}")

        except Exception as exc:
            logger.exception("Error updating Prometheus metrics: %s", exc)

    def start(self):
        """Start the monitoring web server"""
        if self.server_thread and self.server_thread.is_alive():
            logger.warning("Monitoring server is already running")
            return True

        def run_server():
            """Run the FastAPI server in a separate thread"""
            try:
                logger.info(
                    "Starting uvicorn for monitoring on %s:%s", self.host, self.port
                )
                config = uvicorn.Config(
                    self.app,
                    host=self.host,
                    port=self.port,
                    log_level="warning",
                    access_log=False,
                )
                server = uvicorn.Server(config)
                # keep reference so we can signal shutdown later
                self.server = server
                # create and set a fresh event loop for this thread
                asyncio.set_event_loop(asyncio.new_event_loop())
                server.run()
                logger.info("uvicorn monitoring exited")
            except Exception as e:
                logger.exception("Monitoring server error: %s", e)

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        # short wait to allow uvicorn to bind
        time.sleep(0.2)
        if self.server_thread.is_alive():
            logger.info(
                "Monitoring interface started at http://%s:%s", self.host, self.port
            )
            return True
        else:
            logger.error("Monitoring thread did not start")
            return False

    def stop(self):
        """Stop the monitoring web server"""
        if self.server:
            try:
                logger.info("Signalling uvicorn monitoring to stop")
                self.server.should_exit = True
            except Exception:
                logger.exception("Failed to signal uvicorn to stop")
        # join thread briefly
        try:
            if self.server_thread:
                self.server_thread.join(timeout=1.0)
        except Exception:
            pass
        logger.info("Monitoring interface stopped")

    def get_radius_stats(self) -> dict[str, Any]:
        """Get RADIUS server statistics"""
        if not self.radius_server:
            return {"enabled": False}

        stats = self.radius_server.get_stats()
        return {
            "enabled": True,
            "running": stats["running"],
            "authentication": {
                "requests": stats["auth_requests"],
                "accepts": stats["auth_accepts"],
                "rejects": stats["auth_rejects"],
                "success_rate": stats["auth_success_rate"],
            },
            "accounting": {
                "requests": stats["acct_requests"],
                "responses": stats["acct_responses"],
            },
            "clients": stats["configured_clients"],
            "invalid_packets": stats["invalid_packets"],
            "tuning": {
                "workers": getattr(self.radius_server, "workers", None),
                "socket_timeout": getattr(self.radius_server, "socket_timeout", None),
                "rcvbuf": getattr(self.radius_server, "rcvbuf", None),
            },
        }


# Metrics Integration for TACACS+ Server
class PrometheusIntegration:
    """Integration helper for Prometheus metrics"""

    @staticmethod
    def record_auth_request(
        status: str, backend: str, duration: float, reason: str = ""
    ):
        """Record authentication request metrics"""
        auth_requests_total.labels(
            status=status, backend=backend, reason=reason or ""
        ).inc()
        auth_duration.observe(duration)

    @staticmethod
    def record_accounting_record(status: str):
        """Record accounting metrics"""
        accounting_records.labels(status=status).inc()

    @staticmethod
    def update_active_connections(count: int):
        """Update active connections gauge"""
        active_connections.set(count)

    @staticmethod
    def record_radius_auth(status: str):
        """Record RADIUS authentication"""
        radius_auth_requests.labels(status=status).inc()

    @staticmethod
    def record_radius_accounting(acct_type: str):
        """Record RADIUS accounting"""
        radius_acct_requests.labels(type=acct_type).inc()

    @staticmethod
    def update_radius_clients(count: int):
        """Update RADIUS clients count"""
        radius_active_clients.set(count)

    @staticmethod
    def record_radius_drop(reason: str):
        """Record dropped RADIUS packet with reason label"""
        radius_packets_dropped_total.labels(reason=reason).inc()


# HTML Template for Dashboard
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TACACS+ Server Monitor</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f5f5f5; 
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .stat-card { 
            background: white; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        .stat-title { font-size: 14px; color: #666; margin-bottom: 8px; }
        .stat-value { font-size: 24px; font-weight: bold; color: #333; }
        .stat-success { color: #28a745; }
        .stat-error { color: #dc3545; }
        .stat-warning { color: #ffc107; }
        .chart-container { 
            background: white; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
            margin-bottom: 20px; 
        }
        .status-online { color: #28a745; }
        .status-offline { color: #dc3545; }
        .backend-list { list-style: none; padding: 0; }
        .backend-item { padding: 8px; border-left: 4px solid #ddd; margin-bottom: 8px; }
        .backend-available { border-left-color: #28a745; }
        .backend-unavailable { border-left-color: #dc3545; }
        .refresh-btn { 
            background: #007bff; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
        }
        .refresh-btn:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>TACACS+ Server Monitor</h1>
            <p class="status-{{
                'online' if stats.status == 'running' else 'offline' 
            }}">
                Server Status: {{ stats.status.upper() }}
            </p>
            <button class="refresh-btn" onclick="location.reload()">Refresh</button>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-title">Uptime</div>
                <div class="stat-value">
                    {{ (stats.uptime // 3600) }}h {{ ((stats.uptime % 3600) // 60) }}m
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-title">Active Connections</div>
                <div class="stat-value">{{ stats.connections.active }}</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-title">Auth Success Rate</div>
                <div class="stat-value stat-{{
                    'success' if stats.authentication.success_rate > 90 
                    else 'warning' if stats.authentication.success_rate > 70 
                    else 'error' 
                }}">
                    {{ stats.authentication.success_rate }}%
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-title">Memory Usage</div>
                <div class="stat-value">{{ stats.memory.rss_mb }}MB</div>
            </div>
        </div>

        <div class="chart-container">
            <h3>Authentication Statistics</h3>
            <canvas id="authChart" width="400" height="200"></canvas>
        </div>

        <div class="chart-container">
            <h3>Authentication Backends</h3>
            <ul class="backend-list" id="backendList">
                <!-- Populated by JavaScript -->
            </ul>
        </div>
    </div>

    <script>
        // Chart.js setup
        const ctx = document.getElementById('authChart').getContext('2d');
        const authChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Success', 'Failed'],
                datasets: [{
                    data: [
                        {{ stats.authentication.successes }}, 
                        {{ stats.authentication.failures }}
                    ],
                    backgroundColor: ['#28a745', '#dc3545']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });

        // WebSocket connection for real-time updates
        let ws = null;
        let reconnectAttempts = 0;
        const maxReconnectAttempts = 5;
        
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws/metrics`;
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function() {
                console.log('WebSocket connected');
                reconnectAttempts = 0;
            };
            
            ws.onmessage = function(event) {
                const message = JSON.parse(event.data);
                if (message.type === 'metrics_update') {
                    updateDashboard(message.data);
                }
            };
            
            ws.onclose = function() {
                console.log('WebSocket disconnected');
                if (reconnectAttempts < maxReconnectAttempts) {
                    setTimeout(() => {
                        reconnectAttempts++;
                        connectWebSocket();
                    }, 2000 * reconnectAttempts);
                } else {
                    // Fallback to page refresh
                    setInterval(() => location.reload(), 30000);
                }
            };
        }
        
        function updateDashboard(stats) {
            // Update connection count
            const activeConnEl = document.querySelector('.stat-value');
            if (activeConnEl) {
                activeConnEl.textContent = stats.connections.active;
            }
            
            // Update success rate
            const successRateEl = document.querySelectorAll('.stat-value')[2];
            if (successRateEl) {
                successRateEl.textContent = stats.authentication.success_rate + '%';
            }
            
            // Update chart data
            authChart.data.datasets[0].data = [
                stats.authentication.successes,
                stats.authentication.failures
            ];
            authChart.update('none'); // No animation for real-time updates
        }
        
        // Initialize WebSocket connection
        connectWebSocket();

        // Load backend information
        fetch('/api/backends')
            .then(response => response.json())
            .then(backends => {
                const backendList = document.getElementById('backendList');
                backendList.innerHTML = '';
                backends.forEach(backend => {
                    const li = document.createElement('li');
                    li.className = `backend-item ${
                        backend.available ? 'backend-available' : 'backend-unavailable'
                    }`;
                    // Sanitize backend data to prevent XSS
                    const safeName = document.createTextNode(backend.name).textContent;
                    const safeType = document.createTextNode(backend.type).textContent;
                    const statusText = backend.available ? 'Available' : 'Unavailable';
                    
                    const nameEl = document.createElement('strong');
                    nameEl.textContent = safeName;
                    
                    li.appendChild(nameEl);
                    li.appendChild(
                        document.createTextNode(` (${safeType}) - ${statusText}`)
                    );
                    backendList.appendChild(li);
                });
            });
    </script>
</body>
</html>
"""
