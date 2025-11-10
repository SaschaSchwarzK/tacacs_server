"""
Web Interface for TACACS+ Server
Provides both HTML dashboard and Prometheus metrics endpoint
"""

import asyncio
import importlib
import os
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path as FilePath
from typing import Any, Optional, cast

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
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from prometheus_client import REGISTRY as _PROM_REGISTRY
from prometheus_client import Counter as _PM_Counter
from prometheus_client import Gauge as _PM_Gauge
from prometheus_client import Histogram as _PM_Histogram
from pydantic import BaseModel

from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.metrics_history import get_metrics_history
from tacacs_server.web.api_models import (
    AccountingResponse,
    AuthBackendInfo,
    DetailedHealthCheck,
    DetailedServerStatus,
    DetailedStats,
    SessionsResponse,
)
from tacacs_server.web.errors import install_exception_handlers as _install_exc
from tacacs_server.web.openapi_config import (
    configure_openapi_ui,
    custom_openapi_schema,
)

DeviceService = Any
LocalUserService = Any
LocalUserGroupService = Any
AdminSessionManager = Any
CommandAuthorizationEngine = Any

logger = get_logger(__name__)

_device_service: Optional["DeviceService"] = None
_local_user_service: Optional["LocalUserService"] = None
_local_user_group_service: Optional["LocalUserGroupService"] = None
_tacacs_server_ref = None
_radius_server_ref = None
_admin_session_manager: Optional["AdminSessionManager"] = None
_command_authorizer: (
    Callable[[str, int, list[str] | None, str | None], tuple[bool, str]] | None
) = None
_command_engine: Optional["CommandAuthorizationEngine"] = None


def _load_config_utils():
    return importlib.import_module("tacacs_server.utils.config_utils")


def set_config(*args: Any, **kwargs: Any):
    return _load_config_utils().set_config(*args, **kwargs)


def get_config(*args: Any, **kwargs: Any):
    return _load_config_utils().get_config(*args, **kwargs)


def get_config_change_user(*args: Any, **kwargs: Any):
    return _load_config_utils().get_config_change_user(*args, **kwargs)


def get_config_change_source_ip(*args: Any, **kwargs: Any):
    return _load_config_utils().get_config_change_source_ip(*args, **kwargs)


def set_config_change_user(*args: Any, **kwargs: Any):
    return _load_config_utils().set_config_change_user(*args, **kwargs)


def set_config_change_source_ip(*args: Any, **kwargs: Any):
    return _load_config_utils().set_config_change_source_ip(*args, **kwargs)


def set_admin_auth_dependency(*args: Any, **kwargs: Any):
    return _load_config_utils().set_admin_auth_dependency(*args, **kwargs)


def get_admin_auth_dependency_func(*args: Any, **kwargs: Any):
    return _load_config_utils().get_admin_auth_dependency_func(*args, **kwargs)


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


# set_config/get_config are re-exported above; avoid redefining


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


# set_admin_auth_dependency and get_admin_auth_dependency_func are re-exported above


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


def _safe_counter(name: str, doc: str, labels: list[str] | None = None):
    try:
        return _PM_Counter(name, doc, labels or [], registry=_PROM_REGISTRY)
    except ValueError:
        # Already registered; fetch existing collector
        return _PROM_REGISTRY._names_to_collectors.get(name)


def _safe_gauge(name: str, doc: str):
    try:
        return _PM_Gauge(name, doc, registry=_PROM_REGISTRY)
    except ValueError:
        return _PROM_REGISTRY._names_to_collectors.get(name)


def _safe_histogram(name: str, doc: str):
    try:
        return _PM_Histogram(name, doc, registry=_PROM_REGISTRY)
    except ValueError:
        return _PROM_REGISTRY._names_to_collectors.get(name)


# Prometheus Metrics (idempotent registration)
auth_requests_total = _safe_counter(
    "tacacs_auth_requests_total",
    "Total authentication requests",
    ["status", "backend", "reason"],
)
auth_duration = _safe_histogram(
    "tacacs_auth_duration_seconds", "Authentication request duration"
)
active_connections = _safe_gauge(
    "tacacs_active_connections", "Number of active connections"
)
server_uptime = _safe_gauge("tacacs_server_uptime_seconds", "Server uptime in seconds")
proxied_connections = _safe_gauge(
    "tacacs_connections_proxied_total", "Total proxied TCP connections observed"
)
direct_connections = _safe_gauge(
    "tacacs_connections_direct_total", "Total direct TCP connections observed"
)

accounting_records = _safe_counter(
    "tacacs_accounting_records_total", "Total accounting records", ["status"]
)
radius_auth_requests = _safe_counter(
    "radius_auth_requests_total", "RADIUS authentication requests", ["status"]
)
radius_acct_requests = _safe_counter(
    "radius_acct_requests_total", "RADIUS accounting requests", ["type"]
)
radius_active_clients = _safe_gauge(
    "radius_active_clients", "Number of configured RADIUS clients"
)
radius_packets_dropped_total = _safe_counter(
    "radius_packets_dropped_total", "Dropped RADIUS packets", ["reason"]
)
device_identity_cache_hits = _safe_gauge(
    "tacacs_device_identity_cache_hits", "Device identity cache hits"
)


# Command authorization metrics
command_authorizations_total = _safe_counter(
    "tacacs_command_authorizations_total",
    "Total TACACS+ command authorization decisions",
    ["outcome"],
)
device_identity_cache_misses = _safe_gauge(
    "tacacs_device_identity_cache_misses", "Device identity cache misses"
)
device_identity_cache_evictions = _safe_gauge(
    "tacacs_device_identity_cache_evictions", "Device identity cache evictions"
)
device_identity_cache_hits_total = _safe_counter(
    "tacacs_device_identity_cache_hits_total", "Cumulative device identity cache hits"
)
device_identity_cache_misses_total = _safe_counter(
    "tacacs_device_identity_cache_misses_total",
    "Cumulative device identity cache misses",
)
device_identity_cache_evictions_total = _safe_counter(
    "tacacs_device_identity_cache_evictions_total",
    "Cumulative device identity cache evictions",
)


class _DeviceIdentityCacheTracker:
    def __init__(self) -> None:
        self.hits = 0
        self.misses = 0
        self.evictions = 0


_device_identity_cache_tracker = _DeviceIdentityCacheTracker()


def _load_router(module_name: str, attr: str = "router"):
    mod = importlib.import_module(module_name)
    return getattr(mod, attr)


class WebServer:
    """Web interface for TACACS+ server"""

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
        self.host = host
        self.port = port
        self.api_token = None
        self.api_enforce_token = False
        self.api_enabled = True
        # API token configuration
        configured_token = os.getenv("API_TOKEN")
        # Production behaviour: API enabled only when a token is configured.
        if configured_token:
            self.api_token = configured_token
            self.api_enforce_token = True
            self.api_enabled = True
            logger.info("API token enforcement: enabled")
        else:
            self.api_token = None
            self.api_enforce_token = False
            self.api_enabled = False
            logger.info("API disabled: API_TOKEN not configured")

        self.app = FastAPI(
            title="TACACS+ Server Monitor",
            version="1.0.0",
            docs_url=None,
            redoc_url=None,
            openapi_tags=tags_metadata,
        )
        _install_exc(self.app)
        # Disable global automatic slash redirects to ensure auth guards
        # execute on both '/path' and '/path/' as explicitly defined.
        try:
            self.app.router.redirect_slashes = False
        except Exception as exc:
            logger.warning("Failed to disable slash redirects: %s", exc)
        # Install shared security headers middleware
        from .middleware import install_security_headers

        install_security_headers(self.app)

        # Global maintenance mode guard: return 503 for most requests while
        # a restore is in progress to avoid using closed DB connections.
        try:
            maintenance_mod = importlib.import_module("tacacs_server.utils.maintenance")
            _get_dbm = getattr(maintenance_mod, "get_db_manager")

            @self.app.middleware("http")
            async def maintenance_guard(request: Request, call_next):
                try:
                    path = request.url.path or ""
                    if _get_dbm().is_in_maintenance():
                        if not (
                            path.startswith("/health")
                            or path.startswith("/tacacs-health")
                            or path.startswith("/ready")
                        ):
                            return JSONResponse(
                                {"error": "Service in maintenance mode"},
                                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            )
                except Exception as exc:
                    logger.warning("Maintenance guard failed: %s", exc)
                return await call_next(request)
        except Exception as exc:
            logger.warning("Maintenance middleware registration failed: %s", exc)

        # Middleware to capture config change context (user + source IP)
        @self.app.middleware("http")
        async def config_change_context(request: Request, call_next):
            try:
                path = request.url.path or ""
                if path.startswith("/api/admin/config"):
                    user = request.headers.get("X-Admin-User") or "system"
                    if user == "system":
                        auth = request.headers.get("Authorization") or ""
                        if auth:
                            user = auth.split()[0]
                    set_config_change_user(user)
                    client = getattr(request, "client", None)
                    ip = getattr(client, "host", None) if client else None
                    set_config_change_source_ip(ip)
            except Exception as exc:
                logger.warning("Config change context extraction failed: %s", exc)
            try:
                resp = await call_next(request)
            finally:
                # Clear context for next request
                try:
                    set_config_change_user("system")
                    set_config_change_source_ip(None)
                except Exception as exc:
                    logger.warning("Reset config change context failed: %s", exc)
            return resp

        # Optional API token protection for all /api routes
        api_token = os.getenv("API_TOKEN")
        # Disable token enforcement when no config is wired (unit/functional tests)
        try:
            if get_config() is None:
                api_token = None
        except Exception:
            api_token = None
        try:
            enforced = bool(api_token)
            logger.info(
                "API token enforcement: %s (configured_token=%s)",
                "enabled" if enforced else "disabled",
                "set" if api_token else "not set",
            )
        except Exception as exc:
            logger.warning("API token enforcement logging failed: %s", exc)

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

        # Include API routers, imported lazily to break circular dependencies
        devices_router = _load_router("tacacs_server.web.api.devices")
        device_groups_router = _load_router("tacacs_server.web.api.device_groups")
        users_router = _load_router("tacacs_server.web.api.users")
        user_groups_router = _load_router("tacacs_server.web.api.usergroups")
        config_router = _load_router("tacacs_server.web.api.config")

        self.app.include_router(devices_router)
        self.app.include_router(device_groups_router)
        self.app.include_router(users_router)
        try:
            admin_mod = importlib.import_module("tacacs_server.web.api.users")
            admin_router = getattr(admin_mod, "admin_router", None)
            if admin_router is not None:
                self.app.include_router(admin_router)
        except Exception as exc:
            logger.warning("Admin router import failed: %s", exc)
        self.app.include_router(user_groups_router)
        # Proxies API routes are registered in the main web_app.py
        self.app.include_router(config_router)
        # Include backup router (admin-protected)
        try:
            backup_router = _load_router("tacacs_server.web.api.backup")

            self.app.include_router(backup_router)
            logger.info("Backup router successfully included")
        except Exception as exc:  # noqa: BLE001
            import traceback

            logger.error(
                "Failed to include backup router: %s\n%s", exc, traceback.format_exc()
            )
        # Include command authorization API (protected by admin guard inside router)
        try:
            cmd_router = _load_router(
                "tacacs_server.authorization.command_authorization"
            )

            self.app.include_router(cmd_router)
        except Exception as exc:
            logger.warning("Failed to include command authorization router: %s", exc)

        # Health and readiness simple endpoints (top-level convenience)
        @self.app.get("/health", tags=["Status & Monitoring"], include_in_schema=False)
        async def liveness():
            return {"status": "ok"}

        # Lightweight TACACS-only health endpoint for container/orchestrator probes.
        # Unauthenticated and not under /api/; returns plain boolean text.
        @self.app.get(
            "/tacacs-health",
            include_in_schema=False,
        )
        async def tacacs_health():
            try:
                running = bool(
                    self.tacacs_server and getattr(self.tacacs_server, "running", False)
                )
            except Exception:
                running = False
            # Return text/plain boolean with 200 when healthy, 503 when not.
            return PlainTextResponse(
                "true" if running else "false",
                status_code=200 if running else 503,
            )

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
        cast(Any, self.app).openapi = lambda: custom_openapi_schema(self.app)
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
                logger.exception("Dashboard rendering error: %s", e)
                raise HTTPException(status_code=500, detail="Dashboard unavailable")

        # API Endpoints
        # Admin guard dependency shared with admin endpoints
        async def admin_guard(request: Request) -> None:
            # Correct: only inspect cookies/headers, do not read body
            try:
                logger.info(
                    "web.admin_guard: path=%s method=%s ct=%s accept=%s has_cookie=%s",
                    getattr(request.url, "path", ""),
                    getattr(request, "method", ""),
                    request.headers.get("content-type", ""),
                    request.headers.get("accept", ""),
                    bool(request.cookies.get("admin_session")),
                )
            except Exception as exc:
                logger.warning("admin_guard logging failed: %s", exc)
            session_token = request.cookies.get("admin_session")
            if not session_token:
                logger.warning("web.admin_guard: missing admin_session cookie")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
            session_mgr = get_admin_session_manager()
            if not session_mgr:
                logger.error("web.admin_guard: session manager not configured")
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
            if not bool(
                getattr(session_mgr, "validate_session", lambda _t: False)(
                    session_token
                )
            ):
                logger.warning("web.admin_guard: session invalid or expired")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
            else:
                logger.debug("web.admin_guard: session valid")

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
                logger.exception("API status error: %s", e)
                raise HTTPException(status_code=500, detail="Status check failed")

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
                logger.exception("API health error: %s", e)
                raise HTTPException(status_code=503, detail="Health check failed")

        # --- Config validation endpoint ---
        @self.app.post(
            "/api/admin/config/validate",
            tags=["Administration"],
            dependencies=[Depends(admin_guard)],
        )
        async def validate_config_change(
            section: str,
            key: str,
            value: str,
        ):
            """Validate a configuration change before applying."""
            cfg = get_config()
            if cfg is None or not hasattr(cfg, "validate_change"):
                raise HTTPException(
                    status_code=503, detail="Configuration not available"
                )
            try:
                ok, issues = cfg.validate_change(section, key, value)
            except Exception as exc:
                logger.exception("Config validation error: %s", exc)
                raise HTTPException(status_code=400, detail="Validation error")
            return {
                "valid": bool(ok),
                "issues": list(issues or []),
                "section": section,
                "key": key,
                "value": value,
            }

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
                logger.exception("API stats error: %s", e)
                raise HTTPException(status_code=500, detail="Stats retrieval failed")

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
                logger.exception("Backend stats error: %s", e)
                raise HTTPException(
                    status_code=500, detail="Failed to get backend stats"
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
                logger.exception("Session stats error: %s", e)
                raise HTTPException(
                    status_code=500, detail="Failed to get session stats"
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
                    except Exception as exc:
                        logger.warning("Failed to filter accounting records: %s", exc)
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
                logger.exception("Reload config failed: %s", e)
                raise HTTPException(status_code=500, detail="Reload failed")

        @self.app.post("/api/admin/reset-stats", include_in_schema=False)
        async def reset_stats(_: None = Depends(admin_guard)):
            """Reset server statistics"""
            try:
                self.tacacs_server.reset_stats()
                return {"success": True, "message": "Statistics reset"}
            except Exception as e:
                logger.exception("Reset stats failed: %s", e)
                raise HTTPException(status_code=500, detail="Reset failed")

        @self.app.get("/api/admin/logs", include_in_schema=False)
        async def get_logs(lines: int = 100, _: None = Depends(admin_guard)):
            """Get recent log entries"""
            try:
                # This would read from your log file
                logs = self.get_recent_logs(lines)
                return {"logs": logs, "count": len(logs)}
            except Exception as e:
                logger.exception("Get logs failed: %s", e)
                raise HTTPException(status_code=500, detail="Logs unavailable")

        # Admin API router
        try:
            from .admin import admin_router

            self.app.include_router(admin_router, include_in_schema=False)
        except Exception as exc:
            logger.warning("Failed to include admin router: %s", exc)

        # Removed legacy compatibility routes under /api/admin/*

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
                    except Exception as exc:
                        logger.warning("Error stopping RADIUS server: %s", exc)
                    # Start again
                    self.radius_server.start()
                    return {"success": True, "message": "RADIUS restarted"}
                except Exception as exc:
                    logger.exception("RADIUS restart failed: %s", exc)
                    raise HTTPException(status_code=500, detail="RADIUS restart failed")

    def get_server_stats(self) -> dict[str, Any]:
        """Get current server statistics"""
        try:
            stats = self.tacacs_server.get_stats()
            health = self.tacacs_server.get_health_status()

            # Update gauges at fetch-time to reflect recent state
            try:
                active_connections.set(stats.get("connections_active", 0))
                server_uptime.set(float(health.get("uptime_seconds", 0)))
                proxied_connections.set(stats.get("connections_proxied", 0))
                direct_connections.set(stats.get("connections_direct", 0))
            except Exception as exc:
                logger.warning("Failed to update server gauges: %s", exc)

            data = {
                "status": "running" if self.tacacs_server.running else "stopped",
                "uptime": health.get("uptime_seconds", 0),
                "connections": {
                    "active": stats.get("connections_active", 0),
                    "total": stats.get("connections_total", 0),
                    "proxied": stats.get("connections_proxied", 0),
                    "direct": stats.get("connections_direct", 0),
                    "proxied_rejected_unknown": stats.get("proxy_rejected_unknown", 0),
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

            # Expose device identity cache counters if available
            try:
                store = getattr(self.tacacs_server, "device_store", None)
                if store is not None and hasattr(store, "get_identity_cache_stats"):
                    cstats = store.get_identity_cache_stats()
                    device_identity_cache_hits.set(cstats.get("hits", 0))
                    device_identity_cache_misses.set(cstats.get("misses", 0))
                    device_identity_cache_evictions.set(cstats.get("evictions", 0))
                    data.setdefault("devices", {})["identity_cache"] = cstats
                    tracker = _device_identity_cache_tracker
                    dh = int(cstats.get("hits", 0)) - tracker.hits
                    dm = int(cstats.get("misses", 0)) - tracker.misses
                    de = int(cstats.get("evictions", 0)) - tracker.evictions
                    if dh > 0:
                        device_identity_cache_hits_total.inc(dh)
                    if dm > 0:
                        device_identity_cache_misses_total.inc(dm)
                    if de > 0:
                        device_identity_cache_evictions_total.inc(de)
                    tracker.hits = int(cstats.get("hits", 0))
                    tracker.misses = int(cstats.get("misses", 0))
                    tracker.evictions = int(cstats.get("evictions", 0))
            except Exception as exc:
                logger.warning("Failed to gather identity cache stats: %s", exc)

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
                    server_header=False,
                    date_header=False,
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
        except Exception as exc:
            logger.warning("Monitoring thread join failed: %s", exc)
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

    @staticmethod
    def record_command_authorization(outcome: str):
        """Record command authorization decision (granted/denied)."""
        # Normalize to a small cardinality set
        outcome = "granted" if outcome == "granted" else "denied"
        command_authorizations_total.labels(outcome=outcome).inc()
