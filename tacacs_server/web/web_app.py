"""
Main Web Application - Simplified & Clean
This is the main FastAPI application that ties everything together
"""

import os
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from tacacs_server.utils.config_utils import set_config as utils_set_config
from tacacs_server.utils.logger import bind_context, clear_context, get_logger

from . import web_admin, web_api, web_auth
from .web import (
    set_config as _set_config,
)
from .web import (
    set_device_service as _set_device_service,
)
from .web import (
    set_local_user_group_service as _set_local_user_group_service,
)
from .web import (
    set_local_user_service as _set_local_user_service,
)
from .web import (
    set_radius_server as _set_radius_server,
)
from .web import (
    set_tacacs_server as _set_tacacs_server,
)

logger = get_logger(__name__)


def create_app(
    admin_username: str = "admin",
    admin_password_hash: str = "",
    api_token: str = None,
    tacacs_server=None,
    radius_server=None,
    device_service=None,
    user_service=None,
    user_group_service=None,
    config_service=None,
) -> FastAPI:
    """
    Create and configure the FastAPI application

    Args:
        admin_username: Admin username for web login
        admin_password_hash: Bcrypt hash of admin password
        api_token: API token for programmatic access (or set via API_TOKEN env)
        tacacs_server: TACACS+ server instance
        radius_server: RADIUS server instance
        device_service: Device management service
        user_service: User management service
        user_group_service: User group management service
        config_service: Configuration service
    """

    # Initialize FastAPI
    app = FastAPI(
        title="TACACS+ Server",
        description="Enterprise-grade TACACS+/RADIUS Server",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # ========================================================================
    # EXCEPTION HANDLERS
    # ========================================================================

    from tacacs_server.exceptions import (
        AuthenticationError,
        AuthorizationError,
        ConfigValidationError,
        RateLimitExceededError,
        ResourceNotFoundError,
        ServiceUnavailableError,
        TacacsServerError,
    )

    @app.exception_handler(ConfigValidationError)
    async def config_validation_error_handler(
        request: Request, exc: ConfigValidationError
    ):
        """Handle configuration validation errors"""
        validation_errors = exc.details.get("errors", {})
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.error_code,
                "message": exc.message,
                "detail": {
                    "field": exc.field,
                    "value": exc.value,
                    "validation_errors": validation_errors,
                },
            },
        )

    @app.exception_handler(AuthenticationError)
    async def authentication_error_handler(request: Request, exc: AuthenticationError):
        """Handle authentication errors"""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.error_code,
                "message": exc.message,
                "detail": exc.details,
            },
        )

    @app.exception_handler(AuthorizationError)
    async def authorization_error_handler(request: Request, exc: AuthorizationError):
        """Handle authorization errors"""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.error_code,
                "message": exc.message,
                "detail": exc.details,
            },
        )

    @app.exception_handler(ResourceNotFoundError)
    async def resource_not_found_handler(request: Request, exc: ResourceNotFoundError):
        """Handle resource not found errors"""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.error_code,
                "message": exc.message,
                "detail": exc.details,
            },
        )

    @app.exception_handler(RateLimitExceededError)
    async def rate_limit_exceeded_handler(
        request: Request, exc: RateLimitExceededError
    ):
        """Handle rate limit exceeded errors"""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.error_code,
                "message": exc.message,
                "detail": exc.details,
            },
        )

    @app.exception_handler(ServiceUnavailableError)
    async def service_unavailable_handler(
        request: Request, exc: ServiceUnavailableError
    ):
        """Handle service unavailable errors"""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.error_code,
                "message": exc.message,
                "detail": exc.details,
            },
        )

    @app.exception_handler(TacacsServerError)
    async def tacacs_server_error_handler(request: Request, exc: TacacsServerError):
        """Handle generic TACACS server errors"""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.error_code,
                "message": exc.message,
                "detail": exc.details,
            },
        )

    # ========================================================================
    # INITIALIZE AUTHENTICATION
    # ========================================================================

    # Use environment variables as fallback
    admin_username = admin_username or os.getenv("ADMIN_USERNAME", "admin")
    admin_password_hash = admin_password_hash or os.getenv("ADMIN_PASSWORD_HASH", "")
    api_token = api_token or os.getenv("API_TOKEN")

    # If a config_service provides creds (common in tests), prefer those
    # 1) Structured config: get_admin_auth_config() -> {username, password_hash}
    if not admin_password_hash and config_service is not None:
        try:
            getter = getattr(config_service, "get_admin_auth_config", None)
            if callable(getter):
                auth_cfg = getter()
                if isinstance(auth_cfg, dict):
                    if auth_cfg.get("username"):
                        admin_username = str(auth_cfg.get("username") or "admin")
                    if auth_cfg.get("password_hash"):
                        admin_password_hash = str(auth_cfg.get("password_hash") or "")
                        logger.info(
                            "Authentication initialized from config_service (hash)"
                        )
        except Exception:
            pass

    # 2) Dict-like config with plaintext
    if not admin_password_hash and config_service is not None:
        try:
            plain_user = None
            plain_pass = None
            if hasattr(config_service, "get") and callable(
                getattr(config_service, "get")
            ):
                plain_user = config_service.get("admin_username")
                plain_pass = config_service.get("admin_password")
            elif isinstance(config_service, dict):
                plain_user = config_service.get("admin_username")
                plain_pass = config_service.get("admin_password")
            if plain_user and plain_pass:
                import bcrypt

                admin_username = plain_user
                admin_password_hash = bcrypt.hashpw(
                    plain_pass.encode("utf-8"), bcrypt.gensalt()
                ).decode("utf-8")
                logger.info(
                    "Authentication initialized from config_service (plaintext)"
                )
        except Exception:
            pass

    # Support plain ADMIN_PASSWORD env by hashing at startup when no hash provided
    if not admin_password_hash:
        plain = os.getenv("ADMIN_PASSWORD")
        if plain:
            try:
                import bcrypt

                admin_password_hash = bcrypt.hashpw(
                    plain.encode("utf-8"), bcrypt.gensalt()
                ).decode("utf-8")
                logger.info("Authentication initialized from environment (plaintext)")
            except Exception:
                admin_password_hash = ""

    if admin_password_hash:
        web_auth.init_auth(
            admin_username=admin_username,
            admin_password_hash=admin_password_hash,
            api_token=api_token,
            session_timeout=60,
        )
        logger.info("Authentication initialized (username=%s)", admin_username)
    else:
        logger.warning("Admin authentication not configured - web UI will be disabled")

    # ========================================================================
    # STORE SERVICES IN APP STATE
    # ========================================================================

    app.state.tacacs_server = tacacs_server
    app.state.radius_server = radius_server
    app.state.device_service = device_service
    app.state.config_service = config_service

    # Also set in global accessors so API endpoints can find it
    if config_service:
        try:
            from tacacs_server.utils import config_utils

            config_utils.set_config(config_service)
            _set_config(config_service)
            logger.info("Configuration service registered with web app")
        except Exception as e:
            logger.error("Failed to register config service: %s", e)

    # Auto-provision device service if not provided
    if not device_service and tacacs_server is not None:
        try:
            from tacacs_server.devices.service import DeviceService
            from tacacs_server.devices.store import DeviceStore

            # Try to reuse device_store attached on server if present
            ds = getattr(tacacs_server, "device_store", None)
            if ds is None:
                # Create default store if none was provided
                ds = DeviceStore("data/devices.db")
            device_service = DeviceService(ds)
            app.state.device_service = device_service
        except Exception:
            pass
    # If no user service was provided, try to build one from tacacs_server.auth_db
    if not user_service and tacacs_server is not None:
        try:
            from tacacs_server.auth.local_user_service import LocalUserService

            # Try known attributes from possible server wrappers
            auth_db = getattr(tacacs_server, "auth_db", None)
            if auth_db:
                user_service = LocalUserService(str(auth_db))
            else:
                # Try store present on a wrapper (main creates a LocalAuthStore)
                store = getattr(tacacs_server, "local_auth_store", None)
                db_path = None
                if store is not None:
                    db_path = getattr(store, "db_path", None) or getattr(
                        store, "path", None
                    )
                if db_path:
                    user_service = LocalUserService(str(db_path), store=store)
        except Exception:
            user_service = user_service

    # Final default fallback so the UI works even if services weren't wired
    if not user_service:
        try:
            from tacacs_server.auth.local_user_service import LocalUserService

            default_path = "data/local_auth.db"
            user_service = LocalUserService(default_path)
            logger.warning(
                "web_app.create_app: constructed default LocalUserService at %s",
                default_path,
            )
        except Exception:
            pass

    app.state.user_service = user_service
    # Auto-provision user group service if not provided
    if not user_group_service:
        try:
            from tacacs_server.auth.local_user_group_service import (
                LocalUserGroupService,
            )

            # Prefer to share the same store/path as the user service if available
            if user_service and hasattr(user_service, "store"):
                user_group_service = LocalUserGroupService(
                    getattr(user_service.store, "db_path", "data/local_auth.db"),
                    store=getattr(user_service, "store", None),
                )
            else:
                # Fallback to default path or from server store
                store = (
                    getattr(tacacs_server, "local_auth_store", None)
                    if tacacs_server
                    else None
                )
                db_path = None
                if store is not None:
                    db_path = getattr(store, "db_path", None) or getattr(
                        store, "path", None
                    )
                user_group_service = LocalUserGroupService(
                    db_path or "data/local_auth.db", store=store
                )
            app.state.user_group_service = user_group_service
        except Exception:
            app.state.user_group_service = user_group_service
    else:
        app.state.user_group_service = user_group_service
    app.state.config_service = config_service

    # Maintain legacy global accessors for modules still importing from web.web
    try:
        _set_tacacs_server(tacacs_server)
        _set_radius_server(radius_server)
        _set_device_service(device_service)
        _set_local_user_service(user_service)
        _set_local_user_group_service(user_group_service)
        _set_config(config_service)
        # Also set via utils to ensure availability in API modules using config_utils
        try:
            utils_set_config(config_service)
        except Exception:
            pass
    except Exception:
        pass

    # ========================================================================
    # SECURITY HEADERS MIDDLEWARE
    # ========================================================================

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        # Unified request logging for Admin UI and API without consuming body
        started = None
        _ctx_token = None
        try:
            import time as _t

            started = _t.time()
            path = str(getattr(request.url, "path", ""))
            # Correlation: use incoming header else generate UUIDv4
            corr = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
            try:
                _ctx_token = bind_context(correlation_id=corr)
            except Exception:
                _ctx_token = None
            logger.debug(
                "HTTP request",
                event="http.request",
                service="web",
                component="web_app",
                method=getattr(request, "method", ""),
                path=path,
                headers_sample={
                    "content-type": request.headers.get("content-type", ""),
                    "accept": request.headers.get("accept", ""),
                },
                client={
                    "ip": getattr(getattr(request, "client", None), "host", ""),
                },
                correlation_id=corr,
            )
        except Exception:
            pass

        response = await call_next(request)

        # Emit completion log with status and duration
        try:
            import time as _t

            dur_ms = int(((_t.time() - started) if started else 0) * 1000)
            logger.debug(
                "HTTP response",
                event="http.response",
                service="web",
                component="web_app",
                method=getattr(request, "method", ""),
                path=str(getattr(request.url, "path", "")),
                status=getattr(response, "status_code", ""),
                duration_ms=dur_ms,
                correlation_id=(request.headers.get("X-Correlation-ID") or None),
            )
        except Exception:
            pass

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # CSP for admin UI - allow only self-hosted resources
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "font-src 'self';"
        )

        # HSTS for HTTPS
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # Remove server identification
        try:
            del response.headers["server"]
        except KeyError:
            pass

        try:
            if _ctx_token is not None:
                clear_context(_ctx_token)
        except Exception:
            pass

        return response

    # ========================================================================
    # STATIC FILES & TEMPLATES
    # ========================================================================

    # Use package-relative paths (works regardless of working directory)
    pkg_root = Path(__file__).resolve().parent.parent
    static_dir = pkg_root / "static"
    # templates handled inside web_admin

    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # ========================================================================
    # FEATURE FLAGS (template globals)
    # ========================================================================

    # Determine if proxy feature is enabled from config/tacacs_server
    try:
        proxy_enabled = False
        # Prefer config_service if available
        if config_service is not None:
            # Newer consolidated proxy protocol section
            try:
                getter = getattr(config_service, "get_proxy_protocol_config", None)
                if callable(getter):
                    pxy = getter() or {}
                    proxy_enabled = bool(pxy.get("enabled", proxy_enabled))
            except Exception:
                pass
            # Legacy flag under server network
            if proxy_enabled is False:
                try:
                    getter = getattr(config_service, "get_server_network_config", None)
                    if callable(getter):
                        net_cfg = getter() or {}
                        proxy_enabled = bool(net_cfg.get("proxy_enabled", False))
                except Exception:
                    pass
        # Fallback to tacacs_server runtime flag if present
        if proxy_enabled is False and tacacs_server is not None:
            proxy_enabled = bool(getattr(tacacs_server, "proxy_enabled", False))

        # Publish to Jinja2 template globals used by base nav and forms
        try:
            from . import web_admin as _web_admin

            _web_admin.templates.env.globals["proxy_enabled"] = proxy_enabled
            logger.debug("Template global proxy_enabled set to %s", proxy_enabled)
        except Exception:
            pass
    except Exception:
        pass

    # ========================================================================
    # INCLUDE ROUTERS
    # ========================================================================

    # Admin web UI routes
    app.include_router(web_admin.router)

    # API routes
    app.include_router(web_api.router)

    # Feature-specific API routes
    try:
        from tacacs_server.web.api.proxies import router as proxies_router

        app.include_router(proxies_router)
        logger.debug("Included proxies API routes under /api/proxies")
    except Exception as exc:
        logger.error("Failed to include proxies API routes: %s", exc)

    # Backup API routes (admin)
    try:
        from tacacs_server.web.api.backup import router as backup_router

        app.include_router(backup_router)
        logger.debug("Included backup API routes under /api/admin/backup")
    except Exception as exc:
        logger.error("Failed to include backup API routes: %s", exc)

    # Config API routes (admin)
    try:
        from tacacs_server.web.api.config import router as config_router

        app.include_router(config_router)
        logger.debug("Included config API routes under /api/admin/config")
    except Exception as exc:
        logger.error("Failed to include config API routes: %s", exc)

    # ========================================================================
    # ROOT & BASIC ENDPOINTS
    # ========================================================================

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def root(request: Request):
        """Root redirect to dashboard or status page"""
        # If authenticated, redirect to admin
        session_mgr = web_auth.get_session_manager()
        if session_mgr:
            token = request.cookies.get("admin_session")
            if token and session_mgr.validate_session(token):
                from fastapi.responses import RedirectResponse

                return RedirectResponse(url="/admin/")

        # Otherwise show simple status page
        return """
        <html>
            <head><title>TACACS+ Server</title></head>
            <body>
                <h1>TACACS+ Server</h1>
                <p>Status: Running</p>
                <ul>
                    <li><a href="/admin/">Admin Interface</a></li>
                    <li><a href="/api/docs">API Documentation</a></li>
                    <li><a href="/metrics">Prometheus Metrics</a></li>
                </ul>
            </body>
        </html>
        """

    @app.get("/health", include_in_schema=False)
    async def health():
        """Simple health check"""
        return {"status": "ok"}

    @app.get("/ready", include_in_schema=False)
    async def readiness():
        """Readiness check"""
        try:
            if tacacs_server and getattr(tacacs_server, "running", False):
                return {"ready": True}
            return JSONResponse(
                {"ready": False, "reason": "server not running"},
                status_code=503,
            )
        except Exception as e:
            return JSONResponse(
                {"ready": False, "reason": str(e)},
                status_code=503,
            )

    # ========================================================================
    # PROMETHEUS METRICS
    # ========================================================================

    @app.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
    async def prometheus_metrics():
        """Prometheus metrics endpoint."""
        try:
            data = generate_latest()
            return PlainTextResponse(content=data, media_type=CONTENT_TYPE_LATEST)
        except Exception as e:
            return JSONResponse(
                {"detail": f"Metrics unavailable: {e}"}, status_code=500
            )

    @app.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
    async def metrics():
        """Prometheus metrics endpoint"""
        try:
            data = generate_latest()
            return PlainTextResponse(content=data, media_type=CONTENT_TYPE_LATEST)
        except Exception as e:
            logger.error(f"Metrics generation error: {e}")
            return PlainTextResponse("# Metrics unavailable\n", status_code=500)

    # ========================================================================
    # ERROR HANDLERS
    # ========================================================================

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        """Custom 404 handler"""
        if "text/html" in request.headers.get("accept", ""):
            return HTMLResponse(
                content="<h1>404 - Not Found</h1>",
                status_code=404,
            )
        return JSONResponse(
            {"error": "Not found"},
            status_code=404,
        )

    @app.exception_handler(500)
    async def server_error_handler(request: Request, exc):
        """Custom 500 handler"""
        logger.error(f"Internal server error: {exc}", exc_info=True)
        if "text/html" in request.headers.get("accept", ""):
            return HTMLResponse(
                content="<h1>500 - Internal Server Error</h1>",
                status_code=500,
            )
        return JSONResponse(
            {"error": "Internal server error"},
            status_code=500,
        )

    # ========================================================================
    # STARTUP / SHUTDOWN
    # ========================================================================

    @app.on_event("startup")
    async def startup():
        """Application startup"""
        # Structured service start log
        try:
            logger.info(
                "Web interface starting",
                event="service.start",
                service="web",
                component="web_app",
                version=getattr(app, "version", None),
                env=os.getenv("ENV") or os.getenv("APP_ENV") or "dev",
            )
        except Exception:
            pass
        logger.debug("Admin Interface: /admin/")
        logger.debug("API Documentation: /api/docs")
        logger.debug("Prometheus Metrics: /metrics")

        # API security notice
        if api_token:
            logger.info(
                "API token configured",
                event="api.config",
                service="web",
                component="web_app",
                api_token_configured=True,
            )
        else:
            # Endpoints guarded by admin-or-api remain accessible with an admin session.
            logger.warning(
                "No API token configured; admin session required for admin-or-api endpoints",
                event="api.config",
                service="web",
                component="web_app",
                api_token_configured=False,
            )

        # Check if admin is enabled
        if admin_password_hash:
            logger.info(
                "Admin web enabled",
                event="admin.config",
                service="web",
                component="web_app",
                admin_username=admin_username,
                admin_enabled=True,
            )
        else:
            logger.warning(
                "Admin web disabled (no password hash configured)",
                event="admin.config",
                service="web",
                component="web_app",
                admin_enabled=False,
            )

        # Log important mounted routes for diagnostics
        try:
            backup_routes = [
                getattr(r, "path", "")
                for r in getattr(app, "routes", [])
                if "/api/admin/backup" in str(getattr(r, "path", ""))
            ]
            logger.debug(
                "Backup API routes mounted",
                event="routes.mounted",
                service="web",
                component="web_app",
                count=len(backup_routes),
                sample=backup_routes[:3],
            )
        except Exception:
            pass

        # Log resolved DB/service paths for isolation diagnostics
        try:
            usr = getattr(app.state, "user_service", None)
            dev = getattr(app.state, "device_service", None)
            user_db = getattr(usr, "db_path", None)
            dev_store = getattr(dev, "store", None)
            dev_db = getattr(dev_store, "db_path", None) if dev_store else None
            logger.debug(
                "Resolved DB paths",
                event="startup.info",
                service="web",
                component="web_app",
                user_db=user_db,
                device_db=dev_db,
                cwd=os.getcwd(),
            )
        except Exception:
            pass

    @app.on_event("shutdown")
    async def shutdown():
        """Application shutdown"""
        try:
            logger.info(
                "Web interface stopping",
                event="service.stop",
                service="web",
                component="web_app",
            )
        except Exception:
            pass

    return app


# ============================================================================
# HELPER TO RUN THE APP
# ============================================================================


def run_server(host: str = "0.0.0.0", port: int = 8080, **kwargs):
    """
    Run the web server using uvicorn

    Args:
        host: Host to bind to
        port: Port to bind to
        **kwargs: Additional arguments for create_app()
    """
    import uvicorn

    app = create_app(**kwargs)

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=False,
        server_header=False,
    )


if __name__ == "__main__":
    # Example: Run standalone
    run_server(
        host="127.0.0.1",
        port=8080,
        admin_username="admin",
        admin_password_hash="$2b$12$example",  # Replace with real hash
        api_token="your-api-token-here",
    )
