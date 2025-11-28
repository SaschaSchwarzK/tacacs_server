"""
Main Web Application - Simplified & Clean
This is the main FastAPI application that ties everything together
"""

import os
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.middleware.sessions import SessionMiddleware

from tacacs_server.config.getters import get_openid_config
from tacacs_server.utils.config_utils import set_config as utils_set_config
from tacacs_server.utils.logger import bind_context, clear_context, get_logger
from tacacs_server.web.openid_auth import OpenIDConfig

from . import web_admin, web_auth
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
    # Enable signed sessions so OpenID state can be stored safely during redirects.
    session_secret = (
        os.getenv("ADMIN_SESSION_SECRET")
        or os.getenv("SESSION_SECRET")
        or uuid.uuid4().hex
    )
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        same_site="lax",
        https_only=False,
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

    def _build_openid_config(source_config=None) -> OpenIDConfig | None:
        """Create OpenIDConfig from config service + env (config takes precedence for non-secrets)."""
        raw_cfg: dict | None = None
        getter = getattr(source_config, "get_openid_config", None)
        if callable(getter):
            try:
                raw_cfg = getter()
            except Exception:
                raw_cfg = None

        # Fallback to env-only parsing when no config service is provided
        if raw_cfg is None:
            try:
                import configparser

                tmp_cfg = configparser.ConfigParser(interpolation=None)
                raw_cfg = get_openid_config(tmp_cfg)
            except Exception:
                raw_cfg = None

        if not raw_cfg or not raw_cfg.get("issuer_url"):
            return None

        allowed_groups = raw_cfg.get("allowed_groups") or None
        try:
            return OpenIDConfig(
                issuer_url=raw_cfg.get("issuer_url", ""),
                client_id=raw_cfg.get("client_id", ""),
                client_secret=raw_cfg.get("client_secret", "") or "",
                redirect_uri=raw_cfg.get("redirect_uri", ""),
                scopes=raw_cfg.get("scopes", "openid profile email"),
                token_endpoint=raw_cfg.get("token_endpoint"),
                userinfo_endpoint=raw_cfg.get("userinfo_endpoint"),
                session_timeout_minutes=int(
                    raw_cfg.get("session_timeout_minutes", 60) or 60
                ),
                allowed_groups=allowed_groups,
                use_interaction_code=bool(raw_cfg.get("use_interaction_code")),
                code_verifier=raw_cfg.get("code_verifier"),
                client_auth_method=raw_cfg.get("client_auth_method", "client_secret"),
                client_private_key=raw_cfg.get("client_private_key"),
                client_private_key_id=raw_cfg.get("client_private_key_id"),
            )
        except Exception as exc:
            logger.warning("Failed to initialize OpenID configuration: %s", exc)
            return None

    openid_config = _build_openid_config(config_service)

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
            pass  # Config service auth retrieval failed, will try other methods

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
            pass  # Plaintext password hashing failed, will try other methods

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

    # Initialize auth when either a password hash is provided OR OpenID is configured
    if admin_password_hash or openid_config:
        web_auth.init_auth(
            admin_username=admin_username,
            admin_password_hash=admin_password_hash or "",
            api_token=api_token,
            session_timeout=60,
            openid_config=openid_config,
        )
        # Bridge session manager into global accessor for modules using config_utils
        try:
            from tacacs_server.web.web import set_admin_session_manager as _set_admin_sm

            _set_admin_sm(web_auth.get_session_manager())
        except Exception:
            pass
        logger.info(
            "Authentication initialized (username=%s, openid=%s)",
            admin_username,
            bool(openid_config),
        )
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
            pass  # Device service initialization failed, will continue without it
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
            logger.exception("web_app.create_app: failed to derive LocalUserService")

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
            pass  # User service initialization failed, will continue without it

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
            pass  # Config utils initialization failed, will continue
    except Exception:
        pass  # Service initialization failed, will continue with defaults

    # ========================================================================
    # SECURITY HEADERS MIDDLEWARE
    # ========================================================================

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        # Unified request logging for Admin UI and API without consuming body
        started = None
        _ctx_token = None
        user_email = None
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
            # Identify the authenticated admin user (if any) for downstream logging.
            try:
                sm = web_auth.get_session_manager()
                token = (
                    request.cookies.get("admin_session")
                    if hasattr(request, "cookies")
                    else None
                )
                if sm and token:
                    user_email = sm.validate_session(token)
                    if user_email and hasattr(request, "state"):
                        request.state.user_email = user_email
            except Exception:
                user_email = None
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
            pass  # Context binding failed, request will proceed without context

        response = await call_next(request)

        # Emit completion log with status and duration
        try:
            import time as _t

            dur_ms = int(((_t.time() - started) if started else 0) * 1000)
            # Log with user context: GETs at debug, mutations at info.
            method = getattr(request, "method", "").upper()
            log_payload = {
                "event": "http.user_activity",
                "service": "web",
                "component": "web_app",
                "method": method,
                "path": str(getattr(request.url, "path", "")),
                "status": getattr(response, "status_code", ""),
                "duration_ms": dur_ms,
                "user_email": user_email,
                "correlation_id": (request.headers.get("X-Correlation-ID") or None),
            }
            if method == "GET":
                logger.debug("HTTP GET (user)", extra=log_payload)
            else:
                logger.info("HTTP write (user)", extra=log_payload)
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
            pass  # Response logging failed, will continue

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Content Security Policy: relax for documentation UIs that load assets from CDNs
        p = getattr(request.url, "path", "")

        is_docs = p in (
            "/api/docs",
            "/api/redoc",
            "/docs",
            "/redoc",
            "/rapidoc",
            "/api/rapidoc",
        )
        if is_docs:
            # Relax CSP for documentation UIs to allow required CDN assets. Avoid
            # 'unsafe-eval' by default to reduce XSS risk. Some Swagger/Redoc
            # bundles may require eval in certain browsers; if absolutely needed
            # you can opt-in via DOCS_ALLOW_UNSAFE_EVAL=true.
            allow_eval = str(os.getenv("DOCS_ALLOW_UNSAFE_EVAL", "")).lower() in (
                "1",
                "true",
                "yes",
            )
            script_src = (
                "script-src 'self' 'unsafe-inline' "
                + ("'unsafe-eval' " if allow_eval else "")
                + "https://cdn.jsdelivr.net https://unpkg.com; "
            )
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                + script_src
                + "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
                + "img-src 'self' data: https:; connect-src 'self' data:; "
                + "font-src 'self' data: https:; "
                + "media-src 'none'; "
                + "frame-src 'none'; "
                + "object-src 'none'; "
                + "base-uri 'self'; "
                + "form-action 'self';"
            )
        else:
            # Strict CSP for admin UI and API
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self' ws: wss:; "
                "font-src 'self'; "
                "media-src 'none'; "
                "frame-src 'none'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'self';"
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
            pass  # Server header already removed or not present

        try:
            if _ctx_token is not None:
                clear_context(_ctx_token)
        except Exception:
            pass  # Context cleanup failed, will be cleaned up on next request

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
                pass  # Proxy config retrieval failed, will use default
            # Legacy flag under server network
            if proxy_enabled is False:
                try:
                    getter = getattr(config_service, "get_server_network_config", None)
                    if callable(getter):
                        net_cfg = getter() or {}
                        proxy_enabled = bool(net_cfg.get("proxy_enabled", False))
                except Exception:
                    pass  # Network config retrieval failed, will use default
        # Fallback to tacacs_server runtime flag if present
        if proxy_enabled is False and tacacs_server is not None:
            proxy_enabled = bool(getattr(tacacs_server, "proxy_enabled", False))

        # Publish to Jinja2 template globals used by base nav and forms
        try:
            from . import web_admin as _web_admin

            _web_admin.templates.env.globals["proxy_enabled"] = proxy_enabled
            logger.debug("Template global proxy_enabled set to %s", proxy_enabled)
        except Exception:
            pass  # Template global setting failed, will use default
    except Exception:
        pass  # Proxy config initialization failed, will use defaults

    # ========================================================================
    # INCLUDE ROUTERS
    # ========================================================================

    # Admin web UI routes
    app.include_router(web_admin.router)

    # Dedicated User Groups API (CRUD backed by LocalUserGroupService)
    try:
        from tacacs_server.web.api.usergroups import router as user_groups_router

        app.include_router(user_groups_router)
        logger.debug("Included user group API routes under /api/user-groups")
    except Exception as exc:
        logger.error("Failed to include user group API routes: %s", exc)

    # Devices, Device Groups, Users API
    try:
        from tacacs_server.web.api.device_groups import router as device_groups_router
        from tacacs_server.web.api.devices import router as devices_router
        from tacacs_server.web.api.users import router as users_router

        app.include_router(devices_router)
        app.include_router(device_groups_router)
        app.include_router(users_router)
        logger.debug("Included devices and device-groups API routes")
    except Exception as exc:
        logger.error(
            "Failed to include devices/device-groups/users API routes: %s", exc
        )

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

    # Minimal consolidated status/health APIs to replace legacy endpoints
    @app.get("/api/health", tags=["Status & Health"], include_in_schema=True)
    async def api_health():
        try:
            return {"status": "ok"}
        except Exception:
            return JSONResponse({"status": "error"}, status_code=503)

    @app.get("/api/status", tags=["Status & Health"], include_in_schema=True)
    async def api_status():
        try:
            uptime = 0.0
            ver = os.getenv("APP_VERSION", "1.0.0")
            srv = getattr(app.state, "tacacs_server", None)
            if srv and getattr(srv, "start_time", None):
                import time as _t

                uptime = max(0.0, _t.time() - float(getattr(srv, "start_time", 0)))
            return {
                "status": "running",
                "uptime_seconds": uptime,
                "version": ver,
            }
        except Exception:
            return JSONResponse({"status": "error"}, status_code=503)

    @app.get("/api/stats", tags=["Status & Health"], include_in_schema=True)
    async def api_stats():
        try:
            srv = getattr(app.state, "tacacs_server", None)
            backends: list[dict] = []
            if srv and getattr(srv, "auth_backends", None):
                try:
                    for b in srv.auth_backends:
                        backends.append(
                            {
                                "name": getattr(b, "name", b.__class__.__name__),
                                "type": b.__class__.__name__,
                                "available": bool(
                                    getattr(b, "is_available", lambda: False)()
                                ),
                                "stats": getattr(b, "get_stats", lambda: {})(),
                            }
                        )
                except Exception:
                    backends = []
            return {"server": {"running": True}, "backends": backends}
        except Exception:
            return JSONResponse({"detail": "Stats unavailable"}, status_code=500)

    # --------------------------------------------------------------------
    # ADMIN PROTECTION MIDDLEWARE: Require admin session or API token
    # --------------------------------------------------------------------
    @app.middleware("http")
    async def _admin_guard(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/") and path not in ("/api/health", "/api/status"):
            # Allow admin session
            try:
                sm = web_auth.get_session_manager()
                token = request.cookies.get("admin_session")
                if sm and token and sm.validate_session(token):
                    return await call_next(request)
            except Exception as e:
                logger.warning("Admin session validation failed: %s", e)
            # Require API token header
            header_token = request.headers.get("X-API-Token")
            if not header_token:
                auth = request.headers.get("Authorization", "")
                if auth:
                    try:
                        scheme, _, token_part = auth.partition(" ")
                        if scheme.lower() == "bearer" and token_part:
                            header_token = token_part.strip()
                    except Exception as e:
                        logger.warning("Failed to parse Authorization header: %s", e)
                        header_token = None
            # Determine expected token dynamically (supports env changes in tests)
            try:
                from tacacs_server.web.web_auth import get_auth_config as _get_ac

                ac = _get_ac()
                configured = getattr(ac, "api_token", None) if ac else None
            except Exception as e:
                logger.warning("Failed to get configured API token: %s", e)
                configured = None
            expected = configured or os.getenv("API_TOKEN") or ""
            # If no expected token configured, deny by default (tests expect 401)
            if not expected or header_token != expected:
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return await call_next(request)

    # --------------------------------------------------------------------
    # WEBHOOKS ADMIN API (get/set)
    # --------------------------------------------------------------------
    from tacacs_server.utils.webhook import (
        get_webhook_config_dict as _wh_get,
    )
    from tacacs_server.utils.webhook import (
        set_webhook_config as _wh_set,
    )

    @app.get(
        "/api/admin/webhooks-config",
        tags=["Webhooks"],
        include_in_schema=True,
    )
    async def api_get_webhooks_config(_: None = Depends(web_auth.require_admin_or_api)):
        return _wh_get()

    @app.put(
        "/api/admin/webhooks-config",
        tags=["Webhooks"],
        include_in_schema=True,
    )
    async def api_update_webhooks_config(
        payload: dict, _: None = Depends(web_auth.require_admin_or_api)
    ):
        try:
            _wh_set(
                urls=payload.get("urls"),
                headers=payload.get("headers"),
                template=payload.get("template"),
                timeout=payload.get("timeout"),
                threshold_count=payload.get("threshold_count"),
                threshold_window=payload.get("threshold_window"),
            )
            return _wh_get()
        except Exception:
            logger.error("Failed to update webhooks", exc_info=True)
            return JSONResponse(
                {"detail": "Failed to update webhooks"}, status_code=400
            )

    # --------------------------------------------------------------------
    # COMMAND AUTHORIZATION API (rules)
    # --------------------------------------------------------------------
    try:
        from tacacs_server.authorization.command_authorization import (
            router as command_router,
        )

        app.include_router(command_router)
        logger.debug("Included command authorization API routes")
    except Exception as exc:
        logger.error("Failed to include command authorization API routes: %s", exc)

    # Ensure OpenAPI schema generation is bound and UI helpers are available.
    # This makes /openapi.json and /api/docs stable even when custom routers are used.
    try:
        # Bind custom OpenAPI generator
        from typing import Any, cast

        from tacacs_server.web.openapi_config import (
            configure_openapi_ui as _cfg_ui,
        )
        from tacacs_server.web.openapi_config import (
            custom_openapi_schema as _custom_schema,
        )

        def _openapi():
            return _custom_schema(app)

        cast(Any, app).openapi = _openapi
        # Extra UIs at /docs, /redoc, /rapidoc (in addition to /api/docs)
        _cfg_ui(app)
        logger.debug("OpenAPI UI configured and custom schema bound")
    except Exception as exc:
        logger.debug("OpenAPI UI/schema binding skipped: %s", exc)

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

    @app.get("/health", include_in_schema=True, tags=["Status & Health"])
    async def health():
        """Simple health check"""
        return {"status": "ok"}

    @app.get("/ready", include_in_schema=True, tags=["Status & Health"])
    async def readiness():
        """Readiness check"""
        try:
            if tacacs_server and getattr(tacacs_server, "running", False):
                return {"ready": True}
            return JSONResponse(
                {"ready": False, "reason": "server not running"},
                status_code=503,
            )
        except Exception:
            return JSONResponse(
                {"ready": False, "reason": "internal error"},
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
        except Exception:
            return JSONResponse({"detail": "Metrics unavailable"}, status_code=500)

    @app.get("/robots.txt", response_class=PlainTextResponse, include_in_schema=False)
    async def robots():
        """Robots.txt for search engine crawlers."""
        return PlainTextResponse(
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Disallow: /api/admin/\n"
            "Allow: /api/docs\n"
            "Allow: /api/health\n"
            "Allow: /api/status\n"
        )

    # No deprecated/compat routes are exposed; consolidated API only.

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
            pass  # Startup logging failed, will continue
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
            pass  # Backup routes logging failed, will continue

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
            pass  # DB paths logging failed, will continue

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
            pass  # Shutdown logging failed, will continue

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
