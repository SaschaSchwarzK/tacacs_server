"""
Simplified Admin Web Interface
All HTML/browser-based admin routes in one place
"""

import os
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from tacacs_server.auth.local_user_group_service import UNSET
from tacacs_server.utils.logger import get_logger

from .web_auth import get_session_manager, require_admin_session

logger = get_logger(__name__)

# Initialize router
router = APIRouter(prefix="/admin", include_in_schema=False)

# Templates - use absolute path from package root

templates_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


# Register custom Jinja2 filters
def datetimeformat(value, format="%Y-%m-%d %H:%M:%S"):
    """Format a datetime object"""
    if not value:
        return ""
    try:
        return value.strftime(format)
    except Exception:
        return str(value)


def format_bytes(bytes_val):
    """Format bytes to human readable size"""
    if bytes_val in (None, ""):
        return "0 B"
    try:
        bytes_val = int(bytes_val)
        units = ["B", "KB", "MB", "GB", "TB"]
        size = float(bytes_val)
        for unit in units:
            if size < 1024.0 or unit == "TB":
                if unit == "B":
                    return f"{int(size)} {unit}"
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    except Exception:
        return str(bytes_val)


def format_duration(seconds):
    """Format seconds to human readable duration"""
    if seconds in (None, ""):
        return "0s"
    try:
        seconds = int(seconds)
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, secs = divmod(rem, 60)
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        if secs or not parts:
            parts.append(f"{secs}s")
        return " ".join(parts)
    except Exception:
        return str(seconds)


# Register all filters
templates.env.filters["datetimeformat"] = datetimeformat
templates.env.filters["format_bytes"] = format_bytes
templates.env.filters["format_duration"] = format_duration

templates.env.globals["now"] = datetime.now
templates.env.globals["api_disabled"] = not bool(os.getenv("API_TOKEN"))
templates.env.globals["proxy_enabled"] = False  # Will be updated when config loads


# ============================================================================
# BACKUP UI
# ============================================================================


@router.get(
    "/backup",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin_session)],
    name="admin_backup",
)
async def backup_page(request: Request):
    """Backup & Restore UI"""
    return templates.TemplateResponse(
        request,
        "admin/backup/local.html",
        {},
    )


def _redact(data):
    try:
        if isinstance(data, dict):
            redacted_keys = {"password", "pass", "secret", "token", "hash"}
            return {
                k: ("[redacted]" if k.lower() in redacted_keys else _redact(v))
                for k, v in data.items()
            }
        if isinstance(data, list):
            return [_redact(v) for v in data]
    except Exception as exc:
        logger.warning("Redact helper failed: %s", exc)
    return data


def _log_ui(action: str, request: Request, *, details: dict | None = None) -> None:
    details = details or {}
    try:
        logger.info(
            "ui:%s path=%s method=%s accept=%s ct=%s",  # concise always-on
            action,
            getattr(request.url, "path", ""),
            getattr(request, "method", ""),
            request.headers.get("accept", ""),
            request.headers.get("content-type", ""),
        )
        logger.debug(
            "ui:%s details=%s",  # deep dive for troubleshooting
            action,
            _redact(details),
        )
    except Exception as exc:
        logger.warning("UI log hook failed: %s", exc)


# ============================================================================
# LOGIN / LOGOUT
# ============================================================================


@router.get("/login", response_class=HTMLResponse, name="admin_login")
async def login_page(request: Request):
    """Show login form"""
    return templates.TemplateResponse(request, "admin/login.html", {})


@router.post("/login", name="admin_login_post")
async def login(
    request: Request,
    username: str | None = Form(None),
    password: str | None = Form(None),
):
    """Process login via JSON or form submission."""
    session_mgr = get_session_manager()
    initialized_during_request = False
    if not session_mgr:
        # Attempt on-the-fly initialization if credentials are provided
        is_json_ct = request.headers.get("content-type", "").startswith(
            "application/json"
        )
        tmp_user = username
        tmp_pass = password
        if is_json_ct:
            try:
                payload = await request.json()
                tmp_user = (payload.get("username") or "").strip()
                tmp_pass = payload.get("password")
            except Exception:
                # JSON parsing failed, continue with form data
                pass
        if tmp_user and tmp_pass:
            try:
                import bcrypt

                from . import web_auth as _wa

                hashed = bcrypt.hashpw(
                    tmp_pass.encode("utf-8"), bcrypt.gensalt()
                ).decode("utf-8")
                _wa.init_auth(admin_username=tmp_user, admin_password_hash=hashed)
                session_mgr = get_session_manager()
                initialized_during_request = True
            except Exception:
                session_mgr = None
        if not session_mgr:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication not available",
            )

    is_json = request.headers.get("content-type", "").startswith("application/json")
    if is_json:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON")
        username = (payload.get("username") or "").strip()
        password = payload.get("password")

    if not username or not password:
        raise HTTPException(
            status_code=422,
            detail=[
                {
                    "type": "missing",
                    "loc": ["body", "username"],
                    "msg": "Field required",
                    "input": None,
                },
                {
                    "type": "missing",
                    "loc": ["body", "password"],
                    "msg": "Field required",
                    "input": None,
                },
            ],
        )

    try:
        token = session_mgr.create_session(username, password)
    except HTTPException:
        # Retry path:
        # 1) if we just initialised during this request
        # 2) or if the configured password hash is empty (no proper admin configured)
        needs_retry = initialized_during_request
        try:
            cfg_hash = getattr(
                getattr(session_mgr, "config", object()), "admin_password_hash", ""
            )
            if not cfg_hash:
                needs_retry = True
        except Exception:
            # Config hash retrieval failed, continue without retry
            pass
        if needs_retry:
            try:
                token = session_mgr.create_session(username, password)  # retry
            except Exception:
                if is_json:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid username or password",
                    )
                return templates.TemplateResponse(
                    request,
                    "admin/login.html",
                    {"error": "Invalid username or password"},
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
        else:
            if is_json:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username or password",
                )
            return templates.TemplateResponse(
                request,
                "admin/login.html",
                {"error": "Invalid username or password"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

    if is_json:
        from fastapi.responses import JSONResponse

        resp = JSONResponse({"success": True})
        resp.set_cookie(
            "admin_session",
            token,
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="strict",
            max_age=3600,
            path="/",
        )
        return resp

    # Form: redirect to admin
    response = RedirectResponse(url="/admin/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        "admin_session",
        token,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        max_age=3600,  # 1 hour
        path="/",
    )
    return response


@router.post("/logout", name="admin_logout")
async def logout(request: Request):
    """Process logout"""
    session_mgr = get_session_manager()
    if session_mgr:
        token = request.cookies.get("admin_session")
        if token:
            session_mgr.delete_session(token)

    response = RedirectResponse(
        url="/admin/login", status_code=status.HTTP_303_SEE_OTHER
    )
    response.delete_cookie("admin_session")
    return response


# ============================================================================
# DASHBOARD
# ============================================================================


@router.get(
    "/",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin_session)],
    name="admin_home",
)
@router.get(
    "",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin_session)],
    name="admin_home_slash",
)
async def dashboard(request: Request):
    """Admin dashboard - main landing page"""

    # Get services from app state
    device_service = request.app.state.device_service
    user_service = request.app.state.user_service
    user_group_service = request.app.state.user_group_service
    tacacs_server = request.app.state.tacacs_server

    # Initialize summary with safe defaults
    summary = {
        "devices": 0,
        "device_groups": 0,
        "users": 0,
        "user_groups": 0,
    }

    # Get counts from services (safe with try/except)
    try:
        if device_service:
            summary["devices"] = len(device_service.list_devices())
            summary["device_groups"] = len(device_service.list_groups())
    except Exception as e:
        logger.warning(f"Failed to get device counts: {e}")

    try:
        if user_service:
            summary["users"] = len(user_service.list_users())
    except Exception as e:
        logger.warning(f"Failed to get user count: {e}")

    try:
        if user_group_service:
            summary["user_groups"] = len(user_group_service.list_groups())
    except Exception as e:
        logger.warning(f"Failed to get user group count: {e}")

    # Get TACACS stats
    auth_summary = {"total": 0, "success": 0, "failure": 0, "success_percent": 0}
    author_summary = {"total": 0, "success": 0, "failure": 0, "success_percent": 0}
    acct_summary = {"total": 0, "success": 0, "failure": 0, "success_percent": 0}
    system_summary = {
        "uptime": "0s",
        "connections": {"active": 0, "total": 0},
        "cpu_percent": 0,
        "memory_percent": 0,
        "memory_human": "0 B / 0 B",
    }

    try:
        if tacacs_server:
            stats = (
                tacacs_server.get_stats() if hasattr(tacacs_server, "get_stats") else {}
            )

            # Auth stats
            auth_total = stats.get("auth_requests", 0)
            auth_success = stats.get("auth_success", 0)
            auth_failure = stats.get("auth_failures", 0)
            auth_summary = {
                "total": auth_total,
                "success": auth_success,
                "failure": auth_failure,
                "success_percent": round(
                    (auth_success / auth_total * 100) if auth_total else 0, 1
                ),
            }

            # Author stats
            author_total = stats.get("author_requests", 0)
            author_success = stats.get("author_success", 0)
            author_failure = stats.get("author_failures", 0)
            author_summary = {
                "total": author_total,
                "success": author_success,
                "failure": author_failure,
                "success_percent": round(
                    (author_success / author_total * 100) if author_total else 0, 1
                ),
            }

            # Acct stats
            acct_total = stats.get("acct_requests", 0)
            acct_success = stats.get("acct_success", 0)
            acct_failure = stats.get("acct_failures", 0)
            acct_summary = {
                "total": acct_total,
                "success": acct_success,
                "failure": acct_failure,
                "success_percent": round(
                    (acct_success / acct_total * 100) if acct_total else 0, 1
                ),
            }

            # System stats
            uptime_seconds = getattr(tacacs_server, "start_time", None)
            if uptime_seconds:
                import time

                uptime_seconds = time.time() - uptime_seconds
                uptime_str = format_duration(uptime_seconds)
            else:
                uptime_str = "0s"

            # Get memory and CPU
            cpu_percent = 0
            memory_percent = 0
            memory_human = "0 B / 0 B"

            try:
                import psutil

                cpu_percent = psutil.cpu_percent(interval=0.1)
                mem = psutil.virtual_memory()
                memory_percent = mem.percent
                memory_human = f"{format_bytes(mem.used)} / {format_bytes(mem.total)}"
            except Exception:
                # Memory stats retrieval failed, use defaults
                pass

            system_summary = {
                "uptime": uptime_str,
                "connections": {
                    "active": stats.get("connections_active", 0),
                    "total": stats.get("connections_total", 0),
                },
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "memory_human": memory_human,
            }
    except Exception as e:
        logger.warning(f"Failed to get TACACS stats: {e}")

    # Build backend summaries (at least show 'local' when present)
    backend_summaries = []
    try:
        backends = []
        if tacacs_server and hasattr(tacacs_server, "auth_backends"):
            backends = list(getattr(tacacs_server, "auth_backends", []) or [])
        # Fallback: derive from config if server not set
        if not backends:
            try:
                cfg = request.app.state.config_service
                if cfg and hasattr(cfg, "get_auth_backends"):
                    names = cfg.get_auth_backends() or []
                    # Build simple stubs with name only
                    backends = [{"name": n} for n in names]
            except Exception:
                backends = []
        for be in backends:
            try:
                name = getattr(be, "name", None) or (
                    be.get("name") if isinstance(be, dict) else str(be)
                )
                available = True
                try:
                    if hasattr(be, "is_available") and callable(
                        getattr(be, "is_available")
                    ):
                        available = bool(getattr(be, "is_available")())
                except Exception:
                    available = True
                backend_summaries.append({"name": str(name), "status": available})
            except Exception:
                continue
    except Exception:
        backend_summaries = []

    # Sample devices, groups, users for quick glance
    device_samples: list[dict] = []
    group_samples: list[dict] = []
    user_samples: list[dict] = []
    try:
        if device_service and hasattr(device_service, "list_devices"):
            devs = device_service.list_devices()
            for d in devs[:5] if isinstance(devs, list) else []:
                try:
                    device_samples.append(
                        {
                            "name": getattr(d, "display_name", getattr(d, "name", "")),
                            "network": str(getattr(d, "network", "")),
                            "group": getattr(getattr(d, "group", None), "name", None),
                            "has_tacacs_secret": bool(
                                getattr(
                                    getattr(d, "group", None), "tacacs_secret", None
                                )
                            ),
                            "has_radius_secret": bool(
                                getattr(
                                    getattr(d, "group", None), "radius_secret", None
                                )
                            ),
                        }
                    )
                except Exception:
                    continue
    except Exception as e:
        logger.warning(f"Failed to list device samples: {e}")

    try:
        if device_service and hasattr(device_service, "list_groups"):
            grps = device_service.list_groups()
            for g in grps[:5] if isinstance(grps, list) else []:
                try:
                    allowed = getattr(g, "allowed_user_groups", []) or []
                    group_samples.append(
                        {
                            "name": getattr(g, "name", ""),
                            "allowed_user_groups": ", ".join(allowed)
                            if isinstance(allowed, list)
                            else str(allowed),
                            "tacacs_secret": bool(getattr(g, "tacacs_secret", None)),
                            "radius_secret": bool(getattr(g, "radius_secret", None)),
                        }
                    )
                except Exception:
                    continue
    except Exception as e:
        logger.warning(f"Failed to list group samples: {e}")

    try:
        if user_service and hasattr(user_service, "list_users"):
            users = user_service.list_users()
            for u in users[:5] if isinstance(users, list) else []:
                try:
                    user_samples.append(
                        {
                            "username": getattr(u, "username", ""),
                            "privilege_level": getattr(u, "privilege_level", 1),
                            "enabled": bool(getattr(u, "enabled", True)),
                            "groups": ", ".join(getattr(u, "groups", []) or []),
                        }
                    )
                except Exception:
                    continue
    except Exception as e:
        logger.warning(f"Failed to list user samples: {e}")

    return templates.TemplateResponse(
        request,
        "admin/dashboard.html",
        {
            "summary": summary,
            "auth_summary": auth_summary,
            "author_summary": author_summary,
            "acct_summary": acct_summary,
            "system_summary": system_summary,
            "tacacs_summary": {
                "auth": auth_summary,
                "author": author_summary,
                "acct": acct_summary,
            },
            "backend_summaries": backend_summaries,
            "device_samples": device_samples,
            "group_samples": group_samples,
            "user_samples": user_samples,
        },
    )


# ============================================================================
# DEVICES
# ============================================================================


@router.get(
    "/devices",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin_session)],
    name="admin_devices",
)
async def devices_page(request: Request, search: str | None = None):
    """List all devices"""
    _log_ui("devices_page", request, details={"search": search})
    device_service = request.app.state.device_service

    devices = []
    group_options = []

    try:
        if device_service:
            all_devices = device_service.list_devices()

            # Apply search filter
            if search:
                search_lower = search.lower()
                all_devices = [
                    d
                    for d in all_devices
                    if search_lower in d.name.lower()
                    or search_lower in str(d.network).lower()
                ]

            devices = [
                {
                    "id": d.id,
                    "name": d.name,
                    "network": str(d.network),
                    "group": d.group.name if d.group else None,
                }
                for d in all_devices
            ]

            # Get group options for dropdown
            group_options = [g.name for g in device_service.list_groups()]
    except Exception as e:
        logger.warning(f"Failed to get devices: {e}")

    return templates.TemplateResponse(
        request,
        "admin/devices.html",
        {
            "devices": devices,
            "search": search or "",
            "group_options": group_options,
            "total_devices": len(devices),
        },
    )


@router.post(
    "/devices",
    dependencies=[Depends(require_admin_session)],
    name="admin_devices_create",
)
async def create_device(request: Request):
    """Create new device (JSON or form)."""
    _log_ui("device_create", request)
    device_service = request.app.state.device_service
    if not device_service:
        raise HTTPException(status_code=503, detail="Device service unavailable")
    is_json = request.headers.get("content-type", "").startswith("application/json")
    try:
        if is_json:
            data = await request.json()
            name = (data.get("name") or "").strip()
            network = (data.get("network") or "").strip()
            group = data.get("group") or None
        else:
            form = await request.form()
            name = str(form.get("name", "")).strip()
            network = str(form.get("network", "")).strip()
            group = str(form.get("group") or "") or None
        if not name or not network:
            raise HTTPException(status_code=400, detail="name and network are required")
        rec = device_service.create_device(name=name, network=network, group=group)
        logger.info(
            "web_admin.create_device: id=%s name=%s", getattr(rec, "id", None), name
        )
        if "application/json" in request.headers.get("accept", ""):
            from fastapi.responses import JSONResponse

            return JSONResponse(
                {"id": getattr(rec, "id", None)}, status_code=status.HTTP_201_CREATED
            )
        return RedirectResponse(
            url="/admin/devices", status_code=status.HTTP_303_SEE_OTHER
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Bad request")


@router.delete(
    "/devices/{device_id}",
    dependencies=[Depends(require_admin_session)],
    name="admin_devices_delete",
)
async def delete_device(request: Request, device_id: int):
    _log_ui("device_delete", request, details={"device_id": device_id})
    device_service = request.app.state.device_service
    if not device_service:
        raise HTTPException(status_code=503, detail="Device service unavailable")
    try:
        device_service.delete_device(device_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except Exception:
        raise HTTPException(status_code=400, detail="Bad request")


@router.get("/devices/{device_id}", dependencies=[Depends(require_admin_session)])
async def get_device(request: Request, device_id: int):
    _log_ui("device_get", request, details={"device_id": device_id})
    device_service = request.app.state.device_service
    if not device_service:
        raise HTTPException(status_code=503, detail="Device service unavailable")
    try:
        rec = device_service.get_device(device_id)
        return {
            "id": rec.id,
            "name": rec.name,
            "network": str(rec.network),
            "group": rec.group.name if rec.group else None,
        }
    except Exception:
        raise HTTPException(status_code=404, detail="Not found")


@router.put("/devices/{device_id}", dependencies=[Depends(require_admin_session)])
async def update_device(request: Request, device_id: int):
    _log_ui("device_update", request, details={"device_id": device_id})
    device_service = request.app.state.device_service
    if not device_service:
        raise HTTPException(status_code=503, detail="Device service unavailable")
    data = await request.json()
    try:
        rec = device_service.update_device(
            device_id,
            name=data.get("name"),
            network=data.get("network"),
            group=data.get("group"),
            clear_group=(data.get("group") is None and "group" in data),
        )
        return {"id": rec.id}
    except Exception:
        raise HTTPException(status_code=400, detail="Bad request")


# ============================================================================
# DEVICE GROUPS
# ============================================================================


@router.get(
    "/groups",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin_session)],
    name="admin_groups",
)
async def groups_page(request: Request):
    """List all device groups"""
    _log_ui("groups_page", request)
    device_service = request.app.state.device_service
    user_group_service = request.app.state.user_group_service

    groups = []
    proxies = []
    user_group_options: list[str] = []
    proxy_enabled = False

    try:
        if device_service:
            all_groups = device_service.list_groups()
            groups = [
                {
                    "id": g.id,
                    "name": g.name,
                    "description": g.description or "",
                    "tacacs_secret": bool(getattr(g, "tacacs_secret", None)),
                    "radius_secret": bool(getattr(g, "radius_secret", None)),
                    "allowed_user_groups": getattr(g, "allowed_user_groups", []),
                    "proxy_network": getattr(g, "proxy_network", None),
                }
                for g in all_groups
            ]
            # Proxies for select (may be empty even when feature is enabled)
            try:
                proxies = [
                    {"id": p.id, "name": p.name, "network": str(p.network)}
                    for p in device_service.list_proxies()
                ]
            except Exception:
                proxies = []
    except Exception:
        logger.warning("Failed to get groups")

    # Determine feature flag for template rendering (menu + form field)
    try:
        # Prefer template global set during app creation
        proxy_enabled = bool(templates.env.globals.get("proxy_enabled", False))
        if proxy_enabled is False:
            # Fallback to config/tacacs_server state if global not initialized
            cfg = getattr(request.app.state, "config_service", None)
            if cfg is not None:
                try:
                    getter = getattr(cfg, "get_proxy_protocol_config", None)
                    if callable(getter):
                        pxy = getter() or {}
                        proxy_enabled = bool(pxy.get("enabled", proxy_enabled))
                except Exception:
                    # Proxy config retrieval failed, continue with default
                    pass
                if proxy_enabled is False:
                    try:
                        getter = getattr(cfg, "get_server_network_config", None)
                        if callable(getter):
                            net_cfg = getter() or {}
                            proxy_enabled = bool(net_cfg.get("proxy_enabled", False))
                    except Exception:
                        # Network config retrieval failed, continue with default
                        pass
        if proxy_enabled is False:
            ts = getattr(request.app.state, "tacacs_server", None)
            proxy_enabled = bool(getattr(ts, "proxy_enabled", False)) if ts else False
    except Exception:
        proxy_enabled = False

    try:
        if user_group_service:
            user_group_options = [g.name for g in user_group_service.list_groups()]
    except Exception as e:
        logger.warning(f"Failed to get user groups for group form: {e}")

    logger.warning(
        "groups_page: groups=%s proxies=%s user_group_options=%s",
        len(groups),
        len(proxies),
        len(user_group_options),
    )

    return templates.TemplateResponse(
        request,
        "admin/groups.html",
        {
            "groups": groups,
            "proxies": proxies,
            "user_group_options": user_group_options,
            "proxy_enabled": proxy_enabled,
        },
    )


# ============================================================================
# PROXIES
# ============================================================================


@router.get(
    "/proxies",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin_session)],
    name="admin_proxies",
)
async def proxies_page(request: Request):
    """List and manage proxies"""
    _log_ui("proxies_page", request)
    device_service = request.app.state.device_service
    proxies = []
    try:
        if device_service:
            items = device_service.list_proxies()
            proxies = [
                {
                    "id": p.id,
                    "name": p.name,
                    "network": str(p.network),
                    "metadata": getattr(p, "metadata", {}) or {},
                }
                for p in items
            ]
    except Exception as e:
        logger.warning(f"Failed to get proxies: {e}")

    return templates.TemplateResponse(
        request,
        "admin/proxies.html",
        {"proxies": proxies, "proxy_enabled": True},
    )


@router.post(
    "/groups", dependencies=[Depends(require_admin_session)], name="admin_groups_create"
)
async def create_group(request: Request):
    _log_ui("group_create", request)
    device_service = request.app.state.device_service
    if not device_service:
        raise HTTPException(status_code=503, detail="Device service unavailable")
    is_json = request.headers.get("content-type", "").startswith("application/json")
    try:
        if is_json:
            data = await request.json()
        else:
            form = await request.form()
            data = {
                k: (str(form.get(k)) if form.get(k) is not None else None)
                for k in ["name", "description", "radius_secret", "tacacs_secret"]
            }
            if "proxy_id" in form:
                raw_proxy = form.get("proxy_id")
                data["proxy_id"] = int(str(raw_proxy)) if raw_proxy else None
        rec = device_service.create_device_group(
            name=data.get("name", ""),
            description=data.get("description"),
            tacacs_secret=data.get("tacacs_secret"),
            radius_secret=data.get("radius_secret"),
            allowed_user_groups=data.get("allowed_user_groups"),
            proxy_id=data.get("proxy_id"),
        )
        logger.info("web_admin.create_group: name=%s", rec.get("name"))
        if "application/json" in request.headers.get("accept", ""):
            from fastapi.responses import JSONResponse

            return JSONResponse(rec, status_code=status.HTTP_201_CREATED)
        return RedirectResponse(
            url="/admin/groups", status_code=status.HTTP_303_SEE_OTHER
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Bad request")


@router.get("/groups/{group_id}", dependencies=[Depends(require_admin_session)])
async def get_group(request: Request, group_id: int):
    _log_ui("group_get", request, details={"group_id": group_id})
    device_service = request.app.state.device_service
    if not device_service:
        raise HTTPException(status_code=503, detail="Device service unavailable")
    try:
        group = device_service.get_group(group_id)
        return {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "proxy_network": getattr(group, "proxy_network", None),
            "radius_secret": getattr(group, "radius_secret", None),
            "tacacs_secret": getattr(group, "tacacs_secret", None),
            "device_config": getattr(group, "device_config", {}),
            "metadata": group.metadata,
            "allowed_user_groups": getattr(group, "allowed_user_groups", []),
        }
    except Exception:
        raise HTTPException(status_code=404, detail="Not found")


@router.put("/groups/{group_id}", dependencies=[Depends(require_admin_session)])
async def update_group(request: Request, group_id: int):
    _log_ui("group_update", request, details={"group_id": group_id})
    device_service = request.app.state.device_service
    if not device_service:
        raise HTTPException(status_code=503, detail="Device service unavailable")
    data = await request.json()
    try:
        updated = device_service.update_device_group(
            group_id,
            name=data.get("name"),
            description=data.get("description"),
            tacacs_secret=data.get("tacacs_secret"),
            radius_secret=data.get("radius_secret"),
            allowed_user_groups=data.get("allowed_user_groups"),
            proxy_id=data.get("proxy_id"),
        )
        return updated
    except Exception:
        raise HTTPException(status_code=400, detail="Bad request")


@router.delete("/groups/{group_id}", dependencies=[Depends(require_admin_session)])
async def delete_group(request: Request, group_id: int):
    _log_ui("group_delete", request, details={"group_id": group_id})
    device_service = request.app.state.device_service
    if not device_service:
        raise HTTPException(status_code=503, detail="Device service unavailable")
    try:
        device_service.delete_group(group_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except Exception:
        raise HTTPException(status_code=400, detail="Bad request")


# ============================================================================
# USERS
# ============================================================================


@router.get(
    "/users",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin_session)],
    name="admin_users",
)
async def users_page(request: Request):
    """List all users"""
    _log_ui("users_page", request)
    user_service = request.app.state.user_service
    user_group_service = request.app.state.user_group_service

    users = []
    group_options = []

    try:
        if user_service:
            all_users = user_service.list_users()
            users = [
                {
                    "username": u.username,
                    "privilege_level": u.privilege_level,
                    "enabled": u.enabled,
                    "groups": u.groups or [],
                    "description": getattr(u, "description", ""),
                }
                for u in all_users
            ]
    except Exception as e:
        logger.warning(f"Failed to get users: {e}")

    try:
        if user_group_service:
            group_options = [g.name for g in user_group_service.list_groups()]
    except Exception as e:
        logger.warning(f"Failed to get user groups: {e}")

    # Serve JSON when explicitly requested for UI tests and script usage
    accept = request.headers.get("accept", "")
    if "application/json" in accept or request.query_params.get("format") == "json":
        from fastapi.responses import JSONResponse

        return JSONResponse(
            {"users": users, "total": len(users)}, status_code=status.HTTP_200_OK
        )

    return templates.TemplateResponse(
        request,
        "admin/users.html",
        {
            "users": users,
            "group_options": group_options,
            "total_users": len(users),
        },
    )


@router.post(
    "/users", dependencies=[Depends(require_admin_session)], name="admin_users_create"
)
async def create_user(request: Request):
    """Create new user via JSON or form submission.

    - For `Accept: application/json`, returns JSON with 201 on success.
    - Otherwise redirects back to /admin/users.
    """
    user_service = getattr(request.app.state, "user_service", None)
    if not user_service:
        # Fallback: try to pull from tacacs_server instance if available
        ts = getattr(request.app.state, "tacacs_server", None)
        user_service = getattr(ts, "local_user_service", None) if ts else None
    if not user_service:
        # Final fallback: legacy global accessor used by API modules
        try:
            from tacacs_server.web.web import (
                get_local_user_service as _legacy_get_user_service,
            )

            user_service = _legacy_get_user_service()
        except Exception:
            user_service = None
    if not user_service:
        logger.warning(
            "admin_users_create: user service unavailable (no app.state or server/global fallback)"
        )
        raise HTTPException(status_code=503, detail="User service unavailable")

    is_json = request.headers.get("content-type", "").startswith("application/json")
    accept = request.headers.get("accept", "")

    try:
        if is_json:
            payload = await request.json()
            username = (payload.get("username") or "").strip()
            password = payload.get("password")
            privilege_level = int(payload.get("privilege_level", 1))
            enabled = bool(payload.get("enabled", True))
            groups = payload.get("groups")
            description = payload.get("description")
        else:
            form = await request.form()
            username = str(form.get("username", "")).strip()
            password = str(form.get("password", "")) or None
            try:
                raw_priv = form.get("privilege_level", 1)
                privilege_level = int(str(raw_priv)) if raw_priv is not None else 1
            except Exception:
                privilege_level = 1
            enabled = str(form.get("enabled", "true")).lower() == "true"
            groups = None
            description = str(form.get("description", "")) or None

        if not username:
            raise HTTPException(status_code=400, detail="username is required")
        if not password:
            raise HTTPException(status_code=400, detail="password is required")

        _log_ui(
            "user_create",
            request,
            details={
                "username": username,
                "privilege_level": privilege_level,
                "enabled": enabled,
                "has_groups": bool(groups),
            },
        )
        logger.info(
            "web_admin.create_user: user=%s lvl=%s enabled=%s has_groups=%s",
            username,
            privilege_level,
            enabled,
            bool(groups),
        )

        record = user_service.create_user(
            username=username,
            password=password,
            privilege_level=privilege_level,
            service="exec",
            groups=groups,
            enabled=enabled,
            description=description,
        )

        if "application/json" in accept:
            from fastapi.responses import JSONResponse

            return JSONResponse(
                {"username": record.username}, status_code=status.HTTP_201_CREATED
            )
        return RedirectResponse(
            url="/admin/users", status_code=status.HTTP_303_SEE_OTHER
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Failed to create user: {e}")
        raise HTTPException(status_code=400, detail="Bad request")


@router.get("/users/{username}", dependencies=[Depends(require_admin_session)])
async def get_user(request: Request, username: str):
    _log_ui("user_get", request, details={"username": username})
    user_service = request.app.state.user_service
    if not user_service:
        raise HTTPException(status_code=503, detail="User service unavailable")
    try:
        rec = user_service.get_user(username)
        return {
            "username": rec.username,
            "privilege_level": rec.privilege_level,
            "service": rec.service,
            "groups": rec.groups,
            "enabled": rec.enabled,
            "description": getattr(rec, "description", ""),
        }
    except Exception:
        raise HTTPException(status_code=404, detail="Not found")


@router.put("/users/{username}", dependencies=[Depends(require_admin_session)])
async def update_user(request: Request, username: str):
    _log_ui("user_update", request, details={"username": username})
    user_service = request.app.state.user_service
    if not user_service:
        raise HTTPException(status_code=503, detail="User service unavailable")
    data = await request.json()
    try:
        rec = user_service.update_user(
            username,
            privilege_level=data.get("privilege_level"),
            service=data.get("service"),
            groups=data.get("groups"),
            enabled=data.get("enabled"),
            description=data.get("description"),
        )
        return {"username": rec.username}
    except Exception:
        raise HTTPException(status_code=400, detail="Bad request")


@router.post(
    "/users/{username}/password", dependencies=[Depends(require_admin_session)]
)
async def set_user_password(request: Request, username: str):
    _log_ui("user_set_password", request, details={"username": username})
    user_service = request.app.state.user_service
    if not user_service:
        raise HTTPException(status_code=503, detail="User service unavailable")
    data = await request.json()
    try:
        password = data.get("password")
        if not password:
            raise HTTPException(status_code=400, detail="Password is required")
        store_hash = data.get("store_hash", True)
        rec = user_service.set_password(username, password, store_hash=store_hash)
        return {"username": rec.username}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Bad request")


@router.delete("/users/{username}", dependencies=[Depends(require_admin_session)])
async def delete_user(request: Request, username: str):
    user_service = request.app.state.user_service
    if not user_service:
        raise HTTPException(status_code=503, detail="User service unavailable")
    try:
        user_service.delete_user(username)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except Exception:
        raise HTTPException(status_code=400, detail="Bad request")


# ============================================================================
# USER GROUPS
# ============================================================================


@router.get(
    "/user-groups",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin_session)],
    name="admin_user_groups",
)
async def user_groups_page(request: Request):
    """List all user groups"""
    _log_ui("user_groups_page", request)
    svc = request.app.state.user_group_service
    groups = []
    try:
        if svc:
            records = svc.list_groups()
            groups = [
                {
                    "name": r.name,
                    "description": r.description,
                    "metadata": r.metadata,
                    "ldap_group": r.ldap_group,
                    "okta_group": r.okta_group,
                    "privilege_level": r.privilege_level,
                }
                for r in records
            ]
    except Exception as e:
        logger.warning(f"Failed to get user groups for page: {e}")

    logger.warning("user_groups_page: count=%s", len(groups))

    return templates.TemplateResponse(
        request,
        "admin/user_groups.html",
        {"groups": groups},
    )


# User group CRUD to support UI actions
@router.post(
    "/user-groups",
    dependencies=[Depends(require_admin_session)],
    name="admin_user_groups_create",
)
async def create_user_group(request: Request):
    _log_ui("user_group_create", request)
    svc = request.app.state.user_group_service
    if not svc:
        raise HTTPException(status_code=503, detail="User group service unavailable")
    data = await request.json()
    try:
        rec = svc.create_group(
            data.get("name", ""),
            description=data.get("description"),
            metadata=data.get("metadata"),
            ldap_group=data.get("ldap_group"),
            okta_group=data.get("okta_group"),
            privilege_level=int(data.get("privilege_level", 1)),
        )
        from fastapi.responses import JSONResponse

        return JSONResponse({"name": rec.name}, status_code=status.HTTP_201_CREATED)
    except Exception:
        raise HTTPException(status_code=400, detail="Bad request")


@router.get("/user-groups/{name}", dependencies=[Depends(require_admin_session)])
async def get_user_group(request: Request, name: str):
    _log_ui("user_group_get", request, details={"name": name})
    svc = request.app.state.user_group_service
    if not svc:
        raise HTTPException(status_code=503, detail="User group service unavailable")
    try:
        rec = svc.get_group(name)
        return {
            "name": rec.name,
            "description": rec.description,
            "metadata": rec.metadata,
            "ldap_group": rec.ldap_group,
            "okta_group": rec.okta_group,
            "privilege_level": rec.privilege_level,
        }
    except Exception:
        raise HTTPException(status_code=404, detail="Not found")


@router.put("/user-groups/{name}", dependencies=[Depends(require_admin_session)])
async def update_user_group(request: Request, name: str):
    _log_ui("user_group_update", request, details={"name": name})
    svc = request.app.state.user_group_service
    if not svc:
        raise HTTPException(status_code=503, detail="User group service unavailable")
    data = await request.json()
    try:
        rec = svc.update_group(
            name,
            description=data.get("description"),
            metadata=data.get("metadata"),
            ldap_group=data.get("ldap_group") if "ldap_group" in data else UNSET,
            okta_group=data.get("okta_group") if "okta_group" in data else UNSET,
            privilege_level=int(data.get("privilege_level"))
            if "privilege_level" in data
            else None,
        )
        return {"name": rec.name}
    except Exception:
        raise HTTPException(status_code=400, detail="Bad request")


@router.delete("/user-groups/{name}", dependencies=[Depends(require_admin_session)])
async def delete_user_group(request: Request, name: str):
    _log_ui("user_group_delete", request, details={"name": name})
    svc = request.app.state.user_group_service
    if not svc:
        raise HTTPException(status_code=503, detail="User group service unavailable")
    try:
        svc.delete_group(name)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except Exception:
        raise HTTPException(status_code=400, detail="Bad request")


# ============================================================================
# CONFIG
# ============================================================================


@router.get(
    "/config",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin_session)],
    name="admin_config",
)
async def config_page(request: Request):
    """View configuration"""
    config_service = request.app.state.config_service

    config_data = {}
    server_section = {}
    proxy_protocol_section = {}
    configuration = {}
    devices_section = {}
    config_source = "Not available"
    config_json = ""

    try:
        if config_service and hasattr(config_service, "get_config_summary"):
            config_data = config_service.get_config_summary()
            server_section = config_data.get("server", {})
            proxy_protocol_section = config_data.get("proxy_protocol", {})
            devices_section = config_data.get("devices", {})

            # Build configuration dict for template
            configuration = {
                "radius": config_data.get("radius", {}),
                "monitoring": config_service.get_monitoring_config()
                if hasattr(config_service, "get_monitoring_config")
                else {},
                "auth": config_data.get("auth", {}),
                "ldap": config_data.get("ldap", {}),
                "okta": config_data.get("okta", {}),
            }

            config_source = getattr(
                config_service,
                "config_source",
                getattr(config_service, "config_file", "config/tacacs.conf"),
            )

            # Format config as JSON for display
            import json

            config_json = json.dumps(config_data, indent=2)

            # Detect configuration drift specifically for restart-sensitive settings
            pending_restart = False
            drift_summary: dict[str, dict[str, tuple[object, object]]] = {}
            try:
                if hasattr(config_service, "detect_config_drift"):
                    drift = config_service.detect_config_drift() or {}
                    drift_summary = drift
                    # Keys that require a service restart to fully apply
                    restart_sensitive: set[tuple[str, str]] = {
                        ("server", "host"),
                        ("server", "port"),
                        ("auth", "backends"),
                        ("auth", "local_auth_db"),
                        ("devices", "database"),
                        ("radius", "enabled"),
                        ("database", "accounting_db"),
                        ("database", "metrics_history_db"),
                        ("database", "audit_trail_db"),
                        ("proxy_protocol", "enabled"),
                    }
                    # If any restart-sensitive key has drift, suggest restart
                    for section, keys in drift.items():
                        for key in keys.keys():
                            if (str(section), str(key)) in restart_sensitive:
                                pending_restart = True
                                break
                        if pending_restart:
                            break
            except Exception:
                pending_restart = False
    except Exception as e:
        logger.warning(f"Failed to get config: {e}")

    return templates.TemplateResponse(
        request,
        "admin/config.html",
        {
            "config": config_data,
            "server_section": server_section,
            "proxy_protocol_section": proxy_protocol_section,
            "devices_section": devices_section,
            "configuration": configuration,
            "config_source": config_source,
            "config_json": config_json,
            "pending_restart": locals().get("pending_restart", False),
            "drift_summary": locals().get("drift_summary", {}),
        },
    )


@router.put("/config", dependencies=[Depends(require_admin_session)])
async def update_config(request: Request):
    """Update configuration sections"""
    config_service = request.app.state.config_service

    if not config_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configuration service not available",
        )

    try:
        data = await request.json()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid JSON: {e}"
        )

    results = {}
    errors = {}

    # Process each section
    for section, updates in data.items():
        if not updates or not isinstance(updates, dict):
            continue

        update_method = getattr(config_service, f"update_{section}_config", None)
        if not update_method:
            errors[section] = f"Section {section} not updatable"
            continue

        try:
            update_method(**updates)
            results[section] = "success"
        except Exception as e:
            logger.exception(f"Failed to update {section}: {e}")
            errors[section] = "invalid"

    if errors:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Errors updating configuration: {errors}",
        )

    return {"success": True, "results": results}


# ============================================================================
# WEBHOOKS
# ============================================================================


@router.get(
    "/webhooks",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin_session)],
    name="admin_webhooks",
)
async def webhooks_page(request: Request):
    """Configure webhooks"""
    # Get webhook config
    config = {
        "urls": [],
        "headers": {},
        "template": {},
        "timeout": 5.0,
        "threshold_count": 0,
        "threshold_window": 60,
    }

    try:
        from tacacs_server.utils.webhook import get_webhook_config_dict

        config = get_webhook_config_dict()
    except Exception as e:
        logger.warning(f"Failed to get webhook config: {e}")

    return templates.TemplateResponse(
        request,
        "admin/webhooks.html",
        {"config": config},
    )


# ============================================================================
# COMMAND AUTHORIZATION
# ============================================================================


@router.get(
    "/command-authorization",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin_session)],
    name="admin_command_authorization",
)
async def command_auth_page(request: Request):
    """Configure command authorization"""
    return templates.TemplateResponse(
        request,
        "admin/command_auth.html",
        {},
    )


# ============================================================================
# AUDIT
# ============================================================================


@router.get(
    "/audit",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin_session)],
    name="admin_audit",
)
async def audit_page(request: Request):
    """View audit logs"""
    # TODO: Get audit logs from service
    logs: list[dict] = []

    return templates.TemplateResponse(
        request,
        "admin/audit.html",
        {"logs": logs},
    )


# ============================================================================
# SERVER CONTROL
# ============================================================================


@router.post("/server/reload", dependencies=[Depends(require_admin_session)])
async def reload_config():
    """Reload server configuration"""
    # TODO: Trigger reload
    logger.info("Config reload requested")
    return {"success": True, "message": "Configuration reloaded"}


@router.post("/server/restart", dependencies=[Depends(require_admin_session)])
async def restart_services_api():
    """Restart TACACS/RADIUS services and reopen DB connections."""
    try:
        from tacacs_server.utils.maintenance import restart_services as _restart

        _restart()
        return {"success": True, "message": "Services restarted"}
    except Exception as e:
        logger.exception("Restart failed: %s", e)
        return {"success": False, "message": "Restart failed"}


@router.post("/server/reset-stats", dependencies=[Depends(require_admin_session)])
async def reset_stats():
    """Reset server statistics"""
    # TODO: Trigger reset
    logger.info("Stats reset requested")
    return {"success": True, "message": "Statistics reset"}


@router.get("/server/logs", dependencies=[Depends(require_admin_session)])
async def get_logs(lines: int = 100):
    """Get recent log lines"""
    # TODO: Read log file
    return {"logs": [], "count": 0}
