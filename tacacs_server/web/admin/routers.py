"""Admin router skeleton for device management."""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any

import psutil
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from tacacs_server.auth.local_user_group_service import (
    LocalUserGroupExists,
    LocalUserGroupNotFound,
    LocalUserGroupService,
    LocalUserGroupValidationError,
)
from tacacs_server.auth.local_user_service import (
    LocalUserExists,
    LocalUserNotFound,
    LocalUserService,
    LocalUserValidationError,
)
from tacacs_server.devices.service import (
    UNSET,
    DeviceNotFound,
    DeviceService,
    DeviceValidationError,
    GroupNotFound,
)
from tacacs_server.utils.audit_logger import get_audit_logger
from tacacs_server.utils.exceptions import ValidationError
from tacacs_server.utils.validation import (
    FormValidator,
    InputValidator,
)

from ...utils.webhook import get_webhook_config_dict, set_webhook_config
from ..monitoring import (
    get_admin_auth_dependency_func,
    get_admin_session_manager,
    logger,  # reuse monitoring logger for now
)
from ..monitoring import (
    get_config as monitoring_get_config,
)
from ..monitoring import (
    get_device_service as monitoring_get_device_service,
)
from ..monitoring import (
    get_local_user_group_service as monitoring_get_local_user_group_service,
)
from ..monitoring import (
    get_local_user_service as monitoring_get_local_user_service,
)
from ..monitoring import (
    get_radius_server as monitoring_get_radius_server,
)
from ..monitoring import (
    get_tacacs_server as monitoring_get_tacacs_server,
)

admin_router = APIRouter(
    prefix="/admin",
    tags=["Administration"],
    include_in_schema=False,
)
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent.parent / "templates")
)


def get_device_service() -> DeviceService:
    service = monitoring_get_device_service()
    if not service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Device service unavailable",
        )
    return service


def get_user_service() -> LocalUserService:
    service = monitoring_get_local_user_service()
    if not service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User service unavailable",
        )
    return service


def get_user_group_service() -> LocalUserGroupService:
    service = monitoring_get_local_user_group_service()
    if not service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User group service unavailable",
        )
    return service


def _parse_allowed_groups(value) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        raw_tokens = value.replace("\n", ",").split(",")
    else:
        try:
            raw_tokens = [str(token) for token in value]
        except TypeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="allowed_user_groups must be a list or "
                "comma/newline separated string",
            ) from exc
    tokens = []
    for token in raw_tokens:
        trimmed = token.strip()
        if trimmed and trimmed not in tokens:
            tokens.append(trimmed)
    return tokens


def _parse_int(value, field: str, *, required: bool = False) -> int | None:
    if value is None or value == "":
        if required:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field} is required"
            )
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field} must be an integer",
        ) from exc


_SENSITIVE_KEYWORDS = ("secret", "password", "token", "key", "hash")


def _calc_metric(
    stats: dict, *, total_key: str, success_key: str, failure_key: str
) -> dict:
    total = stats.get(total_key, 0) or 0
    success = stats.get(success_key, 0) or 0
    failure = stats.get(failure_key, 0) or max(total - success, 0)
    success_percent = round((success / total) * 100, 1) if total else 0.0
    failure_percent = round((failure / total) * 100, 1) if total else 0.0
    return {
        "total": total,
        "success": success,
        "failure": failure,
        "success_percent": success_percent,
        "failure_percent": failure_percent,
    }


def _format_duration(seconds: float) -> str:
    seconds = int(seconds or 0)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if days or hours:
        parts.append(f"{hours}h")
    if days or minutes or hours:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def _format_bytes(value: int | None) -> str:
    if not value and value != 0:
        return "0 B"
    value = int(value)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(value)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def _mask_value(value: Any) -> str:
    if value is None:
        return "[redacted]"
    if isinstance(value, int | float):
        return "[redacted]"
    if isinstance(value, str):
        length = len(value)
        if length == 0:
            return ""
        return f"[redacted len={length}]"
    return "[redacted]"


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(keyword in lowered for keyword in _SENSITIVE_KEYWORDS)


def _sanitize_config_data(value: Any, *, sensitive: bool = False) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, inner in value.items():
            result[key] = _sanitize_config_data(
                inner, sensitive=sensitive or _is_sensitive_key(key)
            )
        return result
    if isinstance(value, list):
        return [_sanitize_config_data(item, sensitive=sensitive) for item in value]
    if sensitive:
        return _mask_value(value)
    return value


# Ensure admin_guard is defined before use in dependencies
async def admin_guard(request: Request) -> None:
    dependency = get_admin_auth_dependency_func()
    if dependency is None:
        return
    result = dependency(request)
    if inspect.isawaitable(result):
        await result


@admin_router.get("/webhooks", response_class=HTMLResponse)
async def admin_webhooks_page(request: Request, _: None = Depends(admin_guard)):
    cfg = get_webhook_config_dict()
    return templates.TemplateResponse(
        "admin/webhooks.html",
        {"request": request, "config": cfg},
    )


@admin_router.get("/webhooks-config")
async def get_webhooks_config(_: None = Depends(admin_guard)):
    return get_webhook_config_dict()


@admin_router.put("/webhooks-config")
async def update_webhooks_config(request: Request, _: None = Depends(admin_guard)):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    urls = data.get("urls")
    headers = data.get("headers")
    template = data.get("template")
    timeout = data.get("timeout")
    threshold_count = data.get("threshold_count")
    threshold_window = data.get("threshold_window")
    if urls is not None and not isinstance(urls, list):
        raise HTTPException(status_code=400, detail="urls must be a list")
    if headers is not None and not isinstance(headers, dict):
        raise HTTPException(status_code=400, detail="headers must be an object")
    if template is not None and not isinstance(template, dict):
        raise HTTPException(status_code=400, detail="template must be an object")
    try:
        # Update runtime
        set_webhook_config(
            urls, headers, template, timeout, threshold_count, threshold_window
        )
        # Persist to config file
        cfg = monitoring_get_config()
        if cfg is not None:
            cfg.update_webhook_config(
                urls=urls,
                headers=headers,
                template=template,
                timeout=timeout,
                threshold_count=threshold_count,
                threshold_window=threshold_window,
            )
        return get_webhook_config_dict()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to update: {e}")


@admin_router.get("/", response_class=HTMLResponse)
async def admin_home(request: Request, _: None = Depends(admin_guard)):
    device_service = monitoring_get_device_service()
    user_service = monitoring_get_local_user_service()
    user_group_service = monitoring_get_local_user_group_service()
    tacacs_server = monitoring_get_tacacs_server()
    radius_server = monitoring_get_radius_server()

    # Optimize by loading data once and reusing
    devices = device_service.list_devices() if device_service else []
    groups = device_service.list_groups() if device_service else []
    users = user_service.list_users() if user_service else []
    user_groups = user_group_service.list_groups() if user_group_service else []

    summary = {
        "devices": len(devices),
        "device_groups": len(groups),
        "users": len(users),
        "user_groups": len(user_groups),
    }

    raw_stats = tacacs_server.get_stats() if tacacs_server else {}
    health = tacacs_server.get_health_status() if tacacs_server else {}

    auth_summary = _calc_metric(
        raw_stats,
        total_key="auth_requests",
        success_key="auth_success",
        failure_key="auth_failures",
    )
    author_summary = _calc_metric(
        raw_stats,
        total_key="author_requests",
        success_key="author_success",
        failure_key="author_failures",
    )
    acct_summary = _calc_metric(
        raw_stats,
        total_key="acct_requests",
        success_key="acct_success",
        failure_key="acct_failures",
    )

    connections = {
        "active": raw_stats.get("connections_active", 0),
        "total": raw_stats.get("connections_total", 0),
    }
    uptime_seconds = health.get("uptime_seconds", 0)
    uptime_text = _format_duration(uptime_seconds)

    memory_usage = health.get("memory_usage", {}) or {}
    mem_total = memory_usage.get("total")
    mem_used = memory_usage.get("used")
    mem_percent = memory_usage.get("percent")
    if not mem_total:
        vm = psutil.virtual_memory()
        mem_total = vm.total
        mem_used = vm.used
        mem_percent = vm.percent

    cpu_percent = None
    try:
        cpu_percent = psutil.cpu_percent(interval=0.0)
    except Exception:
        cpu_percent = None

    radius_summary = None
    if radius_server:
        r_stats = getattr(radius_server, "stats", {}) or {}
        clients = getattr(radius_server, "clients", []) or []
        radius_acct = _calc_metric(
            {
                "auth_requests": r_stats.get("acct_requests", 0),
                "auth_success": r_stats.get("acct_responses", 0),
                "auth_failures": r_stats.get("acct_requests", 0)
                - r_stats.get("acct_responses", 0),
            },
            total_key="auth_requests",
            success_key="auth_success",
            failure_key="auth_failures",
        )
        radius_summary = {
            "clients": len(clients),
            "auth": _calc_metric(
                r_stats,
                total_key="auth_requests",
                success_key="auth_accepts",
                failure_key="auth_rejects",
            ),
            "acct": radius_acct,
        }

    tacacs_summary = {
        "auth": auth_summary,
        "author": author_summary,
        "acct": acct_summary,
    }

    device_samples = []
    for device_record in devices[:5]:
        group = device_record.group
        device_samples.append(
            {
                "name": device_record.name,
                "network": str(device_record.network),
                "group": getattr(group, "name", None),
                "has_tacacs_secret": bool(getattr(group, "tacacs_secret", None))
                if group
                else False,
                "has_radius_secret": bool(getattr(group, "radius_secret", None))
                if group
                else False,
            }
        )

    group_samples = []
    for group in groups[:5]:
        group_samples.append(
            {
                "name": group.name,
                "description": group.description,
                "allowed_user_groups": len(group.allowed_user_groups or []),
                "tacacs_secret": bool(group.tacacs_secret),
                "radius_secret": bool(group.radius_secret),
            }
        )

    user_samples = []
    for user_record in users[:5]:
        user_samples.append(
            {
                "username": user_record.username,
                "privilege_level": user_record.privilege_level,
                "enabled": user_record.enabled,
                "groups": ", ".join(user_record.groups or []),
            }
        )

    config = monitoring_get_config()
    config_source = None
    if config:
        config_source = getattr(config, "config_source", None) or getattr(
            config, "config_file", "config/tacacs.conf"
        )

    system_summary = {
        "uptime": uptime_text,
        "connections": connections,
        "cpu_percent": cpu_percent,
        "memory_percent": mem_percent,
        "memory_human": f"{_format_bytes(mem_used)} / {_format_bytes(mem_total)}"
        if mem_total is not None
        else "N/A",
        "config_source": config_source,
    }

    accept = request.headers.get("accept", "")
    if "application/json" in accept or request.query_params.get("format") == "json":
        return summary

    return templates.TemplateResponse(
        "admin/dashboard.html",
        {
            "request": request,
            "title": "Dashboard",
            "summary": summary,
            "auth_summary": auth_summary,
            "author_summary": author_summary,
            "acct_summary": acct_summary,
            "radius_summary": radius_summary,
            "tacacs_summary": tacacs_summary,
            "system_summary": system_summary,
            "device_samples": device_samples,
            "group_samples": group_samples,
            "user_samples": user_samples,
        },
    )


@admin_router.get("", include_in_schema=False)
async def admin_root_redirect():
    return RedirectResponse(
        url="/admin/", status_code=status.HTTP_307_TEMPORARY_REDIRECT
    )


@admin_router.get("/config")
async def view_config(
    request: Request,
    _: None = Depends(admin_guard),
):
    config = monitoring_get_config()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configuration unavailable",
        )

    summary = config.get_config_summary()
    sanitized = _sanitize_config_data(summary)
    source = getattr(
        config, "config_source", getattr(config, "config_file", "config/tacacs.conf")
    )

    accept = request.headers.get("accept", "")
    if "application/json" in accept or request.query_params.get("format") == "json":
        return {"source": source, "configuration": sanitized}

    config_json = json.dumps(sanitized, indent=2, sort_keys=True)
    return templates.TemplateResponse(
        "admin/config.html",
        {
            "request": request,
            "title": "Configuration",
            "config_source": source,
            "config_json": config_json,
        },
    )


@admin_router.get("/config/", include_in_schema=False)
async def view_config_trailing_slash():
    return RedirectResponse(
        url="/admin/config", status_code=status.HTTP_307_TEMPORARY_REDIRECT
    )


@admin_router.put("/config")
async def update_config(request: Request, _: None = Depends(admin_guard)):
    """Update server configuration with comprehensive error handling."""
    config = monitoring_get_config()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configuration unavailable",
        )

    try:
        payload = await request.json()
    except (ValueError, TypeError) as e:
        logger.warning("Invalid JSON in config update: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid JSON payload: {e}"
        ) from e

    try:
        # Update different sections based on payload
        if "server" in payload:
            config.update_server_config(**payload["server"])
        if "auth" in payload:
            config.update_auth_config(**payload["auth"])
        if "ldap" in payload:
            config.update_ldap_config(**payload["ldap"])

        logger.info("Configuration updated successfully")
        return {"success": True, "message": "Configuration updated"}
    except ValueError as e:
        logger.error("Configuration validation error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Configuration validation failed: {e}",
        ) from e
    except Exception as e:
        logger.error("Unexpected error updating configuration: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during configuration update",
        ) from e


@admin_router.get("/devices")
async def list_devices(
    request: Request,
    service: DeviceService = Depends(get_device_service),
    _: None = Depends(admin_guard),
    search: str | None = None,
    group_filter: str | None = None,
    limit: int = 100,
):
    # Get all devices
    all_devices = service.list_devices()

    # Apply search filter
    if search:
        search_lower = search.lower()
        all_devices = [
            device
            for device in all_devices
            if (
                search_lower in device.name.lower()
                or search_lower in str(device.network).lower()
            )
        ]

    # Apply group filter
    if group_filter:
        all_devices = [
            device
            for device in all_devices
            if device.group and device.group.name == group_filter
        ]

    # Apply limit
    devices = all_devices[:limit]

    data = [
        {
            "id": record.id,
            "name": record.name,
            "network": str(record.network),
            "group": record.group.name if record.group else None,
            "group_radius_secret": (
                bool(record.group.radius_secret) if record.group else False
            ),
            "group_tacacs_secret": (
                bool(record.group.tacacs_secret) if record.group else False
            ),
        }
        for record in devices
    ]

    accept = request.headers.get("accept", "")
    if "application/json" in accept or request.query_params.get("format") == "json":
        return {
            "devices": data,
            "total": len(all_devices),
            "shown": len(data),
            "filters": {"search": search, "group_filter": group_filter, "limit": limit},
        }

    group_options = sorted(group.name for group in service.list_groups())
    return templates.TemplateResponse(
        "admin/devices.html",
        {
            "request": request,
            "devices": data,
            "title": "Devices",
            "group_options": group_options,
            "total_devices": len(all_devices),
            "search": search or "",
            "group_filter": group_filter or "",
        },
    )


@admin_router.post("/devices", status_code=status.HTTP_201_CREATED)
async def create_device(
    request: Request,
    service: DeviceService = Depends(get_device_service),
    _: None = Depends(admin_guard),
):
    audit_logger = get_audit_logger()
    payload = {}  # Initialize payload to avoid unbound variable errors
    try:
        # Parse and validate JSON payload
        try:
            payload = await request.json()
        except (ValueError, TypeError) as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid JSON payload: {e}",
            ) from e

        payload = FormValidator.validate_device_form(payload)

        record = service.create_device(
            name=str(payload.get("name", "")),
            network=str(payload.get("network", "")),
            group=payload.get("group"),
        )

        # Audit log
        audit_logger.log_action(
            user_id="admin",  # TODO: Get actual user from session
            action="create_device",
            resource_type="device",
            resource_id=str(record.id),
            details={"name": record.name, "network": str(record.network)},
            client_ip=request.client.host if request.client else None,
            success=True,
        )

        logger.info(
            "Admin UI: created device id=%s name=%s",
            record.id,
            InputValidator.sanitize_log_input(payload.get("name", "")),
        )
        return {"id": record.id}
    except ValidationError as exc:
        audit_logger.log_action(
            user_id="admin",
            action="create_device",
            resource_type="device",
            details=payload if "payload" in locals() else {},
            client_ip=request.client.host if request.client else None,
            success=False,
            error_message=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except (DeviceValidationError, GroupNotFound) as exc:
        audit_logger.log_action(
            user_id="admin",
            action="create_device",
            resource_type="device",
            details=payload if "payload" in locals() else {},
            client_ip=request.client.host if request.client else None,
            success=False,
            error_message=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@admin_router.get("/devices/{device_id}")
async def get_device(
    device_id: int,
    service: DeviceService = Depends(get_device_service),
    _: None = Depends(admin_guard),
):
    try:
        record = service.get_device(device_id)
        return {
            "id": record.id,
            "name": record.name,
            "network": str(record.network),
            "group": record.group.name if record.group else None,
        }
    except DeviceNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@admin_router.put("/devices/{device_id}")
async def update_device(
    request: Request,
    device_id: int,
    service: DeviceService = Depends(get_device_service),
    _: None = Depends(admin_guard),
):
    try:
        payload = await request.json()
        payload = FormValidator.validate_device_form(payload)
        record = service.update_device(
            device_id,
            name=payload.get("name"),
            network=payload.get("network"),
            group=payload.get("group"),
            clear_group=payload.get("clear_group", False),
        )
        logger.info("Admin UI: updated device id=%s", device_id)
        return {"id": record.id}
    except (DeviceValidationError, GroupNotFound) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except DeviceNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@admin_router.delete("/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    request: Request,
    device_id: int,
    service: DeviceService = Depends(get_device_service),
    _: None = Depends(admin_guard),
):
    audit_logger = get_audit_logger()
    try:
        service.delete_device(device_id)

        # Audit log
        audit_logger.log_action(
            user_id="admin",
            action="delete_device",
            resource_type="device",
            resource_id=str(device_id),
            client_ip=request.client.host if request.client else None,
            success=True,
        )

        logger.info("Admin UI: deleted device id=%s", device_id)
    except DeviceNotFound as exc:
        audit_logger.log_action(
            user_id="admin",
            action="delete_device",
            resource_type="device",
            resource_id=str(device_id),
            client_ip=request.client.host if request.client else None,
            success=False,
            error_message=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return None


@admin_router.get("/groups")
async def list_groups(
    request: Request,
    service: DeviceService = Depends(get_device_service),
    user_group_service: LocalUserGroupService = Depends(get_user_group_service),
    _: None = Depends(admin_guard),
):
    data = [
        {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "metadata": group.metadata,
            "radius_secret": bool(group.radius_secret),
            "tacacs_secret": bool(group.tacacs_secret),
            "device_config": group.device_config,
            "allowed_user_groups": group.allowed_user_groups,
        }
        for group in service.list_groups()
    ]
    accept = request.headers.get("accept", "")
    if "application/json" in accept or request.query_params.get("format") == "json":
        return data
    user_group_options = sorted(
        record.name for record in user_group_service.list_groups()
    )
    return templates.TemplateResponse(
        "admin/groups.html",
        {
            "request": request,
            "groups": data,
            "title": "Groups",
            "user_group_options": user_group_options,
        },
    )


@admin_router.post("/groups", status_code=status.HTTP_201_CREATED)
async def create_group(
    request: Request,
    service: DeviceService = Depends(get_device_service),
    _: None = Depends(admin_guard),
):
    try:
        payload = await request.json()
        payload = FormValidator.validate_group_form(payload)
        group = service.create_group(
            payload.get("name", ""),
            description=payload.get("description"),
            tacacs_profile=payload.get("tacacs_profile"),
            radius_profile=payload.get("radius_profile"),
            metadata=payload.get("metadata"),
            radius_secret=payload.get("radius_secret"),
            tacacs_secret=payload.get("tacacs_secret"),
            device_config=payload.get("device_config"),
            allowed_user_groups=payload.get("allowed_user_groups"),
        )
        logger.info(
            "Admin UI: created device group id=%s name=%s",
            group.id,
            InputValidator.sanitize_log_input(payload.get("name", "")),
        )
        return {"id": group.id}
    except DeviceValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@admin_router.put("/groups/{group_id}")
async def update_group(
    request: Request,
    group_id: int,
    service: DeviceService = Depends(get_device_service),
    _: None = Depends(admin_guard),
):
    try:
        payload = await request.json()
        payload = FormValidator.validate_group_form(payload)
        group = service.update_group(
            group_id,
            name=payload.get("name"),
            description=payload.get("description"),
            tacacs_profile=payload.get("tacacs_profile"),
            radius_profile=payload.get("radius_profile"),
            metadata=payload.get("metadata"),
            radius_secret=payload.get("radius_secret")
            if "radius_secret" in payload
            else UNSET,
            tacacs_secret=payload.get("tacacs_secret")
            if "tacacs_secret" in payload
            else UNSET,
            device_config=payload.get("device_config")
            if "device_config" in payload
            else UNSET,
            allowed_user_groups=payload.get("allowed_user_groups")
            if "allowed_user_groups" in payload
            else UNSET,
        )
        logger.info("Admin UI: updated device group id=%s", group_id)
        return {"id": group.id}
    except GroupNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except DeviceValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@admin_router.delete("/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: int,
    cascade: bool = False,
    service: DeviceService = Depends(get_device_service),
    _: None = Depends(admin_guard),
):
    try:
        service.delete_group(group_id, cascade=cascade)
        logger.info(
            "Admin UI: deleted device group id=%s cascade=%s", group_id, cascade
        )
    except GroupNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except DeviceValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return None


@admin_router.get("/groups/{group_id}")
async def get_group_details(
    group_id: int,
    service: DeviceService = Depends(get_device_service),
    _: None = Depends(admin_guard),
):
    try:
        group = service.get_group(group_id)
        return {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "metadata": group.metadata,
            "radius_secret": group.radius_secret,
            "tacacs_secret": group.tacacs_secret,
            "device_config": group.device_config,
            "allowed_user_groups": group.allowed_user_groups,
        }
    except GroupNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@admin_router.get("/user-groups")
async def list_user_groups(
    request: Request,
    service: LocalUserGroupService = Depends(get_user_group_service),
    _: None = Depends(admin_guard),
):
    records = service.list_groups()
    data = [
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
    accept = request.headers.get("accept", "")
    if "application/json" in accept or request.query_params.get("format") == "json":
        return data
    return templates.TemplateResponse(
        "admin/user_groups.html",
        {"request": request, "groups": data, "title": "User Groups"},
    )


@admin_router.post("/user-groups", status_code=status.HTTP_201_CREATED)
async def create_user_group(
    request: Request,
    service: LocalUserGroupService = Depends(get_user_group_service),
    _: None = Depends(admin_guard),
):
    try:
        payload = await request.json()
        record = service.create_group(
            payload.get("name", ""),
            description=payload.get("description"),
            metadata=payload.get("metadata"),
            ldap_group=payload.get("ldap_group"),
            okta_group=payload.get("okta_group"),
            privilege_level=_parse_int(
                payload.get("privilege_level"), "privilege_level"
            )
            or 1,
        )
        logger.info("Admin UI: created user group name=%s", record.name)
        return {"name": record.name}
    except LocalUserGroupExists as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    except LocalUserGroupValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@admin_router.put("/user-groups/{name}")
async def update_user_group(
    request: Request,
    name: str,
    service: LocalUserGroupService = Depends(get_user_group_service),
    _: None = Depends(admin_guard),
):
    try:
        payload = await request.json()
        record = service.update_group(
            name,
            description=payload.get("description"),
            metadata=payload.get("metadata"),
            ldap_group=payload.get("ldap_group") if "ldap_group" in payload else UNSET,
            okta_group=payload.get("okta_group") if "okta_group" in payload else UNSET,
            privilege_level=_parse_int(
                payload.get("privilege_level"), "privilege_level"
            )
            if "privilege_level" in payload
            else None,
        )
        logger.info("Admin UI: updated user group name=%s", name)
        return {"name": record.name}
    except LocalUserGroupNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except LocalUserGroupValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@admin_router.delete("/user-groups/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_group(
    name: str,
    service: LocalUserGroupService = Depends(get_user_group_service),
    _: None = Depends(admin_guard),
):
    try:
        service.delete_group(name)
        logger.info("Admin UI: deleted user group name=%s", name)
    except LocalUserGroupNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return None


@admin_router.get("/user-groups/{name}")
async def get_user_group_details(
    name: str,
    service: LocalUserGroupService = Depends(get_user_group_service),
    _: None = Depends(admin_guard),
):
    try:
        record = service.get_group(name)
        return {
            "name": record.name,
            "description": record.description,
            "metadata": record.metadata,
            "ldap_group": record.ldap_group,
            "okta_group": record.okta_group,
            "privilege_level": record.privilege_level,
        }
    except LocalUserGroupNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@admin_router.get("/users")
async def list_users(
    request: Request,
    service: LocalUserService = Depends(get_user_service),
    group_service: LocalUserGroupService = Depends(get_user_group_service),
    _: None = Depends(admin_guard),
    search: str | None = None,
    enabled_filter: bool | None = None,
    group_filter: str | None = None,
    limit: int = 100,
):
    # Get all users
    all_users = service.list_users()

    # Apply search filter
    if search:
        search_lower = search.lower()
        all_users = [
            user
            for user in all_users
            if (
                search_lower in user.username.lower()
                or (user.description and search_lower in user.description.lower())
            )
        ]

    # Apply enabled filter
    if enabled_filter is not None:
        all_users = [user for user in all_users if user.enabled == enabled_filter]

    # Apply group filter
    if group_filter:
        all_users = [
            user for user in all_users if user.groups and group_filter in user.groups
        ]

    # Apply limit
    users = all_users[:limit]

    group_options = [g.name for g in group_service.list_groups()]
    data = [
        {
            "username": r.username,
            "privilege_level": r.privilege_level,
            "service": r.service,
            "shell_command": r.shell_command,
            "groups": r.groups,
            "enabled": r.enabled,
            "description": r.description,
        }
        for r in users
    ]

    accept = request.headers.get("accept", "")
    wants_html = request.query_params.get("format") == "html" or (
        "text/html" in accept and "application/json" not in accept
    )
    if not wants_html:
        return {
            "users": data,
            "total": len(all_users),
            "shown": len(data),
            "filters": {
                "search": search,
                "enabled_filter": enabled_filter,
                "group_filter": group_filter,
                "limit": limit,
            },
        }

    return templates.TemplateResponse(
        "admin/users.html",
        {
            "request": request,
            "users": data,
            "title": "Users",
            "group_options": group_options,
            "total_users": len(all_users),
            "search": search or "",
            "enabled_filter": enabled_filter,
            "group_filter": group_filter or "",
        },
    )


@admin_router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    service: LocalUserService = Depends(get_user_service),
    _: None = Depends(admin_guard),
):
    try:
        # Parse and validate JSON payload
        try:
            payload = await request.json()
        except (ValueError, TypeError) as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid JSON payload: {e}",
            ) from e

        payload = FormValidator.validate_user_form(payload)
        record = service.create_user(
            username=payload.get("username", ""),
            password=payload.get("password"),
            privilege_level=payload.get("privilege_level", 1),
            service=payload.get("service", "exec"),
            shell_command=payload.get("shell_command"),
            groups=payload.get("groups"),
            enabled=payload.get("enabled", True),
            description=payload.get("description"),
        )
        logger.info(
            "Admin UI: created user %s",
            InputValidator.sanitize_log_input(record.username),
        )
        return {"username": record.username}
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except LocalUserExists as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    except LocalUserValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@admin_router.put("/users/{username}")
async def update_user(
    request: Request,
    username: str,
    service: LocalUserService = Depends(get_user_service),
    _: None = Depends(admin_guard),
):
    try:
        # Validate username from path parameter
        username = InputValidator.validate_username(username)
        payload = await request.json()
        payload = FormValidator.validate_user_form(payload)

        record = service.update_user(
            username,
            privilege_level=payload.get("privilege_level"),
            service=payload.get("service"),
            shell_command=payload.get("shell_command"),
            groups=payload.get("groups"),
            enabled=payload.get("enabled"),
            description=payload.get("description"),
        )
        logger.info(
            "Admin UI: updated user %s", InputValidator.sanitize_log_input(username)
        )
        return {"username": record.username}
    except (LocalUserNotFound, ValidationError) as exc:
        status_code = (
            status.HTTP_404_NOT_FOUND
            if isinstance(exc, LocalUserNotFound)
            else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    except LocalUserValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@admin_router.post("/users/{username}/password")
async def set_user_password(
    request: Request,
    username: str,
    service: LocalUserService = Depends(get_user_service),
    _: None = Depends(admin_guard),
):
    try:
        # Validate username from path parameter
        username = InputValidator.validate_username(username)
        payload = await request.json()

        password = payload.get("password")
        if not password:
            raise ValidationError("Password is required")

        # Validate password strength
        password = InputValidator.validate_password(password)

        store_hash = payload.get("store_hash", True)
        record = service.set_password(username, password, store_hash=store_hash)
        logger.info(
            "Admin UI: updated password for user %s",
            InputValidator.sanitize_log_input(username),
        )
        return {"username": record.username}
    except (LocalUserNotFound, ValidationError) as exc:
        status_code = (
            status.HTTP_404_NOT_FOUND
            if isinstance(exc, LocalUserNotFound)
            else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    except LocalUserValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@admin_router.delete("/users/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    username: str,
    service: LocalUserService = Depends(get_user_service),
    _: None = Depends(admin_guard),
):
    try:
        service.delete_user(username)
        logger.info(
            "Admin UI: deleted user %s", InputValidator.sanitize_log_input(username)
        )
    except LocalUserNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return None


@admin_router.get("/users/{username}")
async def get_user_details(
    username: str,
    service: LocalUserService = Depends(get_user_service),
    _: None = Depends(admin_guard),
):
    try:
        record = service.get_user(username)
        return {
            "username": record.username,
            "privilege_level": record.privilege_level,
            "service": record.service,
            "shell_command": record.shell_command,
            "groups": record.groups,
            "enabled": record.enabled,
            "description": record.description,
        }
    except LocalUserNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


# Bulk Operations
@admin_router.post("/devices/bulk", status_code=status.HTTP_201_CREATED)
async def bulk_create_devices(
    devices: list[dict],
    service: DeviceService = Depends(get_device_service),
    _: None = Depends(admin_guard),
):
    """Bulk create devices"""
    results = []
    errors = []

    for i, device_data in enumerate(devices):
        try:
            record = service.create_device(
                name=str(device_data.get("name", "")),
                network=str(device_data.get("network", "")),
                group=device_data.get("group"),
            )
            results.append({"index": i, "id": record.id, "name": record.name})
        except Exception as e:
            logger.warning(
                "Failed to create device at index %d: %s | data: %s",
                i,
                e,
                device_data,
                exc_info=True,
            )
            errors.append(
                {"index": i, "error": "Failed to create device", "data": device_data}
            )

    logger.info(f"Bulk device creation: {len(results)} success, {len(errors)} errors")
    return {
        "created": results,
        "errors": errors,
        "summary": {"success": len(results), "failed": len(errors)},
    }


@admin_router.post("/users/bulk", status_code=status.HTTP_201_CREATED)
async def bulk_create_users(
    users: list[dict],
    service: LocalUserService = Depends(get_user_service),
    _: None = Depends(admin_guard),
):
    """Bulk create users"""
    results = []
    errors = []

    for i, user_data in enumerate(users):
        try:
            record = service.create_user(
                username=user_data.get("username", ""),
                password=user_data.get("password"),
                privilege_level=user_data.get("privilege_level", 1),
                service=user_data.get("service", "exec"),
                shell_command=user_data.get("shell_command"),
                groups=user_data.get("groups"),
                enabled=user_data.get("enabled", True),
                description=user_data.get("description"),
            )
            results.append({"index": i, "username": record.username})
        except Exception as e:
            logger.warning(
                "Failed to create user at index %d: %s | data: %s",
                i,
                e,
                user_data,
                exc_info=True,
            )
            errors.append(
                {"index": i, "error": "Failed to create user", "data": user_data}
            )

    logger.info(f"Bulk user creation: {len(results)} success, {len(errors)} errors")
    return {
        "created": results,
        "errors": errors,
        "summary": {"success": len(results), "failed": len(errors)},
    }


@admin_router.get("/devices/export")
async def export_devices(
    service: DeviceService = Depends(get_device_service),
    _: None = Depends(admin_guard),
    format: str = "json",
):
    """Export devices data"""
    devices = service.list_devices()
    data = [
        {
            "name": device.name,
            "network": str(device.network),
            "group": device.group.name if device.group else None,
        }
        for device in devices
    ]

    if format.lower() == "csv":
        import csv
        import io

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["name", "network", "group"])
        writer.writeheader()
        writer.writerows(data)

        from fastapi.responses import Response

        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=devices.csv"},
        )

    return {"devices": data, "count": len(data)}


@admin_router.get("/users/export")
async def export_users(
    service: LocalUserService = Depends(get_user_service),
    _: None = Depends(admin_guard),
    format: str = "json",
):
    """Export users data"""
    users = service.list_users()
    data = [
        {
            "username": user.username,
            "privilege_level": user.privilege_level,
            "service": user.service,
            "groups": ",".join(user.groups or []),
            "enabled": user.enabled,
            "description": user.description,
        }
        for user in users
    ]

    if format.lower() == "csv":
        import csv
        import io

        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "username",
                "privilege_level",
                "service",
                "groups",
                "enabled",
                "description",
            ],
        )
        writer.writeheader()
        writer.writerows(data)

        from fastapi.responses import Response

        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=users.csv"},
        )

    return {"users": data, "count": len(data)}


# Audit Trail API
@admin_router.get("/audit")
async def get_audit_log(
    hours: int = 24,
    user_id: str | None = None,
    action: str | None = None,
    limit: int = 100,
    _: None = Depends(admin_guard),
):
    """Get audit trail entries"""
    audit_logger = get_audit_logger()
    entries = audit_logger.get_audit_log(hours, user_id, action, limit)
    summary = audit_logger.get_audit_summary(hours)

    return {
        "entries": entries,
        "summary": summary,
        "filters": {
            "hours": hours,
            "user_id": user_id,
            "action": action,
            "limit": limit,
        },
    }


@admin_router.get("/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    return templates.TemplateResponse("admin/login.html", {"request": request})


@admin_router.post("/login")
async def admin_login(
    request: Request,
    username: str | None = Form(None),
    password: str | None = Form(None),
):
    manager = get_admin_session_manager()
    if not manager:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin auth not configured",
        )

    is_json = request.headers.get("content-type", "").startswith("application/json")
    if is_json:
        payload = await request.json()
        username = payload.get("username", "")
        password = payload.get("password", "")
    else:
        if username is None or password is None:
            form = await request.form()
            username = str(form.get("username", ""))
            password = str(form.get("password", ""))

    try:
        # Validate login inputs
        if not username or not password:
            raise ValidationError("Username and password are required")

        username = InputValidator.validate_username(username)
        # Don't validate password strength for login, just basic sanitization
        if len(password) > 128:
            raise ValidationError("Password too long")

        token = manager.login(username, password)
    except (HTTPException, ValidationError) as exc:
        if isinstance(exc, ValidationError):
            exc = HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            )
        if is_json:
            raise exc
        return templates.TemplateResponse(
            "admin/login.html",
            {"request": request, "error": exc.detail},
            status_code=exc.status_code,
        )

    response: Response
    if is_json:
        response = JSONResponse({"success": True})
    else:
        response = RedirectResponse(
            url="/admin/", status_code=status.HTTP_303_SEE_OTHER
        )
    # Determine if the request is over HTTPS (direct or via reverse proxy)
    import os as _os

    forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
    is_https = request.url.scheme == "https" or forwarded_proto == "https"
    secure_env = _os.getenv("SECURE_COOKIES", "true").strip().lower() != "false"
    secure_flag = True if secure_env else is_https
    # Set session cookie with secure defaults
    response.set_cookie(
        "admin_session",
        token,
        httponly=True,
        samesite="strict",
        secure=secure_flag,
        max_age=int(manager.config.session_timeout.total_seconds()),
        path="/",
    )
    return response


@admin_router.post("/logout")
async def admin_logout(request: Request):
    manager = get_admin_session_manager()
    if manager:
        manager.logout()
    accept = request.headers.get("accept", "")
    response: Response
    if "application/json" in accept:
        response = JSONResponse({"success": True})
    else:
        response = RedirectResponse(
            url="/admin/login", status_code=status.HTTP_303_SEE_OTHER
        )
    # Mirror cookie attributes on delete to ensure removal across browsers
    response.delete_cookie(
        "admin_session",
        path="/",
        samesite="strict",
    )
    return response


# Server Control Endpoints
@admin_router.post("/server/reload-config")
async def reload_server_config(_: None = Depends(admin_guard)):
    """Reload server configuration"""
    tacacs_server = monitoring_get_tacacs_server()
    if not tacacs_server:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TACACS server unavailable",
        )

    try:
        success = tacacs_server.reload_configuration()
        return {
            "success": success,
            "message": "Configuration reloaded" if success else "Reload failed",
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@admin_router.post("/server/reset-stats")
async def reset_server_stats(_: None = Depends(admin_guard)):
    """Reset server statistics"""
    tacacs_server = monitoring_get_tacacs_server()
    if not tacacs_server:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TACACS server unavailable",
        )

    try:
        tacacs_server.reset_stats()
        return {"success": True, "message": "Statistics reset"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@admin_router.get("/server/logs")
async def get_server_logs(lines: int = 100, _: None = Depends(admin_guard)):
    """Get recent server log entries with proper error handling."""
    # Validate lines parameter to prevent resource exhaustion
    if lines < 1 or lines > 10000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Lines parameter must be between 1 and 10000",
        )

    log_file = "logs/tacacs.log"
    try:
        with open(log_file, encoding="utf-8") as f:
            all_lines = f.readlines()
            recent_logs = [line.strip() for line in all_lines[-lines:]]
        return {"logs": recent_logs, "count": len(recent_logs)}
    except FileNotFoundError:
        logger.warning("Log file not found: %s", log_file)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Log file not found"
        )
    except PermissionError:
        logger.error("Permission denied reading log file: %s", log_file)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied reading log file",
        )
    except UnicodeDecodeError as e:
        logger.error("Encoding error reading log file: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Log file encoding error",
        )
    except Exception as e:
        logger.error("Unexpected error reading logs: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not read log file",
        )


@admin_router.get("/server/status")
async def get_server_status(_: None = Depends(admin_guard)):
    """Get detailed server status"""
    tacacs_server = monitoring_get_tacacs_server()
    radius_server = monitoring_get_radius_server()

    if not tacacs_server:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TACACS server unavailable",
        )

    try:
        stats = tacacs_server.get_stats()
        health = tacacs_server.get_health_status()

        result = {
            "tacacs": {
                "running": tacacs_server.running,
                "uptime_seconds": health.get("uptime_seconds", 0),
                "connections": {
                    "active": stats.get("connections_active", 0),
                    "total": stats.get("connections_total", 0),
                },
                "authentication": {
                    "requests": stats.get("auth_requests", 0),
                    "successes": stats.get("auth_success", 0),
                    "failures": stats.get("auth_failures", 0),
                },
            }
        }

        if radius_server:
            radius_stats = radius_server.get_stats()
            result["radius"] = {
                "enabled": True,
                "running": radius_stats.get("running", False),
                "authentication": {
                    "requests": radius_stats.get("auth_requests", 0),
                    "accepts": radius_stats.get("auth_accepts", 0),
                    "rejects": radius_stats.get("auth_rejects", 0),
                },
            }
        else:
            result["radius"] = {"enabled": False}

        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
