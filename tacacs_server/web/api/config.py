from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from tacacs_server.exceptions import (
    ConfigValidationError,
    ResourceNotFoundError,
    ServiceUnavailableError,
)
from tacacs_server.utils import config_utils
from tacacs_server.utils.logger import get_logger
from tacacs_server.web.api_models import (
    ConfigDriftResponse,
    ConfigExportResponse,
    ConfigHistoryResponse,
    ConfigImportResponse,
    ConfigSectionResponse,
    ConfigSectionsResponse,
    ConfigStatusResponse,  # Added
    ConfigUpdateResponse,
    ConfigVersionsResponse,
)

router = APIRouter(prefix="/api/admin/config", tags=["Configuration"])

logger = get_logger("tacacs.api.config")


async def admin_guard(request: Request) -> None:
    # Cookie-based admin session only; do not read body
    try:
        logger.info(
            "Admin guard",
            event="admin.guard",
            service="web",
            component="web_api.config",
            path=getattr(request.url, "path", ""),
            method=getattr(request, "method", ""),
            has_cookie=bool(request.cookies.get("admin_session")),
            content_type=request.headers.get("content-type", ""),
        )
    except Exception:
        pass
    token = request.cookies.get("admin_session")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    # Validate against the active web_auth session manager (used by /admin/login)
    try:
        from tacacs_server.web.web_auth import get_session_manager as _get_sm

        sm = _get_sm()
    except Exception:
        sm = None
    if not sm:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
    if not sm.validate_session(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    # Ensure configuration is initialized in this request context
    try:
        cfg = config_utils.get_config()
        if cfg is None:
            # Prefer app.state first (set by web_app.create_app)
            app_cfg = getattr(getattr(request, "app", None), "state", None)
            app_cfg = getattr(app_cfg, "config_service", None)
            if app_cfg is not None:
                config_utils.set_config(app_cfg)
            else:
                # Fallback to legacy global accessor
                from tacacs_server.web.web import (
                    get_config as _web_get_config,
                )

                cfg2 = _web_get_config()
                if cfg2 is not None:
                    config_utils.set_config(cfg2)
    except Exception:
        # Non-fatal; endpoints will still check availability and return 503 if needed
        pass


class ConfigUpdateRequest(BaseModel):
    section: str
    updates: dict[str, Any]
    reason: str | None = None


@router.get("/status", response_model=ConfigStatusResponse)
async def get_config_status(_: None = Depends(admin_guard)) -> ConfigStatusResponse:
    """Get the overall status of the configuration."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise ServiceUnavailableError("Configuration not available")

    issues = cfg.validate_config()
    overrides_count = sum(len(keys) for keys in cfg.overridden_keys.values())

    return ConfigStatusResponse(
        source=cfg.config_source,
        is_url_config=cfg.is_url_config(),
        valid=not issues,
        issues=issues,
        last_reload=getattr(
            cfg, "_last_reload_time", None
        ),  # Assuming this attribute exists
        overrides_count=overrides_count,
    )


@router.post("/validate")
async def validate_config_api(
    section: str | None = None,
    key: str | None = None,
    value: str | None = None,
    _: None = Depends(admin_guard),
) -> dict:
    """Validate configuration - either full config or a specific change."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise ServiceUnavailableError("Configuration not available")

    # If section/key/value provided, validate just that change
    if section and key and value is not None:
        is_valid, issues = cfg.validate_change(section, key, value)
        return {"valid": is_valid, "issues": issues}

    # Otherwise validate entire config
    issues = cfg.validate_config()
    return {"valid": not issues, "issues": issues}


@router.post("/reload")
async def reload_config_api(_: None = Depends(admin_guard)) -> dict:
    """Reload the configuration from its source."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise ServiceUnavailableError("Configuration not available")

    try:
        # Obtain server reference from web module accessors
        from tacacs_server.web.web import get_tacacs_server

        tacacs_server = get_tacacs_server()
        if not tacacs_server:
            raise ServiceUnavailableError("TACACS+ server not available")
        success = bool(getattr(tacacs_server, "reload_configuration", lambda: False)())
        if success:
            return {"success": True, "message": "Configuration reloaded successfully."}
        else:
            return {"success": False, "message": "Configuration reload failed."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sections", response_model=ConfigSectionsResponse)
@router.get(
    "/sections/", response_model=ConfigSectionsResponse, include_in_schema=False
)
async def list_sections(_: None = Depends(admin_guard)) -> ConfigSectionsResponse:
    """List all configuration sections."""
    cfg = config_utils.get_config()

    if cfg is None:
        logger.error("Configuration not available - config was never initialized")
        raise ServiceUnavailableError(
            "Configuration not available. Server may not be fully initialized."
        )

    # Verify config has required attributes
    if not hasattr(cfg, "config") or cfg.config is None:
        logger.error("Configuration object is missing 'config' attribute")
        raise ServiceUnavailableError("Configuration object is invalid")

    try:
        sections = list(cfg.config.sections())
        logger.debug("Found %d configuration sections", len(sections))
        return ConfigSectionsResponse(sections=sections)
    except Exception as e:
        logger.exception("Failed to retrieve configuration sections")
        raise ServiceUnavailableError(f"Failed to read configuration: {str(e)}")


@router.get("/history", response_model=ConfigHistoryResponse)
async def get_config_history(
    section: str | None = None, limit: int = 100, _: None = Depends(admin_guard)
):
    """Get configuration change history."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise ServiceUnavailableError("Configuration store not available")
    # mypy: narrow and cast config_store
    from typing import Any, cast

    store = cast(Any, getattr(cfg, "config_store", None))
    if not store:
        raise ServiceUnavailableError("Configuration store not available")
    hist = store.get_history(section=section, limit=limit)
    return ConfigHistoryResponse(history=hist, count=len(hist))


@router.get("/versions", response_model=ConfigVersionsResponse)
async def list_versions(_: None = Depends(admin_guard)) -> ConfigVersionsResponse:
    """List configuration versions (metadata only)."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise ServiceUnavailableError("Configuration store not available")
    from typing import Any, cast

    store = cast(Any, getattr(cfg, "config_store", None))
    if not store:
        raise ServiceUnavailableError("Configuration store not available")
    versions = store.list_versions()
    return ConfigVersionsResponse(versions=versions)


@router.post("/versions/{version_number}/restore", response_model=ConfigImportResponse)
async def restore_version(
    version_number: int, _: None = Depends(admin_guard)
) -> ConfigImportResponse:
    """Restore configuration to a previous version with a safety backup."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise ServiceUnavailableError("Configuration store not available")
    try:
        # Pre-restore backup
        current = cfg._export_full_config()
        from typing import Any, cast

        store = cast(Any, getattr(cfg, "config_store", None))
        if not store:
            raise ServiceUnavailableError("Configuration store not available")
        store.create_version(
            config_dict=current,
            created_by="system",
            description=f"Pre-restore backup before reverting to v{version_number}",
        )
        # Restore snapshot (returns dict); applying to live config is out of scope here
        store.restore_version(version_number=version_number, restored_by="admin")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return ConfigImportResponse(success=True, version=version_number)


@router.get("/drift", response_model=ConfigDriftResponse)
async def detect_drift(_: None = Depends(admin_guard)) -> ConfigDriftResponse:
    """Detect configuration drift between base configuration and overrides."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise ServiceUnavailableError("Configuration not available")
    raw = cfg.detect_config_drift()
    # Consistent, meaningful contract:
    # - No drift -> return an empty list ([])
    # - Drift present -> return a section-keyed mapping (dict)
    if not raw:
        return ConfigDriftResponse(drift=[], has_drift=False)
    # Normalize non-empty into a mapping
    if isinstance(raw, dict):
        drift_map = raw
    elif isinstance(raw, list):
        try:
            drift_map = dict(raw)
        except Exception:
            drift_map = {}
    else:
        drift_map = {}
    return ConfigDriftResponse(drift=drift_map, has_drift=len(drift_map) > 0)


@router.get("/export", response_model=ConfigExportResponse)
async def export_config(_: None = Depends(admin_guard)) -> ConfigExportResponse:
    """Export the full effective configuration as JSON."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise ServiceUnavailableError("Configuration not available")
    try:
        data = cfg._export_full_config()
        version_num: int | None = None
        try:
            from typing import Any, cast

            store = cast(Any, getattr(cfg, "config_store", None))
            if store:
                latest = store.get_latest_version()
                if latest and isinstance(latest.get("version_number"), int):
                    version_num = latest["version_number"]
        except Exception:
            version_num = None
        return ConfigExportResponse(config=data, version=version_num)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/import", response_model=ConfigImportResponse)
async def import_config(
    payload: dict[str, Any], _: None = Depends(admin_guard)
) -> ConfigImportResponse:
    """Import configuration snapshot; records a version and returns success."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise ServiceUnavailableError("Configuration store not available")
    config_dict = payload.get("config")
    if not isinstance(config_dict, dict):
        raise ConfigValidationError("Missing or invalid 'config' field", field="config")
    version = payload.get("version")
    try:
        from typing import Any, cast

        store = cast(Any, getattr(cfg, "config_store", None))
        if not store:
            raise ServiceUnavailableError("Configuration store not available")
        meta = store.create_version(
            config_dict=config_dict,
            created_by="admin",
            description=f"imported version {version}"
            if version is not None
            else "imported config",
            is_baseline=False,
        )
        return ConfigImportResponse(success=True, version=meta.get("version_number"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.delete("/overrides", status_code=status.HTTP_204_NO_CONTENT)
async def reset_all_overrides(request: Request, _: None = Depends(admin_guard)):
    """Reset all configuration overrides to their baseline values."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise ServiceUnavailableError("Configuration store not available")
    from typing import Any, cast

    store = cast(Any, getattr(cfg, "config_store", None))
    if not store:
        raise ServiceUnavailableError("Configuration store not available")
    store.clear_overrides(changed_by="admin")
    return


@router.delete("/{section}/overrides", status_code=status.HTTP_204_NO_CONTENT)
async def reset_section_overrides(
    section: str, request: Request, _: None = Depends(admin_guard)
):
    """Reset all overrides in a specific section."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise ServiceUnavailableError("Configuration store not available")
    from typing import Any, cast

    store = cast(Any, getattr(cfg, "config_store", None))
    if not store:
        raise ServiceUnavailableError("Configuration store not available")
    store.clear_overrides(section=section, changed_by="admin")
    return


@router.delete("/{section}/{key}/override", status_code=status.HTTP_204_NO_CONTENT)
async def reset_key_override(
    section: str, key: str, request: Request, _: None = Depends(admin_guard)
):
    """Reset a single configuration key to its baseline value."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise ServiceUnavailableError("Configuration store not available")
    from typing import Any, cast

    store = cast(Any, getattr(cfg, "config_store", None))
    if not store:
        raise ServiceUnavailableError("Configuration store not available")
    store.delete_override(section=section, key=key, changed_by="admin")
    return


@router.get("/{section}", response_model=ConfigSectionResponse)
async def get_section(
    section: str, _: None = Depends(admin_guard)
) -> ConfigSectionResponse:
    """Get all keys in a section with override indicators."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise ServiceUnavailableError("Configuration not available")
    if section not in cfg.config:
        raise ResourceNotFoundError("Section not found")
    values = dict(cfg.config[section])
    overridden = cfg.overridden_keys.get(section, set())
    return ConfigSectionResponse(
        section=section, values=values, overridden_keys=list(overridden)
    )


@router.put("", status_code=status.HTTP_200_OK)
async def update_config_multi(
    updates: dict[str, dict[str, Any]], _: None = Depends(admin_guard)
):
    """Update multiple configuration sections at once (for admin panel)."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise ServiceUnavailableError("Configuration not available")


    results: dict[str, Any] = {}
    errors: dict[str, Any] = {}

    for section, section_updates in updates.items():
        if not section_updates:
            continue

        update_method = getattr(cfg, f"update_{section}_config", None)
        if not update_method:
            errors[section] = f"Section {section} not updatable"
            continue

        # Validate all changes in this section
        validation_errors: dict[str, list[str]] = {}
        for key, value in section_updates.items():
            ok, issues = cfg.validate_change(section, key, value)
            if not ok:
                validation_errors[key] = issues

        if validation_errors:
            errors[section] = validation_errors
            continue

        # Apply updates
        try:
            update_method(**section_updates)
            results[section] = "success"
        except Exception as exc:
            errors[section] = str(exc)

    if errors:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"success": False, "errors": errors, "results": results},
        )

    return {"success": True, "results": results}


@router.put("/{section}", response_model=ConfigUpdateResponse)
async def update_section(
    section: str, request: ConfigUpdateRequest, _: None = Depends(admin_guard)
):
    """Validate and apply configuration updates to a section."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise ServiceUnavailableError("Configuration not available")
    # Validate all changes
    validation_errors: dict[str, list[str]] = {}
    for key, value in request.updates.items():
        ok, issues = cfg.validate_change(section, key, value)
        if not ok:
            validation_errors[key] = issues
    if validation_errors:
        raise ConfigValidationError(
            "Validation failed",
            field=section,
            value=request.updates,
            errors=validation_errors,
        )
    # Apply
    update_method = getattr(cfg, f"update_{section}_config", None)
    if not update_method:
        raise ConfigValidationError("Section not updatable via API", field=section)
    try:
        update_method(_change_reason=request.reason, **request.updates)
        return ConfigUpdateResponse(success=True, section=section)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
