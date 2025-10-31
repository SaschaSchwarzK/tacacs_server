from __future__ import annotations

import asyncio
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from tacacs_server.exceptions import (
    ConfigValidationError,
    ResourceNotFoundError,
    ServiceUnavailableError,
)
from tacacs_server.utils import config_utils

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


async def admin_guard(request: Request) -> None:
    # Cookie-based admin session only; do not read body
    token = request.cookies.get("admin_session")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    mgr = config_utils.get_admin_session_manager()
    if not mgr:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
    if not mgr.validate_session(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


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
async def validate_config_api(_: None = Depends(admin_guard)) -> dict:
    """Trigger a full configuration validation."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise ServiceUnavailableError("Configuration not available")
    issues = cfg.validate_config()
    return {"valid": not issues, "issues": issues}


@router.post("/reload")
async def reload_config_api(_: None = Depends(admin_guard)) -> dict:
    """Reload the configuration from its source."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise ServiceUnavailableError("Configuration not available")

    try:
        # This assumes a method exists on the server to reload config
        # Re-using logic from admin/routers.py for now
        tacacs_server = config_utils.get_tacacs_server()
        if not tacacs_server:
            raise ServiceUnavailableError("TACACS+ server not available")
        success = tacacs_server.reload_configuration()
        if success:
            return {"success": True, "message": "Configuration reloaded successfully."}
        else:
            return {"success": False, "message": "Configuration reload failed."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sections", response_model=ConfigSectionsResponse)
async def list_sections(_: None = Depends(admin_guard)) -> ConfigSectionsResponse:
    """List all configuration sections."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise ServiceUnavailableError("Configuration not available")
    return ConfigSectionsResponse(sections=list(cfg.config.sections()))


@router.get("/history", response_model=ConfigHistoryResponse)
async def get_config_history(
    section: str | None = None, limit: int = 100, _: None = Depends(admin_guard)
):
    """Get configuration change history."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise ServiceUnavailableError("Configuration store not available")
    hist = cfg.config_store.get_history(section=section, limit=limit)
    return ConfigHistoryResponse(history=hist, count=len(hist))


@router.get("/versions", response_model=ConfigVersionsResponse)
async def list_versions(_: None = Depends(admin_guard)) -> ConfigVersionsResponse:
    """List configuration versions (metadata only)."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise ServiceUnavailableError("Configuration store not available")
    versions = cfg.config_store.list_versions()
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
        cfg.config_store.create_version(
            config_dict=current,
            created_by="system",
            description=f"Pre-restore backup before reverting to v{version_number}",
        )
        # Restore snapshot (returns dict); applying to live config is out of scope here
        cfg.config_store.restore_version(
            version_number=version_number, restored_by="admin"
        )
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
            if getattr(cfg, "config_store", None):
                latest = cfg.config_store.get_latest_version()
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
        meta = cfg.config_store.create_version(
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
    # user = request.state.user.username # Assuming user is in state
    cfg.config_store.clear_overrides(changed_by="admin")
    return


@router.delete("/{section}/overrides", status_code=status.HTTP_204_NO_CONTENT)
async def reset_section_overrides(
    section: str, request: Request, _: None = Depends(admin_guard)
):
    """Reset all overrides in a specific section."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise ServiceUnavailableError("Configuration store not available")
    cfg.config_store.clear_overrides(section=section, changed_by="admin")
    return


@router.delete("/{section}/{key}/override", status_code=status.HTTP_204_NO_CONTENT)
async def reset_key_override(
    section: str, key: str, request: Request, _: None = Depends(admin_guard)
):
    """Reset a single configuration key to its baseline value."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise ServiceUnavailableError("Configuration store not available")
    cfg.config_store.delete_override(section=section, key=key, changed_by="admin")
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

    results = {}
    errors = {}

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
