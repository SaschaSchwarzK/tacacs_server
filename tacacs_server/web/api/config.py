from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from tacacs_server.web.monitoring import (
    get_config,
    get_admin_auth_dependency_func,
)


router = APIRouter(prefix="/api/admin/config", tags=["Configuration"])


async def admin_guard(request: Request) -> None:
    dep = get_admin_auth_dependency_func()
    if dep is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    result = dep(request)
    if hasattr(result, "__await__"):
        await result  # type: ignore[func-returns-value]


class ConfigUpdateRequest(BaseModel):
    section: str
    updates: dict[str, Any]
    reason: str | None = None


@router.get("/sections")
async def list_sections(_: None = Depends(admin_guard)):
    """List all configuration sections."""
    cfg = get_config()
    if cfg is None:
        raise HTTPException(status_code=503, detail="Configuration not available")
    return {"sections": list(cfg.config.sections())}


@router.get("/{section}")
async def get_section(section: str, _: None = Depends(admin_guard)):
    """Get all keys in a section with override indicators."""
    cfg = get_config()
    if cfg is None:
        raise HTTPException(status_code=503, detail="Configuration not available")
    if section not in cfg.config:
        raise HTTPException(status_code=404, detail="Section not found")
    values = dict(cfg.config[section])
    overridden = cfg.overridden_keys.get(section, set())
    return {"section": section, "values": values, "overridden_keys": list(overridden)}


@router.put("/{section}")
async def update_section(
    section: str, request: ConfigUpdateRequest, _: None = Depends(admin_guard)
):
    """Validate and apply configuration updates to a section."""
    cfg = get_config()
    if cfg is None:
        raise HTTPException(status_code=503, detail="Configuration not available")
    # Validate all changes
    validation_errors: dict[str, list[str]] = {}
    for key, value in request.updates.items():
        ok, issues = cfg.validate_change(section, key, value)
        if not ok:
            validation_errors[key] = issues
    if validation_errors:
        raise HTTPException(status_code=400, detail={"validation_errors": validation_errors})
    # Apply
    update_method = getattr(cfg, f"update_{section}_config", None)
    if not update_method:
        raise HTTPException(status_code=400, detail="Section not updatable via API")
    try:
        update_method(_change_reason=request.reason, **request.updates)
        return {"success": True, "section": section}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/history")
async def get_config_history(
    section: str | None = None, limit: int = 100, _: None = Depends(admin_guard)
):
    """Get configuration change history."""
    cfg = get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise HTTPException(status_code=503, detail="Configuration store not available")
    hist = cfg.config_store.get_history(section=section, limit=limit)
    return {"history": hist, "count": len(hist)}


@router.get("/versions")
async def list_versions(_: None = Depends(admin_guard)):
    """List configuration versions (metadata only)."""
    cfg = get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise HTTPException(status_code=503, detail="Configuration store not available")
    versions = cfg.config_store.list_versions()
    return {"versions": versions}


@router.post("/versions/{version_number}/restore")
async def restore_version(version_number: int, _: None = Depends(admin_guard)):
    """Restore configuration to a previous version with a safety backup."""
    cfg = get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise HTTPException(status_code=503, detail="Configuration store not available")
    try:
        # Pre-restore backup
        current = cfg._export_full_config()
        cfg.config_store.create_version(
            config_dict=current,
            created_by="system",
            description=f"Pre-restore backup before reverting to v{version_number}",
        )
        # Restore snapshot (returns dict); applying to live config is out of scope here
        cfg.config_store.restore_version(version_number=version_number, restored_by="admin")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {
        "success": True,
        "message": "Configuration restored. Restart may be required.",
        "version": version_number,
    }


@router.get("/drift")
async def detect_drift(_: None = Depends(admin_guard)):
    """Detect configuration drift between base configuration and overrides."""
    cfg = get_config()
    if cfg is None:
        raise HTTPException(status_code=503, detail="Configuration not available")
    drift = cfg.detect_config_drift()
    return {"drift": drift, "has_drift": len(drift) > 0}

