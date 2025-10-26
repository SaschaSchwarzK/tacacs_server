from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from tacacs_server.utils import config_utils
import os


router = APIRouter(prefix="/api/admin/config", tags=["Configuration"])


async def admin_guard(request: Request) -> None:
    # Allow API token header or Bearer token like other API routes
    api_token = os.getenv("API_TOKEN")
    if api_token:
        token = request.headers.get("X-API-Token") or ""
        if not token:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth.removeprefix("Bearer ").strip()
        if token == api_token:
            return
    dep = config_utils.get_admin_auth_dependency_func()
    if dep is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    result = dep(request)
    if asyncio.iscoroutine(result):
        await result  # type: ignore[func-returns-value]


class ConfigUpdateRequest(BaseModel):
    section: str
    updates: dict[str, Any]
    reason: str | None = None


@router.get("/sections")
async def list_sections(_: None = Depends(admin_guard)):
    """List all configuration sections."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise HTTPException(status_code=503, detail="Configuration not available")
    return {"sections": list(cfg.config.sections())}


@router.get("/history")
async def get_config_history(
    section: str | None = None, limit: int = 100, _: None = Depends(admin_guard)
):
    """Get configuration change history."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise HTTPException(status_code=503, detail="Configuration store not available")
    hist = cfg.config_store.get_history(section=section, limit=limit)
    return {"history": hist, "count": len(hist)}


@router.get("/versions")
async def list_versions(_: None = Depends(admin_guard)):
    """List configuration versions (metadata only)."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise HTTPException(status_code=503, detail="Configuration store not available")
    versions = cfg.config_store.list_versions()
    return {"versions": versions}


@router.post("/versions/{version_number}/restore")
async def restore_version(version_number: int, _: None = Depends(admin_guard)):
    """Restore configuration to a previous version with a safety backup."""
    cfg = config_utils.get_config()
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
    cfg = config_utils.get_config()
    if cfg is None:
        raise HTTPException(status_code=503, detail="Configuration not available")
    raw = cfg.detect_config_drift()
    # Consistent, meaningful contract:
    # - No drift -> return an empty list ([])
    # - Drift present -> return a section-keyed mapping (dict)
    if not raw:
        return {"drift": [], "has_drift": False}
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
    return {"drift": drift_map, "has_drift": len(drift_map) > 0}


@router.get("/export")
async def export_config(_: None = Depends(admin_guard)):
    """Export the full effective configuration as JSON."""
    cfg = config_utils.get_config()
    if cfg is None:
        raise HTTPException(status_code=503, detail="Configuration not available")
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
        resp: dict = {"config": data}
        if version_num is not None:
            resp["version"] = version_num
        return resp
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/import")
async def import_config(payload: dict[str, Any], _: None = Depends(admin_guard)):
    """Import configuration snapshot; records a version and returns success."""
    cfg = config_utils.get_config()
    if cfg is None or not getattr(cfg, "config_store", None):
        raise HTTPException(status_code=503, detail="Configuration store not available")
    config_dict = payload.get("config")
    if not isinstance(config_dict, dict):
        raise HTTPException(status_code=400, detail="Missing or invalid 'config' field")
    version = payload.get("version")
    try:
        meta = cfg.config_store.create_version(
            config_dict=config_dict,
            created_by="admin",
            description=f"imported version {version}" if version is not None else "imported config",
            is_baseline=False,
        )
        return {"success": True, "version": meta.get("version_number")}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{section}")
async def get_section(section: str, _: None = Depends(admin_guard)):
    """Get all keys in a section with override indicators."""
    cfg = config_utils.get_config()
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
    cfg = config_utils.get_config()
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
