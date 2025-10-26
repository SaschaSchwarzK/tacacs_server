from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from tacacs_server.backup.destinations import create_destination
from tacacs_server.backup.service import get_backup_service

from .config import admin_guard

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/api/admin/backup", tags=["Backup"])


class DestinationCreate(BaseModel):
    name: str
    type: str  # local, ftp, sftp, azure
    config: dict[str, Any]
    retention_days: int = 30


class BackupTriggerRequest(BaseModel):
    destination_id: str
    comment: str | None = None


class RestoreRequest(BaseModel):
    backup_path: str
    destination_id: str | None = None
    components: list[str] | None = None  # ["config", "devices", "users"]
    confirm: bool = False


@router.post("/destinations")
async def create_destination_api(
    request: DestinationCreate, _: None = Depends(admin_guard)
):
    """Create new backup destination"""
    service = get_backup_service()

    # Validate destination config
    try:
        destination = create_destination(request.type, request.config)
        success, message = destination.test_connection()
        if not success:
            raise HTTPException(
                status_code=400, detail=f"Connection test failed: {message}"
            )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Store destination
    dest_id = service.execution_store.create_destination(
        name=request.name,
        dest_type=request.type,
        config=request.config,
        retention_days=request.retention_days,
        created_by="admin",  # TODO: Extract from auth context
    )

    return {
        "id": dest_id,
        "name": request.name,
        "type": request.type,
        "connection_test": "passed",
    }


@router.get("/destinations")
async def list_destinations(_: None = Depends(admin_guard)):
    """List all backup destinations"""
    service = get_backup_service()
    destinations = service.execution_store.list_destinations()
    # Add parsed config
    for dest in destinations:
        try:
            dest["config"] = json.loads(dest.get("config_json") or "{}")
        except Exception:
            dest["config"] = {}
        dest.pop("config_json", None)
    return {"destinations": destinations}


@router.get("/destinations/{dest_id}")
async def get_destination_api(dest_id: str, _: None = Depends(admin_guard)):
    """Get destination details"""
    service = get_backup_service()
    dest = service.execution_store.get_destination(dest_id)
    if not dest:
        raise HTTPException(status_code=404, detail="Destination not found")
    try:
        dest["config"] = json.loads(dest.get("config_json") or "{}")
    except Exception:
        dest["config"] = {}
    dest.pop("config_json", None)
    return dest


@router.put("/destinations/{dest_id}")
async def update_destination(
    dest_id: str, updates: dict[str, Any], _: None = Depends(admin_guard)
):
    """Update destination configuration"""
    service = get_backup_service()
    dest = service.execution_store.get_destination(dest_id)
    if not dest:
        raise HTTPException(status_code=404, detail="Destination not found")
    # Test connection if config changed
    if "config" in updates:
        dest_type = updates.get("type", dest.get("type"))
        destination = create_destination(dest_type, updates["config"])  # type: ignore[arg-type]
        ok, msg = destination.test_connection()
        if not ok:
            raise HTTPException(
                status_code=400, detail=f"Connection test failed: {msg}"
            )
        # Ensure JSON persistence
        updates["config_json"] = json.dumps(updates.pop("config"))
    service.execution_store.update_destination(dest_id, **updates)
    return {"success": True}


@router.delete("/destinations/{dest_id}")
async def delete_destination(dest_id: str, _: None = Depends(admin_guard)):
    """Delete backup destination"""
    service = get_backup_service()
    executions = service.execution_store.list_executions()
    if any(e.get("destination_id") == dest_id for e in executions):
        raise HTTPException(
            status_code=400, detail="Cannot delete destination with existing backups"
        )
    if not service.execution_store.delete_destination(dest_id):
        raise HTTPException(status_code=404, detail="Destination not found")
    return {"success": True}


@router.post("/destinations/{dest_id}/test")
async def test_destination(dest_id: str, _: None = Depends(admin_guard)):
    """Test destination connectivity"""
    service = get_backup_service()
    dest = service.execution_store.get_destination(dest_id)
    if not dest:
        raise HTTPException(status_code=404, detail="Destination not found")
    try:
        destination = create_destination(
            dest["type"], json.loads(dest.get("config_json") or "{}")
        )
        success, message = destination.test_connection()
        return {
            "success": success,
            "message": message,
            "tested_at": datetime.now(UTC).isoformat(),
        }
    except Exception as e:
        return {
            "success": False,
            "message": str(e),
            "tested_at": datetime.now(UTC).isoformat(),
        }


@router.post("/trigger")
async def trigger_backup(
    request: BackupTriggerRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(admin_guard),
):
    """Trigger manual backup"""
    service = get_backup_service()
    dest = service.execution_store.get_destination(request.destination_id)
    if not dest:
        raise HTTPException(status_code=404, detail="Destination not found")

    execution_id = str(uuid.uuid4())

    def run_backup() -> None:
        try:
            service.execute_backup(
                destination_id=request.destination_id,
                triggered_by="manual:admin",
                backup_type="manual",
                execution_id=execution_id,
            )
        except Exception as e:
            logger.exception("Background backup failed: %s", e)

    background_tasks.add_task(run_backup)
    return {
        "execution_id": execution_id,
        "status": "started",
        "message": "Backup job started in background",
    }


@router.get("/executions")
async def list_executions(
    limit: int = 100,
    offset: int = 0,
    status: str | None = None,
    _: None = Depends(admin_guard),
):
    """List backup executions"""
    service = get_backup_service()
    executions = service.execution_store.list_executions(
        limit=limit, offset=offset, status=status
    )
    return {"executions": executions, "limit": limit, "offset": offset}


@router.get("/executions/{execution_id}")
async def get_execution(execution_id: str, _: None = Depends(admin_guard)):
    """Get execution status and details"""
    service = get_backup_service()
    execution = service.execution_store.get_execution(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    if execution.get("manifest_json"):
        try:
            execution["manifest"] = json.loads(execution.get("manifest_json") or "{}")
        except Exception:
            execution["manifest"] = {}
        execution.pop("manifest_json", None)
    return execution


@router.get("/list")
async def list_backups(
    destination_id: str | None = None, _: None = Depends(admin_guard)
):
    """List available backups from destination(s)"""
    service = get_backup_service()
    if destination_id:
        dest = service.execution_store.get_destination(destination_id)
        if not dest:
            raise HTTPException(status_code=404, detail="Destination not found")
        destinations = [dest]
    else:
        destinations = service.execution_store.list_destinations(enabled_only=True)

    all_backups: list[dict[str, Any]] = []
    for dest in destinations or []:
        try:
            destination = create_destination(
                dest["type"], json.loads(dest.get("config_json") or "{}")
            )
            backups = destination.list_backups()
            for backup in backups:
                # Enrich with destination info when possible
                if isinstance(backup, dict):
                    backup["destination_id"] = dest.get("id")
                    backup["destination_name"] = dest.get("name")
            all_backups.extend(backups)  # type: ignore[arg-type]
        except Exception as e:
            logger.error("Failed to list backups from %s: %s", dest.get("name"), e)
            continue
    try:
        all_backups.sort(key=lambda x: x.get("timestamp"), reverse=True)
    except Exception:
        pass
    return {"backups": all_backups}


@router.post("/restore")
async def restore_backup_api(request: RestoreRequest, _: None = Depends(admin_guard)):
    """Restore from backup"""
    if not request.confirm:
        raise HTTPException(
            status_code=400, detail="Must set confirm=true to proceed with restore"
        )
    service = get_backup_service()
    # Validate backup exists
    if request.destination_id:
        dest = service.execution_store.get_destination(request.destination_id)
        if not dest:
            raise HTTPException(status_code=404, detail="Destination not found")
        destination = create_destination(
            dest["type"], json.loads(dest.get("config_json") or "{}")
        )
        if not destination.get_backup_info(request.backup_path):
            raise HTTPException(
                status_code=404, detail="Backup not found at destination"
            )
    try:
        success, message = service.restore_backup(
            source_path=request.backup_path,
            destination_id=request.destination_id,
            components=request.components,
        )
        if success:
            return {"success": True, "message": message, "restart_required": True}
        raise HTTPException(status_code=500, detail=message)
    except Exception as e:
        logger.exception("Restore failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Restore failed: {e}")


@router.delete("/backups")
async def delete_backup(
    backup_path: str, destination_id: str, _: None = Depends(admin_guard)
):
    """Delete a backup from destination"""
    service = get_backup_service()
    dest = service.execution_store.get_destination(destination_id)
    if not dest:
        raise HTTPException(status_code=404, detail="Destination not found")
    destination = create_destination(
        dest["type"], json.loads(dest.get("config_json") or "{}")
    )
    if not destination.delete_backup(backup_path):
        raise HTTPException(
            status_code=404, detail="Backup not found or deletion failed"
        )
    return {"success": True}


@router.get("/schedule")
async def get_schedule(_: None = Depends(admin_guard)):
    """Get backup schedule configuration"""
    service = get_backup_service()
    scheduler = getattr(service, "scheduler", None)
    jobs = scheduler.list_jobs() if scheduler else []
    return {
        "jobs": jobs,
        "scheduler_running": bool(scheduler and scheduler.scheduler.running),
    }


@router.post("/schedule")
async def create_scheduled_backup(
    destination_id: str,
    schedule_type: str,
    schedule_value: str,
    job_name: str | None = None,
    _: None = Depends(admin_guard),
):
    """Create scheduled backup job"""
    service = get_backup_service()
    dest = service.execution_store.get_destination(destination_id)
    if not dest:
        raise HTTPException(status_code=404, detail="Destination not found")
    # Validate schedule
    if schedule_type == "cron":
        try:
            from croniter import croniter

            if not croniter.is_valid(schedule_value):
                raise HTTPException(status_code=400, detail="Invalid cron expression")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid cron expression")
    elif schedule_type == "interval":
        try:
            unit, value = schedule_value.split(":")
            if unit not in ["hours", "days", "weeks", "minutes", "seconds"]:
                raise ValueError()
            int(value)
        except Exception:
            raise HTTPException(
                status_code=400, detail="Invalid interval format (use 'unit:value')"
            )
    else:
        raise HTTPException(
            status_code=400, detail="schedule_type must be 'cron' or 'interval'"
        )
    scheduler = getattr(service, "scheduler", None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler unavailable")
    job_id = scheduler.add_job(
        job_id=job_name or f"backup_{destination_id}_{schedule_type}",
        schedule_type=schedule_type,
        schedule_value=schedule_value,
        destination_id=destination_id,
    )
    return {
        "job_id": job_id,
        "schedule_type": schedule_type,
        "schedule_value": schedule_value,
        "destination_id": destination_id,
    }


@router.delete("/schedule/{job_id}")
async def delete_scheduled_backup(job_id: str, _: None = Depends(admin_guard)):
    """Delete scheduled backup job"""
    service = get_backup_service()
    scheduler = getattr(service, "scheduler", None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler unavailable")
    if not scheduler.remove_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    return {"success": True}


@router.post("/schedule/{job_id}/pause")
async def pause_scheduled_backup(job_id: str, _: None = Depends(admin_guard)):
    """Pause scheduled backup job"""
    service = get_backup_service()
    scheduler = getattr(service, "scheduler", None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler unavailable")
    if not scheduler.pause_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    return {"success": True, "status": "paused"}


@router.post("/schedule/{job_id}/resume")
async def resume_scheduled_backup(job_id: str, _: None = Depends(admin_guard)):
    """Resume scheduled backup job"""
    service = get_backup_service()
    scheduler = getattr(service, "scheduler", None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler unavailable")
    if not scheduler.resume_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    return {"success": True, "status": "running"}


@router.post("/schedule/{job_id}/trigger")
async def trigger_scheduled_job(job_id: str, _: None = Depends(admin_guard)):
    """Manually trigger a scheduled job immediately"""
    service = get_backup_service()
    scheduler = getattr(service, "scheduler", None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler unavailable")
    execution_id = scheduler.trigger_job_now(job_id)
    return {
        "execution_id": execution_id,
        "status": "triggered",
        "message": "Job triggered manually",
    }
