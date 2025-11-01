from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, cast

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from tacacs_server.backup.destinations import create_destination
from tacacs_server.backup.service import get_backup_service
from tacacs_server.utils.logger import get_logger
from tacacs_server.web.api_models import (
    BackupDeleteResponse,
    BackupDestinationListResponse,
    BackupDestinationModel,
    BackupExecutionDetail,
    BackupExecutionsResponse,
    BackupItem,
    BackupListResponse,
    BackupRestoreResponse,
    BackupScheduleCreateResponse,
    BackupScheduleListResponse,
    BackupScheduleStateResponse,
    BackupScheduleTriggerResponse,
    BackupStatsResponse,
    BackupTestResponse,
    BackupTriggerResponse,
    RetentionPolicyUpdate,
)

from .config import admin_guard

logger = get_logger(__name__)


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


@router.post(
    "/destinations",
    summary="Create backup destination",
    description=(
        "Create a new backup destination and validate connectivity. "
        "Supported types: local, ftp, sftp, azure. The request `config` field "
        "must contain the destination-specific settings."
    ),
)
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


@router.get(
    "/destinations",
    summary="List backup destinations",
    description="Return all configured backup destinations with their parsed configuration.",
    response_model=BackupDestinationListResponse,
)
async def list_destinations(
    _: None = Depends(admin_guard),
) -> BackupDestinationListResponse:
    """List all backup destinations"""
    service = get_backup_service()
    db_rows = service.execution_store.list_destinations()
    items: list[BackupDestinationModel] = []
    for dest in db_rows:
        try:
            cfg = json.loads(dest.get("config_json") or "{}")
        except Exception:
            cfg = {}
        items.append(
            BackupDestinationModel(
                id=str(dest.get("id")),
                name=str(dest.get("name")),
                type=str(dest.get("type")),
                enabled=bool(dest.get("enabled", 1)),
                retention_days=int(dest.get("retention_days", 30)),
                created_at=dest.get("created_at"),
                created_by=dest.get("created_by"),
                last_backup_at=dest.get("last_backup_at"),
                last_backup_status=dest.get("last_backup_status"),
                config=cfg,
            )
        )
    return BackupDestinationListResponse(destinations=items)


@router.get(
    "/destinations/{dest_id}",
    summary="Get destination",
    description="Return a single destination by ID including its parsed configuration.",
)
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


@router.put(
    "/destinations/{dest_id}/retention",
    summary="Update retention policy",
    description=(
        "Update retention policy for a destination. Strategies: simple, gfs, hanoi."
    ),
)
async def update_retention_policy(
    dest_id: str, policy: RetentionPolicyUpdate, _: None = Depends(admin_guard)
):
    """Update retention policy for destination"""
    service = get_backup_service()
    dest = service.execution_store.get_destination(dest_id)
    if not dest:
        raise HTTPException(status_code=404, detail="Destination not found")

    # Validate
    try:
        from tacacs_server.backup.retention import RetentionRule, RetentionStrategy

        strategy = RetentionStrategy(policy.strategy)
        rule_dict = policy.model_dump(exclude_none=True)
        rule_dict.pop("strategy", None)
        RetentionRule(strategy=strategy, **rule_dict)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"Invalid retention configuration: {e}"
        )

    # Persist
    service.execution_store.update_destination(
        dest_id,
        retention_strategy=str(policy.strategy),
        retention_config_json=rule_dict,
    )
    return {
        "success": True,
        "retention_policy": {"strategy": policy.strategy, **rule_dict},
    }


@router.post(
    "/destinations/{dest_id}/apply-retention",
    summary="Trigger retention now",
    description="Manually trigger retention policy enforcement for a destination.",
)
async def apply_retention_now(
    dest_id: str, background_tasks: BackgroundTasks, _: None = Depends(admin_guard)
):
    """Manually trigger retention policy enforcement"""
    service = get_backup_service()
    dest = service.execution_store.get_destination(dest_id)
    if not dest:
        raise HTTPException(status_code=404, detail="Destination not found")

    def run_retention():
        try:
            destination = create_destination(
                dest["type"], json.loads(dest["config_json"])
            )
            from tacacs_server.backup.retention import RetentionRule, RetentionStrategy

            strategy = RetentionStrategy(dest.get("retention_strategy", "simple"))
            cfg_raw = dest.get("retention_config_json") or "{}"
            retention_config = (
                json.loads(cfg_raw) if isinstance(cfg_raw, str) else (cfg_raw or {})
            )
            rule = RetentionRule(strategy=strategy, **(retention_config or {}))
            deleted_count = destination.apply_retention_policy(retention_rule=rule)
            logger.info(
                json.dumps(
                    {
                        "event": "retention_policy_applied",
                        "destination_id": dest_id,
                        "deleted_count": deleted_count,
                    }
                )
            )
        except Exception as e:
            logger.exception("Retention policy enforcement failed: %s", e)

    background_tasks.add_task(run_retention)
    return {
        "success": True,
        "message": "Retention policy enforcement started in background",
    }


@router.put(
    "/destinations/{dest_id}",
    summary="Update destination",
    description=(
        "Update destination properties and/or configuration. If `config` is provided, "
        "connectivity is tested before saving."
    ),
)
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
        dest_type = str(updates.get("type", dest.get("type")))
        cfg = (
            cast(dict[str, Any], updates["config"])
            if isinstance(updates.get("config"), dict)
            else {}
        )
        destination = create_destination(dest_type, cfg)
        ok, msg = destination.test_connection()
        if not ok:
            raise HTTPException(
                status_code=400, detail=f"Connection test failed: {msg}"
            )
        # Ensure JSON persistence
        updates["config_json"] = json.dumps(updates.pop("config"))
    service.execution_store.update_destination(dest_id, **updates)
    return {"success": True}


@router.delete(
    "/destinations/{dest_id}",
    summary="Delete destination",
    description="Delete a destination that has no associated backups/executions.",
)
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


@router.post(
    "/destinations/{dest_id}/test",
    summary="Test destination connectivity",
    description="Run a connectivity check against the specified destination and return the result.",
    response_model=BackupTestResponse,
)
async def test_destination(
    dest_id: str, _: None = Depends(admin_guard)
) -> BackupTestResponse:
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
        return BackupTestResponse(
            success=success, message=message, tested_at=datetime.now(UTC).isoformat()
        )
    except Exception as e:
        return BackupTestResponse(
            success=False, message=str(e), tested_at=datetime.now(UTC).isoformat()
        )


@router.post(
    "/trigger",
    summary="Trigger manual backup",
    description="Start a backup job asynchronously for the specified destination.",
    response_model=BackupTriggerResponse,
)
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
    return BackupTriggerResponse(
        execution_id=execution_id,
        status="started",
        message="Backup job started in background",
    )


@router.get(
    "/executions",
    summary="List backup executions",
    description="Return paginated backup executions with optional status filter.",
    response_model=BackupExecutionsResponse,
)
async def list_executions(
    limit: int = 100,
    offset: int = 0,
    status: str | None = None,
    _: None = Depends(admin_guard),
):
    """List backup executions"""
    service = get_backup_service()
    execs = service.execution_store.list_executions(
        limit=limit, offset=offset, status=status
    )
    return BackupExecutionsResponse(executions=execs, limit=limit, offset=offset)


@router.get(
    "/executions/{execution_id}",
    summary="Get execution details",
    description="Return a single execution, including parsed manifest if present.",
    response_model=BackupExecutionDetail,
)
async def get_execution(
    execution_id: str, _: None = Depends(admin_guard)
) -> BackupExecutionDetail:
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
    return BackupExecutionDetail(**execution)


@router.get(
    "/list",
    summary="List available backups",
    description=(
        "List backups from one or all destinations. If `destination_id` is not provided, "
        "the API aggregates backups across all enabled destinations."
    ),
    response_model=BackupListResponse,
)
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

    all_backups: list[BackupItem] = []
    for dest in destinations or []:
        try:
            destination = create_destination(
                dest["type"], json.loads(dest.get("config_json") or "{}")
            )
            entries = destination.list_backups()
            for b in entries:
                if isinstance(b, dict):
                    item = BackupItem(**b)
                else:
                    item = BackupItem(**b.__dict__)
                item.destination_id = str(dest.get("id"))
                item.destination_name = str(dest.get("name"))
                all_backups.append(item)
        except Exception as e:
            logger.error("Failed to list backups from %s: %s", dest.get("name"), e)
            continue
    try:
        all_backups.sort(key=lambda x: x.timestamp, reverse=True)
    except Exception:
        pass
    return BackupListResponse(backups=all_backups)


@router.post(
    "/restore",
    summary="Restore from backup",
    description=(
        "Restore configuration and databases from a backup path. If `destination_id` is provided, "
        "the backup is downloaded before restore. Set `confirm=true` to proceed."
    ),
    response_model=BackupRestoreResponse,
)
async def restore_backup_api(
    request: RestoreRequest, _: None = Depends(admin_guard)
) -> BackupRestoreResponse:
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
            return BackupRestoreResponse(
                success=True, message=message, restart_required=True
            )
        raise HTTPException(status_code=500, detail=message)
    except Exception as e:
        logger.exception("Restore failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Restore failed: {e}")


@router.delete(
    "/backups",
    summary="Delete a backup",
    description="Delete a backup blob/file at a destination by path.",
    response_model=BackupDeleteResponse,
)
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
    return BackupDeleteResponse(success=True)


@router.get(
    "/schedule",
    summary="Get backup schedule",
    description="Return scheduler status and defined jobs.",
    response_model=BackupScheduleListResponse,
)
async def get_schedule(_: None = Depends(admin_guard)) -> BackupScheduleListResponse:
    """Get backup schedule configuration"""
    service = get_backup_service()
    scheduler = getattr(service, "scheduler", None)
    jobs = scheduler.list_jobs() if scheduler else []
    return BackupScheduleListResponse(
        jobs=jobs, scheduler_running=bool(scheduler and scheduler.scheduler.running)
    )


@router.post(
    "/schedule",
    summary="Create scheduled backup",
    description=(
        "Create a scheduled backup job using a cron expression or interval (unit:value)."
    ),
    response_model=BackupScheduleCreateResponse,
)
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
            from croniter import croniter  # type: ignore[import-untyped]

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
    return BackupScheduleCreateResponse(
        job_id=job_id,
        schedule_type=schedule_type,
        schedule_value=schedule_value,
        destination_id=destination_id,
    )


@router.delete(
    "/schedule/{job_id}",
    summary="Delete scheduled backup",
    description="Remove a scheduled backup job by ID.",
    response_model=BackupScheduleStateResponse,
)
async def delete_scheduled_backup(
    job_id: str, _: None = Depends(admin_guard)
) -> BackupScheduleStateResponse:
    """Delete scheduled backup job"""
    service = get_backup_service()
    scheduler = getattr(service, "scheduler", None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler unavailable")
    if not scheduler.remove_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    return BackupScheduleStateResponse(success=True)


@router.post(
    "/schedule/{job_id}/pause",
    summary="Pause scheduled backup",
    description="Pause a scheduled job without removing it.",
    response_model=BackupScheduleStateResponse,
)
async def pause_scheduled_backup(
    job_id: str, _: None = Depends(admin_guard)
) -> BackupScheduleStateResponse:
    """Pause scheduled backup job"""
    service = get_backup_service()
    scheduler = getattr(service, "scheduler", None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler unavailable")
    if not scheduler.pause_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    return BackupScheduleStateResponse(success=True, status="paused")


@router.post(
    "/schedule/{job_id}/resume",
    summary="Resume scheduled backup",
    description="Resume a paused scheduled job.",
    response_model=BackupScheduleStateResponse,
)
async def resume_scheduled_backup(
    job_id: str, _: None = Depends(admin_guard)
) -> BackupScheduleStateResponse:
    """Resume scheduled backup job"""
    service = get_backup_service()
    scheduler = getattr(service, "scheduler", None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler unavailable")
    if not scheduler.resume_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    return BackupScheduleStateResponse(success=True, status="running")


@router.post(
    "/schedule/{job_id}/trigger",
    summary="Trigger scheduled job now",
    description="Immediately run a scheduled job and return the execution id.",
    response_model=BackupScheduleTriggerResponse,
)
async def trigger_scheduled_job(
    job_id: str, _: None = Depends(admin_guard)
) -> BackupScheduleTriggerResponse:
    """Manually trigger a scheduled job immediately"""
    service = get_backup_service()
    scheduler = getattr(service, "scheduler", None)
    if not scheduler:
        raise HTTPException(status_code=503, detail="Scheduler unavailable")
    execution_id = scheduler.trigger_job_now(job_id)
    return BackupScheduleTriggerResponse(
        execution_id=execution_id, status="triggered", message="Job triggered manually"
    )


@router.get("/stats", response_model=BackupStatsResponse)
async def get_backup_stats(_: None = Depends(admin_guard)) -> BackupStatsResponse:
    """Get high-level statistics about all backups."""
    service = get_backup_service()
    executions = service.execution_store.list_executions(
        limit=10000
    )  # Get all for stats

    total_backups = len(executions)
    if total_backups == 0:
        return BackupStatsResponse(
            total_backups=0,
            total_size_bytes=0,
            success_rate=100.0,
            oldest_backup_at=None,
            newest_backup_at=None,
        )

    total_size = sum(e.get("compressed_size_bytes", 0) or 0 for e in executions)
    successful_backups = sum(1 for e in executions if e["status"] == "completed")
    success_rate = (
        (successful_backups / total_backups) * 100 if total_backups > 0 else 100.0
    )

    sorted_executions = sorted(executions, key=lambda e: e["started_at"])
    oldest = sorted_executions[0]["started_at"]
    newest = sorted_executions[-1]["started_at"]

    return BackupStatsResponse(
        total_backups=total_backups,
        total_size_bytes=total_size,
        success_rate=round(success_rate, 2),
        oldest_backup_at=oldest,
        newest_backup_at=newest,
    )
