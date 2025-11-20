from __future__ import annotations

import json
import os
import threading
import traceback
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger

from tacacs_server.utils.logger import get_logger


class ExecutionStoreProtocol(Protocol):
    def list_destinations(
        self, *, enabled_only: bool
    ) -> list[dict[str, Any]] | None: ...


class BackupServiceProtocol(Protocol):
    execution_store: ExecutionStoreProtocol

    def execute_backup(
        self,
        destination_id: str,
        *,
        triggered_by: str,
        backup_type: str = ...,
        execution_id: str | None = ...,
    ) -> str: ...


_SCHEDULERS: dict[str, BackupScheduler] = {}

_log = get_logger(__name__)


def _execute_job_static(
    reg_id: str,
    job_id: str,
    destination_id: str | None,
    execution_id: str | None = None,
) -> None:
    sch = _SCHEDULERS.get(reg_id)
    if not sch:
        _log.warning(
            "Scheduler registry missing entry",
            registry_id=reg_id,
            job_id=job_id,
        )
        return
    sch._execute_job_impl(job_id, destination_id, execution_id)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class BackupScheduler:
    """Backup job scheduler using APScheduler with persistent jobstore.

    Jobs persist across restarts in data/backup_jobs.db. Minimal metadata is
    stored in a sidecar JSON file to track created_by/created_at and failure
    counts in a scheduler-agnostic way.
    """

    def __init__(self, backup_service: BackupServiceProtocol) -> None:
        self.backup_service = backup_service
        os.makedirs("data", exist_ok=True)
        self._meta_path = os.path.join("data", "backup_jobs_meta.json")
        self._meta_lock = threading.RLock()
        self._metadata: dict[str, Any] = self._load_metadata()
        self._executions: dict[str, dict[str, Any]] = {}
        self._registry_id: str = str(id(self))
        _SCHEDULERS[self._registry_id] = self

        jobstores = {"default": SQLAlchemyJobStore(url="sqlite:///data/backup_jobs.db")}
        executors = {"default": ThreadPoolExecutor(max_workers=4)}
        job_defaults = {"coalesce": False, "max_instances": 1, "misfire_grace_time": 60}
        self.scheduler = BackgroundScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
            timezone=UTC,
        )

    # --- metadata helpers ---
    def _load_metadata(self) -> dict[str, Any]:
        try:
            if os.path.exists(self._meta_path):
                with open(self._meta_path, encoding="utf-8") as fh:
                    data = json.load(fh)
                    # Ensure dict shape for typing
                    if isinstance(data, dict):
                        return data
        except Exception as exc:
            _log.warning(
                "Failed to load scheduler metadata",
                error=str(exc),
                meta_path=self._meta_path,
            )
        return {"jobs": {}}

    def _save_metadata(self) -> None:
        try:
            with self._meta_lock:
                with open(self._meta_path, "w", encoding="utf-8") as fh:
                    json.dump(self._metadata, fh, indent=2, sort_keys=True)
        except Exception as exc:
            _log.warning(
                "Failed to persist scheduler metadata",
                error=str(exc),
                meta_path=self._meta_path,
            )

    # --- lifecycle ---
    def start(self) -> None:
        """Start the scheduler and add system jobs."""
        if not self.scheduler.running:
            self.scheduler.start()
        # Daily retention enforcement at 04:00
        try:
            self.scheduler.add_job(
                func=self._run_retention_enforcement,
                trigger=CronTrigger(hour=4, minute=0, timezone=UTC),
                id="retention_enforcement",
                name="Daily Retention Policy Enforcement",
                replace_existing=True,
                max_instances=1,
            )
            _log.info(
                "Scheduled daily retention policy enforcement",
                event="retention_schedule_initialized",
                schedule="0 4 * * *",
            )
        except Exception as exc:
            _log.warning(
                "Failed to schedule daily retention enforcement job",
                error=str(exc),
            )

    def stop(self) -> None:
        try:
            self.scheduler.shutdown(wait=False)
        except Exception as exc:
            _log.warning("Failed to shut down scheduler", error=str(exc))
        try:
            _SCHEDULERS.pop(self._registry_id, None)
        except Exception as exc:
            _log.warning(
                "Failed to remove scheduler registry entry",
                error=str(exc),
                registry_id=self._registry_id,
            )

    # --- job management ---
    def add_job(
        self,
        job_id: str,
        schedule_type: str,
        schedule_value: str,
        destination_id: str | None = None,
        *,
        created_by: str = "system",
    ) -> str:
        """Add a new job (cron/interval/manual). Returns job_id."""
        schedule_type = schedule_type.lower()
        if schedule_type not in {"cron", "interval", "manual"}:
            raise ValueError("Unsupported schedule_type")
        # Persist minimal job meta
        with self._meta_lock:
            self._metadata.setdefault("jobs", {})[job_id] = {
                "created_by": created_by,
                "created_at": _utc_now().isoformat(),
                "schedule_type": schedule_type,
                "schedule_value": schedule_value,
                "destination_id": destination_id,
                "failure_count": 0,
                "status": "scheduled" if schedule_type != "manual" else "manual",
            }
            self._save_metadata()

        if schedule_type == "manual":
            # do not schedule; manual trigger only
            return job_id

        if schedule_type == "cron":
            trigger = CronTrigger.from_crontab(schedule_value, timezone=UTC)
        else:  # interval
            # format: "hours:24" or "days:1" or "minutes:15"
            try:
                k, v = schedule_value.split(":", 1)
                kwargs = {k.strip(): int(v.strip())}
            except Exception as exc:
                raise ValueError(
                    f"Invalid interval schedule_value: {schedule_value}"
                ) from exc
            trigger = IntervalTrigger(timezone=UTC, **kwargs)

        self.scheduler.add_job(
            _execute_job_static,
            trigger=trigger,
            id=job_id,
            args=[self._registry_id, job_id, destination_id],
            replace_existing=True,
            max_instances=1,
        )
        return job_id

    def remove_job(self, job_id: str) -> bool:
        try:
            self.scheduler.remove_job(job_id)
        except Exception as exc:
            _log.warning("Failed to remove job %s: %s", job_id, exc)
        with self._meta_lock:
            removed = self._metadata.get("jobs", {}).pop(job_id, None) is not None
            self._save_metadata()
            return removed

    def pause_job(self, job_id: str) -> bool:
        try:
            self.scheduler.pause_job(job_id)
            with self._meta_lock:
                if job_id in self._metadata.get("jobs", {}):
                    self._metadata["jobs"][job_id]["status"] = "paused"
                    self._save_metadata()
            return True
        except Exception as exc:
            _log.warning("Failed to pause job %s: %s", job_id, exc)
            return False

    def resume_job(self, job_id: str) -> bool:
        try:
            self.scheduler.resume_job(job_id)
            with self._meta_lock:
                if job_id in self._metadata.get("jobs", {}):
                    self._metadata["jobs"][job_id]["status"] = "scheduled"
                    self._save_metadata()
            return True
        except Exception as exc:
            _log.warning("Failed to resume job %s: %s", job_id, exc)
            return False

    def trigger_job_now(self, job_id: str) -> str:
        exec_id = str(uuid.uuid4())
        job_meta = self._metadata.get("jobs", {}).get(job_id) or {}
        dest = job_meta.get("destination_id")
        run_time = _utc_now() + timedelta(seconds=1)
        self.scheduler.add_job(
            _execute_job_static,
            trigger=DateTrigger(run_date=run_time),
            id=f"{job_id}__{exec_id}",
            args=[self._registry_id, job_id, dest, exec_id],
            replace_existing=False,
            max_instances=1,
        )
        return exec_id

    def get_job_status(self, job_id: str) -> dict[str, Any]:
        job = self.scheduler.get_job(job_id)
        # Ensure a concrete dict for typing
        meta: dict[str, Any] = dict(self._metadata.get("jobs", {}).get(job_id, {}))
        meta["job_id"] = job_id
        meta["next_run"] = (
            job.next_run_time.isoformat() if job and job.next_run_time else None
        )
        meta["pending"] = job is not None
        return meta

    def list_jobs(self) -> list[dict[str, Any]]:
        jobs = []
        ids = set()
        for job in self.scheduler.get_jobs():
            jid = job.id
            ids.add(jid)
            item = self._metadata.get("jobs", {}).get(jid, {}).copy()
            item["job_id"] = jid
            item["next_run"] = (
                job.next_run_time.isoformat() if job.next_run_time else None
            )
            jobs.append(item)
        # Include manual jobs which won't exist in scheduler
        for jid, meta in (self._metadata.get("jobs", {}) or {}).items():
            if jid not in ids and meta.get("schedule_type") == "manual":
                item = meta.copy()
                item["job_id"] = jid
                item["next_run"] = None
                jobs.append(item)
        return sorted(jobs, key=lambda x: x.get("job_id", ""))

    # --- retention enforcement ---
    def _run_retention_enforcement(self) -> None:
        """Run retention policy enforcement for all enabled destinations."""
        _log.info("Starting retention enforcement", event="retention_enforcement_start")
        try:
            destinations = self.backup_service.execution_store.list_destinations(
                enabled_only=True
            )
            for dest in destinations or []:
                try:
                    # Lazy imports to avoid heavy deps on scheduler import
                    from tacacs_server.backup.destinations import (
                        create_destination as _create_dest,
                    )
                    from tacacs_server.backup.retention import (
                        RetentionRule as _Rule,
                    )
                    from tacacs_server.backup.retention import (
                        RetentionStrategy as _Strat,
                    )

                    destination = _create_dest(
                        dest["type"], json.loads(dest.get("config_json") or "{}")
                    )

                    strat = _Strat(dest.get("retention_strategy", "simple"))
                    cfg_raw = dest.get("retention_config_json") or "{}"
                    retention_cfg = (
                        json.loads(cfg_raw)
                        if isinstance(cfg_raw, str)
                        else (cfg_raw or {})
                    )
                    rule = _Rule(strategy=strat, **(retention_cfg or {}))
                    deleted_count = destination.apply_retention_policy(
                        retention_rule=rule
                    )
                    _log.info(
                        "Retention enforcement completed",
                        event="retention_enforcement_completed",
                        destination_id=dest.get("id"),
                        destination_name=dest.get("name"),
                        deleted_count=deleted_count,
                    )
                except Exception as e:
                    _log.error(
                        "Retention enforcement failed for destination",
                        error=str(e),
                        destination_id=dest.get("id"),
                        destination_name=dest.get("name"),
                    )
                    continue
        except Exception as e:  # pragma: no cover - logging path
            _log.exception("Global retention enforcement failed", error=str(e))
        finally:
            _log.info(
                "Retention enforcement finished", event="retention_enforcement_end"
            )

    # --- execution handler ---
    def _execute_job_impl(
        self, job_id: str, destination_id: str | None, execution_id: str | None = None
    ) -> None:
        exec_id = execution_id or str(uuid.uuid4())
        start = _utc_now()
        ok = False
        err = None
        _log.info(
            "Executing scheduled backup job",
            event="backup_job_started",
            job_id=job_id,
            destination_id=destination_id,
            execution_id=exec_id,
        )
        try:
            self._executions[exec_id] = {
                "job_id": job_id,
                "destination_id": destination_id,
                "start_time": start.isoformat(),
                "status": "running",
            }
            self.backup_service.execute_backup(
                destination_id or "", triggered_by="scheduler"
            )
            ok = True
        except Exception as e:
            err = f"{e}\n{traceback.format_exc()}"
            _log.warning(
                "Scheduled backup job failed",
                event="backup_job_failed",
                job_id=job_id,
                destination_id=destination_id,
                execution_id=exec_id,
                error=str(e),
            )
        finally:
            end = _utc_now()
            info = self._executions.get(exec_id, {})
            info.update(
                {
                    "end_time": end.isoformat(),
                    "status": "success" if ok else "failed",
                    "error": err,
                }
            )
            self._executions[exec_id] = info
            # update job meta
            with self._meta_lock:
                jm = self._metadata.get("jobs", {}).get(job_id, {})
                jm["last_run"] = end.isoformat()
                # exponential backoff if failed
                if not ok:
                    fails = int(jm.get("failure_count", 0)) + 1
                    jm["failure_count"] = fails
                    # schedule a one-off retry (capped)
                    delay = min(3600, 30 * (2 ** min(fails, 6)))
                    run_time = _utc_now() + timedelta(seconds=delay)
                    self.scheduler.add_job(
                        self._execute_job_impl,
                        trigger=DateTrigger(run_date=run_time),
                        id=f"{job_id}__retry__{fails}",
                        args=[job_id, destination_id],
                        replace_existing=False,
                        max_instances=1,
                    )
                else:
                    jm["failure_count"] = 0
                self._metadata["jobs"][job_id] = jm
                self._save_metadata()
            _log.info(
                "Scheduled backup job finished",
                event="backup_job_finished",
                job_id=job_id,
                destination_id=destination_id,
                execution_id=exec_id,
                status="success" if ok else "failed",
                duration_seconds=(end - start).total_seconds(),
            )
