from __future__ import annotations

import json
import os
import threading
import traceback
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger

# Registry to avoid pickling bound methods (APScheduler jobstores pickle callables)
_SCHEDULERS: dict[str, BackupScheduler] = {}


def _execute_job_static(
    reg_id: str,
    job_id: str,
    destination_id: str | None,
    execution_id: str | None = None,
) -> None:
    sch = _SCHEDULERS.get(reg_id)
    if not sch:
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

    def __init__(self, backup_service: BackupService) -> None:
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
                    return json.load(fh)
        except Exception:
            pass
        return {"jobs": {}}

    def _save_metadata(self) -> None:
        try:
            with self._meta_lock:
                with open(self._meta_path, "w", encoding="utf-8") as fh:
                    json.dump(self._metadata, fh, indent=2, sort_keys=True)
        except Exception:
            pass

    # --- lifecycle ---
    def start(self) -> None:
        if not self.scheduler.running:
            self.scheduler.start()

    def stop(self) -> None:
        try:
            self.scheduler.shutdown(wait=False)
        except Exception:
            pass
        try:
            _SCHEDULERS.pop(self._registry_id, None)
        except Exception:
            pass

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
        except Exception:
            pass
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
        except Exception:
            return False

    def resume_job(self, job_id: str) -> bool:
        try:
            self.scheduler.resume_job(job_id)
            with self._meta_lock:
                if job_id in self._metadata.get("jobs", {}):
                    self._metadata["jobs"][job_id]["status"] = "scheduled"
                    self._save_metadata()
            return True
        except Exception:
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

    def get_job_status(self, job_id: str) -> dict:
        job = self.scheduler.get_job(job_id)
        meta = self._metadata.get("jobs", {}).get(job_id, {}).copy()
        meta["job_id"] = job_id
        meta["next_run"] = (
            job.next_run_time.isoformat() if job and job.next_run_time else None
        )
        meta["pending"] = job is not None
        return meta

    def list_jobs(self) -> list[dict]:
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

    # --- execution handler ---
    def _execute_job_impl(
        self, job_id: str, destination_id: str | None, execution_id: str | None = None
    ) -> None:
        exec_id = execution_id or str(uuid.uuid4())
        start = _utc_now()
        ok = False
        err = None
        try:
            self._executions[exec_id] = {
                "job_id": job_id,
                "destination_id": destination_id,
                "start_time": start.isoformat(),
                "status": "running",
            }
            self.backup_service.execute_backup(destination_id, triggered_by="scheduler")
            ok = True
        except Exception as e:
            err = f"{e}\n{traceback.format_exc()}"
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
                        self._execute_job,
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
