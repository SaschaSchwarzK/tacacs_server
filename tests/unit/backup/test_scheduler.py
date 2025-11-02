import os
import time
from pathlib import Path

import pytest

from tacacs_server.backup.scheduler import BackupScheduler


class DummyBackupService:
    def __init__(self):
        self.calls: list[dict] = []
        self.fail_next: bool = False

    def execute_backup(self, destination_id, triggered_by: str = "scheduler"):
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("boom")
        self.calls.append(
            {
                "destination_id": destination_id,
                "triggered_by": triggered_by,
                "t": time.time(),
            }
        )


def _mk_scheduler(tmp: Path, svc: DummyBackupService) -> BackupScheduler:
    # Ensure the default jobstore path lives under tmp by chdir
    os.chdir(tmp)
    (tmp / "data").mkdir(exist_ok=True)
    sch = BackupScheduler(svc)
    sch.start()
    return sch


def test_job_management_add_remove_pause_resume_list(tmp_path: Path):
    svc = DummyBackupService()
    sch = _mk_scheduler(tmp_path, svc)
    try:
        job_id = sch.add_job(
            job_id="job1",
            schedule_type="interval",
            schedule_value="seconds:5",
            destination_id="destA",
            created_by="tester",
        )
        assert job_id == "job1"
        listed = sch.list_jobs()
        assert any(j.get("job_id") == job_id for j in listed)
        # Pause and resume
        assert sch.pause_job(job_id) is True
        meta = sch.get_job_status(job_id)
        assert meta.get("status") == "paused"
        assert sch.resume_job(job_id) is True
        meta2 = sch.get_job_status(job_id)
        assert meta2.get("status") in ("scheduled", "manual")
        # Remove
        assert sch.remove_job(job_id) is True
        assert all(j.get("job_id") != job_id for j in sch.list_jobs())
    finally:
        sch.stop()


def test_persistence_across_restarts(tmp_path: Path):
    svc = DummyBackupService()
    sch = _mk_scheduler(tmp_path, svc)
    try:
        sch.add_job("persist1", "interval", "seconds:30", destination_id=None)
    finally:
        sch.stop()
    # Restart new scheduler with same working dir/jobstore
    svc2 = DummyBackupService()
    sch2 = _mk_scheduler(tmp_path, svc2)
    try:
        jobs = sch2.list_jobs()
        assert any(j.get("job_id") == "persist1" for j in jobs)
    finally:
        sch2.stop()


@pytest.mark.flaky(reruns=1)
def test_schedule_execution_interval_and_cron(tmp_path: Path):
    svc = DummyBackupService()
    sch = _mk_scheduler(tmp_path, svc)
    try:
        # Interval every second
        sch.add_job("int1", "interval", "seconds:1", destination_id="D1")
        # Cron: next minute; we won't wait, but ensure job is registered
        sch.add_job("cron1", "cron", "* * * * *", destination_id="D2")
        # Allow a couple of seconds to tick
        time.sleep(2.2)
        # At least one call should be recorded from interval
        assert any(c.get("destination_id") == "D1" for c in svc.calls)
        # Ensure max_instances=1 prevents overlap (no insane growth in short time)
        assert len(svc.calls) < 5
    finally:
        sch.stop()


def test_failed_jobs_logged_and_backoff(tmp_path: Path):
    svc = DummyBackupService()
    sch = _mk_scheduler(tmp_path, svc)
    try:
        sch.add_job("failjob", "interval", "seconds:1", destination_id="D3")
        # Make next run fail
        svc.fail_next = True
        time.sleep(1.5)
        # Metadata should track failure_count >= 1
        meta = sch._metadata.get("jobs", {}).get("failjob", {})
        assert int(meta.get("failure_count", 0)) >= 1
    finally:
        sch.stop()


def test_manual_trigger_returns_exec_id(tmp_path: Path):
    svc = DummyBackupService()
    sch = _mk_scheduler(tmp_path, svc)
    try:
        sch.add_job("manjob", "manual", "-", destination_id="D4")
        exec_id = sch.trigger_job_now("manjob")
        assert isinstance(exec_id, str) and exec_id
        # job remains listed as manual with no next run
        jobs = sch.list_jobs()
        mj = next(j for j in jobs if j.get("job_id") == "manjob")
        assert mj.get("schedule_type") == "manual"
        assert mj.get("next_run") is None
    finally:
        sch.stop()
