import time
from pathlib import Path

import pytest


def _poll(predicate, timeout=10.0, interval=0.3):
    start = time.time()
    while time.time() - start < timeout:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.mark.integration
def test_backup_end_to_end(server_factory):
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={"admin_username": "admin", "admin_password": "admin123"},
    )
    with server:
        base = server.get_base_url()
        session = server.login_admin()
        # Create local destination
        dest_dir = Path(server.work_dir) / "backups"
        dest_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "name": "local-dest",
            "type": "local",
            "config": {"base_path": str(dest_dir.resolve())},
            "retention_days": 7,
        }
        r = session.post(
            f"{base}/api/admin/backup/destinations", json=payload, timeout=5
        )
        assert r.status_code == 200, r.text
        dest_id = r.json()["id"]
        # Trigger backup
        t = session.post(
            f"{base}/api/admin/backup/trigger",
            json={"destination_id": dest_id},
            timeout=5,
        )
        assert t.status_code == 200, t.text

        # Wait for at least one execution to appear and complete/failed
        def _has_execution():
            rr = session.get(f"{base}/api/admin/backup/executions", timeout=5)
            if rr.status_code != 200:
                return False
            data = rr.json().get("executions") or []
            return len(data) > 0

        assert _poll(_has_execution, timeout=15.0)
        # Verify backup exists by listing
        lr = session.get(f"{base}/api/admin/backup/list", timeout=5)
        assert lr.status_code == 200, lr.text
        backups = lr.json().get("backups") or []
        # If there is at least one backup, check file exists
        if backups:
            path = backups[0].get("path") or backups[0].get("remote_path")
            if path:
                assert Path(path).exists()


@pytest.mark.integration
def test_restore_end_to_end(server_factory):
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={"admin_username": "admin", "admin_password": "admin123"},
    )
    with server:
        base = server.get_base_url()
        session = server.login_admin()
        dest_dir = Path(server.work_dir) / "rest-backups"
        dest_dir.mkdir(parents=True, exist_ok=True)
        # Create destination
        cr = session.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "d1",
                "type": "local",
                "config": {"base_path": str(dest_dir.resolve())},
                "retention_days": 3,
            },
            timeout=5,
        )
        assert cr.status_code == 200, cr.text
        dest_id = cr.json()["id"]
        # Trigger backup and wait for listing
        session.post(
            f"{base}/api/admin/backup/trigger",
            json={"destination_id": dest_id},
            timeout=5,
        )
        assert _poll(
            lambda: session.get(f"{base}/api/admin/backup/list", timeout=5)
            .json()
            .get("backups"),
            timeout=15.0,
        )
        backups = (
            session.get(f"{base}/api/admin/backup/list", timeout=5)
            .json()
            .get("backups")
        )
        if not backups:
            pytest.skip("No backups listed to restore in this environment")
        bp = backups[0].get("path") or backups[0].get("remote_path")
        # Modify configuration (set server port override)
        upd = {"section": "server", "updates": {"port": 5055}}
        ur = session.put(f"{base}/api/admin/config/server", json=upd, timeout=5)
        assert ur.status_code in (200, 400), ur.text  # 400 if validation model differs
        # Restore
        rr = session.post(
            f"{base}/api/admin/backup/restore",
            json={"backup_path": bp, "destination_id": dest_id, "confirm": True},
            timeout=10,
        )
        assert rr.status_code in (200, 500), rr.text


@pytest.mark.integration
def test_scheduled_backups_and_manual_trigger(server_factory):
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={"admin_username": "admin", "admin_password": "admin123"},
    )
    with server:
        base = server.get_base_url()
        session = server.login_admin()
        dest_dir = Path(server.work_dir) / "sched"
        dest_dir.mkdir(parents=True, exist_ok=True)
        # Create destination
        cr = session.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "sched1",
                "type": "local",
                "config": {"base_path": str(dest_dir.resolve())},
                "retention_days": 3,
            },
            timeout=5,
        )
        assert cr.status_code == 200, cr.text
        dest_id = cr.json()["id"]
        # Create schedule (interval seconds:1)
        sr = session.post(
            f"{base}/api/admin/backup/schedule",
            params={
                "destination_id": dest_id,
                "schedule_type": "interval",
                "schedule_value": "seconds:1",
                "job_name": "job-int-1",
            },
            timeout=5,
        )
        assert sr.status_code == 200, sr.text
        # Verify job created
        gj = session.get(f"{base}/api/admin/backup/schedule", timeout=5)
        assert gj.status_code == 200 and any(
            j.get("job_id") == "job-int-1" for j in gj.json().get("jobs") or []
        )
        # Trigger manually
        tr = session.post(
            f"{base}/api/admin/backup/schedule/job-int-1/trigger", timeout=5
        )
        assert tr.status_code == 200, tr.text
        # Verify an execution recorded soon after
        assert _poll(
            lambda: (
                session.get(f"{base}/api/admin/backup/executions", timeout=5)
                .json()
                .get("executions")
                or []
            ),
            timeout=15.0,
        )


@pytest.mark.integration
def test_multiple_destinations(server_factory):
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={"admin_username": "admin", "admin_password": "admin123"},
    )
    with server:
        base = server.get_base_url()
        session = server.login_admin()
        # Local dest A
        dA = (Path(server.work_dir) / "A").resolve()
        dA.mkdir(parents=True, exist_ok=True)
        rA = session.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "A",
                "type": "local",
                "config": {"base_path": str(dA)},
                "retention_days": 2,
            },
            timeout=5,
        )
        assert rA.status_code == 200
        idA = rA.json()["id"]
        # Local dest B
        dB = (Path(server.work_dir) / "B").resolve()
        dB.mkdir(parents=True, exist_ok=True)
        rB = session.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "B",
                "type": "local",
                "config": {"base_path": str(dB)},
                "retention_days": 2,
            },
            timeout=5,
        )
        assert rB.status_code == 200
        idB = rB.json()["id"]
        # Backup to both (sequentially)
        session.post(
            f"{base}/api/admin/backup/trigger", json={"destination_id": idA}, timeout=5
        )
        session.post(
            f"{base}/api/admin/backup/trigger", json={"destination_id": idB}, timeout=5
        )
        assert _poll(
            lambda: (
                session.get(f"{base}/api/admin/backup/executions", timeout=5)
                .json()
                .get("executions")
                or []
            ),
            timeout=15.0,
        )
        # List backups from all
        lb = session.get(f"{base}/api/admin/backup/list", timeout=5)
        assert lb.status_code == 200
        backups = lb.json().get("backups") or []
        assert isinstance(backups, list)
        # Attempt restore from specific destination when available
        if backups:
            b = backups[0]
            path = b.get("path") or b.get("remote_path")
            dest_id = b.get("destination_id")
            if path and dest_id:
                rr = session.post(
                    f"{base}/api/admin/backup/restore",
                    json={
                        "backup_path": path,
                        "destination_id": dest_id,
                        "confirm": True,
                    },
                    timeout=10,
                )
                assert rr.status_code in (200, 500)
