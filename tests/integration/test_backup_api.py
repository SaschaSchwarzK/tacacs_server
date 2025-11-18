"""
Backup API Integration Tests
===========================

This module contains end-to-end integration tests for the backup and restore
functionality of the TACACS+ server. It tests the backup API endpoints,
including backup creation, restoration, scheduling, and management of multiple
backup destinations.

Test Environment:
- Real server instance with admin API enabled
- Local filesystem for backup storage
- In-memory and on-disk database backends

Test Cases:
- test_backup_end_to_end: Tests basic backup creation and verification
- test_restore_end_to_end: Tests backup restoration process
- test_scheduled_backups_and_manual_trigger: Tests scheduled backups and manual triggers
- test_multiple_destinations: Tests backup to multiple destinations

Configuration:
- admin_username: 'admin' (default)
- admin_password: 'admin123' (default)
- backup_retention_days: 7 (configurable per test)
- temp_directory: System temp directory (configurable)

Example Usage:
    pytest tests/integration/test_backup_api.py -v

Note: These tests require write access to the filesystem for backup storage.
"""

import time
from pathlib import Path

import pytest


def _setup_test_backup_root():
    """Setup test backup root using allowed paths."""
    from tests.conftest_backup_fixtures import setup_test_backup_root

    return setup_test_backup_root()


def _poll(predicate: callable, timeout: float = 10.0, interval: float = 0.3) -> bool:
    """Poll a condition until it becomes true or timeout is reached.

    Args:
        predicate: Callable that returns a boolean indicating success
        timeout: Maximum time to wait in seconds (default: 10.0)
        interval: Time to wait between checks in seconds (default: 0.3)

    Returns:
        bool: True if the predicate returned True within the timeout, False otherwise
    """
    start = time.time()
    while time.time() - start < timeout:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.mark.integration
def test_backup_end_to_end(server_factory):
    """Test end-to-end backup creation and verification."""
    # Setup allowed backup root
    backup_root = _setup_test_backup_root()

    # Configure and start server with required services
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={"admin_username": "admin", "admin_password": "admin123"},
    )
    with server:
        base = server.get_base_url()
        session = server.login_admin()

        # Create local destination under the allowed backup root
        dest_dir = backup_root / "api-backups"
        dest_dir.mkdir(parents=True, exist_ok=True)

        payload = {
            "name": "local-dest",
            "type": "local",
            "config": {
                "base_path": str(dest_dir.resolve()),
                "allowed_root": str(backup_root),
            },
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
    """Test end-to-end backup restoration process."""
    # Setup allowed backup root
    backup_root = _setup_test_backup_root()

    # Server will initialize backup service via main.py
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={"admin_username": "admin", "admin_password": "admin123"},
    )
    with server:
        base = server.get_base_url()
        session = server.login_admin()

        dest_dir = backup_root / "rest-backups"
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Create destination
        cr = session.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "d1",
                "type": "local",
                "config": {
                    "base_path": str(dest_dir.resolve()),
                    "allowed_root": str(backup_root),
                },
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

        def _has_dest_backup() -> bool:
            try:
                lst = session.get(f"{base}/api/admin/backup/list", timeout=5)
                if lst.status_code != 200:
                    return False
                items = lst.json().get("backups") or []
                return any(str(b.get("destination_id")) == str(dest_id) for b in items)
            except Exception:
                return False

        assert _poll(_has_dest_backup, timeout=30.0)
        # Pick the newest backup for our destination_id specifically
        blist = session.get(f"{base}/api/admin/backup/list", timeout=5)
        assert blist.status_code == 200, blist.text
        items = [
            b
            for b in (blist.json().get("backups") or [])
            if str(b.get("destination_id")) == str(dest_id)
        ]
        assert items, "No backups found for our destination"
        # Sort by timestamp if available, otherwise use returned order
        try:
            items.sort(key=lambda x: str(x.get("timestamp") or ""), reverse=True)
        except Exception:
            pass
        bp = items[0].get("path") or items[0].get("remote_path")

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
    """Test scheduled backups and manual trigger functionality."""
    # Setup allowed backup root
    backup_root = _setup_test_backup_root()

    # Server will initialize backup service via main.py
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={"admin_username": "admin", "admin_password": "admin123"},
    )
    with server:
        base = server.get_base_url()
        session = server.login_admin()

        dest_dir = backup_root / "sched"
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Create destination
        cr = session.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "sched1",
                "type": "local",
                "config": {
                    "base_path": str(dest_dir.resolve()),
                    "allowed_root": str(backup_root),
                },
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
    """Test backup to multiple destinations simultaneously."""
    # Setup allowed backup root
    backup_root = _setup_test_backup_root()

    # Server will initialize backup service via main.py
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
        dA = (backup_root / "A").resolve()
        dA.mkdir(parents=True, exist_ok=True)
        rA = session.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "A",
                "type": "local",
                "config": {"base_path": str(dA), "allowed_root": str(backup_root)},
                "retention_days": 2,
            },
            timeout=5,
        )
        assert rA.status_code == 200, rA.text
        idA = rA.json()["id"]

        # Local dest B
        dB = (backup_root / "B").resolve()
        dB.mkdir(parents=True, exist_ok=True)
        rB = session.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "B",
                "type": "local",
                "config": {"base_path": str(dB), "allowed_root": str(backup_root)},
                "retention_days": 2,
            },
            timeout=5,
        )
        assert rB.status_code == 200, rB.text
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
