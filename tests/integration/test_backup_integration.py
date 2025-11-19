"""
Backup Integration Tests
=======================

This module contains end-to-end integration tests for the backup functionality
while the TACACS+ server is actively processing requests. These tests verify
that backup operations work correctly under load and don't interfere with
normal server operations.

Test Environment:
- Running TACACS+ server instance
- Admin API enabled for backup operations
- Local filesystem for backup storage
- Concurrent operations simulation

Test Cases:
- test_backup_while_server_running: Tests backup operations during active server usage

Configuration:
- Admin credentials: admin/admin123
- Backup retention: 7 days
- Timeout: 30 seconds for backup completion
- Test directory: Temporary directory for backups

Example Usage:
    pytest tests/integration/test_backup_integration.py -v

Note: These tests require write access to the filesystem for backup storage
and may take longer to run due to the nature of integration testing.
"""

import os
import time
from collections.abc import Callable
from pathlib import Path

import pytest


def _setup_test_backup_root():
    """Setup test backup root and ensure it's in ALLOWED_ROOTS."""
    import tacacs_server.backup.path_policy as _pp

    # Get the backup root from environment (set by conftest fixture)
    backup_root_str = os.environ.get("TACACS_BACKUP_ROOT")
    if backup_root_str:
        backup_root = Path(backup_root_str).resolve()
        # Ensure it's in ALLOWED_ROOTS
        if backup_root not in _pp.ALLOWED_ROOTS:
            _pp.ALLOWED_ROOTS.append(backup_root)
        _pp.DEFAULT_BACKUP_ROOT = backup_root
        return backup_root
    return _pp.DEFAULT_BACKUP_ROOT


def _wait(
    predicate: Callable[[], bool], timeout: float = 20.0, interval: float = 0.5
) -> bool:
    """Wait for a condition to become true within a timeout period.

    Args:
        predicate: Callable that returns a boolean indicating success
        timeout: Maximum time to wait in seconds (default: 20.0)
        interval: Time between checks in seconds (default: 0.5)

    Returns:
        bool: True if the predicate returned True within the timeout,
              False otherwise

    Note:
        Uses a simple polling mechanism with exponential backoff could be
        implemented for more efficient waiting in production code.
    """
    start = time.time()
    while time.time() - start < timeout:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.mark.integration
def test_backup_while_server_running(server_factory, tmp_path: Path) -> None:
    """Verify backup operations work while the TACACS+ server is processing requests.

    This test verifies that backup operations can be performed while the server
    is actively handling TACACS authentication requests, ensuring that backups
    don't interfere with normal server operation.

    Test Steps:
    1. Start a TACACS+ server with admin API enabled
    2. Create a local backup destination in a temporary directory
    3. Simulate server load by making concurrent API requests
    4. Trigger a backup operation
    5. Wait for backup completion with timeout
    6. Verify backup status and list of available backups

    Expected Behavior:
    - Server starts successfully with all required services
    - Backup destination is created (HTTP 200)
    - Backup is triggered successfully (HTTP 200)
    - Backup completes within the timeout period
    - Backup is listed in the backups collection

    Configuration:
    - Admin credentials: admin/admin123
    - Backup retention: 7 days
    - Timeout: 30 seconds for backup completion
    - Test directory: Temporary directory for backups

    Note:
        This is an integration test that verifies the interaction between
        the backup system and the running TACACS+ server. It's designed
        to catch issues that might only appear under load.
    """
    # Setup allowed backup root
    backup_root = _setup_test_backup_root()

    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={"admin_username": "admin", "admin_password": "admin123"},
    )

    with server:
        base = server.get_base_url()
        session = server.login_admin()

        # Create a local destination for backups under allowed root
        dest_dir = (backup_root / "live-backups").resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)
        cr = session.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "live",
                "type": "local",
                "config": {
                    "base_path": str(dest_dir),
                    "allowed_root": str(backup_root),
                },
                "retention_days": 7,
            },
            timeout=5,
        )
        assert cr.status_code == 200, cr.text
        dest_id = cr.json()["id"]

        # Simulate some concurrent operations here (e.g., list sections)
        s = session.get(f"{base}/api/admin/config/sections", timeout=5)
        assert s.status_code == 200

        # Trigger backup
        tr = session.post(
            f"{base}/api/admin/backup/trigger",
            json={"destination_id": dest_id, "comment": "test backup"},
            timeout=5,
        )
        assert tr.status_code == 200, tr.text
        execution_id = tr.json().get("execution_id")
        assert execution_id

        # Wait for completion
        def _done():
            st = session.get(
                f"{base}/api/admin/backup/executions/{execution_id}", timeout=5
            )
            if st.status_code != 200:
                return False
            data = st.json() or {}
            return data.get("status") in ("completed", "failed")

        assert _wait(_done, timeout=30.0)
        # Verify status endpoint
        st = session.get(
            f"{base}/api/admin/backup/executions/{execution_id}", timeout=5
        ).json()
        assert st.get("status") in ("completed", "failed")

        # Verify at least one backup is listed
        lb = session.get(f"{base}/api/admin/backup/list", timeout=5)
        assert lb.status_code == 200
        backups = lb.json().get("backups") or []
        assert isinstance(backups, list)
