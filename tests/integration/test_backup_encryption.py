"""Test backup encryption with proper database isolation"""

from __future__ import annotations

import time
from pathlib import Path

import pytest


def _wait_for(cond, timeout=30.0, interval=0.5) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        if cond():
            return True
        time.sleep(interval)
    return False


@pytest.mark.integration
def test_encrypted_backup_restore(server_factory, tmp_path: Path):
    """Test complete encrypted backup and restore cycle with proper database isolation."""
    passphrase = "TestEncryptionKey123!@#"

    test_db_dir = tmp_path / "test_dbs"
    test_db_dir.mkdir(parents=True, exist_ok=True)
    auth_db = test_db_dir / "auth.db"
    devices_db = test_db_dir / "devices.db"

    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        config={
            "database": {
                "auth_db": str(auth_db),
                "devices_db": str(devices_db),
            },
            "backup": {
                "enabled": "true",
                "encryption_enabled": "true",
                "encryption_passphrase": passphrase,
                "temp_directory": str(tmp_path / "backup_temp"),
            },
        },
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(auth_db))
        user_service.create_user("testuser", password="Pass123!", privilege_level=15)

        created_user = user_service.get_user("testuser")
        assert created_user is not None
        assert int(created_user.privilege_level) == 15

        # Close the user service connection before backup
        del user_service

        base = server.get_base_url()
        session = server.login_admin()

        base_dir = (tmp_path / "enc-backups").resolve()
        base_dir.mkdir(parents=True, exist_ok=True)

        dest_resp = session.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "test-dest",
                "type": "local",
                "config": {"base_path": str(base_dir)},
                "retention_days": 7,
            },
            timeout=5,
        )
        assert dest_resp.status_code == 200, dest_resp.text
        dest_id = dest_resp.json()["id"]

        backup_resp = session.post(
            f"{base}/api/admin/backup/trigger",
            json={"destination_id": dest_id},
            timeout=5,
        )
        assert backup_resp.status_code == 200, backup_resp.text
        execution_id = backup_resp.json()["execution_id"]

        assert _wait_for(
            lambda: (
                session.get(
                    f"{base}/api/admin/backup/executions/{execution_id}", timeout=5
                ).json()
            ).get("status")
            in ("completed", "failed"),
            timeout=60.0,
        ), "Backup did not complete in time"

        exec_resp = session.get(
            f"{base}/api/admin/backup/executions/{execution_id}", timeout=5
        )
        execution = exec_resp.json()
        assert execution["status"] == "completed", f"Backup failed: {execution}"
        assert ".enc" in execution["backup_filename"], "Backup should be encrypted"

        backup_path = execution["backup_path"]

        # Delete user to simulate data loss - use new service instance
        delete_service = LocalUserService(str(auth_db))
        delete_service.delete_user("testuser")

        # Verify deletion
        try:
            delete_service.get_user("testuser")
            pytest.fail("User should have been deleted")
        except Exception:
            pass  # Expected

        del delete_service
        time.sleep(0.5)  # Allow connection to close

        # Restore via API
        restore_resp = session.post(
            f"{base}/api/admin/backup/restore",
            json={
                "backup_path": backup_path,
                "destination_id": dest_id,
                "components": ["users"],
                "confirm": True,
            },
            timeout=30,
        )

        assert restore_resp.status_code == 200, f"Restore failed: {restore_resp.text}"
        restore_result = restore_resp.json()
        print(f"Restore result: {restore_result}")

    # Exit the server context to close all connections
    # Now verify the restored data with fresh connection
    time.sleep(0.5)

    restored_service = LocalUserService(str(auth_db))
    user = restored_service.get_user("testuser")
    assert user is not None, "User should be restored from backup"
    assert int(user.privilege_level) == 15, "User privilege level should be preserved"
    del restored_service
    try:
        if auth_db.exists():
            auth_db.unlink()
        if devices_db.exists():
            devices_db.unlink()
    except Exception:
        pass
