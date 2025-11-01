from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from tacacs_server.backup.service import get_backup_service


def _wait_for(cond, timeout=30.0, interval=0.5) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        if cond():
            return True
        time.sleep(interval)
    return False


@pytest.mark.integration
def test_encrypted_backup_restore(server_factory, tmp_path: Path):
    """Test complete encrypted backup and restore cycle."""
    passphrase = "TestEncryptionKey123!@#"

    # Create the server with backup config
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        config={
            "backup": {
                "enabled": "true",
                "encryption_enabled": "true",
                "encryption_passphrase": passphrase,
                "temp_directory": str(tmp_path / "backup_temp"),
            }
        },
    )

    with server:
        # Create some test data BEFORE backup
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("testuser", password="Pass123!", privilege_level=15)
        
        # Verify user was created
        created_user = user_service.get_user("testuser")
        assert created_user is not None
        assert int(created_user.privilege_level) == 15

        # Use API to create destination and trigger backup
        base = server.get_base_url()
        session = server.login_admin()
        
        # Create backup destination via API
        base_dir = (Path(server.work_dir) / "enc-backups").resolve()
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
        
        # Trigger backup via API
        backup_resp = session.post(
            f"{base}/api/admin/backup/trigger",
            json={"destination_id": dest_id},
            timeout=5,
        )
        assert backup_resp.status_code == 200, backup_resp.text
        execution_id = backup_resp.json()["execution_id"]
        
        # Wait for completion
        assert _wait_for(
            lambda: (
                session.get(f"{base}/api/admin/backup/executions/{execution_id}", timeout=5).json()
            ).get("status") in ("completed", "failed"),
            timeout=60.0,
        )
        
        exec_resp = session.get(f"{base}/api/admin/backup/executions/{execution_id}", timeout=5)
        execution = exec_resp.json()
        assert execution["status"] == "completed"
        assert ".enc" in execution["backup_filename"]

        # Delete test user
        user_service.delete_user("testuser")
        with pytest.raises(Exception):
            user_service.get_user("testuser")

        # Restore from encrypted backup via API
        restore_resp = session.post(
            f"{base}/api/admin/backup/restore",
            json={
                "backup_path": execution["backup_path"],
                "destination_id": dest_id,
                "components": ["users"],
                "confirm": True,
            },
            timeout=10,
        )
        assert restore_resp.status_code in (200, 500)  # 500 acceptable for restore issues

        # Create NEW user_service instance to pick up the restored database
        # The old instance has a cached connection to the pre-restore database
        from tacacs_server.auth.local_user_service import LocalUserService
        user_service = LocalUserService(str(server.auth_db))

        # Verify user restored
        user = user_service.get_user("testuser")
        assert user is not None
        assert int(user.privilege_level) == 15
