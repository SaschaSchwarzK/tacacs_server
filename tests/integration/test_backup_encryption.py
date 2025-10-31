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

    # Get the backup service and update its config directly
    backup_service = get_backup_service()
    if hasattr(backup_service, "config"):
        # Force update the backup config in the service
        backup_config = {
            "enabled": True,
            "encryption_enabled": True,
            "encryption_passphrase": passphrase,
            "temp_directory": str(tmp_path / "backup_temp"),
            "default_retention_days": 30,
        }
        # Monkey patch the get_backup_config method to return our test config
        backup_service.config.get_backup_config = lambda: backup_config

    with server:
        # Create some test data
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("testuser", password="Pass123!", privilege_level=15)

        # Ensure a local destination exists (under server work dir)
        backup_service = get_backup_service()
        base_dir = (Path(server.work_dir) / "enc-backups").resolve()
        base_dir.mkdir(parents=True, exist_ok=True)

        # Use a unique name for the destination to avoid conflicts
        import uuid

        dest_name = f"local_enc_{uuid.uuid4().hex[:8]}"

        dest_id = backup_service.execution_store.create_destination(
            name=dest_name,
            dest_type="local",
            config={"base_path": str(base_dir)},
            retention_days=7,
            created_by="test",
        )

        # Trigger encrypted backup
        execution_id = backup_service.create_manual_backup(
            destination_id=dest_id, created_by="admin"
        )

        # Wait for completion
        assert _wait_for(
            lambda: (
                backup_service.execution_store.get_execution(execution_id) or {}
            ).get("status")
            in ("completed", "failed"),
            timeout=60.0,
        )
        execution = backup_service.execution_store.get_execution(execution_id)
        assert execution["status"] == "completed"
        assert ".enc" in execution["backup_filename"]

        # Verify manifest shows encryption
        manifest = (
            json.loads(execution["manifest_json"])
            if execution.get("manifest_json")
            else {}
        )
        assert manifest.get("encrypted") is True
        assert manifest.get("encryption_algorithm") == "Fernet-AES128-CBC"

        # Delete test user
        user_service.delete_user("testuser")
        with pytest.raises(Exception):
            user_service.get_user("testuser")

        # Restore from encrypted backup (users only)
        success, message = backup_service.restore_backup(
            source_path=execution["backup_path"],
            destination_id=dest_id,
            components=["users"],
        )
        assert success, f"Restore failed: {message}"

        # Reload user_service to pick up the restored database
        user_service.reload()

        # Verify user restored
        user = user_service.get_user("testuser")
        assert user is not None
        assert int(user.privilege_level) == 15
