"""Test backup encryption using only API calls"""

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
    """Test backup/restore using only API calls - no direct DB access."""
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

    backup_path = None
    dest_id = None

    with server:
        base = server.get_base_url()
        session = server.login_admin()

        # Create user via API
        print("\n=== Creating User via API ===")
        user_resp = session.post(
            f"{base}/api/users",
            json={
                "username": "testuser",
                "password": "Pass123!",
                "privilege_level": 15,
                "enabled": True,
            },
            timeout=5,
        )
        print(f"Create user response: {user_resp.status_code}")
        assert user_resp.status_code in (200, 201), f"Failed to create user: {user_resp.text}"

        # Verify user exists via API
        get_user_resp = session.get(f"{base}/api/users/testuser", timeout=5)
        print(f"Get user response: {get_user_resp.status_code}")
        assert get_user_resp.status_code == 200
        user_data = get_user_resp.json()
        print(f"User data: {user_data}")
        assert user_data["username"] == "testuser"
        assert user_data["privilege_level"] == 15

        # Create backup destination
        print("\n=== Creating Backup Destination ===")
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
        assert dest_resp.status_code == 200
        dest_id = dest_resp.json()["id"]
        print(f"Destination ID: {dest_id}")

        # Trigger backup
        print("\n=== Triggering Backup ===")
        backup_resp = session.post(
            f"{base}/api/admin/backup/trigger",
            json={"destination_id": dest_id},
            timeout=5,
        )
        assert backup_resp.status_code == 200
        execution_id = backup_resp.json()["execution_id"]
        print(f"Execution ID: {execution_id}")

        # Wait for backup completion
        assert _wait_for(
            lambda: session.get(
                f"{base}/api/admin/backup/executions/{execution_id}", timeout=5
            ).json().get("status") in ("completed", "failed"),
            timeout=60.0,
        ), "Backup did not complete"

        exec_resp = session.get(
            f"{base}/api/admin/backup/executions/{execution_id}", timeout=5
        )
        execution = exec_resp.json()
        print(f"Backup status: {execution['status']}")
        assert execution["status"] == "completed", f"Backup failed: {execution}"
        backup_path = execution["backup_path"]
        print(f"Backup path: {backup_path}")

        # Delete user via API
        print("\n=== Deleting User via API ===")
        delete_resp = session.delete(f"{base}/api/users/testuser", timeout=5)
        print(f"Delete user response: {delete_resp.status_code}")
        assert delete_resp.status_code in (200, 204), f"Failed to delete user: {delete_resp.text}"

        # Verify user is gone
        get_deleted_resp = session.get(f"{base}/api/users/testuser", timeout=5)
        print(f"Get deleted user response: {get_deleted_resp.status_code}")
        assert get_deleted_resp.status_code == 404, "User should not exist"

        # Restore backup
        print("\n=== Restoring Backup via API ===")
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
        print(f"Restore response: {restore_resp.status_code} - {restore_resp.json()}")
        assert restore_resp.status_code == 200, f"Restore failed: {restore_resp.text}"

    # Exit server context to allow background restart
    print("\n=== Server context exited, waiting for restart ===")
    time.sleep(3.0)

    # Verify restored user with new server instance
    print("\n=== Verifying Restored User with New Server ===")
    server2 = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        config={
            "database": {
                "auth_db": str(auth_db),
                "devices_db": str(devices_db),
            },
        },
    )

    with server2:
        base2 = server2.get_base_url()
        session2 = server2.login_admin()

        # Check if user was restored
        get_restored_resp = session2.get(f"{base2}/api/users/testuser", timeout=5)
        print(f"Get restored user response: {get_restored_resp.status_code}")
        
        if get_restored_resp.status_code == 404:
            # List all users for debugging
            list_resp = session2.get(f"{base2}/api/users", timeout=5)
            print(f"All users: {list_resp.json()}")
        
        assert get_restored_resp.status_code == 200, f"User not restored! Response: {get_restored_resp.text}"
        
        restored_user = get_restored_resp.json()
        print(f"Restored user: {restored_user}")
        assert restored_user["username"] == "testuser"
        assert restored_user["privilege_level"] == 15
        print("✓ User successfully restored")
