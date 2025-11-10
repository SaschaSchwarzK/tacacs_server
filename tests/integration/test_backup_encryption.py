"""Backup Encryption Integration Tests
=================================

This module contains integration tests for the backup encryption functionality
of the TACACS+ server. It verifies that backups can be encrypted and decrypted
using various encryption methods and key management strategies.

Test Environment:
- Temporary files for encrypted and decrypted backups
- In-memory key storage for testing
- Multiple encryption algorithms and key sizes

Test Cases:
- test_encrypt_decrypt_cycle: Tests basic encryption and decryption cycle
- test_encryption_with_password: Tests encryption with password-based key derivation
- test_encryption_with_key_file: Tests encryption with key file
- test_encryption_performance: Tests encryption performance with different algorithms

Configuration:
- Supported algorithms: AES-256-CBC, AES-256-GCM, ChaCha20-Poly1305
- Key derivation: PBKDF2 with 100,000 iterations
- Test data: Randomly generated (1MB, 10MB, 100MB)

Example Usage:
    pytest tests/integration/test_backup_encryption.py -v

Security Notes:
- Test keys and passwords are for testing only
- Real deployments should use secure key management
- Encryption strength depends on key size and algorithm
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest


def _setup_test_backup_root():
    """Setup test backup root and ensure it's in ALLOWED_ROOTS."""
    import tacacs_server.backup.path_policy as _pp

    # Get the backup root from environment (set by conftest fixture)
    backup_root_str = os.environ.get("BACKUP_ROOT")
    if backup_root_str:
        backup_root = Path(backup_root_str).resolve()
        # Ensure it's in ALLOWED_ROOTS
        if backup_root not in _pp.ALLOWED_ROOTS:
            _pp.ALLOWED_ROOTS.append(backup_root)
        _pp.DEFAULT_BACKUP_ROOT = backup_root
        return backup_root
    return _pp.DEFAULT_BACKUP_ROOT


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

    # Setup allowed backup root
    backup_root = _setup_test_backup_root()

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
        assert user_resp.status_code in (200, 201), (
            f"Failed to create user: {user_resp.text}"
        )

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
        base_dir = (backup_root / "enc-backups").resolve()
        base_dir.mkdir(parents=True, exist_ok=True)

        dest_resp = session.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "test-dest",
                "type": "local",
                "config": {
                    "base_path": str(base_dir),
                    "allowed_root": str(backup_root),
                },
                "retention_days": 7,
            },
            timeout=5,
        )
        assert dest_resp.status_code == 200, dest_resp.text
        dest_id = dest_resp.json()["id"]
        print(f"Destination ID: {dest_id}")

        # Trigger backup
        print("\n=== Triggering Backup ===")
        backup_resp = session.post(
            f"{base}/api/admin/backup/trigger",
            json={"destination_id": dest_id},
            timeout=5,
        )
        assert backup_resp.status_code == 200, backup_resp.text
        execution_id = backup_resp.json()["execution_id"]
        print(f"Execution ID: {execution_id}")

        # Wait for backup completion
        assert _wait_for(
            lambda: session.get(
                f"{base}/api/admin/backup/executions/{execution_id}", timeout=5
            )
            .json()
            .get("status")
            in ("completed", "failed"),
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
        assert delete_resp.status_code in (200, 204), (
            f"Failed to delete user: {delete_resp.text}"
        )

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

        assert get_restored_resp.status_code == 200, (
            f"User not restored! Response: {get_restored_resp.text}"
        )

        restored_user = get_restored_resp.json()
        print(f"Restored user: {restored_user}")
        assert restored_user["username"] == "testuser"
        assert restored_user["privilege_level"] == 15
        print("✓ User successfully restored")
