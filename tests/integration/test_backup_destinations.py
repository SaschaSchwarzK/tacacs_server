from __future__ import annotations

import os

import pytest

from tacacs_server.backup.destinations.ftp import FTPBackupDestination


@pytest.mark.integration
@pytest.mark.skipif(not os.getenv("TEST_FTP_HOST"), reason="FTP server not configured")
def test_ftp_destination_integration(tmp_path):
    """Integration test with real FTP server (optional)."""
    config = {
        "host": os.getenv("TEST_FTP_HOST"),
        "port": int(os.getenv("TEST_FTP_PORT", "21")),
        "username": os.getenv("TEST_FTP_USER"),
        "password": os.getenv("TEST_FTP_PASS"),
        "base_path": "/test-backups",
        "use_tls": False,
    }

    destination = FTPBackupDestination(config)

    # Test connection
    success, message = destination.test_connection()
    assert success, f"Connection failed: {message}"

    # Create test backup file
    test_file = tmp_path / "test_backup.tar.gz"
    test_file.write_bytes(b"Test backup content " * 1000)

    # Upload
    remote_path = destination.upload_backup(str(test_file), "test_backup.tar.gz")
    assert remote_path

    # List
    backups = destination.list_backups()
    assert len(backups) > 0
    assert any(b.filename == "test_backup.tar.gz" for b in backups)

    # Download
    download_path = tmp_path / "test_backup_downloaded.tar.gz"
    success = destination.download_backup(remote_path, str(download_path))
    assert success and download_path.exists()
    assert download_path.read_bytes() == test_file.read_bytes()

    # Delete
    success = destination.delete_backup(remote_path)
    assert success

    # Verify deleted
    backups = destination.list_backups()
    assert not any(b.filename == "test_backup.tar.gz" for b in backups)
