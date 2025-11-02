from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest


@pytest.fixture(scope="function")
def ftp_server(tmp_path):
    """Start a real FTP server for integration testing."""
    try:
        from pyftpdlib.authorizers import DummyAuthorizer
        from pyftpdlib.handlers import FTPHandler
        from pyftpdlib.servers import FTPServer
    except ImportError:
        pytest.skip("pyftpdlib not installed")

    # Create temp directory for FTP root
    ftp_root = tmp_path / "ftp_root"
    ftp_root.mkdir()

    # Setup authorizer
    authorizer = DummyAuthorizer()
    authorizer.add_user("testuser", "testpass", str(ftp_root), perm="elradfmw")

    # Setup handler
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.permit_foreign_addresses = True

    # Create server
    server = FTPServer(("127.0.0.1", 0), handler)
    port = server.address[1]

    # Run server in thread with controlled shutdown
    def run_server():
        try:
            server.serve_forever(timeout=1.0, blocking=True)
        except (OSError, ValueError):
            # Expected during shutdown
            pass

    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()

    # Wait for server to be ready
    time.sleep(1.0)

    try:
        yield {
            "host": "127.0.0.1",
            "port": port,
            "username": "testuser",
            "password": "testpass",
            "root": ftp_root,
        }
    finally:
        # Graceful shutdown
        try:
            server.close_all()
        except Exception:
            pass


@pytest.mark.integration
def test_ftp_destination_integration(ftp_server, tmp_path: Path):
    """Integration test with real FTP server."""
    from tacacs_server.backup.destinations.ftp import FTPBackupDestination

    config = {
        "host": ftp_server["host"],
        "port": ftp_server["port"],
        "username": ftp_server["username"],
        "password": ftp_server["password"],
        "base_path": "/test-backups",
        "use_tls": False,
        "timeout": 30,
        "passive": True,
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
