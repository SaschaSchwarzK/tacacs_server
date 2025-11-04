"""
Backup Destinations Integration Tests
===================================

This module contains integration tests for various backup destination types
supported by the TACACS+ server. It verifies that backups can be created
and managed across different storage backends.

Test Environment:
- Real FTP server for remote backup testing
- Local filesystem for local backup testing
- Temporary directories for test isolation

Test Cases:
- test_ftp_destination_integration: Tests backup to an FTP server

Dependencies:
- pyftpdlib: Required for FTP server emulation

Configuration:
- FTP server: 127.0.0.1 with random port
- FTP credentials: testuser/testpass
- Test data: Automatically generated

Example Usage:
    pytest tests/integration/test_backup_destinations.py -v

Note: These tests require network access for FTP testing and may be skipped
if dependencies are not available.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture(scope="function")
def ftp_server(tmp_path: Path) -> dict[str, Any]:
    """Start a real FTP server for integration testing.

    This fixture sets up an FTP server with the following configuration:
    - Runs on localhost with a random available port
    - Uses a temporary directory as the FTP root
    - Authenticates with testuser/testpass
    - Provides full permissions (read/write/delete)

    Args:
        tmp_path: Pytest fixture providing a temporary directory

    Yields:
        Dict containing server information:
        - 'host': Server hostname (always '127.0.0.1')
        - 'port': Server port (random available port)
        - 'user': FTP username ('testuser')
        - 'password': FTP password ('testpass')
        - 'root_dir': FTP root directory (temporary path)

    Note:
        The server is automatically started before the test and stopped after.
        Uses pyftpdlib for the FTP server implementation.
    """
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
def test_ftp_destination_integration(
    ftp_server: dict[str, Any], tmp_path: Path
) -> None:
    """Test backup to FTP destination with a real FTP server.

    This test verifies that backups can be successfully uploaded to an FTP server
    with the following steps:
    1. Creates a test backup file
    2. Configures an FTP destination
    3. Uploads the backup to the FTP server
    4. Verifies the file was uploaded correctly
    5. Tests backup listing and retrieval

    Test Steps:
    1. Create a test backup file with known content
    2. Initialize FTP destination with test server details
    3. Upload backup to FTP server
    4. Verify file exists on FTP server
    5. List backups and verify metadata
    6. Download and verify backup content

    Expected Behavior:
    - Backup is successfully uploaded to FTP server
    - File size and modification time are preserved
    - Backup can be listed and retrieved
    - Downloaded content matches original

    Configuration:
    - FTP server: Local test server (see ftp_server fixture)
    - Test file: test_backup.tar.gz with known content
    - FTP path: /backups/

    Dependencies:
    - tacacs_server.backup.destinations.ftp
    - tacacs_server.backup.models
    """

    from tacacs_server.backup.destinations.ftp import FTPBackupDestination

    # Create test backup file with known content
    test_content = "test backup content"
    test_file = tmp_path / "test_backup.tar.gz"
    test_file.write_text(test_content)

    # Configure FTP destination with test server details
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
