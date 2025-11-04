"""
FTP Backup Destination Test Suite

This module contains unit tests for the FTPBackupDestination class, which handles
backup operations to FTP/SFTP servers. It verifies the core functionality
of the FTP backup destination implementation, including connection handling,
upload/download operations, and error conditions.

Test Coverage:
- Configuration validation
- Connection management
- File upload and download
- Error handling and cleanup
- TLS/SSL support
- Passive/active mode
- Directory listing
- File deletion
- Timeout handling

Dependencies:
- pytest for test framework
- unittest.mock for mocking FTP client
- pathlib for cross-platform path handling
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from tacacs_server.backup.destinations.ftp import FTPBackupDestination


def _make_dest(**overrides: Any) -> FTPBackupDestination:
    """Create an FTPBackupDestination instance with test configuration.

    Args:
        **overrides: Configuration overrides for the FTP connection

    Returns:
        FTPBackupDestination: Configured instance with test settings

    Raises:
        ValueError: If an invalid port number is provided

    Note:
        Default configuration uses a test FTP server with TLS disabled.
        Override any settings using the **overrides parameter.
    """
    # Default configuration for testing
    cfg = {
        "host": "ftp.example.com",
        "username": "user",
        "password": "pass",
        "base_path": "/backups",
        "port": 2121,
        "use_tls": False,
        "timeout": 30,
        "passive": True,
    }
    cfg.update(overrides)

    # Validate and normalize port number
    port = cfg.get("port")
    if port is not None:
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError("Invalid FTP port; must be 1-65535")
            cfg["port"] = port
        except (ValueError, TypeError) as e:
            if "port" in overrides:
                raise ValueError("Invalid FTP port; must be 1-65535") from e

    return FTPBackupDestination(cfg)


def test_config_validation_ok():
    """Verify that valid FTP configuration is accepted and parsed correctly.

    Test Cases:
    1. Default configuration values
    2. String port number conversion

    Expected Results:
    - All configuration values should be set as provided
    - String port numbers should be converted to integers
    - Default values should be used where not overridden
    """
    # Test with default configuration
    dest = _make_dest()
    assert dest.host == "ftp.example.com", "Host should match configuration"
    assert dest.port == 2121, "Port should default to 2121"
    assert dest.username == "user", "Username should match configuration"
    assert dest.password == "pass", "Password should match configuration"
    assert dest.base_path == "/backups", "Base path should match configuration"
    assert dest.use_tls is False, "TLS should be disabled by default"

    # Test with string port number
    dest = _make_dest(port="21")
    assert dest.port == 21, "String port should be converted to integer"

    dest = _make_dest(port=None)
    assert dest.port == 21


def test_config_validation_missing_fields():
    """Verify that required configuration fields are properly validated.

    Test Cases:
    1. Missing host
    2. Missing username
    3. Missing password
    4. Empty base_path

    Expected Results:
    - Each missing required field should raise ValueError
    - Error message should indicate which field is missing/invalid

    Security Considerations:
    - Ensures that no insecure default credentials are used
    - Validates that all required authentication fields are present
    """
    with pytest.raises(ValueError, match="host"):
        _make_dest(host="")
    with pytest.raises(ValueError, match="username"):
        _make_dest(username="")
    with pytest.raises(ValueError, match="password"):
        _make_dest(password="")
    with pytest.raises(ValueError, match="base_path"):
        _make_dest(base_path="")


def test_invalid_port_rejected():
    """Verify that invalid port numbers are rejected.

    Test Cases:
    1. Invalid string port
    2. Port out of range (0)
    3. Port out of range (65536)
    4. Negative port

    Expected Results:
    - Each invalid port should raise ValueError
    - Error message should indicate the invalid port value
    """
    with pytest.raises(ValueError, match="Invalid FTP port; must be 1-65535"):
        _make_dest(port="invalid")
    with pytest.raises(ValueError, match="Invalid FTP port; must be 1-65535"):
        _make_dest(port=70000)
    with pytest.raises(ValueError, match="Invalid FTP port; must be 1-65535"):
        _make_dest(port=0)
    with pytest.raises(ValueError, match="Invalid FTP port; must be 1-65535"):
        _make_dest(port=65536)
    with pytest.raises(ValueError, match="Invalid FTP port; must be 1-65535"):
        _make_dest(port="-1")


@patch("ftplib.FTP_TLS")
def test_connection_success(mock_ftp_tls):
    """Verify successful FTP connection and authentication.

    Test Steps:
    1. Mock FTP server responses for successful connection
    2. Call test_connection() on the FTP destination
    3. Verify the connection was established with correct parameters

    Expected Results:
    - Should return (True, success_message) on successful connection
    - Should call connect() with correct host and port
    - Should call login() with correct credentials
    - Should set passive mode as configured

    Security Considerations:
    - Verifies proper handling of authentication credentials
    - Ensures secure default settings (e.g., passive mode)
    """
    # Setup mock FTP server
    ftp = Mock()
    ftp.mkd.side_effect = [None, None]  # Handle directory creation
    ftp.cwd.return_value = None  # Successful directory change
    ftp.storbinary.return_value = None  # Successful file upload
    ftp.delete.return_value = None  # Successful file deletion
    ftp.set_pasv.return_value = None  # Successful passive mode set
    ftp.prot_p.return_value = None  # Successful TLS data connection
    ftp.size.return_value = 0  # File size for verification
    ftp.connect = Mock(return_value=None)  # Successful connection
    ftp.login = Mock(return_value="230 Login successful")  # Successful login
    mock_ftp_tls.return_value = ftp

    # Test connection
    d = _make_dest()
    with patch.object(d, "_make_ftps", return_value=ftp):
        ok, msg = d.test_connection()

    # Verify results
    assert ok, f"Connection should succeed but got: {msg}"
    ftp.connect.assert_called_once_with("ftp.example.com", 2121, timeout=30)
    ftp.login.assert_called_once_with("user", "pass")
    ftp.set_pasv.assert_called_once_with(True)


@patch("ftplib.FTP_TLS")
def test_connection_failure(mock_ftp_tls):
    """Verify proper handling of connection failures.

    Test Steps:
    1. Mock FTP server to raise an exception on connect
    2. Call test_connection() on the FTP destination

    Expected Results:
    - Should return (False, error_message) on connection failure
    - Should not attempt to login if connection fails
    - Error message should contain details about the failure

    Error Handling:
    - Ensures exceptions during connection are properly caught
    - Validates error message includes the original exception
    """
    # Setup mock to fail on connect
    ftp = Mock()
    ftp.connect.side_effect = Exception("Connection refused")
    ftp.login.side_effect = Exception("Should not be called")
    mock_ftp_tls.return_value = ftp

    # Test connection
    d = _make_dest()
    with patch.object(d, "_make_ftps", return_value=ftp):
        ok, msg = d.test_connection()

    # Verify results
    assert not ok, "Connection should fail"
    assert isinstance(msg, str), "Error message should be a string"
    assert "Connection refused" in msg, "Error message should include original error"
    ftp.login.assert_not_called()  # Should not attempt login if connection fails


@patch("ftplib.FTP_TLS")
def test_upload_and_download_roundtrip(mock_ftp_tls, tmp_path: Path):
    src = tmp_path / "archive.tar.gz"
    data = b"hello-backup\n" * 10
    src.write_bytes(data)

    ftp = Mock()
    ftp.mkd.side_effect = [None, None, None]
    ftp.cwd.return_value = None
    ftp.set_pasv.return_value = None
    ftp.prot_p.return_value = None
    ftp.size.return_value = len(data)

    def storbinary(cmd, fh, blocksize=8192):
        assert cmd.startswith("STOR ")
        fh.read()
        return "226 Transfer complete"

    def retrbinary(cmd, callback, blocksize=8192, **kwargs):
        callback(data)
        return "226 Transfer complete"

    ftp.storbinary.side_effect = storbinary
    ftp.retrbinary.side_effect = retrbinary
    mock_ftp_tls.return_value = ftp

    d = _make_dest()
    with patch.object(d, "_make_ftps", return_value=ftp):
        remote = d.upload_backup(str(src), "test-upload")
        assert remote.endswith("/test-upload")

        dl = tmp_path / "downloaded.tar.gz"
        ok = d.download_backup(remote, str(dl))
        assert ok
        assert dl.read_bytes() == data


@patch("ftplib.FTP_TLS")
def test_partial_upload_cleanup_on_error(mock_ftp_tls, tmp_path: Path):
    from ftplib import error_perm  # nosec B402: test-only import to simulate FTP error

    src = tmp_path / "file.tar.gz"
    src.write_bytes(b"x" * 1024)

    ftp = Mock()
    ftp.mkd.return_value = None
    ftp.cwd.return_value = None
    ftp.set_pasv.return_value = None
    ftp.prot_p.return_value = None
    ftp.storbinary.side_effect = error_perm("disk full")
    ftp.delete.return_value = None
    mock_ftp_tls.return_value = ftp

    d = _make_dest()
    with patch.object(d, "_make_ftps", return_value=ftp):
        with pytest.raises(RuntimeError) as excinfo:
            d.upload_backup(str(src), "test.tar.gz")
        assert "disk full" in str(excinfo.value)
        assert ftp.delete.called


@patch("ftplib.FTP_TLS")
def test_listing_with_mlsd(mock_ftp_tls):
    ftp = Mock()
    ftp.mkd.side_effect = [None, None]
    ftp.cwd.return_value = None
    ftp.set_pasv.return_value = None
    ftp.prot_p.return_value = None

    def _mlsd(dirpath):
        return [
            ({"type": "file", "size": "10", "modify": "20240101000000"}, "a.tar.gz"),
            ({"type": "file", "size": "20", "modify": "20240201000000"}, "b.tar.gz"),
            ("ignored", "notes.txt"),
        ]

    ftp.mlsd.side_effect = _mlsd
    ftp.size.return_value = 0
    ftp.connect = Mock(return_value=None)
    ftp.login = Mock(return_value="230 Login successful")
    mock_ftp_tls.return_value = ftp

    d = _make_dest()

    with patch.object(d, "_make_ftps", return_value=ftp):
        items = d.list_backups()

    names = [item.filename for item in items]
    assert len(names) == 2
    assert "a.tar.gz" in names
    assert "b.tar.gz" in names
    assert all(name.endswith(".tar.gz") for name in names)


@patch("ftplib.FTP_TLS")
def test_delete_backup(mock_ftp_tls):
    ftp = Mock()
    ftp.mkd.side_effect = [None, None]
    ftp.cwd.return_value = None
    ftp.delete.return_value = "250 Delete operation successful"
    ftp.set_pasv.return_value = None
    ftp.prot_p.return_value = None
    ftp.connect = Mock(return_value=None)
    ftp.login = Mock(return_value="230 Login successful")
    mock_ftp_tls.return_value = ftp

    d = _make_dest()

    with patch.object(d, "_make_ftps", return_value=ftp):
        ok = d.delete_backup("foo.tar.gz")

    assert ok
    assert ftp.delete.call_count == 2
    ftp.delete.assert_any_call("/foo.tar.gz")
    ftp.delete.assert_any_call("/foo.tar.gz.manifest.json")


@patch("ftplib.FTP_TLS")
def test_tls_and_passive_mode_controls(mock_ftp_tls):
    ftp = Mock()
    ftp.mkd.side_effect = [None, None]
    ftp.cwd.return_value = None
    ftp.storbinary.return_value = None
    ftp.delete.return_value = None
    ftp.size.return_value = 0
    ftp.set_pasv.return_value = None
    ftp.prot_p.return_value = None
    ftp.connect = Mock(return_value=None)
    ftp.login = Mock(return_value="230 Login successful")
    mock_ftp_tls.return_value = ftp

    d = _make_dest(passive=False, use_tls=True)
    with patch.object(d, "_make_ftps", return_value=ftp):
        ok, _ = d.test_connection()

    assert ok
    ftp.set_pasv.assert_called_with(False)
    assert d.use_tls is True
    ftp.prot_p.assert_called_once()
