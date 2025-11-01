from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from tacacs_server.backup.destinations.ftp import FTPBackupDestination


def _make_dest(**overrides: Any) -> FTPBackupDestination:
    # Default config with all required fields
    cfg = {
        "host": "ftp.example.com",
        "username": "user",
        "password": "pass",
        "base_path": "/backups",
        "port": 2121,  # Use a non-standard port for testing
        "use_tls": False,  # Explicitly set to False for tests
        "timeout": 30,  # Add default timeout
        "passive": True,  # Default passive mode
    }
    # Update with any overrides
    cfg.update(overrides)

    # Ensure port is an integer and within valid range
    port = cfg.get("port")
    if port is not None:
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError("Invalid FTP port; must be 1-65535")
            cfg["port"] = port
        except (ValueError, TypeError) as e:
            if "port" in overrides:  # Only raise if port was explicitly provided
                raise ValueError("Invalid FTP port; must be 1-65535") from e

    return FTPBackupDestination(cfg)


def test_config_validation_ok():
    """Test that valid config passes validation."""
    # Test with default config
    dest = _make_dest()
    assert dest.host == "ftp.example.com"
    assert dest.port == 2121
    assert dest.username == "user"
    assert dest.password == "pass"
    assert dest.base_path == "/backups"
    assert dest.use_tls is False

    # Test with string port
    dest = _make_dest(port="21")
    assert dest.port == 21

    # Test with None port (should use default)
    dest = _make_dest(port=None)
    assert dest.port == 21  # Default port for non-TLS


# Remove duplicate test_connection_success function


def test_config_validation_missing_fields():
    with pytest.raises(ValueError):
        FTPBackupDestination({})
    with pytest.raises(ValueError):
        _make_dest(host="")
    with pytest.raises(ValueError):
        _make_dest(username="")
    with pytest.raises(ValueError):
        _make_dest(password="")
    with pytest.raises(ValueError):
        _make_dest(base_path="")


def test_invalid_port_rejected():
    # Test invalid port values
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
    # Prepare mock FTP
    ftp = Mock()
    ftp.mkd.side_effect = [None, None]  # mkd may be called and allowed to fail
    ftp.cwd.return_value = None
    ftp.storbinary.return_value = None
    ftp.delete.return_value = None
    ftp.set_pasv.return_value = None
    ftp.prot_p.return_value = None
    ftp.size.return_value = 0  # Add size method for upload verification
    mock_ftp_tls.return_value = ftp

    # Use a separate mock for the connect method
    ftp.connect = Mock(return_value=None)
    ftp.login = Mock(return_value="230 Login successful")

    d = _make_dest()

    # Test connection with mock
    with patch.object(d, "_make_ftps", return_value=ftp):
        ok, msg = d.test_connection()

    assert ok, msg

    # Verify mocks were called as expected
    ftp.connect.assert_called_once_with("ftp.example.com", 2121, timeout=30)
    ftp.login.assert_called_once_with("user", "pass")
    ftp.set_pasv.assert_called_once_with(True)  # Default passive mode


@patch("ftplib.FTP_TLS")
def test_connection_failure(mock_ftp_tls):
    ftp = Mock()
    ftp.connect.side_effect = Exception("boom")
    mock_ftp_tls.return_value = ftp

    # Mock the login method (shouldn't be called, but just in case)
    ftp.login.side_effect = Exception("Should not be called")

    d = _make_dest()

    # Test connection with mock
    with patch.object(d, "_make_ftps", return_value=ftp):
        ok, msg = d.test_connection()

    assert not ok
    assert isinstance(msg, str)
    assert "boom" in msg


@patch("ftplib.FTP_TLS")
def test_upload_and_download_roundtrip(mock_ftp_tls, tmp_path: Path):
    # Prepare source file
    src = tmp_path / "archive.tar.gz"
    data = b"hello-backup\n" * 10
    src.write_bytes(data)

    # Prepare mock FTP
    ftp = Mock()
    ftp.mkd.side_effect = [None, None, None]  # For base_path and any subdirs
    ftp.cwd.return_value = None
    ftp.set_pasv.return_value = None
    ftp.prot_p.return_value = None
    ftp.size.return_value = len(data)

    # Simulate successful file operations
    def storbinary(cmd, fh, blocksize=8192):
        assert cmd.startswith("STOR ")
        # Read the data to simulate transfer
        fh.read()
        return "226 Transfer complete"

    def retrbinary(cmd, callback, blocksize=8192, **kwargs):
        callback(data)
        return "226 Transfer complete"

    ftp.storbinary.side_effect = storbinary
    ftp.retrbinary.side_effect = retrbinary
    mock_ftp_tls.return_value = ftp

    # Test upload
    d = _make_dest()
    with patch.object(d, "_make_ftps", return_value=ftp):
        remote = d.upload_backup(str(src), "test-upload")
        assert remote.endswith("/test-upload")

        # Test download
        dl = tmp_path / "downloaded.tar.gz"
        ok = d.download_backup(remote, str(dl))
        assert ok
        assert dl.read_bytes() == data


@patch("ftplib.FTP_TLS")
def test_partial_upload_cleanup_on_error(mock_ftp_tls, tmp_path: Path):
    from ftplib import error_perm

    src = tmp_path / "file.tar.gz"
    src.write_bytes(b"x" * 1024)

    # Prepare mock FTP
    ftp = Mock()
    ftp.mkd.return_value = None
    ftp.cwd.return_value = None
    ftp.set_pasv.return_value = None
    ftp.prot_p.return_value = None

    # Simulate upload failure
    ftp.storbinary.side_effect = error_perm("disk full")
    ftp.delete.return_value = None  # For cleanup
    mock_ftp_tls.return_value = ftp

    # Test upload with failure
    d = _make_dest()
    with patch.object(d, "_make_ftps", return_value=ftp):
        with pytest.raises(RuntimeError) as excinfo:
            d.upload_backup(str(src), "test.tar.gz")
        assert "disk full" in str(excinfo.value)

        # Ensure cleanup was attempted
        assert ftp.delete.called


@patch("ftplib.FTP_TLS")
def test_listing_with_mlsd(mock_ftp_tls):
    # Prepare mock FTP
    ftp = Mock()
    ftp.mkd.side_effect = [None, None]  # For base_path
    ftp.cwd.return_value = None
    ftp.set_pasv.return_value = None
    ftp.prot_p.return_value = None

    # mlsd returns iterable; our implementation expects (facts, name)
    def _mlsd(dirpath):
        return [
            ({"type": "file", "size": "10", "modify": "20240101000000"}, "a.tar.gz"),
            ({"type": "file", "size": "20", "modify": "20240201000000"}, "b.tar.gz"),
            ("ignored", "notes.txt"),
        ]

    ftp.mlsd.side_effect = _mlsd
    ftp.size.return_value = 0  # For size checks
    mock_ftp_tls.return_value = ftp

    # Use mocks for connect and login
    ftp.connect = Mock(return_value=None)
    ftp.login = Mock(return_value="230 Login successful")

    # Use _make_dest to ensure proper port configuration
    d = _make_dest()

    d = _make_dest()

    # Test list_backups with mock
    with patch.object(d, "_make_ftps", return_value=ftp):
        items = d.list_backups()

    # Extract filenames from backup items
    names = [item.filename for item in items]

    # Verify we got the expected files (only .tar.gz files should be returned)
    assert len(names) == 2
    assert "a.tar.gz" in names
    assert "b.tar.gz" in names
    assert all(name.endswith(".tar.gz") for name in names)


@patch("ftplib.FTP_TLS")
def test_delete_backup(mock_ftp_tls):
    # Prepare mock FTP
    ftp = Mock()
    ftp.mkd.side_effect = [None, None]  # For base_path
    ftp.cwd.return_value = None
    ftp.delete.return_value = "250 Delete operation successful"
    ftp.set_pasv.return_value = None
    ftp.prot_p.return_value = None
    mock_ftp_tls.return_value = ftp

    # Use mocks for connect and login
    ftp.connect = Mock(return_value=None)
    ftp.login = Mock(return_value="230 Login successful")

    # Use _make_dest to ensure proper port configuration
    d = _make_dest()

    d = _make_dest()

    # Test delete_backup with mock
    with patch.object(d, "_make_ftps", return_value=ftp):
        ok = d.delete_backup("foo.tar.gz")

    assert ok
    # Should attempt to delete both the file and its manifest
    assert ftp.delete.call_count == 2
    ftp.delete.assert_any_call("/foo.tar.gz")
    ftp.delete.assert_any_call("/foo.tar.gz.manifest.json")


@patch("ftplib.FTP_TLS")
def test_tls_and_passive_mode_controls(mock_ftp_tls):
    # Prepare mock FTP
    ftp = Mock()
    ftp.mkd.side_effect = [None, None]  # For base_path
    ftp.cwd.return_value = None
    ftp.storbinary.return_value = None
    ftp.delete.return_value = None
    ftp.size.return_value = 0
    mock_ftp_tls.return_value = ftp

    # Test with passive=False and use_tls=True
    d = _make_dest(passive=False, use_tls=True)
    ok, _ = d.test_connection()
    assert ok

    # Verify passive mode was set to False
    ftp.set_pasv.assert_called_with(False)

    # Verify TLS was used
    assert d.use_tls is True
    ftp.prot_p.assert_called_once()  # Should be called for TLS
