"""
Local Backup Destination Test Suite

This module contains unit tests for the LocalBackupDestination class, which handles
backup operations to local filesystem locations. It verifies the core functionality
of the local backup destination implementation.

Test Coverage:
- Configuration validation
- Connection testing
- File upload and download
- Metadata handling
- File listing and filtering
- Deletion operations
- Retention policy enforcement
- Error conditions and edge cases

Dependencies:
- pytest for test framework
- pathlib for cross-platform path handling
- stat for file permission testing
"""

import os
import stat
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tacacs_server.backup.destinations.local import LocalBackupDestination


def _abs(p: Path) -> str:
    """Convert a Path to an absolute path string.

    Args:
        p: Path to convert

    Returns:
        str: Absolute path as string
    """
    return str(p.resolve())


def test_config_validation_requires_absolute_base(tmp_path: Path):
    """Verify that only valid absolute paths are accepted for base_path.

    Test Steps:
    1. Attempt to create LocalBackupDestination with missing base_path
    2. Attempt with relative path
    3. Verify success with absolute path

    Expected Results:
    - Missing base_path raises ValueError
    - Relative path raises ValueError
    - Absolute path creates instance successfully

    Edge Cases:
    - Empty configuration
    - Relative paths in different formats
    - Path traversal attempts (implicitly tested)
    """
    # Missing base_path
    with pytest.raises(ValueError):
        LocalBackupDestination({})
    # Relative path rejected
    with pytest.raises(ValueError):
        LocalBackupDestination({"base_path": "relative/path"})
    # Valid absolute path
    d = LocalBackupDestination(
        {"base_path": _abs(tmp_path / "dest"), "allowed_root": _abs(tmp_path)}
    )
    assert isinstance(d, LocalBackupDestination), (
        "Should create instance with valid path"
    )


def test_connection_testing(tmp_path: Path):
    """Verify connection testing handles various directory states correctly.

    Test Cases:
    1. Writable directory
    2. Non-existent directory (after initialization)
    3. Read-only directory

    Expected Results:
    - Writable directory should pass connection test
    - Non-existent directory should fail connection test
    - Read-only directory should fail connection test

    Security Considerations:
    - Verifies proper handling of file system permissions
    - Ensures directory existence and write permissions are checked
    """
    # Test with writable directory
    base = tmp_path / "writable"
    base.mkdir(parents=True)
    dest = LocalBackupDestination(
        {"base_path": _abs(base), "allowed_root": _abs(tmp_path)}
    )
    ok, msg = dest.test_connection()
    assert ok, f"Connection test failed with message: {msg}"

    # Test with non-existent directory (after initialization)
    ro = tmp_path / "noexist"
    dest2 = LocalBackupDestination(
        {"base_path": _abs(ro), "allowed_root": _abs(tmp_path)}
    )
    # Directory is created on init; remove to simulate missing
    ro.rmdir()
    ok2, _ = dest2.test_connection()
    assert not ok2, "Should fail when directory disappears"

    # Test with read-only directory
    ro_dir = tmp_path / "readonly"
    ro_dir.mkdir()
    # Remove write perms for owner
    ro_dir.chmod(stat.S_IREAD | stat.S_IEXEC)
    try:
        dest3 = LocalBackupDestination(
            {"base_path": _abs(ro_dir), "allowed_root": _abs(tmp_path)}
        )
        ok3, _ = dest3.test_connection()
        assert not ok3, "Should fail with read-only directory"
    finally:
        # restore to allow tmp cleanup
        ro_dir.chmod(stat.S_IWUSR | stat.S_IREAD | stat.S_IEXEC)


def test_upload_download_and_preserve(tmp_path: Path):
    base = tmp_path / "dest"
    srcdir = tmp_path / "src"
    srcdir.mkdir()
    base.mkdir()
    src = srcdir / "archive.tar.gz"
    content = b"hello-backup"
    src.write_bytes(content)
    # Set a known mtime
    mtime = time.time() - 60
    os.utime(src, (mtime, mtime))
    dest = LocalBackupDestination(
        {"base_path": _abs(base), "allowed_root": _abs(tmp_path)}
    )
    remote = dest.upload_backup(str(src), "sub/dir/file.tar.gz")
    rp = Path(remote)
    assert rp.exists()
    # Check timestamp preservation (allowing some FS variance)
    assert abs(rp.stat().st_mtime - mtime) < 2.5
    # Download to a new path
    # Request download into a relative filename; file will be stored under temp root
    from tacacs_server.backup.path_policy import safe_temp_path

    # Use a unique name to avoid collisions across tests using shared temp root
    rel_name = f"dl_{tmp_path.name}.tar.gz"
    ok = dest.download_backup(str(rp), rel_name)
    expected = safe_temp_path(rel_name)
    assert ok and expected.read_bytes() == content


def test_listing_and_metadata(tmp_path: Path):
    base = tmp_path / "d"
    base.mkdir()
    # Create some backup-like files
    (base / "a.tar.gz").write_bytes(b"a")
    (base / "b.tgz").write_bytes(b"bb")
    (base / "c.zip").write_bytes(b"ccc")
    (base / "ignored.txt").write_text("x")
    dest = LocalBackupDestination(
        {"base_path": _abs(base), "allowed_root": _abs(tmp_path)}
    )
    items = dest.list_backups()
    names = [i.filename for i in items]
    assert set(names) >= {"a.tar.gz", "b.tgz", "c.zip"}
    # Prefix filter
    pref = dest.list_backups(prefix="a.tar.gz")
    assert len(pref) >= 1 and pref[0].filename == "a.tar.gz"


def test_delete_and_manifest(tmp_path: Path):
    base = tmp_path / "x"
    base.mkdir()
    f = base / "old.tar.gz"
    f.write_bytes(b"data")
    # Create a manifest file alongside expected suffix
    (base / "old.tar.gz.manifest.json").write_text("{}", encoding="utf-8")
    dest = LocalBackupDestination(
        {"base_path": _abs(base), "allowed_root": _abs(tmp_path)}
    )
    assert dest.delete_backup(str(f)) is True
    assert not f.exists()
    assert not (base / "old.tar.gz.manifest.json").exists()
    # Deleting non-existent returns False
    assert dest.delete_backup(str(f)) is False


def test_retention_policy(tmp_path: Path):
    base = tmp_path / "ret"
    base.mkdir()
    old = base / "old.tar.gz"
    new = base / "new.tar.gz"
    old.write_bytes(b"o")
    new.write_bytes(b"n")
    # Set times
    old_ts = (datetime.now() - timedelta(days=10)).timestamp()
    new_ts = (datetime.now() - timedelta(days=1)).timestamp()
    os.utime(old, (old_ts, old_ts))
    os.utime(new, (new_ts, new_ts))
    dest = LocalBackupDestination(
        {"base_path": _abs(base), "allowed_root": _abs(tmp_path)}
    )
    deleted = dest.apply_retention_policy(7)
    assert deleted >= 1
    assert not old.exists()
    assert new.exists()
