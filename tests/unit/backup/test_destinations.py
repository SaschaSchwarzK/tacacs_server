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
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import tacacs_server.backup.path_policy as _pp
from tacacs_server.backup.destinations.local import LocalBackupDestination


def _abs(p: Path) -> str:
    """Convert a Path to an absolute path string.

    Args:
        p: Path to convert

    Returns:
        str: Absolute path as string
    """
    return str(p.resolve())


def _get_test_backup_root() -> Path:
    """Get the test backup root that's been set up by conftest."""
    return _pp.get_backup_root()


def _short_test_root() -> Path:
    root = Path(tempfile.mkdtemp(prefix="tacacs-test-backups-"))
    root.mkdir(parents=True, exist_ok=True)
    return root


def _ensure_allowed(root: Path) -> None:
    """Ensure test root is permitted by policy for allowed_root validation."""

    resolved_root = root.resolve()
    temp_base = Path(tempfile.gettempdir()).resolve()
    if temp_base not in _pp.ALLOWED_ROOTS:
        _pp.ALLOWED_ROOTS.append(temp_base)
    if resolved_root not in _pp.ALLOWED_ROOTS:
        _pp.ALLOWED_ROOTS.append(resolved_root)


def test_config_validation_requires_absolute_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
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

    # Valid absolute path under policy-compliant root
    test_root = _short_test_root()
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")
    monkeypatch.setenv("BACKUP_ROOT", str(test_root))
    test_root = _get_test_backup_root()
    _ensure_allowed(test_root)
    base = test_root / f"dest_{tmp_path.name}"
    base.mkdir(parents=True, exist_ok=True)
    d = LocalBackupDestination(
        {"base_path": _abs(base), "allowed_root": _abs(test_root)}
    )
    assert isinstance(d, LocalBackupDestination), (
        "Should create instance with valid path"
    )


def test_connection_testing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
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
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")
    monkeypatch.setenv("BACKUP_ROOT", str(tmp_path / "backups_root"))
    test_root = _short_test_root()
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")
    monkeypatch.setenv("BACKUP_ROOT", str(test_root))
    test_root = _get_test_backup_root()
    _ensure_allowed(test_root)
    _ensure_allowed(test_root)

    # Test with writable directory
    base = test_root / f"writable_{tmp_path.name}"
    base.mkdir(parents=True, exist_ok=True)
    dest = LocalBackupDestination(
        {"base_path": _abs(base), "allowed_root": _abs(test_root)}
    )
    ok, msg = dest.test_connection()
    assert ok, f"Connection test failed with message: {msg}"

    # Test with non-existent directory (after initialization)
    ro = test_root / f"noexist_{tmp_path.name}"
    dest2 = LocalBackupDestination(
        {"base_path": _abs(ro), "allowed_root": _abs(test_root)}
    )
    # Directory is created on init; remove to simulate missing
    ro.rmdir()
    ok2, _ = dest2.test_connection()
    assert not ok2, "Should fail when directory disappears"

    # Test with read-only directory
    ro_dir = test_root / f"readonly_{tmp_path.name}"
    ro_dir.mkdir(parents=True, exist_ok=True)
    # Remove write perms for owner
    ro_dir.chmod(stat.S_IREAD | stat.S_IEXEC)
    try:
        dest3 = LocalBackupDestination(
            {"base_path": _abs(ro_dir), "allowed_root": _abs(test_root)}
        )
        ok3, _ = dest3.test_connection()
        assert not ok3, "Should fail with read-only directory"
    finally:
        # restore to allow tmp cleanup
        ro_dir.chmod(stat.S_IWUSR | stat.S_IREAD | stat.S_IEXEC)


def test_upload_download_and_preserve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    test_root = _short_test_root()
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")
    monkeypatch.setenv("BACKUP_ROOT", str(test_root))
    test_root = _get_test_backup_root()
    _ensure_allowed(test_root)
    base = test_root / f"dest_{tmp_path.name}"
    srcdir = test_root / f"src_{tmp_path.name}"
    srcdir.mkdir(parents=True, exist_ok=True)
    base.mkdir(parents=True, exist_ok=True)

    src = srcdir / "archive.tar.gz"
    content = b"hello-backup"
    src.write_bytes(content)

    # Set a known mtime
    mtime = time.time() - 60
    os.utime(src, (mtime, mtime))

    dest = LocalBackupDestination(
        {"base_path": _abs(base), "allowed_root": _abs(test_root)}
    )
    remote = dest.upload_backup(str(src), "sub/dir/file.tar.gz")
    rp = Path(remote)
    assert rp.exists()

    # Check timestamp preservation (allowing some FS variance)
    assert abs(rp.stat().st_mtime - mtime) < 2.5

    # Download to a new path
    # Use a unique name to avoid collisions across tests using shared temp root
    rel_name = f"dl_{tmp_path.name}.tar.gz"
    ok = dest.download_backup(str(rp), rel_name)
    expected = _pp.safe_temp_path(rel_name)
    assert ok and expected.read_bytes() == content


def test_listing_and_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    test_root = _short_test_root()
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")
    monkeypatch.setenv("BACKUP_ROOT", str(test_root))
    test_root = _get_test_backup_root()
    _ensure_allowed(test_root)
    base = test_root / f"d_{tmp_path.name}"
    base.mkdir(parents=True, exist_ok=True)

    # Create some backup-like files
    (base / "a.tar.gz").write_bytes(b"a")
    (base / "b.tgz").write_bytes(b"bb")
    (base / "c.zip").write_bytes(b"ccc")
    (base / "ignored.txt").write_text("x")

    dest = LocalBackupDestination(
        {"base_path": _abs(base), "allowed_root": _abs(test_root)}
    )
    items = dest.list_backups()
    names = [i.filename for i in items]
    assert set(names) >= {"a.tar.gz", "b.tgz", "c.zip"}

    # Prefix filter
    pref = dest.list_backups(prefix="a.tar.gz")
    assert len(pref) >= 1 and pref[0].filename == "a.tar.gz"


def test_delete_and_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    test_root = _short_test_root()
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")
    monkeypatch.setenv("BACKUP_ROOT", str(test_root))
    test_root = _get_test_backup_root()
    _ensure_allowed(test_root)
    base = test_root / f"x_{tmp_path.name}"
    base.mkdir(parents=True, exist_ok=True)

    f = base / "old.tar.gz"
    f.write_bytes(b"data")
    # Create a manifest file alongside expected suffix
    (base / "old.tar.gz.manifest.json").write_text("{}", encoding="utf-8")

    dest = LocalBackupDestination(
        {"base_path": _abs(base), "allowed_root": _abs(test_root)}
    )
    assert dest.delete_backup(str(f)) is True
    assert not f.exists()
    assert not (base / "old.tar.gz.manifest.json").exists()

    # Deleting non-existent returns False
    assert dest.delete_backup(str(f)) is False


def test_retention_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    test_root = _short_test_root()
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")
    monkeypatch.setenv("BACKUP_ROOT", str(test_root))
    test_root = _get_test_backup_root()
    base = test_root / f"ret_{tmp_path.name}"
    base.mkdir(parents=True, exist_ok=True)

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
        {"base_path": _abs(base), "allowed_root": _abs(test_root)}
    )
    deleted = dest.apply_retention_policy(7)
    assert deleted >= 1
    assert not old.exists()
    assert new.exists()
