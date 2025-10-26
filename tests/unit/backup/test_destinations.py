import os
import stat
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tacacs_server.backup.destinations.local import LocalBackupDestination


def _abs(p: Path) -> str:
    return str(p.resolve())


def test_config_validation_requires_absolute_base(tmp_path: Path):
    # Missing base_path
    with pytest.raises(ValueError):
        LocalBackupDestination({})
    # Relative path rejected
    with pytest.raises(ValueError):
        LocalBackupDestination({"base_path": "relative/path"})
    # Valid absolute path
    d = LocalBackupDestination({"base_path": _abs(tmp_path / "dest")})
    assert isinstance(d, LocalBackupDestination)


def test_connection_testing(tmp_path: Path):
    base = tmp_path / "writable"
    base.mkdir(parents=True)
    dest = LocalBackupDestination({"base_path": _abs(base)})
    ok, msg = dest.test_connection()
    assert ok, msg
    # Non-existent directory (object creates on validate_config, but if removed later)
    ro = tmp_path / "noexist"
    dest2 = LocalBackupDestination({"base_path": _abs(ro)})
    # Directory is created on init; remove to simulate missing
    ro.rmdir()
    ok2, _ = dest2.test_connection()
    assert not ok2
    # Read-only directory fails write test
    ro_dir = tmp_path / "readonly"
    ro_dir.mkdir()
    # Remove write perms for owner
    ro_dir.chmod(stat.S_IREAD | stat.S_IEXEC)
    try:
        dest3 = LocalBackupDestination({"base_path": _abs(ro_dir)})
        ok3, _ = dest3.test_connection()
        assert not ok3
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
    dest = LocalBackupDestination({"base_path": _abs(base)})
    remote = dest.upload_backup(str(src), "sub/dir/file.tar.gz")
    rp = Path(remote)
    assert rp.exists()
    # Check timestamp preservation (allowing some FS variance)
    assert abs(rp.stat().st_mtime - mtime) < 2.5
    # Download to a new path
    dl = tmp_path / "dl.tar.gz"
    ok = dest.download_backup(str(rp), str(dl))
    assert ok and dl.read_bytes() == content


def test_listing_and_metadata(tmp_path: Path):
    base = tmp_path / "d"
    base.mkdir()
    # Create some backup-like files
    (base / "a.tar.gz").write_bytes(b"a")
    (base / "b.tgz").write_bytes(b"bb")
    (base / "c.zip").write_bytes(b"ccc")
    (base / "ignored.txt").write_text("x")
    dest = LocalBackupDestination({"base_path": _abs(base)})
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
    dest = LocalBackupDestination({"base_path": _abs(base)})
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
    dest = LocalBackupDestination({"base_path": _abs(base)})
    deleted = dest.apply_retention_policy(7)
    assert deleted >= 1
    assert not old.exists()
    assert new.exists()
