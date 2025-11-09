from pathlib import Path

import pytest

from tacacs_server.backup.destinations.local import LocalBackupDestination


@pytest.mark.integration
def test_local_destination_lifecycle(tmp_path: Path):
    """Test the full lifecycle of the LocalBackupDestination."""
    # Use a safe root compliant with path policy (avoid symlinked parents)
    # Force BACKUP_ROOT to a directory under the repository workspace
    import os

    repo_root = Path(__file__).resolve().parents[3]
    forced_root = (repo_root / "test_backups_root").resolve()
    forced_root.mkdir(parents=True, exist_ok=True)
    os.environ["BACKUP_ROOT"] = str(forced_root)
    # Some platforms have symlinked parents (e.g., /private/var). Our production
    # policy forbids symlinked parents; to test behavior without relaxing policy,
    # temporarily relax parent-symlink checks in validate_base_directory.
    import tacacs_server.backup.path_policy as _pp

    get_backup_root = _pp.get_backup_root
    _orig_vbd = _pp.validate_base_directory

    def _relaxed_validate_base_directory(
        path: str, allowed_root: Path | None = None
    ) -> Path:
        import os as _os
        from pathlib import Path as _P

        if not isinstance(path, str) or not path or "\x00" in path:
            raise ValueError("Invalid base directory path")
        p = _P(path)
        if not p.is_absolute():
            raise ValueError("Base directory must be an absolute path")
        try:
            p.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        resolved = p.resolve()
        if allowed_root is not None:
            ar = _P(allowed_root).resolve()
            try:
                resolved.relative_to(ar)
            except ValueError:
                raise ValueError(
                    f"Base directory '{resolved}' escapes allowed root '{ar}'"
                )
            if _os.path.commonpath([str(ar), str(resolved)]) != str(ar):
                raise ValueError(
                    f"Base directory must be under allowed root {ar}: {resolved}"
                )
        # Disallow base itself being a symlink; allow symlinked parents during this test
        if resolved.is_symlink():
            raise ValueError("Base directory may not be a symlink")
        return resolved

    _pp.validate_base_directory = _relaxed_validate_base_directory

    dest_dir = get_backup_root() / f"local_backups_{tmp_path.name}"
    dest_dir.mkdir(parents=True, exist_ok=True)

    config = {"base_path": str(dest_dir)}
    destination = LocalBackupDestination(config)

    # 1. Test Connection
    success, msg = destination.test_connection()
    assert success, f"Connection test failed: {msg}"

    # 2. Upload
    dummy_content = b"this is a test backup file"
    dummy_file = (get_backup_root() / f"dummy_{tmp_path.name}.tar.gz").resolve()
    dummy_file.write_bytes(dummy_content)

    remote_path_str = destination.upload_backup(str(dummy_file), "backup1.tar.gz")
    remote_path = Path(remote_path_str)
    assert remote_path.exists()
    assert remote_path.name == "backup1.tar.gz"
    assert remote_path.read_bytes() == dummy_content

    # 3. List
    backups = destination.list_backups()
    assert len(backups) == 1
    assert backups[0].filename == "backup1.tar.gz"
    assert backups[0].size_bytes == len(dummy_content)

    # 4. Get Info
    info = destination.get_backup_info(remote_path_str)
    assert info is not None
    assert info.filename == "backup1.tar.gz"

    # 5. Download
    # Download using a relative target name; destination stores under temp root
    from tacacs_server.backup.path_policy import safe_temp_path

    # Use a unique relative name to avoid cross-test collisions in shared temp
    rel_name = f"downloaded_{tmp_path.name}.tar.gz"
    assert destination.download_backup(remote_path_str, rel_name)
    expected_dl = safe_temp_path(rel_name)
    assert expected_dl.read_bytes() == dummy_content

    # 6. Delete
    assert destination.delete_backup(remote_path_str)
    assert not remote_path.exists()
    assert len(destination.list_backups()) == 0
    # Restore original validator
    _pp.validate_base_directory = _orig_vbd
