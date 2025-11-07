from pathlib import Path

import pytest

from tacacs_server.backup.destinations.local import LocalBackupDestination


@pytest.mark.integration
def test_local_destination_lifecycle(tmp_path: Path):
    """Test the full lifecycle of the LocalBackupDestination."""
    dest_dir = tmp_path / "local_backups"
    dest_dir.mkdir()

    config = {"base_path": str(dest_dir), "allowed_root": str(tmp_path)}
    destination = LocalBackupDestination(config)

    # 1. Test Connection
    success, msg = destination.test_connection()
    assert success, f"Connection test failed: {msg}"

    # 2. Upload
    dummy_content = b"this is a test backup file"
    dummy_file = tmp_path / "dummy_backup.tar.gz"
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
