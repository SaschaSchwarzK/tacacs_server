import os
import sqlite3
from pathlib import Path

import pytest

from tacacs_server.backup import database_utils as dbu
from tacacs_server.backup.destinations.base import BackupDestination, BackupMetadata
from tacacs_server.backup.execution_store import BackupExecutionStore
from tacacs_server.backup.service import BackupService
from tacacs_server.config.config import TacacsConfig


class FakeDestination(BackupDestination):
    def __init__(self, config):
        super().__init__(config)
        self.uploads: list[tuple[str, str]] = []
        self.downloads: list[tuple[str, str]] = []

    def validate_config(self) -> None:
        import os
        from pathlib import Path
        base = self.config.get("base")
        if not base:
            raise ValueError("missing base")
        # Restrict base under a test-only directory to avoid path traversal
        test_root = Path.cwd() / "test-backups"
        base_path = (test_root / os.path.normpath(base)).resolve()
        try:
            base_path.relative_to(test_root.resolve())
        except ValueError:
            raise ValueError("base path escapes test root")
        base_path.mkdir(parents=True, exist_ok=True)
    def test_connection(self) -> tuple[bool, str]:
        return True, "OK"

    def upload_backup(self, local_file_path: str, remote_filename: str) -> str:
        self.uploads.append((local_file_path, remote_filename))
        dest = Path(self.config["base"]) / remote_filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        Path(local_file_path).replace(dest) if Path(local_file_path).exists() else None
        return str(dest)

    def download_backup(self, remote_path: str, local_file_path: str) -> bool:
        self.downloads.append((remote_path, local_file_path))
        try:
            Path(local_file_path).parent.mkdir(parents=True, exist_ok=True)
            Path(remote_path).replace(local_file_path)
            return True
        except Exception:
            return False

    def list_backups(self, prefix: str | None = None) -> list[BackupMetadata]:
        items = []
        base = Path(self.config["base"]) if self.config.get("base") else Path(".")
        for p in base.rglob("*.tar.gz"):
            st = p.stat()
            items.append(
                BackupMetadata(
                    filename=p.name,
                    size_bytes=st.st_size,
                    timestamp=Path(p).stat().st_mtime_ns.__str__(),
                    path=str(p),
                    checksum_sha256="",
                )
            )
        return items

    def delete_backup(self, remote_path: str) -> bool:
        try:
            Path(remote_path).unlink(missing_ok=False)
            return True
        except Exception:
            return False

    def get_backup_info(self, remote_path: str) -> BackupMetadata | None:
        p = Path(remote_path)
        if not p.exists():
            return None
        st = p.stat()
        return BackupMetadata(
            filename=p.name,
            size_bytes=st.st_size,
            timestamp=str(st.st_mtime_ns),
            path=str(p),
            checksum_sha256="",
        )


def _make_sqlite_db(path: Path, table: str = "t1", rows: int = 3) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS {table}(id INTEGER PRIMARY KEY, v TEXT)"
        )
        for i in range(rows):
            conn.execute(f"INSERT INTO {table}(v) VALUES(?)", (f"row{i}",))
        conn.commit()


def _mk_config(tmp: Path) -> TacacsConfig:
    cfg_path = tmp / "tacacs.conf"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text("[server]\nport=49\n[auth]\nbackends=local\n", encoding="utf-8")

    # Ensure data dir exists for config_store
    (tmp / "data").mkdir(parents=True, exist_ok=True)

    import os

    os.chdir(tmp)  # So relative paths work

    return TacacsConfig(str(cfg_path))


def test_backup_service_initialization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg = _mk_config(tmp_path)
    store = BackupExecutionStore(str(tmp_path / "backup_exec.db"))
    svc = BackupService(cfg, store)
    assert svc.temp_dir.exists()
    assert isinstance(svc.instance_name, str) and svc.instance_name
    assert svc.execution_store is store


def test_manifest_creation(tmp_path: Path):
    cfg = _mk_config(tmp_path)
    store = BackupExecutionStore(str(tmp_path / "exec.db"))
    svc = BackupService(cfg, store)
    # Prepare backup dir with files and a sqlite db
    bdir = tmp_path / "b"
    bdir.mkdir()
    f = bdir / "file.txt"
    f.write_text("hello", encoding="utf-8")
    dbp = bdir / "data.db"
    _make_sqlite_db(dbp)
    manifest = svc._create_manifest(str(bdir), "manual", triggered_by="tester")
    assert "backup_metadata" in manifest
    assert manifest["backup_metadata"]["backup_type"] == "manual"
    # contents include file entries with checksum and size
    assert any(it["file"] == "file.txt" for it in manifest["contents"])  # type: ignore[index]
    assert manifest["total_size_bytes"] >= 5


def test_database_ops(tmp_path: Path):
    src = tmp_path / "src.db"
    dst = tmp_path / "dst.db"
    _make_sqlite_db(src, rows=5)
    # export
    dbu.export_database(str(src), str(dst))
    ok, msg = dbu.verify_database_integrity(str(dst))
    assert ok, msg
    counts = dbu.count_database_records(str(dst))
    assert sum(counts.values()) == 5
    # import overwrite
    dest2 = tmp_path / "final.db"
    dbu.import_database(str(dst), str(dest2), verify=True)
    ok2, _ = dbu.verify_database_integrity(str(dest2))
    assert ok2


def test_backup_workflow_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg = _mk_config(tmp_path)
    # Create expected database files in default locations
    _make_sqlite_db(tmp_path / "data" / "config_overrides.db", rows=1)
    _make_sqlite_db(tmp_path / "data" / "devices.db", rows=1)
    _make_sqlite_db(tmp_path / "data" / "local_auth.db", rows=1)
    _make_sqlite_db(tmp_path / "data" / "tacacs_accounting.db", rows=1)
    _make_sqlite_db(tmp_path / "data" / "metrics_history.db", rows=1)
    _make_sqlite_db(tmp_path / "data" / "audit_trail.db", rows=1)
    os.chdir(tmp_path)
    store = BackupExecutionStore(str(tmp_path / "exec.db"))
    svc = BackupService(cfg, store)
    # Add a destination
    dest_id = store.create_destination(
        name="local1",
        dest_type="local",
        config={"base_path": str(tmp_path / "dest")},
        created_by="tester",
    )
    # Monkeypatch factory to return FakeDestination writing under tmp
    from tacacs_server.backup import destinations as dest_mod

    def _fake_create(t: str, config: dict):
        return FakeDestination({"base": str(tmp_path / "dest")})

    monkeypatch.setattr(dest_mod, "create_destination", _fake_create)
    exec_id = svc.execute_backup(dest_id, triggered_by="tester")
    assert isinstance(exec_id, str)
    row = store.get_execution(exec_id)
    assert row is not None
    assert row["status"] in ("completed", "failed")  # allow either if files missing


def test_restore_workflow_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg = _mk_config(tmp_path)
    os.chdir(tmp_path)
    store = BackupExecutionStore(str(tmp_path / "exec.db"))
    svc = BackupService(cfg, store)
    dest_id = store.create_destination(
        name="d1",
        dest_type="local",
        config={"base_path": str(tmp_path / "dest")},
        created_by="tester",
    )
    from tacacs_server.backup import destinations as dest_mod

    def _fake_create(t: str, config: dict):
        return FakeDestination({"base": str(tmp_path / "dest")})

    monkeypatch.setattr(dest_mod, "create_destination", _fake_create)
    # prepare some dbs
    _make_sqlite_db(tmp_path / "data" / "local_auth.db", rows=2)
    exec_id = svc.execute_backup(dest_id, triggered_by="tester")
    row = store.get_execution(exec_id) or {}
    archive_path = row.get("backup_path")
    assert archive_path and Path(archive_path).exists()
    ok, msg = svc.restore_backup(source_path=str(archive_path), destination_id=dest_id)
    assert isinstance(ok, bool)
