from __future__ import annotations

from typing import Any

from .base import BackupDestination, BackupMetadata


class FTPBackupDestination(BackupDestination):
    """Stub FTP destination. Methods are not implemented yet.

    Exists to satisfy factory imports and allow configuration to be created
    without enabling functionality yet.
    """

    def validate_config(self) -> None:
        # Minimal validation to allow storing config; not enforcing specifics yet
        cfg = self.config or {}
        if not isinstance(cfg, dict):
            raise ValueError("config must be a dict")

    def test_connection(self) -> tuple[bool, str]:
        return False, "FTP destination not implemented"

    def upload_backup(self, local_file_path: str, remote_filename: str) -> str:
        raise NotImplementedError("FTP upload not implemented")

    def download_backup(self, remote_path: str, local_file_path: str) -> bool:
        raise NotImplementedError("FTP download not implemented")

    def list_backups(self, prefix: str | None = None) -> list[BackupMetadata]:
        raise NotImplementedError("FTP list not implemented")

    def delete_backup(self, remote_path: str) -> bool:
        raise NotImplementedError("FTP delete not implemented")

    def get_backup_info(self, remote_path: str) -> BackupMetadata | None:
        raise NotImplementedError("FTP get info not implemented")

