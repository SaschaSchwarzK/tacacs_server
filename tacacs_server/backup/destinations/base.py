from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class BackupMetadata:
    """Metadata about a backup file."""

    filename: str
    size_bytes: int
    timestamp: str  # ISO8601
    path: str  # Full path/URL
    checksum_sha256: str


class BackupDestination(ABC):
    def __init__(self, config: dict[str, Any]):
        self.config = config or {}
        self.validate_config()

    @abstractmethod
    def validate_config(self) -> None:
        """Validate configuration, raise ValueError if invalid"""
        raise NotImplementedError

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """Test connectivity. Returns (success, message)"""
        raise NotImplementedError

    @abstractmethod
    def upload_backup(self, local_file_path: str, remote_filename: str) -> str:
        """
        Upload backup file to destination.
        Returns: Full path/URL of uploaded backup
        """
        raise NotImplementedError

    @abstractmethod
    def download_backup(self, remote_path: str, local_file_path: str) -> bool:
        """Download backup from destination to local path"""
        raise NotImplementedError

    @abstractmethod
    def list_backups(self, prefix: str | None = None) -> list[BackupMetadata]:
        """List all backups at destination"""
        raise NotImplementedError

    @abstractmethod
    def delete_backup(self, remote_path: str) -> bool:
        """Delete a backup from destination"""
        raise NotImplementedError

    @abstractmethod
    def get_backup_info(self, remote_path: str) -> BackupMetadata | None:
        """Get metadata about a specific backup"""
        raise NotImplementedError

    def apply_retention_policy(self, retention_days: int) -> int:
        """
        Delete backups older than retention_days.
        Returns: Number of backups deleted
        """
        from datetime import datetime, timezone, timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(days=max(0, int(retention_days)))
        deleted = 0
        try:
            for meta in self.list_backups():
                try:
                    ts = datetime.fromisoformat(meta.timestamp)
                except Exception:
                    # If timestamp not parseable, skip
                    continue
                if ts < cutoff:
                    if self.delete_backup(meta.path):
                        deleted += 1
        except Exception:
            return deleted
        return deleted

