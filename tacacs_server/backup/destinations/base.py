from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
import json

from tacacs_server.utils.logger import get_logger


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
        self._logger = get_logger(__name__)

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

    def apply_retention_policy(
        self,
        retention_days: int | None = None,
        retention_rule: "RetentionRule" | None = None,
    ) -> int:
        """
        Apply retention policy to delete old backups.

        Args:
            retention_days: Simple days-based retention (backwards compat)
            retention_rule: Advanced retention rule (GFS, Hanoi, etc.)

        Returns:
            Number of backups deleted
        """
        # Backwards compatible mapping: days -> simple rule
        if retention_rule is None and retention_days is not None:
            try:
                from tacacs_server.backup.retention import (
                    RetentionRule as _Rule,
                    RetentionStrategy as _Strat,
                )

                retention_rule = _Rule(
                    strategy=_Strat.SIMPLE, keep_days=int(retention_days)
                )
            except Exception:
                retention_rule = None

        if retention_rule is None:
            return 0

        # Compute deletions per policy
        try:
            backups = self.list_backups()
            from tacacs_server.backup.retention import RetentionPolicy as _Policy

            policy = _Policy(retention_rule)  # type: ignore[arg-type]
            to_delete = policy.apply(backups)
        except Exception:
            return 0

        # Delete selected backups
        deleted_count = 0
        for b in to_delete:
            try:
                if self.delete_backup(b.path):
                    deleted_count += 1
                    try:
                        age_days = 0
                        try:
                            ts = (
                                b.timestamp.replace("Z", "+00:00")
                                if isinstance(b.timestamp, str)
                                else str(b.timestamp)
                            )
                            bt = datetime.fromisoformat(ts)
                            if bt.tzinfo is None:
                                bt = bt.replace(tzinfo=UTC)
                            age_days = (datetime.now(UTC) - bt).days
                        except Exception:
                            pass
                        self._logger.info(
                            json.dumps(
                                {
                                    "event": "backup_deleted_by_retention",
                                    "path": b.path,
                                    "age_days": age_days,
                                }
                            )
                        )
                    except Exception:
                        pass
            except Exception as e:
                self._logger.error(f"Failed to delete backup {b.path}: {e}")
        return deleted_count
