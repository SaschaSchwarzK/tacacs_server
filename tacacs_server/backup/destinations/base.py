from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from tacacs_server.utils.logger import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tacacs_server.backup.retention import RetentionRule


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
        self._logger = get_logger(__name__)
        # Subclasses must call validate_config() after their __init__ completes
        # to ensure all subclass-specific attributes are initialized first

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
        retention_rule: RetentionRule | None = None,
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
                )
                from tacacs_server.backup.retention import (
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

            policy = _Policy(retention_rule)
            # RetentionPolicy expects its own BackupMetadata protocol; our
            # BackupMetadata is compatible at runtime. Use a narrow cast here
            # to satisfy static type checkers without changing runtime behavior.
            to_delete = policy.apply(cast(list[Any], backups))
        except Exception:
            return 0

        # Delete selected backups
        deleted_count = 0
        for b in to_delete:
            try:
                if not self.delete_backup(b.path):
                    continue
                deleted_count += 1
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
                except Exception as exc:
                    self._logger.debug("Failed to compute age for %s: %s", b.path, exc)
                try:
                    self._logger.info(
                        json.dumps(
                            {
                                "event": "backup_deleted_by_retention",
                                "path": b.path,
                                "age_days": age_days,
                            }
                        )
                    )
                except Exception as exc:
                    self._logger.debug(
                        "Failed to log deletion event for %s: %s", b.path, exc
                    )
            except Exception as e:
                self._logger.error(f"Failed to delete backup {b.path}: {e}")
        return deleted_count

    # ------------------------------
    # Path safety helpers
    # ------------------------------
    @staticmethod
    def validate_path_segment(
        name: str, *, allow_dot: bool = True, max_len: int = 128
    ) -> str:
        """Validate a single path segment to prevent traversal and unsafe chars.

        - Disallow directory separators and NUL
        - Disallow '.' and '..' segments
        - Allow only [A-Za-z0-9._-] characters (optionally '.' can be disallowed)
        - Enforce a conservative max length
        Returns the original name on success; raises ValueError on invalid input.
        """
        import re as _re

        s = str(name)
        if not s or len(s) > max_len:
            raise ValueError("Invalid name length")
        if "/" in s or "\\" in s or "\x00" in s:
            raise ValueError("Invalid characters in name")
        if s in (".", ".."):
            raise ValueError("Dot-only segments are not allowed")
        pattern = r"^[A-Za-z0-9._-]+$" if allow_dot else r"^[A-Za-z0-9_-]+$"
        if not _re.fullmatch(pattern, s):
            raise ValueError("Name contains disallowed characters")
        return s

    @staticmethod
    def validate_relative_path(path: str, *, max_segments: int = 10) -> str:
        """Validate a relative path composed of safe segments.

        - Must not be absolute; no leading '/'
        - Must not contain backslashes or NULs
        - Segments are separated by '/'
        - Intermediate segments: [A-Za-z0-9_-]+
        - Final segment may include dots to allow extensions
        - No '.' or '..' segments; no empty segments
        - Limit total number of segments
        Returns normalized relative path using '/'.
        """
        s = str(path or "").strip()
        if not s:
            raise ValueError("Empty path")
        if s.startswith("/"):
            raise ValueError("Absolute paths are not allowed")
        if "\\" in s or "\x00" in s:
            raise ValueError("Invalid characters in path")
        parts = [p for p in s.split("/")]
        if not parts or len(parts) > max_segments:
            raise ValueError("Invalid number of path segments")
        cleaned: list[str] = []
        for i, seg in enumerate(parts):
            if not seg:
                raise ValueError("Empty path segment")
            if seg in (".", ".."):
                raise ValueError("Dot segments are not allowed")
            allow_dot = i == (len(parts) - 1)
            cleaned.append(
                BackupDestination.validate_path_segment(seg, allow_dot=allow_dot)
            )
        return "/".join(cleaned)
