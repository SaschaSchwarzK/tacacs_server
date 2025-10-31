from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Protocol


class RetentionStrategy(Enum):
    """Retention policy strategies."""

    SIMPLE = "simple"  # Keep last N backups or days
    GFS = "gfs"  # Grandfather-Father-Son
    TOWER_OF_HANOI = "hanoi"  # Tower of Hanoi pattern


@dataclass
class RetentionRule:
    """Configuration for a retention rule."""

    strategy: RetentionStrategy
    keep_daily: int = 7  # Keep daily backups for N days
    keep_weekly: int = 4  # Keep weekly backups for N weeks
    keep_monthly: int = 12  # Keep monthly backups for N months
    keep_yearly: int = 3  # Keep yearly backups for N years
    keep_count: int | None = None  # For simple strategy: keep last N backups
    keep_days: int | None = None  # For simple strategy: keep backups for N days


class BackupMetadata(Protocol):
    """Protocol for backup metadata objects."""

    filename: str
    timestamp: str
    size_bytes: int
    path: str


class RetentionPolicy:
    """Apply retention policies to backup lists."""

    def __init__(self, rule: RetentionRule):
        self.rule = rule

    def apply(self, backups: list[BackupMetadata]) -> list[BackupMetadata]:
        """
        Determine which backups to delete based on retention policy.

        Args:
            backups: List of all available backups (sorted by timestamp desc recommended)

        Returns:
            List of backups to DELETE
        """
        if self.rule.strategy == RetentionStrategy.SIMPLE:
            return self._apply_simple(backups)
        elif self.rule.strategy == RetentionStrategy.GFS:
            return self._apply_gfs(backups)
        elif self.rule.strategy == RetentionStrategy.TOWER_OF_HANOI:
            return self._apply_hanoi(backups)
        else:  # pragma: no cover - defensive path
            raise ValueError(f"Unknown retention strategy: {self.rule.strategy}")

    # --- strategies ---
    def _apply_simple(self, backups: list[BackupMetadata]) -> list[BackupMetadata]:
        """Simple retention: Keep last N backups or backups younger than N days."""
        to_delete: list[BackupMetadata] = []

        if self.rule.keep_count is not None:
            # Keep last N backups, delete the rest (assumes input sorted newest-first)
            if len(backups) > int(self.rule.keep_count):
                to_delete = backups[int(self.rule.keep_count) :]

        elif self.rule.keep_days is not None:
            # Keep backups younger than N days, delete older
            cutoff_date = datetime.now(UTC) - timedelta(days=int(self.rule.keep_days))
            for backup in backups:
                bt = self._parse_ts(backup.timestamp)
                if bt and bt < cutoff_date:
                    to_delete.append(backup)

        return to_delete

    def _apply_gfs(self, backups: list[BackupMetadata]) -> list[BackupMetadata]:
        """
        Grandfather-Father-Son retention:
        - Daily: Keep for N days
        - Weekly: Keep one per week for N weeks (ISO weeks)
        - Monthly: Keep one per month for N months
        - Yearly: Keep one per year for N years
        """
        now = datetime.now(UTC)
        keep: set[str] = set()

        # Sort oldest->newest for forward pass selection
        sorted_backups = sorted(backups, key=lambda b: b.timestamp)

        # Daily: keep backups from last N days
        daily_cutoff = now - timedelta(days=max(0, int(self.rule.keep_daily)))
        for b in sorted_backups:
            bt = self._parse_ts(b.timestamp)
            if bt and bt >= daily_cutoff:
                keep.add(b.path)

        # Weekly: one per week for N weeks (prior to daily window)
        weekly_cutoff = now - timedelta(weeks=max(0, int(self.rule.keep_weekly)))
        weeks_seen: set[tuple[int, int]] = set()
        for b in sorted_backups:
            bt = self._parse_ts(b.timestamp)
            if not bt:
                continue
            if bt < daily_cutoff and bt >= weekly_cutoff:
                wk = (bt.isocalendar().year, bt.isocalendar().week)
                if wk not in weeks_seen:
                    keep.add(b.path)
                    weeks_seen.add(wk)

        # Monthly: one per month for N months (prior to weekly window)
        monthly_cutoff = now - timedelta(days=max(0, int(self.rule.keep_monthly)) * 30)
        months_seen: set[tuple[int, int]] = set()
        for b in sorted_backups:
            bt = self._parse_ts(b.timestamp)
            if not bt:
                continue
            if bt < weekly_cutoff and bt >= monthly_cutoff:
                mk = (bt.year, bt.month)
                if mk not in months_seen:
                    keep.add(b.path)
                    months_seen.add(mk)

        # Yearly: one per year for N years (prior to monthly window)
        yearly_cutoff = now - timedelta(days=max(0, int(self.rule.keep_yearly)) * 365)
        years_seen: set[int] = set()
        for b in sorted_backups:
            bt = self._parse_ts(b.timestamp)
            if not bt:
                continue
            if bt < monthly_cutoff and bt >= yearly_cutoff:
                yk = bt.year
                if yk not in years_seen:
                    keep.add(b.path)
                    years_seen.add(yk)

        # Everything not selected is deletable
        return [b for b in backups if b.path not in keep]

    def _apply_hanoi(self, backups: list[BackupMetadata]) -> list[BackupMetadata]:
        """
        Tower of Hanoi retention pattern.

        Keep backups at exponentially increasing intervals:
        - Backup 0: Keep (most recent)
        - Backup 1: Keep (1 day ago)
        - Backup 2-3: Keep one (2 day interval)
        - Backup 4-7: Keep one (4 day interval)
        - Backup 8-15: Keep one (8 day interval)
        - etc.
        """
        if not backups:
            return []

        keep: set[str] = set()
        # Newest-first for index-based selection
        sorted_backups = sorted(backups, key=lambda b: b.timestamp, reverse=True)

        # Always keep the most recent
        keep.add(sorted_backups[0].path)

        interval = 1  # Start with 1 backup interval
        next_threshold = 1
        for idx, b in enumerate(sorted_backups):
            if idx >= next_threshold:
                keep.add(b.path)
                interval *= 2
                next_threshold += interval

        return [b for b in backups if b.path not in keep]

    # --- helpers ---
    @staticmethod
    def _parse_ts(ts: str) -> datetime | None:
        """Parse ISO8601 timestamp, tolerant of 'Z' suffix; returns aware UTC datetime."""
        if not ts:
            return None
        try:
            # Accept timestamps like '2024-01-01T00:00:00Z' and convert to aware
            if ts.endswith("Z"):
                ts = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC)
        except Exception:
            return None
