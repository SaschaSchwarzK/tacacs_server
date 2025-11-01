from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

from tacacs_server.backup.retention import (
    RetentionPolicy,
    RetentionRule,
    RetentionStrategy,
)


def _mk_backup(days_ago: int, name: str | None = None) -> Mock:
    ts = (datetime.now(UTC) - timedelta(days=days_ago)).isoformat()
    name = name or f"backup-{days_ago}.tar.gz"
    return Mock(
        filename=name,
        timestamp=ts,
        path=f"/backups/{name}",
        size_bytes=10,
    )


def test_simple_keep_last_n():
    backups = [_mk_backup(i) for i in range(10)]
    rule = RetentionRule(strategy=RetentionStrategy.SIMPLE, keep_count=5)
    policy = RetentionPolicy(rule)
    to_delete = policy.apply(backups)
    assert len(to_delete) == 5
    deleted_names = {b.filename for b in to_delete}
    assert all(f"backup-{i}.tar.gz" in deleted_names for i in range(5, 10))


def test_simple_keep_last_n_underflow():
    backups = [_mk_backup(i) for i in range(3)]
    rule = RetentionRule(strategy=RetentionStrategy.SIMPLE, keep_count=5)
    policy = RetentionPolicy(rule)
    to_delete = policy.apply(backups)
    assert len(to_delete) == 0


def test_simple_keep_days():
    backups = [_mk_backup(0), _mk_backup(1), _mk_backup(10), _mk_backup(20)]
    rule = RetentionRule(strategy=RetentionStrategy.SIMPLE, keep_days=7)
    policy = RetentionPolicy(rule)
    to_delete = policy.apply(backups)
    assert len(to_delete) == 2
    deleted = {b.filename for b in to_delete}
    assert "backup-10.tar.gz" in deleted
    assert "backup-20.tar.gz" in deleted


def test_simple_keep_days_edge_case():
    backups = []
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=7)
    backups.append(
        Mock(
            filename="edge.tar.gz",
            timestamp=cutoff.isoformat(),
            path="/backups/edge.tar.gz",
            size_bytes=1,
        )
    )
    rule = RetentionRule(strategy=RetentionStrategy.SIMPLE, keep_days=7)
    to_delete = RetentionPolicy(rule).apply(backups)
    assert len(to_delete) == 1


def test_gfs_retention():
    from datetime import datetime as _dt
    from datetime import timedelta as _td

    base_time = _dt.utcnow()
    backups = []
    for days_ago in range(400):
        backup_time = base_time - _td(days=days_ago)
        backups.append(
            Mock(
                filename=f"backup-{days_ago}.tar.gz",
                timestamp=backup_time.isoformat() + "Z",
                path=f"/backups/backup-{days_ago}.tar.gz",
                size_bytes=1_000_000,
            )
        )

    rule = RetentionRule(
        strategy=RetentionStrategy.GFS,
        keep_daily=7,
        keep_weekly=4,
        keep_monthly=12,
        keep_yearly=3,
    )
    policy = RetentionPolicy(rule)
    to_delete = policy.apply(backups)
    to_keep = [b for b in backups if b not in to_delete]

    assert len(to_keep) <= 7 + 4 + 12 + 3

    recent = [
        b
        for b in backups
        if (
            base_time
            - _dt.fromisoformat(b.timestamp.replace("Z", "+00:00")).replace(tzinfo=None)
        ).days
        < 7
    ]
    for b in recent:
        assert b in to_keep


def test_hanoi_pattern_keeps_recent_and_exponential():
    backups = [_mk_backup(i) for i in range(32)]
    rule = RetentionRule(strategy=RetentionStrategy.TOWER_OF_HANOI)
    policy = RetentionPolicy(rule)
    to_delete = policy.apply(backups)
    kept = [b for b in backups if b not in to_delete]
    assert backups[0] in kept
    assert len(kept) <= 1 + 1 + 2 + 4 + 8 + 16


def test_hanoi_edge_cases():
    backups = [_mk_backup(0)]
    kept = [
        b
        for b in backups
        if b
        not in RetentionPolicy(
            RetentionRule(strategy=RetentionStrategy.TOWER_OF_HANOI)
        ).apply(backups)
    ]
    assert kept == backups
    backups = [_mk_backup(0), _mk_backup(1)]
    kept = [
        b
        for b in backups
        if b
        not in RetentionPolicy(
            RetentionRule(strategy=RetentionStrategy.TOWER_OF_HANOI)
        ).apply(backups)
    ]
    assert backups[0] in kept and backups[1] in kept
