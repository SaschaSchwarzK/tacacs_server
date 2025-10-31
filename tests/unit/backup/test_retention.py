from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from tacacs_server.backup.retention import (
    RetentionPolicy,
    RetentionRule,
    RetentionStrategy,
)
from tacacs_server.backup.destinations.ftp import FTPBackupDestination
from pathlib import Path


def _mk_backup(days_ago: int, name: str | None = None) -> Mock:
    ts = (datetime.now(UTC) - timedelta(days=days_ago)).isoformat()
    name = name or f"backup-{days_ago}.tar.gz"
    return Mock(
        filename=name,
        timestamp=ts,
        path=f"/backups/{name}",
        size_bytes=10,
    )


# --- Simple strategy: keep_count ---
def test_simple_keep_last_n():
    backups = [_mk_backup(i) for i in range(10)]  # 0..9 (0 newest)
    rule = RetentionRule(strategy=RetentionStrategy.SIMPLE, keep_count=5)
    policy = RetentionPolicy(rule)
    to_delete = policy.apply(backups)
    # Expect 5 deletions (oldest first per input ordering beyond first 5)
    assert len(to_delete) == 5
    deleted_names = {b.filename for b in to_delete}
    assert all(f"backup-{i}.tar.gz" in deleted_names for i in range(5, 10))


def test_simple_keep_last_n_underflow():
    backups = [_mk_backup(i) for i in range(3)]
    rule = RetentionRule(strategy=RetentionStrategy.SIMPLE, keep_count=5)
    policy = RetentionPolicy(rule)
    to_delete = policy.apply(backups)
    assert len(to_delete) == 0


# --- Simple strategy: keep_days ---
def test_simple_keep_days():
    backups = [_mk_backup(0), _mk_backup(1), _mk_backup(10), _mk_backup(20)]
    rule = RetentionRule(strategy=RetentionStrategy.SIMPLE, keep_days=7)
    policy = RetentionPolicy(rule)
    to_delete = policy.apply(backups)
    deleted = {b.filename for b in to_delete}
    assert any("backup-10" in n for n in deleted)
    assert any("backup-20" in n for n in deleted)
    assert all("backup-0" not in n and "backup-1" not in n for n in deleted)


def test_simple_keep_days_edge_case():
    # backup exactly at cutoff should be kept
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
    assert len(to_delete) == 0


# --- GFS strategy ---
def test_gfs_retention():
    """Test Grandfather-Father-Son retention policy"""
    from datetime import datetime as _dt, timedelta as _td

    # Create backups spanning 400 days (newest first in our helper)
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

    # All backups from last 7 days should be kept
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


# --- Hanoi strategy ---
def test_hanoi_pattern_keeps_recent_and_exponential():
    backups = [_mk_backup(i) for i in range(32)]  # 0..31
    rule = RetentionRule(strategy=RetentionStrategy.TOWER_OF_HANOI)
    policy = RetentionPolicy(rule)
    to_delete = policy.apply(backups)
    kept = [b for b in backups if b not in to_delete]
    # Most recent always kept
    assert backups[0] in kept
    # Expect logarithmic count of kept items
    assert len(kept) <= 1 + 1 + 2 + 4 + 8 + 16


def test_hanoi_edge_cases():
    # Single backup
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
    # Two backups -> both kept (indices 0 and 1)
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


def test_ftp_upload_download(ftp_server, tmp_path):
    """Test uploading and downloading a file via FTP."""
    # Create a test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, FTP!")

    # Configure the FTP destination
    config = {
        "host": ftp_server["host"],
        "port": ftp_server["port"],
        "username": ftp_server["username"],
        "password": ftp_server["password"],
        "base_path": "/backups",
        "use_tls": False,  # For testing, we'll use plain FTP
        "passive": True,
    }

    # Create the destination and connect
    dest = FTPBackupDestination(config)

    # Test upload
    remote_path = "test_upload.txt"
    with open(test_file, "rb") as f:
        dest.upload(remote_path, f.read())

    # Verify file exists
    files = dest.list_files()
    assert remote_path in [f.name for f in files]

    # Test download
    download_path = tmp_path / "downloaded.txt"
    file_data = dest.download(remote_path)
    download_path.write_bytes(file_data)

    # Verify content matches
    assert download_path.read_text() == "Hello, FTP!"

    # Test delete
    dest.delete(remote_path)
    files_after_delete = dest.list_files()
    assert remote_path not in [f.name for f in files_after_delete]
