from __future__ import annotations

import os
from pathlib import Path

DEFAULT_BACKUP_ROOT = Path("/data/backups")
DEFAULT_TEMP_ROOT = Path("/var/run/tacacs/tmp")


def _env_path(name: str) -> Path | None:
    val = os.getenv(name)
    if not val:
        return None
    p = Path(val)
    try:
        return p.resolve()
    except Exception:
        return p


def get_backup_root() -> Path:
    """Return the fixed backup root directory.

    Uses BACKUP_ROOT if set; otherwise defaults to /data/backups.
    Ensures the directory exists.
    """
    base = _env_path("BACKUP_ROOT") or DEFAULT_BACKUP_ROOT
    try:
        base.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return base.resolve()


def get_temp_root() -> Path:
    """Return the fixed temp root directory for backup operations.

    Uses BACKUP_TEMP if set; otherwise defaults to /var/run/tacacs/tmp.
    Ensures the directory exists.
    """
    base = _env_path("BACKUP_TEMP") or DEFAULT_TEMP_ROOT
    try:
        base.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return base.resolve()


def _safe_under(base: Path, rel_path: str) -> Path:
    from tacacs_server.backup.destinations.base import BackupDestination as _BD

    # Validate relative path, reject absolute/suspicious segments
    rel = _BD.validate_relative_path(rel_path)
    tgt = (base / rel).resolve()
    # Containment guard
    if os.path.commonpath([str(base), str(tgt)]) != str(base):
        raise ValueError("Path escapes allowed root")
    # Disallow symlinked base for defense-in-depth
    if base.is_symlink():
        raise ValueError("Base directory may not be a symlink")
    return tgt


def safe_local_output(rel_path: str) -> Path:
    """Return a safe output path under the backup root for persistent artifacts."""
    return _safe_under(get_backup_root(), rel_path)


def safe_temp_path(rel_path: str) -> Path:
    """Return a safe path under the temp root for transient files."""
    return _safe_under(get_temp_root(), rel_path)
