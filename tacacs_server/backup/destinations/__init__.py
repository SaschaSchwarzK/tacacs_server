from __future__ import annotations

from typing import Any

from .base import BackupDestination


def create_destination(dest_type: str, config: dict[str, Any]) -> BackupDestination:
    """Factory function to create destination instances."""
    t = (dest_type or "").strip().lower()
    if t == "local":
        from .local import LocalBackupDestination

        return LocalBackupDestination(config)
    elif t == "ftp":
        from .ftp import FTPBackupDestination

        return FTPBackupDestination(config)
    elif t == "sftp":
        raise ValueError("SFTP destination not implemented yet")
    elif t == "azure":
        raise ValueError("Azure destination not implemented yet")
    else:
        raise ValueError(f"Unknown destination type: {dest_type}")
