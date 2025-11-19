"""Shared backup test fixtures."""

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def backup_test_root(tmp_path, monkeypatch):
    """Create a test backup root that's allowed by path policy."""
    # Create test directories under tmp_path
    backup_root = tmp_path / "data" / "backups"
    temp_root = tmp_path / "var" / "run" / "tacacs" / "tmp"
    backup_root.mkdir(parents=True, exist_ok=True)
    temp_root.mkdir(parents=True, exist_ok=True)

    # Add to allowed roots for the test
    import tacacs_server.backup.path_policy as pp

    if backup_root not in pp.ALLOWED_ROOTS:
        pp.ALLOWED_ROOTS.append(backup_root)
    if temp_root.parent.parent not in pp.ALLOWED_ROOTS:
        pp.ALLOWED_ROOTS.append(temp_root.parent.parent)

    # Set environment variables
    monkeypatch.setenv("TACACS_BACKUP_ROOT", str(backup_root))
    monkeypatch.setenv("TACACS_BACKUP_TEMP", str(temp_root))

    return backup_root, temp_root


def setup_test_backup_root():
    """Setup test backup root for integration tests."""
    # Use a writable location for tests
    test_root = Path(tempfile.gettempdir()) / "tacacs_test_backups"
    test_root.mkdir(parents=True, exist_ok=True)

    # Resolve to handle macOS symlinks (/var -> /private/var)
    test_root = test_root.resolve()

    # Add both resolved and unresolved paths to allowed roots
    import tacacs_server.backup.path_policy as pp

    temp_dir = Path(tempfile.gettempdir())
    if test_root not in pp.ALLOWED_ROOTS:
        pp.ALLOWED_ROOTS.append(test_root)
    if temp_dir not in pp.ALLOWED_ROOTS:
        pp.ALLOWED_ROOTS.append(temp_dir)
    if temp_dir.resolve() not in pp.ALLOWED_ROOTS:
        pp.ALLOWED_ROOTS.append(temp_dir.resolve())

    os.environ["TACACS_BACKUP_ROOT"] = str(test_root)
    return test_root
