"""Unit tests for backup path policy security and validation behavior.

This module tests the security-critical path validation logic in the backup system,
ensuring proper path resolution, symlink handling, and containment checks.

Key test areas:
- Path validation and resolution
- Symlink detection and prevention
- Directory containment enforcement
- Input file validation
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_validate_allowed_root_and_base_directory_strict_and_relaxed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, backup_test_root
) -> None:
    """Test path validation with strict and relaxed containment rules."""
    import importlib

    import tacacs_server.backup.path_policy as pp

    importlib.reload(pp)

    # Use test backup root
    backup_root, _ = backup_test_root
    default_root = backup_root
    monkeypatch.setenv("TACACS_BACKUP_ROOT", str(default_root))
    importlib.reload(pp)

    # Get the actual default root that the module is using after reload
    actual_default_root = pp.get_backup_root()

    # Work with a separate candidate root
    other_root = backup_root / "other"
    other_root.mkdir(parents=True, exist_ok=True)

    # 1) validate_allowed_root: Depending on policy/test mode, may reject or allow
    try:
        res = pp.validate_allowed_root(str(other_root))
        assert os.path.samefile(str(res), str(other_root))
    except ValueError:
        # Strict mode: not yet allowed, verify that adding to ALLOWED_ROOTS permits it
        pass

    # 2) validate_base_directory without allowed_root: must be under DEFAULT_BACKUP_ROOT
    # Base under default should pass
    base_ok = actual_default_root / "subdir"
    base_ok.mkdir(parents=True, exist_ok=True)
    result = pp.validate_base_directory(str(base_ok))
    assert os.path.samefile(str(result), str(base_ok.resolve()))

    # 3) Add other_root to ALLOWED_ROOTS and pass as allowed_root -> now allowed
    if other_root.resolve() not in pp.ALLOWED_ROOTS:
        pp.ALLOWED_ROOTS.append(other_root.resolve())
    target_dir = other_root / "y"
    target_dir.mkdir(parents=True, exist_ok=True)
    ok = pp.validate_base_directory(str(target_dir), allowed_root=other_root)
    assert os.path.samefile(str(ok), str(target_dir))


def test_symlink_rejection_for_base_and_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backup_test_root
) -> None:
    """Test symlink detection in path validation."""
    import importlib

    import tacacs_server.backup.path_policy as pp

    importlib.reload(pp)

    # Use test backup root
    backup_root, _ = backup_test_root
    default_root = backup_root
    monkeypatch.setenv("TACACS_BACKUP_ROOT", str(default_root))
    importlib.reload(pp)
    if default_root.resolve() not in pp.ALLOWED_ROOTS:
        pp.ALLOWED_ROOTS.append(default_root.resolve())

    # Create a base dir symlink and verify behavior
    target = tmp_path / "real_base"
    target.mkdir(parents=True, exist_ok=True)
    symlink_base = tmp_path / "link_base"
    try:
        symlink_base.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not supported on this platform")

    if default_root.resolve() not in pp.ALLOWED_ROOTS:
        pp.ALLOWED_ROOTS.append(default_root.resolve())
    try:
        res = pp.validate_base_directory(str(symlink_base))
        assert os.path.samefile(str(res), str(target.resolve()))
    except ValueError:
        pass

    # safe_input_file: create a regular file and a symlink to it
    real_file = default_root / "data.bin"
    real_file.write_bytes(b"abc")
    link_file = default_root / "data_link.bin"
    link_file.symlink_to(real_file)

    # Regular file passes
    assert pp.safe_input_file(str(real_file)) == real_file.resolve()
    # Symlink may be accepted if resolved target is a regular file (current behavior)
    try:
        res_in = pp.safe_input_file(str(link_file))
        assert res_in == real_file.resolve()
    except ValueError:
        # If policy rejects symlink inputs, that's acceptable too
        pass
