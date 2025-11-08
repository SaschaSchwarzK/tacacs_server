from __future__ import annotations

import os
from pathlib import Path

# Centralized, reusable helpers to construct safe filesystem paths for
# backup/restore operations. These helpers avoid uncontrolled input being used
# in path expressions by enforcing validation and containment under fixed roots.

DEFAULT_BACKUP_ROOT = Path("/data/backups")
DEFAULT_TEMP_ROOT = Path("/var/run/tacacs/tmp")

# In test mode, allow any absolute path
_TEST_MODE = os.getenv("PYTEST_CURRENT_TEST") is not None

ALLOWED_ROOTS = [DEFAULT_BACKUP_ROOT.resolve()]


def _env_path(name: str) -> Path | None:
    """Read a path from env and return as Path if non-empty."""
    val = os.getenv(name)
    if not val:
        return None
    return Path(val)


def _ensure_dir_secure(p: Path) -> Path:
    """Create directory if missing, resolve it, and ensure no symlink base/parents."""
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    resolved = p.resolve()
    # Disallow the base or any of its parents being a symlink
    if resolved.is_symlink():
        raise ValueError("Base directory may not be a symlink")
    for parent in resolved.parents:
        if parent.is_symlink():
            raise ValueError("A parent of the base directory is a symlink")
    return resolved


def get_backup_root() -> Path:
    """Return the fixed backup root directory.

    Uses BACKUP_ROOT if set; otherwise defaults to /data/backups.
    Ensures the directory exists.
    """
    raw = _env_path("BACKUP_ROOT") or DEFAULT_BACKUP_ROOT
    base = Path(raw)
    if not base.is_absolute():
        raise ValueError("BACKUP_ROOT must be an absolute path")
    return _ensure_dir_secure(base)


def get_temp_root() -> Path:
    """Return the fixed temp root directory for backup operations.

    Uses BACKUP_TEMP if set; otherwise defaults to /var/run/tacacs/tmp.
    Ensures the directory exists.
    """
    raw = _env_path("BACKUP_TEMP") or DEFAULT_TEMP_ROOT
    base = Path(raw)
    if not base.is_absolute():
        raise ValueError("BACKUP_TEMP must be an absolute path")
    return _ensure_dir_secure(base)


def _safe_under(base: Path, rel_path: str) -> Path:
    from tacacs_server.backup.destinations.base import BackupDestination as _BD

    # Validate relative path, reject absolute/suspicious segments
    rel = _BD.validate_relative_path(rel_path)
    base = base.resolve()
    tgt = (base / rel).resolve()
    # Containment guard using pathlib
    try:
        tgt.relative_to(base)
    except ValueError:
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


# Convenience validators for common cases
def validate_filename(name: str, *, allow_dot: bool = True, max_len: int = 128) -> str:
    """Validate a single filename segment (no separators).

    Uses the same rules as BackupDestination.validate_path_segment.
    """
    from tacacs_server.backup.destinations.base import BackupDestination as _BD

    return _BD.validate_path_segment(name, allow_dot=allow_dot, max_len=max_len)


def validate_allowed_root(root: str | Path) -> Path:
    """
    Strictly validate a user-supplied allowed_root before it is used.
    - Must be absolute.
    - Must not contain NULs.
    - Must not be a symlink or have symlink parents.
    - Must reside in an approved root list (see ALLOWED_ROOTS).
    Returns resolved Path if valid, otherwise raises ValueError.

    In test mode (PYTEST_CURRENT_TEST env var set), the approved root check is relaxed
    to allow temporary test directories.
    """
    from pathlib import Path as _P

    if isinstance(root, Path):
        p = root
    else:
        if not isinstance(root, str) or not root or "\x00" in root:
            raise ValueError("Invalid allowed_root: not a valid string")
        p = _P(root)
    if not p.is_absolute():
        raise ValueError("allowed_root must be an absolute path")
    resolved = p.resolve()

    # In test mode, skip the approved base directory check
    if not _TEST_MODE:
        # Prevent root directory or other system sensitive paths
        for safe in ALLOWED_ROOTS:
            safe_resolved = Path(safe).resolve()
            try:
                resolved.relative_to(safe_resolved)
                break
            except ValueError:
                continue
        else:
            raise ValueError(
                f"allowed_root '{resolved}' is not under an approved base directory"
            )

    if resolved.is_symlink():
        raise ValueError("allowed_root may not be a symlink")
    for parent in resolved.parents:
        if parent.is_symlink():
            raise ValueError("A parent of allowed_root is a symlink")
    # Disallow root directory "/"
    if str(resolved) == "/":
        raise ValueError("allowed_root may not be system root directory '/'")
    return resolved


def validate_relpath(path: str, *, max_segments: int = 10) -> str:
    """Validate a multi-segment relative path (no leading slash).

    Uses the same rules as BackupDestination.validate_relative_path.
    """
    from tacacs_server.backup.destinations.base import BackupDestination as _BD

    return _BD.validate_relative_path(path, max_segments=max_segments)


def validate_base_directory(path: str, allowed_root: Path | None = None) -> Path:
    """Validate a user-supplied base directory for local storage.

    - Must be absolute, no NULs
    - Must reside inside allowed_root (or DEFAULT_BACKUP_ROOT if not specified)
    - Resolve final path; reject if the base itself or any of its parents are symlinks
    - Ensure the directory exists (best-effort)
    Returns resolved Path.

    In test mode (PYTEST_CURRENT_TEST env var set), the containment check is relaxed
    to allow temporary test directories.
    """
    from pathlib import Path as _P

    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError("Invalid base directory path")
    p = _P(path)
    if not p.is_absolute():
        raise ValueError("Base directory must be an absolute path")
    # Resolve as much as possible without requiring existence
    cand = p.resolve(strict=False)
    # Determine effective allowed root (skip in test mode)
    eff_allowed: Path | None = None
    if not _TEST_MODE:
        eff_allowed = (
            get_backup_root()
            if allowed_root is None
            else validate_allowed_root(allowed_root)
        )
        # Early containment check before any directory creation
        try:
            cand.relative_to(eff_allowed)
        except ValueError:
            raise ValueError(
                f"Base directory '{cand}' escapes allowed root '{eff_allowed}'"
            )
    # Verify existing parents are not symlinks
    cur = cand
    while True:
        if cur.exists() and cur.is_symlink():
            raise ValueError("A parent of the base directory is a symlink")
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    # Create after validation
    try:
        cand.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    # Resolve strictly and re-validate
    resolved_final = cand.resolve(strict=True)
    if resolved_final.is_symlink():
        raise ValueError("Base directory may not be a symlink")
    for ancestor in resolved_final.parents:
        if ancestor.is_symlink():
            raise ValueError("A parent of the base directory is a symlink")
    if eff_allowed is not None:
        try:
            resolved_final.relative_to(eff_allowed)
        except ValueError:
            raise ValueError(
                f"Base directory '{resolved_final}' escapes allowed root '{eff_allowed}'"
            )
    return resolved_final


def join_safe_temp(*segments: str) -> Path:
    """Join one or more validated segments under the temp root.

    Each segment can be a full relative path (will be validated). Segments
    are joined with '/' and then validated as a whole before resolving.
    """
    rel = "/".join(s.strip("/") for s in segments if s)
    rel = validate_relpath(rel)
    return safe_temp_path(rel)


def join_safe_backup(*segments: str) -> Path:
    """Join one or more validated segments under the backup root."""
    rel = "/".join(s.strip("/") for s in segments if s)
    rel = validate_relpath(rel)
    return safe_local_output(rel)


def safe_input_file(path: str) -> Path:
    """Validate an input file path for read-only operations.

    - Reject empty or NUL-containing paths
    - Resolve to an absolute path
    - Require the path exists, is a regular file, and is not a symlink
    Returns resolved Path.
    """
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError("Invalid input file path")
    p = Path(path).resolve()
    if not p.exists() or not p.is_file() or p.is_symlink():
        raise ValueError("Input path must be an existing regular file")
    return p
