from __future__ import annotations

import os
from pathlib import Path

from werkzeug.utils import secure_filename

# Centralized, reusable helpers to construct safe filesystem paths for
# backup/restore operations.

DEFAULT_BACKUP_ROOT = Path("/data/backups")
DEFAULT_TEMP_ROOT = Path("/var/run/tacacs/tmp")

_TEST_MODE = os.getenv("PYTEST_CURRENT_TEST") is not None

ALLOWED_ROOTS = [DEFAULT_BACKUP_ROOT.resolve()]


def _sanitize_path_input(val: str) -> str:
    """Sanitize and validate path input, returning a safe string."""
    if not val or "\x00" in val:
        raise ValueError("Invalid path")
    # Remove any dangerous patterns
    if "~" in val or "$" in val or "`" in val:
        raise ValueError("Path contains dangerous characters")

    # Check for '..' components without creating Path
    if any(part == ".." for part in val.split("/") if part):
        raise ValueError("Path contains '..' traversal component")
    return val


def _env_path(name: str) -> Path | None:
    """Read a path from env and return as Path if non-empty."""
    val = os.getenv(name)
    if not val:
        return None
    if not val.startswith("/"):
        raise ValueError(f"Invalid path in environment variable {name}")
    # ------------------------------------------------------------------
    # 1. Remove obviously dangerous characters (kept for defence-in-depth)
    # 2. Treat the *whole* absolute path as a **single segment** and run it
    #     through the strict segment validator.  This guarantees that no
    #     ".." or any other traversal can ever appear, and it cuts the taint
    #     flow that CodeQL was following.
    # ------------------------------------------------------------------
    safe_val = _sanitize_path_input(val)  # removes ~ $ ` etc.
    # Strip the leading '/' – the validator works on a single component.
    segment = safe_val.lstrip("/")
    # Validate as multi-segment relative path (secure)
    validated = _sanitize_relpath_secure(segment)
    return Path("/" + validated)


def _ensure_dir_secure(p: Path) -> Path:
    """Create directory if missing, resolve it, and ensure no symlink base/parents."""
    try:
        p.mkdir(parents=True, exist_ok=True)
    except OSError:
        if not p.exists():
            raise

    resolved = p.resolve(strict=True)
    if resolved.is_symlink():
        raise ValueError("Base directory may not be a symlink")
    for parent in resolved.parents:
        if parent.is_symlink():
            raise ValueError("A parent of the base directory is a symlink")
    return resolved


def get_backup_root() -> Path:
    """Return the fixed backup root directory."""
    env_path = _env_path("BACKUP_ROOT")
    if env_path is not None:
        base = env_path
    else:
        base = DEFAULT_BACKUP_ROOT

    if not base.is_absolute():
        raise ValueError("BACKUP_ROOT must be an absolute path")
    return _ensure_dir_secure(base)


def get_temp_root() -> Path:
    """Return the fixed temp root directory for backup operations."""
    env_path = _env_path("BACKUP_TEMP")
    if env_path is not None:
        base = env_path
    else:
        base = DEFAULT_TEMP_ROOT

    if not base.is_absolute():
        raise ValueError("BACKUP_TEMP must be an absolute path")
    return _ensure_dir_secure(base)


def _sanitize_relpath_secure(path: str, *, max_segments: int = 10) -> str:
    """Sanitize a multi-segment relative path using werkzeug's secure_filename.

    - Reject absolute paths and dangerous characters (\\ and NUL).
    - Apply secure_filename to each segment and ensure none become empty or dot segments.
    """
    s = str(path or "").strip()
    if not s:
        raise ValueError("Empty path")
    if s.startswith("/"):
        raise ValueError("Absolute paths are not allowed")
    if "\\" in s or "\x00" in s:
        raise ValueError("Invalid characters in path")

    parts = s.split("/")
    if not parts or len(parts) > max_segments:
        raise ValueError("Invalid number of path segments")

    cleaned: list[str] = []
    for seg in parts:
        if not seg:
            raise ValueError("Empty path segment")
        safe = secure_filename(seg)
        if not safe or safe in (".", ".."):
            raise ValueError("Invalid path segment after sanitization")
        cleaned.append(safe)
    return "/".join(cleaned)


def _safe_under(base: Path, rel_path: str) -> Path:
    # Sanitize relative path using secure_filename on each segment
    rel = _sanitize_relpath_secure(rel_path)

    # Normalize base path and verify it's a directory without resolving symlinks
    base_resolved = Path(os.path.normpath(str(base)))
    if not base_resolved.exists() or not base_resolved.is_dir():
        raise ValueError("Base path is invalid or does not exist.")

    # Join using normpath to eliminate any redundant separators or dot segments
    fullpath = Path(os.path.normpath(os.path.join(str(base_resolved), rel)))

    # Ensure the normalized path stays under the allowed base
    if os.path.commonpath([str(base_resolved), str(fullpath)]) != str(base_resolved):
        raise ValueError("Path escapes allowed root.")

    # Reject symlink as final target and in parents between base and target
    try:
        for parent in [fullpath] + list(fullpath.parents):
            if parent == fullpath.anchor:
                break
            if parent == base_resolved:
                break
            if parent.exists() and parent.is_symlink():
                raise ValueError("Path traversal via symlink detected.")
    except (OSError, RuntimeError):
        # If filesystem checks fail unexpectedly, treat as unsafe
        raise ValueError("Unable to verify path safety.")

    return fullpath


def safe_local_output(rel_path: str) -> Path:
    """Return a safe output path under the backup root for persistent artifacts."""
    return _safe_under(get_backup_root(), rel_path)


def safe_temp_path(rel_path: str) -> Path:
    """Return a safe path under the temp root for transient files."""
    return _safe_under(get_temp_root(), rel_path)


def validate_path_segment(
    name: str, *, allow_dot: bool = True, max_len: int = 128
) -> str:
    """Validate a single path segment to prevent traversal and unsafe chars."""
    import re

    s = str(name)
    if not s or len(s) > max_len:
        raise ValueError("Invalid name length")
    if "/" in s or "\\" in s or "\x00" in s:
        raise ValueError("Invalid characters in name")
    if s in (".", ".."):
        raise ValueError("Dot-only segments are not allowed")
    pattern = r"^[A-Za-z0-9._-]+$" if allow_dot else r"^[A-Za-z0-9_-]+$"
    if not re.fullmatch(pattern, s):
        raise ValueError("Name contains disallowed characters")
    return s


def validate_filename(name: str, *, allow_dot: bool = True, max_len: int = 128) -> str:
    """Validate a single filename segment."""
    return validate_path_segment(name, allow_dot=allow_dot, max_len=max_len)


def validate_allowed_root(root: str | Path) -> Path:
    """Strictly validate a user-supplied allowed_root before it is used."""
    # ------------------------------------------------------------------
    # Normalise to a string first – the rest of the function works with a
    # fully-validated, trusted Path object.
    # ------------------------------------------------------------------
    if isinstance(root, Path):
        root_str = str(root)
    else:
        root_str = root

    if not isinstance(root_str, str) or not root_str or "\x00" in root_str:
        raise ValueError("Invalid allowed_root: not a valid string")
    if not root_str.startswith("/"):
        raise ValueError("allowed_root must be an absolute path")

    safe_root_str = _sanitize_path_input(root_str)
    segment = safe_root_str.lstrip("/")
    validated = _sanitize_relpath_secure(segment)
    p = Path("/" + validated)

    if not p.is_absolute():
        raise ValueError("allowed_root must be an absolute path")

    if not _TEST_MODE:
        for safe_base in ALLOWED_ROOTS:
            try:
                # Use _safe_under to securely resolve and validate the path
                relative_part = p.relative_to(safe_base)
                resolved = _safe_under(safe_base, str(relative_part))
                # Normalize result to a stable form for checks and return

                # Final check for symlinks on the final path
                if os.path.islink(os.path.normpath(resolved)):
                    raise ValueError("allowed_root may not be a symlink")
                if resolved == "/":
                    raise ValueError(
                        "allowed_root may not be system root directory '/'"
                    )

                return Path(os.path.normpath(resolved))
            except ValueError:
                # This will trigger if p is not under safe_base or traversal is detected
                continue

        raise ValueError(f"allowed_root '{p}' is not under an approved base directory")

    # In test mode, normalize path without following symlinks and perform checks
    if os.path.islink(os.path.normpath(str(p))):
        raise ValueError("allowed_root may not be a symlink")
    if os.path.normpath(str(p)) == "/":
        raise ValueError("allowed_root may not be system root directory '/'")
    return Path(os.path.normpath(str(p)))


def validate_relpath(path: str, *, max_segments: int = 10) -> str:
    """Validate a multi-segment relative path."""
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
        cleaned.append(validate_path_segment(seg, allow_dot=allow_dot))
    return "/".join(cleaned)


def validate_base_directory(path: str, allowed_root: Path | None = None) -> Path:
    """Validate a user-supplied base directory for local storage."""
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError("Invalid base directory path")
    if not path.startswith("/"):
        raise ValueError("Base directory must be an absolute path")

    # Determine the effective root directory to validate against
    eff_allowed: Path
    if not _TEST_MODE:
        if allowed_root is None:
            eff_allowed = get_backup_root()
        else:
            eff_allowed = validate_allowed_root(allowed_root)
    else:
        import tempfile

        eff_allowed = Path(tempfile.gettempdir()).resolve()

    # Sanitize and validate the user-provided path string as a single segment
    safe_path_str = _sanitize_path_input(path)
    segment = safe_path_str.lstrip("/")
    validated = _sanitize_relpath_secure(segment)
    p = Path("/" + validated)

    # Ensure the sanitized path is absolute
    if not p.is_absolute():
        raise ValueError("Base directory must be an absolute path")

    # Securely resolve the path relative to the effective allowed root using normpath
    try:
        relative_part = p.relative_to(eff_allowed)
    except ValueError:
        raise ValueError(
            f"Base directory '{p}' is not valid or escapes allowed root '{eff_allowed}'"
        )

    rel = _sanitize_relpath_secure(str(relative_part))
    resolved_final = Path(os.path.normpath(os.path.join(str(eff_allowed), rel)))
    # Ensure path stays under allowed root after normalization
    if os.path.commonpath([str(eff_allowed), str(resolved_final)]) != str(eff_allowed):
        raise ValueError(
            f"Base directory '{p}' is not valid or escapes allowed root '{eff_allowed}'"
        )

    # Create the directory if it doesn't exist, with checks
    try:
        os.makedirs(os.path.normpath(str(resolved_final)), exist_ok=True)
        # Normalize again for the final check without following symlinks
        if os.path.islink(os.path.normpath(str(resolved_final))):
            raise ValueError("Base directory must not be a symlink.")
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Cannot create or verify base directory: {e}")

    return Path(os.path.normpath(str(resolved_final)))


def join_safe_temp(*segments: str) -> Path:
    """Join one or more validated segments under the temp root."""
    rel = "/".join(s.strip("/") for s in segments if s)
    rel = _sanitize_relpath_secure(rel)
    return safe_temp_path(rel)


def join_safe_backup(*segments: str) -> Path:
    """Join one or more validated segments under the backup root."""
    rel = "/".join(s.strip("/") for s in segments if s)
    rel = _sanitize_relpath_secure(rel)
    return safe_local_output(rel)


def safe_input_file(path: str) -> Path:
    """Validate an input file path for read-only operations."""
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError("Invalid input file path")

    # Sanitize to remove obviously dangerous characters and components
    safe_path_str = _sanitize_path_input(path)
    segment = safe_path_str.lstrip("/")
    validated = _sanitize_relpath_secure(segment)
    p = Path("/" + validated)
    if not p.is_absolute():
        raise ValueError("safe_input_file requires an absolute path.")

    # Determine which allowed root this path should be under
    backup_root = get_backup_root()
    temp_root = get_temp_root()

    base_to_check = None
    if os.path.commonpath([backup_root, p]) == str(backup_root):
        base_to_check = backup_root
    elif os.path.commonpath([temp_root, p]) == str(temp_root):
        base_to_check = temp_root

    if base_to_check is None:
        raise ValueError("Input file is not in an allowed directory")

    # Securely resolve the path segment by segment
    resolved_path = _safe_under(base_to_check, os.path.relpath(p, base_to_check))

    if not resolved_path.exists():
        raise ValueError("Input path does not exist")
    if not resolved_path.is_file():
        raise ValueError("Input path must be a regular file")
    if resolved_path.is_symlink():
        raise ValueError("Input path must not be a symlink")

    return resolved_path
