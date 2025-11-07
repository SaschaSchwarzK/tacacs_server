from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime
from pathlib import Path

from tacacs_server.utils.logger import get_logger

from .base import BackupDestination, BackupMetadata

_logger = get_logger(__name__)


class LocalBackupDestination(BackupDestination):
    """Store backups in a local filesystem directory."""

    def validate_config(self) -> None:
        # For compatibility with tests and existing configs, require an absolute base_path
        base_path = self.config.get("base_path")
        if not isinstance(base_path, str) or not base_path:
            raise ValueError("'base_path' must be a non-empty string")
        # Normalize and harden base path via policy
        from pathlib import Path as _P

        from tacacs_server.backup.path_policy import validate_base_directory

        # Optionally constrain base_path to be under an allowed_root (useful in tests)
        allowed_root_cfg = self.config.get("allowed_root")
        allowed_root = (
            _P(allowed_root_cfg).resolve()
            if isinstance(allowed_root_cfg, str) and allowed_root_cfg
            else None
        )
        try:
            validated = validate_base_directory(base_path, allowed_root=allowed_root)
        except Exception as exc:
            raise ValueError(f"Invalid base_path: {exc}")
        # Persist normalized resolved path back to config
        self.config["base_path"] = str(validated)

    def _root(self) -> Path:
        return Path(str(self.config["base_path"])).resolve()

    def _safe_local_path(self, local_path: str) -> Path:
        """Anchor local outputs to a safe temp subdirectory, rejecting config/local_root entirely.

        Ensures use of only temp directory, prevents absolute paths, symlink escapes, path traversal.
        """
        import os
        import tempfile
        from pathlib import Path as _P

        lp = _P(local_path)
        # Disallow absolute user-provided paths
        if lp.is_absolute():
            raise ValueError("Absolute paths are not allowed for local output")

        allowed_temp_prefix = _P(tempfile.gettempdir()).resolve()
        # Use only dedicated fallback -- never read config!
        base = allowed_temp_prefix / "tacacs_server_restore"
        base.mkdir(parents=True, exist_ok=True)
        base = base.resolve()
        # Make sure no symlinks exist anywhere in the base's parent chain
        for parent in base.parents:
            if parent.is_symlink():
                raise ValueError("Unsafe: parent of backup base directory is a symlink")
        if base.is_symlink():
            raise ValueError("Backup base directory may not be a symlink")

        # Reject any path input with segments that are suspicious, such as ".." parts
        for part in lp.parts:
            if part == "..":
                raise ValueError("Path traversal detected in local file path")

        # Normalize the target path before resolving or checking containment

        tgt_rel_norm = os.path.normpath(str(lp))
        # Ensure that normalization didn't introduce a root or traversal
        if tgt_rel_norm.startswith(os.sep):
            raise ValueError(
                "Path escapes allowed local directory (unexpected absolute after normalization)"
            )
        if ".." in tgt_rel_norm.split(os.sep):
            raise ValueError("Path traversal detected in normalized path")
        tgt = (base / tgt_rel_norm).resolve(strict=False)
        # Confirm real path containment even for symlink/complex filesystem situations
        if os.path.commonpath([str(base), str(tgt)]) != str(base):
            raise ValueError("Local path escapes allowed root directory")
        # Ensure no symlinks anywhere in target's parent chain
        for parent in tgt.parents:
            if parent.is_symlink():
                raise ValueError("Target path parent is a symlink")
        # Additionally ensure that the path itself is neither a symlink nor does it point to one (if existent)
        if tgt.exists():
            # If the target exists, it must be a regular file (never a symlink, socket, or special type)
            if tgt.is_symlink() or not tgt.is_file():
                raise ValueError(
                    "Target path is not a regular file (or is a symlink/special file)"
                )
        return tgt

    def test_connection(self) -> tuple[bool, str]:
        try:
            root = self._root()
            if not root.exists():
                return False, "Base path does not exist"
            test_file = root / ".write_test"
            try:
                test_file.write_text("ok", encoding="utf-8")
                test_file.unlink(missing_ok=True)
            except Exception as exc:
                return False, f"Not writable: {exc}"
            return True, "OK"
        except Exception as exc:
            return False, str(exc)

    def _safe_join(self, *parts: str) -> Path:
        # Prevent path traversal by resolving under root
        root = self._root()
        target = root.joinpath(*parts)
        try:
            target_abs = target.resolve()
            if root not in target_abs.parents and target_abs != root:
                raise ValueError("Path traversal detected")
            return target_abs
        except Exception as exc:
            raise ValueError(f"Invalid path: {exc}")

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def upload_backup(self, local_file_path: str, remote_filename: str) -> str:
        from tacacs_server.backup.path_policy import safe_input_file

        src = safe_input_file(local_file_path)
        # Validate relative path (allow subdirectories with safe segments)
        from .base import BackupDestination as _BD

        safe_rel = _BD.validate_relative_path(remote_filename)
        dest = self._safe_join(safe_rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        try:
            shutil.copy2(str(src), tmp)
            tmp.replace(dest)  # atomic rename on same FS
        except OSError as exc:
            raise OSError(f"Failed to store backup: {exc}")
        return str(dest)

    def download_backup(self, remote_path: str, local_file_path: str) -> bool:
        # Accept absolute remote path under base, otherwise validate relative
        from .base import BackupDestination as _BD

        rp = Path(remote_path)
        if rp.is_absolute():
            try:
                src = rp.resolve()
                base = self._root().resolve()
                src.relative_to(base)
            except Exception:
                raise ValueError("Absolute remote path must reside under base_path")
        else:
            safe_rel = _BD.validate_relative_path(remote_path)
            src = self._safe_join(safe_rel)
        # Build safe destination path using centralized path policy
        from tacacs_server.backup.path_policy import get_temp_root, safe_temp_path

        dst = Path(local_file_path)
        if not dst.is_absolute():
            dst = safe_temp_path(str(dst.name))
        else:
            try:
                base = get_temp_root().resolve()
                dst_resolved = dst.resolve()
                dst_resolved.relative_to(base)
                dst = dst_resolved
            except Exception:
                # Fallback to safe temp path using the basename
                dst = safe_temp_path(str(dst.name))
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, dst)
            return True
        except Exception:
            return False

    def list_backups(self, prefix: str | None = None) -> list[BackupMetadata]:
        root = self._root()
        items: list[BackupMetadata] = []
        if not root.exists():
            return items
        # Traverse recursively and list common archive extensions
        exts = {".tar.gz", ".tgz", ".zip"}
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if not any(str(p).endswith(ext) for ext in exts):
                continue
            if prefix and prefix not in str(p):
                continue
            try:
                size = p.stat().st_size
                ts = datetime.fromtimestamp(p.stat().st_mtime, UTC).isoformat()
                checksum = self._sha256_file(p)
                items.append(
                    BackupMetadata(
                        filename=p.name,
                        size_bytes=size,
                        timestamp=ts,
                        path=str(p),
                        checksum_sha256=checksum,
                    )
                )
            except Exception:
                continue
        return sorted(items, key=lambda m: m.timestamp, reverse=True)

    def delete_backup(self, remote_path: str) -> bool:
        try:
            rp = Path(remote_path)
            if rp.is_absolute():
                p = rp.resolve()
                base = self._root().resolve()
                p.relative_to(base)
            else:
                from .base import BackupDestination as _BD

                safe_rel = _BD.validate_relative_path(remote_path)
                p = self._safe_join(safe_rel)
            p.unlink(missing_ok=False)
            # Remove manifest if present
            man = p.with_suffix(p.suffix + ".manifest.json")
            man.unlink(missing_ok=True)
            return True
        except Exception:
            return False

    def get_backup_info(self, remote_path: str) -> BackupMetadata | None:
        try:
            rp = Path(remote_path)
            if rp.is_absolute():
                p = rp.resolve()
                base = self._root().resolve()
                p.relative_to(base)
            else:
                from .base import BackupDestination as _BD

                safe_rel = _BD.validate_relative_path(remote_path)
                p = self._safe_join(safe_rel)
            if not p.exists():
                return None
            size = p.stat().st_size
            ts = datetime.fromtimestamp(p.stat().st_mtime, UTC).isoformat()
            checksum = self._sha256_file(p)
            return BackupMetadata(
                filename=p.name,
                size_bytes=size,
                timestamp=ts,
                path=str(p),
                checksum_sha256=checksum,
            )
        except Exception:
            return None
