from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime
from pathlib import Path

from .base import BackupDestination, BackupMetadata


class LocalBackupDestination(BackupDestination):
    """Store backups in a local filesystem directory."""

    def validate_config(self) -> None:
        base_path = self.config.get("base_path")
        if not isinstance(base_path, str) or not base_path:
            raise ValueError("'base_path' must be a non-empty string")
        p = Path(base_path)
        if not p.is_absolute():
            raise ValueError("'base_path' must be an absolute path")
        try:
            p.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            raise ValueError(f"Cannot create base_path: {exc}")

    def _root(self) -> Path:
        return Path(str(self.config["base_path"]))

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

        # Strictly resolve the destination path; raises on broken symlinks/missing parents
        tgt = (base / lp).resolve(strict=True)
        # Confirm real path containment even for symlink/complex filesystem situations
        if os.path.commonpath([str(base), str(tgt)]) != str(base):
            raise ValueError("Local path escapes allowed root directory")
        # Ensure no symlinks anywhere in target's parent chain
        for parent in tgt.parents:
            if parent.is_symlink():
                raise ValueError("Target path parent is a symlink")
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
        src = Path(local_file_path)
        if not src.is_file():
            raise FileNotFoundError(str(src))
        # Validate relative path (allow subdirectories with safe segments)
        from .base import BackupDestination as _BD

        safe_rel = _BD.validate_relative_path(remote_filename)
        dest = self._safe_join(safe_rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        try:
            shutil.copy2(src, tmp)
            tmp.replace(dest)  # atomic rename on same FS
        except OSError as exc:
            raise OSError(f"Failed to store backup: {exc}")
        return str(dest)

    def download_backup(self, remote_path: str, local_file_path: str) -> bool:
        # Validate relative path before resolving
        from .base import BackupDestination as _BD

        safe_rel = _BD.validate_relative_path(remote_path)
        src = self._safe_join(safe_rel)
        # Constrain local output to an allowed root (config['local_root'] or CWD)
        dst = self._safe_local_path(local_file_path)
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
