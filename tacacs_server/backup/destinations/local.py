from __future__ import annotations

import hashlib
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

from .base import BackupDestination, BackupMetadata


def _sanitize_for_filesystem(user_input: str) -> str:
    """Sanitization barrier to break taint flow for static analysis.

    This function validates and sanitizes user input before filesystem operations.
    After this function, the returned value is considered safe.
    """
    from tacacs_server.backup.path_policy import _sanitize_relpath_secure

    # This breaks the taint chain for static analysis
    return _sanitize_relpath_secure(user_input)


class LocalBackupDestination(BackupDestination):
    """Store backups in a local filesystem directory."""

    def validate_config(self) -> None:
        # For compatibility with tests and existing configs, require an absolute base_path
        base_path = self.config.get("base_path")
        if not isinstance(base_path, str) or not base_path:
            raise ValueError("'base_path' must be a non-empty string")
        # Normalize and harden base path via policy

        from tacacs_server.backup.path_policy import validate_base_directory

        # Optionally constrain base_path to be under an allowed_root (useful in tests)
        allowed_root_cfg = self.config.get("allowed_root")
        from tacacs_server.backup.path_policy import validate_allowed_root

        allowed_root = (
            validate_allowed_root(allowed_root_cfg)
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
        # Normalize base path without resolving symlinks
        return Path(os.path.normpath(str(self.config["base_path"])))

    def _safe_local_path(self, local_path: str) -> Path:
        """Anchor local outputs to a safe temp subdirectory.

        Uses safe_temp_path from path_policy to avoid taint issues.
        """
        from werkzeug.utils import secure_filename

        from tacacs_server.backup.path_policy import safe_temp_path

        # Validate input
        if local_path.startswith("/") or (len(local_path) > 1 and local_path[1] == ":"):
            raise ValueError("Absolute paths are not allowed for local output")

        # Sanitize filename
        sanitized_name = secure_filename(local_path)
        if not sanitized_name:
            raise ValueError("Invalid filename after sanitization")

        # Use path_policy safe function which handles all validation
        return safe_temp_path(sanitized_name)

    def test_connection(self) -> tuple[bool, str]:
        try:
            root = self._root()
            if not root.is_dir():
                return False, "Base path does not exist"
            # Use hardcoded test filename to avoid taint
            test_file = root / ".write_test"
            try:
                test_file.write_text("ok", encoding="utf-8")
                if test_file.exists():
                    test_file.unlink()
            except Exception as exc:
                return False, f"Not writable: {exc}"
            return True, "OK"
        except Exception as exc:
            return False, str(exc)

    def _safe_join(self, *parts: str) -> Path:
        # Sanitize and join parts using barrier function
        safe_parts = [p.strip("/") for p in parts if p]
        rel = "/".join(safe_parts)
        # Sanitization barrier breaks taint flow
        rel_safe = _sanitize_for_filesystem(rel)
        # Construct path using only sanitized value
        root = self._root()
        result = root / rel_safe
        # Validate containment
        if not str(result).startswith(str(root) + os.sep) and result != root:
            raise ValueError("Path traversal detected")
        return result

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        # Use Path.read_bytes to avoid direct os operations
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def upload_backup(self, local_file_path: str, remote_filename: str) -> str:
        from tacacs_server.backup.path_policy import safe_input_file

        src = safe_input_file(local_file_path)
        # Sanitization barrier
        safe_rel = _sanitize_for_filesystem(remote_filename)
        dest = self._safe_join(safe_rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        try:
            shutil.copy2(src, tmp)
            tmp.replace(dest)
        except OSError as exc:
            raise OSError(f"Failed to store backup: {exc}")
        return str(dest)

    def download_backup(self, remote_path: str, local_file_path: str) -> bool:
        from tacacs_server.backup.path_policy import safe_temp_path

        # Sanitize remote path
        if Path(remote_path).is_absolute():
            root = self._root()
            if not remote_path.startswith(str(root) + os.sep) and remote_path != str(
                root
            ):
                raise ValueError("Absolute remote path must reside under base_path")
            # Use sanitization barrier
            safe_rel = _sanitize_for_filesystem(os.path.relpath(remote_path, root))
            src = root / safe_rel
        else:
            safe_rel = _sanitize_for_filesystem(remote_path)
            src = self._safe_join(safe_rel)

        # Sanitize destination path
        dst_path = Path(local_file_path)
        if not dst_path.is_absolute():
            dst = safe_temp_path(dst_path.name)
        else:
            from tacacs_server.backup.path_policy import get_temp_root

            temp_root = get_temp_root()
            if (
                not str(dst_path).startswith(str(temp_root) + os.sep)
                and dst_path != temp_root
            ):
                dst = safe_temp_path(dst_path.name)
            else:
                dst = dst_path

        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, dst)
            return True
        except Exception as e:
            import logging

            logging.getLogger(__name__).debug("Failed to download backup: %s", e)
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
            # Sanitize remote path
            if Path(remote_path).is_absolute():
                root = self._root()
                if not remote_path.startswith(
                    str(root) + os.sep
                ) and remote_path != str(root):
                    raise ValueError("Absolute remote path must reside under base_path")
                safe_rel = _sanitize_for_filesystem(os.path.relpath(remote_path, root))
                p = root / safe_rel
            else:
                safe_rel = _sanitize_for_filesystem(remote_path)
                p = self._safe_join(safe_rel)

            if not p.exists():
                return False
            p.unlink()
            # Remove manifest if present
            manifest_path = p.with_suffix(p.suffix + ".manifest.json")
            try:
                manifest_path.unlink()
            except FileNotFoundError:
                pass  # Manifest doesn't exist
            return True
        except Exception as e:
            import logging

            logging.getLogger(__name__).debug("Failed to delete backup: %s", e)
            return False

    def get_backup_info(self, remote_path: str) -> BackupMetadata | None:
        try:
            # Sanitize remote path
            if Path(remote_path).is_absolute():
                root = self._root()
                if not remote_path.startswith(
                    str(root) + os.sep
                ) and remote_path != str(root):
                    raise ValueError("Absolute remote path must reside under base_path")
                safe_rel = _sanitize_for_filesystem(os.path.relpath(remote_path, root))
                p = root / safe_rel
            else:
                safe_rel = _sanitize_for_filesystem(remote_path)
                p = self._safe_join(safe_rel)

            if not p.exists():
                return None
            stat = p.stat()
            size = stat.st_size
            ts = datetime.fromtimestamp(stat.st_mtime, UTC).isoformat()
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
