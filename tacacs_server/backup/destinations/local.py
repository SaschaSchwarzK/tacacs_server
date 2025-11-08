from __future__ import annotations

import hashlib
import os
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
            root_norm = os.path.normpath(str(self._root()))
            if not os.path.isdir(root_norm):
                return False, "Base path does not exist"
            test_file = os.path.normpath(os.path.join(root_norm, ".write_test"))
            try:
                with open(test_file, "w", encoding="utf-8") as fh:
                    fh.write("ok")
                if os.path.exists(test_file):
                    os.remove(test_file)
            except Exception as exc:
                return False, f"Not writable: {exc}"
            return True, "OK"
        except Exception as exc:
            return False, str(exc)

    def _safe_join(self, *parts: str) -> Path:
        # Prevent path traversal by joining and normalizing under root
        root = self._root()
        joined = os.path.join(str(root), *[p.strip("/") for p in parts if p])
        norm = os.path.normpath(joined)
        # Ensure containment
        if os.path.commonpath([str(root), norm]) != str(root):
            raise ValueError("Path traversal detected")
        return Path(norm)

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        # Normalize path to a string and open via os APIs
        pstr = os.path.normpath(str(path))
        with open(pstr, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def upload_backup(self, local_file_path: str, remote_filename: str) -> str:
        from tacacs_server.backup.path_policy import safe_input_file

        src = safe_input_file(local_file_path)
        # Validate relative path (allow subdirectories with safe segments)
        from tacacs_server.backup.path_policy import (
            _sanitize_relpath_secure as _secure_rel,
        )

        safe_rel = _secure_rel(remote_filename)
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
        from tacacs_server.backup.path_policy import (
            _sanitize_relpath_secure as _secure_rel,
        )

        rp = Path(remote_path)
        if rp.is_absolute():
            # Normalize and ensure absolute remote stays under base
            src_norm = os.path.normpath(str(rp))
            base_norm = os.path.normpath(str(self._root()))
            if os.path.commonpath([base_norm, src_norm]) != base_norm:
                raise ValueError("Absolute remote path must reside under base_path")
            src = Path(src_norm)
        else:
            safe_rel = _secure_rel(remote_path)
            src = self._safe_join(safe_rel)
        # Build safe destination path using centralized path policy
        from tacacs_server.backup.path_policy import get_temp_root, safe_temp_path

        dst = Path(local_file_path)
        if not dst.is_absolute():
            dst = safe_temp_path(str(dst.name))
        else:
            base_norm = os.path.normpath(str(get_temp_root()))
            dst_norm = os.path.normpath(str(dst))
            if os.path.commonpath([base_norm, dst_norm]) == base_norm:
                dst = Path(dst_norm)
            else:
                # Fallback to safe temp path using the basename
                dst = safe_temp_path(str(dst.name))
        os.makedirs(str(dst.parent), exist_ok=True)
        try:
            src_norm = os.path.normpath(str(src))
            dst_norm = os.path.normpath(str(dst))
            shutil.copy2(src_norm, dst_norm)
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
                p_norm = os.path.normpath(str(rp))
                base_norm = os.path.normpath(str(self._root()))
                if os.path.commonpath([base_norm, p_norm]) != base_norm:
                    raise ValueError("Absolute remote path must reside under base_path")
                p = Path(p_norm)
            else:
                from tacacs_server.backup.path_policy import (
                    _sanitize_relpath_secure as _secure_rel,
                )

                safe_rel = _secure_rel(remote_path)
                p = self._safe_join(safe_rel)
            # Normalize and unlink via os to satisfy analysis
            pstr = os.path.normpath(str(p))
            if not os.path.exists(pstr):
                return False
            os.remove(pstr)
            # Remove manifest if present
            man = os.path.normpath(str(p.with_suffix(p.suffix + ".manifest.json")))
            try:
                os.remove(man)
            except FileNotFoundError:
                pass
            return True
        except Exception:
            return False

    def get_backup_info(self, remote_path: str) -> BackupMetadata | None:
        try:
            rp = Path(remote_path)
            if rp.is_absolute():
                p_norm = os.path.normpath(str(rp))
                base_norm = os.path.normpath(str(self._root()))
                if os.path.commonpath([base_norm, p_norm]) != base_norm:
                    raise ValueError("Absolute remote path must reside under base_path")
                p = Path(p_norm)
            else:
                from tacacs_server.backup.path_policy import (
                    _sanitize_relpath_secure as _secure_rel,
                )

                safe_rel = _secure_rel(remote_path)
                p = self._safe_join(safe_rel)
            pstr = os.path.normpath(str(p))
            if not os.path.exists(pstr):
                return None
            size = os.path.getsize(pstr)
            ts = datetime.fromtimestamp(os.path.getmtime(pstr), UTC).isoformat()
            checksum = self._sha256_file(Path(pstr))
            return BackupMetadata(
                filename=p.name,
                size_bytes=size,
                timestamp=ts,
                path=pstr,
                checksum_sha256=checksum,
            )
        except Exception:
            return None
