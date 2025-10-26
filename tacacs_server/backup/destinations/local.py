from __future__ import annotations

import hashlib
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
        # Ensure destination directories exist (allow subdirs in remote_filename)
        dest = self._safe_join(remote_filename)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        try:
            shutil.copy2(src, tmp)
            tmp.replace(dest)  # atomic rename on same FS
        except OSError as exc:
            raise OSError(f"Failed to store backup: {exc}")
        return str(dest)

    def download_backup(self, remote_path: str, local_file_path: str) -> bool:
        src = self._safe_join(remote_path)
        dst = Path(local_file_path)
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
                        filename=p.name, size_bytes=size, timestamp=ts, path=str(p), checksum_sha256=checksum
                    )
                )
            except Exception:
                continue
        return sorted(items, key=lambda m: m.timestamp, reverse=True)

    def delete_backup(self, remote_path: str) -> bool:
        try:
            p = self._safe_join(remote_path)
            p.unlink(missing_ok=False)
            # Remove manifest if present
            man = p.with_suffix(p.suffix + ".manifest.json")
            man.unlink(missing_ok=True)
            return True
        except Exception:
            return False

    def get_backup_info(self, remote_path: str) -> BackupMetadata | None:
        try:
            p = self._safe_join(remote_path)
            if not p.exists():
                return None
            size = p.stat().st_size
            ts = datetime.fromtimestamp(p.stat().st_mtime, UTC).isoformat()
            checksum = self._sha256_file(p)
            return BackupMetadata(
                filename=p.name, size_bytes=size, timestamp=ts, path=str(p), checksum_sha256=checksum
            )
        except Exception:
            return None

