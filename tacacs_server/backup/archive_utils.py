from __future__ import annotations

import os
import tarfile
from typing import Literal


def create_tarball(source_dir: str, output_path: str, compression: Literal["gz", "bz2", "xz", ""] = "gz") -> int:
    """
    Create compressed tarball from directory. Returns archive size in bytes.
    compression: "gz" (default), "bz2", "xz", or "" for no compression.
    """
    mode = f"w:{compression}" if compression else "w"
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with tarfile.open(output_path, mode) as tar:
        for root, _dirs, files in os.walk(source_dir):
            for file in files:
                filepath = os.path.join(root, file)
                arcname = os.path.relpath(filepath, source_dir)
                tar.add(filepath, arcname=arcname)
    return os.path.getsize(output_path)


def extract_tarball(archive_path: str, dest_dir: str) -> None:
    """
    Extract tarball to directory with basic path validation to prevent traversal.
    """
    os.makedirs(dest_dir, exist_ok=True)

    def _is_safe_path(base: str, target: str) -> bool:
        base_abs = os.path.abspath(base)
        target_abs = os.path.abspath(target)
        return os.path.commonpath([base_abs]) == os.path.commonpath([base_abs, target_abs])

    with tarfile.open(archive_path, "r:*") as tar:
        for member in tar.getmembers():
            name = member.name
            if name.startswith("/") or ".." in name.replace("\\", "/"):
                raise ValueError(f"Unsafe path in archive: {name}")
            target_path = os.path.join(dest_dir, name)
            if not _is_safe_path(dest_dir, target_path):
                raise ValueError(f"Unsafe extraction target: {name}")
        tar.extractall(dest_dir)

