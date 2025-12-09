from __future__ import annotations

import os
import shutil
import tarfile
from pathlib import Path
from typing import Literal, cast


def create_tarball(
    source_dir: str,
    output_path: str,
    compression: Literal["gz", "bz2", "xz", ""] = "gz",
) -> int:
    """
    Create compressed tarball from directory. Returns archive size in bytes.
    compression: "gz" (default), "bz2", "xz", or "" for no compression.
    """
    # Constrain mode to known values
    mode_str: str
    if compression == "gz":
        mode_str = "w:gz"
    elif compression == "bz2":
        mode_str = "w:bz2"
    elif compression == "xz":
        mode_str = "w:xz"
    else:
        mode_str = "w"
    # Create output directory safely using pathlib
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    mode_lit = cast(Literal["w", "w:gz", "w:bz2", "w:xz"], mode_str)
    with tarfile.open(name=output_path, mode=mode_lit) as tar:
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
        return os.path.commonpath([base_abs]) == os.path.commonpath(
            [base_abs, target_abs]
        )

    dest_root = Path(dest_dir).resolve()

    def _extract_member_safely(tar: tarfile.TarFile, member: tarfile.TarInfo) -> None:
        name = member.name
        if name.startswith("/") or ".." in name.replace("\\", "/"):
            raise ValueError(f"Unsafe path in archive: {name}")

        target_path = (dest_root / name).resolve()
        if dest_root not in target_path.parents and dest_root != target_path:
            raise ValueError(f"Unsafe extraction target: {name}")

        if member.isdev() or member.issym() or member.islnk():
            raise ValueError(f"Refusing to extract special or link member: {name}")

        if member.isdir():
            target_path.mkdir(parents=True, exist_ok=True)
            return

        if not member.isreg():
            raise ValueError(f"Unsupported tar member type for: {name}")

        target_path.parent.mkdir(parents=True, exist_ok=True)
        extracted = tar.extractfile(member)
        if extracted is None:
            raise ValueError(f"Failed to read archive member: {name}")
        with extracted, open(target_path, "wb") as out_f:
            shutil.copyfileobj(extracted, out_f)

    with tarfile.open(archive_path, "r:*") as tar:
        for member in tar.getmembers():
            _extract_member_safely(tar, member)
