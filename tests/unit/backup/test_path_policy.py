from __future__ import annotations

from pathlib import Path

import pytest

from tacacs_server.backup.path_policy import (
    get_backup_root,
    get_temp_root,
    safe_local_output,
    safe_temp_path,
)


def test_roots_use_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    br = tmp_path / "br"
    tr = tmp_path / "tr"
    monkeypatch.setenv("BACKUP_ROOT", str(br))
    monkeypatch.setenv("BACKUP_TEMP", str(tr))

    assert get_backup_root().resolve() == br.resolve()
    assert get_temp_root().resolve() == tr.resolve()


def test_safe_local_output_and_temp_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    br = tmp_path / "backups"
    tr = tmp_path / "temp"
    monkeypatch.setenv("BACKUP_ROOT", str(br))
    monkeypatch.setenv("BACKUP_TEMP", str(tr))

    p1 = safe_local_output("foo/bar.tar.gz")
    assert str(p1).startswith(str(br))
    assert p1.name == "bar.tar.gz"

    p2 = safe_temp_path("work/file.enc")
    assert str(p2).startswith(str(tr))
    assert p2.name == "file.enc"

    # traversal should be rejected
    with pytest.raises(Exception):
        safe_local_output("../etc/passwd")
    with pytest.raises(Exception):
        safe_temp_path("../../x")
