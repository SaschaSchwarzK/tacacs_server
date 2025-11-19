from __future__ import annotations

import pytest

from tacacs_server.backup.path_policy import (
    get_backup_root,
    get_temp_root,
    safe_local_output,
    safe_temp_path,
)


def test_roots_use_env(backup_test_root):
    # Use the test directories created by the fixture
    br, tr = backup_test_root
    assert get_backup_root().resolve() == br.resolve()
    assert get_temp_root().resolve() == tr.resolve()


def test_safe_local_output_and_temp_paths(backup_test_root):
    # Use the test directories created by the fixture
    br, tr = backup_test_root

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
