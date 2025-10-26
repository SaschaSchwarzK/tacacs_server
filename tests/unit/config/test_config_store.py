import os
import json
import sqlite3
from pathlib import Path

import pytest

from tacacs_server.config.config_store import ConfigStore
from tacacs_server.config.config import TacacsConfig


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)
    )
    return cur.fetchone() is not None


def test_config_store_schema_creation(tmp_path: Path):
    db = tmp_path / "config_store.db"
    store = ConfigStore(str(db))
    try:
        conn = sqlite3.connect(str(db))
        assert _has_table(conn, "config_overrides")
        assert _has_table(conn, "config_history")
        assert _has_table(conn, "config_versions")
        assert _has_table(conn, "system_metadata")
        # partial unique index should exist
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='ux_config_overrides_active'"
        )
        assert cur.fetchone() is not None
    finally:
        store.close()


def test_overrides_basic_operations(tmp_path: Path):
    store = ConfigStore(str(tmp_path / "cs.db"))
    # set override
    store.set_override(
        section="server", key="port", value=8080, value_type="integer", changed_by="tester"
    )
    ov = store.get_override("server", "port")
    assert ov is not None and ov[0] == 8080 and ov[1] == "integer"
    # unique constraint: second set replaces active
    store.set_override(
        section="server", key="port", value=9090, value_type="integer", changed_by="tester"
    )
    ov2 = store.get_override("server", "port")
    assert ov2 is not None and ov2[0] == 9090
    # delete (soft)
    store.delete_override("server", "port", changed_by="tester")
    assert store.get_override("server", "port") is None
    # type conversion json/list/bool
    store.set_override(
        section="auth", key="backends", value=["local", "ldap"], value_type="list", changed_by="tester"
    )
    ov3 = store.get_override("auth", "backends")
    assert ov3 is not None and isinstance(ov3[0], list)
    store.close()


def test_history_and_versions(tmp_path: Path):
    store = ConfigStore(str(tmp_path / "cs2.db"))
    # record change
    store.record_change(
        section="server",
        key="log_level",
        old_value="INFO",
        new_value="DEBUG",
        value_type="string",
        changed_by="tester",
        reason="tune logs",
        source_ip="127.0.0.1",
    )
    hist = store.get_history(section="server", limit=10)
    assert hist and hist[0]["key"] == "log_level"
    # version lifecycle
    ver = store.create_version({"server": {"port": "49"}}, created_by="tester")
    assert isinstance(ver, int)
    m = store.list_versions(limit=10)
    assert any(v["version_number"] == ver for v in m)
    vrow = store.get_version(ver)
    assert vrow and vrow["config_json"]
    restored = store.restore_version(ver, restored_by="tester")
    assert isinstance(restored, dict) and restored.get("server")
    store.close()


def test_history_pagination_and_filters(tmp_path: Path):
    store = ConfigStore(str(tmp_path / "cs3.db"))
    for i in range(10):
        store.record_change(
            section="server" if i % 2 == 0 else "auth",
            key="k",
            old_value=i,
            new_value=i + 1,
            value_type="integer",
            changed_by="tester",
        )
    all_hist = store.get_history(limit=100)
    assert len(all_hist) >= 10
    server_hist = store.get_history(section="server", limit=100)
    assert all(h["section"] == "server" for h in server_hist)
    paged = store.get_history(limit=3, offset=2)
    assert len(paged) == 3
    store.close()


def test_env_precedence_over_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg_path = tmp_path / "tacacs.conf"
    cfg_path.write_text(
        """
[server]
host=127.0.0.1
port=49
log_level=INFO

[auth]
backends=local
local_auth_db=data/local_auth.db

[security]
max_auth_attempts=3
auth_timeout=300
encryption_required=true
""",
        encoding="utf-8",
    )
    os.chdir(tmp_path)
    cfg = TacacsConfig(str(cfg_path))
    assert cfg.config_store is not None
    cfg.config_store.set_override("server", "port", 5555, "integer", changed_by="tester")
    cfg._apply_overrides()
    # get_server_config should honor env override
    monkeypatch.setenv("SERVER_PORT", "6000")
    sc = cfg.get_server_config()
    assert sc["port"] == 6000


def test_merge_overrides_with_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Create a minimal config file
    cfg_path = tmp_path / "tacacs.conf"
    cfg_path.write_text(
        """
[server]
host=127.0.0.1
port=49
log_level=INFO

[auth]
backends=local
local_auth_db=data/local_auth.db

[security]
max_auth_attempts=3
auth_timeout=300
encryption_required=true
allowed_clients=
denied_clients=
""",
        encoding="utf-8",
    )
    os.chdir(tmp_path)
    cfg = TacacsConfig(str(cfg_path))
    # Set override and apply
    assert cfg.config_store is not None
    cfg.config_store.set_override(
        section="server", key="port", value=5555, value_type="integer", changed_by="tester"
    )
    cfg._apply_overrides()
    assert cfg.config.getint("server", "port") == 5555
    assert "port" in cfg.overridden_keys.get("server", set())
