from __future__ import annotations

import tempfile
from pathlib import Path

from sqlalchemy import inspect

from tacacs_server.db.engine import Base, get_session_factory
from tacacs_server.db.models import AccountingLog, LocalUser, LocalUserGroup
from tacacs_server.devices.models import (
    DeviceGroupModel,
    DeviceModel,
    ProxyModel,
    RealmModel,
)
from tacacs_server.devices.store import DeviceStore


def test_engine_sqlite_pragmas_and_pool(tmp_path) -> None:
    db_path = tmp_path / "engine.db"
    factory = get_session_factory(str(db_path))
    engine = factory.bind
    # PRAGMAs configured by connect listener
    with engine.connect() as conn:
        journal_mode = str(
            conn.exec_driver_sql("PRAGMA journal_mode").scalar() or ""
        ).lower()
        busy_timeout = conn.exec_driver_sql("PRAGMA busy_timeout").scalar()
    assert journal_mode == "wal"
    assert busy_timeout == 5000
    # Pool sizing tuned for concurrent use
    pool = engine.pool
    assert getattr(pool, "size")() == 10
    assert getattr(pool, "_max_overflow", None) == 20
    assert getattr(pool, "_timeout", None) == 30


def test_device_foreign_keys_and_indexes(tmp_path) -> None:
    db_path = tmp_path / "devices.db"
    # Ensure models are registered on Base before create_all
    _ = (DeviceModel, DeviceGroupModel, ProxyModel, RealmModel)
    factory = get_session_factory(str(db_path))
    engine = factory.bind
    Base.metadata.create_all(engine)
    insp = inspect(engine)
    idx_names = {idx["name"] for idx in insp.get_indexes("devices")}
    assert "idx_device_network_range" in idx_names
    fks = DeviceModel.__table__.c.group_id.foreign_keys
    assert any(fk.ondelete == "SET NULL" for fk in fks)
    proxy_fks = DeviceModel.__table__.c.proxy_id.foreign_keys
    assert any(fk.ondelete == "SET NULL" for fk in proxy_fks)
    realm_fks = DeviceGroupModel.__table__.c.realm_id.foreign_keys
    assert any(fk.ondelete == "SET NULL" for fk in realm_fks)


def test_accounting_indexes_exist(tmp_path) -> None:
    db_path = tmp_path / "acct.db"
    _ = (AccountingLog, LocalUser)
    factory = get_session_factory(str(db_path))
    engine = factory.bind
    Base.metadata.create_all(engine)
    insp = inspect(engine)
    idx_names = {idx["name"] for idx in insp.get_indexes("accounting_logs")}
    assert {
        "idx_acct_timestamp",
        "idx_acct_username",
        "idx_acct_session",
        "idx_acct_recent",
    }.issubset(idx_names)


def test_device_lookup_by_ip_refreshes_indexes() -> None:
    with tempfile.TemporaryDirectory(dir=".") as tmpdir:
        db_path = Path(tmpdir) / "devices.db"
        store = DeviceStore(db_path=db_path)
        store.ensure_group("netops")
        store.ensure_device("edge-1", "10.1.0.0/24", group="netops")
        record = store.find_device_for_ip("10.1.0.5")
        assert record is not None
        assert record.group is not None
        assert record.group.name == "netops"
        assert str(record.network) == "10.1.0.0/24"


def test_longest_prefix_match_prefers_more_specific() -> None:
    with tempfile.TemporaryDirectory(dir=".") as tmpdir:
        db_path = Path(tmpdir) / "devices.db"
        store = DeviceStore(db_path=db_path)
        store.ensure_group("g1")
        store.ensure_device("edge-24", "10.0.0.0/24", group="g1")
        store.ensure_device("edge-25", "10.0.0.0/25", group="g1")
        result = store.find_device_for_ip("10.0.0.42")
        assert result is not None
        assert result.name == "edge-25"


def test_model_repr_strings() -> None:
    user = LocalUser(id=1, username="alice")  # type: ignore[arg-type]
    DeviceGroupModel(id=2, name="g")  # type: ignore[arg-type]
    device = DeviceModel(
        id=3,
        name="d",
        network="10.0.0.0/24",
        group_id=2,  # type: ignore[arg-type]
    )
    log = AccountingLog(id=4, username="bob", session_id=99, status="start")  # type: ignore[arg-type]

    assert "alice" in repr(user)
    assert "<LocalUserGroup" in repr(LocalUserGroup(id=5, name="admins"))  # type: ignore[arg-type]
    assert "Device" in repr(device)
    assert "AccountingLog" in repr(log)
