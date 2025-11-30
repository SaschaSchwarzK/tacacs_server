"""Functional coverage for admin CLI helpers and related admin operations."""

import csv
import hashlib
from pathlib import Path

from tacacs_server import admin_cli
from tacacs_server.auth.local_models import LocalUserGroupRecord, LocalUserRecord
from tacacs_server.auth.local_store import LocalAuthStore
from tacacs_server.devices.service import DeviceService
from tacacs_server.devices.store import DeviceStore
from tacacs_server.utils.password_hash import PasswordHasher


def _write_config(tmp_path: Path) -> Path:
    auth_db = tmp_path / "local_auth.db"
    cfg = tmp_path / "tacacs.conf"
    cfg.write_text(
        f"[server]\nhost=127.0.0.1\nport=49\n\n[auth]\nlocal_auth_db={auth_db}\n",
        encoding="utf-8",
    )
    return cfg


def test_admin_cli_user_audit_and_migration(tmp_path, capsys, monkeypatch):
    """Audit detects legacy hashes and migrate-hashes upgrades them."""
    monkeypatch.chdir(tmp_path)
    cfg_path = _write_config(tmp_path)
    store = LocalAuthStore(tmp_path / "local_auth.db")
    legacy_hash = hashlib.sha256(b"legacy-pass").hexdigest()
    store.insert_user(
        LocalUserRecord(
            username="alice",
            password_hash=legacy_hash,
            password=None,
            privilege_level=1,
            service="exec",
            groups=["users"],
            enabled=True,
        )
    )

    rc_audit = admin_cli.cmd_audit_hashes(type("Args", (), {"config": str(cfg_path)}))
    assert rc_audit == 1  # legacy hash present

    # Prepare migration CSV
    csv_path = tmp_path / "migrate.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["username", "password"])
        writer.writeheader()
        writer.writerow({"username": "alice", "password": "legacy-pass"})

    rc_migrate = admin_cli.cmd_migrate_hashes(
        type("Args", (), {"config": str(cfg_path), "csv": str(csv_path)})
    )
    assert rc_migrate == 0
    rc_audit_after = admin_cli.cmd_audit_hashes(
        type("Args", (), {"config": str(cfg_path)})
    )
    assert rc_audit_after == 0  # no legacy hashes remain
    user = store.get_user("alice")
    assert user and PasswordHasher.is_bcrypt_hash(user.password_hash or "")


def test_group_management_and_device_registration(tmp_path, monkeypatch):
    """Ensure group creation and device registration flow succeeds."""
    monkeypatch.chdir(tmp_path)
    store = LocalAuthStore(tmp_path / "local_auth.db")
    grp = store.insert_group(
        LocalUserGroupRecord(
            name="netops",
            description="network operators",
            privilege_level=15,
            metadata={"privilege_level": 15},
            ldap_group=None,
            okta_group=None,
            radius_group=None,
        )
    )
    assert grp.name == "netops"
    updated = store.update_group("netops", description="core ops")
    assert updated and updated.description == "core ops"

    device_store = DeviceStore(tmp_path / "devices.db")
    device_service = DeviceService(device_store)
    device_group = device_service.create_device_group("edge")
    device = device_service.create_device(
        name="sw1", network="10.0.0.1/32", group="edge"
    )
    assert device_group["name"] == "edge"
    assert device.name == "sw1"
