import configparser

import pytest

from tacacs_server.auth.local_user_group_service import LocalUserGroupService


@pytest.mark.functional
def test_bootstrap_creates_okta_default_group_when_configured(server_factory, tmp_path):
    okta_group_id = "00g1abcXYZdefault"
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=False,
        enable_admin_web=False,
        config={
            "auth": {"backends": "local"},
            "devices": {"default_group": "default"},
            "okta": {
                "org_url": "https://example.okta.com",
                "default_okta_group": okta_group_id,
            },
        },
    )

    with server:
        # Resolve auth DB path from server's generated config
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(server.config_path)
        auth_db = cfg.get("auth", "local_auth_db", fallback=str(server.auth_db))
        # Verify local user group exists with expected mapping
        lugs = LocalUserGroupService(auth_db)
        group = lugs.get_group("okta-default-group")
        assert group is not None
        assert group.okta_group == okta_group_id

        # Device store default group should allow the created user group
        from tacacs_server.devices.store import DeviceStore

        ds_path = cfg.get("devices", "database")
        ds = DeviceStore(ds_path)
        dg = ds.get_group_by_name(
            cfg.get("devices", "default_group", fallback="default")
        )
        assert dg is not None
        assert "okta-default-group" in (dg.allowed_user_groups or [])


@pytest.mark.functional
def test_no_bootstrap_when_not_configured(server_factory):
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=False,
        enable_admin_web=False,
        config={
            "auth": {"backends": "local"},
            "devices": {"default_group": "default"},
            # No okta.default_okta_group provided
        },
    )

    with server:
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(server.config_path)
        auth_db = cfg.get("auth", "local_auth_db", fallback=str(server.auth_db))
        lugs = LocalUserGroupService(auth_db)
        with pytest.raises(Exception):
            lugs.get_group("okta-default-group")
