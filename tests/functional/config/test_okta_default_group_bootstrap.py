"""
Tests for Okta default group bootstrap functionality.

This module contains tests that verify the automatic creation and configuration
of a default Okta user group during server bootstrap when Okta integration is
configured.

Test Organization:
- test_bootstrap_creates_okta_default_group_when_configured: Verifies that the
  default Okta group is created and configured when the server starts with
  Okta configuration.
- test_no_bootstrap_when_not_configured: Ensures that no default Okta group is
  created when Okta configuration is not provided.

Security Considerations:
- Tests verify proper isolation of Okta group mapping
- Validates that default group permissions are correctly applied
- Ensures no group creation occurs when Okta integration is not configured

Dependencies:
- pytest for test framework
- configparser for reading server configuration
- LocalUserGroupService for user group management
"""

import configparser

import pytest

from tacacs_server.auth.local_user_group_service import LocalUserGroupService


@pytest.mark.functional
def test_bootstrap_creates_okta_default_group_when_configured(server_factory, tmp_path):
    """Verify that the server creates a default Okta group when configured.

    This test ensures that when the server starts with Okta configuration that
    includes a default group ID, it automatically:
    1. Creates a local user group named 'okta-default-group'
    2. Maps it to the specified Okta group ID
    3. Adds this group to the default device group's allowed user groups

    Test Steps:
    1. Start server with Okta configuration including default_okta_group
    2. Verify 'okta-default-group' exists in local auth database
    3. Verify the group is mapped to the correct Okta group ID
    4. Verify the group is allowed in the default device group

    Args:
        server_factory: Pytest fixture to create a test server instance
        tmp_path: Pytest fixture providing a temporary directory

    Expected Results:
        - The 'okta-default-group' should exist in the local auth database
        - The group should be mapped to the provided Okta group ID
        - The group should be in the allowed_user_groups of the default device group
    """
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
    """Verify that no default Okta group is created when not configured.

    This test ensures that when the server starts without Okta default group
    configuration, it does not create any default Okta group mapping.

    Test Steps:
    1. Start server without Okta default group configuration
    2. Attempt to retrieve 'okta-default-group' from local auth database
    3. Verify that the group does not exist

    Args:
        server_factory: Pytest fixture to create a test server instance

    Expected Results:
        - Attempting to get 'okta-default-group' should raise an exception
        - No default Okta group mapping should exist in the system
    """
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
