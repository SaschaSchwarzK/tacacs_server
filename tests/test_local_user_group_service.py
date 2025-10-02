import json

import pytest

from tacacs_server.auth.local_user_group_service import (
    LocalUserGroupExists,
    LocalUserGroupNotFound,
    LocalUserGroupService,
    LocalUserGroupValidationError,
)


def test_group_crud(tmp_path):
    service = LocalUserGroupService(tmp_path / "auth.db")

    group = service.create_group(
        "admins",
        description="Privileged users",
        metadata={"role": "net"},
        ldap_group="cn=admins,ou=groups,dc=example,dc=com",
        okta_group="okta-admins",
        privilege_level=10,
    )
    assert group.name == "admins"
    assert group.ldap_group == "cn=admins,ou=groups,dc=example,dc=com"
    assert group.okta_group == "okta-admins"
    assert group.metadata == {"role": "net"}
    assert group.privilege_level == 10

    with pytest.raises(LocalUserGroupExists):
        service.create_group("admins")

    updated = service.update_group(
        "admins",
        metadata={"role": "full"},
        ldap_group="cn=superadmins,ou=groups,dc=example,dc=com",
        okta_group=None,
        privilege_level=12,
    )
    assert updated.metadata == {"role": "full"}
    assert updated.ldap_group == "cn=superadmins,ou=groups,dc=example,dc=com"
    assert updated.okta_group is None
    assert updated.privilege_level == 12

    listed = service.list_groups()
    assert len(listed) == 1

    service.delete_group("admins")

    with pytest.raises(LocalUserGroupNotFound):
        service.get_group("admins")


def test_validation(tmp_path):
    service = LocalUserGroupService(tmp_path / "auth.db")

    with pytest.raises(LocalUserGroupValidationError):
        service.create_group("", description="empty name")

    service.create_group("ops")
    with pytest.raises(LocalUserGroupNotFound):
        service.update_group("missing")

    with pytest.raises(LocalUserGroupValidationError):
        service.update_group("ops", metadata="invalid")


def test_group_seed_from_json(tmp_path):
    legacy = tmp_path / "legacy_groups.json"
    legacy.write_text(
        json.dumps(
            {
                "legacy": {
                    "description": "Legacy group",
                    "metadata": {"role": "legacy"},
                    "ldap_group": "cn=legacy,dc=example,dc=com",
                }
            }
        )
    )

    service = LocalUserGroupService(tmp_path / "auth.db", seed_file=legacy)
    group = service.get_group("legacy")
    assert group.description == "Legacy group"
    assert group.metadata == {"role": "legacy"}
    assert group.ldap_group == "cn=legacy,dc=example,dc=com"
    assert group.privilege_level == 1
