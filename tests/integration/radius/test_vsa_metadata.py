"""Integration tests for VSA metadata in RADIUS flow."""

from tacacs_server.auth.privilege_resolver import resolve_privilege_level
from tacacs_server.radius.constants import ATTR_SESSION_TIMEOUT, RADIUS_ACCESS_ACCEPT
from tacacs_server.radius.packet import RADIUSPacket
from tacacs_server.radius.vsa_builder import apply_vsa_from_metadata


def test_apply_cisco_vsa_from_metadata():
    metadata = {
        "radius_vsa": {
            "cisco": {
                "avpairs": [
                    {"key": "shell:priv-lvl", "value": "15"},
                    {"key": "shell:roles", "value": "network-admin"},
                ]
            }
        }
    }

    packet = RADIUSPacket(RADIUS_ACCESS_ACCEPT, 1, b"\x00" * 16)
    apply_vsa_from_metadata(packet, metadata)

    avpairs = packet.get_cisco_avpairs()
    assert len(avpairs) == 2
    assert "shell:priv-lvl=15" in avpairs
    assert "shell:roles=network-admin" in avpairs


def test_privilege_resolution_vsa_wins():
    user_attrs = {"privilege_level": 5}
    group_metadata = {
        "privilege_level": 10,
        "radius_vsa": {
            "cisco": {"avpairs": [{"key": "shell:priv-lvl", "value": "15"}]}
        },
    }

    privilege = resolve_privilege_level(user_attrs, group_metadata)
    assert privilege == 15


def test_privilege_resolution_user_wins_over_group():
    user_attrs = {"privilege_level": 7}
    group_metadata = {"privilege_level": 10}

    privilege = resolve_privilege_level(user_attrs, group_metadata)
    assert privilege == 7


def test_privilege_resolution_group_fallback():
    user_attrs: dict[str, object] = {}
    group_metadata = {"privilege_level": 12}

    privilege = resolve_privilege_level(user_attrs, group_metadata)
    assert privilege == 12


def test_privilege_resolution_default():
    privilege = resolve_privilege_level({}, None)
    assert privilege == 1


def test_arista_vsa_privilege():
    user_attrs = {"privilege_level": 5}
    group_metadata = {
        "privilege_level": 10,
        "radius_vsa": {"arista": {"privilege_level": 14}},
    }

    privilege = resolve_privilege_level(user_attrs, group_metadata)
    assert privilege == 14


def test_privilege_resolution_ignores_invalid_cisco_vsa():
    user_attrs = {"privilege_level": 7}
    group_metadata = {
        "privilege_level": 1,
        "radius_vsa": {
            "cisco": {"avpairs": [{"key": "shell:priv-lvl", "value": "999"}]}
        },
    }

    privilege = resolve_privilege_level(user_attrs, group_metadata)
    assert privilege == 7


def test_apply_cisco_timeout_if_no_session_timeout():
    metadata = {
        "radius_vsa": {"cisco": {"avpairs": [], "timeout": 1200}},
        "session_timeouts": {"session_timeout": None},
    }
    packet = RADIUSPacket(RADIUS_ACCESS_ACCEPT, 1, b"\x00" * 16)

    applied = apply_vsa_from_metadata(packet, metadata)
    assert applied is True
    assert packet.get_integer(ATTR_SESSION_TIMEOUT) == 1200
