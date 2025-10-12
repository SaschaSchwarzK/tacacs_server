from types import SimpleNamespace

from tacacs_server.tacacs.constants import (
    TAC_PLUS_AUTHOR_STATUS,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.handlers import AAAHandlers
from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.web.monitoring import set_command_authorizer


class DummyBackend:
    name = "dummy"

    def get_user_attributes(self, user: str):
        # Minimal attributes for authorization
        return {
            "enabled": True,
            "groups": ["users"],
            "privilege_level": 1,
            "shell_command": [],
        }


def make_packet(session_id: int = 1234) -> TacacsPacket:
    # Minimal packet used only to carry session_id and metadata
    return TacacsPacket(
        version=0xC0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
        seq_no=1,
        flags=0,
        session_id=session_id,
        length=0,
        body=b"",
    )


def test_authorizer_hook_denies_command(monkeypatch):
    # Install an authorizer that denies 'configure' for priv<15
    def authorizer(command: str, privilege: int, user_groups, device_group):
        if command.startswith("configure") and privilege < 15:
            return False, "requires_priv_15"
        return True, "ok"

    set_command_authorizer(authorizer)

    handlers = AAAHandlers([DummyBackend()], db_logger=SimpleNamespace())
    pkt = make_packet()
    # priv_lvl parameter represents requested privilege; set to 1 (<= user_priv)
    args = {"cmd": "configure terminal"}
    device = SimpleNamespace(group=None, ip="127.0.0.1")

    resp = handlers._process_authorization(
        pkt,
        user="testuser",
        service=0,
        priv_lvl=1,
        args=args,
        device=device,
    )
    # First byte of body is status
    status = resp.body[0]
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL
