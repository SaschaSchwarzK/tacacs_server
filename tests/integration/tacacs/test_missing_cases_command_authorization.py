import json
import socket
import struct
import time

import pytest

from tacacs_server.auth.local_user_service import LocalUserService
from tacacs_server.devices.store import DeviceStore
from tacacs_server.tacacs.constants import (
    TAC_PLUS_AUTHOR_STATUS,
    TAC_PLUS_FLAGS,
    TAC_PLUS_HEADER_SIZE,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.packet import TacacsPacket


def _server(
    server_factory, *, default_action: str = "deny", extra_cmd_cfg: dict | None = None
):
    cmd_cfg = {"default_action": default_action, "rules_json": json.dumps([])}
    if extra_cmd_cfg:
        cmd_cfg.update(extra_cmd_cfg)
    return server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={
            "auth": {"backends": "local"},
            "command_authorization": cmd_cfg,
            "monitoring": {"enabled": "true", "web_host": "127.0.0.1"},
        },
    )


def _seed_env(
    server,
    *,
    username: str = "user",
    password: str = "Passw0rd1",
    secret: str = "testing123",
    priv: int = 5,
):
    import configparser as _cp

    cfg = _cp.ConfigParser(interpolation=None)
    cfg.read(server.config_path)
    auth_db = cfg.get("auth", "local_auth_db", fallback=str(server.auth_db))
    devices_db = cfg.get("devices", "database", fallback=str(server.devices_db))
    usvc = LocalUserService(auth_db)
    try:
        usvc.create_user(username, password=password, privilege_level=priv)
    except Exception:
        # If user exists, attempt update; if that fails, re-create
        try:
            usvc.update_user(username, privilege_level=priv)
        except Exception:
            usvc.create_user(username, password=password, privilege_level=priv)
    store = DeviceStore(devices_db)
    store.ensure_group(
        "dg-miss", description="missing-tests", metadata={"tacacs_secret": secret}
    )
    store.ensure_device(name="loopback", network="127.0.0.1", group="dg-miss")


def _mk_author_body(
    username: str, cmd: str, *, req_priv: int = 1, service: str = "shell"
) -> bytes:
    user_b = username.encode()
    port_b = b""
    rem_b = b""
    # Build attributes, truncating if needed to fit TACACS+ protocol limits (255 bytes per arg)
    attrs = [f"service={service}".encode()]
    if cmd is not None:
        cmd_attr = f"cmd={cmd}".encode()
        # TACACS+ arg length is 1 byte, so max 255 bytes per attribute
        if len(cmd_attr) > 255:
            cmd_attr = cmd_attr[:255]
        attrs.append(cmd_attr)
    arg_cnt = len(attrs)
    arg_lens = bytes([min(255, len(a)) for a in attrs])
    head = struct.pack(
        "!BBBBBBBB",
        0,
        max(0, min(15, int(req_priv))),
        1,
        1,
        len(user_b),
        len(port_b),
        len(rem_b),
        arg_cnt,
    )
    body = head + user_b + port_b + rem_b + arg_lens + b"".join(attrs)
    return body


def _send_author(host: str, port: int, username: str, cmd: str, *, req_priv: int = 1):
    session_id = int(time.time()) & 0xFFFFFFFF
    pkt = TacacsPacket(
        version=(TAC_PLUS_MAJOR_VER << 4) | 0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
        seq_no=1,
        flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        session_id=session_id,
        length=0,
        body=_mk_author_body(username, cmd, req_priv=req_priv),
    )
    full = pkt.pack("")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        s.sendall(full)
        hdr = s.recv(TAC_PLUS_HEADER_SIZE)
        if len(hdr) != TAC_PLUS_HEADER_SIZE:
            return -1
        header = TacacsPacket.unpack_header(hdr)
        body = s.recv(header.length)
        if len(body) != header.length:
            return -1
        return body[0]
    finally:
        try:
            s.close()
        except Exception:
            pass


@pytest.mark.integration
def test_default_action_permit_and_deny_no_rules(server_factory):
    # default_action=permit -> PASS_* when no rules match
    server = _server(server_factory, default_action="permit")
    with server:
        _seed_env(server, priv=5)
        st = _send_author("127.0.0.1", server.tacacs_port, "user", "nonmatching")
        assert st in (
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
        )
    # default_action=deny -> FAIL when no rules match
    server = _server(server_factory, default_action="deny")
    with server:
        _seed_env(server, priv=5)
        st = _send_author("127.0.0.1", server.tacacs_port, "user", "nonmatching")
        assert st == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL


@pytest.mark.integration
def test_privilege_check_order_after_allows_policy_eval(server_factory):
    # Rule permits show for any priv 1..15; user has priv 5, requests priv 10
    rules = [
        {
            "action": "permit",
            "match_type": "prefix",
            "pattern": "show ",
            "min_privilege": 1,
            "max_privilege": 15,
        }
    ]
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={
            "auth": {"backends": "local"},
            "command_authorization": {
                "default_action": "deny",
                "rules_json": json.dumps(rules),
                "privilege_check_order": "after",
            },
            "monitoring": {"enabled": "true", "web_host": "127.0.0.1"},
        },
    )
    with server:
        _seed_env(server, priv=5)
        st = _send_author(
            "127.0.0.1", server.tacacs_port, "user", "show ip int br", req_priv=10
        )
        assert st in (
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
        )


@pytest.mark.integration
def test_empty_whitespace_and_long_commands(server_factory):
    server = _server(server_factory, default_action="deny")
    with server:
        _seed_env(server, priv=5)
        host, port = "127.0.0.1", server.tacacs_port
        # Empty string should not crash; treated as no command -> PASS_ADD with base attrs
        st_empty = _send_author(host, port, "user", "")
        assert st_empty in (
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
        )
        # Whitespace-only is treated as a command string; with default deny, expect FAIL
        st_ws = _send_author(host, port, "user", "   ")
        assert st_ws == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL
        # Very long command should be processed safely; default deny -> FAIL
        long_cmd = "show " + ("x" * 5000)
        st_long = _send_author(host, port, "user", long_cmd)
        assert st_long == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL


@pytest.mark.integration
def test_privilege_check_order_before_blocks_higher_request(server_factory):
    # With 'before', a req_priv higher than user's priv blocks before policy evaluation
    rules = [
        {
            "action": "permit",
            "match_type": "prefix",
            "pattern": "show ",
            "min_privilege": 1,
            "max_privilege": 15,
        }
    ]
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={
            "auth": {"backends": "local"},
            "command_authorization": {
                "default_action": "permit",
                "rules_json": json.dumps(rules),
                "privilege_check_order": "before",
            },
            "monitoring": {"enabled": "true", "web_host": "127.0.0.1"},
        },
    )
    with server:
        _seed_env(server, priv=5)
        st = _send_author(
            "127.0.0.1", server.tacacs_port, "user", "show version", req_priv=10
        )
        assert st == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL
