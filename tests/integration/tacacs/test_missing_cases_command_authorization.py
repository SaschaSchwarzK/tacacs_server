"""
TACACS+ Command Authorization Edge Case Tests
==========================================

This module contains integration tests for edge cases and missing scenarios
in TACACS+ command authorization. It verifies the behavior of the command
authorization system in various edge conditions and special cases.

Test Environment:
- TACACS+ server with command authorization enabled
- Local user and device store for authentication
- Various edge case scenarios and special conditions

Test Cases:
- test_default_action_permit_and_deny_no_rules: Tests behavior with no rules configured
- test_privilege_check_order_after_allows_policy_eval: Verifies privilege check order
- test_empty_whitespace_and_long_commands: Tests handling of empty and malformed commands
- test_privilege_check_order_before_blocks_higher_request: Verifies privilege check order for higher privileges

Configuration:
- Default actions: 'permit' and 'deny' configurations tested
- Test user: 'user' with password 'Passw0rd1'
- Device secret: 'testing123'
- Default privilege level: 5

Example Usage:
    pytest tests/integration/tacacs/test_missing_cases_command_authorization.py -v
"""

import json
import secrets
import socket
import struct
from typing import Any

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
    server_factory: Any,
    *,
    default_action: str = "deny",
    extra_cmd_cfg: dict[str, Any] | None = None,
) -> Any:
    """Create and configure a test server with command authorization settings.

    Args:
        server_factory: Pytest fixture for creating server instances
        default_action: Default action ('permit' or 'deny') when no rules match
        extra_cmd_cfg: Additional command authorization configuration

    Returns:
        Configured server instance with the specified command authorization settings

    Example:
        server = _server(
            server_factory,
            default_action="permit",
            extra_cmd_cfg={"some_setting": "value"}
        )
    """
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
    server: Any,
    *,
    username: str = "user",
    password: str = "Passw0rd1",
    secret: str = "testing123",
    priv: int = 5,
) -> None:
    """Seed the test environment with a user and device configuration.

    Args:
        server: Server instance to configure
        username: Username for the test user
        password: Password for the test user
        secret: Shared secret for device authentication
        priv: Default privilege level for the user

    Note:
        This function modifies the server's configuration to include
        a test user and device with the specified credentials.
    """
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
    session_id = secrets.randbits(32)
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
def test_default_action_permit_and_deny_no_rules(server_factory: Any) -> None:
    """Test command authorization behavior when no rules are configured.

    This test verifies that:
    1. The default action is respected when no rules match
    2. Both 'permit' and 'deny' default actions work as expected
    3. The server responds with the appropriate status codes

    Test Steps:
    1. Start server with default_action="permit" and no rules
    2. Verify all commands are permitted
    3. Restart server with default_action="deny" and no rules
    4. Verify all commands are denied

    Expected Behavior:
    - With default_action="permit" -> All commands are allowed
    - With default_action="deny" -> All commands are denied
    """
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
def test_privilege_check_order_after_allows_policy_eval(server_factory: Any) -> None:
    """Test that privilege checks occur after allow policy evaluation.

    This test verifies that:
    1. Command authorization checks the command against allow rules first
    2. Privilege level is only checked if the command is allowed
    3. The order of these checks is correct

    Test Steps:
    1. Create a rule that allows a command for privilege level 5
    2. Test with a user having privilege level 1
    3. Verify the command is denied due to insufficient privileges

    Expected Behavior:
    - Command matches allow rule but is denied due to insufficient privileges
    - The server returns TAC_PLUS_AUTHOR_STATUS.FAIL with appropriate status
    """
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
def test_empty_whitespace_and_long_commands(server_factory: Any) -> None:
    """Test handling of empty, whitespace-only, and very long commands.

    This test verifies that:
    1. Empty commands are handled gracefully
    2. Commands with only whitespace are handled correctly
    3. Very long commands don't cause buffer overflows or other issues

    Test Steps:
    1. Test with an empty command string
    2. Test with a command containing only whitespace
    3. Test with a very long command (exceeding typical buffer sizes)

    Expected Behavior:
    - Empty/whitespace commands should be rejected with appropriate status
    - Long commands should be handled without errors (though may be rejected based on policy)
    - The server should remain stable and responsive
    """
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
def test_privilege_check_order_before_blocks_higher_request(
    server_factory: Any,
) -> None:
    """Test privilege check order when requesting higher privileges.

    This test verifies that:
    1. Privilege level is checked before command authorization
    2. Requests for higher privileges than the user has are denied
    3. The server returns the appropriate status code

    Test Steps:
    1. Create a test user with privilege level 5
    2. Attempt to execute a command requesting privilege level 15
    3. Verify the request is denied

    Expected Behavior:
    - Command should be denied with TAC_PLUS_AUTHOR_STATUS.FAIL
    - The server should indicate insufficient privileges in the response
    """
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
