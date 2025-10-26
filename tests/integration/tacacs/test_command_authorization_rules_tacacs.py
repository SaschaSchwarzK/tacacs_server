import json
import socket
import struct
import time

import pytest
import requests

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
from tests.utils.logs import parse_json_lines


def _server_with_rules(server_factory, rules: list[dict], default_action: str = "deny"):
    return server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={
            "auth": {"backends": "local"},
            "command_authorization": {
                "default_action": default_action,
                "rules_json": json.dumps(rules),
            },
            # Ensure monitoring is enabled so engine is initialized early and
            # authorizer is wired deterministically in all environments.
            "monitoring": {"enabled": "true", "web_host": "127.0.0.1"},
        },
    )


def _read_exact(sock: socket.socket, length: int, timeout: float = 3.0) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _mk_author_body(
    username: str, cmd: str, service: str = "shell", req_priv: int = 1
) -> bytes:
    user_b = username.encode()
    port_b = b""
    rem_b = b""
    attrs = [f"service={service}".encode(), f"cmd={cmd}".encode()]
    arg_cnt = len(attrs)
    arg_lens = bytes([len(a) for a in attrs])
    head = struct.pack(
        "!BBBBBBBB",
        0,  # authen_method NOT_SET
        max(0, min(15, int(req_priv))),  # requested priv_lvl
        1,  # authen_type ASCII
        1,  # authen_service LOGIN
        len(user_b),
        len(port_b),
        len(rem_b),
        arg_cnt,
    )
    body = head + user_b + port_b + rem_b + arg_lens + b"".join(attrs)
    return body


def _send_author(
    host: str, port: int, username: str, cmd: str, *, req_priv: int = 1
) -> int:
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
        hdr = _read_exact(s, TAC_PLUS_HEADER_SIZE)
        if len(hdr) != TAC_PLUS_HEADER_SIZE:
            return -1
        header = TacacsPacket.unpack_header(hdr)
        body = _read_exact(s, header.length)
        if len(body) != header.length:
            return -1
        return body[0]
    finally:
        try:
            s.close()
        except Exception:
            pass


def _send_author_expect(
    host: str,
    port: int,
    username: str,
    cmd: str,
    expect_status: int,
    *,
    retries: int = 5,
    req_priv: int = 1,
) -> int:
    """Send AUTHOR, retry briefly if status doesn't match yet (engine warmup)."""
    last = -1
    for i in range(max(1, retries)):
        st = _send_author(host, port, username, cmd, req_priv=req_priv)
        last = st
        if st == expect_status:
            return st
        time.sleep(0.1)
    return last


def _seed_user_and_device(
    server,
    username: str = "authzuser",
    password: str = "TestPass1!",
    secret: str = "testing123",
) -> None:
    # Read DB paths from generated config to avoid drift
    import configparser as _cp

    cfg = _cp.ConfigParser(interpolation=None)
    cfg.read(server.config_path)
    auth_db = cfg.get("auth", "local_auth_db", fallback=str(server.auth_db))
    devices_db = cfg.get("devices", "database", fallback=str(server.devices_db))

    usvc = LocalUserService(auth_db)
    try:
        usvc.create_user(username, password=password, privilege_level=15)
    except Exception:
        pass
    store = DeviceStore(devices_db)
    store.ensure_group(
        "dg-ca", description="command auth", metadata={"tacacs_secret": secret}
    )
    store.ensure_device(name="loopback", network="127.0.0.1", group="dg-ca")


def _ensure_engine_ready(server) -> None:
    """Best-effort ping to ensure command engine is initialized."""
    base = server.get_base_url()
    sess = requests.Session()
    deadline = time.time() + 3
    while time.time() < deadline:
        try:
            r = sess.get(f"{base}/api/command-authorization/rules", timeout=0.5)
            if r.status_code in (200, 401):
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.1)


@pytest.mark.integration
def test_tacacs_rule_regex_capturing_groups(server_factory):
    rules = [
        {
            "action": "permit",
            "match_type": "regex",
            "pattern": r"^show\s+interface\s+(\S+)$",
        }
    ]
    server = _server_with_rules(server_factory, rules)
    with server:
        _seed_user_and_device(server)
        _ensure_engine_ready(server)
        host, port = "127.0.0.1", server.tacacs_port
        st_ok = _send_author_expect(
            host,
            port,
            "authzuser",
            "show interface Gi0/1",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
        )
        st_no = _send_author_expect(
            host,
            port,
            "authzuser",
            "show interfaces Gi0/1",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
        )
        assert st_ok == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        assert st_no == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL
        # Log assertions
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs().lower()
        assert "authorization_granted" in logs
        assert "authorization_denied" in logs


@pytest.mark.integration
def test_tacacs_rule_case_insensitive(server_factory):
    rules = [
        {
            "action": "permit",
            "match_type": "regex",
            "pattern": r"(?i)^configure terminal$",
        }
    ]
    server = _server_with_rules(server_factory, rules)
    with server:
        _seed_user_and_device(server)
        _ensure_engine_ready(server)
        host, port = "127.0.0.1", server.tacacs_port
        st1 = _send_author_expect(
            host,
            port,
            "authzuser",
            "configure terminal",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
        )
        st2 = _send_author_expect(
            host,
            port,
            "authzuser",
            "ConFiGuRe TeRmInAl",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
        )
        st3 = _send_author_expect(
            host,
            port,
            "authzuser",
            "configure term",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
        )
        assert st1 == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        assert st2 == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        assert st3 == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs().lower()
        assert "authorization_granted" in logs
        assert "authorization_denied" in logs


@pytest.mark.integration
def test_tacacs_rule_priority_first_match_wins(server_factory):
    rules = [
        {"action": "permit", "match_type": "prefix", "pattern": "show "},
        {
            "action": "deny",
            "match_type": "regex",
            "pattern": r"^show\s+running-config$",
        },
    ]
    server = _server_with_rules(server_factory, rules)
    with server:
        _seed_user_and_device(server)
        _ensure_engine_ready(server)
        host, port = "127.0.0.1", server.tacacs_port
        st = _send_author_expect(
            host,
            port,
            "authzuser",
            "show running-config",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
        )
        assert st == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs().lower()
        assert "authorization_granted" in logs

    rules2 = list(reversed(rules))
    server2 = _server_with_rules(server_factory, rules2)
    with server2:
        _seed_user_and_device(server2)
        _ensure_engine_ready(server2)
        host, port = "127.0.0.1", server2.tacacs_port
        st = _send_author_expect(
            host,
            port,
            "authzuser",
            "show running-config",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
        )
        assert st == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL
        import time as _t

        _t.sleep(0.1)
        logs = server2.get_logs().lower()
        assert "authorization_denied" in logs


@pytest.mark.integration
def test_tacacs_rule_wildcard_patterns(server_factory):
    rules = [{"action": "permit", "match_type": "wildcard", "pattern": "copy * tftp *"}]
    server = _server_with_rules(server_factory, rules)
    with server:
        _seed_user_and_device(server)
        _ensure_engine_ready(server)
        host, port = "127.0.0.1", server.tacacs_port
        st1 = _send_author_expect(
            host,
            port,
            "authzuser",
            "copy running-config tftp 10.0.0.1",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
        )
        st2 = _send_author_expect(
            host,
            port,
            "authzuser",
            "copy startup-config tftp 192.168.1.10",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
        )
        st3 = _send_author_expect(
            host,
            port,
            "authzuser",
            "copy tftp running-config 10.0.0.1",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
        )
        assert st1 == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        assert st2 == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        assert st3 == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs().lower()
        assert "authorization_granted" in logs
        assert "authorization_denied" in logs


@pytest.mark.integration
def test_tacacs_multiple_matching_rules_precedence(server_factory):
    rules = [
        {"action": "deny", "match_type": "regex", "pattern": r"^debug\s+ip\s+icmp$"},
        {"action": "permit", "match_type": "prefix", "pattern": "debug "},
    ]
    server = _server_with_rules(server_factory, rules)
    with server:
        _seed_user_and_device(server)
        _ensure_engine_ready(server)
        host, port = "127.0.0.1", server.tacacs_port
        st = _send_author_expect(
            host,
            port,
            "authzuser",
            "debug ip icmp",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
        )
        assert st == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs().lower()
        assert "authorization_denied" in logs


@pytest.mark.integration
def test_tacacs_rule_command_aliases_via_regex(server_factory):
    rules = [
        {
            "action": "permit",
            "match_type": "regex",
            "pattern": r"^(show|display)\s+version$",
        }
    ]
    server = _server_with_rules(server_factory, rules)
    with server:
        _seed_user_and_device(server)
        _ensure_engine_ready(server)
        host, port = "127.0.0.1", server.tacacs_port
        st1 = _send_author_expect(
            host,
            port,
            "authzuser",
            "show version",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
        )
        st2 = _send_author_expect(
            host,
            port,
            "authzuser",
            "display version",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
        )
        st3 = _send_author_expect(
            host,
            port,
            "authzuser",
            "show versions",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
        )
        assert st1 == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        assert st2 == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        assert st3 == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL


@pytest.mark.integration
def test_author_permit_with_argument_modification_pass_add(server_factory):
    # Allow show; user has specific privilege and service returned as attributes
    rules = [{"action": "permit", "match_type": "prefix", "pattern": "show "}]
    server = _server_with_rules(server_factory, rules)
    with server:
        _seed_user_and_device(server)
        _ensure_engine_ready(server)
        # Adjust user to custom privilege/service
        import configparser as _cp

        cfg = _cp.ConfigParser(interpolation=None)
        cfg.read(server.config_path)
        auth_db = cfg.get("auth", "local_auth_db", fallback=str(server.auth_db))
        usvc = LocalUserService(auth_db)
        # Derive privilege via group so policy engine computes it
        from tacacs_server.auth.local_user_group_service import (
            LocalUserGroupService as _LUGS,
        )

        lugs = _LUGS(auth_db)
        try:
            lugs.create_group("ops7", privilege_level=7)
        except Exception:
            pass
        usvc.update_user("authzuser", groups=["ops7"], service="shell")
        host, port = "127.0.0.1", server.tacacs_port
        st, msg, attrs = _send_author_full_expect(
            host,
            port,
            "authzuser",
            "show ip int br",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
        )
        assert st == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        assert "Authorization" in msg or msg == ""
        # Expect attributes include priv-lvl and service
        assert any(a.startswith("priv-lvl=") for a in attrs)
        assert any(a.startswith("service=") for a in attrs)


@pytest.mark.integration
def test_author_pass_add_with_rule_attrs(server_factory):
    # Per-rule attrs injected on permit
    rules = [
        {
            "action": "permit",
            "match_type": "regex",
            "pattern": r"^show\s+interfaces$",
            "attrs": {"role": "ro", "context": "netops"},
            "response_mode": "pass_add",
        }
    ]
    server = _server_with_rules(server_factory, rules)
    with server:
        _seed_user_and_device(server)
        host, port = "127.0.0.1", server.tacacs_port
        st, msg, attrs = _send_author_full_expect(
            host,
            port,
            "authzuser",
            "show interfaces",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
        )
        assert st == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        assert any(a == "role=ro" for a in attrs), f"attrs={attrs}"
        assert any(a == "context=netops" for a in attrs), f"attrs={attrs}"


@pytest.mark.integration
def test_author_pass_repl_per_rule(server_factory):
    # Per-rule pass_repl overrides config default
    rules = [
        {
            "action": "permit",
            "match_type": "regex",
            "pattern": r"^show\s+clock$",
            "attrs": {"mode": "replace"},
            "response_mode": "pass_repl",
        }
    ]
    server = _server_with_rules(server_factory, rules, default_action="deny")
    with server:
        _seed_user_and_device(server)
        _ensure_engine_ready(server)
        # Give engine extra time to be fully wired into handlers
        import time as _t

        _t.sleep(0.5)
        host, port = "127.0.0.1", server.tacacs_port
        st, msg, attrs = _send_author_full_expect(
            host,
            port,
            "authzuser",
            "show clock",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
        )
        assert st == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL
        # Because mode is pass_repl, we expect only provided attrs
        assert attrs == ["mode=replace"]
        # Verify structured log has mode=pass_repl
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        entries = parse_json_lines(logs)
        # Debug: print all authorization_granted entries
        auth_entries = [e for e in entries if e.get("event") == "authorization_granted"]
        if auth_entries:
            print(f"\nFound {len(auth_entries)} authorization_granted entries:")
            for e in auth_entries:
                print(f"  mode={e.get('mode')}, command={e.get('command')}")
        else:
            print("\nNo authorization_granted entries found in logs")
            print(f"Total entries: {len(entries)}")
            # Show what events we do have
            event_types = {}
            for e in entries:
                evt = e.get("event", "unknown")
                event_types[evt] = event_types.get(evt, 0) + 1
            print(f"Event types found: {event_types}")
            # Show a sample of entries
            print("\nSample entries:")
            for e in entries[:5]:
                print(f"  {e}")
        assert any(
            e.get("event") == "authorization_granted" and e.get("mode") == "pass_repl"
            for e in entries
        )


@pytest.mark.integration
def test_author_deny_with_custom_message_insufficient_priv(server_factory):
    # No specific command rules; default policy requires priv 15 for non-show
    rules = []
    server = _server_with_rules(server_factory, rules)
    with server:
        _seed_user_and_device(server)
        import configparser as _cp

        cfg = _cp.ConfigParser(interpolation=None)
        cfg.read(server.config_path)
        auth_db = cfg.get("auth", "local_auth_db", fallback=str(server.auth_db))
        usvc = LocalUserService(auth_db)
        usvc.update_user("authzuser", privilege_level=1, service="exec")
        host, port = "127.0.0.1", server.tacacs_port
        st, msg, attrs = _send_author_full_expect(
            host,
            port,
            "authzuser",
            "configure terminal",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
            req_priv=15,
        )
        assert st == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL
        assert "Insufficient privilege" in msg


@pytest.mark.integration
def test_author_pass_add_with_additional_arguments(server_factory):
    # Allow show; ensure multiple attributes returned in PASS_ADD
    rules = [{"action": "permit", "match_type": "prefix", "pattern": "show "}]
    server = _server_with_rules(server_factory, rules)
    with server:
        _seed_user_and_device(server)
        import configparser as _cp

        cfg = _cp.ConfigParser(interpolation=None)
        cfg.read(server.config_path)
        auth_db = cfg.get("auth", "local_auth_db", fallback=str(server.auth_db))
        usvc = LocalUserService(auth_db)
        # Create a local user group with privilege 9 and assign user to it so
        # the policy engine derives effective privilege=9
        from tacacs_server.auth.local_user_group_service import (
            LocalUserGroupService as _LUGS,
        )

        lugs = _LUGS(auth_db)
        try:
            lugs.create_group("ops9", privilege_level=9)
        except Exception:
            pass
        usvc.update_user("authzuser", groups=["ops9"], service="exec")
        host, port = "127.0.0.1", server.tacacs_port
        st, msg, attrs = _send_author_full_expect(
            host,
            port,
            "authzuser",
            "show version",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
        )
        assert st == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        assert any(a.startswith("priv-lvl=9") for a in attrs), f"attrs={attrs}"
        assert any(a.startswith("service=") for a in attrs)


@pytest.mark.integration
def test_author_pass_repl_replace_all_arguments(server_factory):
    # Configure response_mode=pass_repl to instruct server to return PASS_REPL on allow
    rules = [{"action": "permit", "match_type": "prefix", "pattern": "show "}]
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={
            "auth": {"backends": "local"},
            "command_authorization": {
                "default_action": "deny",
                "response_mode": "pass_repl",
                "rules_json": json.dumps(rules),
            },
            # Ensure monitoring is enabled so engine is initialized early
            "monitoring": {"enabled": "true", "web_host": "127.0.0.1"},
        },
    )
    with server:
        _seed_user_and_device(server)
        _ensure_engine_ready(server)
        # Give engine extra time to be fully wired into handlers
        import time as _t

        _t.sleep(0.5)
        host, port = "127.0.0.1", server.tacacs_port
        st, msg, attrs = _send_author_full_expect(
            host,
            port,
            "authzuser",
            "show version",
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
        )
        assert st == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        entries = parse_json_lines(logs)
        # Debug: print all authorization_granted entries
        auth_entries = [e for e in entries if e.get("event") == "authorization_granted"]
        if auth_entries:
            print(f"\nFound {len(auth_entries)} authorization_granted entries:")
            for e in auth_entries:
                print(f"  mode={e.get('mode')}, command={e.get('command')}")
        else:
            print("\nNo authorization_granted entries found in logs")
            print(f"Total entries: {len(entries)}")
        assert any(
            e.get("event") == "authorization_granted" and e.get("mode") == "pass_repl"
            for e in entries
        )


def _send_author_full(
    host: str, port: int, username: str, cmd: str, *, req_priv: int = 1
):
    """Return (status, server_msg:str, attrs:list[str])"""
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
        hdr = _read_exact(s, TAC_PLUS_HEADER_SIZE)
        if len(hdr) != TAC_PLUS_HEADER_SIZE:
            return -1, "", []
        header = TacacsPacket.unpack_header(hdr)
        body = _read_exact(s, header.length)
        if len(body) != header.length:
            return -1, "", []
        if len(body) < 6:
            return -1, "", []
        status, arg_cnt, msg_len, data_len = struct.unpack("!BBHH", body[:6])
        offset = 6
        arg_lens = []
        for _ in range(arg_cnt):
            if offset >= len(body):
                return status, "", []
            arg_lens.append(body[offset])
            offset += 1
        server_msg = (
            body[offset : offset + msg_len].decode(errors="replace") if msg_len else ""
        )
        offset += msg_len
        attrs = []
        for ln in arg_lens:
            attrs.append(body[offset : offset + ln].decode(errors="replace"))
            offset += ln
        return status, server_msg, attrs
    finally:
        try:
            s.close()
        except Exception:
            pass


def _send_author_full_expect(
    host: str,
    port: int,
    username: str,
    cmd: str,
    expect_status: int,
    *,
    retries: int = 5,
    req_priv: int = 1,
):
    last = (-1, "", [])
    for _ in range(max(1, retries)):
        res = _send_author_full(host, port, username, cmd, req_priv=req_priv)
        last = res
        if res[0] == expect_status:
            return res
        time.sleep(0.1)
    return last
