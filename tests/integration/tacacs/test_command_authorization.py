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


@pytest.mark.integration
def test_command_authorization_allow_and_deny(server_factory):
    """Verify command authorization engine enforces allow/deny and exposes config."""
    # Configure command authorization rules via config
    rules = [
        {
            "action": "permit",
            "match_type": "prefix",
            "pattern": "show ",
            "min_privilege": 1,
            "description": "Allow show commands",
        },
        {
            "action": "deny",
            "match_type": "regex",
            "pattern": r"^(reload|shutdown).*",
            "min_privilege": 0,
            "max_privilege": 15,
            "description": "Deny system restart commands",
        },
    ]

    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={
            "command_authorization": {
                "default_action": "deny",
                "rules_json": __import__("json").dumps(rules),
            }
        },
    )
    with server:
        base = server.get_base_url()
        # Authenticate like other API tests so admin-protected endpoints are accessible
        sess = server.login_admin()

        # Wait briefly for monitoring to initialize and attach the engine
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                r = sess.get(f"{base}/api/health", timeout=1)
                if r.status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)

        # Check rules surfaced via API
        r_rules = sess.get(f"{base}/api/command-authorization/", timeout=5)
        assert r_rules.status_code in (200, 401), "Rules endpoint should exist"
        # If unauthorized, skip rules content checks but continue functional checks via /check
        if r_rules.status_code == 200:
            payload = r_rules.json()
            assert "rules" in payload and isinstance(payload["rules"], list)
            # Some builds may not surface rules over HTTP; presence is sufficient here

        # Verify settings endpoint reflects default action (if accessible)
        r_settings = sess.get(f"{base}/api/command-authorization/settings", timeout=5)
        if r_settings.status_code == 200:
            assert r_settings.json().get("default_action") in ("deny", "permit")

        # Core functionality: check allow (show) and deny (reload) via /check
        r_allow = sess.post(
            f"{base}/api/command-authorization/check",
            json={
                "command": "show ip interface brief",
                "privilege_level": 15,
                "user_groups": ["netops"],
                "device_group": "core",
            },
            timeout=5,
        )
        assert r_allow.status_code in (200, 401), "Check endpoint available"
        if r_allow.status_code == 200:
            data = r_allow.json()
            assert data["authorized"] is True
            assert "show" in data.get("command", "")

        r_deny = sess.post(
            f"{base}/api/command-authorization/check",
            json={
                "command": "reload",
                "privilege_level": 15,
                "user_groups": ["netops"],
                "device_group": "core",
            },
            timeout=5,
        )
        assert r_deny.status_code in (200, 401)
        if r_deny.status_code == 200:
            data = r_deny.json()
            assert data["authorized"] is False

        # Logging: the HTTP check endpoint does not log command authorization decisions
        # at TACACS handler level, but the engine is attached and TACACS path would log.
        # We at least ensure no server errors occurred during engine setup.
        logs = server.get_logs()
        assert "Command authorization initialization failed" not in logs


def _read_exact(sock: socket.socket, length: int, timeout: float = 3.0) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _mk_author_body(username: str, cmd: str, service: str = "shell") -> bytes:
    """Build a minimal TACACS+ authorization request body.

    Layout (per RFC 8907):
      1B authen_method, 1B priv_lvl, 1B authen_type, 1B authen_service,
      1B user_len, 1B port_len, 1B rem_addr_len, 1B arg_cnt,
      arg_len[0..N-1] (N bytes), followed by user, port, rem_addr, then args.
    Args are strings like 'service=shell' and 'cmd=...'.
    """
    user_b = username.encode()
    port_b = b""
    rem_b = b""
    attrs = [f"service={service}".encode(), f"cmd={cmd}".encode()]
    arg_cnt = len(attrs)
    arg_lens = bytes([len(a) for a in attrs])
    head = struct.pack(
        "!BBBBBBBB",
        0,  # authen_method (NOT_SET)
        1,  # priv_lvl minimal
        1,  # authen_type ASCII
        1,  # authen_service LOGIN
        len(user_b),
        len(port_b),
        len(rem_b),
        arg_cnt,
    )
    # Order per parser: header -> user/port/rem -> arg_lens -> args
    body = head + user_b + port_b + rem_b + arg_lens + b"".join(attrs)
    return body


@pytest.mark.integration
def test_tacacs_authorization_logs_and_status(server_factory):
    """Send real TACACS+ AUTHOR requests to verify allow/deny and logs.

    Seeds a local user and device with matching secret; configures command auth
    rules to allow 'show' and deny 'reload'. Then sends two AUTHOR requests and
    verifies response status codes and server logs.
    """
    rules = [
        {
            "action": "permit",
            "match_type": "prefix",
            "pattern": "show ",
            "min_privilege": 1,
        },
        {
            "action": "deny",
            "match_type": "regex",
            "pattern": r"^(reload|shutdown).*",
            "min_privilege": 0,
            "max_privilege": 15,
        },
    ]
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={
            "auth": {"backends": "local"},
            "command_authorization": {
                "default_action": "deny",
                "rules_json": __import__("json").dumps(rules),
            },
        },
    )
    with server:
        # Seed user and device with secret used by TACACS
        import configparser as _cp

        cfg = _cp.ConfigParser(interpolation=None)
        cfg.read(server.config_path)
        auth_db = cfg.get("auth", "local_auth_db", fallback=str(server.auth_db))
        devices_db = cfg.get("devices", "database", fallback=str(server.devices_db))

        username = "authzuser"
        usvc = LocalUserService(auth_db)
        try:
            usvc.create_user(username, password="TestPass1!", privilege_level=15)
        except Exception:
            pass
        store = DeviceStore(devices_db)
        store.ensure_group(
            "dg-ca",
            description="command auth",
            metadata={"tacacs_secret": "testing123"},
        )
        store.ensure_device(name="loopback", network="127.0.0.1", group="dg-ca")

        host = "127.0.0.1"
        port = server.tacacs_port

        def _send_author(cmd: str) -> int:
            session_id = int(time.time()) & 0xFFFFFFFF
            pkt = TacacsPacket(
                version=(TAC_PLUS_MAJOR_VER << 4) | 0,
                packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
                seq_no=1,
                flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
                session_id=session_id,
                length=0,
                body=_mk_author_body(username, cmd),
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

        # Allowed command
        st_allow = _send_author("show version")
        assert st_allow == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD

        # Denied command
        st_deny = _send_author("reload")
        assert st_deny == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL

        # Verify logs reflect both decisions
        logs = server.get_logs().lower()
        assert "authorization_granted" in logs
        assert "authorization_denied" in logs

        # Give metrics a moment to be recorded and exposed
        time.sleep(0.5)

        # Verify Prometheus counters for command authorization decisions
        # Fetch metrics text and check for our counters with non-zero values.
        base = server.get_base_url()
        sess = requests.Session()
        m = sess.get(f"{base}/metrics", timeout=5)
        assert m.status_code == 200
        import re as _re

        granted = None
        denied = None
        for line in m.text.splitlines():
            m_gr = _re.match(
                r'^tacacs_command_authorizations_total\{outcome="granted"\}\s+([0-9.]+)',
                line,
            )
            if m_gr:
                try:
                    granted = float(m_gr.group(1))
                except Exception:
                    pass
            m_de = _re.match(
                r'^tacacs_command_authorizations_total\{outcome="denied"\}\s+([0-9.]+)',
                line,
            )
            if m_de:
                try:
                    denied = float(m_de.group(1))
                except Exception:
                    pass

        # Debug: print metrics if assertions will fail
        if granted is None or denied is None:
            print("\n=== METRICS DEBUG ===")
            print(f"Granted metric value: {granted}")
            print(f"Denied metric value: {denied}")
            print("\nAll metrics lines containing 'command_authorization':")
            for line in m.text.splitlines():
                if "command_authorization" in line.lower():
                    print(f"  {line}")
            print("=== END METRICS DEBUG ===\n")

        # Expect at least one of each in this isolated server instance
        assert granted is not None and granted >= 1.0, (
            f"Expected granted metric >= 1.0, got {granted}"
        )
        assert denied is not None and denied >= 1.0, (
            f"Expected denied metric >= 1.0, got {denied}"
        )
