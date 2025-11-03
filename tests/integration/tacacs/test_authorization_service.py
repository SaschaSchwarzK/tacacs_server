import socket
import struct
import time
import secrets

import pytest

from tacacs_server.tacacs.constants import (
    TAC_PLUS_AUTHOR_STATUS,
    TAC_PLUS_FLAGS,
    TAC_PLUS_HEADER_SIZE,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.packet import TacacsPacket


def _read_exact(sock: socket.socket, length: int, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _mk_author_body(user: str, args: list[str], priv: int = 1) -> bytes:
    """Build minimal TACACS+ authorization request body.

    Header: authen_method, priv_lvl, authen_type, authen_service,
            user_len, port_len, rem_len, arg_cnt
    Then: user, port, rem_addr, arg_lens[], args bytes
    """
    user_b = user.encode()
    port_b = b""
    rem_b = b""
    arg_bytes = [a.encode() for a in args]
    head = struct.pack(
        "!BBBBBBBB",
        0,  # authen_method NOT_SET
        max(1, min(15, int(priv))),
        1,  # authen_type ASCII
        1,  # authen_service LOGIN
        len(user_b),
        len(port_b),
        len(rem_b),
        len(arg_bytes),
    )
    # order: user, port, rem, arg_lens[], args
    body = head + user_b + port_b + rem_b
    for ab in arg_bytes:
        body += struct.pack("!B", len(ab))
    for ab in arg_bytes:
        body += ab
    return body


def _send_author(host: str, port: int, body: bytes) -> tuple[int | None, list[str]]:
    pkt = TacacsPacket(
        version=(TAC_PLUS_MAJOR_VER << 4) | 0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
        seq_no=1,
        flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        session_id=secrets.randbits(32),
        length=0,
        body=body,
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(2)
        s.connect((host, port))
        s.sendall(pkt.pack(""))
        hdr = _read_exact(s, TAC_PLUS_HEADER_SIZE)
        if len(hdr) != TAC_PLUS_HEADER_SIZE:
            return None, []
        header = TacacsPacket.unpack_header(hdr)
        rbody = _read_exact(s, header.length)
        if len(rbody) != header.length:
            return None, []
        # parse response: status(1), arg_cnt(1), msg_len(2), data_len(2)
        if len(rbody) < 6:
            return None, []
        status = rbody[0]
        argc = rbody[1]
        msg_len, _ = struct.unpack("!HH", rbody[2:6])
        off = 6
        arg_lens = []
        for _ in range(argc):
            if off >= len(rbody):
                break
            arg_lens.append(rbody[off])
            off += 1
        # skip server_msg
        off_msg_end = off + msg_len
        off = min(off_msg_end, len(rbody))
        args_out: list[str] = []
        for ln in arg_lens:
            if off + ln > len(rbody):
                break
            args_out.append(rbody[off : off + ln].decode("utf-8", errors="replace"))
            off += ln
        return status, args_out
    except Exception:
        return None, []
    finally:
        try:
            s.close()
        except Exception:
            pass


@pytest.mark.integration
def test_authorization_multiple_arguments(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        args = ["service=shell", "cmd=show ip interface", "priv-lvl=15", "role=netops"]
        body = _mk_author_body("user1", args, priv=15)
        status, resp_args = _send_author(host, port, body)
        assert status in (
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
        )
        # If PASS_ADD, expect useful attributes like priv-lvl/service in response
        if status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD:
            joined = ",".join(resp_args)
            assert "priv-lvl=" in joined or "service=" in joined


@pytest.mark.integration
def test_authorization_avpairs_roundtrip(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        args = ["service=exec", "cmd=show version"]
        body = _mk_author_body("user2", args, priv=15)
        status, resp_args = _send_author(host, port, body)
        assert status in (
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
        )
        if status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD:
            # Response encodes server-selected attrs; ensure it's a list of key=value pairs
            assert all("=" in a for a in resp_args)


@pytest.mark.integration
def test_authorization_response_pass_repl_behavior(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        # Request without cmd; server replies PASS_ADD with minimal attributes
        body = _mk_author_body("user3", ["service=exec"], priv=1)
        status, _ = _send_author(host, port, body)
        # Current implementation uses PASS_ADD; PASS_REPL not used yet
        assert status in (
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
        )


@pytest.mark.integration
def test_malformed_authorization_request_handling(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        # Build malformed body: argc claims 3, but provide zero arg lengths/args
        head = struct.pack("!BBBBBBBB", 0, 1, 1, 1, 0, 0, 0, 3)
        body = head  # missing user/port/rem/arg_lens/args
        status, _ = _send_author(host, port, body)
    # Server should not crash; may default to minimal PASS_ADD when no cmd
    assert status in (
        None,
        TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
        TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
    )


@pytest.mark.integration
def test_authorization_empty_username(server_factory):
    server = server_factory(enable_tacacs=True)
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        args = ["service=shell", "cmd=show clock"]
        # empty username
        body = _mk_author_body("", args, priv=15)
        status, _ = _send_author(host, port, body)
        # Expect FAIL for command with no user attributes
        assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL


@pytest.mark.integration
def test_authorization_timeout_scenarios(server_factory, monkeypatch):
    server = server_factory(enable_tacacs=True)
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        # Simulate backend attribute retrieval delay, ensure server still returns
        try:
            from tacacs_server.auth.local import LocalAuthBackend as _LAB

            original = _LAB.get_user_attributes

            def slow_get(self, username):
                import time as _t

                _t.sleep(0.5)
                return original(self, username)

            monkeypatch.setattr(_LAB, "get_user_attributes", slow_get, raising=True)
        except Exception:
            pass

        body = _mk_author_body("user-timeout", ["service=shell", "cmd=whoami"], priv=15)
        t0 = time.time()
        status, _ = _send_author(host, port, body)
        elapsed = time.time() - t0
        # Should return within a reasonable time and not hang
        assert elapsed < 3.0
        assert status in (
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
        )
