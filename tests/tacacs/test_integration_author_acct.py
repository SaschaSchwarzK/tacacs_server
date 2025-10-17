import os
import socket
import struct
import time

import requests

from tacacs_server.tacacs.constants import (
    TAC_PLUS_ACCT_FLAG,
    TAC_PLUS_ACCT_STATUS,
    TAC_PLUS_AUTHOR_STATUS,
    TAC_PLUS_FLAGS,
    TAC_PLUS_HEADER_SIZE,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.packet import TacacsPacket


def _recv_all(sock, n: int) -> bytes:
    """Receive exactly n bytes from a blocking socket.

    Under load, a single recv() is not guaranteed to return the full payload.
    """
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        # If the peer closed the connection unexpectedly
        assert chunk, "socket closed while reading response body"
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send(
    sock, pkt: TacacsPacket, host: str | None = None, port: int | None = None
) -> TacacsPacket:
    """Send packet and receive response robustly with limited retries.

    Under perf load connections can be shed briefly; retry with small backoff.
    """
    import time as _time

    def _attempt(cur_sock: socket.socket) -> tuple[socket.socket, TacacsPacket | None]:
        try:
            data = pkt.pack("")
            cur_sock.sendall(data)
            hdr = cur_sock.recv(TAC_PLUS_HEADER_SIZE)
            if len(hdr) != TAC_PLUS_HEADER_SIZE:
                return cur_sock, None
            resp = TacacsPacket.unpack_header(hdr)
            body = _recv_all(cur_sock, resp.length) if resp.length else b""
            if len(body) != resp.length:
                return cur_sock, None
            resp.body = body
            return cur_sock, resp
        except (ConnectionResetError, TimeoutError, OSError):
            return cur_sock, None

    attempts = 0
    backoff = 0.03
    s = sock
    while attempts < 3:
        s, resp = _attempt(s)
        if resp is not None:
            return resp
        attempts += 1
        # Need host/port to reconnect
        if not (host and port):
            break
        try:
            s.close()
        except Exception:
            pass
        _time.sleep(backoff)
        backoff *= 2
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        # tiny settle time before sending
        _time.sleep(0.005)
    assert False, "failed to receive full response after retry"


def _wait_for_quiet_web(
    base_url: str, *, max_active: int = 10, timeout_s: float = 3.0
) -> None:
    """Wait until the server reports a low number of active connections.

    Helps avoid per‑IP cap shedding when running perf + integration suites together.
    """
    import time as _time

    deadline = _time.monotonic() + timeout_s
    while _time.monotonic() < deadline:
        try:
            r = requests.get(f"{base_url}/api/status", timeout=0.5)
            if r.status_code == 200:
                data = (
                    r.json()
                    if r.headers.get("content-type", "").startswith("application/json")
                    else {}
                )
                active = (
                    (data.get("connections", {}) or {}).get("active", 0)
                    if isinstance(data, dict)
                    else 0
                )
                if active <= max_active:
                    return
        except Exception:
            pass
        _time.sleep(0.05)


def _author_body(user: str, args: list[bytes]) -> bytes:
    # !BBBBBBBB (method, priv, type, service, ulen, plen, rlen, argc)
    method = 5  # LOCAL
    priv = 1
    atype = 1
    svc = 1
    u = user.encode()
    port = b""
    rem = b""
    argc = len(args)
    head = struct.pack(
        "!BBBBBBBB", method, priv, atype, svc, len(u), len(port), len(rem), argc
    )
    # This server expects arg lengths after user/port/rem
    lens = b"".join(bytes([len(a)]) for a in args)
    return head + u + port + rem + lens + b"".join(args)


def _acct_body(user: str, flags: int, args: list[bytes]) -> bytes:
    # !BBBBBBBBB (flags, method, priv, type, service, ulen, plen, rlen, argc)
    method = 5
    priv = 1
    atype = 1
    svc = 1
    u = user.encode()
    port = b""
    rem = b""
    argc = len(args)
    head = struct.pack(
        "!BBBBBBBBB", flags, method, priv, atype, svc, len(u), len(port), len(rem), argc
    )
    lens = b"".join(bytes([len(a)]) for a in args)
    return head + lens + u + port + rem + b"".join(args)


def test_authorization_minimal_unencrypted(tacacs_server):
    host = tacacs_server["host"]
    port = tacacs_server["port"]
    # Give the server a moment to drain previous connections when running combined suites
    base = os.environ.get(
        "TACACS_WEB_BASE", f"http://{host}:{os.environ.get('TEST_WEB_PORT', '8080')}"
    )
    _wait_for_quiet_web(base)
    session_id = int(time.time()) & 0xFFFFFFFF

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect((host, port))
    try:
        pkt = TacacsPacket(
            version=(TAC_PLUS_MAJOR_VER << 4) | 0,
            packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
            seq_no=1,
            flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
            session_id=session_id,
            body=_author_body("apitestuser", [b"service=shell"]),
        )
        resp = _send(s, pkt, host, port)
        assert resp.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR
        assert resp.seq_no == 2
        status = resp.body[0]
        print(f"[AUTH-DEBUG] minimal author status={status}")
        if status not in (
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
        ):
            try:
                base = os.environ.get(
                    "TACACS_WEB_BASE",
                    f"http://127.0.0.1:{os.environ.get('TEST_WEB_PORT', '8080')}",
                )
                rlog = requests.get(f"{base}/api/admin/logs", timeout=3)
                print(
                    f"[AUTH-DEBUG] /api/admin/logs -> {rlog.status_code} body[:1000]={(rlog.text or '')[:1000]}"
                )
            except Exception as e:
                print(f"[AUTH-DEBUG] fetching logs failed: {e}")
        assert status in (
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
        )
    finally:
        s.close()


def test_accounting_start_stop_unencrypted(tacacs_server):
    host = tacacs_server["host"]
    port = tacacs_server["port"]
    base = os.environ.get(
        "TACACS_WEB_BASE", f"http://{host}:{os.environ.get('TEST_WEB_PORT', '8080')}"
    )
    _wait_for_quiet_web(base)
    session_id = (int(time.time()) + 1) & 0xFFFFFFFF

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect((host, port))
    try:
        # START
        start_pkt = TacacsPacket(
            version=(TAC_PLUS_MAJOR_VER << 4) | 0,
            packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
            seq_no=1,
            flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
            session_id=session_id,
            body=_acct_body(
                "apitestuser",
                TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START,
                [b"task_id=1"],
            ),
        )
        r1 = _send(s, start_pkt, host, port)
        assert r1.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT
        # Response body begins with two shorts (srv_msg_len, data_len) then status short
        status = struct.unpack("!HHH", r1.body[:6])[2]
        assert status in (
            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS,
            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_FOLLOW,
        )
        # STOP
        stop_pkt = TacacsPacket(
            version=(TAC_PLUS_MAJOR_VER << 4) | 0,
            packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
            seq_no=3,
            flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
            session_id=session_id,
            body=_acct_body(
                "apitestuser",
                TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_STOP,
                [b"task_id=1"],
            ),
        )
        r2 = _send(s, stop_pkt, host, port)
        status2 = struct.unpack("!HHH", r2.body[:6])[2]
        assert status2 in (
            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS,
            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_FOLLOW,
        )
    finally:
        s.close()
