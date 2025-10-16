import socket
import struct
import time

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


def _send(sock, pkt: TacacsPacket) -> TacacsPacket:
    data = pkt.pack("")
    sock.sendall(data)
    hdr = sock.recv(TAC_PLUS_HEADER_SIZE)
    assert len(hdr) == TAC_PLUS_HEADER_SIZE
    resp = TacacsPacket.unpack_header(hdr)
    body = sock.recv(resp.length)
    assert len(body) == resp.length
    resp.body = body
    return resp


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
        resp = _send(s, pkt)
        assert resp.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR
        assert resp.seq_no == 2
        status = resp.body[0]
        print(f"[AUTH-DEBUG] minimal author status={status}")
        if status not in (
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
        ):
            try:
                import os, requests
                base = os.environ.get(
                    "TACACS_WEB_BASE",
                    f"http://127.0.0.1:{os.environ.get('TEST_WEB_PORT','8080')}",
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
        r1 = _send(s, start_pkt)
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
        r2 = _send(s, stop_pkt)
        status2 = struct.unpack("!HHH", r2.body[:6])[2]
        assert status2 in (
            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS,
            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_FOLLOW,
        )
    finally:
        s.close()
