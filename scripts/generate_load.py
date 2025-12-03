"""
Generate TACACS+ traffic to exercise monitoring and Prometheus/Grafana dashboards.

Usage examples:

  poetry run python scripts/generate_load.py --host 127.0.0.1 --port 8049 \
      --users apitestuser:ApiTestPass1! --rps 50 --duration 30 --mix auth,author,acct

Notes:
- Uses UNENCRYPTED TACACS+ bodies so it works without shared secrets.
- Creates short-lived TCP connections per request to stimulate connection metrics.
- You can pre-create the user via admin UI or LocalUserService; for auth PASS ensure valid creds.
"""

from __future__ import annotations

import argparse
import queue
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass

from tacacs_server.tacacs.constants import (
    TAC_PLUS_ACCT_FLAG,
    TAC_PLUS_ACCT_STATUS,
    TAC_PLUS_AUTHEN_ACTION,
    TAC_PLUS_AUTHEN_STATUS,
    TAC_PLUS_AUTHEN_SVC,
    TAC_PLUS_AUTHEN_TYPE,
    TAC_PLUS_AUTHOR_STATUS,
    TAC_PLUS_FLAGS,
    TAC_PLUS_HEADER_SIZE,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.packet import TacacsPacket


def _pack(pkt: TacacsPacket) -> bytes:
    # UNENCRYPTED bodies; key is irrelevant
    return pkt.pack("")


def _send_and_recv(host: str, port: int, pkt: TacacsPacket) -> TacacsPacket | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host, port))
        s.sendall(_pack(pkt))
        hdr = s.recv(TAC_PLUS_HEADER_SIZE)
        if len(hdr) != TAC_PLUS_HEADER_SIZE:
            return None
        resp = TacacsPacket.unpack_header(hdr)
        body = s.recv(resp.length)
        if len(body) != resp.length:
            return None
        resp.body = body
        return resp
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def _mk_auth_body(username: str, password: str) -> bytes:
    u = username.encode()
    d = password.encode()
    head = struct.pack(
        "!BBBBBBBB",
        TAC_PLUS_AUTHEN_ACTION.TAC_PLUS_AUTHEN_LOGIN,
        1,
        TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
        TAC_PLUS_AUTHEN_SVC.TAC_PLUS_AUTHEN_SVC_LOGIN,
        len(u),
        0,
        0,
        len(d),
    )
    return head + u + d


def _mk_author_body(username: str, args: list[bytes]) -> bytes:
    # method, priv, type, service, ulen, plen, rlen, argc
    method = 5
    priv = 1
    atype = 1
    svc = 1
    u = username.encode()
    argc = len(args)
    header = struct.pack("!BBBBBBBB", method, priv, atype, svc, len(u), 0, 0, argc)
    lens = b"".join(bytes([len(a)]) for a in args)
    return header + u + b"" + b"" + lens + b"".join(args)


def _mk_acct_body(username: str, flags: int, args: list[bytes]) -> bytes:
    # flags, method, priv, type, service, ulen, plen, rlen, argc
    method = 5
    priv = 1
    atype = 1
    svc = 1
    u = username.encode()
    argc = len(args)
    header = struct.pack(
        "!BBBBBBBBB", flags, method, priv, atype, svc, len(u), 0, 0, argc
    )
    lens = b"".join(bytes([len(a)]) for a in args)
    return header + lens + u + b"" + b"" + b"".join(args)


def make_packet(session_id: int, seq: int, ptype: int, body: bytes) -> TacacsPacket:
    return TacacsPacket(
        version=(TAC_PLUS_MAJOR_VER << 4) | 0,
        packet_type=ptype,
        seq_no=seq,
        flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        session_id=session_id,
        body=body,
    )


@dataclass
class Counters:
    auth_ok: int = 0
    auth_err: int = 0
    author_ok: int = 0
    author_err: int = 0
    acct_ok: int = 0
    acct_err: int = 0


def worker(
    host: str,
    port: int,
    user: str,
    pwd: str,
    mix: list[str],
    end_ts: float,
    q: queue.Queue[tuple[str, bool]],
):
    rng = random.Random()
    while time.time() < end_ts:
        op = rng.choice(mix)
        session = rng.randrange(1, 2**32 - 1)
        try:
            if op == "auth":
                body = _mk_auth_body(user, pwd)
                pkt = make_packet(
                    session, 1, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, body
                )
                resp = _send_and_recv(host, port, pkt)
                ok = bool(
                    resp
                    and len(resp.body) > 0
                    and resp.body[0]
                    == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS
                )
                q.put(("auth", ok))
            elif op == "author":
                args = [b"service=shell", b"cmd=show version"]
                body = _mk_author_body(user, args)
                pkt = make_packet(
                    session, 1, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR, body
                )
                resp = _send_and_recv(host, port, pkt)
                ok = bool(
                    resp
                    and len(resp.body) > 0
                    and resp.body[0]
                    in (
                        TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                        TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
                    )
                )
                q.put(("author", ok))
            else:  # acct
                args = [b"task_id=loadgen"]
                body1 = _mk_acct_body(
                    user, TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START, args
                )
                pkt1 = make_packet(
                    session, 1, TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT, body1
                )
                r1 = _send_and_recv(host, port, pkt1)
                ok1 = False
                if r1 and len(r1.body) >= 6:
                    try:
                        status1 = struct.unpack("!HHH", r1.body[:6])[2]
                        ok1 = status1 in (
                            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS,
                            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_FOLLOW,
                        )
                    except Exception:
                        ok1 = False
                body2 = _mk_acct_body(
                    user, TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_STOP, args
                )
                pkt2 = make_packet(
                    session, 3, TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT, body2
                )
                r2 = _send_and_recv(host, port, pkt2)
                ok2 = False
                if r2 and len(r2.body) >= 6:
                    try:
                        status2 = struct.unpack("!HHH", r2.body[:6])[2]
                        ok2 = status2 in (
                            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS,
                            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_FOLLOW,
                        )
                    except Exception:
                        ok2 = False
                q.put(("acct", ok1 and ok2))
        except Exception:
            q.put((op, False))
        # Light pacing between ops inside a single worker loop
        time.sleep(0.01)


def main():
    ap = argparse.ArgumentParser(description="Generate TACACS+ load for monitoring")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=int(time.time()) % 10000 + 40000)
    ap.add_argument(
        "--users",
        default="apitestuser:ApiTestPass1!",
        help="comma-separated user:pass entries",
    )
    ap.add_argument("--duration", type=int, default=30, help="duration in seconds")
    ap.add_argument(
        "--concurrency", type=int, default=5, help="number of worker threads"
    )
    ap.add_argument(
        "--mix", default="auth,author,acct", help="comma-separated operations to send"
    )
    args = ap.parse_args()

    users = []
    for entry in (args.users or "").split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        u, p = entry.split(":", 1)
        if u and p:
            users.append((u, p))
    if not users:
        users = [("apitestuser", "ApiTestPass1!")]

    mix = [m.strip() for m in args.mix.split(",") if m.strip()]
    if not mix:
        mix = ["auth", "author", "acct"]

    end_ts = time.time() + max(1, args.duration)
    q: queue.Queue[tuple[str, bool]] = queue.Queue()
    threads: list[threading.Thread] = []

    for i in range(max(1, args.concurrency)):
        user, pwd = users[i % len(users)]
        t = threading.Thread(
            target=worker,
            args=(args.host, args.port, user, pwd, mix, end_ts, q),
            daemon=True,
        )
        threads.append(t)
        t.start()

    # Aggregate counters while threads run
    counters = Counters()
    while any(t.is_alive() for t in threads) or not q.empty():
        try:
            op, ok = q.get(timeout=0.5)
        except queue.Empty:
            continue
        if op == "auth":
            counters.auth_ok += 1 if ok else 0
            counters.auth_err += 0 if ok else 1
        elif op == "author":
            counters.author_ok += 1 if ok else 0
            counters.author_err += 0 if ok else 1
        elif op == "acct":
            counters.acct_ok += 1 if ok else 0
            counters.acct_err += 0 if ok else 1

    for t in threads:
        t.join(timeout=1)

    print("\n=== Load Generation Summary ===")
    print(f"Auth    : ok={counters.auth_ok} err={counters.auth_err}")
    print(f"Author  : ok={counters.author_ok} err={counters.author_err}")
    print(f"Acct    : ok={counters.acct_ok} err={counters.acct_err}")
    print("================================\n")


if __name__ == "__main__":
    main()
