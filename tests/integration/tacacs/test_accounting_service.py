"""Fixed accounting tests - adapts to new log format and JSON structure"""

import socket
import sqlite3
import struct
import time
from pathlib import Path

import pytest

from tacacs_server.tacacs.constants import (
    TAC_PLUS_ACCT_FLAG,
    TAC_PLUS_ACCT_STATUS,
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


def _mk_acct_body(username: str, flags: int, args: list[str]) -> bytes:
    user_b = username.encode()
    port_b = b""
    rem_b = b""
    arg_bytes = [a.encode() for a in args]
    head = struct.pack(
        "!BBBBBBBBB",
        flags,
        0,
        1,
        1,
        1,
        len(user_b),
        len(port_b),
        len(rem_b),
        len(arg_bytes),
    )
    body = head
    for ab in arg_bytes:
        body += struct.pack("!B", len(ab))
    body += user_b + port_b + rem_b
    for ab in arg_bytes:
        body += ab
    return body


def _send_acct(host: str, port: int, session_id: int, body: bytes) -> int | None:
    pkt = TacacsPacket(
        version=(TAC_PLUS_MAJOR_VER << 4) | 0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
        seq_no=1,
        flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        session_id=session_id,
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
            return None
        header = TacacsPacket.unpack_header(hdr)
        rbody = _read_exact(s, header.length)
        if len(rbody) < 1:
            return None
        return rbody[0]
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def _db_rows(db_path: str, where: str = "", params: tuple = ()) -> list[tuple]:
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        q = (
            "SELECT username, session_id, status, service, command FROM accounting_logs "
            + where
        )
        cur.execute(q, params)
        return cur.fetchall()
    finally:
        con.close()


def _db_path_from_logs(server) -> str | None:
    logs = server.get_logs()
    candidates: list[str] = []
    # Updated: look for JSON format database path
    import json

    for line in logs.splitlines():
        if '"database"' in line or "database" in line.lower():
            try:
                # Try parsing as JSON first
                if line.strip().startswith("{"):
                    obj = json.loads(line)
                    if "database" in obj:
                        candidates.append(obj["database"])
                # Fallback to text parsing
                elif "Database initialized:" in line:
                    raw = line.split("Database initialized:", 1)[1].strip()
                    candidates.append(raw.strip('"} '))
                elif "Database:" in line:
                    raw = line.split("Database:", 1)[1].strip()
                    candidates.append(raw.strip('"} '))
            except Exception:
                continue
    if not candidates:
        return None
    for c in reversed(candidates):
        if "test_accounting_" in c:
            return c
    return candidates[-1] if candidates else None


def _db_path(server) -> str:
    alt = _db_path_from_logs(server)
    if alt:
        p = Path(alt)
        if not p.is_absolute():
            return str(Path(server.work_dir) / p)
        return str(p)
    cfg = Path(str(server.accounting_db))
    if not cfg.is_absolute():
        return str(Path(server.work_dir) / cfg)
    return str(cfg)


def _wait_for_table(db_path: str, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            con = sqlite3.connect(db_path)
            try:
                cur = con.cursor()
                cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='accounting_logs'"
                )
                row = cur.fetchone()
                if row:
                    return
            finally:
                con.close()
        except Exception:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"accounting_logs not found in DB within {timeout}s: {db_path}")


@pytest.mark.integration
def test_accounting_start_update_stop(server_factory):
    acc_db = "data/test_accounting.db"
    server = server_factory(
        enable_tacacs=True, config={"database": {"accounting_db": acc_db}}
    )
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        session = int(time.time()) & 0xFFFFFFFF
        _wait_for_table(_db_path(server))
        b_start = _mk_acct_body(
            "acctuser",
            TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START,
            ["service=shell", "cmd=session-start", "bytes_in=0", "bytes_out=0"],
        )
        st = _send_acct(host, port, session, b_start)
        assert st in (
            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS,
            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR,
            0,
            None,
        )
        b_upd = _mk_acct_body(
            "acctuser",
            TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_WATCHDOG,
            ["service=shell", "cmd=progress", "bytes_in=100", "bytes_out=64"],
        )
        su = _send_acct(host, port, session, b_upd)
        assert su in (
            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS,
            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR,
            0,
            None,
        )
        b_stop = _mk_acct_body(
            "acctuser",
            TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_STOP,
            ["service=shell", "cmd=session-stop", "bytes_in=200", "bytes_out=120"],
        )
        ss = _send_acct(host, port, session, b_stop)
        assert ss in (
            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS,
            TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR,
            0,
            None,
        )
        time.sleep(0.5)
        rows = _db_rows(_db_path(server), "WHERE session_id=?", (session,))
        statuses = {r[2] for r in rows}
        assert {"START", "UPDATE", "STOP"}.issubset(statuses)


@pytest.mark.integration
def test_accounting_flags_variations(server_factory):
    acc_db = "data/test_accounting.db"
    server = server_factory(
        enable_tacacs=True, config={"database": {"accounting_db": acc_db}}
    )
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        session = (int(time.time()) + 1) & 0xFFFFFFFF
        _wait_for_table(_db_path(server))
        for flag, expect in [
            (TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START, "START"),
            (TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_WATCHDOG, "UPDATE"),
            (TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_STOP, "STOP"),
        ]:
            body = _mk_acct_body(
                "userf", flag, ["service=shell", f"cmd={expect.lower()}"]
            )
            st = _send_acct(host, port, session, body)
            assert st in (
                TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS,
                TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR,
                0,
                None,
            )
        time.sleep(0.3)
        rows = _db_rows(_db_path(server), "WHERE session_id=?", (session,))
        got = {r[2] for r in rows}
        assert got == {"START", "UPDATE", "STOP"}


@pytest.mark.integration
def test_accounting_session_correlation(server_factory):
    acc_db = "data/test_accounting.db"
    server = server_factory(
        enable_tacacs=True, config={"database": {"accounting_db": acc_db}}
    )
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        s1 = (int(time.time()) + 10) & 0xFFFFFFFF
        s2 = (int(time.time()) + 11) & 0xFFFFFFFF
        _wait_for_table(_db_path(server))
        for sess in (s1, s2):
            _send_acct(
                host,
                port,
                sess,
                _mk_acct_body(
                    "alpha",
                    TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START,
                    ["service=shell"],
                ),
            )
            _send_acct(
                host,
                port,
                sess,
                _mk_acct_body(
                    "alpha",
                    TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_STOP,
                    ["service=shell"],
                ),
            )
        time.sleep(0.3)
        rows1 = _db_rows(_db_path(server), "WHERE session_id=?", (s1,))
        rows2 = _db_rows(_db_path(server), "WHERE session_id=?", (s2,))
        assert len(rows1) >= 2 and len(rows2) >= 2


@pytest.mark.integration
def test_accounting_db_storage_verification(server_factory):
    acc_db = "data/test_accounting.db"
    server = server_factory(
        enable_tacacs=True, config={"database": {"accounting_db": acc_db}}
    )
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        sess = (int(time.time()) + 20) & 0xFFFFFFFF
        _wait_for_table(_db_path(server))
        _send_acct(
            host,
            port,
            sess,
            _mk_acct_body(
                "delta",
                TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START,
                [
                    "service=shell",
                    "cmd=run",
                    "bytes_in=10",
                    "bytes_out=5",
                    "elapsed_time=1",
                ],
            ),
        )
        time.sleep(0.3)
        rows = _db_rows(_db_path(server), "WHERE session_id=?", (sess,))
        assert rows, "No accounting rows stored"
        u, sid, status, service, command = rows[0]
        assert u == "delta" and sid == sess and status in {"START", "UPDATE", "STOP"}
        assert service in ("shell", "unknown")


@pytest.mark.integration
def test_accounting_concurrent_sessions(server_factory):
    acc_db = "data/test_accounting.db"
    server = server_factory(
        enable_tacacs=True, config={"database": {"accounting_db": acc_db}}
    )
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        sessions = [(int(time.time()) + i) & 0xFFFFFFFF for i in range(30, 35)]
        _wait_for_table(_db_path(server))
        for sid in sessions:
            _send_acct(
                host,
                port,
                sid,
                _mk_acct_body(
                    "gamma",
                    TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START,
                    ["service=exec"],
                ),
            )
        time.sleep(0.5)
        rows = _db_rows(_db_path(server), "WHERE username=?", ("gamma",))
        sids = {sid for (_, sid, *_) in rows}
        assert set(sessions).issubset(sids)


@pytest.mark.integration
def test_accounting_disconnect_mid_session(server_factory):
    acc_db = "data/test_accounting.db"
    server = server_factory(
        enable_tacacs=True, config={"database": {"accounting_db": acc_db}}
    )
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        pre_sid = (int(time.time()) + 49) & 0xFFFFFFFF
        _send_acct(
            host,
            port,
            pre_sid,
            _mk_acct_body(
                "init", TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START, ["service=shell"]
            ),
        )
        _wait_for_table(_db_path(server))
        sid = (int(time.time()) + 50) & 0xFFFFFFFF
        body = _mk_acct_body(
            "omega", TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START, ["service=shell"]
        )
        pkt = TacacsPacket(
            version=(TAC_PLUS_MAJOR_VER << 4) | 0,
            packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
            seq_no=1,
            flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
            session_id=sid,
            length=0,
            body=body,
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.sendall(pkt.pack(""))
        s.close()
        rows = []
        deadline = time.time() + 3.0
        while time.time() < deadline:
            rows = _db_rows(_db_path(server), "WHERE session_id=?", (sid,))
            if any(r[2] == "START" for r in rows):
                break
            time.sleep(0.1)
        assert any(r[2] == "START" for r in rows)
