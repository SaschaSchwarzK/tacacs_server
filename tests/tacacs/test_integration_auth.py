import configparser
import os
import socket
import struct
import time

from tacacs_server.auth.local_user_service import LocalUserService
from tacacs_server.tacacs.constants import (
    TAC_PLUS_AUTHEN_ACTION,
    TAC_PLUS_AUTHEN_STATUS,
    TAC_PLUS_AUTHEN_SVC,
    TAC_PLUS_AUTHEN_TYPE,
    TAC_PLUS_FLAGS,
    TAC_PLUS_HEADER_SIZE,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.packet import TacacsPacket


def _get_auth_db_from_config() -> str:
    cfg_path = os.environ.get("TACACS_CONFIG")
    assert cfg_path and os.path.exists(cfg_path)
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(cfg_path)
    return cfg.get("auth", "local_auth_db", fallback="data/local_auth.db")


def _mk_auth_start_body(username: str, password: str) -> bytes:
    # !BBBBBBBB -> action, priv, type, service, user_len, port_len, rem_len, data_len
    user_b = username.encode()
    port_b = b""
    rem_b = b""
    data_b = password.encode()
    head = struct.pack(
        "!BBBBBBBB",
        TAC_PLUS_AUTHEN_ACTION.TAC_PLUS_AUTHEN_LOGIN,
        1,
        TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
        TAC_PLUS_AUTHEN_SVC.TAC_PLUS_AUTHEN_SVC_LOGIN,
        len(user_b),
        len(port_b),
        len(rem_b),
        len(data_b),
    )
    return head + user_b + port_b + rem_b + data_b


def test_auth_pap_unencrypted_happy_path(tacacs_server):
    # Arrange: ensure a local user exists
    auth_db = _get_auth_db_from_config()
    print(f"[INTEG-DEBUG] auth_db from TACACS_CONFIG -> {auth_db}")
    usvc = LocalUserService(auth_db)
    username = "apitestuser"
    password = "ApiTestPass1!"
    try:
        usvc.create_user(username, password=password, privilege_level=1)
    except Exception:
        # ignore if already exists from previous runs
        pass

    host = tacacs_server["host"]
    port = tacacs_server["port"]
    # Debug backend state via monitoring API
    try:
        import os

        import requests

        base = os.environ.get(
            "TACACS_WEB_BASE",
            f"http://{host}:{os.environ.get('TEST_WEB_PORT', '8080')}",
        )
        rb = requests.get(f"{base}/api/backends", timeout=3)
        print(
            f"[INTEG-DEBUG] /api/backends -> {rb.status_code} {(rb.text or '')[:300]}"
        )
    except Exception as e:
        print(f"[INTEG-DEBUG] backend stats fetch failed: {e}")

    # Build unencrypted TACACS+ auth START packet
    session_id = int(time.time()) & 0xFFFFFFFF
    seq_no = 1
    pkt = TacacsPacket(
        version=(TAC_PLUS_MAJOR_VER << 4) | 0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=seq_no,
        flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        session_id=session_id,
        length=0,
        body=_mk_auth_start_body(username, password),
    )
    body = pkt.body
    hdr = pkt.pack_header()[:-4]  # we will replace length after
    # pack complete header + body
    full = pkt.pack("")  # key irrelevant since unencrypted

    # Send and receive
    print(f"[INTEG-DEBUG] connecting to {host}:{port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((host, port))
    try:
        print(
            f"[INTEG-DEBUG] sending len={len(full)} unencrypted seq={seq_no} sess=0x{session_id:08x}"
        )
        s.sendall(full)
        # Read response header
        hdr = s.recv(TAC_PLUS_HEADER_SIZE)
        print(f"[INTEG-DEBUG] recv header len={len(hdr)}")
        assert len(hdr) == TAC_PLUS_HEADER_SIZE
        r = TacacsPacket.unpack_header(hdr)
        print(
            f"[INTEG-DEBUG] resp type={r.packet_type} seq={r.seq_no} flags=0x{r.flags:02x} len={r.length}"
        )
        assert r.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN
        assert r.seq_no == 2  # server replies with even seq
        # Read body
        body = s.recv(r.length)
        print(f"[INTEG-DEBUG] recv body len={len(body)}")
        assert len(body) == r.length
        r.body = body
        status = body[0]
        print(f"[INTEG-DEBUG] auth status byte={status}")
        if status != TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS:
            # Surface server logs for diagnosis
            try:
                import os

                import requests

                base = os.environ.get(
                    "TACACS_WEB_BASE",
                    f"http://127.0.0.1:{os.environ.get('TEST_WEB_PORT', '8080')}",
                )
                rlog = requests.get(f"{base}/api/admin/logs", timeout=3)
                print(
                    f"[INTEG-DEBUG] /api/admin/logs -> {rlog.status_code} body[:1000]={(rlog.text or '')[:1000]}"
                )
            except Exception as e:
                print(f"[INTEG-DEBUG] fetching logs failed: {e}")
            try:
                log_path = tacacs_server.get("log_path")
                if log_path:
                    with open(log_path) as lf:
                        tail = lf.read()[-2000:]
                        print(f"[INTEG-DEBUG] server log tail:\n{tail}")
            except Exception as e:
                print(f"[INTEG-DEBUG] reading log file failed: {e}")
        assert status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS
    finally:
        s.close()
