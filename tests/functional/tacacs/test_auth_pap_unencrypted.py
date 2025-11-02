"""TACACS+ encryption test with detailed diagnostics"""

from __future__ import annotations

import configparser
import socket
import struct
import time

from tacacs_server.auth.local_user_service import LocalUserService
from tacacs_server.devices.store import DeviceStore
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


def _read_exact(sock: socket.socket, length: int, timeout: float = 3.0) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _mk_auth_start_body(username: str, password: str) -> bytes:
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


def _seed_state(server) -> tuple[str, str, int]:
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(server.config_path)
    auth_db = cfg.get("auth", "local_auth_db", fallback=str(server.auth_db))
    devices_db = cfg.get("devices", "database", fallback=str(server.devices_db))

    username = "apitestuser"
    password = "ApiTestPass1!"
    
    print(f"Creating user: {username}")
    usvc = LocalUserService(auth_db)
    try:
        usvc.create_user(username, password=password, privilege_level=1)
    except Exception as e:
        print(f"User creation warning: {e}")

    print(f"Creating device group and device")
    store = DeviceStore(devices_db)
    store.ensure_group(
        "dg-plain",
        description="TACACS auth test",
        metadata={"tacacs_secret": "testing123"},
    )
    device = store.ensure_device(name="loopback", network="127.0.0.1", group="dg-plain")
    print(f"Device: {device.name}, group={device.group.name if device.group else None}, secret={device.tacacs_secret}")
    
    return username, password, server.tacacs_port


def _try_auth_unencrypted(host: str, port: int, username: str, password: str) -> bool:
    session_id = int(time.time()) & 0xFFFFFFFF
    pkt = TacacsPacket(
        version=(TAC_PLUS_MAJOR_VER << 4) | 0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        session_id=session_id,
        length=0,
        body=_mk_auth_start_body(username, password),
    )
    full = pkt.pack("")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        s.sendall(full)
        hdr = _read_exact(s, TAC_PLUS_HEADER_SIZE)
        if len(hdr) != TAC_PLUS_HEADER_SIZE:
            print(f"Unencrypted: Short header {len(hdr)}")
            return False
        header = TacacsPacket.unpack_header(hdr)
        body = _read_exact(s, header.length)
        if len(body) != header.length:
            print(f"Unencrypted: Short body {len(body)}/{header.length}")
            return False
        status = body[0]
        print(f"Unencrypted: status={status}, PASS={TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS}")
        return status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS
    except Exception as e:
        print(f"Unencrypted exception: {e}")
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _try_auth_encrypted(
    host: str, port: int, username: str, password: str, secret: str = "testing123"
) -> bool:
    session_id = int(time.time()) & 0xFFFFFFFF
    pkt = TacacsPacket(
        version=(TAC_PLUS_MAJOR_VER << 4) | 0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        flags=0,
        session_id=session_id,
        length=0,
        body=_mk_auth_start_body(username, password),
    )
    full = pkt.pack(secret)
    print(f"Encrypted: session={session_id:08x}, secret='{secret}'")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        s.sendall(full)
        hdr = _read_exact(s, TAC_PLUS_HEADER_SIZE)
        if len(hdr) != TAC_PLUS_HEADER_SIZE:
            print(f"Encrypted: Short header {len(hdr)}")
            return False
        header = TacacsPacket.unpack_header(hdr)
        print(f"Encrypted: response seq={header.seq_no}, len={header.length}, flags={header.flags}")
        body = _read_exact(s, header.length)
        if len(body) != header.length:
            print(f"Encrypted: Short body {len(body)}/{header.length}")
            return False
        
        import hashlib as _hashlib

        def _md5_pad(
            sess_id: int, secret: str, version: int, seq_no: int, length: int
        ) -> bytes:
            pad = bytearray()
            sid = struct.pack("!L", sess_id)
            sec = secret.encode("utf-8")
            ver = bytes([(TAC_PLUS_MAJOR_VER << 4) | 0])
            seq = bytes([header.seq_no])
            while len(pad) < length:
                md5_in = sid + sec + ver + seq + (pad if pad else b"")
                pad.extend(_hashlib.md5(md5_in, usedforsecurity=False).digest())
            return bytes(pad[:length])

        pad = _md5_pad(
            header.session_id,
            secret,
            (TAC_PLUS_MAJOR_VER << 4) | 0,
            header.seq_no,
            len(body),
        )
        dec = bytes(a ^ b for a, b in zip(body, pad))
        status = dec[0]
        print(f"Encrypted: decrypted status={status}, PASS={TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS}")
        if len(dec) > 6:
            import struct
            server_msg_len, data_len = struct.unpack("!HH", dec[2:6])
            if server_msg_len > 0:
                msg = dec[6:6+server_msg_len].decode('ascii', errors='replace')
                print(f"Encrypted: server_msg='{msg}'")
        return status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS
    except Exception as e:
        print(f"Encrypted exception: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def test_auth_pap_respects_encryption_required(server_factory):
    """Test encryption enforcement with diagnostics."""
    for require_enc in (False, True):
        print(f"\n{'='*60}")
        print(f"Testing encryption_required={require_enc}")
        print(f"{'='*60}")
        
        server = server_factory(
            config={
                "auth": {"backends": "local"},
                "encryption_required": str(require_enc).lower(),
            },
            enable_tacacs=True,
        )
        with server:
            username, password, port = _seed_state(server)
            host = "127.0.0.1"
            
            print(f"\nTesting unencrypted auth...")
            unenc_ok = _try_auth_unencrypted(host, port, username, password)
            print(f"Result: {'PASS' if unenc_ok else 'FAIL'}")
            
            print(f"\nTesting encrypted auth...")
            enc_ok = _try_auth_encrypted(host, port, username, password, secret="testing123")
            print(f"Result: {'PASS' if enc_ok else 'FAIL'}")
            
            print(f"\n--- Server Logs ---")
            logs = server.get_logs()
            for line in logs.split('\n')[-20:]:
                if line.strip():
                    print(line)
            
            if require_enc:
                assert not unenc_ok, "Unencrypted should fail when encryption_required=true"
                logs_lower = logs.lower()
                assert "unencrypted tacacs+ not permitted" in logs_lower or "rejecting unencrypted tacacs+ auth" in logs_lower
                assert enc_ok, "Encrypted should work when encryption_required=true"
            else:
                assert unenc_ok, "Unencrypted should work when encryption_required=false"
                assert enc_ok, "Encrypted should work when encryption_required=false"
            
            print(f"✓ Test passed for encryption_required={require_enc}")
