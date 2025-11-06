#!/usr/bin/env python3
import argparse
import hashlib
import secrets
import socket
import struct
import sys


def md5_pad(session_id: int, key: str, version: int, seq_no: int, length: int) -> bytes:
    pad = bytearray()
    session_id_bytes = struct.pack("!L", session_id)
    key_bytes = key.encode("utf-8")
    version_byte = bytes([version])
    seq_byte = bytes([seq_no])
    while len(pad) < length:
        if not pad:
            md5_input = session_id_bytes + key_bytes + version_byte + seq_byte
        else:
            md5_input = session_id_bytes + key_bytes + version_byte + seq_byte + pad
        pad.extend(hashlib.md5(md5_input, usedforsecurity=False).digest())
    return bytes(pad[:length])


def transform_body(body: bytes, session_id: int, key: str, version: int, seq_no: int) -> bytes:
    if not key:
        return body
    pad = md5_pad(session_id, key, version, seq_no, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))


def tacacs_authenticate(host: str, port: int, key: str, username: str, password: str) -> tuple[bool, str]:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))

        session_id = secrets.randbits(32)
        user_bytes = username.encode("utf-8")
        port_bytes = b"console"
        rem_addr_bytes = b"127.0.0.1"
        data_bytes = password.encode("utf-8")

        body = struct.pack("!BBBBBBBB", 1, 15, 2, 1, len(user_bytes), len(port_bytes), len(rem_addr_bytes), len(data_bytes))
        body += user_bytes + port_bytes + rem_addr_bytes + data_bytes

        version = 0xC0
        seq_no = 1
        encrypted_body = transform_body(body, session_id, key, version, seq_no)
        header = struct.pack("!BBBBLL", version, 1, seq_no, 0, session_id, len(encrypted_body))
        sock.sendall(header + encrypted_body)

        response_header = sock.recv(12)
        if len(response_header) != 12:
            return False, "Invalid response header"
        r_version, r_type, r_seq, _, r_session, r_length = struct.unpack("!BBBBLL", response_header)
        response_body = sock.recv(r_length) if r_length else b""
        if len(response_body) < r_length:
            return False, "Truncated response body"
        decrypted = transform_body(response_body, r_session, key, r_version, r_seq)
        if len(decrypted) < 6:
            return False, "Response too short"
        status, _flags, msg_len, data_len = struct.unpack("!BBHH", decrypted[:6])
        success = status == 1
        detail = {1: "authentication accepted", 2: "authentication rejected"}.get(status, f"status={status}")
        return success, detail
    except Exception as e:
        return False, f"Connection error: {e}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=49)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--allow-reject", action="store_true", help="Exit 0 when server responds even if authentication is rejected")
    args = ap.parse_args()
    ok, msg = tacacs_authenticate(args.host, args.port, args.secret, args.username, args.password)
    print(msg)
    if ok:
        return 0
    # Treat receipt of explicit rejection as success when requested
    if args.allow_reject and (msg.startswith("authentication rejected") or msg.startswith("status=") or msg.startswith("authentication accepted") or msg.startswith("Connection error") is False):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
