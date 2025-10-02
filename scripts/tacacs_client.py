#!/usr/bin/env python3
"""Simple TACACS+ PAP client for quick end-to-end checks."""

from __future__ import annotations

import argparse
import hashlib
import socket
import struct
import sys
import time
from dataclasses import dataclass


def md5_pad(session_id: int, key: str, version: int, seq_no: int, length: int) -> bytes:
    """Generate the MD5 pad defined in RFC 1492."""

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
        pad.extend(hashlib.md5(md5_input).digest())

    return bytes(pad[:length])


def transform_body(
    body: bytes, session_id: int, key: str, version: int, seq_no: int
) -> bytes:
    """Encrypt/decrypt the TACACS+ body using the MD5 pad."""

    if not key:
        return body
    pad = md5_pad(session_id, key, version, seq_no, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))


@dataclass
class PapResult:
    success: bool
    status: int
    server_message: str | None
    detail: str


def pap_authentication(
    host: str = "localhost",
    port: int = 49,
    key: str = "tacacs123",
    username: str = "admin",
    password: str = "admin123",
) -> PapResult:
    """Perform a single TACACS+ PAP authentication round-trip."""

    print("\n=== TACACS+ PAP Authentication Test ===\n")
    print(f"Target        : {host}:{port}")
    print(f"Username      : {username}")
    obscured = "*" * len(password) if password else "(empty)"
    print(f"Password      : {obscured}")
    print(f"Shared Secret : {key}\n")

    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))

        session_id = int(time.time()) & 0xFFFFFFFF
        user_bytes = username.encode("utf-8")
        port_bytes = b"console"
        rem_addr_bytes = b"127.0.0.1"
        data_bytes = password.encode("utf-8")

        body = struct.pack(
            "!BBBBBBBB",
            1,  # action: LOGIN
            15,  # priv_lvl
            2,  # authen_type: PAP
            1,  # service: LOGIN
            len(user_bytes),
            len(port_bytes),
            len(rem_addr_bytes),
            len(data_bytes),
        )
        body += user_bytes + port_bytes + rem_addr_bytes + data_bytes

        version = 0xC0
        seq_no = 1
        encrypted_body = transform_body(body, session_id, key, version, seq_no)
        header = struct.pack(
            "!BBBBLL", version, 1, seq_no, 0, session_id, len(encrypted_body)
        )

        print("Sending PAP authentication request...")
        sock.sendall(header + encrypted_body)

        response_header = sock.recv(12)
        if len(response_header) != 12:
            return PapResult(False, -1, None, "invalid response header")

        r_version, r_type, r_seq, _, r_session, r_length = struct.unpack(
            "!BBBBLL", response_header
        )
        print(f"Received header: type={r_type}, seq={r_seq}, length={r_length}")

        response_body = sock.recv(r_length) if r_length else b""
        if len(response_body) < r_length:
            return PapResult(False, -1, None, "truncated response body")

        decrypted = transform_body(response_body, r_session, key, r_version, r_seq)
        if len(decrypted) < 6:
            return PapResult(False, -1, None, "response too short")

        status, _flags, msg_len, data_len = struct.unpack("!BBHH", decrypted[:6])
        offset = 6
        server_message = None
        if msg_len:
            server_message = decrypted[offset:offset + msg_len].decode(
                "utf-8", errors="replace"
            )
            offset += msg_len

        success = status == 1
        detail = {
            1: "authentication accepted",
            2: "authentication rejected",
            0: "user continues",
        }.get(status, f"status={status}")

        print()
        if success:
            print("Result        : ✅ Authentication accepted")
        else:
            print("Result        : ❌ Authentication rejected")
        print(f"Status Detail : {detail}")
        if server_message:
            print(f"Server Message: {server_message}")
        if data_len:
            attr_data = decrypted[offset:offset + data_len]
            print(f"Additional Data ({data_len} bytes): {attr_data.hex()}")

        return PapResult(success, status, server_message, detail)

    except OSError as exc:
        print(f"✗ Network error: {exc}")
        return PapResult(False, -1, None, "network error")
    except Exception as exc:  # pragma: no cover - emergency logging path
        print(f"✗ Unexpected error: {exc}")
        return PapResult(False, -1, None, "unexpected error")
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple TACACS+ PAP client")
    parser.add_argument(
        "host", nargs="?", default="localhost", help="Server host (default: localhost)"
    )
    parser.add_argument(
        "port", nargs="?", type=int, default=49, help="Server port (default: 49)"
    )
    parser.add_argument("secret", nargs="?", default="tacacs123", help="Shared secret")
    parser.add_argument("username", nargs="?", default="admin", help="Username")
    parser.add_argument("password", nargs="?", default="admin123", help="Password")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = pap_authentication(
        args.host, args.port, args.secret, args.username, args.password
    )
    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())