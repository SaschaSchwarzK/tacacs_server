#!/usr/bin/env python3
"""
TACACS+ Authorization Test Client

Usage:
  python tacacs_authorization_client.py [host] [port] [secret] [username] \
    [command] [service]

Example:
  python tacacs_authorization_client.py localhost 49 tacacs123 admin \
    "show version" shell
"""

import argparse
import hashlib
import os
import socket
import struct
import sys
import time
import warnings
from dataclasses import dataclass


def md5_pad(session_id: int, key: str, version: int, seq_no: int, length: int) -> bytes:
    """Generate the MD5 pad as defined in TACACS+ RFC 8907."""
    if length <= 0:
        return b""

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
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            pad.extend(hashlib.md5(md5_input, usedforsecurity=False).digest())

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
class AuthorizationResult:
    success: bool
    status: int
    server_message: str | None
    attributes: dict[str, str]
    detail: str


def tacacs_authorization(
    host: str = "localhost",
    port: int = 49,
    key: str | None = None,
    username: str | None = None,
    command: str | None = None,
    service: str = "shell",
    privilege_level: int = 15,
) -> AuthorizationResult:
    """Perform TACACS+ authorization test."""

    print("\n=== TACACS+ Authorization Test ===\n")
    print(f"Target        : {host}:{port}")
    print(f"Username      : {username}")
    print(f"Command       : {command}")
    print(f"Service       : {service}")
    print(f"Privilege Lvl : {privilege_level}")
    # Do not print shared secrets to avoid leaking sensitive data

    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))

        session_id = int(time.time()) & 0xFFFFFFFF
        user_bytes = (username or "").encode("utf-8")
        port_bytes = b"console"
        rem_addr_bytes = b"127.0.0.1"

        # Build authorization arguments
        args = []
        if service == "shell" and command:
            args.append(f"service={service}".encode())
            args.append(f"cmd={command}".encode())
        elif service == "exec":
            args.append(f"service={service}".encode())
        else:
            args.append(f"service={service}".encode())

        # Authorization packet structure:
        # authen_method, priv_lvl, authen_type, authen_service,
        # user_len, port_len, rem_addr_len, arg_cnt
        body = struct.pack(
            "!BBBBBBBB",
            6,  # authen_method: TACACSPLUS
            privilege_level,  # priv_lvl
            1,  # authen_type: ASCII
            1,  # authen_service: LOGIN
            len(user_bytes),
            len(port_bytes),
            len(rem_addr_bytes),
            len(args),
        )

        # Add user, port, rem_addr first
        body += user_bytes
        body += port_bytes
        body += rem_addr_bytes

        # Then add argument lengths
        for arg in args:
            body += struct.pack("!B", len(arg))

        # Finally add arguments
        for arg in args:
            body += arg

        version = 0xC0
        seq_no = 1
        encrypted_body = transform_body(body, session_id, key or "", version, seq_no)
        header = struct.pack(
            "!BBBBLL", version, 2, seq_no, 0, session_id, len(encrypted_body)
        )

        print("Sending authorization request...")
        sock.sendall(header + encrypted_body)

        response_header = sock.recv(12)
        if len(response_header) != 12:
            return AuthorizationResult(False, -1, None, {}, "invalid response header")

        r_version, r_type, r_seq, _, r_session, r_length = struct.unpack(
            "!BBBBLL", response_header
        )
        print(f"Received header: type={r_type}, seq={r_seq}, length={r_length}")

        response_body = sock.recv(r_length) if r_length else b""
        if len(response_body) < r_length:
            return AuthorizationResult(False, -1, None, {}, "truncated response body")

        decrypted = transform_body(
            response_body, r_session, key or "", r_version, r_seq
        )
        if len(decrypted) < 6:
            return AuthorizationResult(False, -1, None, {}, "response too short")

        status, arg_cnt, msg_len, data_len = struct.unpack("!BBHH", decrypted[:6])
        offset = 6

        # Read argument lengths
        arg_lengths = []
        for _ in range(arg_cnt):
            if offset >= len(decrypted):
                break
            arg_lengths.append(decrypted[offset])
            offset += 1

        # Read server message
        server_message = None
        if msg_len:
            server_message = decrypted[offset : offset + msg_len].decode(
                "utf-8", errors="replace"
            )
            offset += msg_len

        # Read arguments (attributes)
        attributes = {}
        for arg_len in arg_lengths:
            if offset + arg_len > len(decrypted):
                break
            arg_str = decrypted[offset : offset + arg_len].decode(
                "utf-8", errors="replace"
            )
            if "=" in arg_str:
                key_attr, value = arg_str.split("=", 1)
                attributes[key_attr] = value
            else:
                attributes[arg_str] = ""
            offset += arg_len

        success = status == 1  # TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        detail = {
            1: "authorization granted (PASS_ADD)",
            2: "authorization granted (PASS_REPL)",
            16: "authorization denied (FAIL)",
            17: "authorization error (ERROR)",
            21: "authorization follow (FOLLOW)",
        }.get(status, f"status={status}")

        print()
        if success:
            print("Result        : ✅ Authorization granted")
        else:
            print("Result        : ❌ Authorization denied")
        print(f"Status Detail : {detail}")
        if server_message:
            print(f"Server Message: {server_message}")
        if attributes:
            print("Attributes    :")
            for key_attr, value in attributes.items():
                print(f"  {key_attr} = {value}")

        return AuthorizationResult(success, status, server_message, attributes, detail)

    except OSError as exc:
        print(f"✗ Network error: {exc}")
        return AuthorizationResult(False, -1, None, {}, "network error")
    except Exception as exc:
        print(f"✗ Unexpected error: {exc}")
        return AuthorizationResult(False, -1, None, {}, "unexpected error")
    finally:
        if sock is not None:
            try:
                sock.close()
            except (OSError, AttributeError):
                pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TACACS+ Authorization Test Client")
    parser.add_argument(
        "host",
        nargs="?",
        default=os.getenv("TACACS_SERVER", "localhost"),
        help="Server host",
    )
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        default=int(os.getenv("TACACS_PORT", "49")),
        help="Server port",
    )
    parser.add_argument(
        "secret", nargs="?", default=os.getenv("TACACS_SECRET"), help="Shared secret"
    )
    parser.add_argument(
        "username", nargs="?", default=os.getenv("TACACS_USERNAME"), help="Username"
    )
    parser.add_argument(
        "command", nargs="?", default="show version", help="Command to authorize"
    )
    parser.add_argument(
        "service", nargs="?", default="shell", help="Service type (shell, exec)"
    )
    parser.add_argument(
        "--privilege-level", type=int, default=15, help="Privilege level (0-15)"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if not args.secret:
        print("Error: TACACS+ secret required")
        return 1
    if not args.username:
        print("Error: Username required")
        return 1

    result = tacacs_authorization(
        args.host,
        args.port,
        args.secret,
        args.username,
        args.command,
        args.service,
        args.privilege_level,
    )
    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
