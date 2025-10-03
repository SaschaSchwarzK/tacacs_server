#!/usr/bin/env python3
"""
TACACS+ PAP Test Client

Usage:
  Single test: python tacacs_client.py [host] [port] [secret] [username] [password]
  Batch test:  python tacacs_client.py --batch credentials.csv

CSV format: username,password
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import socket
import struct
import sys
import time
import warnings
from dataclasses import dataclass


def md5_pad(session_id: int, key: str, version: int, seq_no: int, length: int) -> bytes:
    """Generate the MD5 pad as defined in TACACS+ RFC 8907.

    Note: MD5 is used here as mandated by the TACACS+ protocol specification,
    not for general cryptographic purposes. This is protocol-required legacy.

    Args:
        session_id: TACACS+ session identifier
        key: Shared secret key
        version: TACACS+ version byte
        seq_no: Sequence number
        length: Required pad length in bytes

    Returns:
        Encryption pad bytes of specified length
    """
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
        # MD5 required by TACACS+ RFC 8907 - not for general cryptographic use
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
class PapResult:
    success: bool
    status: int
    server_message: str | None
    detail: str


def pap_authentication(
    host: str = "localhost",
    port: int = 49,
    key: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> PapResult:
    """Perform TACACS+ PAP authentication test.

    Args:
        host: TACACS+ server hostname or IP
        port: TACACS+ server port (default 49)
        key: Shared secret key
        username: Username for authentication
        password: Password for authentication

    Returns:
        PapResult containing authentication outcome and details

    Raises:
        OSError: On network connection errors
    """
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
            server_message = decrypted[offset : offset + msg_len].decode(
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
            attr_data = decrypted[offset : offset + data_len]
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
            except (OSError, AttributeError):
                pass  # Socket already closed, invalid, or None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple TACACS+ PAP client")
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
        "password", nargs="?", default=os.getenv("TACACS_PASSWORD"), help="Password"
    )
    return parser.parse_args(argv)


def test_batch_credentials(
    csv_file: str, host: str = "localhost", port: int = 49, key: str | None = None
) -> bool:
    """Test multiple credentials from CSV file"""
    if not key:
        print("Error: TACACS+ secret required for batch testing")
        return False

    # Validate file path to prevent path traversal
    from pathlib import Path

    try:
        csv_path = Path(csv_file).resolve()
        cwd = Path.cwd().resolve()
        if not csv_path.is_relative_to(cwd) or not csv_path.is_file():
            print(f"Error: Invalid or unsafe file path: {csv_file}")
            return False
    except (OSError, ValueError):
        print(f"Error: Invalid file path: {csv_file}")
        return False

    try:
        with open(csv_file) as f:
            reader = csv.reader(f)
            credentials = [(row[0], row[1]) for row in reader if len(row) >= 2]
    except (FileNotFoundError, IndexError, PermissionError) as e:
        print(f"Error reading CSV file: {e}")
        return False

    if not credentials:
        print("No valid credentials found in CSV file")
        return False

    print(f"\nBatch testing {len(credentials)} credentials...\n")

    results = []
    start_time = time.time()

    for i, (username, password) in enumerate(credentials, 1):
        print(f"[{i}/{len(credentials)}] Testing {username}...")
        result = pap_authentication(host, port, key, username, password)
        results.append((username, result.success))
        time.sleep(0.1)  # Brief pause between tests

    # Summary
    total_time = time.time() - start_time
    successful = sum(1 for _, success in results if success)
    failed = len(results) - successful

    print("\n=== Batch Test Summary ===")
    print(f"Total tests: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Success rate: {successful/len(results)*100:.1f}%")
    print(f"Total time: {total_time:.2f}s")
    print(f"Average time per test: {total_time/len(results):.2f}s")

    return failed == 0


def main(argv: list[str] | None = None) -> int:
    # Check for batch mode
    if argv and len(argv) > 0 and argv[0] == "--batch":
        if len(argv) < 2:
            print("Error: CSV file required for batch mode")
            print("Usage: python tacacs_client.py --batch credentials.csv")
            return 1

        csv_file = argv[1]
        host = os.getenv("TACACS_SERVER", "localhost")
        port = int(os.getenv("TACACS_PORT", "49"))
        secret = os.getenv("TACACS_SECRET")

        if not secret:
            print(
                "Error: TACACS_SECRET environment variable required for batch testing"
            )
            return 1

        success = test_batch_credentials(csv_file, host, port, secret)
        return 0 if success else 1

    # Single test mode (existing functionality)
    args = parse_args(argv)

    if not args.secret:
        print(
            "Error: TACACS+ secret required (set TACACS_SECRET env var "
            "or pass as argument)"
        )
        return 1
    if not args.username:
        print(
            "Error: Username required (set TACACS_USERNAME env var or pass as argument)"
        )
        return 1
    if not args.password:
        print(
            "Error: Password required (set TACACS_PASSWORD env var or pass as argument)"
        )
        return 1

    result = pap_authentication(
        args.host, args.port, args.secret, args.username, args.password
    )
    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
