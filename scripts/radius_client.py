#!/usr/bin/env python3
"""
RADIUS Test Client

Usage:
  Single test: python radius_client.py [server] [port] [secret] [username] [password]
  Batch test:  python radius_client.py --batch credentials.csv

CSV format: username,password
"""

import csv
import hashlib
import os
import secrets
import socket
import struct
import sys
import time
import warnings


def create_access_request(
    username: str, password: str, identifier: int, secret: bytes
) -> bytes:
    """Create RADIUS Access-Request packet with encrypted password.

    Args:
        username: Username for authentication
        password: Password for authentication
        identifier: Packet identifier (0-255)
        secret: Shared secret as bytes

    Returns:
        Tuple of (packet_bytes, authenticator_bytes)

    Note: MD5 is used for password encryption as mandated by RADIUS RFC 2865.
    """
    # Generate random authenticator
    authenticator = secrets.token_bytes(16)

    # Create attributes
    attributes = b""

    # User-Name attribute
    username_bytes = username.encode("utf-8")
    attributes += struct.pack("BB", 1, len(username_bytes) + 2) + username_bytes

    # User-Password attribute (encrypted)
    password_bytes = password.encode("utf-8")
    # Pad to 16 byte boundary
    pad_length = 16 - (len(password_bytes) % 16)
    password_bytes += b"\x00" * pad_length

    # Encrypt password
    encrypted_password = b""
    prev = authenticator
    for i in range(0, len(password_bytes), 16):
        chunk = password_bytes[i : i + 16]
        hash_input = secret + prev
        # MD5 required by RADIUS RFC 2865 - not for general cryptographic use
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            key = hashlib.md5(hash_input, usedforsecurity=False).digest()
        encrypted_chunk = bytes(a ^ b for a, b in zip(chunk, key))
        encrypted_password += encrypted_chunk
        prev = encrypted_chunk

    attributes += struct.pack("BB", 2, len(encrypted_password) + 2) + encrypted_password

    # IP-Address attribute (0.0.0.0)
    attributes += struct.pack("BB", 4, 6) + bytes([0, 0, 0, 0])

    # Service-Type attribute (Administrative)
    attributes += struct.pack("BBBBBB", 6, 6, 0, 0, 0, 6)

    # Calculate length
    length = 20 + len(attributes)

    # Create packet
    packet = struct.pack("!BBH", 1, identifier, length) + authenticator + attributes

    return packet, authenticator


def test_radius_auth(
    server="localhost", port=1812, secret=None, username=None, password=None
):
    """Test RADIUS authentication against server.

    Args:
        server: RADIUS server hostname or IP
        port: RADIUS server port (default 1812)
        secret: Shared secret string
        username: Username for authentication
        password: Password for authentication

    Returns:
        bool: True if authentication successful, False otherwise
    """
    """Test RADIUS authentication"""

    print("Testing RADIUS authentication:")
    print(f"  Server: {server}:{port}")
    print(f"  Username: {username}")
    print(f"  Password: {'*' * len(password)}")
    print()

    try:
        # Create socket with timeout to prevent blocking connections
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)  # 5 second timeout

        # Create Access-Request
        identifier = secrets.randbelow(256)
        secret_bytes = secret.encode("utf-8")
        request, request_auth = create_access_request(
            username, password, identifier, secret_bytes
        )

        # Send request
        print("Sending Access-Request...")
        sock.sendto(request, (server, port))

        # Receive response
        response_data, addr = sock.recvfrom(4096)

        if len(response_data) < 20:
            print("Invalid response received")
            return False

        # Parse response
        code, resp_id, length = struct.unpack("!BBH", response_data[:4])

        code_names = {1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject"}
        print(f"Response received: {code_names.get(code, f'Unknown({code})')}")

        if code == 2:  # Access-Accept
            print("✓ Authentication SUCCESSFUL")

            # Parse attributes
            offset = 20
            while offset < length:
                if offset + 2 > len(response_data):
                    break
                attr_type, attr_len = struct.unpack(
                    "BB", response_data[offset : offset + 2]
                )
                if attr_len < 2 or offset + attr_len > len(response_data):
                    break

                attr_value = response_data[offset + 2 : offset + attr_len]

                # Reply-Message
                if attr_type == 18:
                    message = attr_value.decode("utf-8", errors="replace")
                    print(f"  Reply-Message: {message}")

                offset += attr_len

            return True

        elif code == 3:  # Access-Reject
            print("✗ Authentication FAILED")
            return False
        else:
            print(f"Unexpected response code: {code}")
            return False

    except TimeoutError:
        print("✗ Request timed out - server not responding")
        return False
    except (ConnectionError, OSError) as e:
        print(f"✗ Network error: {e}")
        return False
    except (ValueError, struct.error) as e:
        print(f"✗ Protocol error: {e}")
        return False
    finally:
        try:
            sock.close()
        except (OSError, AttributeError):
            pass  # Socket already closed, invalid, or None


def test_batch_credentials(csv_file, server="localhost", port=1812, secret=None):
    """Test multiple credentials from CSV file"""
    if not secret:
        print("Error: RADIUS secret required for batch testing")
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
        success = test_radius_auth(server, port, secret, username, password)
        results.append((username, success))
        time.sleep(0.1)  # Brief pause between tests

    # Summary
    total_time = time.time() - start_time
    successful = sum(1 for _, success in results if success)
    failed = len(results) - successful

    print("\n=== Batch Test Summary ===")
    print(f"Total tests: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Success rate: {successful / len(results) * 100:.1f}%")
    print(f"Total time: {total_time:.2f}s")
    print(f"Average time per test: {total_time / len(results):.2f}s")

    return failed == 0


def main():
    """Main function"""
    # Check for batch mode
    if len(sys.argv) > 1 and sys.argv[1] == "--batch":
        if len(sys.argv) < 3:
            print("Error: CSV file required for batch mode")
            print("Usage: python radius_client.py --batch credentials.csv")
            sys.exit(1)

        csv_file = sys.argv[2]
        server = os.getenv("RADIUS_SERVER", "localhost")
        port = int(os.getenv("RADIUS_PORT", "1812"))
        secret = os.getenv("RADIUS_SECRET")

        if not secret:
            print(
                "Error: RADIUS_SECRET environment variable required for batch testing"
            )
            sys.exit(1)

        success = test_batch_credentials(csv_file, server, port, secret)
        sys.exit(0 if success else 1)

    # Single test mode (existing functionality)
    server = (
        sys.argv[1] if len(sys.argv) > 1 else os.getenv("RADIUS_SERVER", "localhost")
    )
    port = (
        int(sys.argv[2]) if len(sys.argv) > 2 else int(os.getenv("RADIUS_PORT", "1812"))
    )
    secret = sys.argv[3] if len(sys.argv) > 3 else os.getenv("RADIUS_SECRET")
    username = sys.argv[4] if len(sys.argv) > 4 else os.getenv("RADIUS_USERNAME")
    password = sys.argv[5] if len(sys.argv) > 5 else os.getenv("RADIUS_PASSWORD")

    if not secret:
        print(
            "Error: RADIUS secret required (set RADIUS_SECRET env var "
            "or pass as argument)"
        )
        sys.exit(1)
    if not username:
        print(
            "Error: Username required (set RADIUS_USERNAME env var or pass as argument)"
        )
        sys.exit(1)
    if not password:
        print(
            "Error: Password required (set RADIUS_PASSWORD env var or pass as argument)"
        )
        sys.exit(1)

    success = test_radius_auth(server, port, secret, username, password)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
