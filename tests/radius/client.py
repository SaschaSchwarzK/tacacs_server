"""Minimal RADIUS client for tests.

Provides helpers to send Access-Request and Accounting-Request packets
and receive responses against the live test server fixture.
"""

from __future__ import annotations

import hashlib
import secrets
import socket
import struct
import warnings

RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCOUNTING_REQUEST = 4


def _pack_attr(attr_type: int, value: bytes) -> bytes:
    length = len(value) + 2
    return struct.pack("BB", attr_type, length) + value


def build_access_request(
    username: str, password: str, secret: bytes, identifier: int | None = None
) -> tuple[bytes, bytes]:
    """Build a RADIUS Access-Request packet with encrypted User-Password.

    Returns (packet_bytes, request_authenticator).
    """
    if identifier is None:
        identifier = secrets.randbelow(256)
    # Random request authenticator
    req_auth = secrets.token_bytes(16)
    attrs = b""
    attrs += _pack_attr(1, username.encode("utf-8"))  # User-Name
    # Encrypt password per RFC 2865
    pwd = password.encode("utf-8")
    pad = (-len(pwd)) % 16
    if pad:
        pwd += b"\x00" * pad
    enc = b""
    prev = req_auth
    for i in range(0, len(pwd), 16):
        block = pwd[i : i + 16]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            key = hashlib.md5(secret + prev, usedforsecurity=False).digest()
        enc_block = bytes(a ^ b for a, b in zip(block, key))
        enc += enc_block
        prev = enc_block
    attrs += _pack_attr(2, enc)  # User-Password
    # Minimal NAS-IP-Address (0.0.0.0)
    attrs += _pack_attr(4, bytes([0, 0, 0, 0]))
    length = 20 + len(attrs)
    header = struct.pack("!BBH", RADIUS_ACCESS_REQUEST, identifier, length)
    return header + req_auth + attrs, req_auth


def build_accounting_request(
    secret: bytes, attrs: bytes = b"", identifier: int | None = None
) -> bytes:
    """Build a minimal Accounting-Request with valid Request Authenticator."""
    if identifier is None:
        identifier = secrets.randbelow(256)
    length = 20 + len(attrs)
    header = struct.pack("!BBH", RADIUS_ACCOUNTING_REQUEST, identifier, length)
    zero = b"\x00" * 16
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        req_auth = hashlib.md5(
            header + zero + attrs + secret, usedforsecurity=False
        ).digest()
    return header + req_auth + attrs


def send_and_recv(
    sock: socket.socket, packet: bytes, addr: tuple[str, int], timeout: float = 1.0
) -> tuple[int, bytes] | None:
    """Send a RADIUS packet and receive a response.

    Returns (code, raw_response) or None on timeout.
    """
    sock.settimeout(timeout)
    sock.sendto(packet, addr)
    try:
        data, _ = sock.recvfrom(4096)
    except TimeoutError:
        return None
    if len(data) < 4:
        return None
    code = data[0]
    return code, data
