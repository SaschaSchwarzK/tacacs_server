import hashlib
import struct

from tacacs_server.radius.server import (
    RADIUS_ACCOUNTING_REQUEST,
    _verify_request_authenticator,
)


def _build_acct_request(
    secret: bytes, attrs: bytes = b"", identifier: int = 1
) -> bytes:
    # Build header: Code, Identifier, Length
    code = RADIUS_ACCOUNTING_REQUEST
    length = 20 + len(attrs)
    header = struct.pack("!BBH", code, identifier, length)
    # Request Authenticator for Accounting-Request is MD5(Code+ID+Len+16*0+Attrs+Secret)
    zero_auth = b"\x00" * 16
    to_hash = header + zero_auth + attrs + secret
    calc = hashlib.md5(to_hash).digest()
    return header + calc + attrs


def test_verify_request_authenticator_valid():
    secret = b"radiussecret"
    packet = _build_acct_request(secret)
    assert _verify_request_authenticator(packet, secret) is True


def test_verify_request_authenticator_tampered():
    secret = b"radiussecret"
    packet = bytearray(_build_acct_request(secret))
    # Flip a byte in the authenticator
    packet[10] ^= 0xFF
    assert _verify_request_authenticator(bytes(packet), secret) is False


def test_verify_request_authenticator_wrong_length():
    secret = b"radiussecret"
    # Build a valid packet then corrupt the length field to be too small
    pkt = bytearray(_build_acct_request(secret))
    # Set length to 10 (invalid; < 20)
    pkt[2:4] = (10).to_bytes(2, "big")
    assert _verify_request_authenticator(bytes(pkt), secret) is False


def test_verify_request_authenticator_non_accounting_code():
    secret = b"radiussecret"
    # Build an Accounting-Request then change Code to Access-Request (1)
    pkt = bytearray(_build_acct_request(secret))
    pkt[0] = 1
    assert _verify_request_authenticator(bytes(pkt), secret) is False
