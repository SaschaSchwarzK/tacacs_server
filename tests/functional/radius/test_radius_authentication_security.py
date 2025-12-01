"""Functional checks for RADIUS authentication security primitives."""

import hashlib
import hmac
import os
import socket
import struct
import warnings

import pytest

from tacacs_server.radius.authenticator import verify_message_authenticator
from tacacs_server.radius.constants import (
    ATTR_MESSAGE_AUTHENTICATOR,
    ATTR_NAS_IDENTIFIER,
    ATTR_NAS_IP_ADDRESS,
    ATTR_USER_NAME,
    ATTR_USER_PASSWORD,
)
from tacacs_server.radius.packet import (
    RADIUSAttribute,
    RADIUSPacket,
)


def _build_access_request(
    secret: bytes, username: bytes, password: bytes, authenticator: bytes
):
    """Construct an Access-Request with Message-Authenticator."""
    pkt = RADIUSPacket(
        code=1,
        identifier=1,
        authenticator=authenticator,
        attributes=[
            RADIUSAttribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16),
            RADIUSAttribute(ATTR_USER_NAME, username),
            RADIUSAttribute(ATTR_USER_PASSWORD, password),
            RADIUSAttribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("127.0.0.1")),
            RADIUSAttribute(ATTR_NAS_IDENTIFIER, b"nas1"),
        ],
    )
    raw = pkt.pack(secret)
    return raw


def test_message_authenticator_validation():
    """Valid Message-Authenticator should verify (RFC 2869 §5.14)."""
    secret = b"sharedsecret"
    raw = _build_access_request(secret, b"alice", b"password", b"\x00" * 16)
    # Verify computed MAC matches expected HMAC-MD5 over the packet with MAC zeroed
    attrs = raw[20:]
    assert attrs[0] == ATTR_MESSAGE_AUTHENTICATOR
    mac = attrs[2:18]
    zeroed = bytearray(raw)
    zeroed[22:38] = b"\x00" * 16
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        expected = hmac.new(secret, bytes(zeroed), digestmod=hashlib.md5).digest()
    assert mac == expected
    assert verify_message_authenticator(raw, secret) is True


def test_invalid_message_authenticator_rejected():
    """Corrupted Message-Authenticator must fail verification."""
    secret = b"sharedsecret"
    raw = _build_access_request(secret, b"alice", b"password", b"\x00" * 16)
    broken = bytearray(raw)
    # Flip a bit inside the Message-Authenticator value
    broken[30] ^= 0xFF
    assert verify_message_authenticator(bytes(broken), secret) is False


def test_invalid_message_authenticator_length_rejected():
    """Malformed Message-Authenticator length should fail verification."""
    secret = b"sharedsecret"
    pkt = RADIUSPacket(
        code=1,
        identifier=2,
        authenticator=b"\x00" * 16,
        attributes=[RADIUSAttribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 8)],
    )
    raw = pkt.pack(secret)
    assert verify_message_authenticator(raw, secret) is False


def test_missing_message_authenticator_returns_true():
    """Access-Request without Message-Authenticator should pass lenient check."""
    secret = b"sharedsecret"
    pkt = RADIUSPacket(
        code=1,
        identifier=3,
        authenticator=os.urandom(16),
        attributes=[RADIUSAttribute(ATTR_USER_NAME, b"alice")],
    )
    raw = pkt.pack(secret)
    assert verify_message_authenticator(raw, secret) is True


def test_request_authenticator_verification():
    """Response authenticators must be computed using request authenticator."""
    secret = b"secret"
    req_auth = os.urandom(16)
    req = RADIUSPacket(
        code=1,
        identifier=7,
        authenticator=req_auth,
        attributes=[RADIUSAttribute(ATTR_USER_NAME, b"bob")],
    )
    raw_req = req.pack(secret)
    resp = RADIUSPacket(
        code=2,
        identifier=7,
        authenticator=req_auth,
        attributes=[RADIUSAttribute(ATTR_USER_NAME, b"bob")],
    )
    raw_resp = resp.pack(secret, request_auth=req_auth)
    # Verify authenticator matches RFC formula: MD5(Code+ID+Len+ReqAuth+Attrs+Secret)
    code, ident, length = struct.unpack("!BBH", raw_resp[:4])
    attrs = raw_resp[20:]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        expected = hashlib.md5(
            struct.pack("!BBH", code, ident, length) + req_auth + attrs + secret,
            usedforsecurity=False,
        ).digest()
    assert raw_resp[4:20] == expected
    assert raw_req[4:20] != raw_resp[4:20]


def test_invalid_request_authenticator_rejected():
    """Changing request authenticator should invalidate MAC computation."""
    secret = b"secret"
    req_auth = os.urandom(16)
    req = RADIUSPacket(
        code=1,
        identifier=3,
        authenticator=req_auth,
        attributes=[RADIUSAttribute(ATTR_USER_NAME, b"bob")],
    )
    req.pack(secret)
    resp = RADIUSPacket(
        code=2,
        identifier=3,
        authenticator=req_auth,
        attributes=[RADIUSAttribute(ATTR_USER_NAME, b"bob")],
    )
    raw_resp = resp.pack(secret, request_auth=req_auth)
    # Tamper with request authenticator used for verification
    bad_req_auth = b"\x00" * 16
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        expected = hashlib.md5(
            raw_resp[:4] + bad_req_auth + raw_resp[20:] + secret,
            usedforsecurity=False,
        ).digest()
    assert raw_resp[4:20] != expected


@pytest.mark.parametrize(
    "password",
    [
        b"short",
        b"exactly16bytes!!",
        b"longerthan16bytespassword",
        b"exactlythirtytwoooooooooobytes!!",
    ],
)
def test_password_encryption_correctness_rfc2865(password: bytes):
    """Ensure User-Password is obfuscated per RFC 2865 §5.2 and decrypts on unpack."""
    secret = b"secret"
    authenticator = b"\xaa" * 16
    req = RADIUSPacket(
        code=1,
        identifier=1,
        authenticator=authenticator,
        attributes=[
            RADIUSAttribute(ATTR_USER_NAME, b"alice"),
            RADIUSAttribute(ATTR_USER_PASSWORD, password),
            RADIUSAttribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("127.0.0.1")),
            RADIUSAttribute(ATTR_NAS_IDENTIFIER, b"nas1"),
        ],
    )
    raw = req.pack(secret)
    # Extract encrypted password block from raw packet
    attrs = raw[20:]
    enc_pw = None
    offset = 0
    while offset + 2 <= len(attrs):
        atype = attrs[offset]
        alen = attrs[offset + 1]
        if alen < 2 or offset + alen > len(attrs):
            break
        if atype == ATTR_USER_PASSWORD:
            enc_pw = attrs[offset + 2 : offset + alen]
            break
        offset += alen
    assert enc_pw is not None
    # Manually compute expected encrypted password
    padded = password + b"\x00" * ((16 - len(password) % 16) % 16 or 16)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        digest = hashlib.md5(secret + authenticator, usedforsecurity=False).digest()
    expected_first_block = bytes(a ^ b for a, b in zip(padded[:16], digest))
    assert enc_pw.startswith(expected_first_block)
    # Unpack with secret to trigger decryption back to plaintext
    decoded = RADIUSPacket.unpack(raw, secret=secret)
    pw_attr = next(a for a in decoded.attributes if a.attr_type == ATTR_USER_PASSWORD)
    assert pw_attr.value == password


def test_known_good_packet_vector_response_authenticity():
    """Use a deterministic vector to ensure response authenticator matches expectation."""
    secret = b"s3cr3t"
    req_auth = bytes(range(16))
    req = RADIUSPacket(
        code=1,
        identifier=9,
        authenticator=req_auth,
        attributes=[RADIUSAttribute(ATTR_USER_NAME, b"carol")],
    )
    req.pack(secret)
    resp = RADIUSPacket(
        code=2,
        identifier=9,
        authenticator=req_auth,
        attributes=[
            RADIUSAttribute(ATTR_USER_NAME, b"carol"),
            RADIUSAttribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16),
        ],
    )
    raw_resp = resp.pack(secret, request_auth=req_auth)
    # Verify message authenticator still passes after packing
    assert verify_message_authenticator(raw_resp, secret) is True
    # Tamper with attributes and ensure authenticator no longer matches
    tampered = bytearray(raw_resp)
    tampered[-1] ^= 0xFF
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        expected = hashlib.md5(
            tampered[:4] + req_auth + tampered[20:-1] + b"\x00" + secret,
            usedforsecurity=False,
        ).digest()
    assert tampered[4:20] != expected
