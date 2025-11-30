"""Unit tests for RADIUS packet encoding/decoding and helpers."""

import hashlib
import os
import socket
import struct
import warnings

import pytest

from tacacs_server.radius.server import (
    ATTR_MESSAGE_AUTHENTICATOR,
    ATTR_NAS_IP_ADDRESS,
    ATTR_NAS_PORT,
    ATTR_USER_NAME,
    ATTR_USER_PASSWORD,
    ATTR_VENDOR_SPECIFIC,
    RADIUSAttribute,
    RADIUSPacket,
    _verify_message_authenticator,
)


def _encrypt_password(password: bytes, secret: bytes, authenticator: bytes) -> bytes:
    """RFC 2865 Section 5.2 password obfuscation."""
    padded = password + b"\x00" * ((16 - len(password) % 16) % 16 or 16)
    encrypted = b""
    prev = authenticator
    for i in range(0, len(padded), 16):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            digest = hashlib.md5(secret + prev, usedforsecurity=False).digest()
        block = bytes(a ^ b for a, b in zip(padded[i : i + 16], digest))
        encrypted += block
        prev = block
    return encrypted


def test_packet_creation_and_packing():
    secret = b"sharedsecret"
    attrs = [
        RADIUSAttribute(ATTR_USER_NAME, b"alice"),
        RADIUSAttribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("127.0.0.1")),
    ]
    pkt = RADIUSPacket(
        code=1, identifier=10, authenticator=os.urandom(16), attributes=attrs
    )
    raw = pkt.pack(secret)
    assert raw[0] == 1  # Access-Request
    assert raw[1] == 10
    length = struct.unpack("!H", raw[2:4])[0]
    assert length == len(raw)


def test_attribute_encoding_integer_string_ip():
    """Verify integer, string, and IP attribute packing."""
    int_attr = RADIUSAttribute(ATTR_NAS_PORT, struct.pack("!I", 1234)).pack()
    str_attr = RADIUSAttribute(ATTR_USER_NAME, b"bob").pack()
    ip_attr = RADIUSAttribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("192.0.2.1")).pack()
    assert int_attr[0] == ATTR_NAS_PORT and int_attr[1] == 6
    assert struct.unpack("!I", int_attr[2:6])[0] == 1234
    assert str_attr[0] == ATTR_USER_NAME and str_attr[2:] == b"bob"
    assert ip_attr[0] == ATTR_NAS_IP_ADDRESS and ip_attr[2:] == socket.inet_aton(
        "192.0.2.1"
    )


def test_vendor_specific_attribute_type_26():
    """Vendor-Specific attribute packs vendor ID + payload."""
    vendor_id = 9
    payload = b"\x01\x02"
    attr = RADIUSAttribute(
        ATTR_VENDOR_SPECIFIC, struct.pack("!I", vendor_id) + payload
    ).pack()
    assert attr[0] == ATTR_VENDOR_SPECIFIC
    assert attr[1] == len(attr)
    assert struct.unpack("!I", attr[2:6])[0] == vendor_id
    assert attr[6:] == payload


def test_message_authenticator_calculation_and_verification():
    """Message-Authenticator should validate per RFC 2869."""
    secret = b"secret"
    attrs = [
        RADIUSAttribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16),
        RADIUSAttribute(ATTR_USER_NAME, b"alice"),
        RADIUSAttribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("127.0.0.1")),
    ]
    pkt = RADIUSPacket(
        code=1,
        identifier=1,
        authenticator=b"\x00" * 16,
        attributes=attrs,
    )
    raw = pkt.pack(secret)
    assert _verify_message_authenticator(raw, secret) is True


def test_request_response_authenticator_differs():
    """Request and response authenticators should differ."""
    secret = b"secret"
    req = RADIUSPacket(
        code=1,
        identifier=5,
        authenticator=b"\x01" * 16,
        attributes=[RADIUSAttribute(ATTR_USER_NAME, b"alice")],
    )
    raw_req = req.pack(secret)
    resp = RADIUSPacket(
        code=2,
        identifier=5,
        authenticator=req.authenticator,
        attributes=[RADIUSAttribute(ATTR_USER_NAME, b"alice")],
    )
    raw_resp = resp.pack(secret, request_auth=req.authenticator)
    assert raw_req[4:20] != raw_resp[4:20]


def test_password_decryption_per_rfc2865():
    """User-Password should decrypt to plaintext on unpack."""
    secret = b"secret"
    authenticator = b"\xaa" * 16
    encrypted_pw = _encrypt_password(b"letmein", secret, authenticator)
    attrs = [
        RADIUSAttribute(ATTR_USER_NAME, b"alice").pack(),
        RADIUSAttribute(ATTR_USER_PASSWORD, encrypted_pw).pack(),
        RADIUSAttribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("127.0.0.1")).pack(),
    ]
    length = 20 + sum(len(a) for a in attrs)
    header = struct.pack("!BBH", 1, 3, length)
    raw = header + authenticator + b"".join(attrs)
    pkt = RADIUSPacket.unpack(raw, secret=secret)
    pw_attr = next(a for a in pkt.attributes if a.attr_type == ATTR_USER_PASSWORD)
    assert pw_attr.value == b"letmein"


def test_unpack_error_handling_for_short_packet():
    """Unpack should raise for malformed packets."""
    with pytest.raises(ValueError):
        RADIUSPacket.unpack(b"\x01\x01\x00\x10")
