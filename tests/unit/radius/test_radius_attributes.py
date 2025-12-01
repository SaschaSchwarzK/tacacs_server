"""RFC-aligned checks for RADIUS attribute handling."""

import hashlib
import socket
import struct
import warnings

from tacacs_server.radius.authenticator import verify_message_authenticator
from tacacs_server.radius.constants import (
    ATTR_ACCT_SESSION_ID,
    ATTR_ACCT_STATUS_TYPE,
    ATTR_CLASS,
    ATTR_IDLE_TIMEOUT,
    ATTR_MESSAGE_AUTHENTICATOR,
    ATTR_NAS_IDENTIFIER,
    ATTR_NAS_IP_ADDRESS,
    ATTR_NAS_PORT,
    ATTR_REPLY_MESSAGE,
    ATTR_SERVICE_TYPE,
    ATTR_SESSION_TIMEOUT,
    ATTR_STATE,
    ATTR_USER_NAME,
    ATTR_USER_PASSWORD,
)
from tacacs_server.radius.packet import (
    RADIUSAttribute,
    RADIUSPacket,
)


def _encrypt_password(password: bytes, secret: bytes, authenticator: bytes) -> bytes:
    pad_len = (-len(password)) % 16
    padded = password + (b"\x00" * pad_len)
    enc = b""
    prev = authenticator
    for i in range(0, len(padded), 16):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            digest = hashlib.md5(secret + prev, usedforsecurity=False).digest()
        block = bytes(a ^ b for a, b in zip(padded[i : i + 16], digest))
        enc += block
        prev = block
    return enc


def test_basic_attribute_packing_known_types():
    attrs = [
        RADIUSAttribute(ATTR_USER_NAME, b"alice"),
        RADIUSAttribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("192.0.2.1")),
        RADIUSAttribute(ATTR_NAS_PORT, struct.pack("!I", 49)),
        RADIUSAttribute(ATTR_SERVICE_TYPE, struct.pack("!I", 1)),  # LOGIN
        RADIUSAttribute(ATTR_REPLY_MESSAGE, b"hello"),
        RADIUSAttribute(ATTR_STATE, b"opaque"),
        RADIUSAttribute(ATTR_CLASS, b"classdata"),
        RADIUSAttribute(ATTR_ACCT_STATUS_TYPE, struct.pack("!I", 1)),  # Start
        RADIUSAttribute(ATTR_ACCT_SESSION_ID, b"sess-1"),
        RADIUSAttribute(ATTR_SESSION_TIMEOUT, struct.pack("!I", 300)),
        RADIUSAttribute(ATTR_IDLE_TIMEOUT, struct.pack("!I", 120)),
    ]
    packed = b"".join(a.pack() for a in attrs)
    # Ensure lengths and type codes are correct
    assert packed[0] == ATTR_USER_NAME
    assert packed[packed.find(bytes([ATTR_REPLY_MESSAGE])) + 1] == 2 + len(b"hello")


def test_user_password_encrypt_decrypt_roundtrip():
    secret = b"secret"
    authenticator = b"\xaa" * 16
    password = b"letmein"
    pkt = RADIUSPacket(
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
    raw = pkt.pack(secret)
    decoded = RADIUSPacket.unpack(raw, secret=secret)
    pw_attr = next(a for a in decoded.attributes if a.attr_type == ATTR_USER_PASSWORD)
    assert pw_attr.value == password


def test_message_authenticator_encoding_and_validation():
    secret = b"shared"
    pkt = RADIUSPacket(
        code=1,
        identifier=2,
        authenticator=b"\x00" * 16,
        attributes=[
            RADIUSAttribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16),
            RADIUSAttribute(ATTR_USER_NAME, b"bob"),
        ],
    )
    raw = pkt.pack(secret)
    assert verify_message_authenticator(raw, secret) is True
    # Corrupt MAC to ensure failure
    tampered = bytearray(raw)
    tampered[30] ^= 0x01
    assert verify_message_authenticator(bytes(tampered), secret) is False


def test_multiple_attributes_same_type_preserved():
    attrs = [
        RADIUSAttribute(ATTR_REPLY_MESSAGE, b"msg1"),
        RADIUSAttribute(ATTR_REPLY_MESSAGE, b"msg2"),
    ]
    pkt = RADIUSPacket(
        code=2, identifier=1, authenticator=b"\x00" * 16, attributes=attrs
    )
    raw = pkt.pack()
    parsed = RADIUSPacket.unpack(raw)
    replies = [a.value for a in parsed.attributes if a.attr_type == ATTR_REPLY_MESSAGE]
    assert replies == [b"msg1", b"msg2"]


def test_unknown_attribute_handling_graceful():
    # Type 250 is unknown; ensure packing/unpacking doesn’t explode
    unknown = RADIUSAttribute(250, b"\x01\x02")
    pkt = RADIUSPacket(
        code=2,
        identifier=5,
        authenticator=b"\x00" * 16,
        attributes=[unknown],
    )
    raw = pkt.pack()
    parsed = RADIUSPacket.unpack(raw)
    restored = next(a for a in parsed.attributes if a.attr_type == 250)
    assert restored.value == b"\x01\x02"


def test_accounting_status_and_session_fields_roundtrip():
    attrs = [
        RADIUSAttribute(ATTR_ACCT_STATUS_TYPE, struct.pack("!I", 2)),  # Stop
        RADIUSAttribute(ATTR_ACCT_SESSION_ID, b"sess-stop"),
    ]
    pkt = RADIUSPacket(
        code=4, identifier=7, authenticator=b"\x00" * 16, attributes=attrs
    )
    raw = pkt.pack()
    parsed = RADIUSPacket.unpack(raw)
    amap = {a.attr_type: a for a in parsed.attributes}
    assert struct.unpack("!I", amap[ATTR_ACCT_STATUS_TYPE].value)[0] == 2
    assert amap[ATTR_ACCT_SESSION_ID].value == b"sess-stop"
