"""RFC 2865/2866/2869 compliance checks for RADIUS packet structures."""

import hashlib
import os
import socket
import struct
import warnings

from tacacs_server.radius.authenticator import verify_message_authenticator
from tacacs_server.radius.constants import (
    ATTR_MESSAGE_AUTHENTICATOR,
    ATTR_NAS_IP_ADDRESS,
    ATTR_REPLY_MESSAGE,
    ATTR_USER_NAME,
    RADIUS_ACCESS_ACCEPT,
    RADIUS_ACCESS_CHALLENGE,
    RADIUS_ACCESS_REJECT,
    RADIUS_ACCESS_REQUEST,
    RADIUS_ACCOUNTING_REQUEST,
    RADIUS_ACCOUNTING_RESPONSE,
)
from tacacs_server.radius.packet import (
    RADIUSAttribute,
    RADIUSPacket,
)


def _make_auth_request(identifier: int) -> RADIUSPacket:
    return RADIUSPacket(
        code=RADIUS_ACCESS_REQUEST,
        identifier=identifier,
        authenticator=os.urandom(16),
        attributes=[
            RADIUSAttribute(ATTR_USER_NAME, b"alice"),
            RADIUSAttribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("127.0.0.1")),
            RADIUSAttribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16),
        ],
    )


def test_access_request_structure_rfc2865():
    secret = b"secret"
    req = _make_auth_request(1)
    raw = req.pack(secret)
    # Header: Code(1), ID(1), Length(2)
    assert raw[0] == RADIUS_ACCESS_REQUEST
    length = struct.unpack("!H", raw[2:4])[0]
    assert length == len(raw)
    assert verify_message_authenticator(raw, secret)


def test_access_accept_structure_rfc2865():
    secret = b"secret"
    req = _make_auth_request(2)
    req_raw = req.pack(secret)
    accept = RADIUSPacket(
        code=RADIUS_ACCESS_ACCEPT,
        identifier=req.identifier,
        authenticator=req.authenticator,
        attributes=[RADIUSAttribute(ATTR_REPLY_MESSAGE, b"ok")],
    )
    raw = accept.pack(secret, request_auth=req.authenticator)
    assert raw[0] == RADIUS_ACCESS_ACCEPT
    assert raw[1] == req.identifier
    # Response authenticator should differ from request authenticator
    assert raw[4:20] != req_raw[4:20]


def test_access_reject_structure_rfc2865():
    secret = b"secret"
    req = _make_auth_request(3)
    reject = RADIUSPacket(
        code=RADIUS_ACCESS_REJECT,
        identifier=req.identifier,
        authenticator=req.authenticator,
        attributes=[RADIUSAttribute(ATTR_REPLY_MESSAGE, b"no")],
    )
    raw = reject.pack(secret, request_auth=req.authenticator)
    assert raw[0] == RADIUS_ACCESS_REJECT
    assert raw[1] == req.identifier


def test_accounting_request_structure_rfc2866():
    secret = b"secret"
    acct = RADIUSPacket(
        code=RADIUS_ACCOUNTING_REQUEST,
        identifier=5,
        authenticator=os.urandom(16),
        attributes=[
            RADIUSAttribute(ATTR_USER_NAME, b"alice"),
            RADIUSAttribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("127.0.0.1")),
        ],
    )
    raw = acct.pack(secret)
    assert raw[0] == RADIUS_ACCOUNTING_REQUEST
    assert struct.unpack("!H", raw[2:4])[0] == len(raw)


def test_accounting_response_structure_rfc2866():
    secret = b"secret"
    req = RADIUSPacket(
        code=RADIUS_ACCOUNTING_REQUEST,
        identifier=6,
        authenticator=os.urandom(16),
        attributes=[RADIUSAttribute(ATTR_USER_NAME, b"alice")],
    )
    req_raw = req.pack(secret)
    resp = RADIUSPacket(
        code=RADIUS_ACCOUNTING_RESPONSE,
        identifier=req.identifier,
        authenticator=req.authenticator,
        attributes=[],
    )
    raw = resp.pack(secret, request_auth=req.authenticator)
    assert raw[0] == RADIUS_ACCOUNTING_RESPONSE
    assert raw[1] == req.identifier
    assert raw[4:20] != req_raw[4:20]


def test_message_authenticator_support_rfc2869():
    secret = b"secret"
    req = _make_auth_request(7)
    raw = req.pack(secret)
    assert verify_message_authenticator(raw, secret)


def test_packet_length_validation_max_4096():
    secret = b"secret"
    # Build multiple small attributes to stay under per-attribute and packet limits
    attrs = [
        RADIUSAttribute(ATTR_REPLY_MESSAGE, b"x" * 200),
        RADIUSAttribute(ATTR_REPLY_MESSAGE, b"y" * 200),
        RADIUSAttribute(ATTR_REPLY_MESSAGE, b"z" * 200),
    ]
    pkt = RADIUSPacket(
        code=RADIUS_ACCESS_CHALLENGE,
        identifier=9,
        authenticator=os.urandom(16),
        attributes=attrs,
    )
    raw = pkt.pack(secret)
    assert len(raw) <= 4096


def test_identifier_matching_in_responses():
    secret = b"secret"
    req = _make_auth_request(11)
    resp = RADIUSPacket(
        code=RADIUS_ACCESS_ACCEPT,
        identifier=req.identifier,
        authenticator=req.authenticator,
        attributes=[],
    )
    raw = resp.pack(secret, request_auth=req.authenticator)
    assert raw[1] == req.identifier


def test_authenticator_verification_request_and_response():
    secret = b"secret"
    req = _make_auth_request(12)
    req_raw = req.pack(secret)
    # Response authenticator is MD5(Code+ID+Len+ReqAuth+Attrs+Secret)
    resp = RADIUSPacket(
        code=RADIUS_ACCESS_ACCEPT,
        identifier=req.identifier,
        authenticator=req.authenticator,
        attributes=[RADIUSAttribute(ATTR_REPLY_MESSAGE, b"ok")],
    )
    raw_resp = resp.pack(secret, request_auth=req.authenticator)
    code, ident, length = struct.unpack("!BBH", raw_resp[:4])
    attrs = raw_resp[20:]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        expected = hashlib.md5(
            struct.pack("!BBH", code, ident, length)
            + req.authenticator
            + attrs
            + secret,
            usedforsecurity=False,
        ).digest()
    assert raw_resp[4:20] == expected
    assert raw_resp[4:20] != req_raw[4:20]
