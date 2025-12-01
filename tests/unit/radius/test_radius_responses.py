"""Tests for RADIUS response packet construction and attributes."""

import hashlib
import os
import socket
import struct
import warnings

from tacacs_server.radius.authenticator import verify_message_authenticator
from tacacs_server.radius.constants import (
    ATTR_CLASS,
    ATTR_IDLE_TIMEOUT,
    ATTR_MESSAGE_AUTHENTICATOR,
    ATTR_NAS_IP_ADDRESS,
    ATTR_REPLY_MESSAGE,
    ATTR_SERVICE_TYPE,
    ATTR_SESSION_TIMEOUT,
    ATTR_USER_NAME,
    RADIUS_ACCESS_ACCEPT,
    RADIUS_ACCESS_CHALLENGE,
    RADIUS_ACCESS_REJECT,
    RADIUS_ACCESS_REQUEST,
    RADIUS_ACCOUNTING_RESPONSE,
)
from tacacs_server.radius.packet import RADIUSAttribute, RADIUSPacket


def _build_access_request(identifier: int):
    return RADIUSPacket(
        code=RADIUS_ACCESS_REQUEST,
        identifier=identifier,
        authenticator=os.urandom(16),
        attributes=[
            RADIUSAttribute(ATTR_USER_NAME, b"user"),
            RADIUSAttribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16),
            RADIUSAttribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("127.0.0.1")),
        ],
    )


def test_access_accept_structure_and_attributes():
    secret = b"secret"
    req = _build_access_request(1)
    req_auth = req.authenticator
    accept = RADIUSPacket(
        code=RADIUS_ACCESS_ACCEPT,
        identifier=req.identifier,
        authenticator=req_auth,
        attributes=[
            RADIUSAttribute(ATTR_REPLY_MESSAGE, b"ok"),
            RADIUSAttribute(
                ATTR_SERVICE_TYPE, struct.pack("!I", 6)
            ),  # NAS-Prompt/ADMIN
            RADIUSAttribute(ATTR_SESSION_TIMEOUT, struct.pack("!I", 300)),
            RADIUSAttribute(ATTR_IDLE_TIMEOUT, struct.pack("!I", 120)),
            RADIUSAttribute(ATTR_CLASS, b"priv15"),
            RADIUSAttribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16),
        ],
    )
    raw = accept.pack(secret, request_auth=req_auth)
    assert raw[0] == RADIUS_ACCESS_ACCEPT
    assert raw[1] == req.identifier
    parsed = RADIUSPacket.unpack(raw)
    attrs = {a.attr_type: a for a in parsed.attributes}
    assert struct.unpack("!I", attrs[ATTR_SERVICE_TYPE].value)[0] == 6
    assert struct.unpack("!I", attrs[ATTR_SESSION_TIMEOUT].value)[0] == 300
    assert struct.unpack("!I", attrs[ATTR_IDLE_TIMEOUT].value)[0] == 120
    assert attrs[ATTR_CLASS].value == b"priv15"
    assert verify_message_authenticator(raw, secret)


def test_access_reject_structure_and_reply_message():
    secret = b"secret"
    req = _build_access_request(2)
    reject = RADIUSPacket(
        code=RADIUS_ACCESS_REJECT,
        identifier=req.identifier,
        authenticator=req.authenticator,
        attributes=[RADIUSAttribute(ATTR_REPLY_MESSAGE, b"denied")],
    )
    raw = reject.pack(secret, request_auth=req.authenticator)
    assert raw[0] == RADIUS_ACCESS_REJECT
    assert raw[1] == req.identifier
    parsed = RADIUSPacket.unpack(raw)
    rm = next(a for a in parsed.attributes if a.attr_type == ATTR_REPLY_MESSAGE)
    assert rm.value == b"denied"


def test_access_challenge_structure():
    secret = b"secret"
    req = _build_access_request(3)
    challenge = RADIUSPacket(
        code=RADIUS_ACCESS_CHALLENGE,
        identifier=req.identifier,
        authenticator=req.authenticator,
        attributes=[RADIUSAttribute(ATTR_REPLY_MESSAGE, b"challenge")],
    )
    raw = challenge.pack(secret, request_auth=req.authenticator)
    assert raw[0] == RADIUS_ACCESS_CHALLENGE
    assert raw[1] == req.identifier


def test_accounting_response_structure():
    secret = b"secret"
    req_auth = os.urandom(16)
    resp = RADIUSPacket(
        code=RADIUS_ACCOUNTING_RESPONSE,
        identifier=9,
        authenticator=req_auth,
        attributes=[RADIUSAttribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16)],
    )
    raw = resp.pack(secret, request_auth=req_auth)
    assert raw[0] == RADIUS_ACCOUNTING_RESPONSE
    assert verify_message_authenticator(raw, secret)


def test_response_authenticator_calculation():
    secret = b"secret"
    req = _build_access_request(10)
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


def test_privilege_level_in_class_attribute():
    secret = b"secret"
    req = _build_access_request(12)
    resp = RADIUSPacket(
        code=RADIUS_ACCESS_ACCEPT,
        identifier=req.identifier,
        authenticator=req.authenticator,
        attributes=[
            RADIUSAttribute(ATTR_CLASS, b"priv7"),
            RADIUSAttribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16),
        ],
    )
    raw = resp.pack(secret, request_auth=req.authenticator)
    parsed = RADIUSPacket.unpack(raw)
    cls_attr = next(a for a in parsed.attributes if a.attr_type == ATTR_CLASS)
    assert cls_attr.value == b"priv7"
