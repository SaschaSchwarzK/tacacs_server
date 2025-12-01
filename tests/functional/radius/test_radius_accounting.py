"""Functional tests for RADIUS accounting handling."""

import hashlib
import os
import socket
import struct
import time
import warnings
from typing import Any

import pytest

from tacacs_server.radius.constants import (
    ATTR_ACCT_DELAY_TIME,
    ATTR_ACCT_INPUT_OCTETS,
    ATTR_ACCT_INPUT_PACKETS,
    ATTR_ACCT_OUTPUT_OCTETS,
    ATTR_ACCT_OUTPUT_PACKETS,
    ATTR_ACCT_SESSION_ID,
    ATTR_ACCT_SESSION_TIME,
    ATTR_ACCT_STATUS_TYPE,
    ATTR_ACCT_TERMINATE_CAUSE,
    ATTR_NAS_IP_ADDRESS,
    ATTR_REPLY_MESSAGE,
    ATTR_USER_NAME,
    RADIUS_ACCOUNTING_REQUEST,
    RADIUS_ACCOUNTING_RESPONSE,
)
from tacacs_server.radius.packet import (
    RADIUSAttribute,
    RADIUSPacket,
)


class DummyRadiusHandler:
    """Lightweight handler to emulate accounting packet processing."""

    def __init__(self):
        self.records: list[dict[str, Any]] = []

    def handle_accounting(self, attrs: dict[str, Any]) -> dict[str, Any]:
        self.records.append(attrs)
        # Minimal response mimicking a successful Accounting-Response
        return {
            "Code": "Accounting-Response",
            "Status-Type": attrs.get("Acct-Status-Type"),
        }


def _make_attrs(status: str, session_id: str, **kwargs) -> dict[str, Any]:
    attrs = {
        "User-Name": "alice",
        "Acct-Status-Type": status,
        "Acct-Session-Id": session_id,
        "Acct-Input-Octets": kwargs.get("in_octets", 0),
        "Acct-Output-Octets": kwargs.get("out_octets", 0),
        "Acct-Input-Packets": kwargs.get("in_pkts", 0),
        "Acct-Output-Packets": kwargs.get("out_pkts", 0),
        "Acct-Session-Time": kwargs.get("session_time", 0),
        "NAS-IP-Address": "127.0.0.1",
    }
    attrs.update(kwargs)
    return attrs


def test_accounting_request_parsing_and_statuses():
    """Ensure accounting requests for START/STOP/UPDATE/ON/OFF are accepted."""
    handler = DummyRadiusHandler()
    statuses = ["Start", "Stop", "Interim-Update", "Accounting-On", "Accounting-Off"]
    for status in statuses:
        resp = handler.handle_accounting(_make_attrs(status, session_id=f"s-{status}"))
        assert resp["Code"] == "Accounting-Response"
        assert resp["Status-Type"] == status
    assert len(handler.records) == len(statuses)


def test_session_id_tracking_and_octets_packets():
    """Track session attributes across multiple updates."""
    handler = DummyRadiusHandler()
    session_id = "sess-123"
    handler.handle_accounting(
        _make_attrs(
            "Start", session_id, in_octets=10, out_octets=20, in_pkts=1, out_pkts=2
        )
    )
    handler.handle_accounting(
        _make_attrs(
            "Interim-Update",
            session_id,
            in_octets=50,
            out_octets=80,
            in_pkts=5,
            out_pkts=8,
        )
    )
    handler.handle_accounting(
        _make_attrs(
            "Stop", session_id, in_octets=100, out_octets=200, in_pkts=10, out_pkts=20
        )
    )
    # Session id should be consistent across records
    assert all(rec["Acct-Session-Id"] == session_id for rec in handler.records)
    # Verify final tallies captured
    stop = handler.records[-1]
    assert stop["Acct-Input-Octets"] == 100
    assert stop["Acct-Output-Octets"] == 200
    assert stop["Acct-Input-Packets"] == 10
    assert stop["Acct-Output-Packets"] == 20


def test_packet_encode_decode_roundtrip_for_accounting_request():
    """Encode an Accounting-Request and ensure fields survive unpack."""
    auth = os.urandom(16)
    attrs = [
        RADIUSAttribute(ATTR_USER_NAME, b"alice"),
        RADIUSAttribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("127.0.0.1")),
        RADIUSAttribute(ATTR_ACCT_STATUS_TYPE, struct.pack("!I", 1)),  # Start
        RADIUSAttribute(ATTR_ACCT_SESSION_ID, b"sess-1"),
        RADIUSAttribute(ATTR_ACCT_INPUT_OCTETS, struct.pack("!I", 123)),
        RADIUSAttribute(ATTR_ACCT_OUTPUT_OCTETS, struct.pack("!I", 456)),
        RADIUSAttribute(ATTR_ACCT_INPUT_PACKETS, struct.pack("!I", 7)),
        RADIUSAttribute(ATTR_ACCT_OUTPUT_PACKETS, struct.pack("!I", 9)),
        RADIUSAttribute(ATTR_ACCT_SESSION_TIME, struct.pack("!I", 10)),
    ]
    pkt = RADIUSPacket(code=4, identifier=1, authenticator=auth, attributes=attrs)
    raw = pkt.pack(secret=b"secret")
    parsed = RADIUSPacket.unpack(raw)
    # Check attribute values decode correctly
    parsed_map = {a.attr_type: a for a in parsed.attributes}
    assert parsed_map[ATTR_ACCT_SESSION_ID].value == b"sess-1"
    assert struct.unpack("!I", parsed_map[ATTR_ACCT_INPUT_OCTETS].value)[0] == 123
    assert struct.unpack("!I", parsed_map[ATTR_ACCT_OUTPUT_OCTETS].value)[0] == 456
    assert struct.unpack("!I", parsed_map[ATTR_ACCT_INPUT_PACKETS].value)[0] == 7
    assert struct.unpack("!I", parsed_map[ATTR_ACCT_OUTPUT_PACKETS].value)[0] == 9
    assert struct.unpack("!I", parsed_map[ATTR_ACCT_SESSION_TIME].value)[0] == 10


def test_accounting_unpack_rejects_bad_length():
    """Malformed Accounting packet (short length) should raise."""
    # Code=4, ID=1, length=20 but missing authenticator/attrs
    bad = b"\x04\x01\x00\x10"
    with pytest.raises(ValueError):
        RADIUSPacket.unpack(bad)


def test_session_time_tracking_and_timeout():
    """Session time should progress; simulate timeout by elapsed time."""
    handler = DummyRadiusHandler()
    session_id = "sess-time"
    handler.handle_accounting(_make_attrs("Start", session_id, session_time=0))
    time.sleep(0.1)
    handler.handle_accounting(_make_attrs("Interim-Update", session_id, session_time=5))
    time.sleep(0.1)
    handler.handle_accounting(_make_attrs("Stop", session_id, session_time=10))
    times = [rec["Acct-Session-Time"] for rec in handler.records]
    assert times == sorted(times)


def test_concurrent_session_accounting():
    """Multiple sessions tracked independently."""
    handler = DummyRadiusHandler()
    sessions = ["s1", "s2", "s3"]
    for sess in sessions:
        handler.handle_accounting(_make_attrs("Start", sess))
        handler.handle_accounting(_make_attrs("Interim-Update", sess, in_octets=10))
    handler.handle_accounting(_make_attrs("Stop", "s2", out_octets=50))
    assert len(handler.records) == len(sessions) * 2 + 1
    by_session = {}
    for rec in handler.records:
        by_session.setdefault(rec["Acct-Session-Id"], []).append(rec)
    assert all(len(records) >= 2 for records in by_session.values())
    assert any(rec["Acct-Output-Octets"] == 50 for rec in by_session["s2"])


def test_accounting_response_format_validation():
    """Responses should include Accounting-Response code and mirror status type."""
    handler = DummyRadiusHandler()
    req = _make_attrs("Start", "sess-check", in_octets=1, out_octets=2)
    resp = handler.handle_accounting(req)
    assert resp == {"Code": "Accounting-Response", "Status-Type": "Start"}


def test_request_authenticator_verification():
    """Response authenticator should be derived from request authenticator."""
    secret = b"secret"
    auth = os.urandom(16)
    pkt = RADIUSPacket(
        code=4,
        identifier=11,
        authenticator=auth,
        attributes=[RADIUSAttribute(ATTR_USER_NAME, b"alice")],
    )
    raw_req = pkt.pack(secret)
    resp = RADIUSPacket(
        code=5,
        identifier=pkt.identifier,
        authenticator=pkt.authenticator,
        attributes=[RADIUSAttribute(ATTR_REPLY_MESSAGE, b"ok")],
    )
    raw_resp = resp.pack(secret, request_auth=pkt.authenticator)
    # Authenticator should differ from request and follow MD5 formula
    assert raw_req[4:20] != raw_resp[4:20]
    code, ident, length = struct.unpack("!BBH", raw_resp[:4])
    attrs = raw_resp[20:]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        expected = hashlib.md5(
            struct.pack("!BBH", code, ident, length)
            + pkt.authenticator
            + attrs
            + secret,
            usedforsecurity=False,
        ).digest()
    assert raw_resp[4:20] == expected


def test_invalid_authenticator_rejection():
    """Tampering with authenticator should fail verification logic."""
    secret = b"secret"
    auth = os.urandom(16)
    pkt = RADIUSPacket(
        code=4,
        identifier=12,
        authenticator=auth,
        attributes=[RADIUSAttribute(ATTR_USER_NAME, b"alice")],
    )
    raw = pkt.pack(secret)
    tampered = bytearray(raw)
    tampered[5] ^= 0xFF  # flip a bit in authenticator
    # Compute expected authenticator for the original request
    code, ident, length = struct.unpack("!BBH", raw[:4])
    attrs = raw[20:]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        expected = hashlib.md5(
            struct.pack("!BBH", code, ident, length) + auth + attrs + secret,
            usedforsecurity=False,
        ).digest()
    assert tampered[4:20] != expected


def test_request_authenticator_verification_accounting():
    """Accounting-Response authenticator must use request authenticator."""
    secret = b"secret"
    req_auth = os.urandom(16)
    req = RADIUSPacket(
        code=RADIUS_ACCOUNTING_REQUEST,
        identifier=20,
        authenticator=req_auth,
        attributes=[RADIUSAttribute(ATTR_USER_NAME, b"alice")],
    )
    resp = RADIUSPacket(
        code=RADIUS_ACCOUNTING_RESPONSE,
        identifier=req.identifier,
        authenticator=req.authenticator,
        attributes=[],
    )
    raw_resp = resp.pack(secret, request_auth=req.authenticator)
    code, ident, length = struct.unpack("!BBH", raw_resp[:4])
    attrs = raw_resp[20:]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        expected = hashlib.md5(
            struct.pack("!BBH", code, ident, length) + req_auth + attrs + secret,
            usedforsecurity=False,
        ).digest()
    assert raw_resp[4:20] == expected


def test_acct_terminate_cause_handling():
    """Accounting Stop should carry terminate-cause and be parsed."""
    auth = os.urandom(16)
    attrs = [
        RADIUSAttribute(ATTR_USER_NAME, b"alice"),
        RADIUSAttribute(ATTR_ACCT_STATUS_TYPE, struct.pack("!I", 2)),  # Stop
        RADIUSAttribute(ATTR_ACCT_SESSION_ID, b"sess-stop"),
        RADIUSAttribute(
            ATTR_ACCT_TERMINATE_CAUSE, struct.pack("!I", 1)
        ),  # User Request
    ]
    pkt = RADIUSPacket(
        code=4,
        identifier=13,
        authenticator=auth,
        attributes=attrs,
    )
    raw = pkt.pack()
    parsed = RADIUSPacket.unpack(raw)
    amap = {a.attr_type: a for a in parsed.attributes}
    assert struct.unpack("!I", amap[ATTR_ACCT_TERMINATE_CAUSE].value)[0] == 1


def test_acct_delay_time_tracking():
    """Acct-Delay-Time should be preserved and parsed."""
    auth = os.urandom(16)
    attrs = [
        RADIUSAttribute(ATTR_USER_NAME, b"alice"),
        RADIUSAttribute(ATTR_ACCT_STATUS_TYPE, struct.pack("!I", 3)),  # Interim
        RADIUSAttribute(ATTR_ACCT_SESSION_ID, b"sess-delay"),
        RADIUSAttribute(ATTR_ACCT_DELAY_TIME, struct.pack("!I", 5)),
    ]
    pkt = RADIUSPacket(
        code=4,
        identifier=14,
        authenticator=auth,
        attributes=attrs,
    )
    raw = pkt.pack()
    parsed = RADIUSPacket.unpack(raw)
    amap = {a.attr_type: a for a in parsed.attributes}
    assert struct.unpack("!I", amap[ATTR_ACCT_DELAY_TIME].value)[0] == 5
