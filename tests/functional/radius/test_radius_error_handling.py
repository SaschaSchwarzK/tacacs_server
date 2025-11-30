"""Error-handling and RFC conformance checks for RADIUS packet parsing."""

import os
import struct

import pytest

from tacacs_server.radius.server import RADIUSPacket


def _minimal_packet(
    code: int, identifier: int, attrs: bytes = b"", length_override: int | None = None
):
    authenticator = os.urandom(16)
    length = length_override if length_override is not None else 20 + len(attrs)
    header = struct.pack("!BBH", code, identifier, length)
    return header + authenticator + attrs


def test_packet_too_short_raises():
    with pytest.raises(ValueError):
        RADIUSPacket.unpack(b"\x01\x01\x00\x10")


def test_packet_too_large_raises():
    # Declare an excessive length > 4096
    raw = _minimal_packet(1, 1, attrs=b"", length_override=5000)
    with pytest.raises(ValueError):
        RADIUSPacket.unpack(raw)


def test_invalid_packet_code_rejected():
    raw = _minimal_packet(255, 1)
    with pytest.raises(ValueError):
        RADIUSPacket.unpack(raw)


def test_missing_required_attributes_rejected():
    # Access-Request with no attributes should be rejected by RFC 2865
    raw = _minimal_packet(1, 1)
    with pytest.raises(ValueError):
        RADIUSPacket.unpack(raw)


def test_invalid_attribute_length():
    # Attribute length too small (<2)
    attrs = b"\x01\x01"  # type=1, len=1 invalid
    raw = _minimal_packet(1, 1, attrs=attrs)
    with pytest.raises(ValueError):
        RADIUSPacket.unpack(raw)


def test_malformed_attribute_truncated():
    attrs = b"\x01\x05ab"  # declares length 5 but only 2 bytes of value
    raw = _minimal_packet(1, 1, attrs=attrs)
    with pytest.raises(ValueError):
        RADIUSPacket.unpack(raw)
