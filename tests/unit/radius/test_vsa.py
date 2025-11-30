"""Unit tests for RADIUS VSA implementation."""

import struct

import pytest

from tacacs_server.radius.constants import (
    CISCO_AVPAIR,
    RADIUS_ACCESS_ACCEPT,
    VENDOR_CISCO,
)
from tacacs_server.radius.server import RADIUSPacket, VendorSpecificAttribute


class TestVendorSpecificAttribute:
    def test_pack_cisco_avpair(self):
        """Test packing Cisco-AVPair VSA."""
        avpair = "shell:priv-lvl=15"
        vsa = VendorSpecificAttribute(
            vendor_id=VENDOR_CISCO,
            vendor_type=CISCO_AVPAIR,
            vendor_data=avpair.encode("utf-8"),
        )

        packed = vsa.pack()

        # Verify structure: Vendor-Id(4) + Type(1) + Length(1) + Data
        assert len(packed) == 4 + 1 + 1 + len(avpair)
        vendor_id = struct.unpack("!L", packed[:4])[0]
        assert vendor_id == VENDOR_CISCO
        assert packed[4] == CISCO_AVPAIR
        assert packed[6:] == avpair.encode("utf-8")

    def test_unpack_cisco_avpair(self):
        """Test unpacking Cisco-AVPair VSA."""
        avpair = "shell:priv-lvl=15"
        data_bytes = avpair.encode("utf-8")

        # Build raw VSA: Vendor-Id(4) + Type(1) + Length(1) + Data
        vendor_length = len(data_bytes) + 2
        raw_data = (
            struct.pack("!LBB", VENDOR_CISCO, CISCO_AVPAIR, vendor_length) + data_bytes
        )

        vsa, consumed = VendorSpecificAttribute.unpack(raw_data)

        assert vsa.vendor_id == VENDOR_CISCO
        assert vsa.vendor_type == CISCO_AVPAIR
        assert vsa.as_string() == avpair
        assert consumed == len(raw_data)

    def test_unpack_short_data_raises(self):
        """Test that unpacking incomplete VSA raises ValueError."""
        incomplete_data = struct.pack(
            "!LB", VENDOR_CISCO, CISCO_AVPAIR
        )  # Missing length

        with pytest.raises(ValueError, match="VSA data too short"):
            VendorSpecificAttribute.unpack(incomplete_data)

    def test_pack_exceeds_max_length_raises(self):
        """Test that packing VSA >255 bytes raises ValueError."""
        huge_data = b"X" * 250  # Will exceed 255 with headers
        vsa = VendorSpecificAttribute(VENDOR_CISCO, CISCO_AVPAIR, huge_data)

        with pytest.raises(ValueError, match="VSA attribute too long"):
            vsa.pack()


class TestRADIUSPacketVSA:
    def test_add_cisco_avpair(self):
        """Test adding Cisco-AVPair to RADIUS packet."""
        packet = RADIUSPacket(
            code=RADIUS_ACCESS_ACCEPT,
            identifier=42,
            authenticator=b"\x00" * 16,
        )

        packet.add_cisco_avpair("shell:priv-lvl=15")

        avpairs = packet.get_cisco_avpairs()
        assert len(avpairs) == 1
        assert avpairs[0] == "shell:priv-lvl=15"

    def test_get_cisco_avpairs(self):
        """Test extracting Cisco-AVPairs from packet."""
        packet = RADIUSPacket(
            code=RADIUS_ACCESS_ACCEPT,
            identifier=42,
            authenticator=b"\x00" * 16,
        )

        packet.add_cisco_avpair("shell:priv-lvl=15")
        packet.add_cisco_avpair("shell:roles=network-admin")

        avpairs = packet.get_cisco_avpairs()
        assert avpairs == ["shell:priv-lvl=15", "shell:roles=network-admin"]

    def test_pack_and_unpack_with_vsa(self):
        """Test round-trip pack/unpack with VSA."""
        secret = b"testing123"
        original = RADIUSPacket(
            code=RADIUS_ACCESS_ACCEPT,
            identifier=99,
            authenticator=b"\x00" * 16,
        )
        original.add_cisco_avpair("shell:priv-lvl=15")

        packed = original.pack(secret, b"\x11" * 16)
        unpacked = RADIUSPacket.unpack(packed, secret)

        assert unpacked.get_cisco_avpairs() == ["shell:priv-lvl=15"]
