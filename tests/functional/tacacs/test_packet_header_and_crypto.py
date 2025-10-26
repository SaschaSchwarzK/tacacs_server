import struct

import pytest

from tacacs_server.tacacs.constants import (
    TAC_PLUS_FLAGS,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.tacacs.server import TacacsServer


def _mk_header(
    version_major: int, ptype: int, seq: int, flags: int, session: int, length: int
) -> bytes:
    # major is 4-bit field; mask to keep within 0..15 even for invalid cases
    version = ((version_major & 0x0F) << 4) | 0  # minor 0
    return struct.pack("!BBBBLL", version, ptype, seq, flags, session, length)


def test_unpack_header_too_short():
    with pytest.raises(ValueError):
        TacacsPacket.unpack_header(b"\x00\x01")


def test_header_validation_bad_version():
    server = TacacsServer()
    # Use an invalid major within 4-bit space (e.g., 0x0E when expected 0x0C)
    hdr = _mk_header(0x0E, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, 0x12345678, 0)
    pkt = TacacsPacket.unpack_header(hdr)
    assert server._validate_packet_header(pkt) is False


def test_header_validation_bad_type():
    server = TacacsServer()
    hdr = _mk_header(TAC_PLUS_MAJOR_VER, 0xFF, 1, 0, 0x11111111, 0)
    pkt = TacacsPacket.unpack_header(hdr)
    assert server._validate_packet_header(pkt) is False


def test_header_validation_seq_parity_and_monotonic():
    server = TacacsServer()
    sess = 0xAABBCCDD
    # Even seq should be rejected
    hdr_even = _mk_header(
        TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 2, 0, sess, 0
    )
    pkt_even = TacacsPacket.unpack_header(hdr_even)
    assert server._validate_packet_header(pkt_even) is False
    # Odd seq accepted and tracked
    hdr1 = _mk_header(
        TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, sess, 0
    )
    pkt1 = TacacsPacket.unpack_header(hdr1)
    assert server._validate_packet_header(pkt1) is True
    # Regression (seq<=last) rejected
    hdr1b = _mk_header(
        TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, sess, 0
    )
    pkt1b = TacacsPacket.unpack_header(hdr1b)
    assert server._validate_packet_header(pkt1b) is False
    # Next odd seq ok
    hdr3 = _mk_header(
        TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 3, 0, sess, 0
    )
    pkt3 = TacacsPacket.unpack_header(hdr3)
    assert server._validate_packet_header(pkt3) is True


def test_encrypt_decrypt_paths_identity_for_unencrypted_and_roundtrip_encrypted():
    # UNENCRYPTED flag: body should pass through unchanged
    pkt_unenc = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        session_id=1,
    )
    pkt_unenc.body = b"hello"
    enc = pkt_unenc.encrypt_body("secret")
    assert enc == b"hello"
    dec = pkt_unenc.decrypt_body("secret", enc)
    assert dec == b"hello"

    # Encrypted: encrypt then decrypt roundtrip
    pkt_enc = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        flags=0,
        session_id=0x01020304,
    )
    pkt_enc.body = b"world"
    enc2 = pkt_enc.encrypt_body("secret")
    assert enc2 != b"world"
    dec2 = pkt_enc.decrypt_body("secret", enc2)
    assert dec2 == b"world"
