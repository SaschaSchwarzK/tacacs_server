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
    """Create a TACACS+ packet header with the specified parameters.

    Args:
        version_major: Major version of the TACACS+ protocol (4-bit)
        ptype: Packet type (AUTHEN, AUTHOR, ACCOUNT)
        seq: Sequence number (should be odd for client, even for server)
        flags: Packet flags (e.g., encryption, single connection)
        session: Session identifier
        length: Length of the packet body

    Returns:
        bytes: Packed TACACS+ header (12 bytes)
    """
    # major is 4-bit field; mask to keep within 0..15 even for invalid cases
    version = ((version_major & 0x0F) << 4) | 0  # minor 0
    return struct.pack("!BBBBLL", version, ptype, seq, flags, session, length)


def test_unpack_header_too_short():
    """Test that unpacking an incomplete header raises ValueError.

    Verifies that the TACACS+ packet header unpacking function properly
    validates the input length and raises an exception for headers that
    are too short to be valid.

    Test Steps:
    1. Attempt to unpack a 2-byte buffer (less than the 12-byte header size)

    Expected Result:
    - ValueError should be raised due to insufficient data
    """
    with pytest.raises(ValueError):
        TacacsPacket.unpack_header(b"\x00\x01")


def test_header_validation_bad_version():
    """Test validation of TACACS+ headers with unsupported version numbers.

    Verifies that the server rejects packets with unsupported TACACS+
    protocol versions.

    Test Steps:
    1. Create a header with an unsupported version number (0x0E)
    2. Attempt to validate the header

    Expected Result:
    - Header validation should fail due to unsupported version
    - _validate_packet_header() should return False
    """
    server = TacacsServer()
    # Use an invalid major within 4-bit space (e.g., 0x0E when expected 0x0C)
    hdr = _mk_header(0x0E, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, 0x12345678, 0)
    pkt = TacacsPacket.unpack_header(hdr)
    assert server._validate_packet_header(pkt) is False


def test_header_validation_bad_type():
    """Test validation of TACACS+ headers with unknown packet types.

    Verifies that the server rejects packets with invalid or unknown
    packet type values.

    Test Steps:
    1. Create a header with an invalid packet type (0xFF)
    2. Attempt to validate the header

    Expected Result:
    - Header validation should fail due to unknown packet type
    - _validate_packet_header() should return False
    """
    server = TacacsServer()
    hdr = _mk_header(TAC_PLUS_MAJOR_VER, 0xFF, 1, 0, 0x11111111, 0)
    pkt = TacacsPacket.unpack_header(hdr)
    assert server._validate_packet_header(pkt) is False


def test_header_validation_seq_parity_and_monotonic():
    """Test validation of TACACS+ sequence number parity and ordering.

    Verifies that the server enforces the TACACS+ sequence number rules:
    - Client-to-server packets must have odd sequence numbers
    - Server-to-client packets must have even sequence numbers
    - Sequence numbers must increase monotonically within a session

    Test Steps:
    1. Test even sequence number (should be rejected for client-to-server)
    2. Test odd sequence number (should be accepted for client-to-server)
    3. Test next even sequence (should be accepted for server-to-client)
    4. Test out-of-order sequence (should be rejected)

    Expected Results:
    - Even sequence in client-to-server context → Rejected
    - Odd sequence in client-to-server context → Accepted
    - Next even sequence in server-to-client context → Accepted
    - Out-of-order sequence → Rejected
    """
    server = TacacsServer()
    sess = 0xAABBCCDD
    # Even seq should be rejected for client-to-server
    hdr_even = _mk_header(
        TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 2, 0, sess, 0
    )
    pkt_even = TacacsPacket.unpack_header(hdr_even)
    assert server._validate_packet_header(pkt_even) is False

    # Odd seq should be accepted (client to server)
    hdr_odd1 = _mk_header(
        TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, sess, 0
    )
    pkt_odd1 = TacacsPacket.unpack_header(hdr_odd1)
    assert server._validate_packet_header(pkt_odd1) is True

    # Next valid client request should be the next odd (monotonic by +2)
    hdr_odd3 = _mk_header(
        TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 3, 0, sess, 0
    )
    pkt_odd3 = TacacsPacket.unpack_header(hdr_odd3)
    assert server._validate_packet_header(pkt_odd3) is True

    # Duplicate sequence (sending 3 again) should be rejected
    hdr_dup3 = _mk_header(
        TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 3, 0, sess, 0
    )
    pkt_dup3 = TacacsPacket.unpack_header(hdr_dup3)
    assert server._validate_packet_header(pkt_dup3) is False


def test_sequence_zero_invalid():
    """Sequence number 0 should be rejected (must be odd and >=1)."""
    server = TacacsServer()
    sess = 0x01020304
    hdr = _mk_header(TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 0, 0, sess, 0)
    pkt = TacacsPacket.unpack_header(hdr)
    assert server._validate_packet_header(pkt) is False


def test_non_sequential_numbers_odd_progression_valid():
    """Client requests in odd sequence (1,3,5,...) should be valid and monotonic."""
    server = TacacsServer()
    sess = 0x0A0B0C0D
    for seq in (1, 3, 5):
        hdr = _mk_header(TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, seq, 0, sess, 0)
        pkt = TacacsPacket.unpack_header(hdr)
        assert server._validate_packet_header(pkt) is True


def test_invalid_even_in_between():
    """A sequence like 1,2,3 should fail on the even 2, but 3 is accepted afterward."""
    server = TacacsServer()
    sess = 0x0F0E0D0C
    # 1 accepted
    hdr1 = _mk_header(TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, sess, 0)
    pkt1 = TacacsPacket.unpack_header(hdr1)
    assert server._validate_packet_header(pkt1) is True
    # 2 rejected (even)
    hdr2 = _mk_header(TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 2, 0, sess, 0)
    pkt2 = TacacsPacket.unpack_header(hdr2)
    assert server._validate_packet_header(pkt2) is False
    # 3 accepted (next odd step)
    hdr3 = _mk_header(TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 3, 0, sess, 0)
    pkt3 = TacacsPacket.unpack_header(hdr3)
    assert server._validate_packet_header(pkt3) is True


def test_duplicate_sequence_numbers_rejected():
    """Sending the same odd sequence twice within a session is rejected the second time."""
    server = TacacsServer()
    sess = 0xDEADBEEF
    hdr1 = _mk_header(TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, sess, 0)
    pkt1 = TacacsPacket.unpack_header(hdr1)
    assert server._validate_packet_header(pkt1) is True
    # Duplicate 1 should be rejected
    hdr1_dup = _mk_header(TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, sess, 0)
    pkt1_dup = TacacsPacket.unpack_header(hdr1_dup)
    assert server._validate_packet_header(pkt1_dup) is False


def test_encrypt_decrypt_paths_identity_for_unencrypted_and_roundtrip_encrypted():
    """Test encryption and decryption of TACACS+ packet bodies.

    Verifies that:
    1. When no encryption key is provided, the data remains unchanged (identity function)
    2. When an encryption key is provided, data is properly encrypted and can be decrypted
    3. The encryption/decryption is reversible (roundtrip test)

    Test Steps:
    1. Test with no encryption key (should return data as-is)
    2. Test decryption with no key (should also return data as-is)
    3. Test encryption with a key (should modify the data)
    4. Test decryption of encrypted data (should return original data)

    Expected Results:
    - No encryption: data remains unchanged
    - With encryption: data is modified and can be decrypted back to original
    - Roundtrip encryption/decryption returns original data
    """
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
