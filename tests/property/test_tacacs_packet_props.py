from hypothesis import given
from hypothesis import strategies as st

from tacacs_server.tacacs.constants import (
    TAC_PLUS_HEADER_SIZE,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.packet import TacacsPacket


@given(
    version=st.integers(min_value=0, max_value=255),
    packet_type=st.sampled_from(
        [
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
        ]
    ),
    seq_no=st.integers(min_value=1, max_value=255),
    flags=st.integers(min_value=0, max_value=255),
    session_id=st.integers(min_value=0, max_value=0xFFFFFFFF),
    length=st.integers(min_value=0, max_value=4096),
)
def test_pack_unpack_header_roundtrip(
    version, packet_type, seq_no, flags, session_id, length
):
    pkt = TacacsPacket(
        version=version,
        packet_type=packet_type,
        seq_no=seq_no,
        flags=flags,
        session_id=session_id,
        length=length,
    )
    header = pkt.pack_header()
    assert isinstance(header, (bytes, bytearray))
    assert len(header) == TAC_PLUS_HEADER_SIZE
    unpacked = TacacsPacket.unpack_header(header)
    assert unpacked.version == version
    assert unpacked.packet_type == packet_type
    assert unpacked.seq_no == seq_no
    assert unpacked.flags == flags
    assert unpacked.session_id == session_id
    assert unpacked.length == length


@given(length=st.integers(min_value=65536, max_value=2**24))
def test_unpack_header_rejects_oversized_length(length: int):
    # Construct a header with invalid length (too large)
    pkt = TacacsPacket(
        version=0xC0, packet_type=1, seq_no=1, flags=0, session_id=1, length=length
    )
    header = pkt.pack_header()
    import pytest

    with pytest.raises(ValueError):
        TacacsPacket.unpack_header(header)
