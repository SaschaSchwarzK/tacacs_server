import hashlib
import hmac
import struct

from tacacs_server.radius.server import (
    ATTR_MESSAGE_AUTHENTICATOR,
    RADIUS_ACCESS_ACCEPT,
    RADIUS_ACCESS_REQUEST,
    RADIUSPacket,
    _verify_message_authenticator,
)


def _build_access_request_with_ma(
    secret: bytes, attrs: bytes = b"", identifier: int = 1
) -> bytes:
    """Build an Access-Request with a valid Message-Authenticator attribute."""
    # Start with header and authenticator (random/zero is fine for MA calculation)
    req_auth = b"\x11" * 16
    # Insert a zeroed Message-Authenticator attr at the start of attrs
    ma_attr = bytes([ATTR_MESSAGE_AUTHENTICATOR, 18]) + (b"\x00" * 16)
    attrs2 = ma_attr + attrs
    length = 20 + len(attrs2)
    header = struct.pack("!BBH", RADIUS_ACCESS_REQUEST, identifier, length)
    packet_zero = header + req_auth + attrs2
    # Compute HMAC-MD5 over entire packet with zeroed MA
    mac = hmac.new(secret, packet_zero, hashlib.md5).digest()
    # Replace zeroed value with computed MAC
    final_attrs = bytes([ATTR_MESSAGE_AUTHENTICATOR, 18]) + mac + attrs
    final = header + req_auth + final_attrs
    return final


def test_verify_message_authenticator_valid():
    secret = b"radsecret"
    pkt = _build_access_request_with_ma(secret)
    assert _verify_message_authenticator(pkt, secret) is True


def test_verify_message_authenticator_tampered():
    secret = b"radsecret"
    pkt = bytearray(_build_access_request_with_ma(secret))
    # flip a byte of the MAC
    pkt[22] ^= 0xFF
    assert _verify_message_authenticator(bytes(pkt), secret) is False


def test_response_packing_computes_message_authenticator():
    """Ensure RADIUSPacket.pack fills Message-Authenticator when present."""
    secret = b"radsecret"
    # Create response with zeroed Message-Authenticator attr
    resp = RADIUSPacket(
        code=RADIUS_ACCESS_ACCEPT,
        identifier=7,
        authenticator=b"\x00" * 16,
        attributes=[],
    )
    # Add a zeroed MA attribute to the response
    resp.add_attribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16)
    # Build a fake request authenticator
    req_auth = b"\x22" * 16
    # Pack the response; this should compute Response Auth and fill MA
    packet = resp.pack(secret=secret, request_auth=req_auth)
    # Verify: zero the MA value and recompute HMAC-MD5 over full packet; compare
    code, ident, length = struct.unpack("!BBH", packet[:4])
    assert code == RADIUS_ACCESS_ACCEPT
    attrs = packet[20:length]
    # Find MA attr
    idx = 0
    found = False
    mutable = bytearray(packet[:length])
    recv_mac = None
    while idx + 2 <= len(attrs):
        atype = attrs[idx]
        alen = attrs[idx + 1]
        if alen < 2 or idx + alen > len(attrs):
            break
        if atype == ATTR_MESSAGE_AUTHENTICATOR and alen == 18:
            off = 20 + idx + 2
            recv_mac = bytes(mutable[off : off + 16])
            mutable[off : off + 16] = b"\x00" * 16
            found = True
            break
        idx += alen
    assert found and recv_mac is not None
    calc = hmac.new(secret, bytes(mutable), hashlib.md5).digest()
    assert hmac.compare_digest(calc, recv_mac)
