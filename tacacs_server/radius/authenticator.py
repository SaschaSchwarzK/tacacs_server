import hashlib
import hmac
import struct
import warnings

from tacacs_server.utils.logger import get_logger

from .constants import (
    ATTR_MESSAGE_AUTHENTICATOR,
    MAX_RADIUS_PACKET_LENGTH,
    RADIUS_ACCESS_REQUEST,
    RADIUS_ACCOUNTING_REQUEST,
)

logger = get_logger("tacacs_server.radius.authenticator", component="radius")


def encrypt_password_value(
    password: bytes, secret: bytes, authenticator: bytes
) -> bytes:
    """Encrypt User-Password per RFC 2865 §5.2 (MD5-based obfuscation)."""
    auth = authenticator
    if len(auth) != 16:
        auth = (auth or b"")[:16].ljust(16, b"\x00")
    pad_len = 16 - (len(password) % 16)
    padded = password + (b"\x00" * pad_len)
    encrypted = b""
    prev = auth
    for i in range(0, len(padded), 16):
        block = padded[i : i + 16]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            digest = hashlib.md5(secret + prev, usedforsecurity=False).digest()
        enc = bytes(a ^ b for a, b in zip(block, digest))
        encrypted += enc
        prev = enc
    return encrypted


def verify_request_authenticator(data: bytes, secret: bytes) -> bool:
    """
    Verify the Request Authenticator for Accounting-Request packets.
    RFC 2866: For Accounting-Request, server MUST verify the Request Authenticator:
    MD5(Code+ID+Length+16*0 + Attributes + Secret)
    """
    if len(data) < 20:
        return False
    try:
        # Parse header
        code, identifier, length = struct.unpack("!BBH", data[:4])
        if length > MAX_RADIUS_PACKET_LENGTH or length < 20 or len(data) < length:
            return False
        # Only applicable to Accounting-Request (RFC 2866)
        if code != RADIUS_ACCOUNTING_REQUEST:
            return False
        # Extract fields
        recv_auth = data[4:20]
        # Build a copy with zeroed authenticator
        zeroed = bytearray(data[:length])
        zeroed[4:20] = b"\x00" * 16
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            calc = hashlib.md5(bytes(zeroed) + secret, usedforsecurity=False).digest()
        # Constant-time comparison
        return hmac.compare_digest(calc, recv_auth)
    except Exception:
        return False


def verify_message_authenticator(data: bytes, secret: bytes) -> bool:
    """
    Verify Message-Authenticator (Attr 80) on Access-Request.
    Steps (RFC 2869 §5.14):
      - Locate the Message-Authenticator attribute.
      - Set its 16-byte value to zero.
      - Compute HMAC-MD5 over the entire packet (Code..end) keyed by the shared secret.
      - Compare to the received value (constant-time).
    If there is no Message-Authenticator attribute, return True (not required unless EAP/CHAP or mandated by policy).
    """
    if len(data) < 20:
        return False
    try:
        code, identifier, length = struct.unpack("!BBH", data[:4])
        if length > MAX_RADIUS_PACKET_LENGTH or length < 20 or len(data) < length:
            return False
        if code != RADIUS_ACCESS_REQUEST:
            return True
        # Walk attributes to find attr 80
        attrs = data[20:length]
        idx = 0
        found = False
        recv_mac = None
        mutable = bytearray(data[:length])
        while idx + 2 <= len(attrs):
            atype = attrs[idx]
            alen = attrs[idx + 1]
            if alen < 2 or idx + alen > len(attrs):
                break
            if atype == ATTR_MESSAGE_AUTHENTICATOR:
                if alen != 18:
                    return False  # Invalid length for Message-Authenticator
                # Position of the 16-byte value within the whole packet
                offset_in_packet = 20 + idx + 2
                recv_mac = bytes(mutable[offset_in_packet : offset_in_packet + 16])
                # Zero the value in the mutable copy
                mutable[offset_in_packet : offset_in_packet + 16] = b"\x00" * 16
                found = True
                # Do not break; standard permits multiple attrs, but we validate the first
                break
            idx += alen
        if not found:
            return True  # No Message-Authenticator present
        # mypy: ensure recv_mac is bytes, not Optional
        if recv_mac is None:
            return False
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            calc = hmac.new(secret, bytes(mutable), digestmod=hashlib.md5).digest()
        return hmac.compare_digest(calc, recv_mac)
    except Exception:
        return False


__all__ = [
    "encrypt_password_value",
    "verify_request_authenticator",
    "verify_message_authenticator",
]
