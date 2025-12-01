import hashlib
import hmac
import struct
import warnings
from dataclasses import dataclass

from tacacs_server.utils.logger import get_logger

from .authenticator import encrypt_password_value
from .constants import (
    ATTR_MESSAGE_AUTHENTICATOR,
    ATTR_NAS_IDENTIFIER,
    ATTR_NAS_IP_ADDRESS,
    ATTR_USER_NAME,
    ATTR_USER_PASSWORD,
    ATTR_VENDOR_SPECIFIC,
    CISCO_AVPAIR,
    MAX_RADIUS_PACKET_LENGTH,
    RADIUS_ACCESS_ACCEPT,
    RADIUS_ACCESS_CHALLENGE,
    RADIUS_ACCESS_REJECT,
    RADIUS_ACCESS_REQUEST,
    RADIUS_ACCOUNTING_REQUEST,
    RADIUS_ACCOUNTING_RESPONSE,
    VENDOR_ARISTA,
    VENDOR_CISCO,
    VENDOR_FORTINET,
    VENDOR_JUNIPER,
    VENDOR_MICROSOFT,
    VENDOR_PALO_ALTO,
    VENDOR_PFSENSE,
)

logger = get_logger("tacacs_server.radius.packet", component="radius")


@dataclass
class RADIUSAttribute:
    """RADIUS attribute"""

    attr_type: int
    value: bytes

    def pack(self) -> bytes:
        """Pack attribute into bytes"""
        length = len(self.value) + 2
        if length > 255:
            raise ValueError(f"Attribute too long: {length} bytes")
        return struct.pack("BB", self.attr_type, length) + self.value

    @classmethod
    def unpack(cls, data: bytes) -> tuple["RADIUSAttribute", int]:
        """Unpack attribute from bytes"""
        if len(data) < 2:
            raise ValueError("Incomplete attribute header")

        attr_type, length = struct.unpack("BB", data[:2])
        if length < 2 or length > len(data):
            raise ValueError(f"Invalid attribute length: {length}")

        value = data[2:length]
        return cls(attr_type, value), length

    def as_string(self) -> str:
        """Get value as string"""
        return self.value.decode("utf-8", errors="replace")

    def as_int(self) -> int:
        """Get value as integer"""
        if len(self.value) == 4:
            return int(struct.unpack("!I", self.value)[0])
        raise ValueError("Attribute is not an integer")

    def as_ipaddr(self) -> str:
        """Get value as IP address"""
        if len(self.value) == 4:
            return ".".join(str(b) for b in self.value)
        raise ValueError("Attribute is not an IP address")


@dataclass
class VendorSpecificAttribute:
    """RADIUS Vendor-Specific Attribute (Type 26, RFC 2865 §5.26)

    Format: Type(1) Length(1) Vendor-Id(4) Vendor-Type(1) Vendor-Length(1) Vendor-Data(...)
    """

    vendor_id: int
    vendor_type: int
    vendor_data: bytes

    def pack(self) -> bytes:
        """Pack VSA into its value representation (no outer Type/Length).

        Returns:
            Vendor-Id(4) + Vendor-Type(1) + Vendor-Length(1) + Vendor-Data(...)
        """
        vendor_length = len(self.vendor_data) + 2  # Vendor-Type + Vendor-Length + Data
        total_length = (
            4 + vendor_length
        )  # Vendor-Id + Vendor-Type + Vendor-Length + Data

        # Including outer Type/Length would be 2 + total_length; ensure bounded
        if 2 + total_length > 255:
            raise ValueError(
                f"VSA attribute too long: {2 + total_length} bytes (max 255)"
            )

        return (
            struct.pack("!LBB", self.vendor_id, self.vendor_type, vendor_length)
            + self.vendor_data
        )

    @classmethod
    def unpack(cls, data: bytes) -> tuple["VendorSpecificAttribute", int]:
        """Unpack VSA from wire format.

        Args:
            data: Raw attribute data starting after Type(26) and Length bytes

        Returns:
            Tuple of (VendorSpecificAttribute, bytes_consumed)

        Raises:
            ValueError: If data is malformed or incomplete
        """
        if len(data) < 6:  # Vendor-Id(4) + Vendor-Type(1) + Vendor-Length(1)
            raise ValueError(f"VSA data too short: {len(data)} bytes, need at least 6")

        vendor_id, vendor_type, vendor_length = struct.unpack("!LBB", data[:6])

        if vendor_length < 2:
            raise ValueError(f"Invalid vendor-length: {vendor_length} (min 2)")

        # Vendor-Length includes Type(1) + Length(1) + Data
        vendor_data_len = vendor_length - 2
        total_consumed = 6 + vendor_data_len

        if len(data) < total_consumed:
            raise ValueError(
                f"Incomplete VSA: need {total_consumed} bytes, got {len(data)}"
            )

        vendor_data = data[6:total_consumed]
        return cls(vendor_id, vendor_type, vendor_data), total_consumed

    def as_string(self) -> str:
        """Get vendor data as UTF-8 string."""
        return self.vendor_data.decode("utf-8", errors="replace")

    def __str__(self) -> str:
        vendor_names = {
            VENDOR_CISCO: "Cisco",
            VENDOR_JUNIPER: "Juniper",
            VENDOR_MICROSOFT: "Microsoft",
            VENDOR_ARISTA: "Arista",
            VENDOR_PALO_ALTO: "PaloAlto",
        }
        vendor_name = vendor_names.get(self.vendor_id, f"Vendor-{self.vendor_id}")
        return (
            f"VSA({vendor_name}, type={self.vendor_type}, len={len(self.vendor_data)})"
        )


class RADIUSPacket:
    """RADIUS packet structure"""

    def __init__(
        self,
        code: int,
        identifier: int,
        authenticator: bytes,
        attributes: list[RADIUSAttribute] | None = None,
    ):
        self.code = code
        self.identifier = identifier
        self.authenticator = authenticator  # 16 bytes
        self.attributes = attributes or []
        self.vsa_attributes: list[VendorSpecificAttribute] = []
        self._init_vsas_from_attributes()

    def _init_vsas_from_attributes(self) -> None:
        """Populate vsa_attributes from any existing vendor-specific attributes."""
        for attr in list(self.attributes):
            if attr.attr_type != ATTR_VENDOR_SPECIFIC:
                continue
            try:
                vsa, consumed = VendorSpecificAttribute.unpack(attr.value)
                if consumed != len(attr.value):
                    raise ValueError("VSA length mismatch")
                self.vsa_attributes.append(vsa)
            except (ValueError, struct.error) as exc:
                logger.debug(
                    "Failed to decode VSA attribute",
                    event="radius.vsa.decode_failed",
                    error=str(exc),
                )

    def pack(
        self, secret: bytes | None = None, request_auth: bytes | None = None
    ) -> bytes:
        """Pack RADIUS packet into bytes with proper authenticator calculation.

        Args:
            secret: Shared secret for response authenticator calculation
            request_auth: Request authenticator for response packets

        Returns:
            Complete RADIUS packet as bytes

        Note: MD5 is used for authenticator calculation as mandated by RADIUS RFC 2865.
        """
        # Pack attributes (with a temporary zeroed Message-Authenticator if present)
        raw_attrs: list[bytes] = []
        msg_auth_idx = None  # index in raw_attrs where Message-Authenticator sits
        for attr in self.attributes or []:
            if attr.attr_type == ATTR_MESSAGE_AUTHENTICATOR and len(attr.value) == 16:
                # Temporarily zero this attribute for authenticator calculations
                raw = RADIUSAttribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16).pack()
                msg_auth_idx = len(raw_attrs)
                raw_attrs.append(raw)
            elif (
                attr.attr_type == ATTR_USER_PASSWORD
                and secret
                and self.code == RADIUS_ACCESS_REQUEST
            ):
                # Obfuscate password per RFC 2865 §5.2 using request authenticator
                auth_seed = request_auth or self.authenticator
                encrypted = encrypt_password_value(
                    attr.value, secret, auth_seed or b"\x00" * 16
                )
                raw_attrs.append(RADIUSAttribute(ATTR_USER_PASSWORD, encrypted).pack())
            else:
                raw_attrs.append(attr.pack())
        attrs_data = b"".join(raw_attrs)

        # Calculate length and header
        length = 20 + len(attrs_data)
        header = struct.pack("!BBH", self.code, self.identifier, length)

        # Determine authenticator
        if secret and request_auth and self.code != RADIUS_ACCESS_REQUEST:
            # Response Authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                authenticator = hashlib.md5(
                    header + request_auth + attrs_data + secret, usedforsecurity=False
                ).digest()
        else:
            authenticator = self.authenticator

        # Build packet with current authenticator
        packet = header + authenticator + attrs_data

        # If we have a Message-Authenticator attribute, compute its HMAC-MD5 and inject it
        if msg_auth_idx is not None and secret:
            # Rebuild attrs_data with the real HMAC
            for i in range(len(self.attributes or [])):
                if i == msg_auth_idx:
                    # Compute HMAC-MD5 over the full packet with the 16 bytes zeroed
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", DeprecationWarning)
                        mac = hmac.new(secret, packet, digestmod=hashlib.md5).digest()
                    # Replace zeros with the computed MAC
                    # raw_attrs[i] is: type(1) + len(1) + value(16)
                    raw_attrs[i] = bytes([ATTR_MESSAGE_AUTHENTICATOR, 18]) + mac
                    break
            # Repack with real msg-authenticator
            attrs_data = b"".join(raw_attrs)
            length = 20 + len(attrs_data)
            header = struct.pack("!BBH", self.code, self.identifier, length)
            packet = header + authenticator + attrs_data

        return packet

    @classmethod
    def unpack(cls, data: bytes, secret: bytes | None = None) -> "RADIUSPacket":
        """Unpack RADIUS packet from bytes"""
        if len(data) < 20:
            raise ValueError(f"Packet too short: {len(data)} bytes")

        # Parse header
        code, identifier, length = struct.unpack("!BBH", data[:4])

        # Validate packet length to prevent buffer overflow
        if length > MAX_RADIUS_PACKET_LENGTH:  # RFC 2865 maximum packet size
            raise ValueError(f"Packet too large: {length} bytes")

        if len(data) < length:
            raise ValueError(f"Incomplete packet: got {len(data)}, expected {length}")

        if code not in {
            RADIUS_ACCESS_REQUEST,
            RADIUS_ACCESS_ACCEPT,
            RADIUS_ACCESS_REJECT,
            RADIUS_ACCOUNTING_REQUEST,
            RADIUS_ACCOUNTING_RESPONSE,
            RADIUS_ACCESS_CHALLENGE,
        }:
            raise ValueError(f"Invalid RADIUS code: {code}")

        authenticator = data[4:20]

        # Parse attributes (strict length validation)
        attributes = []
        vsa_attributes = []
        offset = 20
        while offset < length:
            try:
                # Peek at attribute type
                if len(data) < offset + 2:
                    raise ValueError("Incomplete attribute header")

                attr_type = data[offset]
                attr_length = data[offset + 1]

                if attr_type == ATTR_VENDOR_SPECIFIC:
                    if attr_length < 8 or offset + attr_length > length:
                        raise ValueError("Invalid VSA attribute length")
                    vsa_data = data[offset + 2 : offset + attr_length]
                    try:
                        vsa, consumed_inner = VendorSpecificAttribute.unpack(vsa_data)
                    except Exception as exc:
                        raise ValueError(f"Invalid VSA: {exc}") from exc
                    if consumed_inner != len(vsa_data):
                        raise ValueError("VSA length mismatch")
                    vsa_attributes.append(vsa)
                    # Also store raw attribute for compatibility
                    attr = RADIUSAttribute(attr_type, vsa_data)
                    attributes.append(attr)
                    offset += attr_length
                else:
                    # Parse as standard attribute
                    attr, consumed = RADIUSAttribute.unpack(data[offset:length])
                    attributes.append(attr)
                    offset += consumed
            except ValueError as e:
                logger.warning(
                    "Error parsing attribute at offset",
                    offset=offset,
                    error=str(e),
                    event="radius.packet.parse_failed",
                )
                raise ValueError(f"Invalid attribute at offset {offset}: {e}") from e

        # Basic required attribute presence for Access-Request (RFC 2865)
        if code == RADIUS_ACCESS_REQUEST:
            has_user = any(a.attr_type == ATTR_USER_NAME for a in attributes)
            has_nas = any(
                a.attr_type in (ATTR_NAS_IP_ADDRESS, ATTR_NAS_IDENTIFIER)
                for a in attributes
            )
            if not has_user:
                raise ValueError("Access-Request missing required attributes")
            if not has_nas:
                logger.warning(
                    "Access-Request without NAS-IP-Address/Identifier",
                    event="radius.access_request.missing_nas",
                )

        packet = cls(code, identifier, authenticator, attributes)
        packet.vsa_attributes = vsa_attributes

        # Decrypt password attribute if present
        if secret and code == RADIUS_ACCESS_REQUEST:
            packet._decrypt_password(secret)

        return packet

    def _decrypt_password(self, secret: bytes):
        """Decrypt User-Password attribute using RADIUS RFC 2865 algorithm.

        Note: MD5 is used here as mandated by RADIUS RFC 2865 specification,
        not for general cryptographic purposes. This is protocol-required legacy.

        Args:
            secret: Shared secret for decryption
        """
        for i, attr in enumerate(self.attributes):
            if attr.attr_type == ATTR_USER_PASSWORD:
                # Password is encrypted: c(1) = p(1) XOR MD5(secret + authenticator)
                # c(n) = p(n) XOR MD5(secret + c(n-1))
                encrypted = attr.value
                if len(encrypted) % 16 != 0:
                    logger.warning(
                        "Invalid encrypted password length: %d", len(encrypted)
                    )
                    continue

                decrypted = b""
                prev = self.authenticator

                for j in range(0, len(encrypted), 16):
                    chunk = encrypted[j : j + 16]
                    hash_input = secret + prev
                    # MD5 required by RADIUS RFC 2865 - not for general crypto use
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", DeprecationWarning)
                        key = hashlib.md5(hash_input, usedforsecurity=False).digest()
                    decrypted_chunk = bytes(a ^ b for a, b in zip(chunk, key))
                    decrypted += decrypted_chunk
                    prev = chunk

                # Remove padding (null bytes at the end)
                decrypted = decrypted.rstrip(b"\x00")
                self.attributes[i] = RADIUSAttribute(ATTR_USER_PASSWORD, decrypted)

    def add_attribute(self, attr_type: int, value: bytes):
        """Add attribute to packet"""
        attr = RADIUSAttribute(attr_type, value)
        self.attributes.append(attr)
        if attr_type == ATTR_VENDOR_SPECIFIC:
            try:
                vsa, consumed = VendorSpecificAttribute.unpack(value)
                if consumed == len(value):
                    self.vsa_attributes.append(vsa)
                else:
                    logger.debug(
                        "VSA length mismatch on add_attribute",
                        event="radius.vsa.length_mismatch",
                    )
            except (ValueError, struct.error) as exc:
                logger.debug(
                    "Failed to decode VSA during add_attribute",
                    event="radius.vsa.decode_failed",
                    error=str(exc),
                )

    def add_string(self, attr_type: int, value: str):
        """Add string attribute"""
        self.add_attribute(attr_type, value.encode("utf-8"))

    def add_integer(self, attr_type: int, value: int):
        """Add integer attribute"""
        self.add_attribute(attr_type, struct.pack("!I", value))

    def add_ipaddr(self, attr_type: int, ip: str):
        """Add IP address attribute"""
        parts = [int(p) for p in ip.split(".")]
        self.add_attribute(attr_type, bytes(parts))

    def get_attribute(self, attr_type: int) -> RADIUSAttribute | None:
        """Get first attribute of given type"""
        for attr in self.attributes:
            if attr.attr_type == attr_type:
                return attr
        return None

    def get_string(self, attr_type: int) -> str | None:
        """Get string attribute value"""
        attr = self.get_attribute(attr_type)
        return attr.as_string() if attr else None

    def get_integer(self, attr_type: int) -> int | None:
        """Get integer attribute value"""
        attr = self.get_attribute(attr_type)
        try:
            return attr.as_int() if attr else None
        except ValueError:
            return None

    def add_vsa(self, vendor_id: int, vendor_type: int, vendor_data: bytes):
        """Add Vendor-Specific Attribute to packet."""
        vsa = VendorSpecificAttribute(vendor_id, vendor_type, vendor_data)
        self.vsa_attributes.append(vsa)
        # Add raw VSA attribute using value-only packing (Type/Length handled by RADIUSAttribute)
        self.attributes.append(RADIUSAttribute(ATTR_VENDOR_SPECIFIC, vsa.pack()))

    def get_vsas(self, vendor_id: int | None = None) -> list[VendorSpecificAttribute]:
        """Get all VSAs, optionally filtered by vendor_id."""
        if vendor_id is None:
            return self.vsa_attributes
        return [vsa for vsa in self.vsa_attributes if vsa.vendor_id == vendor_id]

    # Cisco
    def add_cisco_avpair(self, avpair: str):
        """Add Cisco-AVPair VSA (e.g., 'shell:priv-lvl=15')."""
        self.add_vsa(VENDOR_CISCO, CISCO_AVPAIR, avpair.encode("utf-8"))

    def get_cisco_avpairs(self) -> list[str]:
        """Get all Cisco-AVPair strings from packet."""
        cisco_vsas = self.get_vsas(VENDOR_CISCO)
        avpairs = []
        for vsa in cisco_vsas:
            if vsa.vendor_type == CISCO_AVPAIR:
                avpairs.append(vsa.as_string())
        return avpairs

    # Fortinet
    def add_fortinet_group(self, group_name: str):
        """Add Fortinet group membership VSA"""
        self.add_vsa(VENDOR_FORTINET, 1, group_name.encode("utf-8"))

    def get_fortinet_groups(self) -> list[str]:
        """Get all Fortinet group memberships"""
        return [
            vsa.as_string()
            for vsa in self.get_vsas(VENDOR_FORTINET)
            if vsa.vendor_type == 1  # Fortinet-Group-Name
        ]

    # pfsense/OPNsense
    def add_pfsense_client_ip(self, ip_address: str):
        """Add OPNsense client IP VSA"""
        self.add_vsa(VENDOR_PFSENSE, 2, ip_address.encode("utf-8"))

    def get_pfsense_client_ip(self) -> str | None:
        """Get OPNsense client IP from packet"""
        pfsense_vsas = self.get_vsas(VENDOR_PFSENSE)
        for vsa in pfsense_vsas:
            if vsa.vendor_type == 2:  # OPNsense-Client-IP
                return vsa.as_string()
        return None

    # Juniper
    def add_juniper_role(self, role: str):
        """Add Juniper user role VSA"""
        self.add_vsa(VENDOR_JUNIPER, 1, role.encode("utf-8"))

    # Palo Alto
    def add_palo_alto_role(self, role: str):
        """Add Palo Alto user role VSA"""
        self.add_vsa(VENDOR_PALO_ALTO, 1, role.encode("utf-8"))

    # Arista
    def add_arista_privilege(self, level: int):
        """Add Arista privilege level VSA (1-15)"""
        self.add_vsa(VENDOR_ARISTA, 2, str(level).encode("utf-8"))

    def __str__(self) -> str:
        """String representation for debugging"""
        code_names = {
            1: "Access-Request",
            2: "Access-Accept",
            3: "Access-Reject",
            4: "Accounting-Request",
            5: "Accounting-Response",
            11: "Access-Challenge",
        }
        return (
            f"RADIUSPacket(code={code_names.get(self.code, self.code)}, "
            f"id={self.identifier}, attrs={len(self.attributes)})"
        )
