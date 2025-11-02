import ipaddress
import struct
from dataclasses import dataclass
from typing import Literal


@dataclass
class ProxyInfo:
    """Parsed PROXY protocol v2 header information"""

    version: int
    command: int  # 0=LOCAL, 1=PROXY
    family: int  # 0=UNSPEC, 1=INET, 2=INET6, 3=UNIX
    protocol: int  # 0=UNSPEC, 1=STREAM, 2=DGRAM
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int

    @property
    def is_proxied(self) -> bool:
        """True if this is a proxied connection (not LOCAL)"""
        return self.command == 1


class ProxyProtocolV2Parser:
    """Parser for HAProxy PROXY protocol version 2"""

    SIGNATURE = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
    MIN_HEADER_LEN = 16  # signature(12) + ver_cmd(1) + fam(1) + len(2)

    @staticmethod
    def parse(data: bytes) -> tuple[ProxyInfo | None, int]:
        """
        Parse PROXY protocol v2 header from data.

        Returns:
            (ProxyInfo | None, bytes_consumed)
            - ProxyInfo if valid header found
            - None if no/invalid proxy header
            - bytes_consumed is header length if valid, 0 otherwise
        """
        if len(data) < ProxyProtocolV2Parser.MIN_HEADER_LEN:
            return None, 0

        # Check signature
        if not data.startswith(ProxyProtocolV2Parser.SIGNATURE):
            return None, 0

        # Parse version and command
        ver_cmd = data[12]
        version = (ver_cmd & 0xF0) >> 4
        command = ver_cmd & 0x0F

        # Only PROXY protocol v2 supported
        if version != 2:
            return None, 0
        # Valid commands are 0 (LOCAL) and 1 (PROXY)
        if command not in (0, 1):
            return None, 0

        # Parse family and protocol
        fam_proto = data[13]
        family = (fam_proto & 0xF0) >> 4
        protocol = fam_proto & 0x0F

        # Parse address length
        addr_len = struct.unpack("!H", data[14:16])[0]

        # Validate total length
        total_len = 16 + addr_len
        if len(data) < total_len:
            return None, 0

        # For LOCAL command, addresses are not meaningful (but TLVs may exist)
        if command == 0:  # LOCAL
            return ProxyInfo(
                version=version,
                command=command,
                family=family,
                protocol=protocol,
                src_addr="0.0.0.0",
                dst_addr="0.0.0.0",
                src_port=0,
                dst_port=0,
            ), total_len

        # Parse addresses based on family
        addr_data = data[16:total_len]

        if family == 1:  # AF_INET (IPv4)
            if len(addr_data) < 12:
                return None, 0
            src_ip = ".".join(str(b) for b in addr_data[0:4])
            dst_ip = ".".join(str(b) for b in addr_data[4:8])
            src_port = struct.unpack("!H", addr_data[8:10])[0]
            dst_port = struct.unpack("!H", addr_data[10:12])[0]

        elif family == 2:  # AF_INET6 (IPv6)
            if len(addr_data) < 36:
                return None, 0
            src_ip = str(ipaddress.IPv6Address(addr_data[0:16]))
            dst_ip = str(ipaddress.IPv6Address(addr_data[16:32]))
            src_port = struct.unpack("!H", addr_data[32:34])[0]
            dst_port = struct.unpack("!H", addr_data[34:36])[0]

        else:  # UNSPEC or UNIX
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            src_port = 0
            dst_port = 0

        return ProxyInfo(
            version=version,
            command=command,
            family=family,
            protocol=protocol,
            src_addr=src_ip,
            dst_addr=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
        ), total_len


#
# Device identification helpers using (client_ip, proxy_ip)
#


def normalize_ip(ip: str | None) -> str | None:
    """Normalize an IP address string to a canonical form.

    Returns the compressed representation for IPv6 and the standard dotted
    decimal for IPv4. If ip is falsy/None, returns None.
    """
    if not ip:
        return None
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip  # Leave as-is; caller may decide to reject later


def build_device_identity(
    client_ip: str, proxy_ip: str | None
) -> tuple[str | None, str | None]:
    """Create an identity tuple (client_ip, proxy_ip) with normalized IPs.

    - client_ip: the original source IP from the PROXY v2 header (or socket)
    - proxy_ip: the immediate proxy/load balancer IP (destination in header),
                or None for direct connections
    """
    return normalize_ip(client_ip), normalize_ip(proxy_ip)


def ip_in_cidr(ip: str, cidr: str) -> bool:
    """Check if IP is contained in a CIDR/network.

    Supports both IPv4 and IPv6. Raises ValueError if inputs are invalid.
    """
    addr = ipaddress.ip_address(ip)
    net = ipaddress.ip_network(cidr, strict=False)
    return addr in net


def identity_matches(
    identity: tuple[str, str | None],
    *,
    client_network: str | None = None,
    proxy_network: str | Literal["any"] | None = None,
) -> bool:
    """Match a (client_ip, proxy_ip) identity against optional networks.

    - client_network: CIDR the client_ip must match; if None, any client OK
    - proxy_network:
        - CIDR the proxy_ip must match
        - "any" (case-insensitive): any proxy is acceptable (proxy_ip must be present)
        - None: only matches direct connections (proxy_ip must be None)

    Examples:
      - client_network=192.168.1.0/24, proxy_network=None
        -> Only direct connections from that subnet
      - client_network=192.168.1.0/24, proxy_network=10.0.0.0/8
        -> Proxied connections via that proxy network
      - client_network=fd00::/8, proxy_network="any"
        -> Proxied connections via any proxy (IPv6 tenant), not direct
    """
    client_ip, prox_ip = identity

    # Client network check
    if client_network:
        try:
            if not ip_in_cidr(client_ip, client_network):
                return False
        except ValueError:
            return False

    # Proxy rules
    if proxy_network is None:
        # Only direct connections
        return prox_ip is None

    if isinstance(proxy_network, str) and proxy_network.lower() == "any":
        # Must be proxied, any proxy allowed
        return prox_ip is not None

    # Specific proxy network must match
    if prox_ip is None:
        return False
    try:
        # at this point proxy_network is a specific CIDR string
        return ip_in_cidr(prox_ip, str(proxy_network))
    except ValueError:
        return False
