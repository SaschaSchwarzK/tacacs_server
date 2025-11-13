"""PROXY protocol handling"""

import ipaddress

from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.proxy_protocol import ProxyProtocolV2Parser

logger = get_logger(__name__)


class ProxyHandler:
    """Handles PROXY protocol v2 parsing and validation"""

    def __init__(self, device_store=None, validate_sources: bool = False):
        self.device_store = device_store
        self.validate_sources = validate_sources

    def parse_proxy_header(
        self, first12: bytes, socket_recv_func
    ) -> tuple[object | None, int, bytes]:
        """
        Parse PROXY v2 header if present

        Returns: (info, consumed_bytes, buffered_data)
        """
        buffered = first12
        info = None
        consumed = 0

        if not first12 or len(first12) < len(ProxyProtocolV2Parser.SIGNATURE):
            return None, 0, buffered

        if not first12.startswith(ProxyProtocolV2Parser.SIGNATURE):
            return None, 0, buffered

        logger.debug("PROXY v2 signature detected")

        try:
            next4 = socket_recv_func(4) or b""
            buffered += next4
            hdr16 = first12 + next4
            addr_len = int.from_bytes(hdr16[14:16], "big")
            rest = socket_recv_func(addr_len) or b""
            buffered += rest
            raw_header = hdr16 + rest

            info, consumed = ProxyProtocolV2Parser.parse(raw_header)

            logger.debug(
                "PROXY header: read=%d bytes, consumed=%d, addr_len=%d",
                len(raw_header),
                consumed,
                addr_len,
            )

        except Exception as e:
            logger.debug("PROXY header parse error: %s", e)
            return None, 0, buffered

        return info, consumed, buffered

    def validate_proxy_source(self, proxy_ip: str) -> bool:
        """Check if proxy IP is in configured proxy networks"""
        if not self.validate_sources:
            return True

        try:
            p_ip = ipaddress.ip_address(proxy_ip)
        except Exception:
            logger.debug("Failed to parse proxy IP: %s", proxy_ip)
            return False

        if self.device_store is None:
            logger.debug("No device store configured, allowing proxy IP: %s", proxy_ip)
            return True

        try:
            proxies = self.device_store.list_proxies()
            logger.debug(
                "Checking proxy IP %s against %d configured proxies",
                proxy_ip,
                len(proxies),
            )

            for p in proxies:
                try:
                    if p_ip in p.network:
                        logger.debug(
                            "Proxy IP %s matched proxy network %s", proxy_ip, p.network
                        )
                        return True
                except Exception as e:
                    logger.debug(
                        "Error checking proxy %s: %s",
                        getattr(p, "name", "unknown"),
                        e,
                    )
                    continue

            logger.debug(
                "Proxy IP %s not found in any configured proxy networks", proxy_ip
            )
        except Exception as e:
            logger.debug("Error listing proxies: %s, failing open", e)
            return True

        return False
