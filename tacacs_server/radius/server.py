"""
RADIUS Server Implementation

Provides a complete RADIUS server that shares authentication backends with TACACS+.
Supports Authentication and Accounting (Authorization is TACACS+ specific).

RFC 2865 - Remote Authentication Dial In User Service (RADIUS)
RFC 2866 - RADIUS Accounting
"""

import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import threading
import uuid
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from tacacs_server.auth.base import AuthenticationBackend
from tacacs_server.utils.logger import bind_context, clear_context, get_logger
from tacacs_server.utils.policy import PolicyContext, PolicyResult, evaluate_policy
from tacacs_server.utils.rate_limiter import get_rate_limiter

logger = get_logger(__name__)

# RADIUS Packet Codes
RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCOUNTING_REQUEST = 4
RADIUS_ACCOUNTING_RESPONSE = 5
RADIUS_ACCESS_CHALLENGE = 11

# Packet limits
MAX_RADIUS_PACKET_LENGTH = 4096  # RFC 2865 maximum

# RADIUS Attribute Types
ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_CHAP_PASSWORD = 3
ATTR_NAS_IP_ADDRESS = 4
ATTR_NAS_PORT = 5
ATTR_SERVICE_TYPE = 6
ATTR_FRAMED_PROTOCOL = 7
ATTR_FRAMED_IP_ADDRESS = 8
ATTR_FILTER_ID = 11
ATTR_REPLY_MESSAGE = 18
ATTR_STATE = 24
ATTR_CLASS = 25
ATTR_VENDOR_SPECIFIC = 26
ATTR_SESSION_TIMEOUT = 27
ATTR_IDLE_TIMEOUT = 28
ATTR_CALLED_STATION_ID = 30
ATTR_CALLING_STATION_ID = 31
ATTR_NAS_IDENTIFIER = 32
ATTR_ACCT_STATUS_TYPE = 40
ATTR_ACCT_DELAY_TIME = 41
ATTR_ACCT_INPUT_OCTETS = 42
ATTR_ACCT_OUTPUT_OCTETS = 43
ATTR_ACCT_SESSION_ID = 44
ATTR_ACCT_AUTHENTIC = 45
ATTR_ACCT_SESSION_TIME = 46
ATTR_ACCT_INPUT_PACKETS = 47
ATTR_ACCT_OUTPUT_PACKETS = 48
ATTR_ACCT_TERMINATE_CAUSE = 49
ATTR_NAS_PORT_TYPE = 61
ATTR_MESSAGE_AUTHENTICATOR = 80

# Service Types
SERVICE_TYPE_LOGIN = 1
SERVICE_TYPE_FRAMED = 2
SERVICE_TYPE_CALLBACK_LOGIN = 3
SERVICE_TYPE_CALLBACK_FRAMED = 4
SERVICE_TYPE_OUTBOUND = 5
SERVICE_TYPE_ADMINISTRATIVE = 6
SERVICE_TYPE_NAS_PROMPT = 7

# Accounting Status Types
ACCT_STATUS_START = 1
ACCT_STATUS_STOP = 2
ACCT_STATUS_INTERIM_UPDATE = 3
ACCT_STATUS_ACCOUNTING_ON = 7
ACCT_STATUS_ACCOUNTING_OFF = 8

# NAS Port Types
NAS_PORT_TYPE_ASYNC = 0
NAS_PORT_TYPE_SYNC = 1
NAS_PORT_TYPE_ISDN = 2
NAS_PORT_TYPE_ISDN_V120 = 3
NAS_PORT_TYPE_ISDN_V110 = 4
NAS_PORT_TYPE_VIRTUAL = 5
NAS_PORT_TYPE_ETHERNET = 15
NAS_PORT_TYPE_WIRELESS = 19


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

        authenticator = data[4:20]

        # Parse attributes
        attributes = []
        offset = 20
        while offset < length:
            try:
                attr, consumed = RADIUSAttribute.unpack(data[offset:length])
                attributes.append(attr)
                offset += consumed
            except ValueError as e:
                logger.warning(f"Error parsing attribute at offset {offset}: {e}")
                break

        packet = cls(code, identifier, authenticator, attributes)

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
        self.attributes.append(RADIUSAttribute(attr_type, value))

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


# Helper for verifying RADIUS Request Authenticator for Accounting-Request (RFC 2866)
def _verify_request_authenticator(data: bytes, secret: bytes) -> bool:
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


# Helper for verifying Message-Authenticator (RFC 2869 §5.14)
def _verify_message_authenticator(data: bytes, secret: bytes) -> bool:
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
            if atype == ATTR_MESSAGE_AUTHENTICATOR and alen == 18:
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


@dataclass
class RadiusClient:
    """Resolved RADIUS client configuration (single host or network)."""

    network: ipaddress._BaseNetwork
    secret: str
    name: str
    group: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    allowed_user_groups: list[str] = field(default_factory=list)

    def contains(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return ip_obj in self.network

    @property
    def secret_bytes(self) -> bytes:
        return self.secret.encode("utf-8")


if TYPE_CHECKING:
    from ..devices.store import DeviceStore as _DeviceStore


class RADIUSServer:
    """RADIUS Server implementation"""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 1812,
        accounting_port: int = 1813,
        secret: str | None = None,
    ):
        self.host = host
        self.port = port
        self.accounting_port = accounting_port
        # Default fallback secret - should be overridden by device-specific secrets
        if secret is None:
            secret = os.getenv("RADIUS_DEFAULT_SECRET", "CHANGE_ME_FALLBACK")
        self.secret = secret.encode("utf-8")
        if secret == "CHANGE_ME_FALLBACK":
            logger.warning(
                "RADIUS default secret is the insecure fallback; set RADIUS_DEFAULT_SECRET or per-client secrets."
            )

        self.auth_backends: list[AuthenticationBackend] = []
        self.accounting_logger = None
        self.device_store: _DeviceStore | None = None
        self.local_user_group_service = None

        self.running = False
        self.auth_socket: socket.socket | None = None
        self.acct_socket: socket.socket | None = None

        # Config knobs
        self.socket_timeout = float(os.getenv("RADIUS_SOCKET_TIMEOUT", "1.0"))
        self.rcvbuf = int(os.getenv("RADIUS_SO_RCVBUF", "1048576"))
        self.worker_count = int(os.getenv("RADIUS_WORKERS", "8"))
        # Packet worker pool (created on start)
        self._executor: ThreadPoolExecutor | None = None

        # Statistics
        self.stats = {
            "auth_requests": 0,
            "auth_accepts": 0,
            "auth_rejects": 0,
            "acct_requests": 0,
            "acct_responses": 0,
            "invalid_packets": 0,
        }
        self._stats_lock = threading.Lock()

        # Client configuration (RADIUS client devices)
        self._client_lock = threading.RLock()
        self.clients: list[RadiusClient] = []

    def _inc(self, key: str, amount: int = 1) -> None:
        with self._stats_lock:
            self.stats[key] = self.stats.get(key, 0) + amount

    # Backwards-compatible workers property used by main.py
    @property
    def workers(self) -> int:
        return self.worker_count

    @workers.setter
    def workers(self, value: int) -> None:
        try:
            ivalue = int(value)
        except (TypeError, ValueError):
            return
        # Clamp to reasonable bounds
        self.worker_count = max(1, min(64, ivalue))

    def add_auth_backend(self, backend):
        """Add authentication backend (shared with TACACS+)"""
        self.auth_backends.append(backend)
        try:
            name = getattr(backend, "name", None) or str(backend)
        except Exception:
            # Backend name retrieval failed, use string representation
            name = str(backend)
        logger.info(
            "Authentication backend added",
            event="auth.backend.added",
            service="radius",
            component="radius_server",
            backend=name,
        )

    def set_accounting_logger(self, accounting_logger):
        """Set accounting logger (shared with TACACS+)"""
        self.accounting_logger = accounting_logger
        logger.info(
            "Accounting logger configured",
            event="accounting.logger.configured",
            service="radius",
            component="radius_server",
        )

    def set_local_user_group_service(self, service) -> None:
        self.local_user_group_service = service

    def add_client(
        self,
        network: str,
        secret: str,
        name: str | None = None,
        *,
        group: str | None = None,
        attributes: dict[str, Any] | None = None,
        allowed_user_groups: list[str] | None = None,
    ) -> bool:
        """Add a RADIUS client by IP or network."""
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            logger.error("RADIUS: Invalid client network '%s'", network)
            return False

        client = RadiusClient(
            network=net,
            secret=secret,
            name=name or str(net),
            group=group,
            attributes=attributes or {},
            allowed_user_groups=list(allowed_user_groups or []),
        )
        with self._client_lock:
            self.clients.append(client)
            # ensure most specific networks are matched first
            self.clients.sort(key=lambda entry: entry.network.prefixlen, reverse=True)
        logger.info("RADIUS: Added client %s (%s)", client.name, client.network)
        return True

    def load_clients(self, clients: list["RadiusClient"]) -> None:
        """Replace current clients with pre-built entries (e.g. from DeviceStore)."""
        with self._client_lock:
            self.clients = sorted(
                clients, key=lambda entry: entry.network.prefixlen, reverse=True
            )
        logger.info("RADIUS: Loaded %d client definitions", len(clients))

    def refresh_clients(self, client_configs) -> None:
        """Rebuild client list from iterable configs (network, secret, etc.)."""
        new_clients: list[RadiusClient] = []
        for cfg in client_configs:
            try:
                network = getattr(cfg, "network")
                secret = getattr(cfg, "secret")
                name = getattr(cfg, "name", str(network))
                group = getattr(cfg, "group", None)
                attributes = dict(getattr(cfg, "attributes", {}) or {})
                allowed_user_groups = list(
                    getattr(cfg, "allowed_user_groups", []) or []
                )
            except AttributeError as exc:
                logger.warning(
                    "RADIUS: Skipping invalid client config %s: %s", cfg, exc
                )
                continue
            new_clients.append(
                RadiusClient(
                    network=network,
                    secret=secret,
                    name=name,
                    group=group,
                    attributes=attributes,
                    allowed_user_groups=allowed_user_groups,
                )
            )
        with self._client_lock:
            self.clients = sorted(
                new_clients, key=lambda entry: entry.network.prefixlen, reverse=True
            )
        logger.info("RADIUS: Refreshed %d client definitions", len(new_clients))

    def lookup_client(self, ip: str) -> Optional["RadiusClient"]:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning("RADIUS: Received packet from invalid IP '%s'", ip)
            return None
        with self._client_lock:
            for client in self.clients:
                if ip_obj in client.network:
                    return client
        return None

    def start(self):
        """Start RADIUS server"""
        if self.running:
            logger.warning("RADIUS server already running")
            return

        self.running = True

        # Start worker pool
        self._executor = ThreadPoolExecutor(
            max_workers=self.worker_count, thread_name_prefix="RADIUS"
        )

        # Start authentication server
        auth_thread = threading.Thread(
            target=self._start_auth_server, daemon=True, name="RADIUS-Auth"
        )
        auth_thread.start()

        # Start accounting server
        acct_thread = threading.Thread(
            target=self._start_acct_server, daemon=True, name="RADIUS-Acct"
        )
        acct_thread.start()

        logger.info(
            "RADIUS server listening",
            event="service.start",
            service="radius",
            component="radius_server",
            host=self.host,
            auth_port=self.port,
            acct_port=self.accounting_port,
            workers=self.worker_count,
        )

    def stop(self):
        """Stop RADIUS server"""
        self.running = False

        if self.auth_socket:
            try:
                self.auth_socket.close()
            except (OSError, AttributeError) as socket_close_exc:
                # Socket close failed, continue with shutdown
                logger.warning(
                    "Failed to close RADIUS authentication socket: %s",
                    socket_close_exc,
                )
        if self.acct_socket:
            try:
                self.acct_socket.close()
            except (OSError, AttributeError) as socket_close_exc:
                # Socket close failed, continue with shutdown
                logger.warning(
                    "Failed to close RADIUS accounting socket: %s", socket_close_exc
                )

        if self._executor:
            try:
                self._executor.shutdown(wait=False, cancel_futures=True)
            except Exception as executor_shutdown_exc:
                # Executor shutdown failed, continue with cleanup
                logger.warning(
                    "Failed to shutdown RADIUS executor: %s", executor_shutdown_exc
                )
            finally:
                self._executor = None

        logger.info(
            "RADIUS server stopped",
            event="service.stop",
            service="radius",
            component="radius_server",
        )

    def _start_auth_server(self):
        """Start authentication server thread"""
        try:
            self.auth_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.auth_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.auth_socket.bind((self.host, self.port))
            self.auth_socket.settimeout(self.socket_timeout)
            try:
                self.auth_socket.setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf
                )
            except Exception as socket_setopt_exc:
                # Socket buffer size tuning failed, continue with default
                logger.warning(
                    "Failed to set RADIUS authentication socket buffer size: %s",
                    socket_setopt_exc,
                )

            logger.debug(
                "RADIUS authentication server listening on %s:%s", self.host, self.port
            )

            sock = self.auth_socket
            assert sock is not None
            while self.running:
                try:
                    data, addr = sock.recvfrom(MAX_RADIUS_PACKET_LENGTH)
                    # Handle in thread pool or fallback to thread
                    if self._executor:
                        self._executor.submit(self._handle_auth_request, data, addr)
                    else:
                        threading.Thread(
                            target=self._handle_auth_request,
                            args=(data, addr),
                            daemon=True,
                        ).start()
                except TimeoutError:
                    continue
                except (OSError, ConnectionError) as e:
                    if self.running:
                        logger.error(f"RADIUS auth server error: {e}")
                    break

        except (OSError, ConnectionError) as e:
            logger.error(f"Failed to start RADIUS auth server: {e}")
        finally:
            if self.auth_socket:
                try:
                    self.auth_socket.close()
                except (OSError, AttributeError) as socket_close_exc:
                    # Socket close failed during cleanup
                    logger.warning(
                        "Failed to close RADIUS authentication socket: %s",
                        socket_close_exc,
                    )
                finally:
                    self.auth_socket = None

    def _start_acct_server(self):
        """Start accounting server thread"""
        try:
            self.acct_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.acct_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.acct_socket.bind((self.host, self.accounting_port))
            self.acct_socket.settimeout(self.socket_timeout)
            try:
                self.acct_socket.setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf
                )
            except Exception as socket_setopt_exc:
                # Socket buffer size tuning failed, continue with default
                logger.warning(
                    "Failed to set RADIUS accounting socket buffer size: %s",
                    socket_setopt_exc,
                )

            logger.debug(
                "RADIUS accounting server listening on %s:%s",
                self.host,
                self.accounting_port,
            )

            sock2 = self.acct_socket
            assert sock2 is not None
            while self.running:
                try:
                    data, addr = sock2.recvfrom(MAX_RADIUS_PACKET_LENGTH)
                    # Handle in thread pool or fallback to thread
                    if self._executor:
                        self._executor.submit(self._handle_acct_request, data, addr)
                    else:
                        threading.Thread(
                            target=self._handle_acct_request,
                            args=(data, addr),
                            daemon=True,
                        ).start()
                except TimeoutError:
                    continue
                except (OSError, ConnectionError) as e:
                    if self.running:
                        logger.error(f"RADIUS acct server error: {e}")
                    break

        except (OSError, ConnectionError) as e:
            logger.error(f"Failed to start RADIUS acct server: {e}")
        finally:
            if self.acct_socket:
                try:
                    self.acct_socket.close()
                except (OSError, AttributeError) as socket_close_exc:
                    # Socket close failed during cleanup
                    logger.warning(
                        "Failed to close RADIUS accounting socket: %s",
                        socket_close_exc,
                    )
                finally:
                    self.acct_socket = None

    def _handle_auth_request(self, data: bytes, addr: tuple[str, int]):
        """Handle authentication request"""
        client_ip, client_port = addr
        _ctx = None
        try:
            _ctx = bind_context(
                correlation_id=str(uuid.uuid4()), client={"ip": client_ip}
            )
        except Exception:
            # Context binding failed, continue without correlation context
            _ctx = None

        # Per-IP rate limiting to mitigate floods
        limiter = get_rate_limiter()
        if not limiter.allow_request(client_ip):
            logger.warning("RADIUS rate limit exceeded for %s", client_ip)
            return

        try:
            client_config = self.lookup_client(client_ip)
            if not client_config:
                # Auto-register unknown client as device when enabled, then retry
                auto_reg = bool(getattr(self, "device_auto_register", True))
                ds = getattr(self, "device_store", None)
                if auto_reg and ds is not None:
                    try:
                        # Ensure default group exists
                        group_name = getattr(self, "default_device_group", "default")
                        ds.ensure_group(group_name)
                        # Create single-host device
                        cidr = f"{client_ip}/32"
                        if ":" in client_ip:
                            cidr = f"{client_ip}/128"
                        ds.ensure_device(
                            name=f"auto-{client_ip.replace(':', '_')}",
                            network=cidr,
                            group=group_name,
                        )
                        # Refresh RADIUS clients from device store and retry lookup
                        try:
                            configs = ds.iter_radius_clients()
                            self.refresh_clients(configs)
                        except Exception as refresh_clients_exc:
                            # Client refresh failed, continue with existing clients
                            logger.warning(
                                "Failed to refresh RADIUS clients: %s",
                                refresh_clients_exc,
                            )
                        client_config = self.lookup_client(client_ip)
                    except Exception as exc:
                        logger.warning(
                            "RADIUS auto-registration failed for %s: %s", client_ip, exc
                        )
                if not client_config:
                    logger.warning(
                        "RADIUS auth request from unknown client: %s", client_ip
                    )
                    self._inc("invalid_packets")
                    return

            client_secret = client_config.secret_bytes

            # If present, verify Message-Authenticator (RFC 2869 §5.14)
            if not _verify_message_authenticator(data, client_secret):
                logger.warning(
                    "RADIUS auth request with invalid Message-Authenticator from %s",
                    client_ip,
                )
                self._inc("invalid_packets")
                return

            # Parse request
            request = RADIUSPacket.unpack(data, client_secret)

            if request.code != RADIUS_ACCESS_REQUEST:
                logger.warning("Unexpected packet code in auth port: %s", request.code)
                return

            self._inc("auth_requests")

            # Detailed (DEBUG) request trace
            try:
                nas_ip = request.get_string(ATTR_NAS_IP_ADDRESS)
                nas_port = request.get_integer(ATTR_NAS_PORT)
                logger.debug(
                    "RADIUS request",
                    event="radius.request",
                    service="radius",
                    code=request.code,
                    client={"ip": client_ip, "port": client_port},
                    nas_ip=nas_ip,
                    nas_port=nas_port,
                    client_group=getattr(client_config, "group", None),
                )
            except Exception as debug_logging_exc:
                # Debug logging failed, continue processing request
                logger.warning("Failed to log RADIUS request: %s", debug_logging_exc)

            # Extract authentication info
            username = request.get_string(ATTR_USER_NAME)
            password_attr = request.get_attribute(ATTR_USER_PASSWORD)
            password = password_attr.as_string() if password_attr else None

            if not username or not password:
                logger.warning(
                    "RADIUS auth request missing username or password from %s",
                    client_ip,
                )
                response = self._create_access_reject(request, "Missing credentials")
                if request.get_attribute(ATTR_MESSAGE_AUTHENTICATOR):
                    response.add_attribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16)
                self._send_response(
                    response, addr, client_secret, request.authenticator
                )
                return

            logger.debug(
                "RADIUS auth request: user=%s from %s (matched %s)",
                username or "<unknown>",
                client_ip,
                client_config.network,
            )

            # Authenticate against backends.
            authenticated, auth_detail = self._authenticate_user(username, password)

            device_label = (
                client_config.group or client_config.name or str(client_config.network)
            )

            if authenticated:
                # Enforce RADIUS client allowed_user_groups for Okta-backed users.
                # This mirrors the TACACS AAA device-scoped enforcement: client
                # allowed_user_groups (local group names) are mapped via local
                # user groups' okta_group to Okta group names, then intersected
                # with the user's Okta groups from the Okta backend.
                denial_reason: str | None = None
                try:
                    svc = getattr(self, "local_user_group_service", None)
                    if svc is not None and client_config.allowed_user_groups:
                        okta_backends = [
                            b
                            for b in self.auth_backends
                            if getattr(b, "name", "") == "okta"
                        ]
                        backend = okta_backends[0] if okta_backends else None
                        if backend is not None:
                            allowed_targets: set[str] = set()
                            for gname in client_config.allowed_user_groups:
                                try:
                                    rec = svc.get_group(gname)
                                except Exception:
                                    continue
                                okg = getattr(rec, "okta_group", None)
                                if okg:
                                    try:
                                        allowed_targets.add(str(okg).lower())
                                    except Exception:
                                        continue
                            if allowed_targets:
                                try:
                                    raw_groups = backend.get_user_groups(username)
                                    user_groups = {
                                        str(g).lower() for g in (raw_groups or [])
                                    }
                                except Exception as e:
                                    logger.debug(
                                        "RADIUS Okta group resolution failed for %s: %s",
                                        username,
                                        e,
                                    )
                                    user_groups = set()
                                if not (allowed_targets & user_groups):
                                    denial_reason = "group_not_allowed"
                                    authenticated = False
                                    auth_detail = "radius_okta_group_not_allowed"
                                    logger.warning(
                                        "RADIUS Okta user not in allowed groups for client %s: user=%s allowed_targets=%s user_groups=%s",
                                        device_label,
                                        username,
                                        sorted(list(allowed_targets)),
                                        sorted(list(user_groups)),
                                    )
                except Exception:
                    # Best-effort enforcement; fall back to existing policy if this fails.
                    logger.debug(
                        "RADIUS Okta device-scoped enforcement failed; falling back to policy engine",
                        exc_info=True,
                    )

                # Get user attributes for response
                user_attrs = self._get_user_attributes(username)
                allowed_ok, denial_message = self._apply_user_group_policy(
                    client_config, user_attrs
                )
                if authenticated and allowed_ok and not denial_reason:
                    response = self._create_access_accept(request, user_attrs)
                    self._inc("auth_accepts")
                    logger.info(
                        "RADIUS authentication success: user=%s detail=%s device=%s",
                        username,
                        auth_detail,
                        device_label,
                    )
                    try:
                        from ..web.monitoring import PrometheusIntegration

                        PrometheusIntegration.record_radius_auth("accept")
                    except Exception as prometheus_integration_exc:
                        # Prometheus metrics recording failed, continue without metrics
                        logger.warning(
                            "Failed to record RADIUS authentication accept: %s",
                            prometheus_integration_exc,
                        )
                else:
                    response = self._create_access_reject(
                        request, denial_reason or denial_message
                    )
                    self._inc("auth_rejects")
                    logger.warning(
                        "RADIUS authentication failed: user=%s reason=%s device=%s",
                        username,
                        f"policy_denied={denial_message}",
                        device_label,
                    )
                    try:
                        from ..web.monitoring import PrometheusIntegration

                        PrometheusIntegration.record_radius_auth("reject")
                    except Exception as prometheus_integration_exc:
                        # Prometheus metrics recording failed, continue without metrics
                        logger.warning(
                            "Failed to record RADIUS authentication reject: %s",
                            prometheus_integration_exc,
                        )
            else:
                response = self._create_access_reject(request, "Authentication failed")
                self._inc("auth_rejects")
                logger.warning(
                    "RADIUS authentication failed: user=%s reason=%s device=%s",
                    username,
                    auth_detail or "no backend accepted credentials",
                    device_label,
                )
                try:
                    from ..web.monitoring import PrometheusIntegration

                    PrometheusIntegration.record_radius_auth("reject")
                except Exception as prometheus_integration_exc:
                    # Prometheus metrics recording failed, continue without metrics
                    logger.warning(
                        "Failed to record RADIUS authentication reject: %s",
                        prometheus_integration_exc,
                    )

            # Mirror Message-Authenticator if client used it
            if request.get_attribute(ATTR_MESSAGE_AUTHENTICATOR):
                response.add_attribute(ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16)

            # Send response
            self._send_response(response, addr, client_secret, request.authenticator)
            try:
                status = (
                    "accept"
                    if response.code == RADIUS_ACCESS_ACCEPT
                    else "reject"
                    if response.code == RADIUS_ACCESS_REJECT
                    else str(response.code)
                )
                logger.debug(
                    "RADIUS response",
                    event="radius.reply",
                    service="radius",
                    code=response.code,
                    status=status,
                    client={"ip": client_ip, "port": client_port},
                )
            except Exception as debug_logging_exc:
                # Debug logging failed, continue without response logging
                logger.warning("Failed to log RADIUS response: %s", debug_logging_exc)

        except Exception as e:
            logger.error("Error handling RADIUS auth request from %s: %s", client_ip, e)
            self._inc("invalid_packets")
        finally:
            try:
                if _ctx is not None:
                    clear_context(_ctx)
            except Exception as context_cleanup_exc:
                # Context cleanup failed, continue without cleanup
                logger.warning(
                    "Failed to cleanup correlation context: %s", context_cleanup_exc
                )

    def _handle_acct_request(self, data: bytes, addr: tuple[str, int]):
        """Handle RADIUS accounting request with improved error handling.

        Args:
            data: Raw packet data
            addr: Client address tuple (ip, port)
        """
        client_ip, client_port = addr
        _ctx = None
        try:
            _ctx = bind_context(
                correlation_id=str(uuid.uuid4()), client={"ip": client_ip}
            )
        except Exception:
            # Context binding failed, continue without correlation context
            _ctx = None

        # Per-IP rate limiting for accounting path
        limiter = get_rate_limiter()
        if not limiter.allow_request(client_ip):
            logger.warning("RADIUS acct rate limit exceeded for %s", client_ip)
            return

        try:
            client_config = self.lookup_client(client_ip)
            if not client_config:
                # Auto-register unknown client as device when enabled, then retry
                auto_reg = bool(getattr(self, "device_auto_register", True))
                ds = getattr(self, "device_store", None)
                if auto_reg and ds is not None:
                    try:
                        group_name = getattr(self, "default_device_group", "default")
                        ds.ensure_group(group_name)
                        cidr = f"{client_ip}/32"
                        if ":" in client_ip:
                            cidr = f"{client_ip}/128"
                        ds.ensure_device(
                            name=f"auto-{client_ip.replace(':', '_')}",
                            network=cidr,
                            group=group_name,
                        )
                        try:
                            configs = ds.iter_radius_clients()
                            self.refresh_clients(configs)
                        except Exception as refresh_clients_exc:
                            # Client refresh failed, continue with existing clients
                            logger.warning(
                                "Failed to refresh RADIUS clients: %s",
                                refresh_clients_exc,
                            )
                        client_config = self.lookup_client(client_ip)
                    except Exception as exc:
                        logger.warning(
                            "RADIUS auto-registration failed for %s: %s", client_ip, exc
                        )
                if not client_config:
                    logger.warning(
                        "RADIUS acct request from unknown client: %s", client_ip
                    )
                    self._inc("invalid_packets")
                    return

            client_secret = client_config.secret_bytes

            # Verify Request Authenticator for Accounting-Request (RFC 2866)
            if not _verify_request_authenticator(data, client_secret):
                logger.warning(
                    "RADIUS acct request with invalid Request Authenticator from %s",
                    client_ip,
                )
                self._inc("invalid_packets")
                return

            # Parse request with error handling
            try:
                request = RADIUSPacket.unpack(data, client_secret)
            except ValueError as e:
                logger.warning("Invalid RADIUS packet from %s: %s", client_ip, e)
                self._inc("invalid_packets")
                return

            if request.code != RADIUS_ACCOUNTING_REQUEST:
                logger.warning("Unexpected packet code in acct port: %s", request.code)
                self._inc("invalid_packets")
                return

            self._inc("acct_requests")

            # Extract accounting info
            username = request.get_string(ATTR_USER_NAME)
            session_id = request.get_string(ATTR_ACCT_SESSION_ID)
            status_type = request.get_integer(ATTR_ACCT_STATUS_TYPE)

            status_names = {
                1: "START",
                2: "STOP",
                3: "UPDATE",
                7: "ACCOUNTING-ON",
                8: "ACCOUNTING-OFF",
            }
            status_name = status_names.get(status_type or -1, f"UNKNOWN({status_type})")

            logger.info(
                "RADIUS accounting: %s session %s - %s (matched %s)",
                username,
                session_id,
                status_name,
                client_config.network,
            )

            # Detailed (DEBUG) accounting trace
            try:
                logger.debug(
                    "RADIUS accounting request",
                    event="radius.request",
                    service="radius",
                    code=RADIUS_ACCOUNTING_REQUEST,
                    client={"ip": client_ip, "port": client_port},
                    username=username,
                    session=session_id,
                    status=status_name,
                    client_group=getattr(client_config, "group", None),
                )
            except Exception as debug_logging_exc:
                # Debug logging failed, continue processing accounting request
                logger.warning(
                    "Failed to log RADIUS accounting request: %s", debug_logging_exc
                )

            # Log to accounting database if available
            if self.accounting_logger:
                self._log_accounting(request, client_ip)

            # Send response
            response = RADIUSPacket(
                code=RADIUS_ACCOUNTING_RESPONSE,
                identifier=request.identifier,
                authenticator=bytes(16),  # Will be calculated in pack()
            )

            self._send_response(response, addr, client_secret, request.authenticator)
            self._inc("acct_responses")
            try:
                logger.debug(
                    "RADIUS accounting response",
                    event="radius.reply",
                    service="radius",
                    code=RADIUS_ACCOUNTING_RESPONSE,
                    client={"ip": client_ip, "port": client_port},
                    username=username,
                    session=session_id,
                    status=status_name,
                )
            except Exception as debug_logging_exc:
                # Debug logging failed, continue without response logging
                logger.warning(
                    "Failed to log RADIUS accounting response: %s", debug_logging_exc
                )

        except Exception as e:
            logger.error("Error handling RADIUS acct request from %s: %s", client_ip, e)
        finally:
            try:
                if _ctx is not None:
                    clear_context(_ctx)
            except Exception as context_cleanup_exc:
                # Context cleanup failed, continue without cleanup
                logger.warning(
                    "Failed to cleanup correlation context: %s", context_cleanup_exc
                )

    def _authenticate_user(
        self, username: str, password: str, **kwargs
    ) -> tuple[bool, str]:
        """Authenticate user against backends with diagnostic detail."""
        if not self.auth_backends:
            return False, "no authentication backends configured"

        last_error: str | None = None
        for backend in self.auth_backends:
            try:
                if backend.authenticate(username, password, **kwargs):
                    logger.debug(
                        f"RADIUS: Authentication successful via {backend.name}"
                    )
                    return True, f"backend={backend.name}"
            except Exception as e:
                message = f"backend={backend.name} error={e}"
                logger.error(f"RADIUS: {message}")
                last_error = message

        if last_error:
            return False, last_error

        return False, "no backend accepted credentials"

    def _get_user_attributes(self, username: str) -> dict[str, Any]:
        """Get user attributes from backends"""
        for backend in self.auth_backends:
            try:
                attrs = backend.get_user_attributes(username)
                if attrs:
                    return attrs
            except Exception as e:
                logger.error(f"Error getting attributes from {backend.name}: {e}")

        return {}

    def _apply_user_group_policy(
        self, client: RadiusClient, user_attrs: dict[str, Any]
    ) -> tuple[bool, str]:
        context = PolicyContext(
            device_group_name=getattr(client, "group", None),
            allowed_user_groups=getattr(client, "allowed_user_groups", []),
            user_groups=user_attrs.get("groups", []) or [],
            fallback_privilege=user_attrs.get("privilege_level", 1),
        )

        def _lookup_privilege(group_name: str) -> int | None:
            if not self.local_user_group_service:
                return None
            record = self.local_user_group_service.get_group(group_name)
            return getattr(record, "privilege_level", None)

        result: PolicyResult = evaluate_policy(context, _lookup_privilege)
        user_attrs["privilege_level"] = result.privilege_level
        return result.allowed, result.denial_message

    def _create_access_accept(
        self, request: RADIUSPacket, user_attrs: dict[str, Any]
    ) -> RADIUSPacket:
        """Create Access-Accept response"""
        response = RADIUSPacket(
            code=RADIUS_ACCESS_ACCEPT,
            identifier=request.identifier,
            authenticator=bytes(16),  # Will be calculated in pack()
        )

        # Add Reply-Message
        response.add_string(ATTR_REPLY_MESSAGE, "Authentication successful")

        # Add Service-Type
        response.add_integer(ATTR_SERVICE_TYPE, SERVICE_TYPE_ADMINISTRATIVE)

        # Add Session-Timeout if specified
        if "session_timeout" in user_attrs:
            response.add_integer(ATTR_SESSION_TIMEOUT, user_attrs["session_timeout"])

        # Add Idle-Timeout if specified
        if "idle_timeout" in user_attrs:
            response.add_integer(ATTR_IDLE_TIMEOUT, user_attrs["idle_timeout"])

        # Add Class attribute (can be used for tracking)
        privilege_level = user_attrs.get("privilege_level", 1)
        response.add_string(ATTR_CLASS, f"priv{privilege_level}")

        return response

    def _create_access_reject(
        self, request: RADIUSPacket, message: str = "Authentication failed"
    ) -> RADIUSPacket:
        """Create Access-Reject response"""
        response = RADIUSPacket(
            code=RADIUS_ACCESS_REJECT,
            identifier=request.identifier,
            authenticator=bytes(16),
        )

        response.add_string(ATTR_REPLY_MESSAGE, message)

        return response

    def _send_response(
        self,
        response: RADIUSPacket,
        addr: tuple[str, int],
        secret: bytes,
        request_auth: bytes,
    ):
        """Send RADIUS response"""
        try:
            packet_data = response.pack(secret, request_auth)

            if (
                response.code == RADIUS_ACCESS_ACCEPT
                or response.code == RADIUS_ACCESS_REJECT
            ):
                if self.auth_socket is not None:
                    self.auth_socket.sendto(packet_data, addr)
            else:
                if self.acct_socket is not None:
                    self.acct_socket.sendto(packet_data, addr)

        except Exception as e:
            logger.error(f"Error sending RADIUS response to {addr}: {e}")

    def _log_accounting(self, request: RADIUSPacket, client_ip: str):
        """Log accounting information to database"""
        try:
            from ..accounting.models import AccountingRecord

            username = request.get_string(ATTR_USER_NAME) or "unknown"
            session_id_str = request.get_string(ATTR_ACCT_SESSION_ID) or "0"
            status_type = request.get_integer(ATTR_ACCT_STATUS_TYPE)

            # Convert RADIUS status to TACACS status
            status_map = {
                ACCT_STATUS_START: "START",
                ACCT_STATUS_STOP: "STOP",
                ACCT_STATUS_INTERIM_UPDATE: "UPDATE",
            }
            status = status_map.get(int(status_type or -1), "UNKNOWN")

            # Try to parse session ID as integer
            try:
                session_id = (
                    int(session_id_str)
                    if session_id_str.isdigit()
                    else hash(session_id_str) & 0xFFFFFFFF
                )
            except Exception:
                # Session ID parsing failed, use hash as fallback
                session_id = hash(session_id_str) & 0xFFFFFFFF

            record = AccountingRecord(
                username=username,
                session_id=session_id,
                status=status,
                service="radius",
                command=f"RADIUS {status}",
                client_ip=client_ip,
                port=request.get_string(ATTR_CALLED_STATION_ID),
                bytes_in=request.get_integer(ATTR_ACCT_INPUT_OCTETS) or 0,
                bytes_out=request.get_integer(ATTR_ACCT_OUTPUT_OCTETS) or 0,
                elapsed_time=request.get_integer(ATTR_ACCT_SESSION_TIME) or 0,
            )
            if self.accounting_logger is not None:
                self.accounting_logger.log_accounting(record)

        except Exception as e:
            logger.error(f"Error logging RADIUS accounting: {e}")

    def get_stats(self) -> dict[str, Any]:
        """Get server statistics"""
        with self._stats_lock:
            auth_requests = self.stats["auth_requests"]
            auth_accepts = self.stats["auth_accepts"]
            auth_rejects = self.stats["auth_rejects"]
            acct_requests = self.stats["acct_requests"]
            acct_responses = self.stats["acct_responses"]
            invalid_packets = self.stats["invalid_packets"]
        return {
            "auth_requests": auth_requests,
            "auth_accepts": auth_accepts,
            "auth_rejects": auth_rejects,
            "auth_success_rate": (
                (auth_accepts / auth_requests * 100) if auth_requests > 0 else 0
            ),
            "acct_requests": acct_requests,
            "acct_responses": acct_responses,
            "invalid_packets": invalid_packets,
            "configured_clients": len(self.clients),
            "running": self.running,
        }
