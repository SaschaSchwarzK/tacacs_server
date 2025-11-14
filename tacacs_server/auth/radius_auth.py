"""
RADIUS Authentication Backend for TACACS+ Server

This backend acts as a RADIUS client to authenticate TACACS+ users against an
external RADIUS server (RFC 2865). On successful authentication, it extracts
group information from standard attributes to integrate with the authorization
policy engine.

Configuration (section: [radius_auth]):
  - radius_server        (required): RADIUS server host or IP
  - radius_port          (default: 1812): RADIUS authentication port
  - radius_secret        (required): Shared secret with RADIUS server
  - radius_timeout       (default: 5): Socket timeout per attempt (seconds)
  - radius_retries       (default: 3): Number of retry attempts
  - radius_nas_ip        (default: 0.0.0.0): Value used for NAS-IP-Address
  - radius_nas_identifier (optional): Value used for NAS-Identifier

About NAS attributes:
  - radius_nas_ip sets the NAS-IP-Address attribute (type 4). Some RADIUS
    servers use this to identify or apply client-specific policy. If left at
    the default 0.0.0.0, a valid attribute is still sent but may be treated by
    the server as an unspecified client address; set this to the actual source
    IP of your TACACS+ server when your RADIUS server enforces client IP-based
    policies.

  - radius_nas_identifier (type 32) is an optional string identifier for the
    NAS. Set it when your RADIUS policies or accounting rely on a stable device
    identifier rather than source IP. When not set, the attribute is omitted.

Groups extraction:
  - Filter-Id (11): Treated as group names (one per attribute instance)
  - Class (25): Values starting with "group:" are interpreted as group names

These groups are cached on successful authentication and returned by
get_user_attributes(username) for downstream authorization checks.
"""

import hashlib
import secrets
import socket
import struct
from typing import Any

from tacacs_server.utils.logger import get_logger

from .base import AuthenticationBackend

logger = get_logger(__name__)


class RADIUSAuthBackend(AuthenticationBackend):
    """RADIUS authentication backend"""

    # RADIUS packet codes (RFC 2865)
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3

    # RADIUS attribute types (RFC 2865)
    USER_NAME = 1
    USER_PASSWORD = 2
    NAS_IP_ADDRESS = 4
    NAS_PORT = 5
    SERVICE_TYPE = 6
    FILTER_ID = 11
    REPLY_MESSAGE = 18
    CLASS = 25
    NAS_IDENTIFIER = 32

    def __init__(self, cfg: dict[str, Any]):
        """
        Initialize RADIUS backend

        Config options:
            radius_server: RADIUS server hostname/IP (required)
            radius_port: RADIUS server port (default 1812)
            radius_secret: Shared secret (required)
            radius_timeout: Timeout in seconds (default 5)
            radius_retries: Number of retries (default 3)
            radius_nas_ip: NAS IP address to send (default 0.0.0.0)
            radius_nas_identifier: NAS identifier (optional)
        """
        super().__init__("radius")

        self.radius_server: str = str(
            cfg.get("radius_server") or cfg.get("server") or ""
        )
        self.radius_port: int = int(cfg.get("radius_port", 1812))
        self.radius_secret: bytes = (cfg.get("radius_secret") or "").encode("utf-8")
        self.radius_timeout: int = int(cfg.get("radius_timeout", 5))
        self.radius_retries: int = int(cfg.get("radius_retries", 3))
        self.radius_nas_ip: str = str(cfg.get("radius_nas_ip", "0.0.0.0"))
        self.radius_nas_identifier: str | None = (
            str(cfg.get("radius_nas_identifier"))
            if cfg.get("radius_nas_identifier")
            else None
        )

        if not self.radius_server:
            raise ValueError("RADIUS server must be specified (radius_server)")
        if not self.radius_secret:
            raise ValueError("RADIUS shared secret must be specified (radius_secret)")

        logger.info(
            f"Initialized RADIUS backend: server={self.radius_server}:{self.radius_port}"
        )

    def _create_authenticator(self) -> bytes:
        """Generate random 16-byte request authenticator"""
        return secrets.token_bytes(16)

    def _encrypt_password(self, password: str, authenticator: bytes) -> bytes:
        """
        Encrypt password using shared secret (RFC 2865 Section 5.2)

        Password is XORed with MD5 hash of (secret + authenticator)
        """
        pw_bytes = password.encode("utf-8")

        # Pad to 16-byte boundary
        if len(pw_bytes) % 16:
            pw_bytes += b"\x00" * (16 - len(pw_bytes) % 16)

        # Encrypt in 16-byte chunks
        encrypted = b""
        prev = authenticator

        for i in range(0, len(pw_bytes), 16):
            hash_input = self.radius_secret + prev
            hash_val = hashlib.md5(hash_input).digest()
            chunk = bytes(a ^ b for a, b in zip(pw_bytes[i : i + 16], hash_val))
            encrypted += chunk
            prev = chunk

        return encrypted

    def _add_attribute(self, attr_type: int, value: bytes) -> bytes:
        """Add RADIUS attribute (Type-Length-Value format)"""
        length = 2 + len(value)
        return struct.pack("!BB", attr_type, length) + value

    def _create_request(
        self, username: str, password: str, authenticator: bytes
    ) -> tuple[bytes, int]:
        """Create RADIUS Access-Request packet"""
        # Build attributes
        attributes = b""

        # User-Name attribute
        attributes += self._add_attribute(self.USER_NAME, username.encode("utf-8"))

        # User-Password attribute (encrypted)
        encrypted_pw = self._encrypt_password(password, authenticator)
        attributes += self._add_attribute(self.USER_PASSWORD, encrypted_pw)

        # NAS-IP-Address attribute
        try:
            nas_ip_bytes = socket.inet_aton(self.radius_nas_ip)
            attributes += self._add_attribute(self.NAS_IP_ADDRESS, nas_ip_bytes)
        except OSError:
            logger.warning(f"Invalid NAS IP: {self.radius_nas_ip}")

        # NAS-Port attribute
        attributes += self._add_attribute(self.NAS_PORT, struct.pack("!I", 0))  # Port 0

        # Service-Type attribute (Login = 1)
        attributes += self._add_attribute(self.SERVICE_TYPE, struct.pack("!I", 1))

        # NAS-Identifier attribute (optional)
        if self.radius_nas_identifier:
            attributes += self._add_attribute(
                self.NAS_IDENTIFIER, self.radius_nas_identifier.encode("utf-8")
            )

        # Create packet header
        identifier = secrets.randbelow(256)
        length = 20 + len(attributes)
        header = struct.pack("!BBH", self.ACCESS_REQUEST, identifier, length)

        return header + authenticator + attributes, identifier

    def _verify_response(self, response: bytes, request_auth: bytes) -> bool:
        """Verify response authenticator (RFC 2865 Section 3)"""
        if len(response) < 20:
            return False

        # Extract response authenticator
        resp_auth = response[4:20]

        # Calculate expected authenticator
        # MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
        data = response[:4] + request_auth + response[20:] + self.radius_secret
        expected = hashlib.md5(data).digest()

        return resp_auth == expected

    def _parse_attributes(self, data: bytes) -> dict[int, list[bytes]]:
        """Parse RADIUS attributes from response packet"""
        attributes: dict[int, list[bytes]] = {}
        offset = 0

        while offset < len(data):
            if offset + 2 > len(data):
                break

            attr_type = data[offset]
            attr_len = data[offset + 1]

            if offset + attr_len > len(data) or attr_len < 2:
                break

            value = data[offset + 2 : offset + attr_len]

            if attr_type not in attributes:
                attributes[attr_type] = []
            attributes[attr_type].append(value)

            offset += attr_len

        return attributes

    def _extract_groups(self, attributes: dict[int, list[bytes]]) -> list[str]:
        """
        Extract group names from RADIUS attributes

        Groups can be in:
        - Filter-Id (attribute 11)
        - Class (attribute 25) with "group:" prefix
        """
        groups = []

        # Extract from Filter-Id attributes
        if self.FILTER_ID in attributes:
            for value in attributes[self.FILTER_ID]:
                try:
                    group_name = value.decode("utf-8", errors="ignore").strip()
                    if group_name:
                        groups.append(group_name)
                except Exception as e:
                    logger.warning("Failed to decode RADIUS Filter-Id attribute: %s", e)

        # Extract from Class attributes
        if self.CLASS in attributes:
            for value in attributes[self.CLASS]:
                try:
                    class_str = value.decode("utf-8", errors="ignore").strip()
                    # Check for "group:" prefix
                    if class_str.lower().startswith("group:"):
                        group_name = class_str[6:].strip()
                        if group_name:
                            groups.append(group_name)
                except Exception as e:
                    logger.warning("Failed to decode RADIUS Class attribute: %s", e)

        return groups

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        """Authenticate user against RADIUS server and cache groups for authorization."""
        ok, groups = self._authenticate_and_cache_groups(username, password)
        if ok:
            # Cache already stored in helper, but ensure attribute present
            try:
                setattr(self, f"_cached_groups_{username}", groups or [])
            except Exception:
                pass
        return ok

    def get_user_attributes(self, username: str) -> dict[str, Any]:
        """
        Get user attributes from RADIUS

        Note: RADIUS doesn't support querying without authentication.
        Groups are cached during authentication.
        """
        # RADIUS requires authentication to get attributes
        # Return cached data if available, otherwise empty
        cached_groups = getattr(self, f"_cached_groups_{username}", [])

        return {
            "service": "exec",
            "groups": cached_groups,
            "enabled": True,
        }

    def _authenticate_and_cache_groups(
        self, username: str, password: str
    ) -> tuple[bool, list[str]]:
        """Authenticate and extract groups from response"""
        if not username or not password:
            return False, []

        authenticator = self._create_authenticator()
        request, identifier = self._create_request(username, password, authenticator)

        # Send request with retries
        for attempt in range(self.radius_retries):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.radius_timeout)
                    sock.sendto(request, (self.radius_server, self.radius_port))

                    response, _ = sock.recvfrom(4096)

                if len(response) < 20:
                    logger.warning("RADIUS response too short")
                    continue

                code = response[0]
                resp_id = response[1]

                if resp_id != identifier:
                    logger.debug(
                        "RADIUS response ID mismatch (got %d expected %d)",
                        resp_id,
                        identifier,
                    )
                    continue

                if not self._verify_response(response, authenticator):
                    logger.warning("RADIUS authenticator verification failed")
                    continue

                if code == self.ACCESS_ACCEPT:
                    # Parse attributes to extract groups
                    attributes = self._parse_attributes(response[20:])
                    groups = self._extract_groups(attributes)

                    # Cache groups for this user
                    try:
                        setattr(self, f"_cached_groups_{username}", groups)
                    except Exception:
                        pass

                    logger.info(
                        f"RADIUS authentication successful for {username}, groups: {groups}"
                    )
                    return True, groups

                elif code == self.ACCESS_REJECT:
                    logger.info(f"RADIUS authentication rejected for {username}")
                    return False, []

            except TimeoutError:
                logger.warning(
                    f"RADIUS timeout (attempt {attempt + 1}/{self.radius_retries})"
                )
                continue
            except Exception as e:
                logger.error(f"RADIUS communication error: {e}")
                continue

        return False, []

    def is_available(self) -> bool:
        """Check if RADIUS server is reachable"""
        try:
            # Try to connect to RADIUS server
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.connect((self.radius_server, self.radius_port))
            sock.close()
            return True
        except (OSError, TimeoutError):
            return False

    def get_stats(self) -> dict[str, Any]:
        """Get backend statistics"""
        return {
            "radius_server": self.radius_server,
            "radius_port": self.radius_port,
            "radius_timeout": self.radius_timeout,
            "radius_retries": self.radius_retries,
            "radius_nas_ip": self.radius_nas_ip,
            "available": self.is_available(),
        }
