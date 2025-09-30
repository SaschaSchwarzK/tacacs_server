"""
RADIUS Server Implementation

Provides a complete RADIUS server that shares authentication backends with TACACS+.
Supports Authentication and Accounting (Authorization is TACACS+ specific).

RFC 2865 - Remote Authentication Dial In User Service (RADIUS)
RFC 2866 - RADIUS Accounting
"""

import socket
import hashlib
import struct
import secrets
import logging
import threading
import time
import ipaddress
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from tacacs_server.auth.base import AuthenticationBackend
from tacacs_server.utils.policy import PolicyContext, PolicyResult, evaluate_policy

logger = logging.getLogger(__name__)

# RADIUS Packet Codes
RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCOUNTING_REQUEST = 4
RADIUS_ACCOUNTING_RESPONSE = 5
RADIUS_ACCESS_CHALLENGE = 11

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
        return struct.pack('BB', self.attr_type, length) + self.value
    
    @classmethod
    def unpack(cls, data: bytes) -> Tuple['RADIUSAttribute', int]:
        """Unpack attribute from bytes"""
        if len(data) < 2:
            raise ValueError("Incomplete attribute header")
        
        attr_type, length = struct.unpack('BB', data[:2])
        if length < 2 or length > len(data):
            raise ValueError(f"Invalid attribute length: {length}")
        
        value = data[2:length]
        return cls(attr_type, value), length
    
    def as_string(self) -> str:
        """Get value as string"""
        return self.value.decode('utf-8', errors='replace')
    
    def as_int(self) -> int:
        """Get value as integer"""
        if len(self.value) == 4:
            return struct.unpack('!I', self.value)[0]
        raise ValueError("Attribute is not an integer")
    
    def as_ipaddr(self) -> str:
        """Get value as IP address"""
        if len(self.value) == 4:
            return '.'.join(str(b) for b in self.value)
        raise ValueError("Attribute is not an IP address")


class RADIUSPacket:
    """RADIUS packet structure"""
    
    def __init__(self, code: int, identifier: int, authenticator: bytes,
                 attributes: Optional[List[RADIUSAttribute]] = None):
        self.code = code
        self.identifier = identifier
        self.authenticator = authenticator  # 16 bytes
        self.attributes = attributes or []
    
    def pack(self, secret: bytes = None, request_auth: bytes = None) -> bytes:
        """Pack RADIUS packet into bytes"""
        # Pack attributes
        attrs_data = b''.join(attr.pack() for attr in self.attributes)
        
        # Calculate length
        length = 20 + len(attrs_data)
        
        # Pack header
        header = struct.pack('!BBH', self.code, self.identifier, length)
        
        # Calculate authenticator for response packets
        if secret and request_auth and self.code != RADIUS_ACCESS_REQUEST:
            # Response Authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
            data = header + request_auth + attrs_data + secret
            authenticator = hashlib.md5(data).digest()
        else:
            authenticator = self.authenticator
        
        packet = header + authenticator + attrs_data
        return packet


    @classmethod
    def unpack(cls, data: bytes, secret: bytes = None) -> 'RADIUSPacket':
        """Unpack RADIUS packet from bytes"""
        if len(data) < 20:
            raise ValueError(f"Packet too short: {len(data)} bytes")
        
        # Parse header
        code, identifier, length = struct.unpack('!BBH', data[:4])
        
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
        """Decrypt User-Password attribute"""
        for i, attr in enumerate(self.attributes):
            if attr.attr_type == ATTR_USER_PASSWORD:
                # Password is encrypted: c(1) = p(1) XOR MD5(secret + authenticator)
                # c(n) = p(n) XOR MD5(secret + c(n-1))
                encrypted = attr.value
                if len(encrypted) % 16 != 0:
                    logger.warning("Invalid encrypted password length")
                    continue
                
                decrypted = b''
                prev = self.authenticator
                
                for j in range(0, len(encrypted), 16):
                    chunk = encrypted[j:j+16]
                    hash_input = secret + prev
                    key = hashlib.md5(hash_input).digest()
                    decrypted_chunk = bytes(a ^ b for a, b in zip(chunk, key))
                    decrypted += decrypted_chunk
                    prev = chunk
                
                # Remove padding (null bytes at the end)
                decrypted = decrypted.rstrip(b'\x00')
                self.attributes[i] = RADIUSAttribute(ATTR_USER_PASSWORD, decrypted)
    
    def add_attribute(self, attr_type: int, value: bytes):
        """Add attribute to packet"""
        self.attributes.append(RADIUSAttribute(attr_type, value))
    
    def add_string(self, attr_type: int, value: str):
        """Add string attribute"""
        self.add_attribute(attr_type, value.encode('utf-8'))
    
    def add_integer(self, attr_type: int, value: int):
        """Add integer attribute"""
        self.add_attribute(attr_type, struct.pack('!I', value))
    
    def add_ipaddr(self, attr_type: int, ip: str):
        """Add IP address attribute"""
        parts = [int(p) for p in ip.split('.')]
        self.add_attribute(attr_type, bytes(parts))
    
    def get_attribute(self, attr_type: int) -> Optional[RADIUSAttribute]:
        """Get first attribute of given type"""
        for attr in self.attributes:
            if attr.attr_type == attr_type:
                return attr
        return None
    
    def get_string(self, attr_type: int) -> Optional[str]:
        """Get string attribute value"""
        attr = self.get_attribute(attr_type)
        return attr.as_string() if attr else None
    
    def get_integer(self, attr_type: int) -> Optional[int]:
        """Get integer attribute value"""
        attr = self.get_attribute(attr_type)
        try:
            return attr.as_int() if attr else None
        except ValueError:
            return None
    
    def __str__(self) -> str:
        """String representation for debugging"""
        code_names = {
            1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject",
            4: "Accounting-Request", 5: "Accounting-Response", 11: "Access-Challenge"
        }
        return f"RADIUSPacket(code={code_names.get(self.code, self.code)}, id={self.identifier}, attrs={len(self.attributes)})"


@dataclass
class RadiusClient:
    """Resolved RADIUS client configuration (single host or network)."""

    network: ipaddress._BaseNetwork
    secret: str
    name: str
    group: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    allowed_user_groups: List[str] = field(default_factory=list)

    def contains(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return ip_obj in self.network

    @property
    def secret_bytes(self) -> bytes:
        return self.secret.encode('utf-8')


class RADIUSServer:
    """RADIUS Server implementation"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 1812,
                 accounting_port: int = 1813, secret: str = 'radius123'):
        self.host = host
        self.port = port
        self.accounting_port = accounting_port
        self.secret = secret.encode('utf-8')
        
        self.auth_backends = []
        self.accounting_logger = None
        self.device_store = None
        self.local_user_group_service = None
        
        self.running = False
        self.auth_socket = None
        self.acct_socket = None
        
        # Statistics
        self.stats = {
            'auth_requests': 0,
            'auth_accepts': 0,
            'auth_rejects': 0,
            'acct_requests': 0,
            'acct_responses': 0,
            'invalid_packets': 0
        }
        
        # Client configuration (RADIUS client devices)
        self._client_lock = threading.RLock()
        self.clients: List[RadiusClient] = []

    def add_auth_backend(self, backend):
        """Add authentication backend (shared with TACACS+)"""
        self.auth_backends.append(backend)
        logger.info(f"RADIUS: Added authentication backend: {backend.name}")

    def set_accounting_logger(self, accounting_logger):
        """Set accounting logger (shared with TACACS+)"""
        self.accounting_logger = accounting_logger
        logger.info("RADIUS: Accounting logger configured")

    def set_local_user_group_service(self, service) -> None:
        self.local_user_group_service = service

    def add_client(
        self,
        network: str,
        secret: str,
        name: Optional[str] = None,
        *,
        group: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        allowed_user_groups: Optional[List[str]] = None,
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

    def load_clients(self, clients: List['RadiusClient']) -> None:
        """Replace current clients with pre-built entries (e.g. from DeviceStore)."""
        with self._client_lock:
            self.clients = sorted(clients, key=lambda entry: entry.network.prefixlen, reverse=True)
        logger.info("RADIUS: Loaded %d client definitions", len(clients))

    def refresh_clients(self, client_configs) -> None:
        """Rebuild client list from iterable configs (network, secret, etc.)."""
        new_clients: List[RadiusClient] = []
        for cfg in client_configs:
            try:
                network = getattr(cfg, "network")
                secret = getattr(cfg, "secret")
                name = getattr(cfg, "name", str(network))
                group = getattr(cfg, "group", None)
                attributes = dict(getattr(cfg, "attributes", {}) or {})
                allowed_user_groups = list(getattr(cfg, "allowed_user_groups", []) or [])
            except AttributeError as exc:
                logger.warning("RADIUS: Skipping invalid client config %s: %s", cfg, exc)
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
            self.clients = sorted(new_clients, key=lambda entry: entry.network.prefixlen, reverse=True)
        logger.info("RADIUS: Refreshed %d client definitions", len(new_clients))

    def lookup_client(self, ip: str) -> Optional['RadiusClient']:
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
        
        # Start authentication server
        auth_thread = threading.Thread(
            target=self._start_auth_server,
            daemon=True,
            name="RADIUS-Auth"
        )
        auth_thread.start()
        
        # Start accounting server
        acct_thread = threading.Thread(
            target=self._start_acct_server,
            daemon=True,
            name="RADIUS-Acct"
        )
        acct_thread.start()
        
        logger.debug("RADIUS server started on %s:%s (auth) and %s (acct)", self.host, self.port, self.accounting_port)
    
    def stop(self):
        """Stop RADIUS server"""
        self.running = False
        
        if self.auth_socket:
            self.auth_socket.close()
        if self.acct_socket:
            self.acct_socket.close()
        
        logger.info("RADIUS server stopped")
    
    def _start_auth_server(self):
        """Start authentication server thread"""
        try:
            self.auth_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.auth_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.auth_socket.bind((self.host, self.port))
            self.auth_socket.settimeout(1.0)
            
            logger.debug("RADIUS authentication server listening on %s:%s", self.host, self.port)
            
            while self.running:
                try:
                    data, addr = self.auth_socket.recvfrom(4096)
                    # Handle in separate thread to not block
                    threading.Thread(
                        target=self._handle_auth_request,
                        args=(data, addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"RADIUS auth server error: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Failed to start RADIUS auth server: {e}")
        finally:
            if self.auth_socket:
                self.auth_socket.close()
    
    def _start_acct_server(self):
        """Start accounting server thread"""
        try:
            self.acct_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.acct_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.acct_socket.bind((self.host, self.accounting_port))
            self.acct_socket.settimeout(1.0)
            
            logger.debug("RADIUS accounting server listening on %s:%s", self.host, self.accounting_port)
            
            while self.running:
                try:
                    data, addr = self.acct_socket.recvfrom(4096)
                    # Handle in separate thread
                    threading.Thread(
                        target=self._handle_acct_request,
                        args=(data, addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"RADIUS acct server error: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Failed to start RADIUS acct server: {e}")
        finally:
            if self.acct_socket:
                self.acct_socket.close()
    
    def _handle_auth_request(self, data: bytes, addr: Tuple[str, int]):
        """Handle authentication request"""
        client_ip, client_port = addr

        try:
            client_config = self.lookup_client(client_ip)
            if not client_config:
                logger.warning("RADIUS auth request from unknown client: %s", client_ip)
                self.stats['invalid_packets'] += 1
                return

            client_secret = client_config.secret_bytes

            # Parse request
            request = RADIUSPacket.unpack(data, client_secret)

            if request.code != RADIUS_ACCESS_REQUEST:
                logger.warning("Unexpected packet code in auth port: %s", request.code)
                return

            self.stats['auth_requests'] += 1

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
                self._send_response(response, addr, client_secret, request.authenticator)
                return

            logger.debug(
                "RADIUS auth request: user=%s from %s (matched %s)",
                username or '<unknown>',
                client_ip,
                client_config.network,
            )

            # Authenticate against backends
            authenticated, auth_detail = self._authenticate_user(username, password)

            device_label = client_config.group or client_config.name or str(client_config.network)

            if authenticated:
                # Get user attributes for response
                user_attrs = self._get_user_attributes(username)
                allowed, denial_message = self._apply_user_group_policy(client_config, user_attrs)
                if allowed:
                    response = self._create_access_accept(request, user_attrs)
                    self.stats['auth_accepts'] += 1
                    logger.info(
                        "RADIUS authentication success: user=%s detail=%s device=%s",
                        username,
                        auth_detail,
                        device_label,
                    )
                    try:
                        from ..web.monitoring import PrometheusIntegration
                        PrometheusIntegration.record_radius_auth('accept')
                    except Exception:
                        pass
                else:
                    response = self._create_access_reject(request, denial_message)
                    self.stats['auth_rejects'] += 1
                    logger.warning(
                        "RADIUS authentication failed: user=%s reason=%s device=%s",
                        username,
                        f'policy_denied={denial_message}',
                        device_label,
                    )
                    try:
                        from ..web.monitoring import PrometheusIntegration
                        PrometheusIntegration.record_radius_auth('reject')
                    except Exception:
                        pass
            else:
                response = self._create_access_reject(request, "Authentication failed")
                self.stats['auth_rejects'] += 1
                logger.warning(
                    "RADIUS authentication failed: user=%s reason=%s device=%s",
                    username,
                    auth_detail or "no backend accepted credentials",
                    device_label,
                )
                try:
                    from ..web.monitoring import PrometheusIntegration
                    PrometheusIntegration.record_radius_auth('reject')
                except Exception:
                    pass

            # Send response
            self._send_response(response, addr, client_secret, request.authenticator)

        except Exception as e:
            logger.error("Error handling RADIUS auth request from %s: %s", client_ip, e)
            self.stats['invalid_packets'] += 1

    def _handle_acct_request(self, data: bytes, addr: Tuple[str, int]):
        """Handle accounting request"""
        client_ip, client_port = addr

        try:
            client_config = self.lookup_client(client_ip)
            if not client_config:
                logger.warning("RADIUS acct request from unknown client: %s", client_ip)
                return

            client_secret = client_config.secret_bytes

            # Parse request
            request = RADIUSPacket.unpack(data, client_secret)

            if request.code != RADIUS_ACCOUNTING_REQUEST:
                logger.warning("Unexpected packet code in acct port: %s", request.code)
                return

            self.stats['acct_requests'] += 1

            # Extract accounting info
            username = request.get_string(ATTR_USER_NAME)
            session_id = request.get_string(ATTR_ACCT_SESSION_ID)
            status_type = request.get_integer(ATTR_ACCT_STATUS_TYPE)

            status_names = {
                1: "START", 2: "STOP", 3: "UPDATE",
                7: "ACCOUNTING-ON", 8: "ACCOUNTING-OFF"
            }
            status_name = status_names.get(status_type, f"UNKNOWN({status_type})")

            logger.info(
                "RADIUS accounting: %s session %s - %s (matched %s)",
                username,
                session_id,
                status_name,
                client_config.network,
            )

            # Log to accounting database if available
            if self.accounting_logger:
                self._log_accounting(request, client_ip)

            # Send response
            response = RADIUSPacket(
                code=RADIUS_ACCOUNTING_RESPONSE,
                identifier=request.identifier,
                authenticator=bytes(16)  # Will be calculated in pack()
            )

            self._send_response(response, addr, client_secret, request.authenticator)
            self.stats['acct_responses'] += 1

        except Exception as e:
            logger.error("Error handling RADIUS acct request from %s: %s", client_ip, e)
    
    def _authenticate_user(self, username: str, password: str) -> tuple[bool, str]:
        """Authenticate user against backends with diagnostic detail."""
        if not self.auth_backends:
            return False, 'no authentication backends configured'

        last_error: Optional[str] = None
        for backend in self.auth_backends:
            try:
                if backend.authenticate(username, password):
                    logger.debug(f"RADIUS: Authentication successful via {backend.name}")
                    return True, f'backend={backend.name}'
            except Exception as e:
                message = f'backend={backend.name} error={e}'
                logger.error(f"RADIUS: {message}")
                last_error = message

        if last_error:
            return False, last_error

        return False, 'no backend accepted credentials'
    
    def _get_user_attributes(self, username: str) -> Dict[str, Any]:
        """Get user attributes from backends"""
        for backend in self.auth_backends:
            try:
                attrs = backend.get_user_attributes(username)
                if attrs:
                    return attrs
            except Exception as e:
                logger.error(f"Error getting attributes from {backend.name}: {e}")
        
        return {}

    def _apply_user_group_policy(self, client: RadiusClient, user_attrs: Dict[str, Any]) -> tuple[bool, str]:
        context = PolicyContext(
            device_group_name=getattr(client, "group", None),
            allowed_user_groups=getattr(client, "allowed_user_groups", []),
            user_groups=user_attrs.get('groups', []) or [],
            fallback_privilege=user_attrs.get('privilege_level', 1),
        )

        def _lookup_privilege(group_name: str) -> Optional[int]:
            if not self.local_user_group_service:
                return None
            record = self.local_user_group_service.get_group(group_name)
            return getattr(record, 'privilege_level', None)

        result: PolicyResult = evaluate_policy(context, _lookup_privilege)
        user_attrs['privilege_level'] = result.privilege_level
        return result.allowed, result.denial_message
    
    def _create_access_accept(self, request: RADIUSPacket, 
                            user_attrs: Dict[str, Any]) -> RADIUSPacket:
        """Create Access-Accept response"""
        response = RADIUSPacket(
            code=RADIUS_ACCESS_ACCEPT,
            identifier=request.identifier,
            authenticator=bytes(16)  # Will be calculated in pack()
        )
        
        # Add Reply-Message
        response.add_string(ATTR_REPLY_MESSAGE, "Authentication successful")
        
        # Add Service-Type
        response.add_integer(ATTR_SERVICE_TYPE, SERVICE_TYPE_ADMINISTRATIVE)
        
        # Add Session-Timeout if specified
        if 'session_timeout' in user_attrs:
            response.add_integer(ATTR_SESSION_TIMEOUT, user_attrs['session_timeout'])
        
        # Add Idle-Timeout if specified
        if 'idle_timeout' in user_attrs:
            response.add_integer(ATTR_IDLE_TIMEOUT, user_attrs['idle_timeout'])
        
        # Add Class attribute (can be used for tracking)
        privilege_level = user_attrs.get('privilege_level', 1)
        response.add_string(ATTR_CLASS, f"priv{privilege_level}")
        
        return response
    
    def _create_access_reject(self, request: RADIUSPacket, 
                            message: str = "Authentication failed") -> RADIUSPacket:
        """Create Access-Reject response"""
        response = RADIUSPacket(
            code=RADIUS_ACCESS_REJECT,
            identifier=request.identifier,
            authenticator=bytes(16)
        )
        
        response.add_string(ATTR_REPLY_MESSAGE, message)
        
        return response
    
    def _send_response(self, response: RADIUSPacket, addr: Tuple[str, int],
                      secret: bytes, request_auth: bytes):
        """Send RADIUS response"""
        try:
            packet_data = response.pack(secret, request_auth)
            
            if response.code == RADIUS_ACCESS_ACCEPT or response.code == RADIUS_ACCESS_REJECT:
                self.auth_socket.sendto(packet_data, addr)
            else:
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
                ACCT_STATUS_INTERIM_UPDATE: "UPDATE"
            }
            status = status_map.get(status_type, "UNKNOWN")
            
            # Try to parse session ID as integer
            try:
                session_id = int(session_id_str) if session_id_str.isdigit() else hash(session_id_str) & 0xFFFFFFFF
            except:
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
                elapsed_time=request.get_integer(ATTR_ACCT_SESSION_TIME) or 0
            )
            
            self.accounting_logger.log_accounting(record)
            
        except Exception as e:
            logger.error(f"Error logging RADIUS accounting: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics"""
        return {
            'auth_requests': self.stats['auth_requests'],
            'auth_accepts': self.stats['auth_accepts'],
            'auth_rejects': self.stats['auth_rejects'],
            'auth_success_rate': (self.stats['auth_accepts'] / self.stats['auth_requests'] * 100) 
                if self.stats['auth_requests'] > 0 else 0,
            'acct_requests': self.stats['acct_requests'],
            'acct_responses': self.stats['acct_responses'],
            'invalid_packets': self.stats['invalid_packets'],
            'configured_clients': len(self.clients),
            'running': self.running
        }
