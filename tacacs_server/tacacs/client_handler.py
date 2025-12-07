"""Client connection handler"""

import logging
import socket

from tacacs_server.tacacs.constants import (
    TAC_PLUS_ACCT_STATUS,
    TAC_PLUS_AUTHEN_STATUS,
    TAC_PLUS_AUTHOR_STATUS,
    TAC_PLUS_FLAGS,
    TAC_PLUS_HEADER_SIZE,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.utils.logger import bind_context, clear_context, get_logger
from tacacs_server.utils.rate_limiter import get_rate_limiter

from .network import NetworkHandler
from .proxy import ProxyHandler

logger = get_logger(__name__)


class ClientHandler:
    """Handles individual client connections"""

    def __init__(
        self,
        handlers,
        session_manager,
        stats_manager,
        validator,
        conn_limiter,
        device_store=None,
        proxy_handler: ProxyHandler | None = None,
        proxy_reject_invalid: bool = True,
        default_secret: str = "CHANGE_ME_FALLBACK", # nosec
        encryption_required: bool = True,
        client_timeout: float = 15.0,
        device_auto_register: bool = False,
        default_device_group: str = "default",
    ):
        self.handlers = handlers
        self.session_manager = session_manager
        self.stats = stats_manager
        self.validator = validator
        self.conn_limiter = conn_limiter
        self.device_store = device_store
        self.proxy_handler = proxy_handler
        self.proxy_reject_invalid = proxy_reject_invalid
        self.default_secret = default_secret
        self.encryption_required = encryption_required
        self.client_timeout = client_timeout
        self.device_auto_register = device_auto_register
        self.default_device_group = default_device_group

    def handle(self, client_socket: socket.socket, address: tuple[str, int]):
        """Handle client connection"""
        ctx_token = bind_context(
            client_ip=address[0],
            client_port=address[1],
            service="tacacs",
        )
        conn_logger = self._create_logger(address)
        session_ids: set[int] = set()
        client_ip = address[0]
        proxy_ip: str | None = None
        connection_device = None

        # Parse PROXY protocol header
        first_header_data, client_ip, proxy_ip = self._handle_proxy_protocol(
            client_socket, address, conn_logger
        )

        if first_header_data is None:
            return

        # Help type checkers: first_header_data is non-None beyond this point
        assert first_header_data is not None

        # Validate proxy source
        if not self._validate_proxy(proxy_ip, address, conn_logger):
            return

        # Record connection type
        self.stats.record_connection_type(proxy_ip is not None)

        # Secondary rate limiting - request rate limiting (not connection limiting)
        # This is DIFFERENT from the per-IP connection limit in the accept loop
        # This limits the rate of requests/packets, not concurrent connections
        rate_limiter = get_rate_limiter()
        if not rate_limiter.allow_request(client_ip):
            conn_logger.warning("TACACS rate limit exceeded for %s", client_ip)
            NetworkHandler.safe_close_socket(client_socket)
            return

        # Resolve device
        connection_device = self._resolve_device(client_ip, proxy_ip, conn_logger)
        if connection_device is None and not self.device_auto_register:
            conn_logger.warning(
                "Unknown device %s and auto_register disabled; closing connection",
                client_ip,
            )
            NetworkHandler.safe_close_socket(client_socket)
            return

        # Process packets
        try:
            client_socket.settimeout(self.client_timeout)
            self._process_packets(
                client_socket,
                address,
                first_header_data,
                connection_device,
                session_ids,
                conn_logger,
            )
        except Exception as e:
            conn_logger.error("Client handling error %s: %s", address, e)
        finally:
            clear_context(ctx_token)
            NetworkHandler.safe_close_socket(client_socket)
            self.session_manager.cleanup_sessions(session_ids, self.handlers)
            # Note: conn_limiter.release() and stats.update_active_connections(-1)
            # are handled in server.py's _handle_client_wrapper to ensure they
            # always execute even if handle() raises an exception early
            conn_logger.debug("Connection closed: %s", address)

    def _create_logger(self, address: tuple[str, int]):
        """Create contextual logger for connection"""
        try:
            extra: dict[str, object] = {
                "client_ip": address[0],
                "client_port": address[1],
            }
            return logging.LoggerAdapter(logger, extra)
        except Exception:
            return logger

    def _handle_proxy_protocol(
        self, client_socket: socket.socket, address: tuple[str, int], conn_logger
    ) -> tuple[bytes | None, str, str | None]:
        """Handle PROXY protocol v2 header parsing"""
        client_ip = address[0]
        proxy_ip: str | None = None
        first_header_data: bytes | None = b""

        if self.proxy_handler is None:
            first_header_data = NetworkHandler.recv_exact(client_socket, 12)
            return first_header_data, client_ip, proxy_ip

        try:
            first12 = NetworkHandler.recv_exact(client_socket, 12)
            if not first12:
                return None, client_ip, proxy_ip

            info, consumed, buffered = self.proxy_handler.parse_proxy_header(
                first12, lambda n: NetworkHandler.recv_exact(client_socket, n)
            )

            if info and consumed > 0:
                self.stats.increment("proxy_headers_parsed")
                if hasattr(info, "is_proxied") and info.is_proxied:
                    if hasattr(info, "src_addr"):
                        client_ip = info.src_addr
                        proxy_ip = address[0]
                        conn_logger.debug(
                            "Using proxied identity: client_ip=%s, proxy_ip=%s",
                            client_ip,
                            proxy_ip,
                        )
                recv_data = NetworkHandler.recv_exact(client_socket, 12)
                first_header_data = recv_data if recv_data is not None else b""
            elif consumed == 0 and first12.startswith(
                b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
            ):
                self.stats.increment("proxy_header_errors")
                # Only hard-reject invalid headers when strict validation is enabled
                if self.proxy_reject_invalid and getattr(
                    self.proxy_handler, "validate_sources", False
                ):
                    conn_logger.debug(
                        "Invalid PROXY v2 header, rejecting connection",
                        event="tacacs.proxy.invalid_header",
                        proxy_enabled=self.proxy_reject_invalid,
                    )
                    return None, client_ip, proxy_ip
                else:
                    conn_logger.debug(
                        "Invalid PROXY v2 header, reading fresh TACACS header",
                        event="tacacs.proxy.invalid_header",
                        proxy_enabled=self.proxy_reject_invalid,
                    )
                    recv_data = NetworkHandler.recv_exact(client_socket, 12)
                    first_header_data = recv_data if recv_data is not None else b""
            else:
                first_header_data = first12

        except Exception as e:
            self.stats.increment("proxy_header_errors")
            # Only hard-reject on parse error when strict validation is enabled
            if self.proxy_reject_invalid and getattr(
                self.proxy_handler, "validate_sources", False
            ):
                conn_logger.debug(
                    "PROXY parse error and reject_invalid set; closing",
                    event="tacacs.proxy.parse_error",
                    error=str(e),
                    proxy_enabled=self.proxy_reject_invalid,
                )
                return None, client_ip, proxy_ip
            conn_logger.debug(
                "PROXY parse error; proceeding as direct",
                event="tacacs.proxy.parse_error",
                error=str(e),
                proxy_enabled=self.proxy_reject_invalid,
            )
            recv_data = NetworkHandler.recv_exact(client_socket, 12)
            first_header_data = recv_data if recv_data is not None else b""

        return first_header_data, client_ip, proxy_ip

    def _validate_proxy(
        self, proxy_ip: str | None, address: tuple[str, int], conn_logger
    ) -> bool:
        """Validate proxy source IP"""
        if proxy_ip is None or self.proxy_handler is None:
            return True

        allowed = self.proxy_handler.validate_proxy_source(proxy_ip)
        if not allowed:
            self.stats.increment("proxy_rejected_unknown")
            conn_logger.error(
                "Rejecting proxied connection from %s: proxy IP %s not in configured proxy networks",
                address[0],
                proxy_ip,
            )
            return False

        conn_logger.debug("Proxy IP %s validated successfully", proxy_ip)
        return True

    def _resolve_device(self, client_ip: str, proxy_ip: str | None, conn_logger):
        """Resolve device from IP"""
        if not self.device_store:
            return None

        try:
            if proxy_ip is not None:
                conn_logger.debug(
                    "Resolving device for proxied connection",
                    event="tacacs.device.resolve",
                    client_ip=client_ip,
                    proxy_ip=proxy_ip,
                )
                device = self.device_store.find_device_for_identity(client_ip, proxy_ip)
            else:
                device = self.device_store.find_device_for_ip(client_ip)

            if device:
                conn_logger.debug(
                    "Device resolved",
                    event="tacacs.device.resolved",
                    device_name=device.name,
                    device_group=device.group.name if device.group else None,
                )
                return device

            conn_logger.debug("No device found for client_ip=%s", client_ip)

            if self.device_auto_register:
                return self._auto_register_device(client_ip, proxy_ip, conn_logger)

        except Exception as exc:
            logger.warning("Failed to resolve device for %s: %s", client_ip, exc)

        return None

    def _auto_register_device(self, client_ip: str, proxy_ip: str | None, conn_logger):
        """Auto-register unknown device"""
        try:
            cidr = f"{client_ip}/{'128' if ':' in client_ip else '32'}"
            name = f"auto-{client_ip.replace(':', '_')}"
            self.device_store.ensure_device(
                name=name, network=cidr, group=self.default_device_group
            )

            if proxy_ip is not None:
                device = self.device_store.find_device_for_identity(client_ip, proxy_ip)
            else:
                device = self.device_store.find_device_for_ip(client_ip)

            if device:
                conn_logger.info(
                    "Auto-registered device %s in group %s",
                    device.name,
                    self.default_device_group,
                )
            return device
        except Exception as exc:
            conn_logger.warning("Auto-registration failed for %s: %s", client_ip, exc)
            return None

    def _process_packets(
        self,
        client_socket: socket.socket,
        address: tuple[str, int],
        first_header_data: bytes,
        connection_device,
        session_ids: set[int],
        conn_logger,
    ):
        """Process packets from client"""
        first_packet = True

        while True:
            try:
                # Get header
                if first_packet and first_header_data:
                    header_data = first_header_data
                    first_packet = False
                else:
                    _maybe = NetworkHandler.recv_exact(
                        client_socket, TAC_PLUS_HEADER_SIZE
                    )
                    if _maybe is None:
                        break
                    header_data = _maybe

                # Unpack header
                packet = self._unpack_header(header_data, conn_logger, address)
                if packet is None:
                    break

                session_ids.add(packet.session_id)

                # Enrich logger with session ID
                conn_logger = self._enrich_logger(conn_logger, packet.session_id)

                # Validate
                if not self._validate_and_read_body(
                    client_socket, packet, connection_device, conn_logger, address
                ):
                    break

                # Process and respond
                response = self._process_and_respond(
                    packet, address, connection_device, conn_logger
                )

                if response:
                    secret = self.session_manager.get_or_create_secret(
                        packet.session_id, connection_device, self.default_secret
                    )
                    response_data = response.pack(secret)
                    client_socket.send(response_data)

                    if response.flags & TAC_PLUS_FLAGS.TAC_PLUS_SINGLE_CONNECT_FLAG:
                        break

            except TimeoutError:
                conn_logger.debug("Client timeout: %s", address)
                break
            except OSError as e:
                conn_logger.debug("Client socket error %s: %s", address, e)
                break
            except Exception as e:
                conn_logger.error("Error handling client %s: %s", address, e)
                break

    def _unpack_header(self, header_data: bytes, conn_logger, address):
        """Unpack packet header"""
        try:
            return TacacsPacket.unpack_header(
                header_data, max_length=self.validator.max_packet_length
            )
        except Exception as e:
            conn_logger.warning(
                "Invalid packet header",
                event="tacacs.packet.header_error",
                client_ip=address[0],
                reason=str(e),
                packet_length=len(header_data),
            )
            return None

    def _enrich_logger(self, conn_logger, session_id: int):
        """Enrich logger with session ID"""
        try:
            if isinstance(conn_logger, logging.LoggerAdapter):
                base_extra = getattr(conn_logger, "extra", {}) or {}
                new_extra = dict(base_extra)
                new_extra["session_id"] = f"0x{session_id:08x}"
                return logging.LoggerAdapter(logger, new_extra)
        except Exception as log_exc:
            logger.debug("Failed to enrich logger: %s", log_exc)
        return conn_logger

    def _validate_and_read_body(
        self, client_socket, packet, connection_device, conn_logger, address
    ) -> bool:
        """Validate packet and read body"""
        if not self.validator.validate_header(packet):
            conn_logger.warning("Invalid packet header from %s: %s", address, packet)
            return False

        if not self.session_manager.validate_sequence(packet.session_id, packet.seq_no):
            return False

        if packet.length > 0:
            if not self.validator.validate_size(packet.length):
                conn_logger.warning(
                    "Packet too large from %s: %s bytes", address, packet.length
                )
                return False

            body_data = NetworkHandler.recv_exact(client_socket, packet.length)
            if not body_data:
                conn_logger.warning("Incomplete packet body from %s", address)
                return False

            secret = self.session_manager.get_or_create_secret(
                packet.session_id, connection_device, self.default_secret
            )
            packet.body = packet.decrypt_body(secret, body_data)

        return True

    def _process_and_respond(self, packet, address, connection_device, conn_logger):
        """Process packet and generate response"""
        conn_logger.debug(
            "Processing packet",
            event="tacacs.packet.processing",
            client_address=address,
            packet_type=getattr(packet, "packet_type", None),
        )

        if packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN:
            return self._handle_authentication(packet, connection_device, conn_logger)
        elif packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR:
            return self._handle_authorization(packet, connection_device, conn_logger)
        elif packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT:
            return self._handle_accounting(packet, connection_device, conn_logger)
        else:
            logger.error(
                "Unknown packet type: %s", getattr(packet, "packet_type", None)
            )
            return None

    def _handle_authentication(self, packet, device_record, conn_logger):
        """Handle authentication request"""
        # Check encryption requirement
        if self._check_encryption_required(packet, conn_logger):
            return self._create_encryption_error_response(packet)

        self.stats.increment("auth_requests")
        response = self.handlers.handle_authentication(packet, device_record)

        if response and len(response.body) > 0:
            status = response.body[0]
            if status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS:
                self.stats.increment("auth_success")
            elif status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL:
                self.stats.increment("auth_failures")

        return response

    def _check_encryption_required(self, packet, conn_logger) -> bool:
        """Check if encryption is required but not used"""
        if not self.encryption_required:
            return False

        try:
            if packet.flags & TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG:
                conn_logger.warning("rejecting unencrypted tacacs+ auth")
                return True
        except Exception as log_exc:
            logger.debug("Failed to check encryption: %s", log_exc)

        return False

    def _create_encryption_error_response(self, packet):
        """Create error response for unencrypted auth"""
        try:
            return self.handlers._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL,
                server_msg="Unencrypted TACACS+ not permitted",
            )
        except Exception:
            return None

    def _handle_authorization(self, packet, device_record, conn_logger=None):
        """Handle authorization request"""
        if conn_logger is None:
            conn_logger = logger
        self.stats.increment("author_requests")
        response = self.handlers.handle_authorization(packet, device_record)

        if response and len(response.body) > 0:
            status = response.body[0]
            if status in [
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
            ]:
                self.stats.increment("author_success")
                self._record_command_metric("granted")
                conn_logger.debug(
                    "Authorization granted",
                    event="tacacs.author.granted",
                    device=device_record.name if device_record else None,
                )
            elif status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL:
                self.stats.increment("author_failures")
                self._record_command_metric("denied")
                conn_logger.warning(
                    "Authorization denied",
                    event="tacacs.author.denied",
                    device=device_record.name if device_record else None,
                )

        return response

    def _handle_accounting(self, packet, device_record, conn_logger=None):
        """Handle accounting request"""
        if conn_logger is None:
            conn_logger = logger
        self.stats.increment("acct_requests")
        response = self.handlers.handle_accounting(packet, device_record)

        if response and len(response.body) >= 6:
            try:
                import struct

                _, _, status = struct.unpack("!HHH", response.body[:6])
                if status == TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS:
                    self.stats.increment("acct_success")
                    conn_logger.debug(
                        "Accounting accepted",
                        event="tacacs.accounting.accepted",
                        device=device_record.name if device_record else None,
                    )
                else:
                    self.stats.increment("acct_failures")
                    conn_logger.warning(
                        "Accounting rejected",
                        event="tacacs.accounting.rejected",
                        device=device_record.name if device_record else None,
                    )
            except Exception as ste_stat_exc:
                logger.debug("Failed to parse accounting status: %s", ste_stat_exc)

        return response

    def _record_command_metric(self, result: str):
        """Record command authorization metric"""
        try:
            from tacacs_server.web.web import PrometheusIntegration as _PM

            _PM.record_command_authorization(result)
        except Exception as rec_autho_exc:
            logger.debug("Failed to record command authorization: %s", rec_autho_exc)
