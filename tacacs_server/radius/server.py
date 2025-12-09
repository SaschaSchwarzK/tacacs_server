"""
RADIUS Server Implementation

Provides a complete RADIUS server that shares authentication backends with TACACS+.
Supports Authentication and Accounting (Authorization is TACACS+ specific).

RFC 2865 - Remote Authentication Dial In User Service (RADIUS)
RFC 2866 - RADIUS Accounting
"""

import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any, Optional

from tacacs_server.auth.base import AuthenticationBackend
from tacacs_server.utils.logger import get_logger

from .auth import AuthServices
from .client import (
    RadiusClient,
    add_radius_client,
    load_radius_clients,
    lookup_client_by_ip,
    refresh_radius_clients,
)
from .constants import (
    MAX_RADIUS_PACKET_LENGTH,
)
from .handlers import handle_acct_request, handle_auth_request, log_accounting_record
from .packet import RADIUSPacket
from .response import ResponseBuilder, ResponseContext, send_response

logger = get_logger("tacacs_server.radius.server", component="radius")


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
            secret = os.getenv("RADIUS_DEFAULT_SECRET", "CHANGE_ME_FALLBACK")  # nosec
        self.secret = secret.encode("utf-8")
        if secret == "CHANGE_ME_FALLBACK":  # nosec
            logger.warning(
                "RADIUS default secret is the insecure fallback; set RADIUS_DEFAULT_SECRET or per-client secrets."
            )

        self.auth_backends: list[AuthenticationBackend] = []
        self.accounting_logger = None
        self.device_store: _DeviceStore | None = None
        self.local_user_group_service = None
        self.auth_services = AuthServices(
            local_user_group_service=self.local_user_group_service
        )
        self.response_context = ResponseContext(
            local_user_group_service=self.local_user_group_service
        )
        self.response_builder = ResponseBuilder(self.response_context)

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
        logger.debug(
            "Authentication backend added",
            event="radius.auth.backend_added",
            backend=name,
        )

    def set_accounting_logger(self, accounting_logger):
        """Set accounting logger (shared with TACACS+)"""
        self.accounting_logger = accounting_logger
        logger.debug(
            "Accounting logger configured",
            event="radius.accounting.logger_configured",
        )

    def set_local_user_group_service(self, service) -> None:
        self.local_user_group_service = service
        self.response_context.local_user_group_service = service
        self.auth_services.local_user_group_service = service

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
        return add_radius_client(
            self.clients,
            self._client_lock,
            network,
            secret,
            name=name,
            group=group,
            attributes=attributes,
            allowed_user_groups=allowed_user_groups,
        )

    def load_clients(self, clients: list["RadiusClient"]) -> None:
        """Replace current clients with pre-built entries (e.g. from DeviceStore)."""
        load_radius_clients(self.clients, self._client_lock, clients)

    def refresh_clients(self, client_configs) -> None:
        """Rebuild client list from iterable configs (network, secret, etc.)."""
        refresh_radius_clients(self.clients, self._client_lock, client_configs)

    def lookup_client(self, ip: str) -> Optional["RadiusClient"]:
        return lookup_client_by_ip(self.clients, self._client_lock, ip)

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
                    "Failed to close RADIUS authentication socket",
                    event="radius.auth.socket_close_failed",
                    error=str(socket_close_exc),
                )
        if self.acct_socket:
            try:
                self.acct_socket.close()
            except (OSError, AttributeError) as socket_close_exc:
                # Socket close failed, continue with shutdown
                logger.warning(
                    "Failed to close RADIUS accounting socket",
                    event="radius.acct.socket_close_failed",
                    error=str(socket_close_exc),
                )

        if self._executor:
            try:
                self._executor.shutdown(wait=False, cancel_futures=True)
            except Exception as executor_shutdown_exc:
                # Executor shutdown failed, continue with cleanup
                logger.warning(
                    "Failed to shutdown RADIUS executor",
                    event="radius.executor.shutdown_failed",
                    error=str(executor_shutdown_exc),
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
                    "Failed to set RADIUS authentication socket buffer size",
                    event="radius.socket.rcvbuf_failed",
                    error=str(socket_setopt_exc),
                )

            logger.debug(
                "RADIUS authentication socket bound",
                event="radius.auth.socket_bound",
                host=self.host,
                port=self.port,
                rcvbuf=self.rcvbuf,
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
                        logger.warning(
                            "RADIUS auth server socket error",
                            event="radius.auth.socket_error",
                            error=str(e),
                        )
                    break

        except (OSError, ConnectionError) as e:
            logger.error(
                "Failed to start RADIUS auth server",
                event="radius.auth.start_failed",
                error=str(e),
                host=self.host,
                port=self.port,
            )
        finally:
            if self.auth_socket:
                try:
                    self.auth_socket.close()
                except (OSError, AttributeError) as socket_close_exc:
                    # Socket close failed during cleanup
                    logger.warning(
                        "Failed to close RADIUS authentication socket",
                        event="radius.auth.socket_close_failed",
                        error=str(socket_close_exc),
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
                    "Failed to set RADIUS accounting socket buffer size",
                    event="radius.acct.socket_rcvbuf_failed",
                    error=str(socket_setopt_exc),
                )

            logger.debug(
                "RADIUS accounting socket bound",
                event="radius.acct.socket_bound",
                host=self.host,
                port=self.accounting_port,
                rcvbuf=self.rcvbuf,
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
                        logger.warning(
                            "RADIUS acct server socket error",
                            event="radius.acct.socket_error",
                            error=str(e),
                        )
                    break

        except (OSError, ConnectionError) as e:
            logger.error(
                "Failed to start RADIUS acct server",
                event="radius.acct.start_failed",
                error=str(e),
                host=self.host,
                port=self.accounting_port,
            )
        finally:
            if self.acct_socket:
                try:
                    self.acct_socket.close()
                except (OSError, AttributeError) as socket_close_exc:
                    # Socket close failed during cleanup
                    logger.warning(
                        "Failed to close RADIUS accounting socket",
                        event="radius.acct.socket_close_failed",
                        error=str(socket_close_exc),
                    )
                finally:
                    self.acct_socket = None

    def _handle_auth_request(self, data: bytes, addr: tuple[str, int]):
        """Delegate authentication request handling to shared handler."""
        return handle_auth_request(self, data, addr)

    def _handle_acct_request(self, data: bytes, addr: tuple[str, int]):
        """Delegate accounting request handling to shared handler."""
        return handle_acct_request(self, data, addr)

    def _create_access_accept(
        self, request: RADIUSPacket, user_attrs: dict[str, Any]
    ) -> RADIUSPacket:
        """Create Access-Accept response via shared builder (backwards compatibility)."""
        return self.response_builder.create_access_accept(request, user_attrs)

    def _create_access_reject(
        self, request: RADIUSPacket, message: str = "Authentication failed"
    ) -> RADIUSPacket:
        """Create Access-Reject response via shared builder (backwards compatibility)."""
        return self.response_builder.create_access_reject(request, message)

    def _send_response(
        self,
        response: RADIUSPacket,
        addr: tuple[str, int],
        secret: bytes,
        request_auth: bytes,
    ):
        """Send RADIUS response using shared sender (backwards compatibility)."""
        return send_response(
            self.auth_socket, self.acct_socket, response, addr, secret, request_auth
        )

    def _log_accounting(self, request: RADIUSPacket, client_ip: str):
        """Delegate accounting record logging to shared handler."""
        if self.accounting_logger:
            log_accounting_record(request, client_ip, self.accounting_logger)

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
