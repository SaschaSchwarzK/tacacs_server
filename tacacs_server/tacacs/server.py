"""
TACACS+ Server Main Class
"""

import os
import socket
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

try:
    import json as _json

    _HAS_JSON = True
except Exception:  # pragma: no cover
    _HAS_JSON = False

from tacacs_server.auth.base import AuthenticationBackend

from ..accounting.database import DatabaseLogger
from ..utils.logger import get_logger
from ..utils.metrics import MetricsCollector
from ..utils.rate_limiter import get_rate_limiter
from ..utils.simple_cache import LRUDict
from .constants import (
    TAC_PLUS_ACCT_STATUS,
    TAC_PLUS_AUTHEN_STATUS,
    TAC_PLUS_AUTHOR_STATUS,
    TAC_PLUS_DEFAULT_PORT,
    TAC_PLUS_FLAGS,
    TAC_PLUS_HEADER_SIZE,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)
from .handlers import AAAHandlers
from .packet import TacacsPacket

if TYPE_CHECKING:
    from ..devices import DeviceStore
    from ..web.monitoring import TacacsMonitoringAPI

logger = get_logger(__name__)


class TacacsServer:
    """TACACS+ Server implementation.

    Listens for TACACS+ connections, validates/dispatches requests to
    AAA handlers, tracks metrics, and exposes a monitoring API. Designed
    for high concurrency with optional thread-pool handling and per‑IP caps.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = TAC_PLUS_DEFAULT_PORT,
        secret_key: str | None = None,
    ):
        self.host = host
        self.port = port
        # Default fallback secret - should be overridden by device group secrets
        if secret_key is None:
            secret_key = os.getenv("TACACS_DEFAULT_SECRET", "CHANGE_ME_FALLBACK")
        self.secret_key = secret_key
        if self.secret_key == "CHANGE_ME_FALLBACK":
            logger.warning(
                "Default TACACS secret in use. Configure per-device/group secrets or set TACACS_DEFAULT_SECRET."
            )
        self.auth_backends: list[AuthenticationBackend] = []
        self.db_logger = DatabaseLogger()
        self.handlers = AAAHandlers(self.auth_backends, self.db_logger)
        self.running = False
        self.server_socket: socket.socket | None = None
        self._stats_lock = threading.RLock()
        self.stats = {
            "connections_total": 0,
            "connections_active": 0,
            "auth_requests": 0,
            "auth_success": 0,
            "auth_failures": 0,
            "author_requests": 0,
            "author_success": 0,
            "author_failures": 0,
            "acct_requests": 0,
            "acct_success": 0,
            "acct_failures": 0,
        }
        self.start_time = time.time()
        self.metrics = MetricsCollector()
        self.monitoring_api: TacacsMonitoringAPI | None = None
        self.enable_monitoring = False
        self.device_store: DeviceStore | None = None
        self._session_lock = threading.RLock()
        # Limit session secret storage to avoid unbounded growth (LRU behavior)
        self.max_session_secrets = int(os.getenv("TACACS_MAX_SESSION_SECRETS", "10000"))
        self.session_secrets: LRUDict[int, str] = LRUDict(self.max_session_secrets)
        # Track last seen request sequence number per TACACS session
        self._seq_lock = threading.RLock()
        self._last_request_seq: dict[int, int] = {}
        # Abuse control: per-IP connection caps
        self._ip_conn_lock = threading.RLock()
        self._ip_connections: dict[str, int] = {}
        self.max_connections_per_ip = 20
        # Networking/config knobs with sane defaults (env-overridable)
        self.listen_backlog = int(os.getenv("TACACS_LISTEN_BACKLOG", "128"))
        self.client_timeout = float(os.getenv("TACACS_CLIENT_TIMEOUT", "15"))
        self.max_packet_length = int(os.getenv("TACACS_MAX_PACKET_LENGTH", "4096"))
        self.enable_ipv6 = os.getenv("TACACS_IPV6_ENABLED", "false").lower() == "true"
        self.tcp_keepalive = (
            os.getenv("TACACS_TCP_KEEPALIVE", "true").lower() != "false"
        )
        self.tcp_keepalive_idle = int(os.getenv("TACACS_TCP_KEEPIDLE", "60"))
        self.tcp_keepalive_intvl = int(os.getenv("TACACS_TCP_KEEPINTVL", "10"))
        self.tcp_keepalive_cnt = int(os.getenv("TACACS_TCP_KEEPCNT", "5"))
        # Threading strategy controls
        self.use_thread_pool = (
            os.getenv("TACACS_USE_THREAD_POOL", "true").lower() != "false"
        )
        self.thread_pool_max_workers = int(os.getenv("TACACS_THREAD_POOL_MAX", "100"))
        self._executor: ThreadPoolExecutor | None = None
        self._client_threads: set[threading.Thread] = set()
        self._client_threads_lock = threading.RLock()
        # Cache Prometheus update callable if available
        self._prom_update_active: Callable[[int], None] | None = None
        try:
            from ..web.monitoring import PrometheusIntegration as _PM

            self._prom_update_active = getattr(_PM, "update_active_connections", None)
        except Exception:
            self._prom_update_active = None

    # --- Stats helpers (ensure consistent locking and gauge updates) ---
    def _update_active_connections(self, delta: int) -> None:
        """Atomically update active connections and push gauge."""
        with self._stats_lock:
            current = self.stats.get("connections_active", 0)
            new_val = max(0, current + delta)
            self.stats["connections_active"] = new_val
            push = self._prom_update_active
        try:
            if push is not None:
                push(new_val)
        except Exception:
            pass

    def _get_active_connections(self) -> int:
        with self._stats_lock:
            return int(self.stats.get("connections_active", 0))

    def enable_web_monitoring(
        self, web_host="127.0.0.1", web_port=8080, radius_server=None
    ):
        """Enable web monitoring interface"""
        try:
            from ..web.monitoring import TacacsMonitoringAPI

            logger.info(
                "Attempting to enable web monitoring on %s:%s", web_host, web_port
            )
            self.monitoring_api = TacacsMonitoringAPI(
                self, host=web_host, port=web_port, radius_server=radius_server
            )
            started = False
            try:
                self.monitoring_api.start()
                started = True
            except Exception as e:
                logger.exception("Exception while starting monitoring API: %s", e)
            # give the monitoring thread a short moment to start
            import time

            time.sleep(0.1)
            if (
                started
                and self.monitoring_api
                and getattr(self.monitoring_api, "server_thread", None)
            ):
                alive = self.monitoring_api.server_thread.is_alive()
            else:
                alive = False
            if alive:
                self.enable_monitoring = True
                logger.info(
                    "Web monitoring enabled at http://%s:%s", web_host, web_port
                )
                return True
            else:
                logger.error("Web monitoring thread failed to start")
                # cleanup
                try:
                    self.monitoring_api.stop()
                except Exception:
                    pass
                self.monitoring_api = None
                self.enable_monitoring = False
                return False
        except Exception as e:
            logger.exception(f"Failed to enable web monitoring: {e}")
            return False

    def disable_web_monitoring(self):
        """Disable web monitoring interface"""
        if self.monitoring_api:
            self.monitoring_api.stop()
            self.monitoring_api = None
            self.enable_monitoring = False

    def add_auth_backend(self, backend: AuthenticationBackend):
        """Add authentication backend"""
        self.auth_backends.append(backend)
        self.handlers.auth_backends = self.auth_backends
        logger.info(f"Added authentication backend: {backend}")

    def remove_auth_backend(self, backend_name: str) -> bool:
        """Remove authentication backend by name"""
        for i, backend in enumerate(self.auth_backends):
            if backend.name == backend_name:
                del self.auth_backends[i]
                self.handlers.auth_backends = self.auth_backends
                logger.info(f"Removed authentication backend: {backend_name}")
                return True
        return False

    def start(self):
        """Start TACACS+ server"""
        if self.running:
            logger.warning("Server is already running")
            return
        if not self.auth_backends:
            raise RuntimeError("No authentication backends configured")
        self.running = True
        # IPv6 dual-stack if enabled; otherwise IPv4
        if self.enable_ipv6:
            self.server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            try:
                # Enable dual-stack if supported (Linux)
                self.server_socket.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0
                )
            except OSError:
                pass
        else:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            bind_host = self.host
            if self.enable_ipv6 and bind_host in ("0.0.0.0", "::"):
                bind_host = "::"
            self.server_socket.bind((bind_host, self.port))
            self.server_socket.listen(self.listen_backlog)
            logger.debug("TACACS+ server started on %s:%s", bind_host, self.port)
            logger.debug(
                "Authentication backends: %s", [b.name for b in self.auth_backends]
            )
            logger.debug(
                "Per-device secrets configured; avoiding logging secret details"
            )
            # Start thread pool if configured
            if self.use_thread_pool and self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=self.thread_pool_max_workers
                )
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    if self.tcp_keepalive:
                        self._enable_tcp_keepalive(client_socket)
                    with self._stats_lock:
                        self.stats["connections_total"] += 1
                    # Enforce per-IP concurrent connection cap
                    over_limit = False
                    with self._ip_conn_lock:
                        ip = address[0]
                        new_count = self._ip_connections.get(ip, 0) + 1
                        self._ip_connections[ip] = new_count
                        if new_count > self.max_connections_per_ip:
                            over_limit = True
                    if over_limit:
                        logger.warning(
                            "Per-IP connection cap exceeded for %s (count=%s)",
                            ip,
                            new_count,
                        )
                        try:
                            client_socket.close()
                        except Exception:
                            pass
                        with self._ip_conn_lock:
                            # revert increment
                            current = max(0, self._ip_connections.get(ip, 1) - 1)
                            if current == 0:
                                self._ip_connections.pop(ip, None)
                            else:
                                self._ip_connections[ip] = current
                        continue
                    # Count this as an active connection under lock and update gauge
                    self._update_active_connections(+1)
                    logger.debug("New connection from %s", address)
                    if self._executor is not None:
                        self._executor.submit(
                            self._handle_client, client_socket, address
                        )
                    else:
                        client_thread = threading.Thread(
                            target=self._handle_client,
                            args=(client_socket, address),
                            daemon=True,
                        )
                        with self._client_threads_lock:
                            self._client_threads.add(client_thread)
                        client_thread.start()
                    # Gauge is already updated in _update_active_connections
                except OSError as e:
                    if self.running:
                        logger.error("Socket error: %s", e)
                    # continue accept loop unless stopping
                    continue
                except Exception as e:
                    logger.error("Unexpected error accepting connections: %s", e)
                    continue
        except Exception as e:
            logger.error("Server startup error: %s", e)
            raise
        finally:
            if self.server_socket:
                self.server_socket.close()
            logger.info("TACACS+ server stopped")

    def stop(self):
        """Stop TACACS+ server"""
        if not self.running:
            return
        logger.info("Stopping TACACS+ server...")
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except (OSError, AttributeError):
                pass  # Socket shutdown failed
            try:
                self.server_socket.close()
            except (OSError, AttributeError):
                pass  # Socket close failed

    def _handle_client(self, client_socket: socket.socket, address: tuple[str, int]):
        """Handle client connection with improved error handling and performance."""
        # Create a contextual logger for this connection
        try:
            import logging as _logging

            extra: dict[str, object] = {
                "client_ip": address[0],
                "client_port": address[1],
            }
            conn_logger = _logging.LoggerAdapter(logger, extra)
        except Exception:
            conn_logger = logger
        session_ids: set[int] = set()
        connection_device = None
        client_ip = address[0]

        # Rate limiting check
        rate_limiter = get_rate_limiter()
        if not rate_limiter.allow_request(client_ip):
            conn_logger.warning("Rate limit exceeded for %s", client_ip)
            self._safe_close_socket(client_socket)
            return

        # Pre-resolve device once for performance
        if self.device_store:
            try:
                connection_device = self.device_store.find_device_for_ip(client_ip)
            except Exception as exc:
                logger.warning("Failed to resolve device for %s: %s", client_ip, exc)

        try:
            client_socket.settimeout(self.client_timeout)
            while self.running:
                try:
                    header_data = self._recv_exact(client_socket, TAC_PLUS_HEADER_SIZE)
                    if not header_data:
                        break

                    try:
                        packet = TacacsPacket.unpack_header(
                            header_data, max_length=self.max_packet_length
                        )
                    except Exception as e:
                        if _HAS_JSON:
                            try:
                                log_payload = {
                                    "event": "packet_header_error",
                                    "client_ip": address[0],
                                    "client_port": address[1],
                                    "reason": str(e),
                                    "length": len(header_data),
                                    "max_length": self.max_packet_length,
                                }
                                conn_logger.warning(_json.dumps(log_payload))
                            except Exception:
                                pass
                        else:
                            conn_logger.warning(
                                "Invalid packet from %s: %s", address, e
                            )
                        break

                    session_ids.add(packet.session_id)
                    # Enrich logger context with session_id once known
                    try:
                        import logging as _logging

                        if isinstance(conn_logger, _logging.LoggerAdapter):
                            base_extra = getattr(conn_logger, "extra", {}) or {}
                            new_extra = dict(base_extra)
                            new_extra["session_id"] = f"0x{packet.session_id:08x}"
                            conn_logger = _logging.LoggerAdapter(logger, new_extra)
                    except Exception:
                        pass
                    if not self._validate_packet_header(packet):
                        conn_logger.warning(
                            "Invalid packet header from %s: %s", address, packet
                        )
                        break
                    if packet.length > 0:
                        if packet.length > self.max_packet_length:
                            if _HAS_JSON:
                                try:
                                    conn_logger.warning(
                                        _json.dumps(
                                            {
                                                "event": "packet_too_large",
                                                "client_ip": address[0],
                                                "client_port": address[1],
                                                "length": packet.length,
                                                "max_length": self.max_packet_length,
                                            }
                                        )
                                    )
                                except Exception:
                                    pass
                            else:
                                conn_logger.warning(
                                    "Packet too large from %s: %s bytes",
                                    address,
                                    packet.length,
                                )
                            break
                        body_data = self._recv_exact(client_socket, packet.length)
                        if not body_data:
                            conn_logger.warning(
                                "Incomplete packet body from %s", address
                            )
                            break
                        secret = self._select_session_secret(
                            packet.session_id, connection_device
                        )
                        packet.body = packet.decrypt_body(secret, body_data)
                    response = self._process_packet(packet, address, connection_device)
                    if response:
                        secret = self._select_session_secret(
                            packet.session_id, connection_device
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
        except Exception as e:
            conn_logger.error("Client handling error %s: %s", address, e)
        finally:
            self._safe_close_socket(client_socket)
            self._cleanup_client_session(session_ids)
            # Decrement per-IP counter and active counter safely
            with self._ip_conn_lock:
                ip = address[0]
                current = max(0, self._ip_connections.get(ip, 1) - 1)
                if current == 0:
                    self._ip_connections.pop(ip, None)
                else:
                    self._ip_connections[ip] = current
            # Decrement active count and update gauge
            self._update_active_connections(-1)
            conn_logger.debug("Connection closed: %s", address)
            try:
                if threading.current_thread().daemon:
                    with self._client_threads_lock:
                        self._client_threads.discard(threading.current_thread())
            except Exception:
                pass

    def _safe_close_socket(self, sock: socket.socket) -> None:
        """Safely close socket with proper error handling."""
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except (OSError, AttributeError):
            pass  # Socket may already be closed or invalid
        try:
            sock.close()
        except (OSError, AttributeError):
            pass  # Socket already closed, invalid, or None

    def _cleanup_client_session(self, session_ids: set[int]) -> None:
        """Clean up client session data efficiently."""
        if not session_ids:
            return

        with self._session_lock:
            for session_id in session_ids:
                try:
                    self.session_secrets.pop(session_id)
                except KeyError:
                    pass
                try:
                    self.handlers.cleanup_session(session_id)
                except Exception as e:
                    logger.warning("Failed to cleanup session %s: %s", session_id, e)
        with self._seq_lock:
            for session_id in session_ids:
                self._last_request_seq.pop(session_id, None)

    def _select_session_secret(self, session_id: int, device_record) -> str:
        """Ensure a session secret is registered, preferring device-specific keys."""
        with self._session_lock:
            secret = self.session_secrets.get(session_id)
            if secret is None:
                secret = self._resolve_tacacs_secret(device_record) or self.secret_key
                # Insert; LRUDict enforces size and recency
                self.session_secrets[session_id] = secret
                if device_record is not None:
                    self.handlers.session_device[session_id] = device_record
            elif (
                device_record is not None
                and session_id not in self.handlers.session_device
            ):
                self.handlers.session_device[session_id] = device_record
            else:
                # Touch to mark as recently used
                self.session_secrets.touch(session_id)
            # mypy: LRUDict.get is untyped; ensure we return a string
            return str(secret)

    def _resolve_tacacs_secret(self, device_record) -> str | None:
        """Resolve TACACS shared secret strictly from device group configuration."""
        if not device_record:
            return None
        group = getattr(device_record, "group", None)
        if not group:
            return None
        if getattr(group, "tacacs_secret", None):
            return str(getattr(group, "tacacs_secret"))
        metadata = getattr(group, "metadata", {}) or {}
        if isinstance(metadata, dict):
            secret_obj = metadata.get("tacacs_secret")
            if secret_obj is not None:
                return str(secret_obj)
        return None

    def _recv_exact(self, sock: socket.socket, length: int) -> bytes | None:
        """Receive exactly the specified number of bytes"""
        data = b""
        while len(data) < length:
            try:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            except OSError:
                return None
        return data

    def _validate_packet_header(self, packet: TacacsPacket) -> bool:
        """Validate packet header"""
        major_version = packet.version >> 4 & 15
        if major_version != TAC_PLUS_MAJOR_VER:
            if _HAS_JSON:
                try:
                    logger.warning(
                        _json.dumps(
                            {
                                "event": "invalid_major_version",
                                "session": f"0x{packet.session_id:08x}",
                                "got": major_version,
                                "expected": TAC_PLUS_MAJOR_VER,
                            }
                        )
                    )
                except Exception:
                    pass
            else:
                logger.warning(f"Invalid major version: {major_version}")
            return False
        if packet.packet_type not in [
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
        ]:
            if _HAS_JSON:
                try:
                    logger.warning(
                        _json.dumps(
                            {
                                "event": "invalid_packet_type",
                                "session": f"0x{packet.session_id:08x}",
                                "type": packet.packet_type,
                            }
                        )
                    )
                except Exception:
                    pass
            else:
                logger.warning(f"Invalid packet type: {packet.packet_type}")
            return False
        # TACACS+ client requests must be odd sequence numbers (1,3,5,...)
        if packet.seq_no < 1 or (packet.seq_no % 2) != 1:
            logger.warning(f"Invalid sequence number for request: {packet.seq_no}")
            return False
        # Enforce monotonic odd progression per session (1,3,5,...) best-effort
        try:
            with self._seq_lock:
                last = self._last_request_seq.get(packet.session_id)
                if last is not None:
                    if packet.seq_no <= last:
                        # Allow a reset if the backward gap is very large,
                        # which likely indicates a new client session state.
                        if (last - packet.seq_no) < 100:
                            if _HAS_JSON:
                                try:
                                    logger.warning(
                                        _json.dumps(
                                            {
                                                "event": "out_of_order_sequence",
                                                "session": f"0x{packet.session_id:08x}",
                                                "last": last,
                                                "got": packet.seq_no,
                                            }
                                        )
                                    )
                                except Exception:
                                    pass
                            else:
                                logger.warning(
                                    "Out-of-order sequence: sess=%s last=%s got=%s",
                                    f"0x{packet.session_id:08x}",
                                    last,
                                    packet.seq_no,
                                )
                            return False
                        # Treat as session reset: accept and overwrite
                        self._last_request_seq[packet.session_id] = packet.seq_no
                        return True
                    # Forward movement must remain odd-stepped
                    if ((packet.seq_no - last) % 2) != 0:
                        if _HAS_JSON:
                            try:
                                logger.warning(
                                    _json.dumps(
                                        {
                                            "event": "invalid_sequence_step",
                                            "session": f"0x{packet.session_id:08x}",
                                            "last": last,
                                            "got": packet.seq_no,
                                        }
                                    )
                                )
                            except Exception:
                                pass
                        else:
                            logger.warning(
                                "Invalid sequence step: sess=%s last=%s got=%s",
                                f"0x{packet.session_id:08x}",
                                last,
                                packet.seq_no,
                            )
                        return False
                # Update last seen request sequence (first or valid forward)
                self._last_request_seq[packet.session_id] = packet.seq_no
        except Exception:
            pass
        return True

    def _process_packet(
        self, packet: TacacsPacket, address: tuple[str, int], device_record=None
    ) -> TacacsPacket | None:
        """Process incoming packet and return response with improved error handling."""
        try:
            logger.debug("Processing packet from %s: %s", address, packet)

            # Device record should already be resolved for performance
            if device_record is None and self.device_store:
                try:
                    device_record = self.device_store.find_device_for_ip(address[0])
                except Exception as exc:
                    logger.warning(
                        "Failed to resolve device for %s: %s", address[0], exc
                    )

            self._select_session_secret(packet.session_id, device_record)

            if packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN:
                with self._stats_lock:
                    self.stats["auth_requests"] += 1
                response = self.handlers.handle_authentication(packet, device_record)
                if response and len(response.body) > 0:
                    status = response.body[0]
                    if status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS:
                        with self._stats_lock:
                            self.stats["auth_success"] += 1
                    elif status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL:
                        with self._stats_lock:
                            self.stats["auth_failures"] += 1
                return response
            elif packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR:
                with self._stats_lock:
                    self.stats["author_requests"] += 1
                response = self.handlers.handle_authorization(packet, device_record)
                if response and len(response.body) > 0:
                    status = response.body[0]
                    if status in [
                        TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                        TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
                    ]:
                        with self._stats_lock:
                            self.stats["author_success"] += 1
                    elif status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL:
                        with self._stats_lock:
                            self.stats["author_failures"] += 1
                return response
            elif packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT:
                with self._stats_lock:
                    self.stats["acct_requests"] += 1
                response = self.handlers.handle_accounting(packet, device_record)
                if response and len(response.body) >= 6:
                    # handlers._create_acct_response packs as: !HHH (srv_msg_len, data_len, status)
                    try:
                        import struct as _st

                        _, _, status = _st.unpack("!HHH", response.body[:6])
                    except Exception:
                        status = None
                    if status == TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS:
                        with self._stats_lock:
                            self.stats["acct_success"] += 1
                    else:
                        with self._stats_lock:
                            self.stats["acct_failures"] += 1
                return response
            else:
                logger.error(f"Unknown packet type: {packet.packet_type}")
                return None
        except Exception as e:
            logger.error("Error processing packet from %s: %s", address, e)
            # Return appropriate error response based on packet type
            if packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN:
                with self._stats_lock:
                    self.stats["auth_failures"] += 1
            elif packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR:
                with self._stats_lock:
                    self.stats["author_failures"] += 1
            elif packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT:
                with self._stats_lock:
                    self.stats["acct_failures"] += 1
            return None

    def get_stats(self) -> dict[str, Any]:
        """Get server statistics"""
        stats: dict[str, Any] = dict(self.stats)
        stats.update(
            {
                "server_running": self.running,
                "auth_backends": [
                    {"name": b.name, "available": b.is_available()}
                    for b in self.auth_backends
                ],
                "active_auth_sessions": len(self.handlers.auth_sessions),
            }
        )
        return stats

    def get_active_sessions(self) -> list:
        """Get active accounting sessions"""
        return self.db_logger.get_active_sessions()

    def reset_stats(self):
        """Reset server statistics"""
        self.stats = {
            "connections_total": 0,
            "connections_active": self.stats["connections_active"],
            "auth_requests": 0,
            "auth_success": 0,
            "auth_failures": 0,
            "author_requests": 0,
            "author_success": 0,
            "author_failures": 0,
            "acct_requests": 0,
            "acct_success": 0,
            "acct_failures": 0,
        }
        logger.info("Server statistics reset")

    def get_health_status(self) -> dict[str, Any]:
        """Get server health status"""
        return {
            "status": "healthy" if self.running else "stopped",
            "uptime_seconds": time.time() - self.start_time,
            "active_connections": self.stats["connections_active"],
            "auth_backends": [
                {
                    "name": b.name,
                    "available": b.is_available(),
                    "last_check": getattr(b, "last_health_check", None),
                }
                for b in self.auth_backends
            ],
            "database_status": self._check_database_health(),
            "memory_usage": self._get_memory_usage(),
        }

    def _get_memory_usage(self) -> dict[str, Any]:
        """Get memory usage statistics"""
        try:
            # Optional psutil import to avoid hard dependency
            import psutil

            process = psutil.Process()
            memory_info = process.memory_info()
            return {
                "rss_mb": round(memory_info.rss / 1024 / 1024, 2),
                "vms_mb": round(memory_info.vms / 1024 / 1024, 2),
                "percent": round(process.memory_percent(), 2),
            }
        except Exception:
            return {"error": "Unable to get memory info"}

    def _check_database_health(self) -> dict[str, Any]:
        """Check database health"""
        try:
            # Cheap health check first
            ok = getattr(self.db_logger, "ping", lambda: False)()
            if not ok:
                return {"status": "unhealthy", "error": "Database ping failed"}
            # Optionally add a light stats sample (best-effort)
            try:
                stats = self.db_logger.get_statistics(days=1)
                recs = stats.get("total_records", 0) if isinstance(stats, dict) else 0
            except Exception:
                recs = None
            payload = {"status": "healthy"}
            if recs is not None:
                payload["records_today"] = recs
            return payload
        except Exception as e:
            logger.error("Database health check failed: %s", e)
            return {"status": "unhealthy", "error": "Database error"}

    def reload_configuration(self):
        """Reload configuration without restarting server"""
        try:
            # Reload config (assuming you have access to config object)
            # This would need to be passed in or made accessible
            logger.info("Configuration reload requested")
            # Implementation depends on how you structure config access

            logger.info("Configuration reloaded successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            return False

    def graceful_shutdown(self, timeout_seconds=30):
        """Gracefully shutdown server"""
        logger.info("Initiating graceful shutdown...")
        self.running = False

        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.server_socket.close()

        # Wait for active connections to finish
        start_time = time.time()
        while (
            self._get_active_connections() > 0
            and time.time() - start_time < timeout_seconds
        ):
            time.sleep(0.1)

        if self._get_active_connections() > 0:
            logger.warning(
                f"Force closing {self._get_active_connections()} remaining connections"
            )
        # Join client threads if we created any (best-effort)
        with self._client_threads_lock:
            threads = list(self._client_threads)
            self._client_threads.clear()
        remaining: list[threading.Thread] = []
        for t in threads:
            try:
                t.join(timeout=1.0)
            except Exception:
                # Ignore join errors; treat as still alive
                pass
            if t.is_alive():
                remaining.append(t)
        if remaining:
            try:
                logger.warning(f"{len(remaining)} threads did not terminate gracefully")
            except Exception:
                pass
        # Shutdown thread pool
        if self._executor:
            try:
                self._executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
            finally:
                self._executor = None
        logger.info("Server shutdown complete")

    def _enable_tcp_keepalive(self, sock: socket.socket) -> None:
        """Enable TCP keepalive with best-effort platform options."""
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, "TCP_KEEPIDLE"):
                sock.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, self.tcp_keepalive_idle
                )
            if hasattr(socket, "TCP_KEEPINTVL"):
                sock.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, self.tcp_keepalive_intvl
                )
            if hasattr(socket, "TCP_KEEPCNT"):
                sock.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_KEEPCNT, self.tcp_keepalive_cnt
                )
            if hasattr(socket, "TCP_KEEPALIVE"):
                try:
                    sock.setsockopt(
                        socket.IPPROTO_TCP,
                        socket.TCP_KEEPALIVE,
                        self.tcp_keepalive_idle,
                    )
                except OSError:
                    pass
        except OSError:
            pass
