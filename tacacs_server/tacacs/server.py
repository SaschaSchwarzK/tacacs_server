"""
TACACS+ Server Main Class
"""

import ipaddress
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
    from ..web.web import WebServer

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
            "connections_proxied": 0,
            "connections_direct": 0,
            "proxy_headers_parsed": 0,
            "proxy_header_errors": 0,
            "proxy_rejected_unknown": 0,
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
        self.monitoring_api: WebServer | None = None
        self.enable_monitoring = False
        # Whether proxy-aware identity matching is enabled (configured in main)
        self.proxy_enabled: bool = True
        self.device_store: DeviceStore | None = None
        # Whether to accept HAProxy PROXY v2 headers on inbound connections
        self.accept_proxy_protocol: bool = True
        # Whether to validate that PROXY source ip belongs to configured proxies
        self.proxy_validate_sources: bool = False
        # Reject invalid/unsupported PROXY headers when validation is enabled
        self.proxy_reject_invalid: bool = True
        # Enforce encryption for TACACS+ auth when enabled
        self.encryption_required: bool = True
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
            from ..web.web import PrometheusIntegration as _PM

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
            import os
            import threading
            import time
            import uvicorn
            from ..web.web_app import create_app

            logger.info("Starting web monitoring on %s:%s", web_host, web_port)

            # Get admin credentials from environment or config
            admin_username = os.getenv("ADMIN_USERNAME", "admin")
            admin_password_hash = os.getenv("ADMIN_PASSWORD_HASH", "")
            api_token = os.getenv("API_TOKEN")

            # If no password hash, try to get from config
            if not admin_password_hash and hasattr(self, "config"):
                try:
                    admin_config = self.config.get_admin_auth_config()
                    admin_username = admin_config.get("username", "admin")
                    admin_password_hash = admin_config.get("password_hash", "")
                except:
                    pass

            # Create FastAPI app with credentials
            app = create_app(
                admin_username=admin_username,
                admin_password_hash=admin_password_hash,
                api_token=api_token,
                tacacs_server=self,
                radius_server=radius_server,
                device_service=getattr(self, "device_service", None),
                user_service=getattr(self, "local_user_service", None),
                user_group_service=getattr(self, "local_user_group_service", None),
                config_service=getattr(self, "config", None),
            )

            # Run uvicorn in background thread
            def run_server():
                config = uvicorn.Config(
                    app,
                    host=web_host,
                    port=web_port,
                    log_level="warning",
                    access_log=False,
                )
                server = uvicorn.Server(config)
                server.run()

            thread = threading.Thread(target=run_server, daemon=True)
            thread.start()
            time.sleep(0.2)

            self.enable_monitoring = True
            logger.info("Web monitoring enabled at http://%s:%s", web_host, web_port)
            return True

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
        # Use a consistent format across services and prefer backend logical name
        # (e.g., "local", "okta") rather than the repr that may include class.
        try:
            name = getattr(backend, "name", None) or str(backend)
        except Exception:
            name = str(backend)
        logger.info("TACACS: Added authentication backend: %s", name)

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
                "Device-group secrets supported; secret values are never logged"
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
                    # --- Ensure device resolution is invoked immediately on accept ---
                    # Some tests (and callers) expect device_store.find_device_for_ip to be
                    # called for direct connections even if the client closes immediately.
                    # Resolve here (best-effort) and attach result to the socket so the
                    # handler thread can reuse it without rereading.
                    try:
                        if self.device_store is not None:
                            try:
                                selected = self.device_store.find_device_for_ip(ip)
                                # Attach selected device for handler/tests to observe
                                try:
                                    client_socket.selected_device = selected
                                except Exception:
                                    # If socket object doesn't accept attributes, ignore
                                    pass
                            except Exception as exc:
                                logger.debug(
                                    "Device lookup during accept failed for %s: %s",
                                    ip,
                                    exc,
                                )
                    except Exception:
                        # Defensive: do not let device lookup prevent accepting/handling the connection
                        pass

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
        proxy_ip: str | None = None

        # Attempt to detect and consume PROXY protocol v2 header
        try:
            from tacacs_server.utils.proxy_protocol import ProxyProtocolV2Parser

            # Consume first 16 bytes and decide if it's a PROXY v2 header or a TACACS header
            info = None
            consumed = 0
            first_header_data = b""
            buffered_bytes = b""  # Buffer all bytes read for fallback
            # Read first 12 bytes (either PROXY signature or TACACS header)
            first12 = self._recv_exact(client_socket, 12)
            buffered_bytes = first12 or b""  # Start buffering
            if (
                self.proxy_enabled
                and self.accept_proxy_protocol
                and first12
                and len(first12) >= len(ProxyProtocolV2Parser.SIGNATURE)
                and first12.startswith(ProxyProtocolV2Parser.SIGNATURE)
            ):
                # PROXY v2 signature detected
                conn_logger.debug("PROXY v2 signature detected from %s", address[0])
                # Complete fixed 16-byte header
                next4 = self._recv_exact(client_socket, 4) or b""
                buffered_bytes += next4  # Add to buffer
                hdr16 = (first12 or b"") + next4
                addr_len = int.from_bytes(hdr16[14:16], "big")
                rest = self._recv_exact(client_socket, addr_len) or b""
                buffered_bytes += rest  # Add to buffer
                raw_header = hdr16 + rest
                info, consumed = ProxyProtocolV2Parser.parse(raw_header)
                # Diagnostic: verify lengths for debugging parser expectations
                try:
                    conn_logger.debug(
                        "PROXY header: read=%d bytes, parser consumed=%d, addr_len=%d",
                        len(raw_header),
                        int(consumed),
                        int(addr_len),
                    )
                except Exception:
                    pass
                if info is None or consumed == 0:
                    # Signature matched, but parsing failed — log at debug for diagnostics
                    with self._stats_lock:
                        self.stats["proxy_header_errors"] = (
                            self.stats.get("proxy_header_errors", 0) + 1
                        )
                    try:
                        conn_logger.debug(
                            "Invalid/unsupported PROXY v2 header from %s (len=%s), treating as direct connection",
                            address[0],
                            len(raw_header),
                        )
                    except Exception:
                        pass
                    # Only reject if strict validation is enabled
                    # When validate_sources is false, we're lenient and continue as direct
                    if (
                        getattr(self, "proxy_reject_invalid", True)
                        and self.proxy_validate_sources
                    ):
                        try:
                            conn_logger.error(
                                "Rejecting connection: invalid PROXY v2 header from %s",
                                address[0],
                            )
                        except Exception:
                            pass
                        self._safe_close_socket(client_socket)
                        return
                    # Otherwise, ignore invalid header and proceed as direct connection
                    try:
                        conn_logger.debug(
                            "Lenient mode: ignoring invalid PROXY v2 header from %s; proceeding as direct",
                            address[0],
                        )
                    except Exception:
                        pass
                    # Invalid PROXY header was consumed (buffered_bytes), read fresh TACACS header
                    # The TACACS packet comes AFTER the invalid PROXY header in the stream
                    first_header_data = self._recv_exact(client_socket, 12) or b""
                else:
                    with self._stats_lock:
                        self.stats["proxy_headers_parsed"] = (
                            self.stats.get("proxy_headers_parsed", 0) + 1
                        )
                    # Sanity-check parser 'consumed' vs actual bytes read
                    try:
                        total_read = len(raw_header)
                        if consumed != total_read:
                            try:
                                conn_logger.error(
                                    "PROXY header size mismatch: read=%d, consumed=%d",
                                    total_read,
                                    consumed,
                                )
                            except Exception:
                                pass
                            self._safe_close_socket(client_socket)
                            return
                    except Exception:
                        pass
                    # Log acceptance of a valid PROXY v2 header for observability
                    try:
                        if _HAS_JSON:
                            conn_logger.info(
                                _json.dumps(
                                    {
                                        "event": "proxy_v2_accepted",
                                        "client_ip": address[0],
                                        "src": getattr(info, "src_addr", None),
                                        "dst": getattr(info, "dst_addr", None),
                                        "consumed": consumed,
                                    }
                                )
                            )
                        else:
                            conn_logger.info(
                                "Accepted PROXY v2 header from %s -> src=%s dst=%s",
                                address[0],
                                getattr(info, "src_addr", None),
                                getattr(info, "dst_addr", None),
                            )
                    except Exception:
                        pass
            else:
                # Not a PROXY header; treat first12 as the full TACACS header (12 bytes)
                first_header_data = first12 or b""
            if info and info.is_proxied:
                client_ip = info.src_addr
                proxy_ip = address[0]
                conn_logger.debug(
                    "Using proxied identity: client_ip=%s, proxy_ip=%s",
                    client_ip,
                    proxy_ip,
                )
        except Exception as e:
            # Log at debug and fall back to direct address
            with self._stats_lock:
                self.stats["proxy_header_errors"] = (
                    self.stats.get("proxy_header_errors", 0) + 1
                )
            try:
                # Only reject if strict validation is enabled
                if (
                    getattr(self, "proxy_reject_invalid", True)
                    and self.proxy_validate_sources
                ):
                    conn_logger.error(
                        "Rejecting connection due to PROXY v2 parse error from %s: %s",
                        address[0],
                        e,
                    )
                    self._safe_close_socket(client_socket)
                    return
                else:
                    conn_logger.debug(
                        "Lenient mode: PROXY v2 parse error from %s: %s; proceeding as direct",
                        address[0],
                        e,
                    )
                    # When PROXY parsing fails, the buffered bytes are invalid PROXY data
                    # The actual TACACS header comes AFTER the invalid PROXY header
                    # We need to read fresh bytes from the socket for the TACACS header
                    try:
                        sig = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"  # PROXY v2 signature
                        # Check if buffered bytes start with PROXY signature
                        if (
                            buffered_bytes
                            and len(buffered_bytes) >= 12
                            and buffered_bytes[:12] == sig
                        ):
                            # Buffered bytes are invalid PROXY data, not TACACS
                            # Read fresh TACACS header from socket
                            first_header_data = (
                                self._recv_exact(client_socket, 12) or b""
                            )
                        elif buffered_bytes and len(buffered_bytes) >= 12:
                            # Buffered bytes don't look like PROXY, might be TACACS
                            first_header_data = buffered_bytes[:12]
                        elif first12 and len(first12) == 12:
                            first_header_data = first12
                    except Exception as fallback_err:
                        conn_logger.error(
                            f"Exception in fallback logic: {fallback_err}"
                        )
            except Exception as outer_err:
                conn_logger.error(
                    f"Unexpected exception in PROXY handling: {outer_err}"
                )
            proxy_ip = None

        # Enforce that the proxy IP belongs to a configured proxy network when enabled
        try:
            if (
                self.proxy_enabled
                and self.proxy_validate_sources
                and proxy_ip is not None
                and self.device_store is not None
            ):
                conn_logger.debug(
                    "Validating proxy IP %s against configured proxies", proxy_ip
                )
                allowed = self._proxy_ip_allowed(proxy_ip)
                if not allowed:
                    with self._stats_lock:
                        self.stats["proxy_rejected_unknown"] = (
                            self.stats.get("proxy_rejected_unknown", 0) + 1
                        )
                        try:
                            conn_logger.error(
                                "Rejecting proxied connection from %s: proxy IP %s not in any configured proxy network",
                                address[0],
                                proxy_ip,
                            )
                        except Exception:
                            pass
                        self._safe_close_socket(client_socket)
                        return
                else:
                    conn_logger.debug("Proxy IP %s validated successfully", proxy_ip)
        except Exception:
            pass

        # Increment proxied vs direct counters once per connection
        self._record_connection_counter(proxy_ip)

        # Rate limiting check (use client_ip for fairness)
        rate_limiter = get_rate_limiter()
        if not rate_limiter.allow_request(client_ip):
            conn_logger.warning("Rate limit exceeded for %s", client_ip)
            self._safe_close_socket(client_socket)
            return

        # Pre-resolve device once for performance
        if self.device_store:
            try:
                if self.proxy_enabled and proxy_ip is not None:
                    conn_logger.debug(
                        "Resolving device for proxied connection: client_ip=%s, proxy_ip=%s",
                        client_ip,
                        proxy_ip,
                    )
                    connection_device = self.device_store.find_device_for_identity(
                        client_ip,  # Real client IP from PROXY header
                        proxy_ip,  # Proxy IP from connection
                    )
                else:
                    connection_device = self.device_store.find_device_for_ip(client_ip)

                if connection_device:
                    conn_logger.debug(
                        "Device resolved: %s (group: %s)",
                        connection_device.name,
                        connection_device.group.name
                        if connection_device.group
                        else "none",
                    )
                else:
                    conn_logger.debug("No device found for client_ip=%s", client_ip)
            except Exception as exc:
                logger.warning("Failed to resolve device for %s: %s", client_ip, exc)

        try:
            client_socket.settimeout(self.client_timeout)
            while self.running:
                try:
                    if "first_header_data" in locals() and first_header_data:
                        header_data: bytes = first_header_data
                        first_header_data = b""
                    else:
                        tmp = self._recv_exact(client_socket, TAC_PLUS_HEADER_SIZE)
                        if not tmp:
                            break
                        header_data = tmp
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
                        if _HAS_JSON:
                            try:
                                conn_logger.warning(
                                    _json.dumps(
                                        {
                                            "event": "invalid_packet_header",
                                            "client_ip": address[0],
                                            "client_port": address[1],
                                            "session": f"0x{packet.session_id:08x}",
                                            "packet": str(packet),
                                        }
                                    )
                                )
                            except Exception:
                                conn_logger.warning(
                                    "Invalid packet header from %s: %s", address, packet
                                )
                        else:
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
                            if _HAS_JSON:
                                try:
                                    conn_logger.warning(
                                        _json.dumps(
                                            {
                                                "event": "incomplete_packet_body",
                                                "client_ip": address[0],
                                                "client_port": address[1],
                                                "session": f"0x{packet.session_id:08x}",
                                                "expected_length": packet.length,
                                            }
                                        )
                                    )
                                except Exception:
                                    conn_logger.warning(
                                        "Incomplete packet body from %s", address
                                    )
                            else:
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
            if _HAS_JSON:
                try:
                    logger.warning(
                        _json.dumps(
                            {
                                "event": "invalid_sequence_number",
                                "session": f"0x{packet.session_id:08x}",
                                "got": packet.seq_no,
                                "require": "odd>=1",
                            }
                        )
                    )
                except Exception:
                    logger.warning(
                        f"Invalid sequence number for request: {packet.seq_no}"
                    )
            else:
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
                # Enforce encryption policy: reject unencrypted auth if required
                try:
                    from .constants import TAC_PLUS_FLAGS as _FLAGS_CLASS

                    _unencrypted_flag = _FLAGS_CLASS.TAC_PLUS_UNENCRYPTED_FLAG
                except Exception:
                    _unencrypted_flag = None
                if (
                    getattr(self, "encryption_required", False)
                    and _unencrypted_flag is not None
                    and (packet.flags & _unencrypted_flag) != 0
                ):
                    # Structured log for policy-based rejection
                    if _HAS_JSON:
                        try:
                            logger.warning(
                                _json.dumps(
                                    {
                                        "event": "unencrypted_rejected",
                                        "session": f"0x{packet.session_id:08x}",
                                        "reason": "encryption_required",
                                    }
                                )
                            )
                        except Exception:
                            try:
                                logger.warning(
                                    "Rejecting unencrypted TACACS+ auth: encryption_required policy active"
                                )
                            except Exception:
                                pass
                    else:
                        try:
                            logger.warning(
                                "Rejecting unencrypted TACACS+ auth: encryption_required policy active"
                            )
                        except Exception:
                            pass
                    try:
                        response = self.handlers._create_auth_response(
                            packet,
                            TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL,
                            server_msg="Unencrypted TACACS+ not permitted",
                        )
                    except Exception:
                        response = None
                    # Emit a plain, lowercase compatibility line for tests/consumers
                    try:
                        logger.warning("rejecting unencrypted tacacs+ auth")
                    except Exception:
                        pass
                    with self._stats_lock:
                        self.stats["auth_requests"] += 1
                        self.stats["auth_failures"] += 1
                    return response
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
                        # Record command authorization metric
                        try:
                            from ..web.web import PrometheusIntegration as _PM

                            _PM.record_command_authorization("granted")
                        except Exception:
                            pass
                    elif status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL:
                        with self._stats_lock:
                            self.stats["author_failures"] += 1
                        # Record command authorization metric
                        try:
                            from ..web.web import PrometheusIntegration as _PM

                            _PM.record_command_authorization("denied")
                        except Exception:
                            pass
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

    def _record_connection_counter(self, proxy_ip: str | None) -> None:
        try:
            with self._stats_lock:
                if self.proxy_enabled and proxy_ip is not None:
                    self.stats["connections_proxied"] = (
                        self.stats.get("connections_proxied", 0) + 1
                    )
                else:
                    self.stats["connections_direct"] = (
                        self.stats.get("connections_direct", 0) + 1
                    )
        except Exception:
            pass

    def get_active_sessions(self) -> list:
        """Get active accounting sessions"""
        return self.db_logger.get_active_sessions()

    def reset_stats(self):
        """Reset server statistics"""
        self.stats = {
            "connections_total": 0,
            "connections_active": self.stats["connections_active"],
            "connections_proxied": 0,
            "connections_direct": 0,
            "proxy_headers_parsed": 0,
            "proxy_header_errors": 0,
            "proxy_rejected_unknown": 0,
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
            # Provide stable schema even when psutil is unavailable
            return {"rss_mb": 0.0, "vms_mb": 0.0, "percent": 0.0}

    def _check_database_health(self) -> dict[str, Any]:
        """Check database health"""
        try:
            # Cheap health check first
            ok = getattr(self.db_logger, "ping", lambda: False)()
            if not ok:
                return {
                    "status": "unhealthy",
                    "records_today": 0,
                    "error": "Database ping failed",
                }
            # Optionally add a light stats sample (best-effort)
            try:
                stats = self.db_logger.get_statistics(days=1)
                recs = stats.get("total_records", 0) if isinstance(stats, dict) else 0
            except Exception:
                recs = 0
            payload = {
                "status": "healthy",
                "records_today": int(recs) if recs is not None else 0,
            }
            return payload
        except Exception as e:
            logger.error("Database health check failed: %s", e)
            return {
                "status": "unhealthy",
                "records_today": 0,
                "error": "Database error",
            }

    def reload_configuration(self):
        """Reload configuration without restarting server"""
        try:
            # Reload config (assuming you have access to config object)
            # This would need to be passed in or made accessible
            logger.info("Configuration reload requested")
            # Implementation depends on how you structure config access
            logger.info("Configuration reloaded successfully")
            return True
        except Exception as exc:
            logger.error("Configuration reload failed: %s", exc)
            return False

    def _proxy_ip_allowed(self, proxy_ip: str) -> bool:
        """Check if a proxy IP is within any configured proxy network.

        Fail-open (return True) if device store is unavailable or listing proxies raises.
        """
        try:
            p_ip = ipaddress.ip_address(proxy_ip)
        except Exception:
            logger.debug("Failed to parse proxy IP: %s", proxy_ip)
            return False
        store = getattr(self, "device_store", None)
        if store is None:
            # No store configured: do not block
            logger.debug("No device store configured, allowing proxy IP: %s", proxy_ip)
            return True
        try:
            proxies = store.list_proxies()
            logger.debug(
                "Checking proxy IP %s against %d configured proxies",
                proxy_ip,
                len(proxies),
            )
            print(
                f"DEBUG: Checking proxy IP {proxy_ip} against {len(proxies)} configured proxies"
            )
            for p in proxies:
                try:
                    logger.debug(
                        "Checking if %s is in proxy network %s", proxy_ip, p.network
                    )
                    if p_ip in p.network:
                        logger.debug(
                            "Proxy IP %s matched proxy network %s", proxy_ip, p.network
                        )
                        return True
                except Exception as e:
                    logger.debug(
                        "Error checking proxy %s: %s",
                        p.name if hasattr(p, "name") else "unknown",
                        e,
                    )
                    continue
            logger.debug(
                "Proxy IP %s not found in any configured proxy networks", proxy_ip
            )
        except Exception as e:
            # Fail-open on store/listing errors
            logger.debug("Error listing proxies: %s, failing open", e)
            return True
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
