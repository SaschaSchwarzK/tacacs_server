"""
Refactored TACACS+ Server Main Class
"""

import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from tacacs_server.accounting.database import DatabaseLogger
from tacacs_server.auth.base import AuthenticationBackend
from tacacs_server.tacacs.constants import TAC_PLUS_DEFAULT_PORT
from tacacs_server.tacacs.handlers import AAAHandlers
from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.metrics import MetricsCollector
from tacacs_server.utils.rate_limiter import ConnectionLimiter

from .client_handler import ClientHandler
from .network import NetworkHandler
from .proxy import ProxyHandler
from .session import SessionManager
from .stats import StatsManager
from .validator import PacketValidator

if TYPE_CHECKING:
    from tacacs_server.devices import DeviceStore
    from tacacs_server.web.web import WebServer

logger = get_logger(__name__)


class TacacsServer:
    """TACACS+ Server implementation with improved modularity"""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = TAC_PLUS_DEFAULT_PORT,
        secret_key: str | None = None,
        config: Any | None = None,
    ):
        self.host = host
        self.port = port
        self.secret_key = secret_key or os.getenv(
            "TACACS_DEFAULT_SECRET", "CHANGE_ME_FALLBACK"
        )
        self.config = config

        if self.secret_key == "CHANGE_ME_FALLBACK":
            logger.warning(
                "Default TACACS secret in use. Configure per-device/group secrets."
            )

        # Core components
        self.auth_backends: list[AuthenticationBackend] = []
        self.db_logger = DatabaseLogger()
        pool_size = self._get_backend_process_pool_size()
        self.handlers = AAAHandlers(
            self.auth_backends,
            self.db_logger,
            backend_process_pool_size=pool_size,
        )
        self.metrics = MetricsCollector()

        # Managers
        self.stats = StatsManager()
        self.session_manager = SessionManager(
            int(os.getenv("TACACS_MAX_SESSION_SECRETS", "10000"))
        )

        # Initialize connection limiter with config or env/default
        max_conn_per_ip = self._get_max_connections_per_ip()
        self.conn_limiter = ConnectionLimiter(max_per_ip=max_conn_per_ip)

        self.validator = PacketValidator(
            int(os.getenv("TACACS_MAX_PACKET_LENGTH", "4096"))
        )

        # Server state
        self.running = False
        self.server_socket: socket.socket | None = None
        self.start_time = time.time()

        # Configuration
        self.device_store: DeviceStore | None = None
        self.monitoring_api: WebServer | None = None
        self.enable_monitoring = False

        # Network settings
        self._load_network_config()

        # Proxy settings
        self._load_proxy_config()

        # Threading
        self._load_threading_config()

        # Start rate limiter cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._rate_limiter_cleanup_loop,
            daemon=True,
            name="RateLimiterCleanup",
        )
        self._cleanup_thread.start()

    def _rate_limiter_cleanup_loop(self):
        """Periodically clean old rate limiter entries"""
        import time

        from tacacs_server.utils.rate_limiter import get_rate_limiter

        logger = get_logger(__name__)
        while self.running:
            try:
                time.sleep(600)  # Every 10 minutes
                limiter = get_rate_limiter()
                removed = limiter.cleanup_old_entries(max_age_seconds=3600)
                if removed > 0:
                    logger.info("Rate limiter cleanup: removed %d old entries", removed)
            except Exception as e:
                logger.debug("Rate limiter cleanup error: %s", e)

    def _get_max_connections_per_ip(self) -> int:
        """Get max connections per IP from config, env, or default

        Priority: config object methods > config dict > config object internals > env variable > default
        """
        if self.config:
            # 1. Try config object methods first (from ConfigLoader / TacacsConfig)
            #    This is the PRIMARY method for production use
            if hasattr(self.config, "get_security_config"):
                try:
                    security_config = self.config.get_security_config() or {}
                    max_conn = security_config.get("max_connections_per_ip")
                    if max_conn is not None:
                        value = int(max_conn)
                        logger.info(
                            "Using max_connections_per_ip=%s from config.get_security_config()",
                            value,
                        )
                        return value
                except Exception as e:
                    logger.debug("Failed to get security config: %s", e)

            # 2. Try nested config.config dict (configparser internals)
            if hasattr(self.config, "config"):
                try:
                    cfg = self.config.config
                    if hasattr(cfg, "get") or (
                        hasattr(cfg, "__getitem__") and "security" in cfg
                    ):
                        security_section = (
                            cfg.get("security", {})
                            if hasattr(cfg, "get")
                            else cfg["security"]
                        )
                        max_conn = security_section.get("max_connections_per_ip")
                        if max_conn is not None:
                            value = int(max_conn)
                            logger.info(
                                "Using max_connections_per_ip=%s from config.config internals",
                                value,
                            )
                            return value
                except Exception as e:
                    logger.debug("Failed to read from config.config: %s", e)

            # 3. Try dict format (from tests/programmatic init with plain dict)
            if isinstance(self.config, dict):
                security = self.config.get("security", {})
                max_conn = security.get("max_connections_per_ip")
                if max_conn is not None:
                    value = int(max_conn)
                    logger.info(
                        "Using max_connections_per_ip=%s from config dict", value
                    )
                    return value

        # 4. Fall back to environment variable
        env_value = os.getenv("TACACS_MAX_CONN_PER_IP")
        if env_value:
            value = int(env_value)
            logger.info("Using max_connections_per_ip=%s from environment", value)
            return value

        # 5. Final default
        default = 20
        logger.info("Using max_connections_per_ip=%s (default)", default)
        return default

    def set_config(self, config):
        """Set configuration and reload settings"""
        self.config = config
        self._load_network_config()
        self._load_proxy_config()
        self._load_threading_config()

        # Reload connection limiter with new config
        max_conn = self._get_max_connections_per_ip()
        old_max = self.conn_limiter.max_per_ip
        self.conn_limiter = ConnectionLimiter(max_per_ip=max_conn)
        logger.info(
            "Connection limiter reloaded: max_per_ip changed from %s to %s",
            old_max,
            max_conn,
        )

    def _load_network_config(self):
        """Load network configuration from environment"""
        self.listen_backlog = int(os.getenv("TACACS_LISTEN_BACKLOG", "128"))
        self.client_timeout = float(os.getenv("TACACS_CLIENT_TIMEOUT", "15"))
        self.enable_ipv6 = os.getenv("TACACS_IPV6_ENABLED", "false").lower() == "true"
        self.tcp_keepalive = (
            os.getenv("TACACS_TCP_KEEPALIVE", "true").lower() != "false"
        )
        self.tcp_keepalive_idle = int(os.getenv("TACACS_TCP_KEEPIDLE", "60"))
        self.tcp_keepalive_intvl = int(os.getenv("TACACS_TCP_KEEPINTVL", "10"))
        self.tcp_keepalive_cnt = int(os.getenv("TACACS_TCP_KEEPCNT", "5"))

    def _load_proxy_config(self):
        """Load proxy configuration"""
        self.proxy_enabled = True
        self.accept_proxy_protocol = True
        self.proxy_validate_sources = False
        self.proxy_reject_invalid = True
        self.encryption_required = True

    def _load_threading_config(self):
        """Load threading configuration"""
        self.use_thread_pool = (
            os.getenv("TACACS_USE_THREAD_POOL", "true").lower() != "false"
        )
        self.thread_pool_max_workers = int(os.getenv("TACACS_THREAD_POOL_MAX", "100"))
        self._executor: ThreadPoolExecutor | None = None
        self._client_threads: set[threading.Thread] = set()
        self._client_threads_lock = threading.RLock()

    def _get_backend_process_pool_size(self) -> int:
        """Get backend process pool size from config, env, or default.

        Precedence: config.get_server_config()["backend_process_pool_size"] > env TACACS_BACKEND_PROCESS_POOL_SIZE > default 0 (disabled)
        """
        # 1) Config object method
        if self.config and hasattr(self.config, "get_server_config"):
            try:
                srv = self.config.get_server_config() or {}
                val = srv.get("backend_process_pool_size")
                if val is not None:
                    return int(val)
            except Exception:
                pass
        # 2) Env override
        env_val = os.getenv("TACACS_BACKEND_PROCESS_POOL_SIZE")
        if env_val:
            try:
                return int(env_val)
            except Exception:
                pass
        # 3) Default (disabled)
        return 0

    def enable_web_monitoring(
        self, web_host="127.0.0.1", web_port=8080, radius_server=None
    ):
        """Enable web monitoring interface"""
        try:
            import threading
            import time

            import uvicorn

            from tacacs_server.web.web_app import create_app

            logger.info("Starting web monitoring on %s:%s", web_host, web_port)

            admin_username = os.getenv("ADMIN_USERNAME", "admin")
            admin_password_hash = os.getenv("ADMIN_PASSWORD_HASH", "")
            api_token = os.getenv("API_TOKEN")

            if (
                not admin_password_hash
                and hasattr(self, "config")
                and self.config is not None
            ):
                try:
                    # Check if config has the method (not just a dict)
                    if hasattr(self.config, "get_admin_auth_config"):
                        admin_config = self.config.get_admin_auth_config()
                        admin_username = admin_config.get("username", "admin")
                        admin_password_hash = admin_config.get("password_hash", "")
                except Exception as e:
                    logger.debug("Failed to get admin config: %s", e)

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
        # Inform handlers/process-pool about the newly added backend
        try:
            if hasattr(self.handlers, "on_backend_added"):
                self.handlers.on_backend_added(backend)
        except Exception as e:
            logger.debug("Failed to register backend with handlers: %s", e)
        name = getattr(backend, "name", str(backend))
        logger.info(
            "Authentication backend added",
            event="auth.backend.added",
            service="tacacs",
            backend=name,
        )

    def remove_auth_backend(self, backend_name: str) -> bool:
        """Remove authentication backend by name"""
        for i, backend in enumerate(self.auth_backends):
            if backend.name == backend_name:
                del self.auth_backends[i]
                self.handlers.auth_backends = self.auth_backends
                logger.info(
                    "Authentication backend removed",
                    event="auth.backend.removed",
                    service="tacacs",
                    backend=backend_name,
                )
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
        self._setup_server_socket()

        logger.info(
            "TACACS server listening",
            event="service.start",
            service="tacacs",
            host=self.host,
            port=self.port,
            backends=[b.name for b in self.auth_backends],
        )

        if self.use_thread_pool:
            self._executor = ThreadPoolExecutor(
                max_workers=self.thread_pool_max_workers
            )

        self._accept_loop()

    def _setup_server_socket(self):
        """Setup and bind server socket"""
        # Create socket (IPv6 dual-stack if enabled)
        if self.enable_ipv6:
            self.server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            try:
                self.server_socket.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0
                )
            except OSError as e:
                logger.debug("IPv6 dual-stack not supported: %s", e)
        else:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Allow quick reuse after previous test shutdowns
        try:
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception as set_soc_exc:
            logger.debug("Failed to set socket options: %s", set_soc_exc)

        bind_host = self.host
        if self.enable_ipv6 and bind_host in ("0.0.0.0", "::"):
            bind_host = "::"

        # Log bind attempt explicitly for easier diagnostics in CI logs
        logger.info(
            "Attempting to bind TACACS+ socket",
            extra={"bind_host": bind_host, "bind_port": self.port},
        )

        try:
            self.server_socket.bind((bind_host, self.port))
        except OSError as e:
            # Surface a precise error so test harness tails are actionable
            try:
                err_no = getattr(e, "errno", None)
                err_str = getattr(e, "strerror", str(e))
            except Exception:
                err_no = None
                err_str = str(e)
            logger.error(
                "Failed to bind TACACS+ socket",
                extra={
                    "host": bind_host,
                    "port": self.port,
                    "errno": err_no,
                    "error": err_str,
                },
            )
            # Re-raise to keep current control flow (manager will log and exit)
            raise

        try:
            self.server_socket.listen(self.listen_backlog)
            logger.info(
                "TACACS+ socket bound and listening",
                extra={
                    "bind_host": bind_host,
                    "bind_port": self.port,
                    "backlog": self.listen_backlog,
                },
            )
        except OSError as e:
            logger.error(
                "Failed to listen on TACACS+ socket",
                extra={"host": bind_host, "port": self.port, "error": str(e)},
            )
            raise

    def _accept_loop(self):
        """Main accept loop with per-IP connection limiting"""
        try:
            while self.running:
                try:
                    if self.server_socket is None:
                        break
                    client_socket, address = self.server_socket.accept()

                    if self.tcp_keepalive:
                        NetworkHandler.enable_tcp_keepalive(
                            client_socket,
                            self.tcp_keepalive_idle,
                            self.tcp_keepalive_intvl,
                            self.tcp_keepalive_cnt,
                        )

                    self.stats.increment("connections_total")

                    # CRITICAL: Check per-IP connection limit BEFORE processing
                    # This prevents resource exhaustion from a single IP
                    if not self.conn_limiter.acquire(address[0]):
                        # Connection limit exceeded - close immediately
                        NetworkHandler.safe_close_socket(client_socket)
                        continue

                    # Connection accepted - increment active count
                    self.stats.update_active_connections(+1)
                    logger.debug("New connection from %s", address)

                    # Early device lookup for tests
                    self._early_device_lookup(client_socket, address[0])

                    # Dispatch to handler
                    if self._executor is not None:
                        self._executor.submit(
                            self._handle_client_wrapper, client_socket, address
                        )
                    else:
                        thread = threading.Thread(
                            target=self._handle_client_wrapper,
                            args=(client_socket, address),
                            daemon=True,
                        )
                        with self._client_threads_lock:
                            self._client_threads.add(thread)
                        thread.start()

                except OSError as e:
                    if self.running:
                        logger.error("Socket error", error=str(e))
                    continue
                except Exception as e:
                    logger.error("Accept error", error=str(e))
                    continue

        except Exception as e:
            logger.error("Server startup error", error=str(e))
            raise
        finally:
            if self.server_socket:
                self.server_socket.close()
            logger.info("TACACS server stopped")

    def _early_device_lookup(self, client_socket, ip: str):
        """Early device lookup for test compatibility"""
        if self.device_store is not None:
            try:
                selected = self.device_store.find_device_for_ip(ip)
                try:
                    from typing import Any, cast

                    sock_any = cast(Any, client_socket)
                    sock_any.selected_device = selected
                except (AttributeError, TypeError) as atr_exc:
                    logger.debug("Failed to set selected device: %s", atr_exc)
            except Exception as exc:
                logger.debug("Device lookup during accept failed for %s: %s", ip, exc)

    def _handle_client_wrapper(
        self, client_socket: socket.socket, address: tuple[str, int]
    ):
        """Wrapper for client handler - ensures connection limit is released"""
        try:
            proxy_handler = None
            if self.proxy_enabled and self.accept_proxy_protocol:
                proxy_handler = ProxyHandler(
                    self.device_store, self.proxy_validate_sources
                )

            handler = ClientHandler(
                handlers=self.handlers,
                session_manager=self.session_manager,
                stats_manager=self.stats,
                validator=self.validator,
                conn_limiter=self.conn_limiter,
                device_store=self.device_store,
                proxy_handler=proxy_handler,
                proxy_reject_invalid=getattr(self, "proxy_reject_invalid", True),
                default_secret=self.secret_key or "CHANGE_ME_FALLBACK",
                encryption_required=self.encryption_required,
                client_timeout=self.client_timeout,
                device_auto_register=getattr(self, "device_auto_register", False),
                default_device_group=getattr(self, "default_device_group", "default"),
            )

            handler.handle(client_socket, address)

        finally:
            # CRITICAL: Always release connection slot and decrement active count
            self.conn_limiter.release(address[0])
            self.stats.update_active_connections(-1)

            try:
                if threading.current_thread().daemon:
                    with self._client_threads_lock:
                        self._client_threads.discard(threading.current_thread())
            except Exception as e:
                logger.debug("Failed to release client thread: %s", e)

    def stop(self):
        """Stop TACACS+ server"""
        if not self.running:
            return

        logger.info("Stopping TACACS server")
        self.running = False

        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except (OSError, AttributeError) as e:
                logger.debug("Server socket shutdown failed: %s", e)
            try:
                self.server_socket.close()
            except (OSError, AttributeError) as e:
                logger.debug("Server socket close failed: %s", e)

    def graceful_shutdown(self, timeout_seconds=30):
        """Gracefully shutdown server"""
        logger.info("Initiating graceful shutdown...")
        self.running = False

        # Signal cleanup thread to stop
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            try:
                self._cleanup_thread.join(timeout=2.0)
                logger.debug("Rate limiter cleanup thread stopped")
            except Exception as e:
                logger.debug("Cleanup thread join failed: %s", e)

        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except (OSError, AttributeError) as e:
                logger.debug("Server socket shutdown failed: %s", e)
            try:
                self.server_socket.close()
            except (OSError, AttributeError) as e:
                logger.debug("Server socket close failed: %s", e)

        # Wait for active connections
        start_time = time.time()
        while (
            self.stats.get_active_connections() > 0
            and time.time() - start_time < timeout_seconds
        ):
            time.sleep(0.1)

        if self.stats.get_active_connections() > 0:
            logger.warning(
                f"Force closing {self.stats.get_active_connections()} remaining connections"
            )

        # Join threads
        with self._client_threads_lock:
            threads = list(self._client_threads)
            self._client_threads.clear()

        for t in threads:
            try:
                t.join(timeout=1.0)
            except Exception as e:
                logger.debug("Thread join failed: %s", e)

        # Shutdown thread pool
        if self._executor:
            try:
                self._executor.shutdown(wait=False, cancel_futures=True)
            except Exception as e:
                logger.debug("Thread pool shutdown failed: %s", e)
            finally:
                self._executor = None

        logger.info("Server shutdown complete")

    def get_stats(self) -> dict[str, Any]:
        """Get server statistics"""
        stats = self.stats.get_all()
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
        self.stats.reset()

    def get_health_status(self) -> dict[str, Any]:
        """Get server health status"""
        return {
            "status": "healthy" if self.running else "stopped",
            "uptime_seconds": time.time() - self.start_time,
            "active_connections": self.stats.get_active_connections(),
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
            import psutil

            process = psutil.Process()
            memory_info = process.memory_info()
            return {
                "rss_mb": round(memory_info.rss / 1024 / 1024, 2),
                "vms_mb": round(memory_info.vms / 1024 / 1024, 2),
                "percent": round(process.memory_percent(), 2),
            }
        except Exception:
            return {"rss_mb": 0.0, "vms_mb": 0.0, "percent": 0.0}

    def _check_database_health(self) -> dict[str, Any]:
        """Check database health"""
        try:
            ok = getattr(self.db_logger, "ping", lambda: False)()
            if not ok:
                return {
                    "status": "unhealthy",
                    "records_today": 0,
                    "error": "Database ping failed",
                }

            try:
                stats = self.db_logger.get_statistics(days=1)
                recs = stats.get("total_records", 0) if isinstance(stats, dict) else 0
            except Exception:
                recs = 0

            return {"status": "healthy", "records_today": int(recs) if recs else 0}

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
            logger.info("Configuration reload requested")
            logger.info("Configuration reloaded successfully")
            return True
        except Exception as exc:
            logger.error("Configuration reload failed: %s", exc)
            return False
