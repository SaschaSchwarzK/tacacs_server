import argparse
import os
import signal
import sys
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.auth.local_store import LocalAuthStore
from tacacs_server.auth.local_user_group_service import LocalUserGroupService
from tacacs_server.auth.local_user_service import LocalUserService
from tacacs_server.config.config import TacacsConfig, setup_logging
from tacacs_server.devices.service import DeviceService
from tacacs_server.devices.store import DeviceStore
from tacacs_server.tacacs.server import TacacsServer
from tacacs_server.utils.config_utils import set_config as utils_set_config
from tacacs_server.utils.logger import get_logger
from tacacs_server.web.admin.auth import (
    AdminAuthConfig,
    AdminSessionManager,
    get_admin_auth_dependency,
)
from tacacs_server.web.web import (
    set_admin_auth_dependency,
    set_admin_session_manager,
    set_device_service,
    set_local_user_group_service,
    set_local_user_service,
)
from tacacs_server.web.web import (
    set_config as monitoring_set_config,
)

logger = get_logger(__name__)

DEFAULT_SERVER_HOST = "localhost"
DEFAULT_TACACS_PORT = 49
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_SHARED_SECRET = "tacacs123"
DEFAULT_CONFIG_REFRESH_SECONDS = 300
DEFAULT_CONFIG_REFRESH_MIN_SLEEP = 30
DEFAULT_TCP_KEEPALIVE_IDLE = 60
DEFAULT_LISTEN_BACKLOG = 128
DEFAULT_THREAD_POOL_MAX = 100


@contextmanager
def safe_init(
    name: str,
    *,
    raise_on_fail: bool = False,
    on_error: Callable[[Exception], None] | None = None,
):
    """Context manager to wrap non-critical initialization with consistent logging."""

    try:
        yield
    except Exception as exc:
        logger.warning("%s initialization failed: %s", name, exc)
        if on_error:
            try:
                on_error(exc)
            except Exception:
                logger.debug("safe_init error callback failed for %s", name)
        if raise_on_fail:
            raise


class TacacsServerManager:
    """TACACS+ Server Manager"""

    def __init__(self, config_file: str = "config/tacacs.conf"):
        self.config = TacacsConfig(config_file)
        self._apply_global_config()
        self.server: TacacsServer | None = None
        self.radius_server: Any | None = None
        from tacacs_server.devices.service import DeviceService as _DSe
        from tacacs_server.devices.store import (
            DeviceStore as _DS,
        )  # local import for typing

        self.device_store: _DS | None = None
        self.device_service: _DSe | None = None
        self.local_auth_store: LocalAuthStore | None = None
        from tacacs_server.auth.local_user_group_service import (
            LocalUserGroupService as _LUGS,
        )
        from tacacs_server.auth.local_user_service import LocalUserService as _LUS
        from tacacs_server.web.admin.auth import AdminSessionManager as _ASM

        self.local_user_service: _LUS | None = None
        self.local_user_group_service: _LUGS | None = None
        self.admin_session_manager: _ASM | None = None
        self.device_store_config: dict[str, Any] = {}
        self.running = False
        from collections.abc import Callable

        self._device_change_unsubscribe: Callable[[], None] | None = None
        self._pending_radius_refresh = False
        import threading as _th

        self._config_refresh_thread: _th.Thread | None = None
        # Optional backup service instance (initialized in setup())
        self.backup_service: Any | None = None

    def _apply_global_config(self) -> None:
        """Atomically mirror config into all global consumers."""
        monitoring_set_config(self.config)
        # Mirror into utils accessor so API modules using config_utils see it
        with safe_init("config utils mirror", raise_on_fail=True):
            utils_set_config(self.config)

        # Ensure instance identity and initial version
        with safe_init("instance metadata"):
            store = getattr(self.config, "config_store", None)
            if store is None:
                return
            instance_id = store.ensure_instance_id()
            instance_name = store.get_instance_name()
            if not instance_name:
                try:
                    import socket as _socket

                    hostname = _socket.gethostname()
                except Exception:
                    hostname = "node"
                name = os.getenv("INSTANCE_NAME") or f"tacacs-{hostname}-{instance_id[:8]}"
                store.set_instance_name(name)
                instance_name = name
            logger.info("Instance: %s (ID: %s...)", instance_name, instance_id[:8])
            with safe_init("initial config snapshot"):
                cfg_dict = self.config._export_full_config()
                store.create_version(
                    config_dict=cfg_dict,
                    created_by="system",
                    description="Initial configuration snapshot",
                )

    def setup(self):
        """Setup server components"""
        setup_logging(self.config)
        # Capture a configuration snapshot at startup
        with safe_init("startup config snapshot"):
            store = getattr(self.config, "config_store", None)
            if store is not None:
                cfg_dict = self.config._export_full_config()  # base + overrides
                store.create_version(
                    config_dict=cfg_dict,
                    created_by="system",
                    description="Configuration at startup",
                )
        issues = self.config.validate_config()
        if issues:
            logger.error("Configuration validation failed:")
            for issue in issues:
                logger.error(f"  - {issue}")
            return False
        server_config = self.config.get_server_config()
        self.server = TacacsServer(
            host=server_config["host"],
            port=server_config["port"],
        )
        # Configure accounting database logger path from config
        try:
            from tacacs_server.accounting.database import DatabaseLogger as _DBL

            db_cfg = self.config.get_database_config()
            acct_path = db_cfg.get("accounting_db")
            if acct_path:
                self.server.db_logger = _DBL(acct_path)
                # Rebind handlers to use the new logger
                if hasattr(self.server, "handlers") and self.server.handlers:
                    self.server.handlers.db_logger = self.server.db_logger
        except Exception:
            # Fall back to default path if config/bind fails; server remains usable
            pass
        # Apply extended server/network tuning
        with safe_init("network tuning"):
            net_cfg = self.config.get_server_network_config()
            self.server.listen_backlog = int(
                net_cfg.get("listen_backlog", DEFAULT_LISTEN_BACKLOG)
            )
            self.server.client_timeout = float(net_cfg.get("client_timeout", 15))
            # Adjust validator limit instead of setting a non-existent attribute
            if hasattr(self.server, "validator") and self.server.validator:
                self.server.validator.max_packet_length = int(
                    net_cfg.get("max_packet_length", 4096)
                )
            self.server.enable_ipv6 = bool(net_cfg.get("ipv6_enabled", False))
            self.server.tcp_keepalive = bool(net_cfg.get("tcp_keepalive", True))
            self.server.tcp_keepalive_idle = int(
                net_cfg.get("tcp_keepidle", DEFAULT_TCP_KEEPALIVE_IDLE)
            )
            self.server.tcp_keepalive_intvl = int(net_cfg.get("tcp_keepintvl", 10))
            self.server.tcp_keepalive_cnt = int(net_cfg.get("tcp_keepcnt", 5))
            self.server.thread_pool_max_workers = int(
                net_cfg.get("thread_pool_max", DEFAULT_THREAD_POOL_MAX)
            )
            self.server.use_thread_pool = bool(net_cfg.get("use_thread_pool", True))

            # Proxy protocol settings from single source
            pxy = self.config.get_proxy_protocol_config()
            self.server.proxy_enabled = bool(pxy.get("enabled", False))
            self.server.accept_proxy_protocol = bool(pxy.get("enabled", False))
            self.server.proxy_validate_sources = bool(pxy.get("validate_sources", True))
            self.server.proxy_reject_invalid = bool(pxy.get("reject_invalid", True))
        # Initialize webhook runtime config from file
        with safe_init("webhook config"):
            from tacacs_server.utils.webhook import set_webhook_config as _set_wh

            wh = self.config.get_webhook_config()
            _set_wh(
                urls=wh.get("urls"),
                headers=wh.get("headers"),
                template=wh.get("template"),
                timeout=wh.get("timeout"),
                threshold_count=wh.get("threshold_count"),
                threshold_window=wh.get("threshold_window"),
            )
        # Apply security-related runtime limits
        with safe_init("security runtime limits"):
            sec_cfg = getattr(self, "_cached_security_config", None)
            if sec_cfg is None:
                sec_cfg = self.config.get_security_config()
                self._cached_security_config = sec_cfg
            per_ip_cap = int(sec_cfg.get("max_connections_per_ip", 20))
            if per_ip_cap >= 1 and self.server:
                # Replace connection limiter with new per-IP cap
                try:
                    from tacacs_server.utils.rate_limiter import (
                        ConnectionLimiter as _ConnLimiter,
                    )

                    self.server.conn_limiter = _ConnLimiter(max_per_ip=per_ip_cap)
                except Exception:
                    pass
            # Propagate encryption policy to TACACS server for runtime enforcement
            if self.server is not None:
                try:
                    self.server.encryption_required = bool(
                        sec_cfg.get("encryption_required", True)
                    )
                except Exception:
                    self.server.encryption_required = True

        # Initialize backup system
        with safe_init("backup system"):
            from tacacs_server.backup.service import initialize_backup_service

            backup_service = initialize_backup_service(self.config)
            self.backup_service = backup_service

            logger.info("Backup system initialized")

            # Create initial backup if configured
            try:
                initial_backup = self.config.config.getboolean(
                    "backup", "create_on_startup", fallback=False
                )
            except Exception:
                initial_backup = False
            if initial_backup:
                try:
                    destinations = backup_service.execution_store.list_destinations(
                        enabled_only=True
                    )
                    if destinations:
                        backup_service.create_manual_backup(
                            destination_id=destinations[0]["id"], created_by="system"
                        )
                        logger.info("Created startup backup")
                except Exception:
                    logger.warning("Startup backup creation skipped due to error")

        # Initialize device inventory
        with safe_init("device store setup"):
            self.device_store_config = self.config.get_device_store_config()
            net_cfg = self.config.get_server_network_config()
            self.device_store = DeviceStore(
                self.device_store_config["database"],
                identity_cache_ttl_seconds=self.device_store_config.get(
                    "identity_cache_ttl_seconds"
                ),
                identity_cache_maxsize=self.device_store_config.get(
                    "identity_cache_size"
                ),
                proxy_enabled=bool(net_cfg.get("proxy_enabled", False)),
            )
            default_group = self.device_store_config.get("default_group")
            if default_group:
                self.device_store.ensure_group(
                    default_group, description="Default device group"
                )
            self.device_service = DeviceService(self.device_store)
            set_device_service(self.device_service)
            self._device_change_unsubscribe = self.device_service.add_change_listener(
                self._handle_device_change
            )
            # Expose store on server for future integrations
            if hasattr(self.server, "device_store"):
                self.server.device_store = self.device_store
        if self.device_store is None or self.device_service is None:
            self.device_service = None
            set_device_service(None)

        # Initialize local authentication store and services
        auth_db_path = self.config.get_local_auth_db()

        local_store: LocalAuthStore | None = None
        with safe_init("local auth store"):
            local_store = LocalAuthStore(auth_db_path)
            self.local_auth_store = local_store

        if local_store is None:
            self.local_user_service = None
            self.local_user_group_service = None
            set_local_user_service(None)
            set_local_user_group_service(None)
            if self.server and hasattr(self.server, "handlers"):
                self.server.handlers.set_local_user_group_service(None)
        else:
            with safe_init("local user service"):
                self.local_user_service = LocalUserService(
                    auth_db_path,
                    store=local_store,
                )
                set_local_user_service(self.local_user_service)
            if self.local_user_service is None:
                set_local_user_service(None)

            with safe_init("local user group service"):
                self.local_user_group_service = LocalUserGroupService(
                    auth_db_path,
                    store=local_store,
                )
                set_local_user_group_service(self.local_user_group_service)
                if self.server and hasattr(self.server, "handlers"):
                    self.server.handlers.set_local_user_group_service(
                        self.local_user_group_service
                    )
            if self.local_user_group_service is None:
                set_local_user_group_service(None)
                if self.server and hasattr(self.server, "handlers"):
                    self.server.handlers.set_local_user_group_service(None)

        # Register pending refresh if radius server not yet initialised
        if self.device_store and not self.radius_server:
            self._pending_radius_refresh = True

        # Configure admin authentication
        with safe_init("admin authentication"):
            admin_auth_cfg = self.config.get_admin_auth_config()
            username = admin_auth_cfg.get("username", "admin")
            password_hash = admin_auth_cfg.get("password_hash", "")
            if password_hash:
                auth_config = AdminAuthConfig(
                    username=username,
                    password_hash=password_hash,
                    session_timeout_minutes=admin_auth_cfg.get(
                        "session_timeout_minutes", 60
                    ),
                )
                self.admin_session_manager = AdminSessionManager(auth_config)
                set_admin_session_manager(self.admin_session_manager)
                assert self.admin_session_manager is not None
                dependency = get_admin_auth_dependency(self.admin_session_manager)
                set_admin_auth_dependency(dependency)
                logger.info("Admin authentication enabled for username '%s'", username)
                # Proactive bcrypt availability check to surface image issues early
                with safe_init("bcrypt availability check"):
                    from typing import Any as _Any

                    import bcrypt

                    _ver: _Any = getattr(bcrypt, "__version__", None)
                    _ = _ver  # prevent unused variable
            else:
                logger.warning(
                    "Admin password hash not configured; "
                    "admin routes will be unauthenticated"
                )
                set_admin_session_manager(None)
                set_admin_auth_dependency(None)
        if self.admin_session_manager is None:
            set_admin_session_manager(None)
            set_admin_auth_dependency(None)
        # Setup RADIUS server if enabled
        radius_config = self.config.get_radius_config()
        if radius_config["enabled"]:
            self._setup_radius_server(radius_config)
        auth_backends = self.config.create_auth_backends()
        for backend in auth_backends:
            if isinstance(backend, LocalAuthBackend) and self.local_user_service:
                backend.set_user_service(self.local_user_service)
            if self.server:
                self.server.add_auth_backend(backend)
            if self.radius_server and radius_config.get("share_backends", False):
                if backend not in getattr(self.radius_server, "auth_backends", []):
                    self.radius_server.add_auth_backend(backend)

        if self.radius_server and radius_config.get("share_backends", False):
            shared = len(getattr(self.radius_server, "auth_backends", []))
            logger.info("RADIUS: Sharing %d auth backends with TACACS+", shared)
        # Always initialize command authorization engine for TACACS handlers
        try:
            from tacacs_server.authorization.command_authorization import (
                ActionType,
                CommandAuthorizationEngine,
            )
            from tacacs_server.web.web import (
                set_command_authorizer as _set_authz,
            )
            from tacacs_server.web.web import (
                set_command_engine as _set_engine,
            )

            ca_cfg = self.config.get_command_authorization_config()
            engine = CommandAuthorizationEngine()
            engine.load_from_config(ca_cfg.get("rules") or [])
            engine.default_action = (
                ActionType.PERMIT
                if (ca_cfg.get("default_action") == "permit")
                else ActionType.DENY
            )
            default_mode = ca_cfg.get("response_mode", "pass_add")
            priv_order = ca_cfg.get("privilege_check_order", "before")

            def authorizer(cmd: str, priv: int, groups, device_group):
                allowed, reason, attrs, rule_mode = engine.authorize_command(
                    cmd,
                    privilege_level=priv,
                    user_groups=groups,
                    device_group=device_group,
                )
                mode = rule_mode or default_mode
                return allowed, reason, (attrs or {}), mode

            _set_engine(engine)
            _set_authz(authorizer)
            # Also inject engine into TACACS handlers directly for deterministic use
            try:
                if (
                    self.server
                    and hasattr(self.server, "handlers")
                    and self.server.handlers
                ):
                    self.server.handlers.command_engine = engine
                    # Provide default response mode for handler fallback (when rule has none)
                    try:
                        self.server.handlers.command_response_mode_default = str(
                            default_mode
                        )
                    except Exception as exc:
                        logger.warning(
                            "Failed to set default command response mode: %s", exc
                        )
                    # Pass privilege check ordering preference to handlers
                    try:
                        self.server.handlers.privilege_check_order = str(priv_order)
                    except Exception as exc:
                        logger.warning("Failed to set privilege check order: %s", exc)
            except Exception as exc:
                logger.warning("Failed to inject command engine into handlers: %s", exc)
        except Exception as exc:
            # Do not fail startup if command authorization engine fails
            logger.warning("Command authorization engine init failed: %s", exc)

        # Enable monitoring if configured (tolerate missing section)
        # read monitoring section safely: prefer helper API, fallback to RawConfigParser
        # items()
        try:
            if hasattr(self.config, "get_monitoring_config"):
                monitoring_config = self.config.get_monitoring_config() or {}
            else:
                # self.config.config is a ConfigParser/RawConfigParser
                try:
                    monitoring_config = dict(
                        getattr(self.config, "config").items("monitoring")
                    )
                except Exception:
                    monitoring_config = {}
        except Exception:
            monitoring_config = {}

        if str(monitoring_config.get("enabled", "false")).lower() == "true":
            web_host = monitoring_config.get("web_host", "127.0.0.1")
            web_port = int(monitoring_config.get("web_port", "8080"))
            logger.info(
                "Monitoring configured -> attempting to enable web monitoring on %s:%s",
                web_host,
                web_port,
            )
            try:
                # Web monitoring relies on engine already initialized above.
                # Do not reinitialize the command engine here to avoid overwriting
                # any runtime/test-injected rules.
                started = False
                if self.server:
                    started = self.server.enable_web_monitoring(
                        web_host, web_port, radius_server=self.radius_server
                    )
                if started:
                    logger.info(
                        "Monitoring successfully started at http://%s:%s",
                        web_host,
                        web_port,
                    )
                else:
                    logger.error(
                        "Monitoring failed to start "
                        "(enable_web_monitoring returned False)"
                    )
            except Exception as e:
                logger.exception("Exception while enabling monitoring: %s", e)
        return True

    def _start_config_refresh_scheduler(self) -> None:
        """Start background thread to refresh URL-based config periodically."""
        try:
            import threading
            import time as _t

            if not hasattr(self.config, "refresh_url_config"):
                return

            def _worker():
                # Loop until manager stops
                while True:
                    try:
                        if not self.running:
                            break
                        updated = False
                        try:
                            updated = bool(self.config.refresh_url_config(False))
                        except Exception:
                            updated = False
                        if updated:
                            logger.info("URL configuration refresh applied")
                        # Sleep for configured interval or default 5 minutes
                        interval = int(
                            os.getenv(
                                "CONFIG_REFRESH_SECONDS",
                                str(DEFAULT_CONFIG_REFRESH_SECONDS),
                            )
                        )
                        _t.sleep(max(DEFAULT_CONFIG_REFRESH_MIN_SLEEP, interval))
                    except Exception:
                        _t.sleep(DEFAULT_CONFIG_REFRESH_MIN_SLEEP * 2)

            th = threading.Thread(target=_worker, daemon=True)
            th.start()
            self._config_refresh_thread = th
        except Exception:
            logger.debug("Failed to start config refresh scheduler")

    def _handle_device_change(self) -> None:
        try:
            self._refresh_radius_clients()
        except Exception:
            logger.exception(
                "Failed to refresh RADIUS clients after device inventory change"
            )

    def _refresh_radius_clients(self) -> None:
        if not self.device_store:
            return
        try:
            client_configs = self.device_store.iter_radius_clients()
        except Exception as exc:
            logger.exception("Failed to build RADIUS client list: %s", exc)
            return
        if not self.radius_server:
            self._pending_radius_refresh = True
            return
        self.radius_server.refresh_clients(client_configs)
        self._pending_radius_refresh = False

    def _setup_radius_server(self, radius_config: dict[str, Any]):
        """Setup RADIUS server"""
        try:
            from tacacs_server.radius.server import RADIUSServer

            radius_server = RADIUSServer(
                host=radius_config["host"],
                port=radius_config["auth_port"],
                accounting_port=radius_config["acct_port"],
            )
            self.radius_server = radius_server
            # Apply advanced tuning from config
            try:
                self.radius_server.workers = max(
                    1, min(64, int(radius_config.get("workers", 8)))
                )
                self.radius_server.socket_timeout = max(
                    0.1, float(radius_config.get("socket_timeout", 1.0))
                )
                self.radius_server.rcvbuf = max(
                    262144, int(radius_config.get("rcvbuf", 1048576))
                )
            except Exception as exc:
                logger.warning("Failed to apply RADIUS tuning config: %s", exc)
            if self.device_store:
                self.radius_server.device_store = self.device_store
            if self.local_user_group_service and self.radius_server:
                self.radius_server.set_local_user_group_service(
                    self.local_user_group_service
                )

            # Configure RADIUS client devices from the device store when available
            initial_clients: list[Any] = []
            if self.device_store:
                try:
                    initial_clients = self.device_store.iter_radius_clients()
                except Exception as exc:
                    logger.exception(
                        "Failed to load clients from device store: %s", exc
                    )
                    initial_clients = []

            if self.radius_server:
                self.radius_server.refresh_clients(initial_clients)
            configured_clients = len(initial_clients)
            if not initial_clients:
                logger.info("RADIUS: no clients defined in device store")

            # Share authentication backends with TACACS+
            if radius_config["share_backends"] and self.server and self.radius_server:
                shared_initial = 0
                for backend in self.server.auth_backends:
                    if backend not in getattr(self.radius_server, "auth_backends", []):
                        self.radius_server.add_auth_backend(backend)
                        shared_initial += 1
                if shared_initial and self.radius_server:
                    logger.info(
                        "RADIUS: Sharing %d auth backends with TACACS+",
                        len(getattr(self.radius_server, "auth_backends", [])),
                    )

            # Share accounting database with TACACS+
            if radius_config["share_accounting"] and self.server and self.radius_server:
                self.radius_server.set_accounting_logger(self.server.db_logger)
                logger.info("RADIUS: Sharing accounting database with TACACS+")

            logger.info("RADIUS server configured with %d clients", configured_clients)

            if self._pending_radius_refresh:
                self._refresh_radius_clients()

        except Exception as e:
            logger.error(f"Failed to setup RADIUS server: {e}")
            self.radius_server = None

    def start(self):
        """Start the TACACS+ server"""
        if not self.setup():
            return False
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        try:
            self.running = True
            logger.info("=" * 50)
            logger.info("TACACS+ & RADIUS Server Starting")
            logger.info("=" * 50)
            self._print_startup_info()
            # Start URL config refresh scheduler if applicable
            try:
                self._start_config_refresh_scheduler()
            except Exception:
                logger.debug("Config refresh scheduler not started")
            # Start RADIUS server if configured
            if self.radius_server:
                self.radius_server.start()
            # Start TACACS+ server
            if self.server:
                self.server.start()
            # Keep the process alive until a shutdown signal is received
            # The TACACS+ server runs its own accept loop internally; this loop
            # ensures the main process does not exit immediately after startup.
            import time as _time

            while self.running:
                _time.sleep(0.2)

        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        except Exception as e:
            logger.error(f"Server error: {e}")
            return False
        finally:
            self.stop()
        return True

    def stop(self):
        """Stop the TACACS+ server"""
        if self.server and self.running:
            logger.info("Shutting down servers...")
            self.running = False
            # Stop backup scheduler
            if getattr(self, "backup_service", None):
                try:
                    sched = getattr(self.backup_service, "scheduler", None)
                    if sched:
                        sched.stop()
                        logger.info("Backup scheduler stopped")
                except Exception as e:  # noqa: BLE001
                    logger.error(f"Error stopping backup scheduler: {e}")
            # Stop RADIUS server
            if self.radius_server:
                self.radius_server.stop()
            # Gracefully close auth backends (e.g., Okta sessions)
            try:
                for backend in getattr(self.server, "auth_backends", []) or []:
                    close_fn = getattr(backend, "close", None)
                    if callable(close_fn):
                        try:
                            close_fn()
                        except Exception:
                            logger.debug(
                                "Backend %s close() failed",
                                getattr(backend, "name", backend.__class__.__name__),
                            )
            except Exception:
                logger.debug("Failed to close auth backends cleanly")
            if self._device_change_unsubscribe:
                try:
                    self._device_change_unsubscribe()
                except Exception:
                    logger.exception("Failed to detach device change listener")
                finally:
                    self._device_change_unsubscribe = None
            # Stop TACACS+ server
            self.server.stop()
            logger.info("Servers stopped successfully")

    def _signal_handler(self, signum, frame):
        """Handle system signals"""
        logger.info(f"Received signal {signum}")
        self.stop()

    def _print_startup_info(self):
        """Print server startup information"""
        server_config = self.config.get_server_config()
        auth_backends = (
            [b.name for b in self.server.auth_backends] if self.server else []
        )
        db_config = self.config.get_database_config()
        logger.info(f"Server Address: {server_config['host']}:{server_config['port']}")
        logger.info("Secrets: Per-device group configuration")
        logger.info(f"Authentication Backends: {', '.join(auth_backends)}")
        logger.info(f"Database: {db_config['accounting_db']}")
        source = getattr(self.config, "config_source", self.config.config_file)
        logger.info(f"Configuration: {source}")
        logger.info("")
        logger.info("Testing authentication backends:")
        if self.server:
            for backend in self.server.auth_backends:
                status = "✓ Available" if backend.is_available() else "✗ Unavailable"
                logger.info(f"  {backend.name}: {status}")
                try:
                    if getattr(backend, "name", "").lower() == "okta":
                        stats = getattr(backend, "get_stats", lambda: {})() or {}
                        flags = stats.get("flags", {}) or {}
                        logger.info(
                            "    Okta flags: authn=%s strict_group=%s trust_env=%s require_group=%s",
                            flags.get("authn_enabled", True),
                            flags.get("strict_group_mode"),
                            flags.get("trust_env"),
                            flags.get("require_group_for_auth"),
                        )
                except Exception as exc:
                    logger.warning("Failed to log Okta backend flags: %s", exc)
        # Add RADIUS info
        if self.radius_server:
            logger.info("")
            logger.info("RADIUS Server:")
            logger.info(f"  Authentication Port: {self.radius_server.port}")
            logger.info(f"  Accounting Port: {self.radius_server.accounting_port}")
            client_list = getattr(self.radius_server, "clients", [])
            logger.info(f"  Configured Clients: {len(client_list)}")
            if client_list:
                if isinstance(client_list, dict):
                    entries = list(client_list.values())
                else:
                    entries = list(client_list)

                try:
                    group_counts = Counter(
                        (
                            entry.get("group")
                            if isinstance(entry, dict)
                            else getattr(entry, "group", None)
                        )
                        or "ungrouped"
                        for entry in entries
                    )
                    summary = ", ".join(
                        f"{group}({count})"
                        for group, count in group_counts.most_common(5)
                    )
                    if len(group_counts) > 5:
                        summary += ", ..."
                    logger.info("  Client Groups: %s", summary)
                except Exception:
                    # If summarising fails just skip detailed output
                    pass
        logger.info("")
        logger.info("Server ready - waiting for connections...")
        logger.info("Press Ctrl+C to stop")


def create_test_client_script():
    """Create test client script"""
    template_candidates = [
        Path(__file__).resolve().parent / "templates" / "tacacs_client.py.template"
    ]

    content = None
    for candidate in template_candidates:
        if candidate.exists():
            content = candidate.read_text(encoding="utf-8")
            break

    if content is None:
        raise FileNotFoundError("tacacs_client.py.template not found")

    import os
    import stat

    os.makedirs("scripts", exist_ok=True)
    script_path = "scripts/tacacs_client.py"
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(content)
    st = os.stat(script_path)
    os.chmod(script_path, st.st_mode | stat.S_IEXEC)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="TACACS+ Server")
    parser.add_argument(
        "-c", "--config", default="config/tacacs.conf", help="Configuration file path"
    )
    parser.add_argument(
        "--create-test-client",
        action="store_true",
        help="Create test client script and exit",
    )
    parser.add_argument(
        "--validate-config", action="store_true", help="Validate configuration and exit"
    )
    parser.add_argument("--version", action="version", version="TACACS+ Server 1.0")
    args = parser.parse_args()
    for directory in ["config", "data", "logs", "tests", "scripts"]:
        Path(directory).mkdir(exist_ok=True)
    if args.create_test_client:
        try:
            create_test_client_script()
            print("Test client created: scripts/tacacs_client.py")
            print(
                "Usage: python scripts/tacacs_client.py [host] [port] [secret] "
                "[username] [password]"
            )
        except Exception as e:
            print(f"Error creating test client: {e}")
            return 1
        return 0
    if args.validate_config:
        try:
            config = TacacsConfig(args.config)
            issues = config.validate_config()
            if issues:
                print("Configuration validation failed:")
                for issue in issues:
                    print(f"  - {issue}")
                return 1
            else:
                print("Configuration is valid")
                return 0
        except Exception as e:
            print(f"Error validating configuration: {e}")
            return 1
    try:
        server_manager = TacacsServerManager(args.config)
        success = server_manager.start()
        return 0 if success else 1
    except Exception as e:
        print(f"Failed to start server: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
