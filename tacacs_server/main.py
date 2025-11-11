import argparse
import os
import signal
import sys
import textwrap
from collections import Counter
from pathlib import Path
from typing import Any, cast

from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.auth.local_store import LocalAuthStore
from tacacs_server.auth.local_user_group_service import LocalUserGroupService
from tacacs_server.auth.local_user_service import LocalUserService
from tacacs_server.config.config import TacacsConfig, setup_logging
from tacacs_server.devices.service import DeviceService
from tacacs_server.devices.store import DeviceStore
from tacacs_server.tacacs.server import TacacsServer
from tacacs_server.utils.config_utils import set_config as utils_set_config
from tacacs_server.utils.logger import bind_context, get_logger
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


class TacacsServerManager:
    """TACACS+ Server Manager"""

    def __init__(self, config_file: str = "config/tacacs.conf"):
        self.config = TacacsConfig(config_file)
        monitoring_set_config(self.config)
        # Mirror into utils accessor so API modules using config_utils see it
        try:
            utils_set_config(self.config)
            logger.info("Configuration registered with utilities module")
        except Exception as e:
            logger.error(
                "Failed to register config with utilities: %s", e, exc_info=True
            )
            # This is critical - if utils can't access config, API will fail
            raise
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
        self._config_refresh_thread: Any | None = None
        # Optional backup service instance (initialized later)
        self.backup_service: Any | None = None

        # Ensure instance identity and initial version
        try:
            store = getattr(self.config, "config_store", None)
            if store is not None:
                instance_id = store.ensure_instance_id()
                instance_name = store.get_instance_name()
                if not instance_name:
                    try:
                        import socket as _socket

                        hostname = _socket.gethostname()
                    except Exception:
                        hostname = "node"
                    name = (
                        os.getenv("INSTANCE_NAME")
                        or f"tacacs-{hostname}-{instance_id[:8]}"
                    )
                    store.set_instance_name(name)
                    instance_name = name
                # Bind instance identity into log context for all subsequent logs
                try:
                    bind_context(instance_id=instance_id, instance_name=instance_name)
                except Exception:
                    pass
                logger.info(f"Instance: {instance_name} (ID: {instance_id[:8]}...)")
                # Initial configuration snapshot
                try:
                    cfg_dict = self.config._export_full_config()
                    store.create_version(
                        config_dict=cfg_dict,
                        created_by="system",
                        description="Initial configuration snapshot",
                    )
                except Exception as e:
                    logger.warning(f"Failed to create initial config version: {e}")
        except Exception:
            logger.debug("Instance identity/version init skipped")

    def setup(self):
        """Setup server components"""
        setup_logging(self.config)
        # Capture a configuration snapshot at startup
        try:
            store = getattr(self.config, "config_store", None)
            if store is not None:
                cfg_dict = self.config._export_full_config()  # base + overrides
                store.create_version(
                    config_dict=cfg_dict,
                    created_by="system",
                    description="Configuration at startup",
                )
        except Exception:
            logger.debug("Failed to create startup configuration snapshot")
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
            config=self.config,  # Pass config to constructor for proper initialization
        )
        # Config is now passed in constructor and accessible via self.server.config
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
        try:
            net_cfg = self.config.get_server_network_config()
            self.server.listen_backlog = int(net_cfg.get("listen_backlog", 128))
            self.server.client_timeout = float(net_cfg.get("client_timeout", 15))
            # max_packet_length is set in validator during __init__, not as server attribute
            self.server.enable_ipv6 = bool(net_cfg.get("ipv6_enabled", False))
            self.server.tcp_keepalive = bool(net_cfg.get("tcp_keepalive", True))
            self.server.tcp_keepalive_idle = int(net_cfg.get("tcp_keepidle", 60))
            self.server.tcp_keepalive_intvl = int(net_cfg.get("tcp_keepintvl", 10))
            self.server.tcp_keepalive_cnt = int(net_cfg.get("tcp_keepcnt", 5))
            self.server.thread_pool_max_workers = int(
                net_cfg.get("thread_pool_max", 100)
            )
            self.server.use_thread_pool = bool(net_cfg.get("use_thread_pool", True))
            # Legacy PROXY protocol toggles from [server]
            self.server.accept_proxy_protocol = bool(
                net_cfg.get("accept_proxy_protocol", True)
            )
            # Wire proxy_enabled into server instance for request handling & stats
            try:
                self.server.proxy_enabled = bool(net_cfg.get("proxy_enabled", False))
            except Exception:
                self.server.proxy_enabled = False
            # New proxy protocol config overrides
            try:
                pxy = self.config.get_proxy_protocol_config()
                self.server.proxy_enabled = bool(
                    pxy.get("enabled", self.server.proxy_enabled)
                )
                self.server.accept_proxy_protocol = bool(
                    pxy.get("accept_proxy_protocol", self.server.accept_proxy_protocol)
                )
                self.server.proxy_validate_sources = bool(
                    pxy.get("validate_sources", True)
                )
                try:
                    self.server.proxy_reject_invalid = bool(
                        pxy.get("reject_invalid", True)
                    )
                except Exception:
                    self.server.proxy_reject_invalid = True
            except Exception:
                pass
        except Exception:
            pass
        # Initialize webhook runtime config from file
        try:
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
        except Exception:
            pass
        # Apply security-related runtime limits
        try:
            sec_cfg = self.config.get_security_config()
            # max_connections_per_ip is handled internally by ConnectionLimiter
            # which reads from config during server __init__, no need to set here

            # Propagate encryption policy to TACACS server for runtime enforcement
            if self.server is not None:
                try:
                    self.server.encryption_required = bool(
                        sec_cfg.get("encryption_required", True)
                    )
                except Exception:
                    self.server.encryption_required = True
        except Exception:
            pass

        # Initialize backup system
        try:
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
        except Exception as e:
            logger.error(f"Failed to initialize backup system: {e}")
            # Don't fail startup if backup system has issues
            self.backup_service = None

        # Initialize device inventory
        try:
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
            # Wire device auto-registration behavior into TACACS server
            try:
                cast(Any, self.server).device_auto_register = bool(
                    self.device_store_config.get("auto_register", True)
                )
                cast(
                    Any, self.server
                ).default_device_group = self.device_store_config.get(
                    "default_group", "default"
                )
            except Exception:
                pass
        except Exception as exc:
            logger.exception("Failed to initialise device store: %s", exc)
            self.device_store = None
            self.device_service = None
            set_device_service(None)

        # Initialize local authentication store and services
        auth_db_path = self.config.get_local_auth_db()

        local_store: LocalAuthStore | None = None
        try:
            local_store = LocalAuthStore(auth_db_path)
            self.local_auth_store = local_store
        except Exception as exc:
            logger.exception("Failed to initialise local auth store: %s", exc)
            self.local_auth_store = None

        if local_store is None:
            self.local_user_service = None
            self.local_user_group_service = None
            set_local_user_service(None)
            set_local_user_group_service(None)
            if self.server and hasattr(self.server, "handlers"):
                self.server.handlers.set_local_user_group_service(None)
        else:
            try:
                self.local_user_service = LocalUserService(
                    auth_db_path,
                    store=local_store,
                )
                set_local_user_service(self.local_user_service)
            except Exception as exc:
                logger.exception("Failed to initialise local user service: %s", exc)
                self.local_user_service = None
                set_local_user_service(None)

            try:
                self.local_user_group_service = LocalUserGroupService(
                    auth_db_path,
                    store=local_store,
                )
                set_local_user_group_service(self.local_user_group_service)
                if self.server and hasattr(self.server, "handlers"):
                    self.server.handlers.set_local_user_group_service(
                        self.local_user_group_service
                    )
            except Exception as exc:
                logger.exception(
                    "Failed to initialise local user group service: %s", exc
                )
                self.local_user_group_service = None
                set_local_user_group_service(None)
                if self.server and hasattr(self.server, "handlers"):
                    self.server.handlers.set_local_user_group_service(None)

            # If configured, create/link a default Okta user group
            try:
                # Read from ConfigParser correctly; do not call .get() on the parser
                cp = self.config.config
                if cp is not None and cp.has_section("okta"):
                    default_okta_group = str(
                        cp.get("okta", "default_okta_group", fallback="")
                    ).strip()
                else:
                    default_okta_group = ""
            except Exception:
                default_okta_group = ""
            if default_okta_group and self.local_user_group_service:
                try:
                    # Ensure local user group exists with okta_group mapping
                    local_group_name = "okta-default-group"
                    try:
                        grp = self.local_user_group_service.get_group(local_group_name)
                        if getattr(grp, "okta_group", None) != default_okta_group:
                            self.local_user_group_service.update_group(
                                local_group_name, okta_group=default_okta_group
                            )
                    except Exception:
                        self.local_user_group_service.create_group(
                            local_group_name,
                            description="Auto-created default Okta user group",
                            okta_group=default_okta_group,
                            privilege_level=1,
                        )

                    # Link this user group to the default device group if device store is available
                    if self.device_store and self.device_service:
                        dg_name = (
                            self.device_store_config.get("default_group")
                            if isinstance(self.device_store_config, dict)
                            else None
                        ) or "default"
                        dg = self.device_store.get_group_by_name(dg_name)
                        if dg and dg.id is not None:
                            allowed = list(getattr(dg, "allowed_user_groups", []) or [])
                            if local_group_name not in allowed:
                                allowed.append(local_group_name)
                                self.device_service.update_group(
                                    dg.id, allowed_user_groups=allowed
                                )
                except Exception:
                    logger.debug(
                        "Default Okta group initialization skipped due to error",
                        exc_info=True,
                    )

        # Register pending refresh if radius server not yet initialised
        if self.device_store and not self.radius_server:
            self._pending_radius_refresh = True

        # Configure admin authentication
        try:
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
                try:
                    from typing import Any as _Any

                    import bcrypt

                    _ver: _Any = getattr(bcrypt, "__version__", None)
                    _ = _ver  # prevent unused variable
                except Exception as exc:
                    logger.error(
                        "Admin auth configured but bcrypt unavailable: %s. "
                        "Ensure image has bcrypt built for this Python version.",
                        exc,
                    )
            else:
                logger.warning(
                    "Admin password hash not configured; "
                    "admin routes will be unauthenticated"
                )
                set_admin_session_manager(None)
                set_admin_auth_dependency(None)
        except Exception as exc:
            logger.exception("Failed to configure admin authentication: %s", exc)
            self.admin_session_manager = None
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
                    except Exception:
                        pass
                    # Pass privilege check ordering preference to handlers
                    try:
                        self.server.handlers.privilege_check_order = str(priv_order)
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            # Do not fail startup if command authorization engine fails
            pass

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
                        interval = int(os.getenv("CONFIG_REFRESH_SECONDS", "300"))
                        _t.sleep(max(30, interval))
                    except Exception:
                        _t.sleep(60)

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
            except Exception:
                pass
            if self.device_store:
                self.radius_server.device_store = self.device_store
                # Wire device auto-registration behavior into RADIUS server
                try:
                    cast(Any, self.radius_server).device_auto_register = bool(
                        self.device_store_config.get("auto_register", True)
                    )
                    cast(
                        Any, self.radius_server
                    ).default_device_group = self.device_store_config.get(
                        "default_group", "default"
                    )
                except Exception:
                    pass
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
                except Exception:
                    pass
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
    test_client_code = textwrap.dedent('''\
        #!/usr/bin/env python3
        """Simple TACACS+ PAP client for quick end-to-end checks."""

        from __future__ import annotations

        import argparse
        import hashlib
        import socket
        import struct
        import sys
        import time
        from dataclasses import dataclass
        from typing import Optional


        def md5_pad(
            session_id: int, key: str, version: int, seq_no: int, length: int
        ) -> bytes:
            pad = bytearray()
            session_id_bytes = struct.pack("!L", session_id)
            key_bytes = key.encode("utf-8")
            version_byte = bytes([version])
            seq_byte = bytes([seq_no])

            while len(pad) < length:
                if not pad:
                    md5_input = session_id_bytes + key_bytes + version_byte + seq_byte
                else:
                    md5_input = (
                        session_id_bytes + key_bytes + version_byte + seq_byte + pad
                    )
                pad.extend(hashlib.md5(md5_input, usedforsecurity=False).digest())

            return bytes(pad[:length])


        def transform_body(
            body: bytes, session_id: int, key: str, version: int, seq_no: int
        ) -> bytes:
            if not key:
                return body
            pad = md5_pad(session_id, key, version, seq_no, len(body))
            return bytes(a ^ b for a, b in zip(body, pad))


        @dataclass
        class PapResult:
            success: bool
            status: int
            server_message: Optional[str]
            detail: str


        def pap_authentication(
            host: str = "localhost",
            port: int = 49,
            key: str = "tacacs123",
            username: str = "admin",
            password: str = "admin123",
        ) -> PapResult:
            print("\n=== TACACS+ PAP Authentication Test ===\n")
            print(f"Target        : {host}:{port}")
            print(f"Username      : {username}")
            obscured = "*" * len(password) if password else "(empty)"
            print(f"Password      : {obscured}")
            print(f"Shared Secret : {key}\n")

            sock: Optional[socket.socket] = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((host, port))

                session_id = int(time.time()) & 0xFFFFFFFF
                user_bytes = username.encode("utf-8")
                port_bytes = b"console"
                rem_addr_bytes = b"127.0.0.1"
                data_bytes = password.encode("utf-8")

                body = struct.pack(
                    "!BBBBBBBB",
                    1,
                    15,
                    2,
                    1,
                    len(user_bytes),
                    len(port_bytes),
                    len(rem_addr_bytes),
                    len(data_bytes),
                )
                body += user_bytes + port_bytes + rem_addr_bytes + data_bytes

                version = 0xC0
                seq_no = 1
                encrypted_body = transform_body(body, session_id, key, version, seq_no)
                header = struct.pack(
                    "!BBBBLL", version, 1, seq_no, 0, session_id, len(encrypted_body)
                )

                print("Sending PAP authentication request...")
                sock.sendall(header + encrypted_body)

                response_header = sock.recv(12)
                if len(response_header) != 12:
                    return PapResult(False, -1, None, "invalid response header")

                r_version, r_type, r_seq, _, r_session, r_length = struct.unpack(
                    "!BBBBLL", response_header
                )
                print(f"Received header: type={r_type}, seq={r_seq}, length={r_length}")

                response_body = sock.recv(r_length) if r_length else b""
                if len(response_body) < r_length:
                    return PapResult(False, -1, None, "truncated response body")

                decrypted = transform_body(
                    response_body, r_session, key, r_version, r_seq
                )
                if len(decrypted) < 6:
                    return PapResult(False, -1, None, "response too short")

                status, _flags, msg_len, data_len = struct.unpack(
                    "!BBHH", decrypted[:6]
                )
                offset = 6
                server_message = None
                if msg_len:
                    server_message = decrypted[offset:offset + msg_len].decode(
                        "utf-8", errors="replace"
                    )
                    offset += msg_len

                success = status == 1
                detail = {
                    1: "authentication accepted",
                    2: "authentication rejected",
                    0: "user continues",
                }.get(status, f"status={status}")

                print()
                if success:
                    print("Result        : ✅ Authentication accepted")
                else:
                    print("Result        : ❌ Authentication rejected")
                print(f"Status Detail : {detail}")
                if server_message:
                    print(f"Server Message: {server_message}")
                if data_len:
                    attr_data = decrypted[offset:offset + data_len]
                    print(f"Additional Data ({data_len} bytes): {attr_data.hex()}")

                return PapResult(success, status, server_message, detail)

            except OSError as exc:
                print(f"✗ Network error: {exc}")
                return PapResult(False, -1, None, "network error")
            except Exception as exc:
                print(f"✗ Unexpected error: {exc}")
                return PapResult(False, -1, None, "unexpected error")
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass


        def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
            parser = argparse.ArgumentParser(description="Simple TACACS+ PAP client")
            parser.add_argument(
                "host", nargs="?", default="localhost", 
                help="Server host (default: localhost)"
            )
            parser.add_argument(
                "port", nargs="?", type=int, default=49, 
                help="Server port (default: 49)"
            )
            parser.add_argument(
                "secret", nargs="?", default="tacacs123", help="Shared secret"
            )
            parser.add_argument("username", nargs="?", default="admin", help="Username")
            parser.add_argument(
                "password", nargs="?", default="admin123", help="Password"
            )
            return parser.parse_args(argv)


        def main(argv: Optional[list[str]] = None) -> int:
            args = parse_args(argv)
            result = pap_authentication(
                args.host, args.port, args.secret, args.username, args.password
            )
            return 0 if result.success else 1


        if __name__ == "__main__":
            sys.exit(main())
    ''')
    import os
    import stat

    os.makedirs("scripts", exist_ok=True)
    script_path = "scripts/tacacs_client.py"
    with open(script_path, "w") as f:
        f.write(test_client_code)
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
