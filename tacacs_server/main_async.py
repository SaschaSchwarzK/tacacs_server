from __future__ import annotations
import asyncio
import logging
import signal
from typing import Any
from tacacs_server.runtime import ServerRuntime
from tacacs_server.adapters import TacacsAdapter, RadiusAdapter
from tacacs_server.config.config import TacacsConfig
from tacacs_server.web.monitoring import (
    TacacsMonitoringAPI,
    set_config as monitoring_set_config,
    set_device_service,
    set_local_user_service,
    set_local_user_group_service,
    set_admin_session_manager,
    set_admin_auth_dependency,
)
from tacacs_server.web.admin.auth import (
    AdminSessionManager,
    AdminAuthConfig,
    get_admin_auth_dependency,
)
from tacacs_server.devices.store import DeviceStore
from tacacs_server.devices.service import DeviceService
from tacacs_server.auth.local_user_service import LocalUserService
from tacacs_server.auth.local_user_group_service import LocalUserGroupService
from tacacs_server.auth.local_store import LocalAuthStore

log = logging.getLogger(__name__)

class _AsyncServerShim:
    """Lightweight shim to satisfy web monitoring expectations."""

    def __init__(self, host: str, port: int, *, auth_backends: list[Any] | None = None, db_logger: Any | None = None, runtime: Any | None = None):
        self.host = host
        self.port = port
        self.running = True
        self.auth_backends: list[Any] = list(auth_backends or [])
        self.db_logger = db_logger
        self._runtime = runtime
        self._start_time = asyncio.get_event_loop().time()
        self._stats = {
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

        class _Sock:
            def __init__(self, h: str, p: int):
                self._hp = (h, p)

            def getsockname(self):
                return self._hp

        self.server_socket = _Sock(host, port)

    def get_health_status(self) -> dict[str, Any]:
        uptime = max(0.0, asyncio.get_event_loop().time() - self._start_time)
        mem = {}
        try:
            import psutil  # type: ignore

            vm = psutil.virtual_memory()
            mem = {"total": vm.total, "used": vm.used, "percent": vm.percent}
        except Exception:
            mem = {}
        return {
            "status": "running" if self.running else "stopped",
            "running": self.running,
            "address": f"{self.host}:{self.port}",
            "uptime_seconds": int(uptime),
            "memory_usage": mem,
        }

    def get_stats(self) -> dict[str, Any]:
        # Prefer live runtime stats if available
        try:
            if self._runtime and hasattr(self._runtime, "get_stats"):
                stats = self._runtime.get_stats()  # type: ignore[call-arg]
                # Map minimal fields expected by admin templates
                return {
                    "connections_active": stats.get("connections_active", 0),
                    "connections_total": stats.get("connections_total", 0),
                    "auth_requests": stats.get("tacacs_auth_ok", 0) + stats.get("tacacs_auth_err", 0),
                    "auth_success": stats.get("tacacs_auth_ok", 0),
                    "auth_failures": stats.get("tacacs_auth_err", 0),
                    "author_requests": stats.get("tacacs_author_ok", 0) + stats.get("tacacs_author_err", 0),
                    "author_success": stats.get("tacacs_author_ok", 0),
                    "author_failures": stats.get("tacacs_author_err", 0),
                    "acct_requests": stats.get("tacacs_acct_ok", 0) + stats.get("tacacs_acct_err", 0),
                    "acct_success": stats.get("tacacs_acct_ok", 0),
                    "acct_failures": stats.get("tacacs_acct_err", 0),
                }
        except Exception:
            pass
        return dict(self._stats)

    # Admin control shims used by monitoring API
    def reset_stats(self) -> bool:
        try:
            self._stats = {k: 0 for k in self._stats}
            return True
        except Exception:
            return False

    def reload_configuration(self) -> bool:
        # No-op in async shim; real implementation could re-read cfg
        return True


async def _run() -> None:
    # Load config upfront (respect TACACS_CONFIG if provided)
    import os as _os
    cfg_path = _os.environ.get("TACACS_CONFIG", "config/tacacs.conf")
    cfg = TacacsConfig(cfg_path)
    monitoring_set_config(cfg)

    # Initialize services needed for TACACS and web admin
    device_service = None
    try:
        device_store_cfg = cfg.get_device_store_config()
        ds = DeviceStore(device_store_cfg["database"])
        default_group = device_store_cfg.get("default_group")
        if default_group:
            try:
                ds.ensure_group(default_group, description="Default device group")
            except Exception:
                pass
        device_service = DeviceService(ds)
        set_device_service(device_service)
    except Exception:
        logging.getLogger(__name__).exception("Failed to initialize DeviceService")
        set_device_service(None)

    # Local auth users/groups for web admin
    try:
        auth_db_path = cfg.get_local_auth_db()
        local_store = LocalAuthStore(auth_db_path)
        user_service = LocalUserService(auth_db_path, store=local_store)
        group_service = LocalUserGroupService(auth_db_path, store=local_store)
        set_local_user_service(user_service)
        set_local_user_group_service(group_service)
    except Exception:
        logging.getLogger(__name__).exception("Failed to initialize local user services")
        set_local_user_service(None)
        set_local_user_group_service(None)

    # Build AAAHandlers with configured backends and accounting DB
    from tacacs_server.tacacs.handlers import AAAHandlers
    from tacacs_server.accounting.database import DatabaseLogger

    aaa = None
    backends = []
    db_logger = None
    try:
        backends = cfg.create_auth_backends()
        db_cfg = cfg.get_database_config() if hasattr(cfg, "get_database_config") else {}
        db_logger = DatabaseLogger(db_cfg.get("accounting_db", "data/tacacs_accounting.db"))
        aaa = AAAHandlers(backends, db_logger)
    except Exception:
        logging.getLogger(__name__).exception("Failed to initialize AAAHandlers")

    # Prepare TACACS adapter with real dependencies
    class _Deps:
        pass

    deps = _Deps()
    deps.device_service = device_service
    deps.aaa_handlers = aaa
    deps.encryption_required = bool(cfg.get_security_config().get("encryption_required", True))
    deps.max_len = 262_144
    deps.db_logger = db_logger

    tacacs = TacacsAdapter(deps=deps)
    # Pass deps including device_service and db_logger for RADIUS secret/accounting
    radius = RadiusAdapter(deps=deps)

    # Map configuration/env to async runtime tuning
    net_cfg = {}
    try:
        net_cfg = cfg.get_server_network_config() or {}
    except Exception:
        net_cfg = {}
    def _get_env_float(name: str, default: float) -> float:
        try:
            v = _os.environ.get(name)
            return float(v) if v is not None else default
        except Exception:
            return default
    def _get_env_int(name: str, default: int) -> int:
        try:
            v = _os.environ.get(name)
            return int(v) if v is not None else default
        except Exception:
            return default

    tcp_idle_timeout = _get_env_float("ASYNC_TCP_IDLE_TIMEOUT", float(net_cfg.get("client_timeout", 15.0)))
    tcp_read_timeout = _get_env_float("ASYNC_TCP_READ_TIMEOUT", float(net_cfg.get("client_timeout", 15.0)))
    max_conc_tcp = _get_env_int("ASYNC_MAX_CONCURRENCY_TCP", 200)
    max_conc_udp = _get_env_int("ASYNC_MAX_CONCURRENCY_UDP", 200)

    # Map server host/port from config (tests set non-privileged random ports)
    try:
        sc = cfg.get_server_config()
        tac_host = sc.get("host", "127.0.0.1")
        tac_port = int(sc.get("port", 49))
    except Exception:
        tac_host, tac_port = "127.0.0.1", 49
    try:
        rcfg = cfg.get_radius_config() or {"enabled": False}
        rad_host = rcfg.get("host", tac_host)
        rad_port = int(rcfg.get("auth_port", 1812))
        radius_enabled = bool(rcfg.get("enabled", False))
    except Exception:
        rad_host, rad_port, radius_enabled = tac_host, 1812, False

    rt = ServerRuntime(
        tacacs_host=tac_host,
        tacacs_port=tac_port,
        radius_host=rad_host if radius_enabled else tac_host,
        radius_port=rad_port if radius_enabled else 1812,
        max_concurrency_tcp=max_conc_tcp,
        max_concurrency_udp=max_conc_udp,
        tcp_idle_timeout_sec=tcp_idle_timeout,
        tcp_read_timeout_sec=tcp_read_timeout,
        handler_tacacs=tacacs.authenticate,
        handler_radius=radius.handle,
    )

    # Install a UDP precheck to validate RADIUS Message-Authenticator if present
    def _udp_precheck(data: bytes, addr_tuple: tuple[str, int]) -> bool:
        try:
            # Resolve shared secret from device store (prefer radius client config)
            secret: bytes = b""
            try:
                ds = getattr(deps, "device_service", None)
                if ds is not None:
                    find = getattr(ds, "store", None)
                    if find and hasattr(find, "resolve_radius_client"):
                        rc = find.resolve_radius_client(addr_tuple[0])
                        if rc is not None and getattr(rc, "secret", None):
                            secret = str(rc.secret).encode("utf-8")
                    if not secret and find and hasattr(find, "find_device_for_ip"):
                        dev = find.find_device_for_ip(addr_tuple[0])
                        if dev and getattr(dev, "group", None):
                            secret = (getattr(dev.group, "radius_secret", None) or "").encode("utf-8")
            except Exception:
                secret = b""
            if not secret:
                return True  # cannot validate without a secret; accept

            # Basic header
            if len(data) < 20:
                return False
            code = data[0]
            ident = data[1]  # noqa: F841 - reserved for potential logging
            length = int.from_bytes(data[2:4], "big")
            if length > len(data) or length < 20:
                return False
            req_auth = data[4:20]

            # If Accounting-Request (4), verify Request Authenticator (RFC 2866)
            if code == 4 and secret:
                import hashlib as _hashlib, warnings as _warnings
                hdr = data[:4]
                attrs = data[20:length]
                zeros = b"\x00" * 16
                with _warnings.catch_warnings():
                    _warnings.simplefilter("ignore", DeprecationWarning)
                    calc = _hashlib.md5(hdr + zeros + attrs + secret, usedforsecurity=False).digest()
                if calc != req_auth:
                    return False

            # Scan attributes for Message-Authenticator (type 80)
            pos = 20
            idx = -1
            while pos + 2 <= length:
                at = data[pos]
                alen = data[pos + 1]
                if alen < 2 or pos + alen > length:
                    return False
                if at == 80 and alen == 18:
                    idx = pos
                    break
                pos += alen
            if idx == -1:
                return True  # no Message-Authenticator present
            import hashlib as _hashlib, hmac as _hmac, warnings as _warnings

            tmp = bytearray(data[:length])
            for i in range(16):
                tmp[idx + 2 + i] = 0
            with _warnings.catch_warnings():
                _warnings.simplefilter("ignore", DeprecationWarning)
                mac = _hmac.new(secret, bytes(tmp[:length]), digestmod=_hashlib.md5).digest()
            recv = data[idx + 2 : idx + 18]
            try:
                return _hmac.compare_digest(mac, recv)
            except Exception:
                return mac == recv
        except Exception:
            return False

    try:
        setattr(rt, "_udp_precheck", _udp_precheck)
    except Exception:
        pass
    await rt.start()

    # At this point, services are initialized above

    web_started = False
    web_api = None
    try:
        admin_auth_cfg = cfg.get_admin_auth_config()
        password_hash = admin_auth_cfg.get("password_hash", "")
        if password_hash:
            auth_cfg = AdminAuthConfig(
                username=admin_auth_cfg.get("username", "admin"),
                password_hash=password_hash,
                session_timeout_minutes=admin_auth_cfg.get("session_timeout_minutes", 60),
            )
            asm = AdminSessionManager(auth_cfg)
            set_admin_session_manager(asm)
            set_admin_auth_dependency(get_admin_auth_dependency(asm))

            # Only start web admin if monitoring is enabled in config
            try:
                monitoring_config = cfg.get_monitoring_config() or {}
            except Exception:
                monitoring_config = {}
            if str(monitoring_config.get("enabled", "false")).lower() == "true":
                web_host = monitoring_config.get("web_host", "127.0.0.1")
                web_port = int(monitoring_config.get("web_port", "8080"))
                shim = _AsyncServerShim(host=rt.tacacs_host, port=rt.tacacs_port, auth_backends=backends, db_logger=db_logger, runtime=rt)
                api = TacacsMonitoringAPI(shim, host=web_host, port=web_port, radius_server=None)
                # Initialize command authorization engine and expose to monitoring API
                try:
                    from tacacs_server.authorization.command_authorization import (
                        ActionType,
                        CommandAuthorizationEngine,
                    )
                    from tacacs_server.web.monitoring import (
                        set_command_authorizer,
                        set_command_engine,
                    )

                    ca_cfg = cfg.get_command_authorization_config()
                    engine = CommandAuthorizationEngine()
                    rules = ca_cfg.get("rules") or []
                    engine.load_from_config(rules)
                    engine.default_action = (
                        ActionType.PERMIT
                        if (ca_cfg.get("default_action") == "permit")
                        else ActionType.DENY
                    )

                    def authorizer(cmd: str, priv: int, user_groups: list[str] | None, device_group: str | None):
                        try:
                            return engine.is_command_allowed(cmd, priv, user_groups or [], device_group)
                        except Exception:
                            return False, "error"

                    set_command_engine(engine)
                    set_command_authorizer(authorizer)
                except Exception:
                    pass
                try:
                    api.start()
                    web_started = True
                    web_api = api
                    logging.getLogger(__name__).info(
                        "Web monitoring started at http://%s:%s", web_host, web_port
                    )
                except Exception:
                    logging.getLogger(__name__).exception("Failed to start web monitoring")
        else:
            logging.getLogger(__name__).info(
                "Admin password hash not set; web admin will not start"
            )
    except Exception:
        logging.getLogger(__name__).exception("Admin/monitoring setup failed")

    stop_ev = asyncio.Event()
    loop = asyncio.get_running_loop()

    # Signal handling: POSIX only; tolerate environments where it's unavailable
    try:
        loop.add_signal_handler(signal.SIGTERM, stop_ev.set)
        loop.add_signal_handler(signal.SIGINT, stop_ev.set)
    except NotImplementedError:
        log.debug("Signal handlers not available on this platform")

    try:
        await stop_ev.wait()
    except KeyboardInterrupt:
        pass
    finally:
        await rt.stop()
        try:
            if web_started and web_api is not None:
                web_api.stop()
        except Exception:
            logging.getLogger(__name__).debug("Failed to stop web monitoring cleanly")

def main() -> None:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_run())

if __name__ == "__main__":
    main()
