"""
Configuration Management for TACACS+ Server
"""

import configparser
import json
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from logging.handlers import RotatingFileHandler
from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen

from tacacs_server.auth.ldap_auth import LDAPAuthBackend
from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.utils.logger import configure as configure_logging
from tacacs_server.utils.logger import get_logger

from .config_store import ConfigStore, compute_config_hash
from .schema import TacacsConfigSchema, validate_config_file

logger = get_logger(__name__)


# helper to normalize backend entries (string, dict, ...)
def _normalize_backend_name(item: Any) -> str:
    """
    Convert a backend entry to a backend name string.
    Handles:
      - "local" -> "local"
      - {"name": "local", ...} -> "local"
      - {"local": {...}} -> "local"
      - other -> str(item)
    """
    if isinstance(item, str):
        return item.strip()
    if isinstance(item, dict):
        if "name" in item:
            return str(item["name"]).strip()
        if len(item) == 1:
            return str(next(iter(item.keys()))).strip()
        # fallback: try common keys
        for key in ("type", "backend"):
            if key in item:
                return str(item[key]).strip()
        return str(next(iter(item.keys()))).strip()
    return str(item)


class TacacsConfig:
    """TACACS+ server configuration manager"""

    def __init__(self, config_file: str = "config/tacacs.conf"):
        env_source = os.environ.get("TACACS_CONFIG")
        self.config_source = env_source or config_file
        self.config_file = (
            None if self._is_url(self.config_source) else self.config_source
        )
        self.config = configparser.ConfigParser(interpolation=None)
        # Initialize the configuration override store (creates DB/tables on first run)
        try:
            # Ensure data directory exists before creating store
            os.makedirs("data", exist_ok=True)
            self.config_store: ConfigStore | None = ConfigStore(
                "data/config_overrides.db"
            )
            logger.info("Configuration store initialized successfully")
        except Exception as e:
            # Log the actual error but allow server to continue
            logger.error(
                "Failed to initialize configuration store: %s", e, exc_info=True
            )
            self.config_store = None
        # Track baseline (pre-override) snapshot and which keys were overridden
        self._baseline_snapshot: dict[str, dict[str, str]] = {}
        self.overridden_keys: dict[str, set[str]] = {}
        # URL configuration caching (initialize before loading so fallback works)
        self._baseline_cache_path = os.path.join("data", "config_baseline_cache.conf")
        try:
            os.makedirs(os.path.dirname(self._baseline_cache_path), exist_ok=True)
        except Exception:
            pass
        # Load base configuration (file or URL), then overlay DB overrides
        self._load_config()
        self._snapshot_baseline()
        self._apply_overrides()
        # Default refresh interval (seconds)
        self._refresh_interval_seconds = int(os.getenv("CONFIG_REFRESH_SECONDS", "300"))

    def _load_config(self):
        """Load configuration from file"""
        self._set_defaults()
        try:
            if self._is_url(self.config_source):
                self._load_from_url(self.config_source)
            else:
                path = self.config_file or self.config_source
                if os.path.exists(path):
                    self.config.read(path)
                else:
                    self.config_file = path
                    self.save_config()
        except Exception as e:
            logger.exception("Failed to load configuration (%s). Using defaults.", e)

    def _set_defaults(self):
        """Set default configuration values"""
        self.config["server"] = {
            "host": "0.0.0.0",
            "port": "49",
            "log_level": "INFO",
            "max_connections": "50",
            "socket_timeout": "30",
            "listen_backlog": "128",
            "client_timeout": "15",
            "max_packet_length": "4096",
            "ipv6_enabled": "false",
            "tcp_keepalive": "true",
            "tcp_keepidle": "60",
            "tcp_keepintvl": "10",
            "tcp_keepcnt": "5",
            "thread_pool_max": "100",
            "use_thread_pool": "true",
        }
        self.config["auth"] = {
            "backends": "local",
            "local_auth_db": "data/local_auth.db",
            "require_all_backends": "false",
            # runtime tuning
            "local_auth_cache_ttl_seconds": "60",
            "backend_timeout": "2.0",
        }
        self.config["ldap"] = {
            "server": "ldap://localhost:389",
            "base_dn": "ou=people,dc=example,dc=com",
            "user_attribute": "uid",
            "bind_dn": "",
            "bind_password": "",
            "use_tls": "false",
            "timeout": "10",
        }
        self.config["database"] = {
            "accounting_db": "data/tacacs_accounting.db",
            "cleanup_days": "90",
            "auto_cleanup": "true",
            "metrics_history_db": "data/metrics_history.db",
            "audit_trail_db": "data/audit_trail.db",
            "metrics_retention_days": "30",
            "audit_retention_days": "90",
            # connection pool size for accounting DB
            "db_pool_size": "5",
        }
        self.config["security"] = {
            "max_auth_attempts": "3",
            "auth_timeout": "300",
            "encryption_required": "true",
            "allowed_clients": "",
            "denied_clients": "",
            "rate_limit_requests": "60",
            "rate_limit_window": "60",
            "max_connections_per_ip": "20",
        }
        self.config["webhooks"] = {
            "urls": "",
            "headers_json": "{}",
            "template_json": "{}",
            "timeout": "3",
            "threshold_count": "0",
            "threshold_window": "60",
        }
        self.config["logging"] = {
            "log_file": "logs/tacacs.log",
            "log_format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "log_rotation": "true",
            "max_log_size": "10MB",
            "backup_count": "5",
        }
        # Optional syslog output
        self.config["syslog"] = {
            "enabled": "false",
            "host": "127.0.0.1",
            "port": "514",
            "protocol": "udp",
            "facility": "local0",
            "severity": "info",
            "format": "rfc5424",
            "app_name": "tacacs_server",
            "include_hostname": "true",
        }
        self.config["command_authorization"] = {
            "default_action": "deny",
            # Seed with a sensible read-only rule example
            "rules_json": "[{'action':'permit','match_type':'prefix','pattern':'show ','min_privilege':1}]".replace(
                "'", '"'
            ),
            # Privilege check order relative to command policy: before | after | none
            # - before (legacy): enforce requested priv-lvl <= user privilege before policy
            # - after: evaluate command policy first; do not pre-block on priv mismatch
            # - none: disable explicit priv-level enforcement; policy decides entirely
            "privilege_check_order": "before",
        }
        # Backup configuration defaults
        self.config["backup"] = {
            "enabled": "true",
            "create_on_startup": "false",
            "temp_directory": "data/backup_temp",
            # Encryption
            "encryption_enabled": "false",
            "encryption_passphrase": "",
            # Default retention policy
            "default_retention_strategy": "simple",
            "default_retention_days": "30",
            # GFS defaults (if strategy=gfs)
            "gfs_keep_daily": "7",
            "gfs_keep_weekly": "4",
            "gfs_keep_monthly": "12",
            "gfs_keep_yearly": "3",
            # Compression (1=fastest, 9=best)
            "compression_level": "6",
        }
        self.config["admin"] = {
            "username": os.environ.get("ADMIN_USERNAME", "admin"),
            "password_hash": os.environ.get("ADMIN_PASSWORD_HASH", ""),
            "session_timeout_minutes": "60",
        }
        self.config["devices"] = {
            "database": "data/devices.db",
            "default_group": "default",
            # Lookup/cache tuning
            "identity_cache_ttl_seconds": "60",
            "identity_cache_size": "10000",
        }
        self.config["radius"] = {
            "enabled": "false",
            "auth_port": "1812",
            "acct_port": "1813",
            "host": "0.0.0.0",
            "share_backends": "true",
            "share_accounting": "true",
            # Advanced tuning
            "workers": "8",
            "socket_timeout": "1.0",
            "rcvbuf": "1048576",
        }
        # Optional web monitoring
        self.config["monitoring"] = {
            "enabled": "false",
            "web_host": "127.0.0.1",
            "web_port": "8080",
        }
        # PROXY protocol configuration
        self.config["proxy_protocol"] = {
            "enabled": "false",
            "validate_sources": "true",
            "reject_invalid": "true",
        }

    def save_config(self):
        """Save configuration to file"""
        if self._is_url(self.config_source):
            raise RuntimeError("Cannot save configuration when source is a URL")

        if not self.config_file:
            raise ValueError("No configuration file path specified")

        try:
            cfg_dir = os.path.dirname(self.config_file)
            if cfg_dir and (not os.path.exists(cfg_dir)):
                os.makedirs(cfg_dir, exist_ok=True)
            with open(self.config_file, "w") as fh:
                self.config.write(fh)
        except OSError as e:
            logger.error("Failed to save configuration to %s: %s", self.config_file, e)
            raise RuntimeError(f"Configuration save failed: {e}") from e
        except Exception as e:
            logger.exception("Unexpected error saving configuration: %s", e)
            raise

    def get_server_config(self) -> dict[str, Any]:
        """Get server configuration (excluding sensitive values)"""
        host = os.environ.get("SERVER_HOST", self.config.get("server", "host"))
        port_env = os.environ.get("SERVER_PORT")
        try:
            port = int(port_env) if port_env else self.config.getint("server", "port")
        except Exception:
            port = self.config.getint("server", "port")
        return {
            "host": host,
            "port": port,
            # secret_key intentionally omitted to avoid accidental leakage
            "max_connections": self.config.getint("server", "max_connections"),
            "socket_timeout": self.config.getint("server", "socket_timeout"),
        }

    def get_server_network_config(self) -> dict[str, Any]:
        """Get extended server/network tuning parameters."""
        s = self.config["server"]
        return {
            "listen_backlog": int(s.get("listen_backlog", 128)),
            "client_timeout": float(s.get("client_timeout", 15)),
            "max_packet_length": int(s.get("max_packet_length", 4096)),
            "ipv6_enabled": str(s.get("ipv6_enabled", "false")).lower() == "true",
            "tcp_keepalive": str(s.get("tcp_keepalive", "true")).lower() != "false",
            "tcp_keepidle": int(s.get("tcp_keepidle", 60)),
            "tcp_keepintvl": int(s.get("tcp_keepintvl", 10)),
            "tcp_keepcnt": int(s.get("tcp_keepcnt", 5)),
            "thread_pool_max": int(s.get("thread_pool_max", 100)),
            "use_thread_pool": str(s.get("use_thread_pool", "true")).lower() != "false",
        }

    @staticmethod
    def _to_bool(val: object) -> bool:
        if isinstance(val, bool):
            return val
        if val is None:
            return False
        s = str(val).strip().lower()
        return s in ("1", "true", "yes", "on")

    def get_proxy_protocol_config(self) -> dict:
        """Return proxy_protocol config: enabled, validate_sources, reject_invalid"""
        defaults = {
            "enabled": False,
            "validate_sources": True,
            "reject_invalid": True,
        }
        try:
            if not self.config.has_section("proxy_protocol"):
                return defaults
            sec = dict(self.config.items("proxy_protocol"))
            return {
                "enabled": self._to_bool(sec.get("enabled", False)),
                "validate_sources": self._to_bool(sec.get("validate_sources", True)),
                "reject_invalid": self._to_bool(sec.get("reject_invalid", True)),
            }
        except Exception:
            return defaults

    def get_monitoring_config(self) -> dict[str, Any]:
        """Get monitoring configuration if present."""
        if "monitoring" not in self.config:
            return {}
        m = self.config["monitoring"]
        try:
            enabled = str(m.get("enabled", "false")).lower() == "true"
        except Exception:
            enabled = False
        return {
            "enabled": enabled,
            "web_host": m.get("web_host", "127.0.0.1"),
            "web_port": int(m.get("web_port", 8080)),
        }

    def get_auth_backends(self) -> list[str]:
        """Get list of enabled authentication backends"""
        backends_str = self.config.get("auth", "backends", fallback="local")
        backend_list = backends_str.split(",")
        return [backend.strip() for backend in backend_list if backend.strip()]

    def get_local_auth_db(self) -> str:
        if self.config.has_option("auth", "local_auth_db"):
            val = self.config.get("auth", "local_auth_db")
            # Support ${ENV_VAR} interpolation in file paths
            return os.path.expandvars(val)
        return "data/local_auth.db"

    def create_auth_backends(self) -> list:
        """Create authentication backend instances"""
        backends = []
        backend_names = self.get_auth_backends()

        for backend_name in backend_names:
            backend = self._create_single_backend(backend_name)
            if backend:
                backends.append(backend)

        if not backends:
            fallback_backend = self._create_fallback_backend()
            if fallback_backend:
                backends.append(fallback_backend)

        return backends

    def _create_single_backend(self, backend_name: str):
        """Create a single authentication backend instance"""
        try:
            normalized_name = _normalize_backend_name(backend_name)
            backend_type = normalized_name.lower()

            if backend_type == "local":
                # Pass cache TTL from config
                tuning = self.get_auth_runtime_config()
                ttl = int(tuning.get("local_auth_cache_ttl_seconds", 60))
                return LocalAuthBackend(self.get_local_auth_db(), cache_ttl_seconds=ttl)
            elif backend_type == "ldap":
                return self._create_ldap_backend()
            elif backend_type == "okta":
                return self._create_okta_backend()
            else:
                logger.warning("Unknown auth backend '%s' configured", backend_name)
                return None
        except (KeyError, ValueError) as e:
            logger.error(
                "Configuration error for auth backend '%s': %s", backend_name, e
            )
            return None
        except Exception as e:
            logger.exception(
                "Failed to initialize auth backend '%s': %s", backend_name, e
            )
            return None

    def _create_ldap_backend(self):
        """Create LDAP backend if configuration exists"""
        if "ldap" not in self.config:
            logger.error("LDAP backend configured but no [ldap] section found")
            return None
        return LDAPAuthBackend(dict(self.config["ldap"]))

    def _create_okta_backend(self):
        """Create Okta backend if configuration exists"""
        try:
            from tacacs_server.auth.okta_auth import OktaAuthBackend
        except Exception:
            logger.error("Okta backend requested but module not available")
            return None
        if "okta" not in self.config:
            logger.error("Okta backend configured but no [okta] section found")
            return None
        try:
            return OktaAuthBackend(dict(self.config["okta"]))
        except Exception as exc:
            logger.error("Failed to initialize Okta backend: %s", exc)
            return None

    def _create_fallback_backend(self):
        """Create fallback local authentication backend"""
        try:
            return LocalAuthBackend(self.get_local_auth_db())
        except Exception:
            logger.exception("Failed to initialize fallback local auth backend")
            return None

    def get_database_config(self) -> dict[str, Any]:
        """Get database configuration"""
        return {
            "accounting_db": self.config.get("database", "accounting_db"),
            "cleanup_days": self.config.getint("database", "cleanup_days"),
            "auto_cleanup": self.config.getboolean("database", "auto_cleanup"),
            "metrics_history_db": self.config.get("database", "metrics_history_db"),
            "audit_trail_db": self.config.get("database", "audit_trail_db"),
            "metrics_retention_days": self.config.getint(
                "database", "metrics_retention_days"
            ),
            "audit_retention_days": self.config.getint(
                "database", "audit_retention_days"
            ),
            "db_pool_size": int(
                self.config.get("database", "db_pool_size", fallback="5")
            ),
        }

    def get_auth_runtime_config(self) -> dict[str, Any]:
        """Get runtime tuning for auth backends (non-secret)."""
        a = self.config["auth"]

        def _int(name: str, default: int) -> int:
            try:
                return int(a.get(name, default))
            except Exception:
                return default

        def _float(name: str, default: float) -> float:
            try:
                return float(a.get(name, default))
            except Exception:
                return default

        return {
            "local_auth_cache_ttl_seconds": _int("local_auth_cache_ttl_seconds", 60),
            "backend_timeout": _float("backend_timeout", 2.0),
        }

    def get_device_store_config(self) -> dict[str, Any]:
        """Get device inventory configuration"""
        return {
            "database": self.config.get(
                "devices", "database", fallback="data/devices.db"
            ),
            "default_group": self.config.get(
                "devices", "default_group", fallback="default"
            ),
            "auto_register": (
                self.config.getboolean("devices", "auto_register", fallback=True)
                if "devices" in self.config
                else True
            ),
            "identity_cache_ttl_seconds": int(
                self.config.get("devices", "identity_cache_ttl_seconds", fallback="60")
            ),
            "identity_cache_size": int(
                self.config.get("devices", "identity_cache_size", fallback="10000")
            ),
        }

    def get_admin_auth_config(self) -> dict[str, Any]:
        """Get admin authentication configuration"""
        section = self.config["admin"] if "admin" in self.config else {}
        return {
            "username": section.get("username", "admin"),
            "password_hash": section.get("password_hash", ""),
            "session_timeout_minutes": int(section.get("session_timeout_minutes", 60)),
        }

    def get_backup_config(self) -> dict[str, Any]:
        """Get backup configuration"""
        try:
            enabled = self.config.getboolean("backup", "enabled", fallback=True)
        except Exception:
            enabled = True
        try:
            create_on_startup = self.config.getboolean(
                "backup", "create_on_startup", fallback=False
            )
        except Exception:
            create_on_startup = False
        temp_directory = self.config.get(
            "backup", "temp_directory", fallback="data/backup_temp"
        )
        try:
            encryption_enabled = self.config.getboolean(
                "backup", "encryption_enabled", fallback=False
            )
        except Exception:
            encryption_enabled = False
        from os import getenv as _getenv

        enc_passphrase = _getenv("BACKUP_ENCRYPTION_PASSPHRASE") or self.config.get(
            "backup", "encryption_passphrase", fallback=""
        )
        try:
            retention_days = self.config.getint(
                "backup", "default_retention_days", fallback=30
            )
        except Exception:
            retention_days = 30
        return {
            "enabled": enabled,
            "create_on_startup": create_on_startup,
            "temp_directory": temp_directory,
            "encryption_enabled": encryption_enabled,
            "encryption_passphrase": enc_passphrase,
            "default_retention_days": retention_days,
        }

    def get_command_authorization_config(self) -> dict[str, Any]:
        section = (
            self.config["command_authorization"]
            if "command_authorization" in self.config
            else {}
        )
        default_action = (
            str(section.get("default_action", "deny")).strip().lower() or "deny"
        )
        rules_json = section.get("rules_json", "[]")
        try:
            import json as _json

            rules = _json.loads(rules_json) if rules_json else []
            if not isinstance(rules, list):
                rules = []
        except Exception:
            rules = []
        # Response mode controls whether successful authorization returns
        # PASS_ADD (append attributes) or PASS_REPL (replace all attributes).
        response_mode = str(section.get("response_mode", "pass_add")).strip().lower()
        if response_mode not in ("pass_add", "pass_repl"):
            response_mode = "pass_add"
        # Privilege enforcement order
        order = str(section.get("privilege_check_order", "before")).strip().lower()
        if order not in ("before", "after", "none"):
            order = "before"
        return {
            "default_action": default_action,
            "rules": rules,
            "response_mode": response_mode,
            "privilege_check_order": order,
        }

    def update_command_authorization_config(
        self,
        *,
        default_action: str | None = None,
        rules: list[dict] | None = None,
        privilege_check_order: str | None = None,
    ) -> None:
        if "command_authorization" not in self.config:
            self.config.add_section("command_authorization")
        section = self.config["command_authorization"]
        import json as _json

        if default_action is not None:
            section["default_action"] = str(default_action)
        if rules is not None:
            section["rules_json"] = _json.dumps(rules)
        if privilege_check_order is not None:
            pco = str(privilege_check_order).strip().lower()
            if pco in ("before", "after", "none"):
                section["privilege_check_order"] = pco
        try:
            self.save_config()
        except Exception as e:
            logger.warning("Failed to persist command authorization config: %s", e)

    def get_security_config(self) -> dict[str, Any]:
        """Get security configuration"""
        allowed_clients_str = self.config.get("security", "allowed_clients")
        denied_clients_str = self.config.get("security", "denied_clients")

        allowed_clients = self._parse_client_list(allowed_clients_str)
        denied_clients = self._parse_client_list(denied_clients_str)

        return {
            "max_auth_attempts": self.config.getint("security", "max_auth_attempts"),
            "auth_timeout": self.config.getint("security", "auth_timeout"),
            "encryption_required": self.config.getboolean(
                "security", "encryption_required"
            ),
            "allowed_clients": allowed_clients,
            "denied_clients": denied_clients,
            "rate_limit_requests": self.config.getint(
                "security", "rate_limit_requests"
            ),
            "rate_limit_window": self.config.getint("security", "rate_limit_window"),
            "max_connections_per_ip": self.config.getint(
                "security", "max_connections_per_ip", fallback=20
            ),
        }

    def _parse_client_list(self, clients_str: str) -> list[str]:
        """Parse comma-separated client IP list"""
        if not clients_str:
            return []
        client_list = clients_str.split(",")
        return [ip.strip() for ip in client_list if ip.strip()]

    def get_logging_config(self) -> dict[str, Any]:
        """Get logging configuration"""
        return {
            "log_file": self.config.get("logging", "log_file"),
            "log_format": self.config.get("logging", "log_format"),
            "log_rotation": self.config.getboolean("logging", "log_rotation"),
            "max_log_size": self.config.get("logging", "max_log_size"),
            "backup_count": self.config.getint("logging", "backup_count"),
            "log_level": self.config.get("server", "log_level"),
        }

    def get_syslog_config(self) -> dict[str, Any]:
        """Get syslog configuration (optional)."""
        sec = self.config["syslog"] if "syslog" in self.config else {}
        enabled = str(sec.get("enabled", "false")).lower() == "true"
        host = sec.get("host", "127.0.0.1")
        try:
            port = int(sec.get("port", 514))
        except Exception:
            port = 514
        proto = str(sec.get("protocol", "udp")).strip().lower()
        facility = str(sec.get("facility", "local0")).strip().lower()
        severity = str(sec.get("severity", "info")).strip().lower()
        fmt = str(sec.get("format", "rfc5424"))
        app_name = str(sec.get("app_name", "tacacs_server"))
        include_hostname = str(sec.get("include_hostname", "true")).lower() == "true"
        return {
            "enabled": enabled,
            "host": host,
            "port": port,
            "protocol": proto,
            "facility": facility,
            "severity": severity,
            "format": fmt,
            "app_name": app_name,
            "include_hostname": include_hostname,
        }

    def get_webhook_config(self) -> dict[str, Any]:
        """Get webhook configuration (parsed)."""
        section = self.config["webhooks"] if "webhooks" in self.config else {}
        urls_raw = section.get("urls", "")
        urls = [
            u.strip() for u in str(urls_raw).replace("\n", ",").split(",") if u.strip()
        ]
        headers_json = section.get("headers_json", "{}")
        template_json = section.get("template_json", "{}")
        import json as _json

        try:
            headers = _json.loads(headers_json) if headers_json else {}
        except Exception:
            headers = {}
        try:
            template = _json.loads(template_json) if template_json else {}
        except Exception:
            template = {}
        timeout = float(section.get("timeout", "3") or 3)
        threshold_count = int(section.get("threshold_count", "0") or 0)
        threshold_window = int(section.get("threshold_window", "60") or 60)
        return {
            "urls": urls,
            "headers": headers,
            "template": template,
            "timeout": timeout,
            "threshold_count": threshold_count,
            "threshold_window": threshold_window,
        }

    def update_webhook_config(self, **kwargs: Any) -> None:
        """Update webhook configuration and persist."""
        if "webhooks" not in self.config:
            self.config.add_section("webhooks")
        section = self.config["webhooks"]
        import json as _json

        urls = kwargs.get("urls")
        if isinstance(urls, list):
            section["urls"] = ",".join(urls)
        headers = kwargs.get("headers")
        if isinstance(headers, dict):
            section["headers_json"] = _json.dumps(headers)
        template = kwargs.get("template")
        if isinstance(template, dict):
            section["template_json"] = _json.dumps(template)
        if "timeout" in kwargs and kwargs.get("timeout") is not None:
            section["timeout"] = str(kwargs.get("timeout"))
        if "threshold_count" in kwargs and kwargs.get("threshold_count") is not None:
            tc = kwargs.get("threshold_count")
            if isinstance(tc, (int, float, str)):
                section["threshold_count"] = str(int(float(tc)))
        if "threshold_window" in kwargs and kwargs.get("threshold_window") is not None:
            tw = kwargs.get("threshold_window")
            if isinstance(tw, (int, float, str)):
                section["threshold_window"] = str(int(float(tw)))
        # Persist
        try:
            self.save_config()
        except Exception as e:
            logger.warning("Failed to persist webhook config: %s", e)

    def update_proxy_protocol_config(self, **kwargs):
        """Update proxy_protocol configuration with validation and history tracking"""
        reason = kwargs.pop("_change_reason", None)
        source_ip = kwargs.pop("_source_ip", None)
        old_values: dict[str, str] = {
            k: self.config.get("proxy_protocol", k, fallback="") for k in kwargs.keys()
        }
        temp_config = self._create_temp_config_with_updates("proxy_protocol", kwargs)
        self._validate_temp_config(temp_config)
        self._apply_config_updates("proxy_protocol", kwargs)
        store = getattr(self, "config_store", None)
        if store is not None:
            user = self._get_current_user()
            for key, new_value in kwargs.items():
                vtype = self._infer_type(new_value)
                try:
                    setter = getattr(store, "set_override", None)
                    if callable(setter):
                        setter(
                            section="proxy_protocol",
                            key=key,
                            value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                        )
                except Exception:
                    pass
                try:
                    rec = getattr(store, "record_change", None)
                    if callable(rec):
                        rec(
                            section="proxy_protocol",
                            key=key,
                            old_value=old_values.get(key),
                            new_value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                            source_ip=source_ip,
                        )
                except Exception:
                    pass
            try:
                creator = getattr(store, "create_version", None)
                if callable(creator):
                    creator(
                        config_dict=self._export_full_config(),
                        created_by=user,
                        description=f"Updated proxy_protocol config: {', '.join(kwargs.keys())}",
                    )
            except Exception:
                pass
        self._apply_overrides()
        if not self.is_url_config():
            self.save_config()

    def update_monitoring_config(self, **kwargs):
        """Update monitoring configuration with validation and history tracking"""
        reason = kwargs.pop("_change_reason", None)
        source_ip = kwargs.pop("_source_ip", None)
        old_values: dict[str, str] = {
            k: self.config.get("monitoring", k, fallback="") for k in kwargs.keys()
        }
        temp_config = self._create_temp_config_with_updates("monitoring", kwargs)
        self._validate_temp_config(temp_config)
        self._apply_config_updates("monitoring", kwargs)
        store = getattr(self, "config_store", None)
        if store is not None:
            user = self._get_current_user()
            for key, new_value in kwargs.items():
                vtype = self._infer_type(new_value)
                try:
                    setter = getattr(store, "set_override", None)
                    if callable(setter):
                        setter(
                            section="monitoring",
                            key=key,
                            value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                        )
                except Exception:
                    pass
                try:
                    rec = getattr(store, "record_change", None)
                    if callable(rec):
                        rec(
                            section="monitoring",
                            key=key,
                            old_value=old_values.get(key),
                            new_value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                            source_ip=source_ip,
                        )
                except Exception:
                    pass
            try:
                creator = getattr(store, "create_version", None)
                if callable(creator):
                    creator(
                        config_dict=self._export_full_config(),
                        created_by=user,
                        description=f"Updated monitoring config: {', '.join(kwargs.keys())}",
                    )
            except Exception:
                pass
        self._apply_overrides()
        if not self.is_url_config():
            self.save_config()

    def update_radius_config(self, **kwargs):
        """Update radius configuration with validation and history tracking"""
        reason = kwargs.pop("_change_reason", None)
        source_ip = kwargs.pop("_source_ip", None)
        old_values: dict[str, str] = {
            k: self.config.get("radius", k, fallback="") for k in kwargs.keys()
        }
        temp_config = self._create_temp_config_with_updates("radius", kwargs)
        self._validate_temp_config(temp_config)
        self._apply_config_updates("radius", kwargs)
        store = getattr(self, "config_store", None)
        if store is not None:
            user = self._get_current_user()
            for key, new_value in kwargs.items():
                vtype = self._infer_type(new_value)
                try:
                    setter = getattr(store, "set_override", None)
                    if callable(setter):
                        setter(
                            section="radius",
                            key=key,
                            value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                        )
                except Exception:
                    pass
                try:
                    rec = getattr(store, "record_change", None)
                    if callable(rec):
                        rec(
                            section="radius",
                            key=key,
                            old_value=old_values.get(key),
                            new_value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                            source_ip=source_ip,
                        )
                except Exception:
                    pass
            try:
                creator = getattr(store, "create_version", None)
                if callable(creator):
                    creator(
                        config_dict=self._export_full_config(),
                        created_by=user,
                        description=f"Updated radius config: {', '.join(kwargs.keys())}",
                    )
            except Exception:
                pass
        self._apply_overrides()
        if not self.is_url_config():
            self.save_config()

    def update_okta_config(self, **kwargs):
        """Update okta configuration with validation and history tracking"""
        reason = kwargs.pop("_change_reason", None)
        source_ip = kwargs.pop("_source_ip", None)
        old_values: dict[str, str] = {
            k: self.config.get("okta", k, fallback="") for k in kwargs.keys()
        }
        temp_config = self._create_temp_config_with_updates("okta", kwargs)
        self._validate_temp_config(temp_config)
        self._apply_config_updates("okta", kwargs)
        store = getattr(self, "config_store", None)
        if store is not None:
            user = self._get_current_user()
            for key, new_value in kwargs.items():
                vtype = self._infer_type(new_value)
                try:
                    setter = getattr(store, "set_override", None)
                    if callable(setter):
                        setter(
                            section="okta",
                            key=key,
                            value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                        )
                except Exception:
                    pass
                try:
                    rec = getattr(store, "record_change", None)
                    if callable(rec):
                        rec(
                            section="okta",
                            key=key,
                            old_value=old_values.get(key),
                            new_value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                            source_ip=source_ip,
                        )
                except Exception:
                    pass
            try:
                creator = getattr(store, "create_version", None)
                if callable(creator):
                    creator(
                        config_dict=self._export_full_config(),
                        created_by=user,
                        description=f"Updated okta config: {', '.join(kwargs.keys())}",
                    )
            except Exception:
                pass
        self._apply_overrides()
        if not self.is_url_config():
            self.save_config()

    def update_backup_config(self, **kwargs):
        """Update backup configuration with validation and history tracking"""
        reason = kwargs.pop("_change_reason", None)
        source_ip = kwargs.pop("_source_ip", None)
        old_values: dict[str, str] = {
            k: self.config.get("backup", k, fallback="") for k in kwargs.keys()
        }
        temp_config = self._create_temp_config_with_updates("backup", kwargs)
        self._validate_temp_config(temp_config)
        self._apply_config_updates("backup", kwargs)
        store = getattr(self, "config_store", None)
        if store is not None:
            user = self._get_current_user()
            for key, new_value in kwargs.items():
                vtype = self._infer_type(new_value)
                try:
                    setter = getattr(store, "set_override", None)
                    if callable(setter):
                        setter(
                            section="backup",
                            key=key,
                            value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                        )
                except Exception:
                    pass
                try:
                    rec = getattr(store, "record_change", None)
                    if callable(rec):
                        rec(
                            section="backup",
                            key=key,
                            old_value=old_values.get(key),
                            new_value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                            source_ip=source_ip,
                        )
                except Exception:
                    pass
            try:
                creator = getattr(store, "create_version", None)
                if callable(creator):
                    creator(
                        config_dict=self._export_full_config(),
                        created_by=user,
                        description=f"Updated backup config: {', '.join(kwargs.keys())}",
                    )
            except Exception:
                pass
        self._apply_overrides()
        if not self.is_url_config():
            self.save_config()

    def update_server_config(self, **kwargs):
        """Update server configuration with validation and history tracking"""
        # Extract context hints (not real keys)
        reason = kwargs.pop("_change_reason", None)
        source_ip = kwargs.pop("_source_ip", None)
        # Capture previous values for history
        old_values: dict[str, str] = {
            k: self.config.get("server", k, fallback="") for k in kwargs.keys()
        }
        temp_config = self._create_temp_config_with_updates("server", kwargs)
        self._validate_temp_config(temp_config)
        self._apply_config_updates("server", kwargs)
        # Apply overrides + history + version if store is available
        store = getattr(self, "config_store", None)
        if store is not None:
            user = self._get_current_user()
            for key, new_value in kwargs.items():
                vtype = self._infer_type(new_value)
                try:
                    setter = getattr(store, "set_override", None)
                    if callable(setter):
                        setter(
                            section="server",
                            key=key,
                            value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                        )
                except Exception:
                    pass
                try:
                    rec = getattr(store, "record_change", None)
                    if callable(rec):
                        rec(
                            section="server",
                            key=key,
                            old_value=old_values.get(key),
                            new_value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                            source_ip=source_ip,
                        )
                except Exception:
                    pass
            try:
                creator = getattr(store, "create_version", None)
                if callable(creator):
                    creator(
                        config_dict=self._export_full_config(),
                        created_by=user,
                        description=f"Updated server config: {', '.join(kwargs.keys())}",
                    )
            except Exception:
                pass
        # Apply in-memory overrides for live process
        self._apply_overrides()
        # Persist file-backed configuration
        if not self.is_url_config():
            self.save_config()

    def update_auth_config(self, **kwargs):
        """Update authentication configuration with validation and history tracking"""
        reason = kwargs.pop("_change_reason", None)
        source_ip = kwargs.pop("_source_ip", None)
        old_values: dict[str, str] = {
            k: self.config.get("auth", k, fallback="") for k in kwargs.keys()
        }
        temp_config = self._create_temp_config_with_updates("auth", kwargs)
        self._validate_temp_config(temp_config)
        self._apply_config_updates("auth", kwargs)
        store = getattr(self, "config_store", None)
        if store is not None:
            user = self._get_current_user()
            for key, new_value in kwargs.items():
                vtype = self._infer_type(new_value)
                try:
                    setter = getattr(store, "set_override", None)
                    if callable(setter):
                        setter(
                            section="auth",
                            key=key,
                            value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                        )
                except Exception:
                    pass
                try:
                    rec = getattr(store, "record_change", None)
                    if callable(rec):
                        rec(
                            section="auth",
                            key=key,
                            old_value=old_values.get(key),
                            new_value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                            source_ip=source_ip,
                        )
                except Exception:
                    pass
            try:
                creator = getattr(store, "create_version", None)
                if callable(creator):
                    creator(
                        config_dict=self._export_full_config(),
                        created_by=user,
                        description=f"Updated auth config: {', '.join(kwargs.keys())}",
                    )
            except Exception:
                pass
        self._apply_overrides()
        if not self.is_url_config():
            self.save_config()

    def update_ldap_config(self, **kwargs):
        """Update LDAP configuration with validation and history tracking"""
        reason = kwargs.pop("_change_reason", None)
        source_ip = kwargs.pop("_source_ip", None)
        old_values: dict[str, str] = {
            k: self.config.get("ldap", k, fallback="") for k in kwargs.keys()
        }
        temp_config = self._create_temp_config_with_updates("ldap", kwargs)
        self._validate_temp_config(temp_config)
        self._apply_config_updates("ldap", kwargs)
        store = getattr(self, "config_store", None)
        if store is not None:
            user = self._get_current_user()
            for key, new_value in kwargs.items():
                vtype = self._infer_type(new_value)
                try:
                    setter = getattr(store, "set_override", None)
                    if callable(setter):
                        setter(
                            section="ldap",
                            key=key,
                            value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                        )
                except Exception:
                    pass
                try:
                    rec = getattr(store, "record_change", None)
                    if callable(rec):
                        rec(
                            section="ldap",
                            key=key,
                            old_value=old_values.get(key),
                            new_value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                            source_ip=source_ip,
                        )
                except Exception:
                    pass
            try:
                creator = getattr(store, "create_version", None)
                if callable(creator):
                    creator(
                        config_dict=self._export_full_config(),
                        created_by=user,
                        description=f"Updated ldap config: {', '.join(kwargs.keys())}",
                    )
            except Exception:
                pass
        self._apply_overrides()
        if not self.is_url_config():
            self.save_config()

    def update_devices_config(self, **kwargs):
        """Update devices configuration (auto_register/default_group/cache) with history."""
        reason = kwargs.pop("_change_reason", None)
        source_ip = kwargs.pop("_source_ip", None)
        # Basic key filtering
        allowed = {
            "auto_register",
            "default_group",
            "identity_cache_ttl_seconds",
            "identity_cache_size",
        }
        for k in list(kwargs.keys()):
            if k not in allowed:
                kwargs.pop(k)
        # Validate via temporary config
        temp_config = self._create_temp_config_with_updates("devices", kwargs)
        self._validate_temp_config(temp_config)
        # Apply
        old_values: dict[str, str] = {
            k: self.config.get("devices", k, fallback="") for k in kwargs.keys()
        }
        self._apply_config_updates("devices", kwargs)
        # Persist overrides and audit trail
        store = getattr(self, "config_store", None)
        if store is not None:
            user = self._get_current_user()
            for key, new_value in kwargs.items():
                vtype = self._infer_type(new_value)
                try:
                    setter = getattr(store, "set_override", None)
                    if callable(setter):
                        setter(
                            section="devices",
                            key=key,
                            value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                        )
                except Exception:
                    pass
                try:
                    rec = getattr(store, "record_change", None)
                    if callable(rec):
                        rec(
                            section="devices",
                            key=key,
                            old_value=old_values.get(key),
                            new_value=new_value,
                            value_type=vtype,
                            changed_by=user,
                            reason=reason,
                            source_ip=source_ip,
                        )
                except Exception:
                    pass
            try:
                creator = getattr(store, "create_version", None)
                if callable(creator):
                    creator(
                        config_dict=self._export_full_config(),
                        created_by=user,
                        description=f"Updated devices config: {', '.join(kwargs.keys())}",
                    )
            except Exception:
                pass
        self._apply_overrides()
        if not self.is_url_config():
            self.save_config()

    def _create_temp_config_with_updates(
        self, section: str, updates: dict
    ) -> configparser.ConfigParser:
        """Create temporary config with updates for validation"""
        temp_config = configparser.ConfigParser(interpolation=None)
        temp_config.read_dict(dict(self.config))

        for key, value in updates.items():
            temp_config[section][key] = str(value)

        return temp_config

    def _validate_temp_config(self, temp_config: configparser.ConfigParser):
        """Validate temporary configuration"""
        temp_tacacs_config = TacacsConfig.__new__(TacacsConfig)
        temp_tacacs_config.config = temp_config
        temp_tacacs_config.config_file = self.config_file
        temp_tacacs_config.config_source = self.config_source

        issues = temp_tacacs_config.validate_config()
        if issues:
            raise ValueError(f"Configuration validation failed: {'; '.join(issues)}")

    def _apply_config_updates(self, section: str, updates: dict):
        """Apply configuration updates and save"""
        for key, value in updates.items():
            self.config[section][key] = str(value)
        self.save_config()

    def validate_config(self) -> list[str]:
        """Validate configuration and return list of issues."""
        issues = []

        try:
            config_dict: dict[str, dict[str, Any]] = {
                "server": dict(self.config["server"]),
                "auth": dict(self.config["auth"]),
                "security": dict(self.config["security"]),
            }

            if "ldap" in self.config:
                config_dict["ldap"] = dict(self.config["ldap"])
            if "okta" in self.config:
                config_dict["okta"] = dict(self.config["okta"])

            validated: TacacsConfigSchema = validate_config_file(config_dict)
            logger.info("✓ Configuration validation passed")

            # Directory existence checks
            auth_db_path = validated.auth.local_auth_db
            auth_db_dir = os.path.dirname(auth_db_path)
            if auth_db_dir and not os.path.exists(auth_db_dir):
                issues.append(
                    f"Local auth database directory does not exist: {auth_db_dir}"
                )

            db_file = self.config.get("database", "accounting_db")
            db_dir = os.path.dirname(db_file)
            if db_dir and not os.path.exists(db_dir):
                issues.append(f"Database directory does not exist: {db_dir}")

            # Additional validation checks
            issues.extend(self._validate_server_config())
            issues.extend(self._validate_auth_config())
            issues.extend(self._validate_security_config())

        except ValueError as exc:
            logger.error("✗ Configuration validation failed: %s", exc)
            issues.append(str(exc))

        return issues

    def _validate_server_config(self) -> list[str]:
        """Validate server configuration section"""
        issues = []

        # Port validation
        port = self.config.getint("server", "port")
        if port < 1 or port > 65535:
            issues.append(f"Invalid server port: {port} (must be 1-65535)")

        # Note: TACACS+ secrets are now per-device group, not global

        # Connection limits
        max_conn = self.config.getint("server", "max_connections")
        if max_conn < 1 or max_conn > 1000:
            issues.append(f"Invalid max_connections: {max_conn} (must be 1-1000)")

        return issues

    def _validate_auth_config(self) -> list[str]:
        """Validate authentication configuration section"""
        issues = []

        # Backend validation
        backends = self.get_auth_backends()
        if not backends:
            issues.append("No authentication backends configured")

        for backend in backends:
            backend_name = _normalize_backend_name(backend)
            if backend_name.lower() not in ["local", "ldap", "okta"]:
                issues.append(f"Unknown authentication backend: {backend_name}")

        # Database file validation
        auth_db = self.get_local_auth_db()
        if not auth_db:
            issues.append("Local auth database path not configured")

        return issues

    def _validate_security_config(self) -> list[str]:
        """Validate security configuration section"""
        issues = []

        # Auth attempts validation
        max_attempts = self.config.getint("security", "max_auth_attempts")
        if max_attempts < 1 or max_attempts > 10:
            issues.append(f"Invalid max_auth_attempts: {max_attempts} (must be 1-10)")

        # Timeout validation
        timeout = self.config.getint("security", "auth_timeout")
        if timeout < 30 or timeout > 3600:
            issues.append(f"Invalid auth_timeout: {timeout} (must be 30-3600 seconds)")

        # Per-IP connection cap validation
        try:
            cap = self.config.getint("security", "max_connections_per_ip")
        except Exception:
            cap = 20
        if cap < 1 or cap > 1000:
            issues.append(f"Invalid max_connections_per_ip: {cap} (must be 1-1000)")

        return issues

    def validate_and_backup_config(self) -> tuple[bool, list[str]]:
        """Validate configuration and create backup if valid"""
        issues = self.validate_config()

        if not issues:
            # Create backup before any changes
            try:
                if self.config_file and os.path.exists(self.config_file):
                    backup_file = f"{self.config_file}.backup"
                    import shutil

                    shutil.copy2(self.config_file, backup_file)
                    logger.info(f"Configuration backup created: {backup_file}")
            except Exception as e:
                issues.append(f"Failed to create config backup: {e}")
                return False, issues

        return len(issues) == 0, issues

    def get_config_summary(self) -> dict[str, Any]:
        """Get configuration summary for display with validation status"""
        summary = {
            "server": dict(self.config["server"]),
            "auth": dict(self.config["auth"]),
            "ldap": dict(self.config["ldap"]),
            "database": dict(self.config["database"]),
            "security": dict(self.config["security"]),
            "logging": dict(self.config["logging"]),
        }
        if "admin" in self.config:
            summary["admin"] = dict(self.config["admin"])
        if "devices" in self.config:
            summary["devices"] = dict(self.config["devices"])
        if "radius" in self.config:
            summary["radius"] = dict(self.config["radius"])
        if "proxy_protocol" in self.config:
            summary["proxy_protocol"] = dict(self.config["proxy_protocol"])
        if "monitoring" in self.config:
            summary["monitoring"] = dict(self.config["monitoring"])
        if "okta" in self.config:
            summary["okta"] = dict(self.config["okta"])
        if "backup" in self.config:
            summary["backup"] = dict(self.config["backup"])

        # Add validation status
        validation_issues = self.validate_config()
        summary["_validation"] = {
            "valid": str(len(validation_issues) == 0),
            "issues": str(validation_issues),
            "last_checked": str(time.time()),
        }

        return summary

    def get_radius_config(self) -> dict[str, Any]:
        """Get RADIUS server configuration"""
        enabled_env = os.environ.get("RADIUS_ENABLED")
        host = os.environ.get("RADIUS_HOST", self.config.get("radius", "host"))
        auth_port_env = os.environ.get("RADIUS_AUTH_PORT")
        acct_port_env = os.environ.get("RADIUS_ACCT_PORT")
        try:
            enabled = (
                bool(int(enabled_env))
                if enabled_env is not None and enabled_env.strip() != ""
                else self.config.getboolean("radius", "enabled")
            )
        except Exception:
            enabled = self.config.getboolean("radius", "enabled")
        try:
            auth_port = (
                int(auth_port_env)
                if auth_port_env and auth_port_env.isdigit()
                else self.config.getint("radius", "auth_port")
            )
        except Exception:
            auth_port = self.config.getint("radius", "auth_port")
        try:
            acct_port = (
                int(acct_port_env)
                if acct_port_env and acct_port_env.isdigit()
                else self.config.getint("radius", "acct_port")
            )
        except Exception:
            acct_port = self.config.getint("radius", "acct_port")
        return {
            "enabled": enabled,
            "auth_port": auth_port,
            "acct_port": acct_port,
            "host": host,
            "share_backends": self.config.getboolean("radius", "share_backends"),
            "share_accounting": self.config.getboolean("radius", "share_accounting"),
            "workers": int(self.config.get("radius", "workers", fallback="8")),
            "socket_timeout": float(
                self.config.get("radius", "socket_timeout", fallback="1.0")
            ),
            "rcvbuf": int(self.config.get("radius", "rcvbuf", fallback="1048576")),
        }

    @staticmethod
    def _is_url(source: str) -> bool:
        parsed = urlparse(source)
        return parsed.scheme in {"http", "https", "file"}

    def _load_from_url(self, source: str) -> None:
        """Load configuration from URL with security validation"""
        if not self._is_url_safe(source):
            return

        try:
            payload = self._fetch_url_content(source)
            if payload:
                # Load into config and cache baseline to disk
                self.config.read_string(payload)
                try:
                    with open(self._baseline_cache_path, "w", encoding="utf-8") as fh:
                        fh.write(payload)
                except Exception:
                    pass
                # Update metadata
                try:
                    if self.config_store:
                        self.config_store.set_metadata(
                            "last_url_fetch", datetime.now(UTC).isoformat()
                        )
                        self.config_store.set_metadata("config_source", source)
                        # Create a baseline version snapshot
                        try:
                            snap = json.loads(self._serialize_config_to_json())
                            self.config_store.create_version(
                                snap,
                                created_by="system",
                                description="URL baseline",
                                is_baseline=True,
                            )
                        except Exception:
                            pass
                except Exception:
                    pass
            else:
                # Fall back to cached baseline if available
                self._load_from_cache()
        except Exception as exc:
            logger.exception("Failed to load configuration from %s: %s", source, exc)
            # Fall back to cached baseline if available
            self._load_from_cache()

    def _load_from_cache(self) -> None:
        try:
            if os.path.exists(self._baseline_cache_path):
                with open(self._baseline_cache_path, encoding="utf-8") as fh:
                    cached = fh.read()
                self.config.read_string(cached)
                logger.warning(
                    "Using cached baseline configuration: %s", self._baseline_cache_path
                )
            else:
                logger.warning(
                    "No cached baseline config found at %s", self._baseline_cache_path
                )
        except Exception:
            logger.exception("Failed to load cached baseline configuration")

    def _serialize_config_to_json(self) -> str:
        # Convert configparser content to a JSON-serializable nested dict
        data: dict[str, dict[str, str]] = {}
        for section in self.config.sections():
            data[section] = {k: v for k, v in self.config.items(section)}
        return json.dumps(data, sort_keys=True)

    def _snapshot_baseline(self) -> None:
        """Store a copy of the current (pre-override) configuration for UI comparisons."""
        snap: dict[str, dict[str, str]] = {}
        for section in self.config.sections():
            snap[section] = {k: v for k, v in self.config.items(section)}
        self._baseline_snapshot = snap

    def _apply_overrides(self) -> None:
        """Apply database overrides on top of base configuration."""
        self.overridden_keys = {}
        store = getattr(self, "config_store", None)
        if not store:
            return
        try:
            ov = store.get_all_overrides()
        except Exception:
            return
        for section, kv in ov.items():
            if not self.config.has_section(section):
                try:
                    self.config.add_section(section)
                except Exception:
                    continue
            for key, (val, vtype) in kv.items():
                # Convert decoded value to a string for configparser
                if isinstance(val, (dict, list)):
                    sval = json.dumps(val)
                elif isinstance(val, bool):
                    sval = "true" if val else "false"
                else:
                    sval = str(val)
                try:
                    self.config.set(section, key, sval)
                    self.overridden_keys.setdefault(section, set()).add(key)
                except Exception:
                    continue

    def is_url_config(self) -> bool:
        return self._is_url(self.config_source)

    def get_baseline_config(self) -> dict[str, Any]:
        """Return base config without overrides (for UI comparison)."""
        # Deep copy snapshot as dict[str, Any]
        data = json.loads(json.dumps(self._baseline_snapshot))
        return dict(data)

    # --- helpers for history/version tracking ---
    def _get_current_user(self) -> str:
        """Return current admin user for audit purposes.

        In this implementation, returns "system". Hook into your auth/session
        context as needed to populate the real user.
        """
        return os.getenv("CURRENT_ADMIN_USER", "system")

    def _infer_type(self, value: Any) -> str:
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int) and not isinstance(value, bool):
            return "integer"
        if isinstance(value, list):
            return "list"
        if isinstance(value, dict):
            return "json"
        return "string"

    def _export_full_config(self) -> dict:
        out: dict[str, dict[str, str]] = {}
        for section in self.config.sections():
            out[section] = {k: v for k, v in self.config.items(section)}
        return out

    # --- drift detection ---
    def _get_base_value(
        self, section: str, key: str, value_type: str | None = None
    ) -> Any:
        """Return the baseline (pre-override) value for section/key.

        Attempts to coerce string baseline to the expected type when provided.
        """
        try:
            sval = self._baseline_snapshot.get(section, {}).get(key)
            if sval is None:
                return None
            if not value_type:
                return sval
            vtype = value_type.lower()
            if vtype in ("boolean", "bool"):
                return str(sval).lower() in ("1", "true", "yes")
            if vtype in ("integer", "int"):
                try:
                    return int(sval)
                except Exception:
                    return sval
            if vtype in ("json", "list"):
                try:
                    return json.loads(sval)
                except Exception:
                    return sval
            # default string
            return sval
        except Exception:
            return None

    def detect_config_drift(self) -> dict[str, dict[str, tuple[Any, Any]]]:
        """
        Compare base config (pre-overrides) with active overrides.

        Returns: {section: {key: (base_value, override_value)}}
        """
        drift: dict[str, dict[str, tuple[Any, Any]]] = {}
        store = getattr(self, "config_store", None)
        if not store:
            return drift
        try:
            overrides = store.get_all_overrides()
        except Exception:
            return drift
        for section, keys in overrides.items():
            for key, (override_value, value_type) in keys.items():
                base_value = self._get_base_value(section, key, value_type)
                if base_value != override_value:
                    drift.setdefault(section, {})[key] = (base_value, override_value)
        return drift

    # --- pre-apply validation ---
    def _is_port_available(self, port: int, host: str = "127.0.0.1") -> bool:
        import socket as _socket

        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
                try:
                    s.bind((host, int(port)))
                except OSError:
                    return False
            return True
        except Exception:
            return False

    def validate_change(
        self, section: str, key: str, value: Any
    ) -> tuple[bool, list[str]]:
        """
        Validate a single configuration change against the schema and custom rules.

        Returns: (is_valid, issues)
        """
        issues: list[str] = []
        # 1) Build a temporary payload with proposed change layered on current config
        payload = self._export_full_config()
        sec = payload.setdefault(section, {})
        # stringify the value for config parser semantics
        sec[key] = str(value)

        # 2) Schema validation
        try:
            validate_config_file(
                {
                    "server": payload.get("server", {}),
                    "auth": payload.get("auth", {}),
                    "security": payload.get("security", {}),
                    **({"ldap": payload.get("ldap", {})} if "ldap" in payload else {}),
                    **({"okta": payload.get("okta", {})} if "okta" in payload else {}),
                    **(
                        {"backup": payload.get("backup", {})}
                        if "backup" in payload
                        else {}
                    ),
                    **(
                        {"source_url": payload.get("source_url", {})}
                        if isinstance(payload.get("source_url"), dict)
                        else {}
                    ),
                }
            )
        except (
            Exception
        ) as e:  # pydantic raises ValidationError (subclass of ValueError)
            issues.append(str(e))
            return False, issues

        # 3) Custom validation
        if section == "server" and key == "port":
            try:
                port_int = int(value)
                if not (1 <= port_int <= 65535):
                    issues.append("Port out of valid range (1-65535)")
                elif not self._is_port_available(port_int):
                    issues.append(f"Port {port_int} is already in use")
            except Exception:
                issues.append("Port must be an integer")

        if section == "auth" and key == "backends":
            try:
                backends = [
                    b.strip().lower() for b in str(value).split(",") if b.strip()
                ]
                valid = {"local", "ldap", "okta"}
                for b in backends:
                    if b not in valid:
                        issues.append(f"Unknown backend: {b}")
            except Exception:
                issues.append("Invalid backends format")

        # Devices custom validation
        if section == "devices":
            if key == "auto_register":
                sval = str(value).lower()
                if sval not in ("1", "0", "true", "false", "yes", "no", "on", "off"):
                    issues.append("auto_register must be boolean")
            elif key == "default_group":
                if not str(value).strip():
                    issues.append("default_group cannot be empty")
            elif key in ("identity_cache_ttl_seconds", "identity_cache_size"):
                try:
                    _ = int(value)
                except Exception:
                    issues.append(f"{key} must be an integer")

        return (len(issues) == 0), issues

    def refresh_url_config(self, force: bool = False) -> bool:
        """Refresh configuration from URL if the source is a URL.

        Returns True if a new configuration was fetched and applied.
        """
        try:
            if not self._is_url(self.config_source):
                return False
            # Check interval
            try:
                last_fetch = None
                if self.config_store:
                    ts = self.config_store.get_metadata("last_url_fetch")
                    if ts:
                        last_fetch = datetime.fromisoformat(ts)
            except Exception:
                last_fetch = None
            if not force and last_fetch is not None:
                if datetime.now(UTC) - last_fetch < timedelta(
                    seconds=self._refresh_interval_seconds
                ):
                    return False
            # Attempt fetch
            payload = self._fetch_url_content(self.config_source) or ""
            if not payload:
                logger.warning("URL refresh failed; using existing configuration")
                return False
            new_hash = compute_config_hash(payload)
            # Current config hash
            current_json = self._serialize_config_to_json()
            current_hash = compute_config_hash(current_json)
            if new_hash == current_hash:
                # Update last fetch metadata even if unchanged
                if self.config_store:
                    self.config_store.set_metadata(
                        "last_url_fetch", datetime.now(UTC).isoformat()
                    )
                return False
            # Apply and cache
            self.config.read_string(payload)
            try:
                with open(self._baseline_cache_path, "w", encoding="utf-8") as fh:
                    fh.write(payload)
            except Exception:
                pass
            # Persist new version snapshot
            try:
                if self.config_store:
                    snap = json.loads(self._serialize_config_to_json())
                    self.config_store.create_version(
                        snap,
                        created_by="system",
                        description="URL refresh",
                        is_baseline=True,
                    )
                    self.config_store.set_metadata(
                        "last_url_fetch", datetime.now(UTC).isoformat()
                    )
            except Exception:
                logger.debug("Failed to persist config version snapshot")
            logger.info("Configuration refreshed from URL (hash changed)")
            return True
        except Exception as e:
            logger.warning("URL configuration refresh failed: %s", e)
            return False

    def _is_url_safe(self, source: str) -> bool:
        """Validate URL safety to prevent SSRF attacks"""
        parsed = urlparse(source)

        if parsed.scheme not in {"https"}:
            logger.error("Only HTTPS URLs are allowed for configuration loading")
            return False

        hostname = parsed.hostname
        if hostname and self._is_private_network(hostname):
            logger.error("Local/private network URLs are not allowed")
            return False

        return True

    def _is_private_network(self, hostname: str) -> bool:
        """Check if hostname resolves to a private, loopback, or unspecified IP address."""
        import ipaddress
        import socket

        if not hostname:
            return True

        if hostname.lower() == "localhost":
            return True

        try:
            # Resolve hostname to IP address
            ip_str = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_unspecified
        except (socket.gaierror, ValueError):
            # If hostname can't be resolved, deny for safety
            return True

    def _fetch_url_content(self, source: str) -> str | None:
        """Fetch and validate URL content"""
        max_size = 1024 * 1024  # 1MB limit

        with urlopen(source, timeout=10) as response:
            if response.length and response.length > max_size:
                logger.error("Configuration file too large")
                return None
            content: str = response.read().decode("utf-8")
            return content


def _parse_size(size_str: str) -> int:
    """Parse human readable size strings like '10MB' -> bytes"""
    try:
        s = size_str.strip().upper()
        if s.endswith("KB"):
            return int(float(s[:-2]) * 1024)
        if s.endswith("MB"):
            return int(float(s[:-2]) * 1024 * 1024)
        if s.endswith("GB"):
            return int(float(s[:-2]) * 1024 * 1024 * 1024)
        return int(s)
    except Exception:
        return 10 * 1024 * 1024


def setup_logging(config: TacacsConfig):
    """Setup logging based on configuration"""
    log_config = config.get_logging_config()
    log_file = log_config["log_file"]
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and (not os.path.exists(log_dir)):
            os.makedirs(log_dir, exist_ok=True)
    log_level = getattr(logging, log_config["log_level"].upper(), logging.INFO)
    handlers: list[logging.Handler] = []

    add_console = True
    try:
        # Avoid duplicate logs when stdout/stderr is redirected (non-interactive)
        # In such cases, a console handler would write to the same destination as
        # the subprocess redirection, causing duplicate entries alongside the
        # configured file handler.
        import sys as _sys

        add_console = bool(getattr(_sys.stdout, "isatty", lambda: False)())
    except Exception:
        add_console = True

    if add_console:
        console_handler = logging.StreamHandler()
        handlers.append(console_handler)

    if log_file:
        try:
            if log_config.get("log_rotation", False):
                max_bytes = _parse_size(log_config.get("max_log_size", "10MB"))
                backup_count = int(log_config.get("backup_count", 5))
                file_handler: logging.Handler = RotatingFileHandler(
                    log_file, maxBytes=max_bytes, backupCount=backup_count
                )
            else:
                file_handler = logging.FileHandler(log_file)
            handlers.append(file_handler)
        except Exception:
            logger.exception("Failed to create file log handler for %s", log_file)

    configure_logging(level=log_level, handlers=handlers)

    if log_config.get("log_format") and log_config["log_format"].lower() not in {
        "",
        "json",
        "structured",
    }:
        logger.warning(
            "Ignoring configured log_format in favour of structured JSON output"
        )

    logger.info(
        "Logging configured: level=%s, file=%s",
        log_config["log_level"],
        log_file or "console-only",
    )

    # Configure optional syslog handler per configuration
    try:
        syslog_cfg = config.get_syslog_config()
        if syslog_cfg.get("enabled"):
            import socket as _socket
            from logging.handlers import SysLogHandler

            address = (syslog_cfg["host"], int(syslog_cfg["port"]))
            socktype = (
                _socket.SOCK_DGRAM
                if syslog_cfg.get("protocol") == "udp"
                else _socket.SOCK_STREAM
            )
            # Facility mapping
            try:
                facility_map = {
                    "kern": SysLogHandler.LOG_KERN,
                    "user": SysLogHandler.LOG_USER,
                    "mail": SysLogHandler.LOG_MAIL,
                    "daemon": SysLogHandler.LOG_DAEMON,
                    "auth": SysLogHandler.LOG_AUTH,
                    "syslog": SysLogHandler.LOG_SYSLOG,
                    "lpr": SysLogHandler.LOG_LPR,
                    "news": SysLogHandler.LOG_NEWS,
                    "uucp": SysLogHandler.LOG_UUCP,
                    "cron": SysLogHandler.LOG_CRON,
                    "authpriv": getattr(
                        SysLogHandler, "LOG_AUTHPRIV", SysLogHandler.LOG_AUTH
                    ),
                    "ftp": getattr(SysLogHandler, "LOG_FTP", SysLogHandler.LOG_USER),
                    "local0": SysLogHandler.LOG_LOCAL0,
                    "local1": SysLogHandler.LOG_LOCAL1,
                    "local2": SysLogHandler.LOG_LOCAL2,
                    "local3": SysLogHandler.LOG_LOCAL3,
                    "local4": SysLogHandler.LOG_LOCAL4,
                    "local5": SysLogHandler.LOG_LOCAL5,
                    "local6": SysLogHandler.LOG_LOCAL6,
                    "local7": SysLogHandler.LOG_LOCAL7,
                }
                facility = facility_map.get(
                    str(syslog_cfg.get("facility", "local0")).lower(),
                    SysLogHandler.LOG_LOCAL0,
                )
            except Exception:
                facility = SysLogHandler.LOG_LOCAL0

            sh = SysLogHandler(address=address, facility=facility, socktype=socktype)

            # Level mapping to approximate syslog severity threshold
            level_map = {
                "debug": logging.DEBUG,
                "info": logging.INFO,
                "notice": logging.INFO,
                "warning": logging.WARNING,
                "err": logging.ERROR,
                "error": logging.ERROR,
                "crit": logging.CRITICAL,
                "alert": logging.CRITICAL,
                "emerg": logging.CRITICAL,
            }
            sh.setLevel(
                level_map.get(
                    str(syslog_cfg.get("severity", "info")).lower(), logging.INFO
                )
            )

            # Simple formatter; SysLogHandler prepends PRI/header. Prefix app name.
            app = syslog_cfg.get("app_name") or "tacacs_server"
            sh.setFormatter(logging.Formatter(f"{app}: %(message)s"))

            # Attach to root to capture all server logs to syslog (as required)
            root = logging.getLogger()
            root.addHandler(sh)
            logger.info(
                "Syslog configured: %s:%s proto=%s facility=%s severity=%s",
                syslog_cfg.get("host"),
                syslog_cfg.get("port"),
                syslog_cfg.get("protocol"),
                syslog_cfg.get("facility"),
                syslog_cfg.get("severity"),
            )
    except Exception as e:
        logger.warning("Failed to configure syslog handler: %s", e)
