"""
Configuration Management for TACACS+ Server

This is the main configuration module that orchestrates all configuration
functionality by delegating to specialized modules.
"""

import configparser
import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler
from typing import Any, cast

from tacacs_server.auth.ldap_auth import LDAPAuthBackend
from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.utils.logger import configure as configure_logging
from tacacs_server.utils.logger import get_logger

from .config_store import ConfigStore
from .config_utils import normalize_backend_name, parse_size
from .constants import DEFAULTS
from .defaults import populate_defaults
from .getters import (
    get_admin_auth_config,
    get_auth_backends,
    get_auth_runtime_config,
    get_backup_config,
    get_command_authorization_config,
    get_config_summary,
    get_database_config,
    get_device_store_config,
    get_local_auth_db,
    get_logging_config,
    get_monitoring_config,
    get_proxy_protocol_config,
    get_radius_config,
    get_security_config,
    get_server_config,
    get_server_network_config,
    get_syslog_config,
    get_webhook_config,
)
from .loader import apply_all_env_overrides, is_url, load_config
from .updaters import (
    _export_full_config as export_full_config_impl,
)
from .updaters import (
    update_command_authorization_config,
    update_section,
    update_webhook_config,
)
from .url_handler import URLConfigHandler, refresh_url_config
from .validators import validate_change, validate_config

logger = get_logger(__name__)


class TacacsConfig:
    """TACACS+ server configuration manager.

    This class is a thin orchestration layer that delegates to specialized
    modules for loading, validation, updates, and URL handling.
    """

    def __init__(self, config_file: str = "config/tacacs.conf"):
        """Initialize configuration manager.

        Args:
            config_file: Path to configuration file or URL
        """
        # Determine config source (file or URL or environment)
        env_source = os.environ.get("TACACS_CONFIG")
        self.config_source = env_source or config_file
        self.config_file = None if is_url(self.config_source) else self.config_source

        # Initialize configuration
        self.config = configparser.ConfigParser(interpolation=None)

        # Initialize configuration override store
        try:
            os.makedirs("data", exist_ok=True)
            self.config_store: ConfigStore | None = ConfigStore(
                "data/config_overrides.db"
            )
            logger.debug(
                "Configuration store initialized successfully",
                event="tacacs.config.store.initialized",
                service="tacacs",
            )
        except Exception as e:
            logger.error(
                "Failed to initialize configuration store",
                event="tacacs.config.store.error",
                service="tacacs",
                error=str(e),
                exc_info=True,
            )
            self.config_store = None

        # Track baseline (pre-override) snapshot and which keys were overridden
        self._baseline_snapshot: dict[str, dict[str, str]] = {}
        self.overridden_keys: dict[str, set[str]] = {}

        # URL configuration handler
        refresh_interval = int(os.getenv("CONFIG_REFRESH_SECONDS", "300"))
        self.url_handler = URLConfigHandler(
            cache_path=os.path.join("data", "config_baseline_cache.conf"),
            refresh_interval=refresh_interval,
        )

        # Load configuration
        self._load_config()
        self._snapshot_baseline()
        self._apply_overrides()

    def _load_config(self):
        """Load configuration from file using unified loader."""
        # Create defaults
        defaults = configparser.ConfigParser(interpolation=None)
        populate_defaults(defaults)

        # Load with unified precedence, passing url_handler for URL sources
        url_handler = self.url_handler if is_url(self.config_source) else None
        self.config = load_config(self.config_source, defaults, url_handler)

        # Save to file if file-based and doesn't exist
        if not is_url(self.config_source):
            path = self.config_file or self.config_source
            if not os.path.exists(path):
                self.config_file = path
                try:
                    self.save_config()
                except Exception as e:
                    logger.error(
                        "Failed to save initial config",
                        event="tacacs.config.save.error",
                        service="tacacs",
                        error=str(e),
                    )

        logger.info(
            "Configuration loaded successfully",
            event="tacacs.config.loaded",
            service="tacacs",
            source=self.config_source,
        )

    def save_config(self):
        """Save configuration to file."""
        if is_url(self.config_source):
            raise RuntimeError("Cannot save configuration when source is a URL")

        if not self.config_file:
            raise ValueError("No configuration file path specified")

        try:
            cfg_dir = os.path.dirname(self.config_file)
            if cfg_dir and not os.path.exists(cfg_dir):
                os.makedirs(cfg_dir, exist_ok=True)
            with open(self.config_file, "w") as fh:
                self.config.write(fh)
        except OSError as e:
            logger.error("Failed to save configuration to %s: %s", self.config_file, e)
            raise RuntimeError(f"Configuration save failed: {e}") from e
        except Exception as e:
            logger.exception("Unexpected error saving configuration: %s", e)
            raise

    # Getter delegations
    def get_server_config(self) -> dict[str, Any]:
        """Get server configuration."""
        return get_server_config(self.config)

    def get_server_network_config(self) -> dict[str, Any]:
        """Get extended server/network tuning parameters."""
        return get_server_network_config(self.config)

    def get_proxy_protocol_config(self) -> dict:
        """Return proxy_protocol config."""
        return get_proxy_protocol_config(self.config)

    def get_monitoring_config(self) -> dict[str, Any]:
        """Get monitoring configuration if present."""
        return get_monitoring_config(self.config)

    def get_auth_backends(self) -> list[str]:
        """Get list of enabled authentication backends."""
        return get_auth_backends(self.config)

    def get_local_auth_db(self) -> str:
        """Get local auth database path."""
        return get_local_auth_db(self.config)

    def create_auth_backends(self) -> list:
        """Create authentication backend instances."""
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
        """Create a single authentication backend instance."""
        try:
            normalized_name = normalize_backend_name(backend_name)
            backend_type = normalized_name.lower()

            if backend_type == "local":
                tuning = get_auth_runtime_config(self.config)
                ttl = int(tuning.get("local_auth_cache_ttl_seconds", 60))
                return LocalAuthBackend(self.get_local_auth_db(), cache_ttl_seconds=ttl)
            elif backend_type == "ldap":
                return self._create_ldap_backend()
            elif backend_type == "okta":
                return self._create_okta_backend()
            elif backend_type == "radius":
                return self._create_radius_auth_backend()
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
        """Create LDAP backend if configuration exists."""
        if "ldap" not in self.config:
            logger.error("LDAP backend configured but no [ldap] section found")
            return None
        return LDAPAuthBackend(dict(self.config["ldap"]))

    def _create_okta_backend(self):
        """Create Okta backend if configuration exists."""
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

    def _create_radius_auth_backend(self):
        """Create RADIUS authentication backend (client to external RADIUS)."""
        try:
            from tacacs_server.auth.radius_auth import RADIUSAuthBackend
        except Exception:
            logger.error("Radius backend requested but module not available")
            return None

        section_name = "radius_auth"
        if section_name not in self.config:
            logger.error(
                "Radius auth backend configured but no [%s] section found",
                section_name,
            )
            return None
        try:
            cfg = dict(self.config[section_name])
            return RADIUSAuthBackend(cfg)
        except Exception as exc:
            logger.error("Failed to initialize Radius backend: %s", exc)
            return None

    def _create_fallback_backend(self):
        """Create fallback local authentication backend."""
        try:
            return LocalAuthBackend(self.get_local_auth_db())
        except Exception:
            logger.exception("Failed to initialize fallback local auth backend")
            return None

    def get_database_config(self) -> dict[str, Any]:
        """Get database configuration."""
        return get_database_config(self.config)

    def get_auth_runtime_config(self) -> dict[str, Any]:
        """Get runtime tuning for auth backends."""
        return get_auth_runtime_config(self.config)

    def get_device_store_config(self) -> dict[str, Any]:
        """Get device inventory configuration."""
        return get_device_store_config(self.config)

    def get_admin_auth_config(self) -> dict[str, Any]:
        """Get admin authentication configuration."""
        return get_admin_auth_config(self.config)

    def get_backup_config(self) -> dict[str, Any]:
        """Get backup configuration."""
        return get_backup_config(self.config)

    def get_command_authorization_config(self) -> dict[str, Any]:
        """Get command authorization configuration."""
        return get_command_authorization_config(self.config)

    def update_command_authorization_config(
        self,
        *,
        default_action: str | None = None,
        rules: list[dict] | None = None,
        privilege_check_order: str | None = None,
    ) -> None:
        """Update command authorization configuration."""
        update_command_authorization_config(
            self.config,
            default_action=default_action,
            rules=rules,
            privilege_check_order=privilege_check_order,
            config_file=self.config_file,
            is_url_config=self.is_url_config(),
        )

    def get_security_config(self) -> dict[str, Any]:
        """Get security configuration."""
        return get_security_config(self.config)

    def get_logging_config(self) -> dict[str, Any]:
        """Get logging configuration."""
        return get_logging_config(self.config)

    def get_syslog_config(self) -> dict[str, Any]:
        """Get syslog configuration."""
        return get_syslog_config(self.config)

    def get_webhook_config(self) -> dict[str, Any]:
        """Get webhook configuration."""
        return get_webhook_config(self.config)

    def update_webhook_config(self, **kwargs: Any) -> None:
        """Update webhook configuration."""
        update_webhook_config(
            self.config,
            config_file=self.config_file,
            is_url_config=self.is_url_config(),
            **kwargs,
        )

    def get_radius_config(self) -> dict[str, Any]:
        """Get RADIUS server configuration."""
        return get_radius_config(self.config)

    def get_config_summary(self) -> dict[str, Any]:
        """Get configuration summary for display with validation status."""
        summary = get_config_summary(self.config)

        # Add validation status
        validation_issues = self.validate_config()
        summary["_validation"] = {
            "valid": str(len(validation_issues) == 0),
            "issues": str(validation_issues),
            "last_checked": str(time.time()),
        }

        return summary

    # Update methods using unified updater
    def update_server_config(self, **kwargs):
        """Update server configuration."""
        updates = self._filter_updates("server", kwargs)
        update_section(
            self.config,
            "server",
            updates,
            self.config_store,
            self.config_file,
            self.is_url_config(),
            **kwargs,
        )
        self._apply_overrides()

    def update_auth_config(self, **kwargs):
        """Update authentication configuration."""
        updates = self._filter_updates("auth", kwargs)
        update_section(
            self.config,
            "auth",
            updates,
            self.config_store,
            self.config_file,
            self.is_url_config(),
            **kwargs,
        )
        self._apply_overrides()

    def update_ldap_config(self, **kwargs):
        """Update LDAP configuration."""
        updates = self._filter_updates("ldap", kwargs)
        update_section(
            self.config,
            "ldap",
            updates,
            self.config_store,
            self.config_file,
            self.is_url_config(),
            **kwargs,
        )
        self._apply_overrides()

    def update_devices_config(self, **kwargs):
        """Update devices configuration."""
        updates = self._filter_updates("devices", kwargs)
        update_section(
            self.config,
            "devices",
            updates,
            self.config_store,
            self.config_file,
            self.is_url_config(),
            **kwargs,
        )
        self._apply_overrides()

    def update_backup_config(self, **kwargs):
        """Update backup configuration."""
        updates = self._filter_updates("backup", kwargs)
        update_section(
            self.config,
            "backup",
            updates,
            self.config_store,
            self.config_file,
            self.is_url_config(),
            **kwargs,
        )
        self._apply_overrides()

    def update_okta_config(self, **kwargs):
        """Update Okta configuration."""
        updates = self._filter_updates("okta", kwargs)
        update_section(
            self.config,
            "okta",
            updates,
            self.config_store,
            self.config_file,
            self.is_url_config(),
            **kwargs,
        )
        self._apply_overrides()

    def update_radius_config(self, **kwargs):
        """Update RADIUS configuration."""
        updates = self._filter_updates("radius", kwargs)
        update_section(
            self.config,
            "radius",
            updates,
            self.config_store,
            self.config_file,
            self.is_url_config(),
            **kwargs,
        )
        self._apply_overrides()

    def update_radius_auth_config(self, **kwargs):
        """Update RADIUS auth backend (client) configuration."""
        updates = self._filter_updates("radius_auth", kwargs)
        update_section(
            self.config,
            "radius_auth",
            updates,
            self.config_store,
            self.config_file,
            self.is_url_config(),
            **kwargs,
        )
        self._apply_overrides()

    def update_monitoring_config(self, **kwargs):
        """Update monitoring configuration."""
        updates = self._filter_updates("monitoring", kwargs)
        update_section(
            self.config,
            "monitoring",
            updates,
            self.config_store,
            self.config_file,
            self.is_url_config(),
            **kwargs,
        )
        self._apply_overrides()

    def update_proxy_protocol_config(self, **kwargs):
        """Update proxy_protocol configuration."""
        updates = self._filter_updates("proxy_protocol", kwargs)
        update_section(
            self.config,
            "proxy_protocol",
            updates,
            self.config_store,
            self.config_file,
            self.is_url_config(),
            **kwargs,
        )
        self._apply_overrides()

    # --- helpers ---
    @staticmethod
    def _filter_updates(section: str, kwargs: dict[str, Any]) -> dict[str, Any]:
        """Filter update kwargs to allowed config keys for the section.

        - Drops context/meta keys starting with underscore (e.g. _change_reason).
        - If section exists in DEFAULTS, only allow keys present there.
        - Otherwise, allow all non-underscore keys.
        """
        # Remove context keys (e.g., _user, _change_reason, _source_ip)
        filtered = {k: v for k, v in kwargs.items() if not str(k).startswith("_")}
        # Restrict to known keys if defaults exist
        if section in DEFAULTS:
            allowed = set(DEFAULTS[section].keys())
            filtered = {k: v for k, v in filtered.items() if k in allowed}
        return filtered

    # Validation methods
    def validate_config(self) -> list[str]:
        """Validate configuration and return list of issues."""
        return validate_config(self.config)

    def validate_and_backup_config(self) -> tuple[bool, list[str]]:
        """Validate configuration and create backup if valid."""
        issues = self.validate_config()

        if not issues:
            try:
                if self.config_file and os.path.exists(self.config_file):
                    backup_file = f"{self.config_file}.backup"
                    import shutil

                    shutil.copy2(self.config_file, backup_file)
                    logger.info(
                        "Configuration backup created: %s",
                        backup_file,
                        event="tacacs.config.backup.created",
                        service="tacacs",
                    )
            except Exception as e:
                issues.append(f"Failed to create config backup: {e}")
                return False, issues

        return len(issues) == 0, issues

    def validate_change(
        self, section: str, key: str, value: Any
    ) -> tuple[bool, list[str]]:
        """Validate a single configuration change."""
        return validate_change(self.config, section, key, value)

    # Override and baseline management
    def _snapshot_baseline(self) -> None:
        """Store a copy of the current (pre-override) configuration."""
        snap: dict[str, dict[str, str]] = {}
        for section in self.config.sections():
            snap[section] = {k: v for k, v in self.config.items(section)}
        self._baseline_snapshot = snap

    def _apply_overrides(self) -> None:
        """Apply database overrides on top of base configuration."""
        self.overridden_keys = {}
        store = self.config_store
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
        """Check if configuration is loaded from URL."""
        return is_url(self.config_source)

    def get_baseline_config(self) -> dict[str, Any]:
        """Return base config without overrides (for UI comparison)."""
        return cast(dict[str, Any], json.loads(json.dumps(self._baseline_snapshot)))

    def detect_config_drift(self) -> dict[str, dict[str, tuple[Any, Any]]]:
        """Compare base config with active overrides."""
        drift: dict[str, dict[str, tuple[Any, Any]]] = {}
        store = self.config_store
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

    def _get_base_value(
        self, section: str, key: str, value_type: str | None = None
    ) -> Any:
        """Return the baseline (pre-override) value for section/key."""
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
            return sval
        except Exception:
            return None

    # URL configuration refresh
    def refresh_url_config(self, force: bool = False) -> bool:
        """Refresh configuration from URL if the source is a URL."""
        if not self.is_url_config():
            return False
        updated = refresh_url_config(
            self.config,
            self.config_source,
            self.config_store,
            force,
            self.url_handler.refresh_interval,
        )
        if updated:
            # After loading new configuration from URL, ensure environment
            # overrides are applied (without overwriting file values), and
            # then re-apply any runtime/database overrides stored in ConfigStore.
            try:
                apply_all_env_overrides(self.config)
            except Exception as e:
                logger.error(
                    "Failed to apply environment overrides after URL refresh: %s",
                    e,
                    exc_info=True,
                )
            try:
                # Re-apply runtime overrides so they remain highest precedence
                self._apply_overrides()
            except Exception as e:
                logger.error(
                    "Failed to apply database overrides after URL refresh: %s",
                    e,
                    exc_info=True,
                )
        return updated

    def _export_full_config(self) -> dict[str, dict[str, str]]:
        """Export full configuration as nested dict.

        This method delegates to the module-level function in updaters.py.
        It's kept as an instance method for backward compatibility with code
        that calls config._export_full_config().

        Returns:
            Nested dictionary with structure {section: {key: value}}
        """
        return export_full_config_impl(self.config)


def setup_logging(config: TacacsConfig):
    """Setup logging based on configuration."""
    log_config = config.get_logging_config()
    log_file = log_config["log_file"]

    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

    log_level = getattr(logging, log_config["log_level"].upper(), logging.INFO)
    handlers: list[logging.Handler] = []

    # Add console handler if interactive
    add_console = True
    try:
        import sys as _sys

        add_console = bool(getattr(_sys.stdout, "isatty", lambda: False)())
    except Exception:
        add_console = True

    if add_console:
        console_handler = logging.StreamHandler()
        handlers.append(console_handler)

    # Add file handler
    if log_file:
        try:
            if log_config.get("log_rotation", False):
                max_bytes = parse_size(log_config.get("max_log_size", "10MB"))
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

    logger.info(
        "Logging configured: level=%s, file=%s",
        log_config["log_level"],
        log_file or "console-only",
    )

    # Configure optional syslog handler
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

            # Level mapping
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

            # Simple formatter
            app = syslog_cfg.get("app_name") or "tacacs_server"
            sh.setFormatter(logging.Formatter(f"{app}: %(message)s"))

            # Attach to root logger
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
