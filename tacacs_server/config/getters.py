"""Configuration getter functions.

All getters are pure functions: ConfigParser → dict
No side effects, no state modification.
"""

import configparser
import json
import os
from typing import Any

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


def get_server_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get server configuration (excluding sensitive values)."""
    return {
        "host": config.get("server", "host"),
        "port": config.getint("server", "port"),
        "max_connections": config.getint("server", "max_connections"),
        "socket_timeout": config.getint("server", "socket_timeout"),
    }


def get_server_network_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get extended server/network tuning parameters."""
    s = config["server"]
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


def get_auth_backends(config: configparser.ConfigParser) -> list[str]:
    """Get list of enabled authentication backends."""
    backends_str = config.get("auth", "backends", fallback="local")
    backend_list = backends_str.split(",")
    return [backend.strip() for backend in backend_list if backend.strip()]


def get_local_auth_db(config: configparser.ConfigParser) -> str:
    """Get local auth database path with environment variable expansion."""
    if config.has_option("auth", "local_auth_db"):
        val = config.get("auth", "local_auth_db")
        return os.path.expandvars(val)
    return "data/local_auth.db"


def get_auth_runtime_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get runtime tuning for auth backends (non-secret)."""
    a = config["auth"]

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


def get_database_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get database configuration."""
    return {
        "accounting_db": config.get("database", "accounting_db"),
        "cleanup_days": config.getint("database", "cleanup_days"),
        "auto_cleanup": config.getboolean("database", "auto_cleanup"),
        "metrics_history_db": config.get("database", "metrics_history_db"),
        "audit_trail_db": config.get("database", "audit_trail_db"),
        "metrics_retention_days": config.getint("database", "metrics_retention_days"),
        "audit_retention_days": config.getint("database", "audit_retention_days"),
        "db_pool_size": int(config.get("database", "db_pool_size", fallback="5")),
    }


def get_device_store_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get device inventory configuration."""
    return {
        "database": config.get("devices", "database", fallback="data/devices.db"),
        "default_group": config.get("devices", "default_group", fallback="default"),
        "auto_register": (
            config.getboolean("devices", "auto_register", fallback=False)
            if "devices" in config
            else False
        ),
        "identity_cache_ttl_seconds": int(
            config.get("devices", "identity_cache_ttl_seconds", fallback="60")
        ),
        "identity_cache_size": int(
            config.get("devices", "identity_cache_size", fallback="10000")
        ),
    }


def get_admin_auth_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get admin authentication configuration."""
    section = config["admin"] if "admin" in config else {}
    return {
        "username": section.get("username", "admin"),
        "password_hash": section.get("password_hash", ""),
        "session_timeout_minutes": int(section.get("session_timeout_minutes", 60)),
    }


def get_openid_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get OpenID configuration merged with env overrides (config takes precedence for non-secrets)."""

    section = config["openid"] if "openid" in config else {}

    def _pick(key: str, env_key: str, default: str = "") -> str:
        try:
            cfg_val = str(section.get(key, "")).strip()
        except Exception:
            cfg_val = ""
        env_val = str(os.getenv(env_key, "")).strip()
        # Precedence: config -> env -> default (env only used when config is empty)
        return cfg_val or env_val or default

    issuer_url = _pick("issuer_url", "OPENID_ISSUER_URL")
    client_id = _pick("client_id", "OPENID_CLIENT_ID")
    redirect_uri = _pick("redirect_uri", "OPENID_REDIRECT_URI")
    scopes = _pick("scopes", "OPENID_SCOPES", "openid profile email")
    try:
        session_timeout_minutes = int(
            _pick("session_timeout_minutes", "OPENID_SESSION_TIMEOUT_MINUTES", "60")
        )
    except Exception:
        session_timeout_minutes = 60

    client_auth_method = (
        _pick("client_auth_method", "OPENID_CLIENT_AUTH_METHOD", "client_secret")
        .lower()
        .strip()
        or "client_secret"
    )
    use_interaction_code = _to_bool(
        section.get("use_interaction_code", None)
        or os.getenv("OPENID_USE_INTERACTION_CODE")
    )
    code_verifier = (
        _pick("code_verifier", "OPENID_CODE_VERIFIER", "")
        if use_interaction_code
        else ""
    )

    allowed_groups_raw = _pick("allowed_groups", "OPENID_ADMIN_GROUPS", "")
    allowed_groups = [g.strip() for g in allowed_groups_raw.split(",") if g.strip()]

    token_endpoint = _pick("token_endpoint", "OPENID_TOKEN_ENDPOINT", "")
    userinfo_endpoint = _pick("userinfo_endpoint", "OPENID_USERINFO_ENDPOINT", "")
    client_private_key_id = _pick(
        "client_private_key_id", "OPENID_CLIENT_PRIVATE_KEY_ID", ""
    )

    # Secrets: env only by policy
    client_secret = os.getenv("OPENID_CLIENT_SECRET", "").strip()
    client_private_key = os.getenv("OPENID_CLIENT_PRIVATE_KEY", "").strip()

    warnings: list[str] = []

    # Not configured: return empty (but warn if partially filled)
    if not (issuer_url and client_id and redirect_uri):
        if issuer_url or client_id or redirect_uri:
            warnings.append(
                "OpenID: issuer_url, client_id, and redirect_uri are all required to enable OpenID"
            )
        for w in warnings:
            try:
                logger.warning(w)
            except Exception:
                pass
        return {"warnings": warnings}

    # Validate combinations
    if client_auth_method == "client_secret":
        if not client_secret:
            warnings.append(
                "OpenID: client_secret auth selected but OPENID_CLIENT_SECRET is missing"
            )
        if client_private_key:
            warnings.append(
                "OpenID: client_secret auth will ignore OPENID_CLIENT_PRIVATE_KEY"
            )
    elif client_auth_method == "private_key_jwt":
        if not client_private_key:
            warnings.append(
                "OpenID: private_key_jwt auth selected but OPENID_CLIENT_PRIVATE_KEY is missing"
            )
        if client_secret:
            warnings.append(
                "OpenID: private_key_jwt auth will ignore OPENID_CLIENT_SECRET"
            )
    else:
        if not use_interaction_code:
            warnings.append(
                f"OpenID: auth method '{client_auth_method}' requires interaction_code/PKCE"
            )

    if use_interaction_code and not code_verifier:
        warnings.append(
            "OpenID: interaction_code enabled but OPENID_CODE_VERIFIER is missing"
        )

    for w in warnings:
        try:
            logger.warning(w)
        except Exception:
            pass

    return {
        "issuer_url": issuer_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "scopes": scopes,
        "session_timeout_minutes": session_timeout_minutes,
        "allowed_groups": allowed_groups,
        "use_interaction_code": use_interaction_code,
        "code_verifier": code_verifier,
        "client_auth_method": client_auth_method,
        "token_endpoint": token_endpoint or None,
        "userinfo_endpoint": userinfo_endpoint or None,
        "client_private_key": client_private_key,
        "client_private_key_id": client_private_key_id,
        "warnings": warnings,
    }


def get_backup_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get backup configuration.

    Secret (encryption_passphrase) only from environment.
    """
    try:
        enabled = config.getboolean("backup", "enabled", fallback=True)
    except Exception:
        enabled = True

    try:
        create_on_startup = config.getboolean(
            "backup", "create_on_startup", fallback=False
        )
    except Exception:
        create_on_startup = False

    temp_directory = config.get("backup", "temp_directory", fallback="data/backup_temp")

    try:
        encryption_enabled = config.getboolean(
            "backup", "encryption_enabled", fallback=False
        )
    except Exception:
        encryption_enabled = False

    # Secret: only from environment (already applied in loader)
    enc_passphrase = os.environ.get("BACKUP_ENCRYPTION_PASSPHRASE", "")

    try:
        retention_days = config.getint("backup", "default_retention_days", fallback=30)
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


def get_command_authorization_config(
    config: configparser.ConfigParser,
) -> dict[str, Any]:
    """Get command authorization configuration."""
    section = (
        config["command_authorization"] if "command_authorization" in config else {}
    )

    default_action = (
        str(section.get("default_action", "deny")).strip().lower() or "deny"
    )
    rules_json = section.get("rules_json", "[]")

    try:
        rules = json.loads(rules_json) if rules_json else []
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


def get_security_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get security configuration."""
    allowed_clients_str = config.get("security", "allowed_clients")
    denied_clients_str = config.get("security", "denied_clients")

    allowed_clients = _parse_client_list(allowed_clients_str)
    denied_clients = _parse_client_list(denied_clients_str)

    return {
        "max_auth_attempts": config.getint("security", "max_auth_attempts"),
        "auth_timeout": config.getint("security", "auth_timeout"),
        "encryption_required": config.getboolean("security", "encryption_required"),
        "allowed_clients": allowed_clients,
        "denied_clients": denied_clients,
        "rate_limit_requests": config.getint("security", "rate_limit_requests"),
        "rate_limit_window": config.getint("security", "rate_limit_window"),
        "max_connections_per_ip": config.getint(
            "security", "max_connections_per_ip", fallback=20
        ),
    }


def _parse_client_list(clients_str: str) -> list[str]:
    """Parse comma-separated client IP list."""
    if not clients_str:
        return []
    client_list = clients_str.split(",")
    return [ip.strip() for ip in client_list if ip.strip()]


def get_logging_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get logging configuration."""
    return {
        "log_file": config.get("logging", "log_file"),
        "log_format": config.get("logging", "log_format"),
        "log_rotation": config.getboolean("logging", "log_rotation"),
        "max_log_size": config.get("logging", "max_log_size"),
        "backup_count": config.getint("logging", "backup_count"),
        "log_level": config.get("server", "log_level"),
    }


def get_syslog_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get syslog configuration (optional)."""
    sec = config["syslog"] if "syslog" in config else {}

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


def get_webhook_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get webhook configuration (parsed)."""
    section = config["webhooks"] if "webhooks" in config else {}

    urls_raw = section.get("urls", "")
    urls = [u.strip() for u in str(urls_raw).replace("\n", ",").split(",") if u.strip()]

    headers_json = section.get("headers_json", "{}")
    template_json = section.get("template_json", "{}")

    try:
        headers = json.loads(headers_json) if headers_json else {}
    except Exception:
        headers = {}

    try:
        template = json.loads(template_json) if template_json else {}
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


def get_proxy_protocol_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Return proxy_protocol config: enabled, validate_sources, reject_invalid."""
    defaults = {
        "enabled": False,
        "validate_sources": True,
        "reject_invalid": True,
    }

    try:
        env_enabled = os.getenv("TACACS_PROXY_PROTOCOL_ENABLED")
        env_validate = os.getenv("TACACS_PROXY_PROTOCOL_VALIDATE_SOURCES")
        env_reject = os.getenv("TACACS_PROXY_PROTOCOL_REJECT_INVALID")
        env_overrides: dict[str, Any] = {}
        if env_enabled is not None:
            env_overrides["enabled"] = _to_bool(env_enabled)
        if env_validate is not None:
            env_overrides["validate_sources"] = _to_bool(env_validate)
        if env_reject is not None:
            env_overrides["reject_invalid"] = _to_bool(env_reject)

        if not config.has_section("proxy_protocol"):
            return {
                "enabled": env_overrides.get("enabled", defaults["enabled"]),
                "validate_sources": env_overrides.get(
                    "validate_sources", defaults["validate_sources"]
                ),
                "reject_invalid": env_overrides.get(
                    "reject_invalid", defaults["reject_invalid"]
                ),
            }

        sec = dict(config.items("proxy_protocol"))
        final_config = {}
        for key, default_val in defaults.items():
            if key in sec:
                final_config[key] = _to_bool(sec.get(key, default_val))
            else:
                final_config[key] = env_overrides.get(key, default_val)
        return final_config
    except Exception:
        return defaults


def _to_bool(val: object) -> bool:
    """Convert various types to boolean."""
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    s = str(val).strip().lower()
    return s in ("1", "true", "yes", "on")


def get_monitoring_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get monitoring configuration if present."""
    if "monitoring" not in config:
        return {}

    m = config["monitoring"]
    try:
        enabled = str(m.get("enabled", "false")).lower() == "true"
    except Exception:
        enabled = False

    return {
        "enabled": enabled,
        "web_host": m.get("web_host", "127.0.0.1"),
        "web_port": int(m.get("web_port", 8080)),
    }


def get_radius_config(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get RADIUS server configuration."""
    return {
        "enabled": config.getboolean("radius", "enabled"),
        "auth_port": config.getint("radius", "auth_port"),
        "acct_port": config.getint("radius", "acct_port"),
        "host": config.get("radius", "host"),
        "share_backends": config.getboolean("radius", "share_backends"),
        "share_accounting": config.getboolean("radius", "share_accounting"),
        "workers": int(config.get("radius", "workers", fallback="8")),
        "socket_timeout": float(config.get("radius", "socket_timeout", fallback="1.0")),
        "rcvbuf": int(config.get("radius", "rcvbuf", fallback="1048576")),
    }


# This function is used to get the configuration summary with secrets redacted for display in the UI.
def get_config_summary(config: configparser.ConfigParser) -> dict[str, Any]:
    """Get configuration summary for display."""
    summary = {
        "server": dict(config["server"]),
        "auth": dict(config["auth"]),
        "ldap": dict(config["ldap"]) if "ldap" in config else {},
        "database": dict(config["database"]),
        "security": dict(config["security"]),
        "logging": dict(config["logging"]),
    }

    optional_sections = [
        "admin",
        "devices",
        "radius",
        "radius_auth",
        "proxy_protocol",
        "monitoring",
        "okta",
        "backup",
    ]

    for section in optional_sections:
        if section in config:
            summary[section] = dict(config[section])

    # Redact sensitive fields
    SENSITIVE_KEYS = {
        "password",
        "secret",
        "token",
        "passphrase",
        "api_key",
        "bind_password",
        "client_secret",
        "private_key",
    }
    for section in summary:
        for key in summary[section]:
            if any(sensitive in key.lower() for sensitive in SENSITIVE_KEYS):
                summary[section][key] = "***REDACTED***"
    return summary
