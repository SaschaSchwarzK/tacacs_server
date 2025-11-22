"""Centralized default configuration values for TACACS server setup."""

from __future__ import annotations

from typing import Any

from .constants import (
    SECTION_ADMIN,
    SECTION_AUTH,
    SECTION_BACKUP,
    SECTION_COMMAND_AUTHORIZATION,
    SECTION_DATABASE,
    SECTION_DEVICES,
    SECTION_LDAP,
    SECTION_LOGGING,
    SECTION_MONITORING,
    SECTION_PROXY_PROTOCOL,
    SECTION_RADIUS,
    SECTION_RADIUS_AUTH,
    SECTION_SECURITY,
    SECTION_SERVER,
    SECTION_SYSLOG,
    SECTION_WEBHOOKS,
)

DEFAULT_SERVER_HOST = "localhost"
DEFAULT_TACACS_PORT = 49
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_SHARED_SECRET = "tacacs123"
DEFAULT_CONFIG_REFRESH_SECONDS = 300
DEFAULT_CONFIG_REFRESH_MIN_SLEEP = 30
DEFAULT_TCP_KEEPALIVE_IDLE = 60
DEFAULT_LISTEN_BACKLOG = 128
DEFAULT_THREAD_POOL_MAX = 100
DEFAULT_CLIENT_TIMEOUT = 15.0
DEFAULT_MAX_PACKET_LENGTH = 4096
DEFAULT_TCP_KEEPINTVL = 10
DEFAULT_TCP_KEEPCNT = 5
DEFAULT_USE_THREAD_POOL = True
DEFAULT_PROXY_ENABLED = False
DEFAULT_PROXY_VALIDATE = True
DEFAULT_PROXY_REJECT = True
DEFAULT_PER_IP_CAP = 20
DEFAULT_ENCRYPTION_REQUIRED = True
DEFAULT_ADMIN_SESSION_TIMEOUT_MINUTES = 60
DEFAULT_MONITORING_HOST = "127.0.0.1"
DEFAULT_MONITORING_PORT = 8080
DEFAULT_RADIUS_WORKERS = 8
DEFAULT_RADIUS_SOCKET_TIMEOUT = 1.0
DEFAULT_RADIUS_RCVBUF = 1_048_576
MIN_RADIUS_RCVBUF = 262_144
DEFAULT_COMMAND_RESPONSE_MODE = "pass_add"
DEFAULT_PRIVILEGE_ORDER = "before"


def populate_defaults(parser: Any) -> None:
    """Populate a ConfigParser with default sections/options."""

    for section, values in CONFIG_DEFAULTS.items():
        if not parser.has_section(section):
            parser.add_section(section)
        for key, val in values.items():
            if not parser.has_option(section, key):
                parser.set(section, key, str(val))


CONFIG_DEFAULTS = {
    SECTION_SERVER: {
        "host": "0.0.0.0",
        "port": str(DEFAULT_TACACS_PORT),
        "log_level": "INFO",
        "max_connections": "50",
        "socket_timeout": "30",
        "listen_backlog": str(DEFAULT_LISTEN_BACKLOG),
        "client_timeout": str(int(DEFAULT_CLIENT_TIMEOUT)),
        "max_packet_length": str(DEFAULT_MAX_PACKET_LENGTH),
        "ipv6_enabled": "false",
        "tcp_keepalive": "true",
        "tcp_keepidle": str(DEFAULT_TCP_KEEPALIVE_IDLE),
        "tcp_keepintvl": str(DEFAULT_TCP_KEEPINTVL),
        "tcp_keepcnt": str(DEFAULT_TCP_KEEPCNT),
        "thread_pool_max": str(DEFAULT_THREAD_POOL_MAX),
        "use_thread_pool": str(DEFAULT_USE_THREAD_POOL).lower(),
    },
    SECTION_AUTH: {
        "backends": "local",
        "local_auth_db": "data/local_auth.db",
        "require_all_backends": "false",
        "local_auth_cache_ttl_seconds": "60",
        "backend_timeout": "2.0",
    },
    SECTION_LDAP: {
        "server": "ldap://localhost:389",
        "base_dn": "ou=people,dc=example,dc=com",
        "user_attribute": "uid",
        "bind_dn": "",
        "bind_password": "",
        "use_tls": "false",
        "timeout": "10",
    },
    SECTION_DATABASE: {
        "accounting_db": "data/tacacs_accounting.db",
        "cleanup_days": "90",
        "auto_cleanup": "true",
        "metrics_history_db": "data/metrics_history.db",
        "audit_trail_db": "data/audit_trail.db",
        "metrics_retention_days": "30",
        "audit_retention_days": "90",
        "db_pool_size": "5",
    },
    SECTION_SECURITY: {
        "max_auth_attempts": "3",
        "auth_timeout": "300",
        "encryption_required": str(DEFAULT_ENCRYPTION_REQUIRED).lower(),
        "allowed_clients": "",
        "denied_clients": "",
        "rate_limit_requests": "60",
        "rate_limit_window": "60",
        "max_connections_per_ip": str(DEFAULT_PER_IP_CAP),
    },
    SECTION_WEBHOOKS: {
        "urls": "",
        "headers_json": "{}",
        "template_json": "{}",
        "timeout": "3",
        "threshold_count": "0",
        "threshold_window": "60",
    },
    SECTION_LOGGING: {
        "log_file": "logs/tacacs.log",
        "log_format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "log_rotation": "true",
        "max_log_size": "10MB",
        "backup_count": "5",
    },
    SECTION_SYSLOG: {
        "enabled": "false",
        "host": "127.0.0.1",
        "port": "514",
        "protocol": "udp",
        "facility": "local0",
        "severity": "info",
        "format": "rfc5424",
        "app_name": "tacacs_server",
        "include_hostname": "true",
    },
    SECTION_COMMAND_AUTHORIZATION: {
        "default_action": "deny",
        "rules_json": "[{'action':'permit','match_type':'prefix','pattern':'show ','min_privilege':1}]".replace(
            "'", '"'
        ),
        "privilege_check_order": "before",
    },
    SECTION_BACKUP: {
        "enabled": "true",
        "create_on_startup": "false",
        "temp_directory": "data/backup_temp",
        "encryption_enabled": "false",
        "encryption_passphrase": "",
        "default_retention_strategy": "simple",
        "default_retention_days": "30",
        "gfs_keep_daily": "7",
        "gfs_keep_weekly": "4",
        "gfs_keep_monthly": "12",
        "gfs_keep_yearly": "3",
        "compression_level": "6",
    },
    SECTION_ADMIN: {
        "username": DEFAULT_ADMIN_USERNAME,
        "password_hash": "",
        "session_timeout_minutes": str(DEFAULT_ADMIN_SESSION_TIMEOUT_MINUTES),
    },
    SECTION_DEVICES: {
        "database": "data/devices.db",
        "default_group": "default",
        "auto_register": "false",
        "identity_cache_ttl_seconds": "60",
        "identity_cache_size": "1000",
    },
    SECTION_RADIUS: {
        "enabled": "false",
        "share_backends": "false",
        "share_accounting": "false",
        "host": "0.0.0.0",
        "auth_port": "1812",
        "acct_port": "1813",
        "workers": str(DEFAULT_RADIUS_WORKERS),
        "socket_timeout": str(DEFAULT_RADIUS_SOCKET_TIMEOUT),
        "rcvbuf": str(DEFAULT_RADIUS_RCVBUF),
    },
    SECTION_MONITORING: {
        "enabled": "false",
        "web_host": DEFAULT_MONITORING_HOST,
        "web_port": str(DEFAULT_MONITORING_PORT),
    },
    SECTION_PROXY_PROTOCOL: {
        "enabled": str(DEFAULT_PROXY_ENABLED).lower(),
        "validate_sources": str(DEFAULT_PROXY_VALIDATE).lower(),
        "reject_invalid": str(DEFAULT_PROXY_REJECT).lower(),
    },
    SECTION_RADIUS_AUTH: {
        "enabled": "false",
        "secret": "",
        "host": "127.0.0.1",
        "port": "1812",
        "retries": "3",
        "timeout": "3",
    },
}
