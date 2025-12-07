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
    SECTION_MFA,
    SECTION_MONITORING,
    SECTION_OPENID,
    SECTION_PROXY_PROTOCOL,
    SECTION_RADIUS,
    SECTION_RADIUS_AUTH,
    SECTION_SECURITY,
    SECTION_SERVER,
    SECTION_SYSLOG,
    SECTION_WEBHOOKS,
)

# Server defaults (transport/tuning)
DEFAULT_SERVER_HOST = "localhost"  # default bind host when not overridden
DEFAULT_TACACS_PORT = 49  # TACACS+ listening port
DEFAULT_LOG_LEVEL = "INFO"  # base log level if not set
DEFAULT_MAX_CONNECTIONS = 50  # maximum concurrent connections overall
DEFAULT_SOCKET_TIMEOUT = 30  # socket read timeout seconds
DEFAULT_LISTEN_BACKLOG = 128  # listen backlog for accept()
DEFAULT_CLIENT_TIMEOUT = 15.0  # client idle timeout seconds
DEFAULT_MAX_PACKET_LENGTH = 4096  # max allowed TACACS packet size
DEFAULT_TCP_KEEPALIVE = True  # enable TCP keepalive on sockets
DEFAULT_TCP_KEEPALIVE_IDLE = 60  # keepalive idle seconds
DEFAULT_TCP_KEEPINTVL = 10  # keepalive interval seconds
DEFAULT_TCP_KEEPCNT = 5  # keepalive retry count
DEFAULT_THREAD_POOL_MAX = 100  # max worker threads for handlers
DEFAULT_USE_THREAD_POOL = True  # toggle thread pool usage
DEFAULT_ENABLE_IPV6 = False  # bind IPv6 sockets if true

# Security defaults (limits/rate control)
DEFAULT_PER_IP_CAP = 20  # max simultaneous connections per IP
DEFAULT_ENCRYPTION_REQUIRED = True  # require encryption for TACACS payloads
DEFAULT_MAX_AUTH_ATTEMPTS = 3  # max auth failures before block
DEFAULT_AUTH_TIMEOUT = 300  # seconds to keep auth session alive
DEFAULT_RATE_LIMIT_REQUESTS = 60  # requests per window for per-device limiter
DEFAULT_RATE_LIMIT_WINDOW = 60  # window seconds for per-device limiter

# Admin/auth defaults
DEFAULT_ADMIN_USERNAME = "admin"  # default admin username
DEFAULT_ADMIN_SESSION_TIMEOUT_MINUTES = 60  # admin session lifetime minutes
DEFAULT_SHARED_SECRET = "tacacs123"  # fallback shared secret # nosec

# Monitoring defaults
DEFAULT_MONITORING_HOST = "127.0.0.1"  # web monitoring bind host
DEFAULT_MONITORING_PORT = 8080  # web monitoring port

# Radius defaults
DEFAULT_RADIUS_WORKERS = 8  # radius worker processes
DEFAULT_RADIUS_AUTH_PORT = 1812  # RADIUS auth port
DEFAULT_RADIUS_ACCT_PORT = 1813  # RADIUS acct port
DEFAULT_RADIUS_SOCKET_TIMEOUT = 1.0  # RADIUS socket timeout seconds
DEFAULT_RADIUS_RCVBUF = 1_048_576  # RADIUS socket receive buffer
MIN_RADIUS_RCVBUF = 262_144  # floor for receive buffer

# Proxy protocol defaults
DEFAULT_PROXY_ENABLED = False  # accept proxy protocol headers
DEFAULT_PROXY_VALIDATE = True  # validate proxy source
DEFAULT_PROXY_REJECT = True  # reject invalid proxy headers

# Command auth defaults
DEFAULT_COMMAND_RESPONSE_MODE = "pass_add"  # default AAA command response mode
DEFAULT_PRIVILEGE_ORDER = "before"  # privilege check ordering

# Syslog defaults
DEFAULT_SYSLOG_HOST = "127.0.0.1"  # syslog destination host
DEFAULT_SYSLOG_PORT = 514  # syslog destination port
DEFAULT_SYSLOG_PROTOCOL = "udp"  # udp|tcp
DEFAULT_SYSLOG_FACILITY = "local0"  # syslog facility
DEFAULT_SYSLOG_SEVERITY = "info"  # syslog severity level
DEFAULT_SYSLOG_FORMAT = "rfc5424"  # wire format
DEFAULT_SYSLOG_APP = "tacacs_server"  # app name tag
DEFAULT_SYSLOG_INCLUDE_HOSTNAME = True  # include hostname in syslog

# Device defaults
DEFAULT_DEVICE_GROUP = "default"  # fallback device group name
DEFAULT_DEVICE_AUTOREGISTER = False  # auto-register devices on connect
DEFAULT_IDENTITY_CACHE_TTL_SECONDS = 60  # identity cache TTL
DEFAULT_IDENTITY_CACHE_SIZE = 1000  # identity cache max entries

# Auth runtime defaults
DEFAULT_LOCAL_AUTH_CACHE_TTL_SECONDS = 60  # local auth cache TTL
DEFAULT_BACKEND_TIMEOUT = 2.0  # backend call timeout seconds

# Logging defaults
DEFAULT_LOG_ROTATION = True  # enable log rotation
DEFAULT_MAX_LOG_SIZE = "10MB"  # rotation size
DEFAULT_LOG_BACKUP_COUNT = 5  # rotated files retained
DEFAULT_LOG_FILE = "logs/tacacs.log"  # default log file path
DEFAULT_LOG_FORMAT = (
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"  # legacy format
)

# Backup defaults
DEFAULT_BACKUP_ENABLED = True  # enable backup subsystem
DEFAULT_BACKUP_CREATE_ON_STARTUP = False  # create backup on startup
DEFAULT_BACKUP_TEMP_DIRECTORY = "data/backup_temp"  # temp dir for backups
DEFAULT_BACKUP_ENCRYPTION_ENABLED = False  # encrypt backups
DEFAULT_BACKUP_ENCRYPTION_PASSPHRASE = ""  # encryption passphrase (empty by default) # nosec
DEFAULT_BACKUP_RETENTION_STRATEGY = "simple"  # retention strategy
DEFAULT_BACKUP_RETENTION_DAYS = 30  # simple strategy retention
DEFAULT_BACKUP_GFS_DAILY = 7  # GFS daily keep
DEFAULT_BACKUP_GFS_WEEKLY = 4  # GFS weekly keep
DEFAULT_BACKUP_GFS_MONTHLY = 12  # GFS monthly keep
DEFAULT_BACKUP_GFS_YEARLY = 3  # GFS yearly keep
DEFAULT_COMPRESSION_LEVEL = 6  # default backup compression level

# Misc runtime defaults
DEFAULT_CONFIG_REFRESH_SECONDS = 300  # config refresh interval seconds
DEFAULT_CONFIG_REFRESH_MIN_SLEEP = 30  # min sleep between refresh attempts


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
        "log_level": DEFAULT_LOG_LEVEL,
        "max_connections": str(DEFAULT_MAX_CONNECTIONS),
        "socket_timeout": str(DEFAULT_SOCKET_TIMEOUT),
        "listen_backlog": str(DEFAULT_LISTEN_BACKLOG),
        "client_timeout": str(int(DEFAULT_CLIENT_TIMEOUT)),
        "max_packet_length": str(DEFAULT_MAX_PACKET_LENGTH),
        "ipv6_enabled": str(DEFAULT_ENABLE_IPV6).lower(),
        "tcp_keepalive": str(DEFAULT_TCP_KEEPALIVE).lower(),
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
        "local_auth_cache_ttl_seconds": str(DEFAULT_LOCAL_AUTH_CACHE_TTL_SECONDS),
        "backend_timeout": str(DEFAULT_BACKEND_TIMEOUT),
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
        "max_auth_attempts": str(DEFAULT_MAX_AUTH_ATTEMPTS),
        "auth_timeout": str(DEFAULT_AUTH_TIMEOUT),
        "encryption_required": str(DEFAULT_ENCRYPTION_REQUIRED).lower(),
        "allowed_clients": "",
        "denied_clients": "",
        "rate_limit_requests": str(DEFAULT_RATE_LIMIT_REQUESTS),
        "rate_limit_window": str(DEFAULT_RATE_LIMIT_WINDOW),
        "max_connections_per_ip": str(DEFAULT_PER_IP_CAP),
        # NOTE: Rate limits above are per-device; per-IP cap is enforced separately.
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
        "log_file": DEFAULT_LOG_FILE,
        "log_format": DEFAULT_LOG_FORMAT,
        "log_rotation": str(DEFAULT_LOG_ROTATION).lower(),
        "max_log_size": DEFAULT_MAX_LOG_SIZE,
        "backup_count": str(DEFAULT_LOG_BACKUP_COUNT),
    },
    SECTION_SYSLOG: {
        "enabled": "false",
        "host": DEFAULT_SYSLOG_HOST,
        "port": str(DEFAULT_SYSLOG_PORT),
        "protocol": DEFAULT_SYSLOG_PROTOCOL,
        "facility": DEFAULT_SYSLOG_FACILITY,
        "severity": DEFAULT_SYSLOG_SEVERITY,
        "format": DEFAULT_SYSLOG_FORMAT,
        "app_name": DEFAULT_SYSLOG_APP,
        "include_hostname": str(DEFAULT_SYSLOG_INCLUDE_HOSTNAME).lower(),
    },
    SECTION_COMMAND_AUTHORIZATION: {
        "default_action": "deny",
        "rules_json": "[{'action':'permit','match_type':'prefix','pattern':'show ','min_privilege':1}]".replace(
            "'", '"'
        ),
        "privilege_check_order": "before",
    },
    SECTION_BACKUP: {
        "enabled": str(DEFAULT_BACKUP_ENABLED).lower(),
        "create_on_startup": str(DEFAULT_BACKUP_CREATE_ON_STARTUP).lower(),
        "temp_directory": DEFAULT_BACKUP_TEMP_DIRECTORY,
        "encryption_enabled": str(DEFAULT_BACKUP_ENCRYPTION_ENABLED).lower(),
        # Azure destination settings (non-secret)
        "use_managed_identity": "false",
        "endpoint_suffix": "core.windows.net",
        "container_name": "",
        "base_path": "",
        "encryption_passphrase": DEFAULT_BACKUP_ENCRYPTION_PASSPHRASE,
        "default_retention_strategy": DEFAULT_BACKUP_RETENTION_STRATEGY,
        "default_retention_days": str(DEFAULT_BACKUP_RETENTION_DAYS),
        "gfs_keep_daily": str(DEFAULT_BACKUP_GFS_DAILY),
        "gfs_keep_weekly": str(DEFAULT_BACKUP_GFS_WEEKLY),
        "gfs_keep_monthly": str(DEFAULT_BACKUP_GFS_MONTHLY),
        "gfs_keep_yearly": str(DEFAULT_BACKUP_GFS_YEARLY),
        "compression_level": str(DEFAULT_COMPRESSION_LEVEL),
    },
    SECTION_ADMIN: {
        "username": DEFAULT_ADMIN_USERNAME,
        "password_hash": "",
        "session_timeout_minutes": str(DEFAULT_ADMIN_SESSION_TIMEOUT_MINUTES),
    },
    SECTION_DEVICES: {
        "database": "data/devices.db",
        "default_group": DEFAULT_DEVICE_GROUP,
        "auto_register": str(DEFAULT_DEVICE_AUTOREGISTER).lower(),
        "identity_cache_ttl_seconds": str(DEFAULT_IDENTITY_CACHE_TTL_SECONDS),
        "identity_cache_size": str(DEFAULT_IDENTITY_CACHE_SIZE),
    },
    SECTION_RADIUS: {
        "enabled": "false",
        "share_backends": "false",
        "share_accounting": "false",
        "host": "0.0.0.0",
        "auth_port": str(DEFAULT_RADIUS_AUTH_PORT),
        "acct_port": str(DEFAULT_RADIUS_ACCT_PORT),
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
        "radius_server": "127.0.0.1",
        "radius_port": "1812",
        "radius_secret": "",
        "radius_timeout": "5",
        "radius_retries": "3",
        "radius_nas_ip": "0.0.0.0",
        "radius_nas_identifier": "",
        "group_cache_ttl": "600",
        "mfa_enabled": "false",
        "mfa_otp_digits": "6",
        "mfa_push_keyword": "push",
        "mfa_timeout_seconds": "25",
        "mfa_poll_interval": "2.0",
    },
    SECTION_MFA: {
        "mfa_enabled": "false",
        "mfa_otp_digits": "6",
        "mfa_push_keyword": "push",
        "mfa_timeout_seconds": "25",
        "mfa_poll_interval": "2.0",
    },
    SECTION_OPENID: {
        "issuer_url": "",
        "client_id": "",
        "redirect_uri": "",
        "scopes": "openid profile email",
        "session_timeout_minutes": "60",
        # Leave blank so env or explicit config can decide; falls back to client_secret in code
        "client_auth_method": "",
        "use_interaction_code": "false",
        "code_verifier": "",
        "allowed_groups": "",
        "token_endpoint": "",
        "userinfo_endpoint": "",
        "client_private_key_id": "",
    },
}
