"""Configuration constants and defaults.

This module contains all default configuration values and constants used
throughout the configuration system.
"""

# Section names
SECTION_SERVER = "server"
SECTION_AUTH = "auth"
SECTION_LDAP = "ldap"
SECTION_DATABASE = "database"
SECTION_SECURITY = "security"
SECTION_WEBHOOKS = "webhooks"
SECTION_LOGGING = "logging"
SECTION_SYSLOG = "syslog"
SECTION_COMMAND_AUTHORIZATION = "command_authorization"
SECTION_BACKUP = "backup"
SECTION_ADMIN = "admin"
SECTION_DEVICES = "devices"
SECTION_RADIUS = "radius"
SECTION_MONITORING = "monitoring"
SECTION_PROXY_PROTOCOL = "proxy_protocol"
SECTION_RADIUS_AUTH = "radius_auth"

# Environment variable prefixes
ENV_PREFIX = "TACACS_"

# Secrets (environment only)
ENV_ADMIN_PASSWORD_HASH = "ADMIN_PASSWORD_HASH"
ENV_LDAP_BIND_PASSWORD = "LDAP_BIND_PASSWORD"
ENV_OKTA_DOMAIN = "OKTA_DOMAIN"
ENV_OKTA_CLIENT_ID = "OKTA_CLIENT_ID"
ENV_OKTA_PRIVATE_KEY = "OKTA_PRIVATE_KEY"
ENV_OKTA_API_TOKEN = "OKTA_API_TOKEN"
ENV_BACKUP_ENCRYPTION_PASSPHRASE = "BACKUP_ENCRYPTION_PASSPHRASE"
ENV_RADIUS_AUTH_SECRET = "RADIUS_AUTH_SECRET"

# Meta-configuration
ENV_TACACS_CONFIG = "TACACS_CONFIG"
ENV_CONFIG_REFRESH_SECONDS = "CONFIG_REFRESH_SECONDS"
ENV_CURRENT_ADMIN_USER = "CURRENT_ADMIN_USER"
ENV_INSTANCE_NAME = "INSTANCE_NAME"

# Default values
DEFAULTS = {
    SECTION_SERVER: {
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
        "encryption_required": "true",
        "allowed_clients": "",
        "denied_clients": "",
        "rate_limit_requests": "60",
        "rate_limit_window": "60",
        "max_connections_per_ip": "20",
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
        "username": "admin",
        "password_hash": "",
        "session_timeout_minutes": "60",
    },
    SECTION_DEVICES: {
        "database": "data/devices.db",
        "default_group": "default",
        "identity_cache_ttl_seconds": "60",
        "identity_cache_size": "10000",
    },
    SECTION_RADIUS: {
        "enabled": "false",
        "auth_port": "1812",
        "acct_port": "1813",
        "host": "0.0.0.0",
        "share_backends": "true",
        "share_accounting": "true",
        "workers": "8",
        "socket_timeout": "1.0",
        "rcvbuf": "1048576",
    },
    SECTION_MONITORING: {
        "enabled": "false",
        "web_host": "127.0.0.1",
        "web_port": "8080",
    },
    SECTION_PROXY_PROTOCOL: {
        "enabled": "false",
        "validate_sources": "true",
        "reject_invalid": "true",
    },
    SECTION_RADIUS_AUTH: {
        "radius_server": "127.0.0.1",
        "radius_port": "1812",
        "radius_secret": "",
        "radius_timeout": "5",
        "radius_retries": "3",
        "radius_nas_ip": "0.0.0.0",
        "radius_nas_identifier": "",
    },
}
