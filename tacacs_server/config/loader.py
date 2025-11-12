"""Unified configuration loading mechanism.

Load order: config file → environment variables → defaults
Exception: Secrets (like passwords, API tokens) only from environment variables.

FIXED: Admin section now allows username from file, password_hash from environment only.
"""

import configparser
import os
from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen

from .constants import (
    ENV_ADMIN_PASSWORD_HASH,
    ENV_BACKUP_ENCRYPTION_PASSPHRASE,
    ENV_LDAP_BIND_PASSWORD,
    ENV_OKTA_API_TOKEN,
    ENV_OKTA_CLIENT_ID,
    ENV_OKTA_DOMAIN,
    ENV_OKTA_PRIVATE_KEY,
)


def is_url(source: str) -> bool:
    """Check if source is a URL."""
    parsed = urlparse(source)
    return parsed.scheme in {"http", "https", "file"}


def load_from_url(source: str, cache_path: str | None = None) -> str | None:
    """Load configuration from URL with optional caching."""
    try:
        max_size = 1024 * 1024  # 1MB limit
        with urlopen(source, timeout=10) as response:
            if response.length and response.length > max_size:
                return None
            content: str = response.read().decode("utf-8")
        
        # Cache if path provided
        if cache_path and content:
            try:
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception:
                pass  # Cache write failed, continue
                
        return content
    except Exception:
        # Try cache fallback if available
        if cache_path and os.path.exists(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as f:
                    return f.read()
            except Exception:
                pass
        return None


def apply_env_overrides(
    config: configparser.ConfigParser,
    section: str,
    key: str,
    env_var: str | None = None
) -> None:
    """Apply environment variable override to config value.
    
    Args:
        config: ConfigParser instance
        section: Section name
        key: Key name
        env_var: Optional custom environment variable name.
                If None, derives from TACACS_SECTION_KEY pattern.
    """
    if env_var is None:
        env_var = f"TACACS_{section.upper()}_{key.upper()}"
    
    value = os.environ.get(env_var)
    if value is not None:
        if not config.has_section(section):
            config.add_section(section)
        config.set(section, key, value)


def apply_env_overrides_section(
    config: configparser.ConfigParser,
    section: str,
    keys: list[str] | None = None
) -> None:
    """Apply environment variable overrides for all keys in a section.
    
    Args:
        config: ConfigParser instance
        section: Section name
        keys: Optional list of keys to check. If None, checks all existing keys.
    """
    if keys is None:
        if config.has_section(section):
            keys = list(dict(config.items(section)).keys())
        else:
            keys = []
    
    for key in keys:
        apply_env_overrides(config, section, key)


def apply_all_env_overrides(config: configparser.ConfigParser) -> None:
    """Apply all environment variable overrides following standard naming.
    
    Environment variables should follow pattern: TACACS_SECTION_KEY
    Examples:
        - TACACS_SERVER_HOST
        - TACACS_SERVER_PORT
        - ADMIN_USERNAME (special case, no TACACS_ prefix)
        
    Secrets (like ADMIN_PASSWORD_HASH) are loaded only from environment.
    
    FIXED: Admin username now allows file → environment precedence.
    """
    # Standard sections and their keys
    sections_keys = {
        "server": [
            "host", "port", "log_level", "max_connections", "socket_timeout",
            "listen_backlog", "client_timeout", "max_packet_length",
            "ipv6_enabled", "tcp_keepalive", "tcp_keepidle", "tcp_keepintvl",
            "tcp_keepcnt", "thread_pool_max", "use_thread_pool"
        ],
        "auth": [
            "backends", "local_auth_db", "require_all_backends",
            "local_auth_cache_ttl_seconds", "backend_timeout"
        ],
        "ldap": [
            "server", "base_dn", "user_attribute", "bind_dn",
            "use_tls", "timeout"
        ],
        "database": [
            "accounting_db", "cleanup_days", "auto_cleanup",
            "metrics_history_db", "audit_trail_db",
            "metrics_retention_days", "audit_retention_days", "db_pool_size"
        ],
        "security": [
            "max_auth_attempts", "auth_timeout", "encryption_required",
            "allowed_clients", "denied_clients", "rate_limit_requests",
            "rate_limit_window", "max_connections_per_ip"
        ],
        "logging": [
            "log_file", "log_format", "log_rotation", "max_log_size", "backup_count"
        ],
        "syslog": [
            "enabled", "host", "port", "protocol", "facility", "severity",
            "format", "app_name", "include_hostname"
        ],
        "command_authorization": [
            "default_action", "rules_json", "privilege_check_order"
        ],
        "backup": [
            "enabled", "create_on_startup", "temp_directory",
            "encryption_enabled",
            "default_retention_strategy", "default_retention_days",
            "gfs_keep_daily", "gfs_keep_weekly", "gfs_keep_monthly",
            "gfs_keep_yearly", "compression_level"
        ],
        "devices": [
            "database", "default_group", "identity_cache_ttl_seconds",
            "identity_cache_size"
        ],
        "radius": [
            "enabled", "auth_port", "acct_port", "host",
            "share_backends", "share_accounting",
            "workers", "socket_timeout", "rcvbuf"
        ],
        "monitoring": ["enabled", "web_host", "web_port"],
        "proxy_protocol": ["enabled", "validate_sources", "reject_invalid"],
        "webhooks": [
            "urls", "headers_json", "template_json", "timeout",
            "threshold_count", "threshold_window"
        ],
    }
    
    for section, keys in sections_keys.items():
        apply_env_overrides_section(config, section, keys)
    
    # FIXED: Admin section - username from file → environment, password_hash from environment only
    if not config.has_section("admin"):
        config.add_section("admin")
    
    # Username: normal precedence (file → environment)
    apply_env_overrides(config, "admin", "username", "ADMIN_USERNAME")
    
    # Password hash: environment ONLY (security requirement)
    admin_password_hash = os.environ.get(ENV_ADMIN_PASSWORD_HASH)
    if admin_password_hash:
        config.set("admin", "password_hash", admin_password_hash)
    
    # Session timeout: normal precedence
    apply_env_overrides(config, "admin", "session_timeout_minutes")
    
    # LDAP bind_password: environment ONLY
    ldap_bind_password = os.environ.get(ENV_LDAP_BIND_PASSWORD)
    if ldap_bind_password:
        if not config.has_section("ldap"):
            config.add_section("ldap")
        config.set("ldap", "bind_password", ldap_bind_password)
    
    # Backup encryption_passphrase: environment ONLY
    backup_passphrase = os.environ.get(ENV_BACKUP_ENCRYPTION_PASSPHRASE)
    if backup_passphrase:
        if not config.has_section("backup"):
            config.add_section("backup")
        config.set("backup", "encryption_passphrase", backup_passphrase)
    
    # Okta section: secrets ONLY from environment
    okta_domain = os.environ.get(ENV_OKTA_DOMAIN)
    okta_client_id = os.environ.get(ENV_OKTA_CLIENT_ID)
    okta_private_key = os.environ.get(ENV_OKTA_PRIVATE_KEY)
    okta_api_token = os.environ.get(ENV_OKTA_API_TOKEN)
    
    if any([okta_domain, okta_client_id, okta_private_key, okta_api_token]):
        if not config.has_section("okta"):
            config.add_section("okta")
        if okta_domain:
            config.set("okta", "domain", okta_domain)
        if okta_client_id:
            config.set("okta", "client_id", okta_client_id)
        if okta_private_key:
            config.set("okta", "private_key", okta_private_key)
        if okta_api_token:
            config.set("okta", "api_token", okta_api_token)


def load_config(
    source: str,
    defaults: configparser.ConfigParser | None = None
) -> configparser.ConfigParser:
    """Load configuration with unified precedence.
    
    Load order:
    1. Start with defaults
    2. Load from file/URL if exists
    3. Apply environment variable overrides
    
    Args:
        source: Configuration file path or URL
        defaults: Optional ConfigParser with default values
        
    Returns:
        Loaded ConfigParser instance
    """
    config = configparser.ConfigParser(interpolation=None)
    
    # Step 1: Apply defaults
    if defaults:
        for section in defaults.sections():
            if not config.has_section(section):
                config.add_section(section)
            for key, value in defaults.items(section):
                config.set(section, key, value)
    
    # Step 2: Load from file/URL
    if is_url(source):
        cache_path = os.path.join("data", "config_baseline_cache.conf")
        content = load_from_url(source, cache_path)
        if content:
            config.read_string(content)
    else:
        if os.path.exists(source):
            config.read(source)
    
    # Step 3: Apply environment overrides
    apply_all_env_overrides(config)
    
    return config


def reload_config(
    config: configparser.ConfigParser,
    source: str,
    force: bool = False
) -> bool:
    """Reload configuration from source.
    
    Args:
        config: Existing ConfigParser to update
        source: Configuration file path or URL
        force: Force reload even if not time-based check
        
    Returns:
        True if config was reloaded, False otherwise
    """
    # For URL sources, check if content changed
    if is_url(source):
        cache_path = os.path.join("data", "config_baseline_cache.conf")
        new_content = load_from_url(source, cache_path)
        if not new_content:
            return False
            
        # Create temp config to compare
        temp = configparser.ConfigParser(interpolation=None)
        temp.read_string(new_content)
        
        # Compare with current
        if not force:
            # Simple comparison - check if sections/keys differ
            if set(temp.sections()) != set(config.sections()):
                pass  # Different, will reload
            else:
                same = True
                for section in temp.sections():
                    if dict(temp.items(section)) != dict(config.items(section)):
                        same = False
                        break
                if same:
                    return False
        
        # Reload
        config.clear()
        config.read_string(new_content)
    else:
        # For file sources, just reload
        if os.path.exists(source):
            config.clear()
            config.read(source)
        else:
            return False
    
    # Reapply environment overrides
    apply_all_env_overrides(config)
    return True
