"""Unified configuration loading mechanism.

Load order: config file → environment variables → defaults
Exception: Secrets (like passwords, API tokens) only from environment variables.

FIXED: Admin section now allows username from file, password_hash from environment only.
"""

import configparser
import os
from urllib.parse import urlparse
from urllib.request import urlopen

from tacacs_server.utils.logger import get_logger

from .constants import (
    ENV_ADMIN_PASSWORD_HASH,
    ENV_BACKUP_ENCRYPTION_PASSPHRASE,
    ENV_LDAP_BIND_PASSWORD,
    ENV_OKTA_CLIENT_ID,
    ENV_OKTA_DOMAIN,
    ENV_OKTA_PRIVATE_KEY,
    ENV_OPENID_CLIENT_PRIVATE_KEY,
    ENV_OPENID_CLIENT_SECRET,
    ENV_RADIUS_AUTH_SECRET,
    ENV_TACACS_SOURCE_URL,
)

logger = get_logger(__name__)


def is_url(source: str) -> bool:
    """Check if source is a URL."""
    parsed = urlparse(source)
    return parsed.scheme in {"http", "https", "file"}


def load_from_url(source: str, cache_path: str | None = None) -> str | None:
    """Load configuration from URL with optional caching."""
    logger.debug(
        "Attempting to load configuration from URL source",
        event="tacacs.config.loader.url_attempt",
        service="tacacs",
        source=source,
    )
    try:
        max_size = 1024 * 1024  # 1MB limit
        with urlopen(source, timeout=10) as response:
            if response.length and response.length > max_size:
                logger.warning(
                    "Configuration from URL source exceeds max allowed size; skipping load",
                    event="tacacs.config.loader.url_oversize",
                    service="tacacs",
                    source=source,
                    size=response.length,
                    max_size=max_size,
                )
                return None
            content: str = response.read().decode("utf-8")

        # Cache if path provided
        if cache_path and content:
            try:
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception as cache_wr_exc:
                logger.debug(
                    "ConfigStore cache write failed for configuration URL source",
                    event="tacacs.config.loader.cache_write_failed",
                    service="tacacs",
                    error=str(cache_wr_exc),
                )

        return content
    except Exception as exc:
        logger.warning(
            "Failed to load configuration from URL source, will try cache fallback",
            event="tacacs.config.loader.url_load_failed",
            service="tacacs",
            source=source,
            error=str(exc),
        )
        # Try cache fallback if available
        if cache_path and os.path.exists(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as f:
                    return f.read()
            except Exception as cache_rd_exc:
                logger.debug(
                    "ConfigStore cache read failed for configuration URL source: %s",
                    cache_rd_exc,
                )
        return None


def apply_env_overrides(
    config: configparser.ConfigParser,
    section: str,
    key: str,
    env_var: str | None = None,
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
        # only overwrite if the key is not already set in the config file
        if not config.has_option(section, key):
            config.set(section, key, value)
            logger.debug(
                "Applied environment override for config key",
                event="tacacs.config.loader.env_override_applied",
                service="tacacs",
                section=section,
                key=key,
                env_var=env_var,
            )
        else:
            logger.debug(
                "Skipping environment override because config already defines the value",
                event="tacacs.config.loader.env_override_skipped",
                service="tacacs",
                section=section,
                key=key,
            )


def apply_env_override_default(
    config: configparser.ConfigParser, key: str, env_var: str
) -> None:
    """Apply environment override to the DEFAULT section."""
    value = os.environ.get(env_var)
    if value is not None:
        if key not in config.defaults():
            config[config.default_section][key] = value
            logger.debug(
                "Applied environment override for default key",
                event="tacacs.config.loader.env_override_applied",
                service="tacacs",
                section="DEFAULT",
                key=key,
                env_var=env_var,
            )


def apply_env_overrides_section(
    config: configparser.ConfigParser, section: str, keys: list[str] | None = None
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
            "host",
            "port",
            "log_level",
            "max_connections",
            "socket_timeout",
            "listen_backlog",
            "client_timeout",
            "max_packet_length",
            "ipv6_enabled",
            "tcp_keepalive",
            "tcp_keepidle",
            "tcp_keepintvl",
            "tcp_keepcnt",
            "thread_pool_max",
            "use_thread_pool",
            "instance_name",
        ],
        "auth": [
            "backends",
            "local_auth_db",
            "require_all_backends",
            "local_auth_cache_ttl_seconds",
            "backend_timeout",
        ],
        "ldap": [
            "server",
            "base_dn",
            "user_attribute",
            "bind_dn",
            "use_tls",
            "timeout",
        ],
        "database": [
            "accounting_db",
            "cleanup_days",
            "auto_cleanup",
            "metrics_history_db",
            "audit_trail_db",
            "metrics_retention_days",
            "audit_retention_days",
            "db_pool_size",
        ],
        "security": [
            "max_auth_attempts",
            "auth_timeout",
            "encryption_required",
            "allowed_clients",
            "denied_clients",
            "rate_limit_requests",
            "rate_limit_window",
            "max_connections_per_ip",
        ],
        "logging": [
            "log_file",
            "log_format",
            "log_rotation",
            "max_log_size",
            "backup_count",
        ],
        "syslog": [
            "enabled",
            "host",
            "port",
            "protocol",
            "facility",
            "severity",
            "format",
            "app_name",
            "include_hostname",
        ],
        "command_authorization": [
            "default_action",
            "rules_json",
            "privilege_check_order",
        ],
        "backup": [
            "enabled",
            "create_on_startup",
            "temp_directory",
            "encryption_enabled",
            "default_retention_strategy",
            "default_retention_days",
            "gfs_keep_daily",
            "gfs_keep_weekly",
            "gfs_keep_monthly",
            "gfs_keep_yearly",
            "compression_level",
        ],
        "devices": [
            "database",
            "default_group",
            "identity_cache_ttl_seconds",
            "identity_cache_size",
        ],
        "radius": [
            "enabled",
            "auth_port",
            "acct_port",
            "host",
            "share_backends",
            "share_accounting",
            "workers",
            "socket_timeout",
            "rcvbuf",
        ],
        "monitoring": ["enabled", "web_host", "web_port"],
        "proxy_protocol": ["enabled", "validate_sources", "reject_invalid"],
        "webhooks": [
            "urls",
            "headers_json",
            "template_json",
            "timeout",
            "threshold_count",
            "threshold_window",
        ],
        "radius_auth": [
            "radius_server",
            "radius_port",
            # note: radius_secret handled via ENV_RADIUS_AUTH_SECRET only
            "radius_timeout",
            "radius_retries",
            "radius_nas_ip",
            "radius_nas_identifier",
        ],
        "okta": [
            "org_url",
            "verify_tls",
            "timeout",
            "default_okta_group",
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
    if any([okta_domain, okta_client_id, okta_private_key]):
        if not config.has_section("okta"):
            config.add_section("okta")
        if okta_domain:
            # Maintain compatibility with legacy 'domain' and schema 'org_url'
            if not config.has_option("okta", "org_url"):
                config.set("okta", "org_url", okta_domain)
            if not config.has_option("okta", "domain"):
                config.set("okta", "domain", okta_domain)
        if okta_client_id and not config.has_option("okta", "client_id"):
            config.set("okta", "client_id", okta_client_id)
        if okta_private_key and not config.has_option("okta", "private_key"):
            config.set("okta", "private_key", okta_private_key)

    # OpenID section: non-secret fields can come from config or env; secrets env-only
    openid_env_map = {
        "issuer_url": os.environ.get("OPENID_ISSUER_URL"),
        "client_id": os.environ.get("OPENID_CLIENT_ID"),
        "redirect_uri": os.environ.get("OPENID_REDIRECT_URI"),
        "scopes": os.environ.get("OPENID_SCOPES"),
        "session_timeout_minutes": os.environ.get("OPENID_SESSION_TIMEOUT_MINUTES"),
        "client_auth_method": os.environ.get("OPENID_CLIENT_AUTH_METHOD"),
        "use_interaction_code": os.environ.get("OPENID_USE_INTERACTION_CODE"),
        "code_verifier": os.environ.get("OPENID_CODE_VERIFIER"),
        "allowed_groups": os.environ.get("OPENID_ADMIN_GROUPS"),
        "token_endpoint": os.environ.get("OPENID_TOKEN_ENDPOINT"),
        "userinfo_endpoint": os.environ.get("OPENID_USERINFO_ENDPOINT"),
        "client_private_key_id": os.environ.get("OPENID_CLIENT_PRIVATE_KEY_ID"),
    }
    if any(val for val in openid_env_map.values()):
        if not config.has_section("openid"):
            config.add_section("openid")
        for key, val in openid_env_map.items():
            if val and not config.has_option("openid", key):
                config.set("openid", key, val)

    openid_client_secret = os.environ.get(ENV_OPENID_CLIENT_SECRET)
    openid_client_private_key = os.environ.get(ENV_OPENID_CLIENT_PRIVATE_KEY)
    if openid_client_secret or openid_client_private_key:
        if not config.has_section("openid"):
            config.add_section("openid")
        if openid_client_secret:
            config.set("openid", "client_secret", openid_client_secret)
        if openid_client_private_key:
            config.set("openid", "client_private_key", openid_client_private_key)

    # RADIUS auth backend secret: environment ONLY
    radius_auth_secret = os.environ.get(ENV_RADIUS_AUTH_SECRET)
    if radius_auth_secret:
        if not config.has_section("radius_auth"):
            config.add_section("radius_auth")
        config.set("radius_auth", "radius_secret", radius_auth_secret)

    # Root-level source_url override
    apply_env_override_default(config, "source_url", ENV_TACACS_SOURCE_URL)


def load_config(
    source: str, defaults: configparser.ConfigParser | None = None, url_handler=None
) -> configparser.ConfigParser:
    """Load configuration with unified precedence.

    Load order (per requirement):
    1. Load from file/URL if exists
    2. Apply environment variable overrides (only when the value is missing)
    3. Apply defaults for anything still unset

    Args:
        source: Configuration file path or URL
        defaults: Optional ConfigParser with default values
        url_handler: Optional URLConfigHandler instance for URL sources

    Returns:
        Loaded ConfigParser instance
    """
    config = configparser.ConfigParser(interpolation=None)

    # Step 1: Load from file/URL
    if is_url(source):
        logger.info(
            "Loading configuration from URL source",
            event="tacacs.config.loader.url_load",
            service="tacacs",
            source=source,
        )
        if url_handler:
            # Use URLConfigHandler for proper caching and security
            content = url_handler.load_from_url(source, use_cache_fallback=True)
        else:
            # Fallback to direct loading
            cache_path = os.path.join("data", "config_baseline_cache.conf")
            content = load_from_url(source, cache_path)
        if content:
            config.read_string(content)
    else:
        if os.path.exists(source):
            logger.info(
                "Loading configuration from file source",
                event="tacacs.config.loader.file_load",
                service="tacacs",
                source=source,
            )
            config.read(source)
        else:
            logger.warning(
                "Configuration file source does not exist; using defaults and overrides",
                event="tacacs.config.loader.missing_file",
                service="tacacs",
                source=source,
            )

    # Step 2: Apply environment overrides (only fill missing keys)
    apply_all_env_overrides(config)

    # Step 3: Apply defaults for anything still unset
    if defaults:
        for section in defaults.sections():
            if not config.has_section(section):
                config.add_section(section)
            for key, value in defaults.items(section):
                if not config.has_option(section, key):
                    config.set(section, key, value)

    return config


def reload_config(
    config: configparser.ConfigParser, source: str, force: bool = False
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
        logger.debug(
            "Checking for configuration changes from URL source",
            event="tacacs.config.loader.check_changes",
            service="tacacs",
            source=source,
        )
        cache_path = os.path.join("data", "config_baseline_cache.conf")
        new_content = load_from_url(source, cache_path)
        if not new_content:
            logger.debug(
                "No configuration content fetched from URL source; skipping reload",
                event="tacacs.config.loader.no_content",
                service="tacacs",
                source=source,
            )
            return False

        # Create temp config to compare
        temp = configparser.ConfigParser(interpolation=None)
        temp.read_string(new_content)

        # Compare with current
        if not force:
            # Simple comparison - check if sections/keys differ
            if set(temp.sections()) != set(config.sections()):
                logger.debug(
                    "ConfigStore: Different sections, will reload",
                    event="tacacs.config.loader.sections_changed",
                    service="tacacs",
                    source=source,
                )
            else:
                same = True
                for section in temp.sections():
                    if dict(temp.items(section)) != dict(config.items(section)):
                        same = False
                        break
                if same:
                    logger.debug(
                        "Configuration from URL source unchanged; skipping reload",
                        event="tacacs.config.loader.unchanged",
                        service="tacacs",
                        source=source,
                    )
                    return False

        # Reload
        config.clear()
        config.read_string(new_content)
        logger.info(
            "Configuration reloaded from URL source",
            event="tacacs.config.loader.url_reloaded",
            service="tacacs",
            source=source,
        )
    else:
        # For file sources, just reload
        if os.path.exists(source):
            config.clear()
            config.read(source)
            logger.info(
                "Configuration reloaded from file source",
                event="tacacs.config.loader.file_reloaded",
                service="tacacs",
                source=source,
            )
        else:
            logger.warning(
                "Configuration file source not found; reload skipped",
                event="tacacs.config.loader.reload_missing_file",
                service="tacacs",
                source=source,
            )
            return False

    # Reapply environment overrides
    apply_all_env_overrides(config)
    return True
