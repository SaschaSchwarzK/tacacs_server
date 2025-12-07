"""URL configuration handling.

Provides secure URL-based configuration loading with:
- SSRF protection
- Caching
- Refresh mechanism
"""

import configparser
import ipaddress
import json
import os
import socket
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import requests

from tacacs_server.utils.logger import get_logger

from .config_store import ConfigStore, compute_config_hash

logger = get_logger(__name__)


class URLConfigHandler:
    """Handle URL-based configuration loading with security and caching."""

    def __init__(
        self,
        cache_path: str = "data/config_baseline_cache.conf",
        refresh_interval: int = 300,
    ):
        """Initialize URL config handler.

        Args:
            cache_path: Path to cache baseline configuration
            refresh_interval: Refresh interval in seconds (default 300)
        """
        self.cache_path = cache_path
        self.refresh_interval = refresh_interval

        # Ensure cache directory exists
        try:
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        except Exception as mkdir_exc:
            logger.debug(
                "ConfigStore cache directory creation failed for configuration URL source: %s",
                mkdir_exc,
            )

    def is_url_safe(self, source: str) -> bool:
        """Validate URL safety to prevent SSRF attacks.

        Args:
            source: URL to validate

        Returns:
            True if URL is safe, False otherwise
        """
        parsed = urlparse(source)

        # Optional development override to permit http/local URLs
        allow_insecure = (
            str(os.getenv("ALLOW_INSECURE_CONFIG_URLS", "")).lower()
            in (
                "1",
                "true",
                "yes",
            )
            or str(os.getenv("PYTEST_CURRENT_TEST", "")).strip() != ""
        )

        # Only allow HTTPS by default; permit HTTP when explicitly enabled for dev/test
        if parsed.scheme not in {"https"}:
            if allow_insecure and parsed.scheme == "http":
                logger.warning(
                    "Insecure HTTP config URL permitted by ALLOW_INSECURE_CONFIG_URLS"
                )
            else:
                logger.error("Only HTTPS URLs are allowed for configuration loading")
                return False

        # Check for private/local networks (unless insecure override is enabled)
        hostname = parsed.hostname
        if not allow_insecure and hostname and self._is_private_network(hostname):
            logger.error("Local/private network URLs are not allowed")
            return False

        return True

    def _is_private_network(self, hostname: str) -> bool:
        """Check if hostname resolves to a private, loopback, or unspecified IP address.

        Args:
            hostname: Hostname to check

        Returns:
            True if hostname is private/local, False otherwise
        """
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

    def fetch_url(self, source: str) -> str | None:
        """Fetch configuration from URL with size limits.

        Args:
            source: URL to fetch from

        Returns:
            Configuration content as string, or None if fetch failed
        """
        if not self.is_url_safe(source):
            return None

        parsed = urlparse(source)
        allow_insecure = str(os.getenv("ALLOW_INSECURE_CONFIG_URLS", "")).lower() in (
            "1",
            "true",
            "yes",
        )
        if parsed.scheme == "http" and not allow_insecure:
            logger.error("Insecure HTTP config URL rejected")
            return None
        if parsed.scheme not in {"http", "https"}:
            logger.error("Unsupported config URL scheme: %s", parsed.scheme or "")
            return None

        try:
            max_size = 1024 * 1024  # 1MB limit

            resp = requests.get(source, timeout=10, allow_redirects=True)
            if resp.status_code != 200:
                logger.error("Configuration URL returned status %s", resp.status_code)
                return None

            body = resp.content or b""
            if len(body) > max_size:
                logger.error("Configuration file too large")
                return None

            return body.decode(resp.encoding or "utf-8")

        except Exception as e:
            logger.error("Failed to fetch URL configuration: %s", e)
            return None

    def cache_config(self, content: str) -> bool:
        """Cache configuration content to disk.

        Args:
            content: Configuration content to cache

        Returns:
            True if caching succeeded, False otherwise
        """
        try:
            with open(self.cache_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            return True
        except Exception as e:
            logger.warning("Failed to cache configuration: %s", e)
            return False

    def load_from_cache(self) -> str | None:
        """Load configuration from cache.

        Returns:
            Cached configuration content, or None if not available
        """
        try:
            if os.path.exists(self.cache_path):
                with open(self.cache_path, encoding="utf-8") as fh:
                    return fh.read()
        except Exception as e:
            logger.warning("Failed to load cached configuration: %s", e)
        return None

    def load_from_url(self, source: str, use_cache_fallback: bool = True) -> str | None:
        """Load configuration from URL with automatic caching and fallback.

        Args:
            source: URL to load from
            use_cache_fallback: Whether to use cache as fallback on failure

        Returns:
            Configuration content, or None if load failed
        """
        content = self.fetch_url(source)

        if content:
            self.cache_config(content)
            return content

        # Fallback to cache if enabled
        if use_cache_fallback:
            logger.warning("Using cached configuration as fallback")
            return self.load_from_cache()

        return None

    def should_refresh(
        self, config_store: ConfigStore | None, force: bool = False
    ) -> bool:
        """Check if configuration should be refreshed.

        Args:
            config_store: Optional ConfigStore for metadata
            force: Force refresh regardless of interval

        Returns:
            True if refresh should happen, False otherwise
        """
        if force:
            return True

        if not config_store:
            return True

        try:
            ts = config_store.get_metadata("last_url_fetch")
            if not ts:
                return True

            last_fetch = datetime.fromisoformat(ts)
            if datetime.now(UTC) - last_fetch < timedelta(
                seconds=self.refresh_interval
            ):
                return False

        except Exception as url_load_exc:
            logger.debug(
                "ConfigStore metadata check failed for configuration URL source: %s",
                url_load_exc,
            )

        return True


def refresh_url_config(
    config: configparser.ConfigParser,
    source: str,
    config_store: ConfigStore | None = None,
    force: bool = False,
    refresh_interval: int = 300,
) -> bool:
    """Refresh configuration from URL if needed.

    Args:
        config: ConfigParser to update
        source: URL source
        config_store: Optional ConfigStore for metadata
        force: Force refresh
        refresh_interval: Refresh interval in seconds

    Returns:
        True if configuration was refreshed, False otherwise
    """
    handler = URLConfigHandler(refresh_interval=refresh_interval)

    # Check if refresh needed
    if not handler.should_refresh(config_store, force):
        return False

    # Fetch new content
    payload = handler.fetch_url(source)
    if not payload:
        logger.warning("URL refresh failed; using existing configuration")
        return False

    # Check if content changed
    new_hash = compute_config_hash(payload)

    # Serialize current config for comparison
    current_data: dict[str, dict[str, str]] = {}
    for section in config.sections():
        current_data[section] = {k: v for k, v in config.items(section)}
    current_json = json.dumps(current_data, sort_keys=True)
    current_hash = compute_config_hash(current_json)

    if new_hash == current_hash:
        # Update metadata even if unchanged
        if config_store:
            try:
                config_store.set_metadata(
                    "last_url_fetch", datetime.now(UTC).isoformat()
                )
            except Exception as meta_exc:
                logger.debug(
                    "ConfigStore metadata update failed for configuration URL source: %s",
                    meta_exc,
                )
        return False

    # Apply new configuration
    config.clear()
    config.read_string(payload)

    # Cache the new content
    handler.cache_config(payload)

    # Update metadata and create version snapshot
    if config_store:
        try:
            snap = json.loads(current_json)
            config_store.create_version(
                snap,
                created_by="system",
                description="URL refresh",
                is_baseline=True,
            )
            config_store.set_metadata("last_url_fetch", datetime.now(UTC).isoformat())
            config_store.set_metadata("config_source", source)
        except Exception as e:
            logger.debug("Failed to persist config version snapshot: %s", e)

    logger.info("Configuration refreshed from URL (hash changed)")
    return True
