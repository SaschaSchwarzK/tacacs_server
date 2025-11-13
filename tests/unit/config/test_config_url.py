import os
from pathlib import Path

import pytest

from tacacs_server.config.config import TacacsConfig


@pytest.fixture
def isolated_config_store(monkeypatch, tmp_path):
    """Ensure each test uses an isolated config store database."""
    from tacacs_server.config import config_store

    test_db_dir = tmp_path / "test_config_data"
    test_db_dir.mkdir()
    test_db = test_db_dir / "config_overrides.db"

    original_init = config_store.ConfigStore.__init__

    def mock_init(self, db_path="data/config_overrides.db"):
        # Always use test-specific database
        return original_init(self, str(test_db))

    monkeypatch.setattr(config_store.ConfigStore, "__init__", mock_init)

    return test_db


def test_url_fetch_and_cache(
    isolated_config_store, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """Test URL configuration fetch and caching functionality."""
    payload = (
        "[server]\n"
        "host=0.0.0.0\n"
        "port=49\n"
        "log_level=INFO\n\n"
        "[auth]\n"
        "backends=local\n"
        "local_auth_db=data/local_auth.db\n\n"
        "[security]\n"
        "max_auth_attempts=3\n"
        "auth_timeout=300\n"
        "encryption_required=true\n"
    )

    # Mock URLConfigHandler methods before creating TacacsConfig
    from tacacs_server.config import url_handler

    def mock_load_from_url(self, source, use_cache_fallback=True):
        """Mock that writes to cache and returns content."""
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                f.write(payload)
        except Exception:
            pass
        return payload

    monkeypatch.setattr(
        url_handler.URLConfigHandler, "is_url_safe", lambda self, s: True
    )
    monkeypatch.setattr(
        url_handler.URLConfigHandler, "load_from_url", mock_load_from_url
    )

    monkeypatch.setenv("CONFIG_REFRESH_SECONDS", "1")
    cfg = TacacsConfig("https://example.com/config")

    # Verify cache was created
    assert os.path.exists(cfg.url_handler.cache_path), (
        f"Cache file not found at {cfg.url_handler.cache_path}"
    )

    # Verify content is correct
    assert cfg.config.getint("server", "port") == 49


def test_fallback_to_cache_on_failure(
    isolated_config_store, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """Test fallback to cached configuration when URL fetch fails."""

    # Create cache file
    cache_dir = tmp_path / "data"
    cache_dir.mkdir()
    cache = cache_dir / "config_baseline_cache.conf"
    cache.write_text("[server]\nhost=127.0.0.1\nport=49\n\n", encoding="utf-8")

    from tacacs_server.config import url_handler

    def mock_load_from_url(self, source, use_cache_fallback=True):
        """Mock that returns None but falls back to cache."""
        if use_cache_fallback and os.path.exists(self.cache_path):
            with open(self.cache_path, encoding="utf-8") as f:
                return f.read()
        return None

    # Override cache path and load behavior
    original_init = url_handler.URLConfigHandler.__init__

    def mock_init(self, cache_path=None, refresh_interval=300):
        self.cache_path = str(cache)
        self.refresh_interval = refresh_interval
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        except Exception:
            pass

    monkeypatch.setattr(url_handler.URLConfigHandler, "__init__", mock_init)
    monkeypatch.setattr(
        url_handler.URLConfigHandler, "is_url_safe", lambda self, s: True
    )
    monkeypatch.setattr(
        url_handler.URLConfigHandler, "load_from_url", mock_load_from_url
    )

    cfg = TacacsConfig("https://example.com/config")

    # Verify configuration was loaded from cache
    assert cfg.config.getint("server", "port") == 49


def test_refresh_logic_time_based(
    isolated_config_store, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """Test time-based configuration refresh logic."""
    base = (
        "[server]\n"
        "host=0.0.0.0\n"
        "port=49\n"
        "log_level=INFO\n\n"
        "[auth]\n"
        "backends=local\n"
        "local_auth_db=data/local_auth.db\n\n"
        "[security]\n"
        "max_auth_attempts=3\n"
        "auth_timeout=300\n"
        "encryption_required=true\n"
    )
    updated = base.replace("port=49", "port=50")

    from tacacs_server.config import url_handler

    # Track which content to return
    content_to_return = {"value": base}

    def mock_load_from_url(self, source, use_cache_fallback=True):
        """Mock that returns different content based on state."""
        content = content_to_return["value"]
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            pass
        return content

    def mock_fetch(self, source):
        """Mock fetch_url for refresh."""
        return content_to_return["value"]

    monkeypatch.setattr(
        url_handler.URLConfigHandler, "is_url_safe", lambda self, s: True
    )
    monkeypatch.setattr(
        url_handler.URLConfigHandler, "load_from_url", mock_load_from_url
    )
    monkeypatch.setattr(url_handler.URLConfigHandler, "fetch_url", mock_fetch)

    # Set very short refresh interval
    monkeypatch.setenv("CONFIG_REFRESH_SECONDS", "0")

    cfg = TacacsConfig("https://example.com/config")

    # Verify initial port value
    assert cfg.config.getint("server", "port") == 49

    # Change the content to return
    content_to_return["value"] = updated

    # Force refresh
    changed = cfg.refresh_url_config(force=True)

    # Verify refresh occurred and config was updated
    assert changed is True
    assert cfg.config.getint("server", "port") == 50

    # Verify version snapshot was created after refresh
    if cfg.config_store:
        vers = cfg.config_store.list_versions()
        assert vers, "Version snapshot expected after refresh"
