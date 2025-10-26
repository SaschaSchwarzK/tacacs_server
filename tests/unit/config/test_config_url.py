import os
from pathlib import Path

import pytest

from tacacs_server.config.config import TacacsConfig


def test_url_fetch_and_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
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
    monkeypatch.setenv("CONFIG_REFRESH_SECONDS", "1")
    cfg = TacacsConfig("https://example.com/config")
    monkeypatch.setattr(cfg, "_is_url_safe", lambda s: True)
    monkeypatch.setattr(cfg, "_fetch_url_content", lambda s: payload)
    cfg._load_config()
    assert os.path.exists(cfg._baseline_cache_path)
    if cfg.config_store:
        versions = cfg.config_store.list_versions()
        assert versions, "Expected at least one baseline version snapshot"


def test_fallback_to_cache_on_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    cfg = TacacsConfig("https://example.com/config")
    monkeypatch.setattr(cfg, "_is_url_safe", lambda s: True)
    cache = tmp_path / "config_baseline_cache.conf"
    cache.write_text("[server]\nhost=127.0.0.1\nport=49\n\n", encoding="utf-8")
    cfg._baseline_cache_path = str(cache)
    monkeypatch.setattr(cfg, "_fetch_url_content", lambda s: None)
    cfg._load_from_url("https://example.com/config")
    assert cfg.config.getint("server", "port") == 49


def test_refresh_logic_time_based(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
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
    monkeypatch.setenv("CONFIG_REFRESH_SECONDS", "0")
    cfg = TacacsConfig("https://example.com/config")
    monkeypatch.setattr(cfg, "_is_url_safe", lambda s: True)
    monkeypatch.setattr(cfg, "_fetch_url_content", lambda s: base)
    cfg._load_config()
    monkeypatch.setattr(cfg, "_fetch_url_content", lambda s: updated)
    changed = cfg.refresh_url_config(force=True)
    assert changed is True
    assert cfg.config.getint("server", "port") == 50
    if cfg.config_store:
        vers = cfg.config_store.list_versions()
        assert vers, "Version snapshot expected after refresh"
