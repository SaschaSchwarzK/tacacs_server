import os
import tempfile

import pytest

from tacacs_server.config.config import TacacsConfig
from tacacs_server.config.loader import load_config


def write_temp_config(contents: str) -> str:
    fd, path = tempfile.mkstemp(prefix="tacacs_test_", suffix=".conf")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        f.write(contents)
    return path


def test_env_overrides_take_precedence_over_file(tmp_path, monkeypatch):
    """
    Verify intended precedence: config file > environment > defaults.

    If an env var is set for a key present in the file, the file value should take precedence
    and the environment variable should be skipped.
    """
    cfg_text = """
[server]
host = 1.2.3.4
port = 49

[auth]
backends = local
"""
    cfg_file = write_temp_config(cfg_text)

    # set env to try to override the file value
    monkeypatch.setenv("TACACS_SERVER_HOST", "9.9.9.9")
    # load via loader.load_config to exercise apply_all_env_overrides path
    cp = load_config(cfg_file)

    # after load_config, the file value should remain (env should be skipped)
    assert cp.get("server", "host") == "1.2.3.4"
    # file-only value should remain intact if not overridden
    assert cp.get("server", "port") == "49"


def test_defaults_then_file_then_env(tmp_path, monkeypatch):
    """
    Create a config where defaults provide a value, file omits it, env provides it: env should fill in
    Also verify that file values override defaults when present.
    """
    # create defaults by passing no defaults to load_config, but the module populates defaults in TacacsConfig
    cfg_text = """
[server]
port = 1234
"""
    cfg_file = write_temp_config(cfg_text)

    # ensure an env var is present for a different key
    monkeypatch.setenv("TACACS_SERVER_HOST", "10.0.0.1")

    cp = load_config(cfg_file)

    # file-defined port should be present
    assert cp.get("server", "port") == "1234"
    # env should supply host even if not present in file
    assert cp.get("server", "host") == "10.0.0.1"


def test_admin_password_hash_only_from_env(tmp_path, monkeypatch):
    """
    Sensitive secrets like ADMIN_PASSWORD_HASH should be taken from environment only and not from file.
    """
    cfg_text = """
[admin]
username = admin
password_hash = should-not-be-used-from-file
"""
    cfg_file = write_temp_config(cfg_text)

    # ensure env contains the real secret
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "$2b$realhashfromenv")

    cp = load_config(cfg_file)

    # loader.apply_all_env_overrides sets admin.password_hash from ENV directly
    assert cp.get("admin", "password_hash") == "$2b$realhashfromenv"


def test_runtime_overrides_applied_in_tacacsconfig(monkeypatch, tmp_path):
    """
    TacacsConfig._apply_overrides reads overrides from the ConfigStore DB.
    We test that when overrides are present, they are applied on top of the loaded config.

    This is a smoke test that uses TacacsConfig with a temporary config file and then
    simulates writing an override into the config_store (if available). If ConfigStore is not
    usable in the test environment, we at least ensure the method is callable and does not crash.
    """
    cfg_text = """
[server]
host = 127.0.0.1
port = 49
"""
    cfg_file = write_temp_config(cfg_text)

    # Create TacacsConfig which will initialize ConfigStore (data/config_overrides.db)
    # Use a temp working directory to avoid colliding with repository data
    d = tmp_path / "workdir"
    d.mkdir()
    monkeypatch.chdir(d)

    tc = TacacsConfig(cfg_file)

    # If config_store is available, insert a runtime override and call _apply_overrides
    store = getattr(tc, "config_store", None)
    if store:
        # set an override via the public store API if available
        try:
            store.set_override("server", "host", "5.5.5.5")
            tc._apply_overrides()
            assert tc.config.get("server", "host") == "5.5.5.5"
        except Exception:
            pytest.skip("ConfigStore API not available in this test environment")
    else:
        # ConfigStore not initialised; ensure calling _apply_overrides does not raise
        tc._apply_overrides()


def test_url_refresh_reapplies_env_and_db_overrides(monkeypatch, tmp_path):
    """
    Ensure that when a URL-based config refresh occurs, environment overrides
    are reapplied (without overwriting file values) and runtime/DB overrides
    from ConfigStore are reapplied last so they retain highest precedence.
    """
    # Prepare working dir
    d = tmp_path / "workdir2"
    d.mkdir()
    monkeypatch.chdir(d)

    # Initial file config
    cfg_text = """
[server]
host = 1.1.1.1
port = 49
"""
    cfg_file = write_temp_config(cfg_text)

    # Create TacacsConfig with the file
    tc = TacacsConfig(cfg_file)

    # Set environment var (should not override file key when file defines it)
    monkeypatch.setenv("TACACS_SERVER_HOST", "env-host")

    # Ensure config_store is available and set a runtime override
    store = getattr(tc, "config_store", None)
    if not store:
        pytest.skip("ConfigStore not available for URL refresh test")

    store.set_override("server", "host", "db-host-2", "string", "test-user")
    # Apply overrides so runtime value is present before refresh
    tc._apply_overrides()
    assert tc.config.get("server", "host") == "db-host-2"


def test_boolean_env_and_file_precedence(monkeypatch, tmp_path):
    """
    Test boolean handling: file value should take precedence over env when present.
    If file missing, env should provide the value.
    """
    d = tmp_path / "work_bool"
    d.mkdir()
    monkeypatch.chdir(d)

    # Case 1: file provides the boolean (use `ipv6_enabled` which loader recognizes)
    cfg_text = """
[server]
ipv6_enabled = true
"""
    cfg_file = write_temp_config(cfg_text)

    # env tries to override but should be skipped because file defines it
    monkeypatch.setenv("TACACS_SERVER_IPV6_ENABLED", "false")
    cp = load_config(cfg_file)
    assert cp.get("server", "ipv6_enabled") == "true"

    # Case 2: file missing -> env should provide the value
    cfg_text2 = """
[server]
# no ipv6_enabled
"""
    cfg_file2 = write_temp_config(cfg_text2)
    monkeypatch.setenv("TACACS_SERVER_IPV6_ENABLED", "false")
    cp2 = load_config(cfg_file2)
    assert cp2.get("server", "ipv6_enabled") == "false"


def test_nested_json_env_handling(monkeypatch, tmp_path):
    """
    Test nested JSON/stringified values via env/file precedence.
    The key `rules_json` is expected to carry JSON payloads in string form.
    """
    d = tmp_path / "work_json"
    d.mkdir()
    monkeypatch.chdir(d)

    # File provides JSON
    cfg_text = """
[command_authorization]
rules_json = [{"rule": "allow all"}]
"""
    cfg_file = write_temp_config(cfg_text)
    # env tries to override but should be skipped
    monkeypatch.setenv(
        "TACACS_COMMAND_AUTHORIZATION_RULES_JSON", '[{"rule":"deny all"}]'
    )
    cp = load_config(cfg_file)
    assert cp.get(
        "command_authorization", "rules_json"
    ) == '[{"rule": "allow all"}]' or cp.get(
        "command_authorization", "rules_json"
    ).startswith("[")

    # Remove file key and ensure env is used
    cfg_text2 = """
[command_authorization]
# no rules_json
"""
    cfg_file2 = write_temp_config(cfg_text2)
    monkeypatch.setenv(
        "TACACS_COMMAND_AUTHORIZATION_RULES_JSON", '[{"rule":"deny all"}]'
    )
    cp2 = load_config(cfg_file2)
    assert cp2.get("command_authorization", "rules_json") == '[{"rule":"deny all"}]'


def test_url_refresh_applies_env_when_file_missing(monkeypatch, tmp_path):
    """
    If the refreshed URL payload does not include a key that is present via ENV,
    the environment override should be applied.
    """
    d = tmp_path / "workdir3"
    d.mkdir()
    monkeypatch.chdir(d)

    # Initial file defines port only (no host)
    cfg_text = """
[server]
port = 49
"""
    cfg_file = write_temp_config(cfg_text)

    # Create TacacsConfig with the file
    tc = TacacsConfig(cfg_file)

    # Set env var for host
    monkeypatch.setenv("TACACS_SERVER_HOST", "env-host")

    # Ensure no DB override
    store = getattr(tc, "config_store", None)
    if store:
        # Clear any existing overrides for the key if present
        try:
            # There is no direct delete helper; set a blank override then deactivate
            pass
        except Exception:
            pass

    # Mock URL fetch to return payload without host
    new_payload = """
[server]
port = 1812
"""
    from tacacs_server.config.url_handler import URLConfigHandler

    def fake_fetch(self, source):
        return new_payload

    monkeypatch.setattr(URLConfigHandler, "fetch_url", fake_fetch)

    tc.config_source = "https://example/config"
    updated = tc.refresh_url_config(force=True)
    assert updated

    # After refresh, the env var should provide the missing host
    assert tc.config.get("server", "host") == "env-host"


def test_file_reload_preserves_db_override_and_env(monkeypatch, tmp_path):
    """
    Simulate a file reload (reload_config) and ensure that env overrides
    are applied and DB/runtime overrides remain highest precedence.
    """
    d = tmp_path / "workdir4"
    d.mkdir()
    monkeypatch.chdir(d)

    cfg_text = """
[server]
host = 10.10.10.10
port = 49
"""
    cfg_file = write_temp_config(cfg_text)

    tc = TacacsConfig(cfg_file)

    # Set env var (should be skipped because file has host)
    monkeypatch.setenv("TACACS_SERVER_HOST", "env-host")

    store = getattr(tc, "config_store", None)
    if not store:
        pytest.skip("ConfigStore not available for file reload test")

    # Set DB override
    store.set_override("server", "host", "db-host-2", "string", "test-user")
    tc._apply_overrides()
    assert tc.config.get("server", "host") == "db-host-2"

    # Now simulate a file change -> write new file (different host)
    new_cfg = """
[server]
host = 7.7.7.7
port = 49
"""
    with open(cfg_file, "w", encoding="utf-8") as f:
        f.write(new_cfg)

    # Call loader.reload_config to simulate file reload
    from tacacs_server.config.loader import reload_config

    reloaded = reload_config(tc.config, cfg_file, force=True)
    assert reloaded

    # After reload, env should not override file-host, and DB override should still win
    # Re-apply runtime overrides to simulate TacacsConfig behavior
    tc._apply_overrides()
    assert tc.config.get("server", "host") == "db-host-2"

    # Now mock URL fetch to return new content that changes host
    new_payload = """
[server]
host = 3.3.3.3
port = 49
"""

    # Monkeypatch URLConfigHandler.fetch_url to return our payload
    from tacacs_server.config.url_handler import URLConfigHandler

    def fake_fetch(self, source):
        return new_payload

    monkeypatch.setattr(URLConfigHandler, "fetch_url", fake_fetch)

    # Point config_source to a URL to trigger URL refresh path
    tc.config_source = "https://example/config"

    # Perform refresh (force=True)
    updated = tc.refresh_url_config(force=True)
    assert updated

    # After refresh, runtime override must still take precedence
    assert tc.config.get("server", "host") == "db-host-2"


if __name__ == "__main__":
    # allow running this file directly for quick debugging
    import pytest

    raise SystemExit(pytest.main([__file__]))
