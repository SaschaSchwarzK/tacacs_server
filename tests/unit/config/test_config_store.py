from pathlib import Path

import pytest
from sqlalchemy import inspect

from tacacs_server.config.config_store import ConfigStore


def test_config_store_schema_creation(tmp_path: Path):
    db = tmp_path / "config_store.db"
    store = ConfigStore(f"sqlite:///{db}")
    try:
        # Verify tables were created
        inspector = inspect(store.engine)
        assert "config_overrides" in inspector.get_table_names()
        assert "config_history" in inspector.get_table_names()
        assert "config_versions" in inspector.get_table_names()
        assert "system_metadata" in inspector.get_table_names()
        
        # Verify indexes
        indexes = inspector.get_indexes("config_overrides")
        assert any(idx['name'] == 'ux_config_overrides_active' for idx in indexes)
    finally:
        store.close()


@pytest.fixture
def config_store(tmp_path: Path) -> ConfigStore:
    """Fixture that provides a clean ConfigStore for each test."""
    db_path = tmp_path / "test_config.db"
    store = ConfigStore(f"sqlite:///{db_path}")
    yield store
    store.close()

def test_overrides_basic_operations(config_store: ConfigStore):
    # Test setting and getting an override
    config_store.set_override(
        section="server", key="port", value=8080, value_type="integer", changed_by="tester"
    )
    ov = config_store.get_override("server", "port")
    assert ov is not None
    assert ov[0] == 8080
    assert ov[1] == "integer"
    
    # Test that second set replaces the active override
    config_store.set_override(
        section="server", key="port", value=9090, value_type="integer", changed_by="tester"
    )
    ov2 = config_store.get_override("server", "port")
    assert ov2 is not None and ov2[0] == 9090
    
    # Test delete (soft)
    config_store.delete_override("server", "port", changed_by="tester")
    assert config_store.get_override("server", "port") is None
    
    # Test type conversion for list
    config_store.set_override(
        section="auth", key="backends", value=["local", "ldap"], value_type="list", changed_by="tester"
    )
    ov3 = config_store.get_override("auth", "backends")
    assert ov3 is not None and isinstance(ov3[0], list)


def test_history_and_versions(config_store: ConfigStore):
    # Set initial version
    v1 = {"server": {"port": 8080, "host": "0.0.0.0"}}
    config_store.save_version(v1, "tester", "initial config")
    
    # Set override
    config_store.set_override("server", "port", 9090, "integer", "tester")
    
    # Get active config (merged)
    config = config_store.get_active_config()
    assert config["server"]["port"] == 9090
    assert config["server"]["host"] == "0.0.0.0"
    
    # List versions
    versions = config_store.list_versions()
    assert len(versions) == 1
    assert versions[0]["description"] == "initial config"
    
    # List history
    history = config_store.get_history()
    assert len(history) >= 2  # version save + override
    
    # Restore version
    config_store.restore_version(versions[0]["version"], "tester", "rollback")
    assert config_store.get_override("server", "port") is None


def test_history_pagination_and_filters(config_store: ConfigStore):
    # Populate with test data
    for i in range(15):
        config_store.set_override(
            section=f"test{i}",
            key="key",
            value=i,
            value_type="integer",
            changed_by="tester"
        )
    
    # Test pagination
    page1 = config_store.get_history(limit=5)
    page2 = config_store.get_history(limit=5, offset=5)
    assert len(page1) == 5
    assert len(page2) == 5
    assert page1[0]["new_value"] != page2[0]["new_value"]
    
    # Test filtering
    filtered = config_store.get_history(section="test1")
    assert len(filtered) >= 1
    assert filtered[0]["section"] == "test1"


def test_env_precedence_over_override(config_store: ConfigStore, monkeypatch: pytest.MonkeyPatch):
    # Set override
    config_store.set_override("server", "debug", False, "boolean", "tester")
    
    # Set env var with higher precedence
    monkeypatch.setenv("TACACS_SERVER_DEBUG", "true")
    
    # Env var should take precedence
    config = config_store.get_active_config()
    assert config["server"]["debug"] is True
    
    # But override is still there
    ov = config_store.get_override("server", "debug")
    assert ov is not None and ov[0] is False


def test_merge_overrides_with_config(config_store: ConfigStore, monkeypatch: pytest.MonkeyPatch):
    # Base config
    base = {
        "server": {
            "port": 8080,
            "host": "0.0.0.0",
            "debug": False,
            "timeout": 30,
        },
        "auth": {
            "backends": ["local"],
            "allow_anonymous": False,
        },
    }
    
    # Set some overrides
    config_store.set_override("server", "port", 9090, "integer", "tester")
    config_store.set_override("auth", "backends", ["ldap"], "list", "tester")
    
    # Get active config which applies overrides
    merged = config_store.get_active_config()
    assert merged["server"]["port"] == 9090
    assert merged["auth"]["backends"] == ["ldap"]
    assert merged["server"]["host"] == "0.0.0.0"
    
    # Test with environment variable override
    monkeypatch.setenv("TACACS_SERVER_DEBUG", "true")
    merged_with_env = config_store.get_active_config()
    assert merged_with_env["server"]["debug"] is True
