"""Test that all backend types use process pool correctly."""

from unittest.mock import Mock, patch

from tacacs_server.tacacs.handlers import AAAHandlers


def test_all_backends_use_process_pool():
    """Verify that local, LDAP, Okta, and RADIUS backends all use process pool."""

    # Create mock backends for each type
    local_backend = Mock()
    local_backend.name = "local"
    local_backend.db_path = "sqlite:///:memory:"

    ldap_backend = Mock()
    ldap_backend.name = "ldap"
    ldap_backend.ldap_server = "ldap://test.com"
    ldap_backend.base_dn = "dc=test,dc=com"
    ldap_backend.bind_dn = None
    ldap_backend.bind_password = None
    ldap_backend.user_attribute = "uid"
    ldap_backend.use_tls = False
    ldap_backend.timeout = 10

    okta_backend = Mock()
    okta_backend.name = "okta"
    okta_backend.org_url = "https://test.okta.com"
    okta_backend.client_id = "test_client"
    okta_backend.client_secret = "test_secret"
    okta_backend.private_key = ""
    okta_backend.private_key_id = ""
    okta_backend.auth_method = "client_secret_post"
    okta_backend.verify_tls = True
    okta_backend.require_group_for_auth = False

    radius_backend = Mock()
    radius_backend.name = "radius"
    radius_backend.radius_server = "127.0.0.1"
    radius_backend.radius_port = 1812
    radius_backend.radius_secret = b"test_secret"
    radius_backend.radius_timeout = 5
    radius_backend.radius_retries = 3
    radius_backend.radius_nas_ip = "0.0.0.0"
    radius_backend.radius_nas_identifier = None

    backends = [local_backend, ldap_backend, okta_backend, radius_backend]
    handlers = AAAHandlers(backends, None, backend_process_pool_size=2)

    # Verify all backends can be serialized (required for process pool)
    for backend in backends:
        config = handlers._serialize_backend_config(backend)
        assert config is not None, f"Backend {backend.name} failed to serialize"
        assert config["type"] == backend.name

        # Verify specific config fields for each backend type
        if backend.name == "local":
            assert "database_url" in config
        elif backend.name == "ldap":
            assert "ldap_server" in config
            assert "base_dn" in config
        elif backend.name == "okta":
            assert "org_url" in config
        elif backend.name == "radius":
            assert "radius_server" in config
            assert "radius_secret" in config

    # Verify process pool was created with workers
    assert handlers._process_pool_size == 2
    assert len(handlers._process_workers) == 2
    assert len(handlers._backend_configs) == 4  # All backends serialized

    # Verify all workers are alive
    assert all(worker.is_alive() for worker in handlers._process_workers)


def test_backend_serialization_completeness():
    """Test that serialization captures all required fields for each backend type."""

    # Test local backend serialization
    local_backend = Mock()
    local_backend.name = "local"
    local_backend.db_path = "sqlite:///test.db"

    handlers = AAAHandlers([local_backend], None, backend_process_pool_size=1)
    config = handlers._serialize_backend_config(local_backend)

    expected_local = {"type": "local", "database_url": "sqlite:///test.db"}
    assert config == expected_local

    # Test LDAP backend serialization
    ldap_backend = Mock()
    ldap_backend.name = "ldap"
    ldap_backend.ldap_server = "ldaps://ldap.example.com"
    ldap_backend.base_dn = "ou=users,dc=example,dc=com"
    ldap_backend.bind_dn = "cn=admin,dc=example,dc=com"
    ldap_backend.bind_password = "secret"
    ldap_backend.user_attribute = "sAMAccountName"
    ldap_backend.use_tls = True
    ldap_backend.timeout = 30

    config = handlers._serialize_backend_config(ldap_backend)
    expected_ldap = {
        "type": "ldap",
        "ldap_server": "ldaps://ldap.example.com",
        "base_dn": "ou=users,dc=example,dc=com",
        "bind_dn": "cn=admin,dc=example,dc=com",
        "bind_password": "secret",
        "user_attribute": "sAMAccountName",
        "use_tls": True,
        "timeout": 30,
    }
    assert config == expected_ldap

    # Test Okta backend serialization
    okta_backend = Mock()
    okta_backend.name = "okta"
    okta_backend.org_url = "https://dev-123.okta.com"
    okta_backend.client_id = "client_123"
    okta_backend.client_secret = "secret_123"
    okta_backend.private_key = "-----BEGIN PRIVATE KEY-----"
    okta_backend.private_key_id = "key_123"
    okta_backend.auth_method = "private_key_jwt"
    okta_backend.verify_tls = False
    okta_backend.require_group_for_auth = True

    config = handlers._serialize_backend_config(okta_backend)
    expected_okta = {
        "type": "okta",
        "org_url": "https://dev-123.okta.com",
        "client_id": "client_123",
        "client_secret": "secret_123",
        "private_key": "-----BEGIN PRIVATE KEY-----",
        "private_key_id": "key_123",
        "auth_method": "private_key_jwt",
        "verify_tls": False,
        "require_group_for_auth": True,
    }
    assert config == expected_okta

    # Test RADIUS backend serialization
    radius_backend = Mock()
    radius_backend.name = "radius"
    radius_backend.radius_server = "192.168.1.100"
    radius_backend.radius_port = 1812
    radius_backend.radius_secret = b"shared_secret"
    radius_backend.radius_timeout = 10
    radius_backend.radius_retries = 5
    radius_backend.radius_nas_ip = "10.0.0.1"
    radius_backend.radius_nas_identifier = "tacacs-server-01"

    config = handlers._serialize_backend_config(radius_backend)
    expected_radius = {
        "type": "radius",
        "radius_server": "192.168.1.100",
        "radius_port": 1812,
        "radius_secret": "shared_secret",  # Converted from bytes
        "radius_timeout": 10,
        "radius_retries": 5,
        "radius_nas_ip": "10.0.0.1",
        "radius_nas_identifier": "tacacs-server-01",
    }
    assert config == expected_radius


def test_process_pool_vs_thread_pool_usage():
    """Test that supported backends use process pool, unsupported use thread pool."""

    # Supported backend (local)
    from tacacs_server.auth.local import LocalAuthBackend

    local_backend = LocalAuthBackend("sqlite:///:memory:")

    # Unsupported backend (custom)
    class UnsupportedBackend:
        def __init__(self):
            self.name = "unsupported"

        def authenticate(self, username, password, **kwargs):
            return False

    unsupported_backend = UnsupportedBackend()

    handlers = AAAHandlers(
        [local_backend, unsupported_backend], None, backend_process_pool_size=1
    )

    # Local backend should be serializable (process pool eligible)
    local_config = handlers._serialize_backend_config(local_backend)
    assert local_config is not None
    assert local_config["type"] == "local"

    # Unsupported backend should not be serializable (thread pool fallback)
    unsupported_config = handlers._serialize_backend_config(unsupported_backend)
    assert unsupported_config is None

    # Only supported backends should be in process pool configs
    assert len(handlers._backend_configs) == 1
    assert handlers._backend_configs[0]["type"] == "local"


@patch("tacacs_server.tacacs.handlers._backend_worker_main")
def test_process_pool_worker_receives_correct_configs(mock_worker):
    """Test that worker processes receive correctly serialized backend configs."""

    # Create backends with specific configurations
    local_backend = Mock()
    local_backend.name = "local"
    local_backend.db_path = "sqlite:///specific.db"

    ldap_backend = Mock()
    ldap_backend.name = "ldap"
    ldap_backend.ldap_server = "ldap://specific.com"
    ldap_backend.base_dn = "dc=specific,dc=com"
    ldap_backend.bind_dn = None
    ldap_backend.bind_password = None
    ldap_backend.user_attribute = "uid"
    ldap_backend.use_tls = False
    ldap_backend.timeout = 10

    handlers = AAAHandlers(
        [local_backend, ldap_backend], None, backend_process_pool_size=1
    )

    # Verify configs were prepared correctly
    assert len(handlers._backend_configs) == 2

    local_config = next(c for c in handlers._backend_configs if c["type"] == "local")
    assert local_config["database_url"] == "sqlite:///specific.db"

    ldap_config = next(c for c in handlers._backend_configs if c["type"] == "ldap")
    assert ldap_config["ldap_server"] == "ldap://specific.com"
    assert ldap_config["base_dn"] == "dc=specific,dc=com"


def test_radius_secret_bytes_to_string_conversion():
    """Test that RADIUS backend secret is properly converted from bytes to string."""

    radius_backend = Mock()
    radius_backend.name = "radius"
    radius_backend.radius_server = "127.0.0.1"
    radius_backend.radius_port = 1812
    radius_backend.radius_secret = b"bytes_secret"  # Bytes input
    radius_backend.radius_timeout = 5
    radius_backend.radius_retries = 3
    radius_backend.radius_nas_ip = "0.0.0.0"
    radius_backend.radius_nas_identifier = None

    handlers = AAAHandlers([radius_backend], None, backend_process_pool_size=1)
    config = handlers._serialize_backend_config(radius_backend)

    # Should convert bytes to string
    assert config["radius_secret"] == "bytes_secret"
    assert isinstance(config["radius_secret"], str)
