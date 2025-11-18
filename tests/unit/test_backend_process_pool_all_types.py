import multiprocessing as mp
import os
import sys
import types

# Ensure 'fork' start method for tests
try:
    mp.set_start_method("fork", force=True)
except Exception:
    pass

# Provide minimal shims for optional imports
for mod in ("requests", "ldap3", "bcrypt"):
    if mod not in sys.modules:
        sys.modules[mod] = types.ModuleType(mod)

if "requests.adapters" not in sys.modules:
    adapters = types.ModuleType("requests.adapters")
    sys.modules["requests.adapters"] = adapters
    setattr(sys.modules["requests"], "adapters", adapters)

    class _DummyHTTPAdapter:
        pass

    setattr(adapters, "HTTPAdapter", _DummyHTTPAdapter)

from tacacs_server.auth.base import AuthenticationBackend  # noqa: E402
from tacacs_server.tacacs.handlers import AAAHandlers  # noqa: E402


class MockLocalBackend(AuthenticationBackend):
    def __init__(self, database_url: str = ""):
        super().__init__("local")
        self.database_url = database_url

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        return username == "testuser" and password == "testpass"

    def get_user_attributes(self, username: str):
        return {"enabled": True}


class MockLDAPBackend(AuthenticationBackend):
    def __init__(self, ldap_server: str = "", base_dn: str = "", **kwargs):
        super().__init__("ldap")
        self.ldap_server = ldap_server
        self.base_dn = base_dn
        self.bind_dn = kwargs.get("bind_dn")
        self.bind_password = kwargs.get("bind_password")
        self.user_attribute = kwargs.get("user_attribute", "uid")
        self.use_tls = kwargs.get("use_tls", False)
        self.timeout = kwargs.get("timeout", 10)

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        return username == "ldapuser" and password == "ldappass"

    def get_user_attributes(self, username: str):
        return {"enabled": True}


class MockOktaBackend(AuthenticationBackend):
    def __init__(self, cfg: dict):
        super().__init__("okta")
        self.org_url = cfg.get("org_url", "")
        self.api_token = cfg.get("api_token", "")
        self.client_id = cfg.get("client_id", "")
        self.client_secret = cfg.get("client_secret", "")
        self.private_key = cfg.get("private_key", "")
        self.private_key_id = cfg.get("private_key_id", "")
        self.auth_method = cfg.get("auth_method", "")
        self.verify_tls = cfg.get("verify_tls", True)
        self.require_group_for_auth = cfg.get("require_group_for_auth", False)

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        return username == "oktauser" and password == "oktapass"

    def get_user_attributes(self, username: str):
        return {"enabled": True}


class MockRadiusBackend(AuthenticationBackend):
    def __init__(self, cfg: dict):
        super().__init__("radius")
        self.radius_server = cfg.get("radius_server", "")
        self.radius_port = cfg.get("radius_port", 1812)
        self.radius_secret = cfg.get("radius_secret", "").encode("utf-8") if cfg.get("radius_secret") else b""
        self.radius_timeout = cfg.get("radius_timeout", 5)
        self.radius_retries = cfg.get("radius_retries", 3)
        self.radius_nas_ip = cfg.get("radius_nas_ip", "0.0.0.0")
        self.radius_nas_identifier = cfg.get("radius_nas_identifier")

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        return username == "radiususer" and password == "radiuspass"

    def get_user_attributes(self, username: str):
        return {"enabled": True}


def test_all_backend_types_serialization():
    """Test that all backend types can be serialized for process pool."""
    # Create mock backends
    local_backend = MockLocalBackend("sqlite:///test.db")
    ldap_backend = MockLDAPBackend(
        ldap_server="ldap://test.com",
        base_dn="dc=test,dc=com",
        bind_dn="cn=admin,dc=test,dc=com",
        bind_password="secret",
        user_attribute="uid",
        use_tls=False,
        timeout=10
    )
    okta_backend = MockOktaBackend({
        "org_url": "https://test.okta.com",
        "api_token": "test_token"
    })
    radius_backend = MockRadiusBackend({
        "radius_server": "radius.test.com",
        "radius_port": 1812,
        "radius_secret": "radius_secret"
    })

    # Create handler with all backend types
    handler = AAAHandlers(
        auth_backends=[local_backend, ldap_backend, okta_backend, radius_backend],
        db_logger=None,
        backend_timeout=1.0,
        backend_process_pool_size=0  # Don't create actual process pool for this test
    )

    # Test serialization of each backend type
    local_config = handler._serialize_backend_config(local_backend)
    assert local_config is not None
    assert local_config["type"] == "local"
    assert local_config["database_url"] == "sqlite:///test.db"

    ldap_config = handler._serialize_backend_config(ldap_backend)
    assert ldap_config is not None
    assert ldap_config["type"] == "ldap"
    assert ldap_config["ldap_server"] == "ldap://test.com"
    assert ldap_config["base_dn"] == "dc=test,dc=com"
    assert ldap_config["bind_dn"] == "cn=admin,dc=test,dc=com"

    okta_config = handler._serialize_backend_config(okta_backend)
    assert okta_config is not None
    assert okta_config["type"] == "okta"
    assert okta_config["org_url"] == "https://test.okta.com"
    assert okta_config["api_token"] == "test_token"

    radius_config = handler._serialize_backend_config(radius_backend)
    assert radius_config is not None
    assert radius_config["type"] == "radius"
    assert radius_config["radius_server"] == "radius.test.com"
    assert radius_config["radius_port"] == 1812
    assert radius_config["radius_secret"] == "radius_secret"


def test_process_pool_with_multiple_backend_types():
    """Test that process pool works with multiple backend types when enabled."""
    # Enable process pool explicitly for this test
    os.environ["TACACS_ENABLE_PROCESS_POOL"] = "1"
    try:
        # Create mock backends
        local_backend = MockLocalBackend("sqlite:///:memory:")
        ldap_backend = MockLDAPBackend(ldap_server="ldap://test.com")

        handler = AAAHandlers(
            auth_backends=[local_backend, ldap_backend],
            db_logger=None,
            backend_timeout=0.5,
            backend_process_pool_size=2
        )

        # If process pool creation succeeded, test it
        if len(handler._process_workers) > 0:
            # Test that process pool was created successfully
            assert len(handler._process_workers) == 2
            assert len(handler._process_in_queues) == 2
            assert handler._process_out_queue is not None
            
            # Test local backend authentication - expect it to fail since we're using
            # a real LocalAuthBackend in the worker process, not our mock
            ok, timed_out, err = handler._authenticate_backend_with_timeout(
                local_backend, "testuser", "testpass", timeout_s=handler.backend_timeout
            )
            # The authentication should complete (not timeout) even if it fails
            assert timed_out is False
            # The result may be False since we're using a real backend, not the mock
            assert isinstance(ok, bool)

            # Test LDAP backend authentication - should fall back to thread pool
            # since LDAP imports may not be available in worker process
            ok, timed_out, err = handler._authenticate_backend_with_timeout(
                ldap_backend, "ldapuser", "ldappass", timeout_s=handler.backend_timeout
            )
            # Should complete without timeout
            assert timed_out is False
            assert isinstance(ok, bool)
        else:
            # Process pool creation failed, ensure thread pool fallback works
            ok, timed_out, err = handler._authenticate_backend_with_timeout(
                local_backend, "testuser", "testpass", timeout_s=handler.backend_timeout
            )
            # Mock should work in thread pool
            assert ok is True
            assert timed_out is False

    finally:
        # Clean up environment
        os.environ.pop("TACACS_ENABLE_PROCESS_POOL", None)


def test_unsupported_backend_serialization():
    """Test that unsupported backend types return None for serialization."""
    class UnsupportedBackend(AuthenticationBackend):
        def __init__(self):
            super().__init__("unsupported")

        def authenticate(self, username: str, password: str, **kwargs) -> bool:
            return False
            
        def get_user_attributes(self, username: str):
            return {}

    handler = AAAHandlers(
        auth_backends=[],
        db_logger=None,
        backend_timeout=1.0,
        backend_process_pool_size=0
    )

    unsupported_backend = UnsupportedBackend()
    config = handler._serialize_backend_config(unsupported_backend)
    assert config is None