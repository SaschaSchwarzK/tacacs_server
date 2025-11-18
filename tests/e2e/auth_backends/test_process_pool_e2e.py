"""E2E tests for process pool with real backends."""

import os
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.tacacs.handlers import AAAHandlers


@pytest.mark.e2e
def test_process_pool_with_local_backend_e2e():
    """E2E test of process pool with real local backend."""
    # Create real local backend with temporary database
    backend = LocalAuthBackend("sqlite:///:memory:")

    # Create test user
    user_service = backend.user_service
    user_service.create_user("testuser", password="TestPass123!", enabled=True)

    # Test with process pool enabled
    handlers = AAAHandlers([backend], None, backend_process_pool_size=2)

    if not handlers._process_workers:
        pytest.skip("Process pool not available on this platform")

    # Verify process pool is used
    assert len(handlers._process_workers) == 2
    assert all(w.is_alive() for w in handlers._process_workers)

    # Test authentication through process pool
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "testuser", "TestPass123!", timeout_s=5.0
    )

    assert ok is True
    assert timed_out is False
    assert err is None


@pytest.mark.e2e
def test_process_pool_with_ldap_backend_e2e():
    """E2E test of process pool with real LDAP backend."""
    from tacacs_server.auth.ldap_auth import LDAPAuthBackend

    # Use environment variables for LDAP connection
    ldap_server = os.getenv("LDAP_SERVER", "ldap://localhost:389")
    base_dn = os.getenv("LDAP_BASE_DN", "ou=people,dc=example,dc=com")
    bind_dn = os.getenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=com")
    bind_password = os.getenv("LDAP_BIND_PASSWORD", "secret")

    backend = LDAPAuthBackend(
        ldap_server=ldap_server,
        base_dn=base_dn,
        bind_dn=bind_dn,
        bind_password=bind_password,
        user_attribute="uid",
        use_tls=False,
        timeout=10,
    )

    # Test with process pool
    handlers = AAAHandlers([backend], None, backend_process_pool_size=2)

    if not handlers._process_workers:
        pytest.skip("Process pool not available on this platform")

    # Verify LDAP backend is serialized correctly
    config = handlers._serialize_backend_config(backend)
    assert config is not None
    assert config["type"] == "ldap"
    assert config["ldap_server"] == ldap_server
    assert config["base_dn"] == base_dn

    # Test authentication (will fail if no test user, but tests serialization)
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "testuser", "testpass", timeout_s=5.0
    )

    # Should complete without timeout (may fail auth if user doesn't exist)
    assert timed_out is False
    assert isinstance(ok, bool)


@pytest.mark.e2e
def test_process_pool_with_okta_backend_e2e():
    """E2E test of process pool with real Okta backend."""
    from tacacs_server.auth.okta_auth import OktaAuthBackend

    # Use environment variables for Okta connection
    okta_config = {
        "org_url": os.getenv("OKTA_ORG_URL", "https://dev-test.okta.com"),
        "api_token": os.getenv("OKTA_API_TOKEN", "test_token"),
        "client_id": os.getenv("OKTA_CLIENT_ID", "test_client"),
        "client_secret": os.getenv("OKTA_CLIENT_SECRET", "test_secret"),
        "private_key": os.getenv("OKTA_PRIVATE_KEY", ""),
        "private_key_id": os.getenv("OKTA_PRIVATE_KEY_ID", ""),
        "auth_method": os.getenv("OKTA_AUTH_METHOD", "client_secret_post"),
        "verify_tls": True,
        "require_group_for_auth": False,
    }

    backend = OktaAuthBackend(okta_config)

    # Test with process pool
    handlers = AAAHandlers([backend], None, backend_process_pool_size=2)

    if not handlers._process_workers:
        pytest.skip("Process pool not available on this platform")

    # Verify Okta backend is serialized correctly
    config = handlers._serialize_backend_config(backend)
    assert config is not None
    assert config["type"] == "okta"
    assert config["org_url"] == okta_config["org_url"]
    assert config["api_token"] == okta_config["api_token"]

    # Test authentication (will fail if no test user, but tests serialization)
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "testuser", "testpass", timeout_s=10.0
    )

    # Should complete without timeout (may fail auth if user doesn't exist)
    assert timed_out is False
    assert isinstance(ok, bool)


@pytest.mark.e2e
def test_process_pool_with_radius_backend_e2e():
    """E2E test of process pool with real RADIUS backend."""
    from tacacs_server.auth.radius_auth import RADIUSAuthBackend

    # Use environment variables for RADIUS connection
    radius_config = {
        "radius_server": os.getenv("RADIUS_SERVER", "127.0.0.1"),
        "radius_port": int(os.getenv("RADIUS_PORT", "1812")),
        "radius_secret": os.getenv("RADIUS_SECRET", "testing123"),
        "radius_timeout": int(os.getenv("RADIUS_TIMEOUT", "5")),
        "radius_retries": int(os.getenv("RADIUS_RETRIES", "3")),
        "radius_nas_ip": os.getenv("RADIUS_NAS_IP", "127.0.0.1"),
        "radius_nas_identifier": os.getenv("RADIUS_NAS_IDENTIFIER", "tacacs-test"),
    }

    backend = RADIUSAuthBackend(radius_config)

    # Test with process pool
    handlers = AAAHandlers([backend], None, backend_process_pool_size=2)

    if not handlers._process_workers:
        pytest.skip("Process pool not available on this platform")

    # Verify RADIUS backend is serialized correctly
    config = handlers._serialize_backend_config(backend)
    assert config is not None
    assert config["type"] == "radius"
    assert config["radius_server"] == radius_config["radius_server"]
    assert config["radius_port"] == radius_config["radius_port"]

    # Test authentication (will timeout if no RADIUS server, but tests serialization)
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "testuser", "testpass", timeout_s=2.0
    )

    # May timeout if no server available (expected behavior)
    assert isinstance(timed_out, bool)
    assert isinstance(ok, bool)


@pytest.mark.e2e
def test_process_pool_concurrent_real_backends():
    """E2E test of process pool under concurrent load with real backends."""
    # Use local backend for reliable testing
    backend = LocalAuthBackend("sqlite:///:memory:")

    # Create multiple test users
    user_service = backend.user_service
    for i in range(10):
        user_service.create_user(f"user{i}", password=f"TestPass{i}123!", enabled=True)

    # Test with process pool
    handlers = AAAHandlers([backend], None, backend_process_pool_size=3)

    if not handlers._process_workers:
        pytest.skip("Process pool not available on this platform")

    def auth_worker(user_id):
        """Worker function for concurrent authentication."""
        ok, timed_out, err = handlers._authenticate_backend_with_timeout(
            backend, f"user{user_id}", f"TestPass{user_id}123!", timeout_s=5.0
        )
        return ok, timed_out, err, user_id

    # Run 30 concurrent authentications
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(auth_worker, i % 10) for i in range(30)]
        results = [f.result() for f in futures]

    # All should complete successfully
    assert len(results) == 30
    for ok, timed_out, err, user_id in results:
        assert ok is True, f"Auth failed for user{user_id}: {err}"
        assert timed_out is False
        assert err is None


@pytest.mark.e2e
def test_process_pool_worker_crash_recovery_e2e():
    """E2E test of worker crash recovery with real backend."""
    backend = LocalAuthBackend("sqlite:///:memory:")

    # Create test user
    user_service = backend.user_service
    user_service.create_user("testuser", password="TestPass123!", enabled=True)

    # Test with process pool
    handlers = AAAHandlers([backend], None, backend_process_pool_size=2)

    if not handlers._process_workers:
        pytest.skip("Process pool not available on this platform")

    # Verify initial authentication works
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "testuser", "TestPass123!", timeout_s=5.0
    )
    assert ok is True

    # Kill a worker
    initial_worker = handlers._process_workers[0]
    initial_worker.terminate()
    initial_worker.join(timeout=2.0)

    # Authentication should still work (worker gets replaced)
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "testuser", "TestPass123!", timeout_s=5.0
    )
    assert ok is True
    assert timed_out is False

    # Verify system continues to work (worker replacement happens on next auth)
    time.sleep(0.5)  # Give time for replacement
    # The key test is that authentication still works after worker crash
    # Worker replacement happens lazily on next authentication attempt


@pytest.mark.e2e
def test_process_pool_timeout_with_real_backend():
    """E2E test of timeout behavior with real backend under load."""
    backend = LocalAuthBackend("sqlite:///:memory:")

    # Create test user
    user_service = backend.user_service
    user_service.create_user("testuser", password="TestPass123!", enabled=True)

    # Test with small process pool to force queuing
    handlers = AAAHandlers([backend], None, backend_process_pool_size=1)

    if not handlers._process_workers:
        pytest.skip("Process pool not available on this platform")

    def auth_with_timeout():
        """Authentication with short timeout."""
        return handlers._authenticate_backend_with_timeout(
            backend,
            "testuser",
            "TestPass123!",
            timeout_s=0.1,  # Very short timeout
        )

    # Run multiple concurrent auths to stress the single worker
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(auth_with_timeout) for _ in range(10)]
        results = [f.result() for f in futures]

    # Some should complete, some might timeout due to queuing
    assert len(results) == 10
    completed = sum(1 for ok, timed_out, err in results if not timed_out)

    # At least some should complete
    assert completed > 0
    # Results should be consistent
    for ok, timed_out, err in results:
        assert isinstance(ok, bool)
        assert isinstance(timed_out, bool)


@pytest.mark.e2e
def test_process_pool_mixed_backends_e2e():
    """E2E test with multiple real backend types in process pool."""
    # Create multiple backends
    local_backend = LocalAuthBackend("sqlite:///:memory:")

    # Create test user in local backend
    user_service = local_backend.user_service
    user_service.create_user("localuser", password="LocalPass123!", enabled=True)

    backends = [local_backend]

    # Add LDAP backend for testing serialization
    try:
        from tacacs_server.auth.ldap_auth import LDAPAuthBackend

        ldap_backend = LDAPAuthBackend(
            ldap_server="ldap.example.com",
            base_dn="ou=people,dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            user_attribute="uid",
            use_tls=False,
            timeout=10,
        )
        backends.append(ldap_backend)
    except ImportError:
        pass

    # Test with process pool
    handlers = AAAHandlers(backends, None, backend_process_pool_size=2)

    if not handlers._process_workers:
        pytest.skip("Process pool not available on this platform")

    # Verify all backends are serialized
    configs = [handlers._serialize_backend_config(b) for b in backends]
    assert all(c is not None for c in configs)

    # Test authentication with local backend
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        local_backend, "localuser", "LocalPass123!", timeout_s=5.0
    )
    assert ok is True
    assert timed_out is False

    # Test with other backends (may fail auth but should not timeout)
    for backend in backends[1:]:
        ok, timed_out, err = handlers._authenticate_backend_with_timeout(
            backend, "testuser", "testpass", timeout_s=5.0
        )
        assert timed_out is False  # Should not timeout
        assert isinstance(ok, bool)
