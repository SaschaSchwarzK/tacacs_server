"""E2E tests for process pool with real backends."""

import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.tacacs.handlers import AAAHandlers


@pytest.mark.e2e
def test_process_pool_with_local_backend_e2e():
    """E2E test of process pool with real local backend."""
    # Create real local backend with shared database
    import os

    db_path = os.path.join("data", "test_process_pool_basic.db")
    # Clean up any existing database
    if os.path.exists(db_path):
        os.remove(db_path)
    backend = LocalAuthBackend(db_path)

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
def test_process_pool_concurrent_real_backends():
    """E2E test of process pool under concurrent load with real backends."""
    # Use local backend for reliable testing with a proper shared database path
    import os

    db_path = os.path.join("data", "test_process_pool_concurrent.db")
    # Clean up any existing database
    if os.path.exists(db_path):
        os.remove(db_path)
    backend = LocalAuthBackend(db_path)

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

    # Clean up
    try:
        os.remove(db_path)
    except Exception:
        pass


@pytest.mark.e2e
def test_process_pool_worker_crash_recovery_e2e():
    """E2E test of worker crash recovery with real backend."""
    import os

    db_path = os.path.join("data", "test_process_pool_crash_recovery.db")
    # Clean up any existing database
    if os.path.exists(db_path):
        os.remove(db_path)
    backend = LocalAuthBackend(db_path)

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

    # Kill a worker and force multiple authentications to trigger replacement
    initial_worker = handlers._process_workers[0]
    initial_worker_pid = initial_worker.pid
    initial_worker.terminate()
    initial_worker.join(timeout=2.0)

    # Force multiple authentications to ensure we hit the dead worker
    # The round-robin will eventually select the dead worker and replace it
    for _ in range(5):
        ok, timed_out, err = handlers._authenticate_backend_with_timeout(
            backend, "testuser", "TestPass123!", timeout_s=5.0
        )
        assert ok is True
        assert timed_out is False

    # Verify worker was replaced (check PID)
    new_worker = handlers._process_workers[0]
    assert new_worker.pid != initial_worker_pid
    assert new_worker.is_alive()


@pytest.mark.e2e
def test_process_pool_timeout_with_real_backend():
    """E2E test of timeout behavior with real backend under load."""
    import os

    db_path = os.path.join("data", "test_process_pool_timeout.db")
    # Clean up any existing database
    if os.path.exists(db_path):
        os.remove(db_path)
    backend = LocalAuthBackend(db_path)

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
            timeout_s=1.0,  # Short but reasonable timeout
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
    # Create local backend
    import os

    db_path = os.path.join("data", "test_process_pool_mixed.db")
    # Clean up any existing database
    if os.path.exists(db_path):
        os.remove(db_path)
    local_backend = LocalAuthBackend(db_path)

    # Create test user in local backend
    user_service = local_backend.user_service
    user_service.create_user("localuser", password="LocalPass123!", enabled=True)

    backends = [local_backend]

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


@pytest.mark.e2e
def test_process_pool_with_ldap_backend_e2e():
    """E2E test of process pool with LDAP backend serialization."""
    from tacacs_server.auth.ldap_auth import LDAPAuthBackend

    # Create LDAP backend with test configuration
    backend = LDAPAuthBackend(
        ldap_server="ldap.example.com",
        base_dn="ou=people,dc=example,dc=com",
        bind_dn="cn=admin,dc=example,dc=com",
        bind_password="secret",
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
    assert config["ldap_server"] == "ldap.example.com"
    assert config["base_dn"] == "ou=people,dc=example,dc=com"
    assert config["bind_dn"] == "cn=admin,dc=example,dc=com"
    assert config["bind_password"] == "secret"
    assert config["user_attribute"] == "uid"
    assert config["use_tls"] is False
    assert config["timeout"] == 10

    # Test authentication (will fail due to no server, but tests serialization)
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "testuser", "TestPass123!", timeout_s=5.0
    )

    # Should complete without timeout (will fail auth due to no server)
    assert timed_out is False
    assert isinstance(ok, bool)
    # Error may be None or string depending on LDAP library behavior
    assert err is None or isinstance(err, str)


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
        backend, "testuser", "TestPass123!", timeout_s=10.0
    )

    # Should complete without timeout (may fail auth if user doesn't exist)
    assert timed_out is False
    assert isinstance(ok, bool)


@pytest.mark.e2e
def test_process_pool_with_radius_backend_e2e():
    """E2E test of process pool with RADIUS backend serialization."""
    from tacacs_server.auth.radius_auth import RADIUSAuthBackend

    # Create RADIUS backend with test configuration
    radius_config = {
        "radius_server": "radius.example.com",
        "radius_port": 1812,
        "radius_secret": "testing123",
        "radius_timeout": 5,
        "radius_retries": 3,
        "radius_nas_ip": "127.0.0.1",
        "radius_nas_identifier": "tacacs-test",
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
    assert config["radius_server"] == "radius.example.com"
    assert config["radius_port"] == 1812
    assert config["radius_secret"] == "testing123"
    assert config["radius_timeout"] == 5
    assert config["radius_retries"] == 3
    assert config["radius_nas_ip"] == "127.0.0.1"
    assert config["radius_nas_identifier"] == "tacacs-test"

    # Test authentication (will fail due to no server, but tests serialization)
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "testuser", "TestPass123!", timeout_s=5.0
    )

    # Should complete without timeout (will fail auth due to no server)
    assert timed_out is False
    assert isinstance(ok, bool)
    # Error may be None or string depending on RADIUS library behavior
    assert err is None or isinstance(err, str)
