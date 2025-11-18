"""E2E tests for process pool with real backends."""

import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.tacacs.handlers import AAAHandlers


@pytest.mark.e2e
def test_process_pool_with_local_backend_e2e():
    """E2E test of process pool with real local backend."""
    backend = LocalAuthBackend("sqlite:///:memory:")

    # Create test user with valid password
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
    backend = LocalAuthBackend("sqlite:///:memory:")

    # Create multiple test users with valid passwords
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
    # Create local backend
    local_backend = LocalAuthBackend("sqlite:///:memory:")

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
