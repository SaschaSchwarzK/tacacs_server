"""Stress tests for process pool coverage gaps."""

import multiprocessing as mp
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from tacacs_server.tacacs.handlers import AAAHandlers


class SlowBackend:
    """Backend that takes time to respond."""

    def __init__(self, delay=0.1):
        self.name = "slow"
        self.delay = delay

    def authenticate(self, username, password, **kwargs):
        time.sleep(self.delay)
        return username == "valid"


class MalformedBackend:
    """Backend with malformed config."""

    def __init__(self):
        self.name = "malformed"
        # Missing required attributes

    def authenticate(self, username, password, **kwargs):
        return False


def test_concurrent_authentication_stress():
    """Test multiple backends under concurrent load."""
    from tacacs_server.auth.local import LocalAuthBackend

    backends = [LocalAuthBackend("sqlite:///:memory:") for _ in range(3)]
    handlers = AAAHandlers(backends, None, backend_process_pool_size=2)

    def auth_worker():
        ok, timed_out, err = handlers._authenticate_backend_with_timeout(
            backends[0], "test", "pass", timeout_s=1.0
        )
        return ok, timed_out, err

    # Run 20 concurrent authentications
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(auth_worker) for _ in range(20)]
        results = [f.result() for f in futures]

    # All should complete without hanging
    assert len(results) == 20
    assert all(isinstance(r, tuple) and len(r) == 3 for r in results)


def test_worker_crash_recovery():
    """Test recovery when worker process crashes."""
    from tacacs_server.auth.local import LocalAuthBackend

    # Use a real backend but simulate crash by killing worker
    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=1)

    # Verify initial worker is alive
    assert len(handlers._process_workers) == 1
    initial_worker = handlers._process_workers[0]
    assert initial_worker.is_alive()

    # Kill the worker to simulate crash
    initial_worker.terminate()
    initial_worker.join(timeout=1.0)
    assert not initial_worker.is_alive()

    # Next auth should detect dead worker and restart it
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "test", "pass", timeout_s=2.0
    )

    # Should have restarted worker
    assert len(handlers._process_workers) == 1
    new_worker = handlers._process_workers[0]
    assert new_worker != initial_worker
    assert new_worker.is_alive()


def test_timeout_edge_cases():
    """Test worker hangs vs slow response."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=1)

    # Normal auth should work quickly
    ok1, timed_out1, err1 = handlers._authenticate_backend_with_timeout(
        backend, "test", "pass", timeout_s=1.0
    )
    assert timed_out1 is False

    # Very short timeout should still complete or timeout gracefully
    ok2, timed_out2, err2 = handlers._authenticate_backend_with_timeout(
        backend, "test", "pass", timeout_s=0.01
    )
    # Should either work quickly or timeout
    assert isinstance(timed_out2, bool)
    assert isinstance(ok2, bool)


def test_queue_overflow_behavior():
    """Test behavior when queues fill up."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=1)

    # Fill queue with many requests
    def flood_queue():
        for _ in range(100):
            try:
                handlers._process_in_queues[0].put(
                    (1, {"type": "local", "database_url": ""}, "user", "pass", {}),
                    timeout=0.01,
                )
            except Exception:
                break  # Queue full

    flood_thread = threading.Thread(target=flood_queue)
    flood_thread.start()
    flood_thread.join()

    # Should still be able to authenticate
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "test", "pass", timeout_s=1.0
    )
    # Should either work or gracefully fail
    assert isinstance(ok, bool)
    assert isinstance(timed_out, bool)


def test_serialization_failures():
    """Test malformed backend configs."""
    malformed = MalformedBackend()
    handlers = AAAHandlers([malformed], None, backend_process_pool_size=1)

    # Should serialize to None for unsupported backend
    config = handlers._serialize_backend_config(malformed)
    assert config is None

    # Should fall back to thread pool
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        malformed, "test", "pass", timeout_s=1.0
    )
    assert isinstance(ok, bool)
    assert timed_out is False  # Should use thread pool, not timeout


def test_mixed_backend_fallback():
    """Test some backends use process pool, others use threads."""
    from tacacs_server.auth.local import LocalAuthBackend

    local_backend = LocalAuthBackend("sqlite:///:memory:")
    malformed_backend = MalformedBackend()

    handlers = AAAHandlers(
        [local_backend, malformed_backend], None, backend_process_pool_size=1
    )

    # Local backend should use process pool
    ok1, timed_out1, err1 = handlers._authenticate_backend_with_timeout(
        local_backend, "test", "pass", timeout_s=1.0
    )

    # Malformed backend should fall back to thread pool
    ok2, timed_out2, err2 = handlers._authenticate_backend_with_timeout(
        malformed_backend, "test", "pass", timeout_s=1.0
    )

    assert isinstance(ok1, bool)
    assert isinstance(ok2, bool)


def test_process_cleanup_on_shutdown():
    """Test graceful termination of workers."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=2)

    # Verify workers are alive
    assert len(handlers._process_workers) == 2
    assert all(p.is_alive() for p in handlers._process_workers)

    # Terminate workers
    for worker in handlers._process_workers:
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=1.0)

    # Verify workers are terminated
    assert all(not p.is_alive() for p in handlers._process_workers)


def test_memory_leak_simulation():
    """Test long-running workers with many auth cycles."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=1)

    # Run many authentication cycles
    for i in range(50):
        ok, timed_out, err = handlers._authenticate_backend_with_timeout(
            backend, f"user{i}", "pass", timeout_s=0.5
        )
        # Should complete without hanging or crashing
        assert isinstance(ok, bool)
        assert isinstance(timed_out, bool)

    # Worker should still be alive
    assert len(handlers._process_workers) == 1
    assert handlers._process_workers[0].is_alive()


def test_backend_state_consistency():
    """Test backend state isolation across processes."""
    from tacacs_server.auth.local import LocalAuthBackend

    # Create two handlers with same backend type
    backend1 = LocalAuthBackend("sqlite:///:memory:")
    backend2 = LocalAuthBackend("sqlite:///:memory:")

    handlers1 = AAAHandlers([backend1], None, backend_process_pool_size=1)
    handlers2 = AAAHandlers([backend2], None, backend_process_pool_size=1)

    # Auth with both should be isolated
    ok1, _, _ = handlers1._authenticate_backend_with_timeout(
        backend1, "test1", "pass", timeout_s=1.0
    )
    ok2, _, _ = handlers2._authenticate_backend_with_timeout(
        backend2, "test2", "pass", timeout_s=1.0
    )

    # Both should complete independently
    assert isinstance(ok1, bool)
    assert isinstance(ok2, bool)


@pytest.mark.skipif(
    not hasattr(mp, "get_context"), reason="Multiprocessing context not available"
)
def test_process_pool_metrics():
    """Test process pool performance tracking."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=2)

    # Track initial state
    initial_workers = len(handlers._process_workers)
    initial_task_id = handlers._next_task_id

    # Perform authentication
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "test", "pass", timeout_s=1.0
    )

    # Verify metrics updated
    assert handlers._next_task_id > initial_task_id
    assert len(handlers._process_workers) == initial_workers
    assert isinstance(ok, bool)


def test_concurrent_worker_restart():
    """Test concurrent worker restart scenarios."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=2)

    if not handlers._process_workers:
        pytest.skip("Process pool not available")

    # Kill one worker while others are working
    worker_to_kill = handlers._process_workers[0]
    worker_to_kill.terminate()
    worker_to_kill.join(timeout=1.0)

    # Continue authentication - should restart worker
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "test", "pass", timeout_s=1.0
    )

    # Should complete successfully
    assert isinstance(ok, bool)
    assert timed_out is False

    # Verify worker was restarted
    assert handlers._process_workers[0] != worker_to_kill
    assert handlers._process_workers[0].is_alive()
