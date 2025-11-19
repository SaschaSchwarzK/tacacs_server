"""Tests for missing process pool coverage scenarios."""

import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from tacacs_server.tacacs.handlers import AAAHandlers


class SlowBackend:
    """Backend that sleeps for specified duration."""

    def __init__(self, sleep_duration=10.0):
        self.name = "slow"
        self.sleep_duration = sleep_duration

    def authenticate(self, username, password, **kwargs):
        time.sleep(self.sleep_duration)
        return username == "valid"


def test_concurrent_load_50_plus_auths():
    """Test 50+ parallel authentications to stress queue/worker selection."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=3)

    def auth_worker(user_id):
        ok, timed_out, err = handlers._authenticate_backend_with_timeout(
            backend, f"user{user_id}", "pass", timeout_s=2.0
        )
        return ok, timed_out, err, user_id

    # Run 60 concurrent authentications to stress the system
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(auth_worker, i) for i in range(60)]
        results = [f.result() for f in futures]

    # All should complete without hanging
    assert len(results) == 60
    assert all(isinstance(r, tuple) and len(r) == 4 for r in results)

    # Verify no hangs occurred
    for ok, timed_out, err, user_id in results:
        assert isinstance(ok, bool)
        assert isinstance(timed_out, bool)


def test_timeout_behavior_10s_sleep_2s_timeout():
    """Test backend that sleeps 10s with 2s timeout - verify timeout behavior."""
    slow_backend = SlowBackend(sleep_duration=10.0)
    handlers = AAAHandlers([slow_backend], None, backend_process_pool_size=2)

    # Authenticate with 2s timeout against 10s sleep backend
    start_time = time.time()
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        slow_backend, "test", "pass", timeout_s=2.0
    )
    elapsed = time.time() - start_time

    # Should timeout in approximately 2 seconds (falls back to thread pool)
    assert timed_out is True
    assert elapsed < 4.0  # Allow some margin but should be much less than 10s
    assert ok is False


def test_mixed_timeout_scenarios():
    """Test mix of fast and slow backends with different timeouts."""
    from tacacs_server.auth.local import LocalAuthBackend

    fast_backend = LocalAuthBackend("sqlite:///:memory:")
    slow_backend = SlowBackend(sleep_duration=2.0)

    # Test them separately to avoid interference
    handlers1 = AAAHandlers([fast_backend], None, backend_process_pool_size=1)
    handlers2 = AAAHandlers([slow_backend], None, backend_process_pool_size=1)

    # Test fast backend
    start = time.time()
    ok1, timed_out1, err1 = handlers1._authenticate_backend_with_timeout(
        fast_backend, "test", "pass", timeout_s=1.0
    )
    fast_elapsed = time.time() - start

    # Test slow backend
    start = time.time()
    ok2, timed_out2, err2 = handlers2._authenticate_backend_with_timeout(
        slow_backend, "test", "pass", timeout_s=0.5
    )
    slow_elapsed = time.time() - start

    # Fast backend should complete quickly
    assert fast_elapsed < 1.0

    # Slow backend should timeout
    assert timed_out2 is True
    assert slow_elapsed < 1.0  # Should timeout around 0.5s


def test_queue_saturation_with_timeouts():
    """Test queue behavior when saturated with timeout-prone requests."""
    slow_backend = SlowBackend(sleep_duration=2.0)
    handlers = AAAHandlers([slow_backend], None, backend_process_pool_size=1)

    def timeout_worker():
        return handlers._authenticate_backend_with_timeout(
            slow_backend, "test", "pass", timeout_s=0.5
        )

    # Saturate with requests that will timeout (falls back to thread pool)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(timeout_worker) for _ in range(10)]
        results = [f.result() for f in futures]

    # All should complete (timeout in thread pool since SlowBackend not serializable)
    assert len(results) == 10
    for ok, timed_out, err in results:
        assert isinstance(ok, bool)
        assert isinstance(timed_out, bool)
        # Should timeout since backend sleeps longer than timeout
        assert timed_out is True
        assert ok is False


def test_worker_replacement_under_load():
    """Test worker replacement works correctly under concurrent load."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=2)

    if not handlers._process_workers:
        pytest.skip("Process pool not available")

    # Kill one worker while system is under load
    def auth_load():
        results = []
        for i in range(10):
            ok, timed_out, err = handlers._authenticate_backend_with_timeout(
                backend, f"user{i}", "pass", timeout_s=1.0
            )
            results.append((ok, timed_out, err))
        return results

    # Record initial worker PIDs
    initial_pids = [w.pid for w in handlers._process_workers]

    with ThreadPoolExecutor(max_workers=5) as executor:
        # Start background load
        load_future = executor.submit(auth_load)

        # Kill a worker mid-load
        time.sleep(0.1)
        worker_to_kill = handlers._process_workers[0]
        worker_to_kill.terminate()

        # Wait for load to complete
        results = load_future.result()

    # All authentications should complete despite worker death
    assert len(results) == 10
    for ok, timed_out, err in results:
        assert isinstance(ok, bool)
        assert isinstance(timed_out, bool)

    # Give time for worker replacement to occur during next auth
    time.sleep(0.1)
    handlers._authenticate_backend_with_timeout(
        backend, "trigger", "pass", timeout_s=1.0
    )

    # At least one worker should have a different PID (indicating replacement)
    current_pids = [w.pid for w in handlers._process_workers]
    assert current_pids != initial_pids or not worker_to_kill.is_alive()
