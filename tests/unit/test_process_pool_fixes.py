"""Tests for process pool pending tasks cleanup and queue overflow fixes."""

import threading
import time
from unittest.mock import patch

import pytest

from tacacs_server.tacacs.handlers import AAAHandlers


class TestBackend:
    """Test backend for process pool testing."""

    def __init__(self, name="test"):
        self.name = name

    def authenticate(self, username, password, **kwargs):
        return username == "valid"


def test_pending_tasks_cleanup():
    """Test that pending tasks are cleaned up to prevent unbounded growth."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=1)

    # Manually add many pending tasks to simulate buildup
    with handlers._process_lock:
        for i in range(1000):
            handlers._pending_tasks[i] = (True, None)

    # Trigger cleanup by adding a new task
    with handlers._process_lock:
        handlers._cleanup_pending_tasks()

    # Should have cleaned up some tasks
    assert len(handlers._pending_tasks) < 1000


def test_pending_tasks_max_size_limit():
    """Test that pending tasks dict respects max size limit."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=1)

    # Fill up to max size
    with handlers._process_lock:
        for i in range(handlers._pending_tasks_max_size + 100):
            handlers._pending_tasks[i] = (True, None)

    # Simulate adding a new result when at max size
    with handlers._process_lock:
        handlers._cleanup_pending_tasks()
        if len(handlers._pending_tasks) < handlers._pending_tasks_max_size:
            handlers._pending_tasks[9999] = (True, None)

    # Should not exceed max size
    assert len(handlers._pending_tasks) <= handlers._pending_tasks_max_size


def test_queue_overflow_handling():
    """Test that queue overflow is handled gracefully."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=1)

    if not handlers._process_workers:
        pytest.skip("Process pool not available")

    # Mock the queue to simulate full queue
    with patch.object(handlers._process_in_queues[0], "put_nowait") as mock_put:
        mock_put.side_effect = Exception("Queue full")

        # Should fall back to thread pool gracefully
        ok, timed_out, err = handlers._authenticate_backend_with_timeout(
            backend, "test", "pass", timeout_s=1.0
        )

        # Should complete using thread pool fallback
        assert isinstance(ok, bool)
        assert timed_out is False  # Thread pool doesn't timeout the same way


def test_cleanup_timing():
    """Test that cleanup only runs periodically to avoid overhead."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=1)

    # Set last cleanup time to recent
    handlers._last_cleanup_time = time.time()

    # Add some tasks
    with handlers._process_lock:
        for i in range(100):
            handlers._pending_tasks[i] = (True, None)

    initial_count = len(handlers._pending_tasks)

    # Call cleanup - should not run due to timing
    with handlers._process_lock:
        handlers._cleanup_pending_tasks()

    # Should not have cleaned up anything
    assert len(handlers._pending_tasks) == initial_count


def test_bounded_queues_creation():
    """Test that queues are created with size limits."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=2)

    if not handlers._process_workers:
        pytest.skip("Process pool not available")

    # Verify queues exist and are bounded
    assert len(handlers._process_in_queues) == 2
    assert handlers._process_out_queue is not None

    # Queues should have maxsize set (can't easily test the actual value
    # but we can verify they were created successfully)
    for in_q in handlers._process_in_queues:
        assert in_q is not None


def test_concurrent_pending_tasks_access():
    """Test thread-safe access to pending tasks."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=1)

    results = []
    errors = []

    def worker():
        try:
            with handlers._process_lock:
                # Simulate concurrent access
                handlers._cleanup_pending_tasks()
                handlers._pending_tasks[threading.current_thread().ident] = (True, None)
                results.append(len(handlers._pending_tasks))
        except Exception as e:
            errors.append(e)

    # Run multiple threads concurrently
    threads = []
    for _ in range(10):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Should complete without errors
    assert len(errors) == 0
    assert len(results) == 10


def test_process_pool_with_bounded_queues_integration():
    """Integration test with bounded queues and cleanup."""
    from tacacs_server.auth.local import LocalAuthBackend

    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers = AAAHandlers([backend], None, backend_process_pool_size=1)

    if not handlers._process_workers:
        pytest.skip("Process pool not available")

    # Perform multiple authentications to test queue handling
    results = []
    for i in range(20):
        ok, timed_out, err = handlers._authenticate_backend_with_timeout(
            backend, f"user{i}", "pass", timeout_s=1.0
        )
        results.append((ok, timed_out, err))

    # All should complete
    assert len(results) == 20
    for ok, timed_out, err in results:
        assert isinstance(ok, bool)
        assert isinstance(timed_out, bool)
