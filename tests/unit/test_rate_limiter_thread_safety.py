"""Unit tests for the rate limiter's thread-safety and token-bucket behavior.

This module stresses the `RateLimiter` with concurrent calls to ensure that:
- Token bookkeeping is safe under multi-threaded access.
- The configured `max_requests` per `window_seconds` cap is respected.

It does not mock time; instead it verifies correctness under real threading
contention, making it a lightweight concurrency regression test.
"""

import threading

from tacacs_server.utils.rate_limiter import RateLimiter


def test_rate_limiter_thread_safety():
    """Stress concurrent access against a single client IP.

    Setup:
    - Create a `RateLimiter(max_requests=100, window_seconds=1)`.
    - Launch 10 threads; each performs 50 immediate `allow_request` calls
      against the same client IP.

    Expectations:
    - The first 100 requests across all threads are allowed (initially full
      bucket minus consumption), the remaining 400 are denied.
    - No exceptions or race conditions occur under contention.
    """
    limiter = RateLimiter(max_requests=100, window_seconds=1)
    results = []

    def stress_test():
        for i in range(50):
            result = limiter.allow_request("192.168.1.1")
            results.append(result)

    # 10 threads, each making 50 requests
    threads = [threading.Thread(target=stress_test) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Should have 100 allowed, 400 denied (hits limit)
    allowed = sum(results)
    denied = len(results) - allowed

    assert allowed == 100, f"Expected 100 allowed, got {allowed}"
    assert denied == 400, f"Expected 400 denied, got {denied}"
    print(f"✓ Thread safety test passed: {allowed} allowed, {denied} denied")
