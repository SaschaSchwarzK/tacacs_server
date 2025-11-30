"""Integration-style tests for RADIUS per-IP rate limiting."""

import time

from tacacs_server.utils.rate_limiter import ConnectionLimiter, RateLimiter


def test_per_ip_rate_limiting():
    limiter = ConnectionLimiter(max_per_ip=2)
    ip = "192.0.2.1"
    assert limiter.acquire(ip)
    assert limiter.acquire(ip)
    assert limiter.acquire(ip) is False  # over limit
    limiter.release(ip)
    assert limiter.get_count(ip) == 1


def test_rate_limit_exceeded_and_recovery():
    rl = RateLimiter(max_requests=3, window_seconds=1)
    ip = "198.51.100.10"
    allowed = [rl.allow_request(ip) for _ in range(4)]
    assert allowed[:3] == [True, True, True]
    assert allowed[3] is False  # exceeded
    # Wait for tokens to refill
    time.sleep(1.1)
    assert rl.allow_request(ip) is True


def test_connection_rejection_when_limited():
    limiter = ConnectionLimiter(max_per_ip=1)
    ip = "203.0.113.1"
    assert limiter.acquire(ip)
    assert limiter.acquire(ip) is False
    limiter.release(ip)


def test_rate_limit_statistics_tracking(monkeypatch):
    rl = RateLimiter(max_requests=2, window_seconds=1)
    ip = "192.0.2.5"
    now = [1000.0]

    def fake_time():
        return now[0]

    monkeypatch.setattr("tacacs_server.utils.rate_limiter.time.time", fake_time)
    assert rl.allow_request(ip) is True
    assert rl.allow_request(ip) is True
    # No time passed; should be limited
    assert rl.allow_request(ip) is False
    # Advance time to refill one token
    now[0] += 0.6
    assert rl.allow_request(ip) is True
