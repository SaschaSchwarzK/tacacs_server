from tacacs_server.utils.rate_limiter import RateLimiter
from tacacs_server.utils.security import AuthRateLimiter


def test_token_bucket_basic_behavior():
    rl = RateLimiter(max_requests=3, window_seconds=60)
    ip = "127.0.0.1"
    assert rl.allow_request(ip)
    assert rl.allow_request(ip)
    assert rl.allow_request(ip)
    assert not rl.allow_request(ip), "Fourth request should be limited"


def test_auth_rate_limiter_window():
    arl = AuthRateLimiter(max_attempts=2, window_seconds=1)
    ip = "127.0.0.1"
    assert arl.is_allowed(ip)
    arl.record_attempt(ip)
    assert arl.is_allowed(ip)
    arl.record_attempt(ip)
    assert not arl.is_allowed(ip)


def test_auth_rate_limiter_cleanup_old_ips(monkeypatch):
    """Stale IP entries are cleaned up to avoid unbounded growth."""
    import time as _time

    arl = AuthRateLimiter(max_attempts=1, window_seconds=1)
    now = _time.time()

    # Inject stale and fresh timestamps directly
    arl.attempts["old.ip"] = [now - 10]
    arl.attempts["new.ip"] = [now]

    # Freeze time during cleanup
    class _FakeTime:
        def __init__(self, value: float):
            self._value = value

        def time(self) -> float:
            return self._value

    fake = _FakeTime(now)
    monkeypatch.setattr("tacacs_server.utils.security.time", fake)

    arl.cleanup_old_ips()
    assert "old.ip" not in arl.attempts
    assert "new.ip" in arl.attempts
