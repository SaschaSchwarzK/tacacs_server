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
