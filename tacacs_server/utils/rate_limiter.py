"""
Rate Limiting for TACACS+ Server

Simple token bucket implementation for protecting against brute force attacks.
"""

import time


class RateLimiter:
    """Token bucket rate limiter"""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.buckets: dict[
            str, tuple[int, float]
        ] = {}  # client_ip -> (tokens, last_refill)  # noqa: E501

    def allow_request(self, client_ip: str) -> bool:
        """Check if request is allowed for client IP"""
        now = time.time()

        if client_ip not in self.buckets:
            # New client - full bucket
            self.buckets[client_ip] = (self.max_requests - 1, now)
            return True

        tokens, last_refill = self.buckets[client_ip]

        # Calculate tokens to add based on time elapsed
        time_passed = now - last_refill
        tokens_to_add = int(time_passed * (self.max_requests / self.window_seconds))

        if tokens_to_add > 0:
            tokens = min(self.max_requests, tokens + tokens_to_add)
            last_refill = now

        if tokens > 0:
            # Allow request and consume token
            self.buckets[client_ip] = (tokens - 1, last_refill)
            return True
        else:
            # Rate limited
            self.buckets[client_ip] = (tokens, last_refill)
            return False

    def get_remaining_tokens(self, client_ip: str) -> int:
        """Get remaining tokens for client IP"""
        if client_ip not in self.buckets:
            return self.max_requests

        tokens, last_refill = self.buckets[client_ip]
        now = time.time()
        time_passed = now - last_refill
        tokens_to_add = int(time_passed * (self.max_requests / self.window_seconds))

        return min(self.max_requests, tokens + tokens_to_add)

    def cleanup_old_entries(self, max_age_seconds: int = 3600):
        """Remove old entries to prevent memory growth"""
        now = time.time()
        to_remove = [
            ip
            for ip, (_, last_refill) in self.buckets.items()
            if now - last_refill > max_age_seconds
        ]
        for ip in to_remove:
            del self.buckets[ip]


# Global rate limiter instance
_rate_limiter = None


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance"""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def set_rate_limiter(limiter: RateLimiter):
    """Set global rate limiter instance"""
    global _rate_limiter
    _rate_limiter = limiter
