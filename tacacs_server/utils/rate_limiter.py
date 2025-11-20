"""
Rate Limiting for TACACS+ Server

Provides two types of rate limiting:
1. ConnectionLimiter - Limits concurrent TCP connections per IP
2. RateLimiter - Token bucket rate limiter for request rate limiting
"""

import threading
import time

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class ConnectionLimiter:
    """Manages per-IP concurrent connection limits"""

    def __init__(self, max_per_ip: int = 20):
        self._ip_conn_lock = threading.RLock()
        self._ip_connections: dict[str, int] = {}
        self.max_per_ip = max_per_ip
        logger.info("ConnectionLimiter initialized with max_per_ip=%s", max_per_ip)

    def acquire(self, ip: str) -> bool:
        """Try to acquire connection slot for IP"""
        with self._ip_conn_lock:
            current = self._ip_connections.get(ip, 0)
            if current >= self.max_per_ip:
                logger.warning(
                    "Per-IP connection cap exceeded for %s (count=%s/%s, limit=%s)",
                    ip,
                    current,
                    self.max_per_ip,
                    self.max_per_ip,
                )
                return False
            self._ip_connections[ip] = current + 1
            logger.debug(
                "Connection acquired for %s (count=%s/%s)",
                ip,
                current + 1,
                self.max_per_ip,
            )
            return True

    def release(self, ip: str):
        """Release connection slot for IP"""
        with self._ip_conn_lock:
            current = max(0, self._ip_connections.get(ip, 1) - 1)
            if current == 0:
                self._ip_connections.pop(ip, None)
                logger.debug("Connection released for %s (count=0)", ip)
            else:
                self._ip_connections[ip] = current
                logger.debug("Connection released for %s (count=%s)", ip, current)

    def get_count(self, ip: str) -> int:
        """Get current connection count for IP"""
        with self._ip_conn_lock:
            return self._ip_connections.get(ip, 0)


class RateLimiter:
    """Token bucket rate limiter for request rate limiting"""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.buckets: dict[
            str, tuple[int, float]
        ] = {}  # client_ip -> (tokens, last_refill)
        self._lock = threading.RLock()

    def allow_request(self, client_ip: str) -> bool:
        """Check if request is allowed for client IP"""
        now = time.time()

        with self._lock:
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
        with self._lock:
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
        with self._lock:
            to_remove = [
                ip
                for ip, (_, last_refill) in self.buckets.items()
                if now - last_refill > max_age_seconds
            ]
            for ip in to_remove:
                del self.buckets[ip]
        return len(to_remove)


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
