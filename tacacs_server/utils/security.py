"""
Security utilities for TACACS+ server
"""

import re
import time
from collections import defaultdict

from .constants import MAX_USERNAME_LENGTH


class AuthRateLimiter:
    """Rate limiter for authentication attempts.

    Tracks attempts per client IP within a sliding time window. To avoid
    unbounded memory growth in long-running processes with many unique IPs,
    stale entries are periodically cleaned up.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300) -> None:
        self.attempts: defaultdict[str, list[float]] = defaultdict(list)
        self.max_attempts = max_attempts
        self.window = window_seconds
        # Counter for lightweight periodic cleanup
        self._checks = 0

    def cleanup_old_ips(self) -> None:
        """Remove IPs that have no recent attempts.

        An IP is considered stale if its most recent attempt is older than
        twice the configured window size. This keeps the structure bounded
        without affecting active clients.
        """
        now = time.time()
        threshold = self.window * 2
        stale_ips = []
        for ip, timestamps in list(self.attempts.items()):
            if not timestamps:
                stale_ips.append(ip)
                continue
            # If the newest attempt is too old, drop the IP entirely
            if now - max(timestamps) > threshold:
                stale_ips.append(ip)
        for ip in stale_ips:
            try:
                del self.attempts[ip]
            except KeyError:
                # Concurrent access may delete between collection and removal
                continue

    def is_allowed(self, client_ip: str) -> bool:
        # Periodically prune stale IPs to avoid unbounded growth
        self._checks += 1
        if self._checks >= 1000:
            self._checks = 0
            self.cleanup_old_ips()

        now = time.time()
        # Clean old attempts for this IP
        self.attempts[client_ip] = [
            t for t in self.attempts[client_ip] if now - t < self.window
        ]
        return len(self.attempts[client_ip]) < self.max_attempts

    def record_attempt(self, client_ip: str) -> None:
        self.attempts[client_ip].append(time.time())


def validate_username(username: str) -> bool:
    """Validate username format.

    Allows alphanumerics plus '.', '_', '-', and '@' to support common
    directory/email-style usernames. Enforces a maximum length via constant.
    The regex is safe from ReDoS as it only uses a simple character class
    with a single repeating quantifier and no nested alternation.
    """
    if not username or len(username) > MAX_USERNAME_LENGTH:
        return False
    match = re.match(r"^[a-zA-Z0-9._@-]+$", username)
    return bool(match is not None)


def sanitize_command(command: str) -> str:
    """Sanitize command for logging"""
    return re.sub(r"[^\w\s.-]", "", command)[:255]
