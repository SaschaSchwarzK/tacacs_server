"""
Security utilities for TACACS+ server
"""

import re
import time
from collections import defaultdict


class AuthRateLimiter:
    """Rate limiter for authentication attempts"""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300) -> None:
        self.attempts: defaultdict[str, list[float]] = defaultdict(list)
        self.max_attempts = max_attempts
        self.window = window_seconds

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        # Clean old attempts
        self.attempts[client_ip] = [
            t for t in self.attempts[client_ip] if now - t < self.window
        ]
        return len(self.attempts[client_ip]) < self.max_attempts

    def record_attempt(self, client_ip: str) -> None:
        self.attempts[client_ip].append(time.time())


def validate_username(username: str) -> bool:
    """Validate username format"""
    if not username or len(username) > 64:
        return False
    match = re.match(r"^[a-zA-Z0-9._-]+$", username)
    return bool(match is not None)


def sanitize_command(command: str) -> str:
    """Sanitize command for logging"""
    return re.sub(r"[^\w\s.-]", "", command)[:255]
