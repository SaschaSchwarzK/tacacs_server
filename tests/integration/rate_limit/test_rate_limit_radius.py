import socket
import time

import pytest

from tacacs_server.utils.rate_limiter import RateLimiter, set_rate_limiter


@pytest.mark.integration
def test_radius_auth_rate_limiter_no_response_when_exceeded(server_factory):
    """Configure strict limiter and send bursts of UDP packets.

    We do not assert on response content (unknown client likely gets no reply),
    but ensure the server remains stable under bursts and test completes.
    """
    # Strict limiter to exercise the path
    set_rate_limiter(RateLimiter(max_requests=3, window_seconds=60))

    server = server_factory(enable_tacacs=False, enable_radius=True)
    with server:
        addr = ("127.0.0.1", server.radius_auth_port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.05)
        sent = 0
        # Send a high burst to exceed ~60 req/min token bucket decisively
        for i in range(400):
            try:
                sock.sendto(b"hello", addr)
                sent += 1
            except Exception:
                break
        sock.close()
        assert sent >= 100

        # Poll logs briefly for limiter message
        found = False
        deadline = time.time() + 2.0
        while time.time() < deadline and not found:
            logs = server.get_logs()
            low = logs.lower()
            if (
                "radius rate limit exceeded" in low
                or "rate limit exceeded" in low
                or "rate limit" in low
            ):
                found = True
                break
            time.sleep(0.05)
        assert found, "Expected RADIUS rate limit message in logs"
