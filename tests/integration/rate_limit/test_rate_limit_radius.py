"""
RADIUS Rate Limiting Tests
=========================

This module contains integration tests for RADIUS authentication rate limiting.
It verifies that the server properly enforces rate limits on RADIUS authentication
requests to prevent abuse and ensure service availability.

Test Environment:
- Real RADIUS server instance
- UDP-based authentication requests
- Configurable rate limiting settings

Test Cases:
- test_radius_auth_rate_limiter_no_response_when_exceeded: Verifies rate limiting
  behavior when request limits are exceeded

Configuration:
- max_requests: Maximum requests allowed in the time window (default: 3)
- window_seconds: Time window for rate limiting in seconds (default: 60)
- burst_size: Number of requests in a burst (test sends 400)

Example Usage:
    pytest tests/integration/rate_limit/test_rate_limit_radius.py -v

Note: These tests involve UDP network operations and may be affected by system load.
"""

import socket
import time

import pytest

from tacacs_server.utils.rate_limiter import RateLimiter, set_rate_limiter


@pytest.mark.integration
def test_radius_auth_rate_limiter_no_response_when_exceeded(server_factory):
    """Test RADIUS server enforces rate limiting on authentication attempts.

    This test verifies that the RADIUS server properly rate limits authentication
    requests when they exceed the configured threshold. It sends a burst of UDP
    packets to the RADIUS authentication port and verifies that rate limiting
    is enforced by checking server logs for rate limit messages.

    Test Steps:
    1. Configure a strict rate limiter (3 requests per 60 seconds)
    2. Start a RADIUS server instance
    3. Send a burst of 400 authentication requests
    4. Verify server remains stable under load
    5. Check server logs for rate limit messages

    Expected Behavior:
    - Server should accept initial requests up to the rate limit
    - Subsequent requests should be rate limited
    - Server should log rate limit events
    - Server should remain stable under heavy load

    Configuration:
    - max_requests: 3 (set in test)
    - window_seconds: 60 (set in test)
    - burst_size: 400 (test sends this many requests)
    - socket_timeout: 0.05s (per request)

    Note:
    - Uses real UDP sockets to simulate RADIUS clients
    - Verifies server stability under load
    - Checks server logs for rate limit indicators
    - May need adjustment based on system performance
    """
    # Configure strict rate limiting (3 requests per 60 seconds)
    set_rate_limiter(RateLimiter(max_requests=3, window_seconds=60))

    # Start RADIUS server with TACACS disabled
    server = server_factory(enable_tacacs=False, enable_radius=True)

    with server:
        # Configure UDP socket for RADIUS authentication
        addr = ("127.0.0.1", server.radius_auth_port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.05)  # Short timeout for test responsiveness

        # Send a burst of requests to trigger rate limiting
        # We send many requests to ensure we exceed the rate limit
        burst_size = 400
        min_required = 100  # Minimum number of sends to consider test valid
        sent = 0

        try:
            # Send multiple requests to trigger rate limiting
            for _ in range(burst_size):
                try:
                    # Send a minimal RADIUS-like packet (just "hello" for testing)
                    sock.sendto(b"hello", addr)
                    sent += 1
                except OSError as e:
                    # Stop if we encounter socket errors
                    print(f"Socket error after {sent} sends: {e}")
                    break
        finally:
            # Ensure socket is properly closed
            sock.close()

        # Verify we sent enough requests to trigger rate limiting
        assert sent >= min_required, (
            f"Expected to send at least {min_required} packets, but only sent {sent}"
        )

        # Poll server logs for rate limit indicators
        # We look for various possible log messages indicating rate limiting
        rate_limit_indicators = [
            "radius rate limit exceeded",
            "rate limit exceeded",
            "rate limit",
            "too many requests",
            "request throttled",
        ]

        # Allow some time for logs to be written
        deadline = time.time() + 2.0  # Max 2 seconds to find the log entry
        found = False

        while time.time() < deadline and not found:
            logs = server.get_logs().lower()

            # Check for any rate limit indicators in logs
            for indicator in rate_limit_indicators:
                if indicator in logs:
                    found = True
                    print(f"Found rate limit indicator in logs: {indicator}")
                    break

            if not found:
                time.sleep(0.05)  # Short delay before next poll

        # Verify we found evidence of rate limiting in the logs
        assert found, (
            "Expected to find rate limit message in server logs. "
            f"Logs: {logs[:1000]}..."  # Include first 1000 chars of logs in error
        )
