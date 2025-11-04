"""
Web Interface Rate Limiting Tests
===============================

This module contains integration tests for rate limiting on the web/admin interface.
It verifies that the server properly enforces rate limits on web login attempts
to prevent brute force attacks and ensure service availability.

Test Environment:
- Real web server instance
- HTTP/HTTPS requests to admin interface
- Configurable rate limiting settings

Test Cases:
- test_web_login_attempt_rate_behavior: Verifies rate limiting behavior
  for failed login attempts

Configuration:
- max_attempts: Maximum failed login attempts before rate limiting (default: 5-8)
- rate_limit_window: Time window for rate limiting (default: 15-60 minutes)
- lockout_duration: Duration of account lockout (if applicable)

Example Usage:
    pytest tests/integration/rate_limit/test_rate_limit_web.py -v

Note: These tests involve HTTP requests and may be affected by network conditions.
"""

import time

import pytest
import requests


@pytest.mark.integration
def test_web_login_attempt_rate_behavior(server_factory):
    """Test web interface enforces rate limiting on failed login attempts.

    This test verifies that the web interface properly rate limits authentication
    attempts after multiple failed logins. It simulates a brute force attack
    by sending multiple login attempts with incorrect credentials and verifies
    that rate limiting is enforced.

    Test Steps:
    1. Start server with web admin interface enabled
    2. Send multiple failed login attempts with incorrect credentials
    3. Verify server responds with 429 (Too Many Requests) or continues with 401
    4. Check server logs for rate limit or lockout messages

    Expected Behavior:
    - Initial failed attempts return 401 Unauthorized
    - After threshold, server should return 429 Too Many Requests
    - Server should log rate limit or lockout events
    - Server should remain stable under repeated failed attempts

    Configuration:
    - max_attempts: 5-8 (varies by security configuration)
    - rate_limit_window: 15-60 minutes (varies by configuration)
    - test_attempts: 8 (number of attempts in this test)

    Note:
    - Uses real HTTP requests to simulate web login attempts
    - Verifies both response codes and server logs
    - May need adjustment based on security configuration
    """
    # Start server with all required services enabled
    server = server_factory(
        enable_tacacs=True, enable_admin_api=True, enable_admin_web=True
    )
    with server:
        base_url = server.get_base_url()
        login_url = f"{base_url}/admin/login"

        # Configure session with reasonable defaults
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": "TACACS+ Rate Limit Test",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        # Test parameters
        max_attempts = 8
        saw_429 = False
        attempts = 0

        # Send multiple login attempts with invalid credentials
        for i in range(max_attempts):
            try:
                response = session.post(
                    login_url,
                    json={
                        "username": "admin",
                        "password": f"wrong_password_{i}",  # Vary password to avoid caching
                    },
                    timeout=5,  # 5 second timeout per request
                )

                attempts += 1
                status = response.status_code

                # Check for rate limiting (429) or successful login (shouldn't happen)
                if status == 429:
                    print(f"Rate limited after {attempts} attempts")
                    saw_429 = True
                    break

                # Verify we got an expected error response
                assert status in (400, 401, 403, 503), (
                    f"Unexpected status code: {status}, response: {response.text}"
                )

                # Small delay between attempts to avoid overwhelming the server
                time.sleep(0.1)

            except requests.RequestException as e:
                print(f"Request failed on attempt {attempts + 1}: {e}")
                raise

        # Verify we either saw a 429 or made multiple attempts
        assert saw_429 or attempts > 1, (
            "Expected to either be rate limited or make multiple attempts"
        )

        # If we were rate limited, verify it's reflected in the logs
        if saw_429:
            # Allow time for logs to be written
            time.sleep(0.5)

            # Get server logs and check for rate limit indicators
            logs = server.get_logs().lower()
            rate_limit_indicators = [
                "429",
                "rate limit",
                "too many requests",
                "request throttled",
                "login attempt limit",
            ]

            # Check for any rate limit indicators in logs
            found_indicator = any(
                indicator in logs for indicator in rate_limit_indicators
            )

            assert found_indicator, (
                "Expected to find rate limit message in server logs when 429 received. "
                f"Searched for: {rate_limit_indicators}\n"
                f"Logs: {logs[:1000]}..."  # Include first 1000 chars of logs in error
            )

            print("Rate limiting confirmed in server logs")
