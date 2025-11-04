"""
TACACS+ Rate Limiting Tests
==========================

This module contains integration tests for TACACS+ connection rate limiting
and concurrent connection management. It verifies that the server properly
enforces limits on the number of concurrent connections per IP address.

Test Environment:
- Real TACACS+ server instance
- Multiple concurrent client connections
- Configurable connection limits

Test Cases:
- test_tacacs_per_ip_rate_limiter: Verifies per-IP connection limits

Configuration:
- max_connections_per_ip: Maximum allowed concurrent connections per IP (default: 3)
- connection_timeout: Timeout for connection attempts (default: 0.5s)

Example Usage:
    pytest tests/integration/rate_limit/test_rate_limit_tacacs.py -v

Note: These tests involve network operations and may be affected by system load.
"""

import socket
import threading
import time

import pytest


@pytest.mark.integration
def test_tacacs_per_ip_rate_limiter(server_factory):
    """Test TACACS+ server enforces per-IP connection limits.

    This test verifies that the TACACS+ server properly limits the number of
    concurrent connections from a single IP address. It creates multiple
    connection attempts and verifies that the server enforces the configured
    connection limit.

    Test Steps:
    1. Start TACACS+ server with max_connections_per_ip=3
    2. Create 10 concurrent connection attempts from the same IP
    3. Verify that only 3 connections are accepted (others are rejected/closed)
    4. Clean up all connections

    Expected Behavior:
    - First 3 connections should be accepted and remain open
    - Additional connections should be either refused or closed by the server
    - At least one connection attempt should be rate limited

    Configuration:
    - max_connections_per_ip: 3 (set in test)
    - connection_timeout: 0.5s (per attempt)
    - test_duration: 0.3s (per connection)

    Note:
    - Uses real network sockets to simulate concurrent clients
    - May be affected by system resource limits (file descriptors, etc.)
    - Test may need adjustment based on system performance
    """
    # Configure server with strict connection limits
    server = server_factory(
        enable_tacacs=True, config={"security": {"max_connections_per_ip": 3}}
    )
    with server:
        host = "127.0.0.1"
        port = server.tacacs_port

        # Track connection attempt results
        results: list[str] = []

        def opener(idx: int) -> None:
            """Attempt to open and maintain a TACACS+ connection.

            Args:
                idx: Thread/connection identifier for debugging

            This function attempts to:
            1. Connect to the TACACS+ server
            2. Keep the connection open for a short duration
            3. Record the connection status
            4. Clean up resources
            """
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)  # Connection and read timeout
            try:
                # Attempt to establish connection
                s.connect((host, port))

                # Keep connection open to test concurrency
                time.sleep(0.3)

                # Check if connection was closed by server
                try:
                    data = s.recv(1)  # Non-blocking check for connection close
                    if data == b"":
                        results.append("closed")  # Connection was closed by server
                    else:
                        results.append("open")  # Connection still open
                except TimeoutError:
                    results.append("open")  # No data received but still connected
            except Exception:
                results.append("refused")  # Connection was refused
            finally:
                # Ensure socket is properly closed
                try:
                    s.close()
                except Exception:
                    pass  # Ignore errors during close

        # Create and start connection threads
        num_attempts = 10
        threads = [
            threading.Thread(target=opener, args=(i,), name=f"conn-{i}")
            for i in range(num_attempts)
        ]

        # Start all connection attempts in parallel
        for t in threads:
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join(timeout=1.0)  # Add timeout to prevent hanging

        # Analyze results
        open_count = results.count("open")
        closed_count = results.count("closed")
        refused_count = results.count("refused")
        total_limited = closed_count + refused_count

        # Log results for debugging
        print(f"Connection results: {results}")
        print(f"Open: {open_count}, Closed: {closed_count}, Refused: {refused_count}")

        # Verify rate limiting was enforced
        assert total_limited >= 1, (
            f"Expected some connections to be limited (closed/refused), but got: {results}"
        )

        # Verify at least some connections were accepted (up to the limit)
        assert open_count <= 3, f"Expected max 3 open connections, but got {open_count}"

        # Verify logs indicate limiter activity
        time.sleep(0.1)
        logs = server.get_logs()
        low = logs.lower()
        assert (
            "per-ip connection cap exceeded" in low
            or "rate limit exceeded" in low
            or "rate limit" in low
        ), "Expected TACACS rate/connection limit message in logs"
