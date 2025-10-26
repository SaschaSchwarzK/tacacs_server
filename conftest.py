"""
Early pytest configuration plugin.

This file is loaded early by pytest to set up the test environment
before any test modules are imported.
"""

import os
import socket
import sys


def _find_free_port() -> int:
    """Find a free port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def pytest_configure(config):
    """
    Configure pytest and set early test environment variables.

    This hook runs very early in the pytest lifecycle, before test
    collection and imports, ensuring the test environment is ready.
    """
    # Mark that we're in test mode
    os.environ["TACACS_TEST_MODE"] = "1"

    # Set early defaults for test ports if not already set
    if "TEST_TACACS_PORT" not in os.environ:
        os.environ["TEST_TACACS_PORT"] = str(_find_free_port())

    if "TEST_WEB_PORT" not in os.environ:
        os.environ["TEST_WEB_PORT"] = str(_find_free_port())

    # Set a test API token
    if "TEST_API_TOKEN" not in os.environ:
        os.environ["TEST_API_TOKEN"] = "test-token"

    # Print diagnostic info
    print("[pytest_configure] Test mode enabled", file=sys.stderr)
    print(
        f"[pytest_configure] TEST_TACACS_PORT={os.environ['TEST_TACACS_PORT']}",
        file=sys.stderr,
    )
    print(
        f"[pytest_configure] TEST_WEB_PORT={os.environ['TEST_WEB_PORT']}",
        file=sys.stderr,
    )
