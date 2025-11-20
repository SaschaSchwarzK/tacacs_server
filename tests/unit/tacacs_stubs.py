"""
Test stubs and utilities for TACACS+ server unit tests.

This module provides mock implementations and test utilities used across multiple
test modules. It includes:
- Stub implementations for Prometheus metrics
- Module stubs to avoid importing heavy dependencies
- Global test state management
- Common test constants and utilities

The stubs allow tests to run in isolation without requiring external services
or complex test setup.
"""

import sys
from pathlib import Path
from types import ModuleType

# Root directory of the repository for resolving package paths
REPO_ROOT = Path(__file__).resolve().parents[2]

# Create a minimal package stub so tests can import tacacs_server.tacacs without
# initializing the full server stack (which requires third-party dependencies)
tacacs_pkg = ModuleType("tacacs_server.tacacs")
tacacs_pkg.__path__ = [str(REPO_ROOT / "tacacs_server" / "tacacs")]
sys.modules.setdefault("tacacs_server.tacacs", tacacs_pkg)

# Global state for tracking Prometheus metrics in tests
PROMETHEUS_COMMANDS: list[str] = []
"""Tracks command authorization results for Prometheus metric verification."""

PROMETHEUS_ACTIVE: list[int] = []
"""Tracks active connection counts for Prometheus metric verification."""


class _PrometheusIntegrationStub:
    """Stub implementation of Prometheus metrics for testing.

    Captures metric updates in global lists for verification in test assertions.
    This avoids requiring a real Prometheus client during testing.
    """

    @staticmethod
    def record_command_authorization(result: str) -> None:
        """Record a command authorization result.

        Args:
            result: The authorization result to record (e.g., 'granted', 'denied')
        """
        PROMETHEUS_COMMANDS.append(result)

    @staticmethod
    def update_active_connections(value: int) -> None:
        """Update the active connections counter.

        Args:
            value: The current number of active connections
        """
        PROMETHEUS_ACTIVE.append(value)


class StubDBLogger:
    """Stub database logger for testing database interactions.

    Simulates database operations without requiring a real database connection.
    Tracks active sessions and provides mock statistics.
    """

    def __init__(self, *args, **kwargs):
        """Initialize with a default session."""
        self._sessions = ["session-1"]

    def get_active_sessions(self) -> list[str]:
        """Return list of active session IDs.

        Returns:
            List of session ID strings
        """
        return list(self._sessions)

    def get_statistics(self, days: int = 1) -> dict:
        """Return mock statistics.

        Args:
            days: Number of days to include in statistics (ignored in stub)

        Returns:
            Dictionary with mock statistics
        """
        return {"total_records": 5}

    def ping(self) -> bool:
        """Check database connectivity.

        Returns:
            Always returns True in the stub implementation
        """
        return True

    def close(self) -> None:
        """Clean up test sessions."""
        self._sessions.clear()
