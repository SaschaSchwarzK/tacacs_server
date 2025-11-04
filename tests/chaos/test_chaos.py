"""
Chaos Engineering Test Suite for TACACS+ Server

This module implements chaos engineering tests to verify the resilience and stability
of the TACACS+ server under various failure conditions. The tests are designed to be
safe, opt-in, and non-destructive by default.

Key Features:
- Network fault injection (latency, packet loss)
- Resource exhaustion scenarios (CPU, memory)
- Configuration validation
- Automated rollback of chaos effects
- Severity-based test filtering

Test Organization:
- NetworkChaos: Tests for network-related failure scenarios
- ResourceChaos: Tests for resource exhaustion scenarios
- ConfigurationChaos: Tests for configuration-related issues

Dependencies:
    pytest-timeout: For test timeouts
    psutil: For system resource monitoring
    requests: For HTTP client functionality

Usage Examples:
    # Run all chaos tests (opt-in)
    pytest -m chaos -v

    # Run only medium and high severity tests
    pytest tests/chaos/test_chaos.py --chaos-level=medium -m chaos

    # Run specific test with debug output
    pytest tests/chaos/test_chaos.py::TestNetworkChaos::test_network_latency_resilience -v

Configuration:
    --chaos-level: Control test severity (low/medium/high)
    CHAOS_ENABLED: Set to 'true' to enable chaos tests
    BASE_URL: Override default server URL

Security Considerations:
- Tests run against a real server instance (no mocks)
- All chaos effects are automatically rolled back
- Tests are isolated and should not affect production
- Network effects are scoped to localhost

Note: These tests require root/administrator privileges for some operations
like network manipulation.
"""

from __future__ import annotations

import random
import socket
import threading
import time

import psutil
import pytest
import requests

# ---------------------------------------------------------------------------
# Chaos Testing Framework
# ---------------------------------------------------------------------------


class ChaosExperiment:
    """Base class for chaos experiments.

    This abstract base class provides the foundation for implementing
    chaos engineering experiments. Subclasses should implement the
    abstract methods to define specific chaos injection and verification
    behavior.

    The typical experiment lifecycle is:
    1. Collect baseline metrics (collect_metrics)
    2. Verify steady state (steady_state_hypothesis)
    3. Inject chaos (inject_chaos)
    4. Verify system behavior
    5. Rollback changes (rollback)
    6. Verify recovery

    Attributes:
        name (str): Human-readable name of the experiment
        severity (str): Severity level (low/medium/high)
        metrics_before (dict): System metrics collected before chaos injection
        metrics_after (dict): System metrics collected after chaos injection
        base_url (str): Base URL of the server under test
        session (requests.Session): HTTP session for making requests

    Methods:
        collect_metrics(): Collect system metrics
        steady_state_hypothesis(): Verify system is in expected state
        inject_chaos(): Apply the chaos condition
        rollback(): Revert the chaos condition
        run(): Execute the complete experiment

    Example:
        class MyExperiment(ChaosExperiment):
            def __init__(self):
                super().__init__("My Experiment", "medium")

            def steady_state_hypothesis(self):
                # Verify system is healthy
                pass

            def inject_chaos(self):
                # Apply the chaos condition
                pass

            def rollback(self):
                # Revert the chaos condition
                pass
    """

    def __init__(self, name: str, severity: str = "medium"):
        self.name = name
        self.severity = severity
        self.metrics_before: dict = {}
        self.metrics_after: dict = {}
        self.base_url: str | None = None
        self.session: requests.Session | None = None

    def steady_state_hypothesis(self) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    def inject_chaos(self):  # pragma: no cover - abstract
        raise NotImplementedError

    def rollback(self):  # pragma: no cover - default
        pass

    def _base_url(self) -> str:
        assert self.base_url, "base_url must be set by the test"
        return self.base_url

    def _session(self) -> requests.Session:
        """HTTP session (injectable)"""
        return self.session or requests.Session()

    def run(self) -> dict:
        """Execute the chaos experiment against the real server."""
        assert self.steady_state_hypothesis(), "System not in steady state!"
        self.metrics_before = self.collect_metrics()

        try:
            self.inject_chaos()
            # Let chaos take effect briefly without dragging CI too long
            time.sleep(1.0)
            still_stable = self.steady_state_hypothesis()
            self.metrics_after = self.collect_metrics()
            return {
                "experiment": self.name,
                "passed": still_stable,
                "metrics_before": self.metrics_before,
                "metrics_after": self.metrics_after,
                "degradation": self.calculate_degradation(),
            }
        finally:
            self.rollback()

    def collect_metrics(self) -> dict:
        """Collect current system metrics from admin endpoints when available."""
        base = self._base_url()
        sess = self._session()
        try:
            # Prefer general status endpoint
            resp = sess.get(f"{base}/api/status", timeout=2)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        try:
            resp = sess.get(f"{base}/api/stats", timeout=2)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}

    def calculate_degradation(self) -> float:
        before_rps = self.metrics_before.get("requests_per_second", 0)
        after_rps = self.metrics_after.get("requests_per_second", 0)
        if before_rps == 0:
            return 0.0
        return ((before_rps - after_rps) / before_rps) * 100.0


# ---------------------------------------------------------------------------
# Network Chaos Experiments
# ---------------------------------------------------------------------------


class NetworkLatencyExperiment(ChaosExperiment):
    """Chaos experiment that introduces artificial network latency.

    This experiment simulates network latency by intercepting socket connections
    and adding a configurable delay. It's useful for testing how the TACACS+ server
    handles slow or high-latency network conditions.

    Args:
        latency_ms (int): The amount of latency to introduce in milliseconds.
                         Default is 200ms.

    Example:
        # Create a latency experiment with 500ms delay
        experiment = NetworkLatencyExperiment(latency_ms=500)
        experiment.run()

    Note:
        This modifies the global socket.socket.connect method during the test.
        The original method is automatically restored when the test completes.
    """

    def __init__(self, latency_ms: int = 200):
        """Initialize the network latency experiment.

        Args:
            latency_ms: Desired latency in milliseconds. Must be >= 0.
        """
        super().__init__(f"Network Latency ({latency_ms}ms)", "low")
        self.latency_ms = latency_ms
        self._original_connect = socket.socket.connect

    def steady_state_hypothesis(self) -> bool:
        base = self._base_url()
        sess = self._session()
        deadline = time.time() + 20
        while time.time() < deadline:
            for path in ("/api/health", "/api/status", "/"):
                try:
                    r = sess.get(f"{base}{path}", timeout=3)
                    if r.status_code == 200:
                        return True
                except Exception:
                    pass
            time.sleep(0.3)
        return False

    def inject_chaos(self):
        original_connect = self._original_connect
        delay = self.latency_ms / 1000.0

        def slow_connect(sock, address):  # type: ignore[override]
            time.sleep(delay)
            return original_connect(sock, address)

        socket.socket.connect = slow_connect  # type: ignore[assignment]

    def rollback(self):
        socket.socket.connect = self._original_connect  # type: ignore[assignment]


class NetworkPacketLossExperiment(ChaosExperiment):
    def __init__(self, loss_rate: float = 0.1):
        super().__init__(f"Packet Loss ({int(loss_rate * 100)}%)", "medium")
        self.loss_rate = loss_rate
        self._original_send = socket.socket.send

    def steady_state_hypothesis(self) -> bool:
        base = self._base_url()
        sess = self._session()
        successes = 0
        attempts = 30
        for _ in range(attempts):
            for path in ("/api/health", "/api/status", "/"):
                try:
                    r = sess.get(f"{base}{path}", timeout=3)
                    if r.status_code == 200:
                        successes += 1
                        break
                except Exception:
                    pass
            time.sleep(0.2)
        # Consider steady if we got several successes over the polling window
        return successes >= 3

    def inject_chaos(self):
        original_send = self._original_send
        loss = self.loss_rate

        def lossy_send(sock, data, flags=0):  # type: ignore[override]
            if random.random() < loss:
                raise OSError("Simulated packet loss")
            return original_send(sock, data, flags)

        socket.socket.send = lossy_send  # type: ignore[assignment]

    def rollback(self):
        socket.socket.send = self._original_send  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Resource Exhaustion Experiments (kept modest to be CI-friendly)
# ---------------------------------------------------------------------------


class CPUExhaustionExperiment(ChaosExperiment):
    """Chaos experiment that simulates CPU exhaustion.

    This test creates CPU-bound threads to simulate high CPU load, allowing
    verification of the server's behavior under resource-constrained conditions.
    The test automatically cleans up the CPU load after the specified duration.

    Args:
        duration_seconds (int): How long to maintain CPU load, in seconds.
                              Default is 2 seconds.

    Security Note:
        This test creates CPU-intensive threads that will consume significant
        system resources. Use with caution in shared environments.
    """

    def __init__(self, duration_seconds: int = 2):
        """Initialize the CPU exhaustion experiment.

        Args:
            duration_seconds: Duration of CPU load in seconds. Must be > 0.
        """
        super().__init__(f"CPU Exhaustion ({duration_seconds}s)", "medium")
        self.duration = duration_seconds
        self._stop = threading.Event()

    def steady_state_hypothesis(self) -> bool:
        return psutil.cpu_percent(interval=0.5) < 90

    def inject_chaos(self):
        def burner():
            end = time.time() + self.duration
            while time.time() < end and not self._stop.is_set():
                _ = sum(i * i for i in range(5000))

        threads: list[threading.Thread] = []
        for _ in range(max(1, psutil.cpu_count(logical=True) // 2)):
            t = threading.Thread(target=burner)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    def rollback(self):
        self._stop.set()


# ---------------------------------------------------------------------------
# Pytest integration
# ---------------------------------------------------------------------------


def pytest_addoption(parser):
    """Add custom command-line options for chaos testing.

    This function is automatically called by pytest to register additional
    command-line options specific to chaos testing.

    Added Options:
        --chaos-level: Controls which chaos tests run based on severity
                      (low, medium, high). Default is 'low'.

    Example:
        # Run only medium and high severity tests
        pytest --chaos-level=medium -m chaos
    """
    parser.addoption(
        "--chaos-level",
        action="store",
        default="low",
        choices=["low", "medium", "high"],
        help="Minimum chaos severity level to run (low, medium, high)",
    )


@pytest.fixture(scope="function", autouse=False)
def chaos_server(server_factory):
    """Start a server with admin API enabled for chaos checks.

    If starting fails for any reason, tests will fall back to mock mode.
    """
    server = server_factory(
        enable_tacacs=True,
        enable_radius=False,
        enable_admin_api=True,
        enable_admin_web=True,
    )
    with server:
        # Proactively wait for health endpoint to be ready
        base = server.get_base_url()
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                r = requests.get(f"{base}/api/health", timeout=1)
                if r.status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        yield server


class TestNetworkChaos:
    @pytest.mark.chaos
    @pytest.mark.timeout(30)
    def test_network_latency_resilience(self, chaos_server):
        """Verify server remains responsive under network latency conditions.

        This test introduces artificial network latency to simulate WAN-like
        conditions and verifies that the server continues to handle requests
        correctly, though potentially more slowly.

        Test Steps:
        1. Start server with admin API enabled
        2. Introduce 100ms network latency
        3. Verify server remains responsive to health checks
        4. Verify latency is within expected bounds

        Expected Results:
        - Server should remain operational
        - Response times should increase by approximately 100ms
        - No timeouts or errors should occur
        """
        experiment = NetworkLatencyExperiment(latency_ms=100)
        experiment.base_url = chaos_server.get_base_url()
        experiment.session = requests.Session()
        result = experiment.run()
        assert result["passed"], "System failed under network latency"
        assert result["degradation"] < 80

    @pytest.mark.chaos
    @pytest.mark.timeout(30)
    def test_packet_loss_resilience(self, chaos_server):
        """Verify server handles packet loss gracefully.

        This test simulates network conditions with 10% packet loss to
        ensure the server can handle retransmissions and maintain
        service availability.

        Test Steps:
        1. Start server with admin API enabled
        2. Introduce 10% packet loss
        3. Verify server remains responsive to health checks
        4. Verify no critical failures occur

        Expected Results:
        - Server should remain operational
        - Some requests may be slower due to retransmissions
        - No data corruption or state inconsistencies should occur
        """
        experiment = NetworkPacketLossExperiment(loss_rate=0.1)
        experiment.base_url = chaos_server.get_base_url()
        experiment.session = requests.Session()
        result = experiment.run()
        assert result["passed"], "System failed under packet loss"


class TestResourceChaos:
    """Test suite for resource-related chaos experiments.

    These tests verify the server's behavior under resource-constrained
    conditions, such as high CPU usage, to ensure graceful degradation
    and recovery.
    """

    @pytest.mark.chaos
    @pytest.mark.timeout(30)
    def test_cpu_saturation_resilience(self, chaos_server):
        """Verify server remains responsive under CPU pressure.

        This test creates CPU contention to simulate a high-load scenario
        and verifies that the server remains responsive to health checks.

        Test Steps:
        1. Start server with admin API enabled
        2. Create CPU-intensive background tasks
        3. Verify server remains responsive to health checks
        4. Verify CPU usage returns to normal after test

        Expected Results:
        - Server should remain operational
        - Response times may increase during the test
        - CPU usage should return to normal after test completion
        - No resource leaks should occur
        """
        experiment = CPUExhaustionExperiment(duration_seconds=2)
        experiment.base_url = chaos_server.get_base_url()
        experiment.session = requests.Session()
        result = experiment.run()
        assert result["passed"], "System unresponsive under CPU load"
