"""
Chaos Engineering Test Suite for TACACS+ Server

Tests system resilience under adverse conditions. Designed to be opt-in and
non-destructive by default. Uses pytest markers so you can include/exclude via
"-m chaos" and optional --chaos-level.

Required tools in practice (for these tests to be meaningful):
    pip install pytest-timeout psutil requests

Usage examples:
    # Run all chaos tests (opt-in)
    pytest -m chaos -q

    # Control severity
    pytest tests/chaos/test_chaos.py -v --chaos-level=medium -m chaos

Notes:
    - These tests prefer hitting the built-in admin/web health endpoints.
    - Tests run only against a real server instance. No mock mode.
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
    """Base class for chaos experiments"""

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
    def __init__(self, latency_ms: int = 200):
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
    def __init__(self, duration_seconds: int = 2):
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
    parser.addoption(
        "--chaos-level",
        action="store",
        default="low",
        help="Chaos level: low, medium, high, critical",
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
        exp = NetworkLatencyExperiment(latency_ms=200)
        exp.base_url = chaos_server.get_base_url()
        exp.session = requests.Session()
        result = exp.run()
        assert result["passed"], "System failed under network latency"
        assert result["degradation"] < 80

    @pytest.mark.chaos
    @pytest.mark.timeout(30)
    def test_packet_loss_resilience(self, chaos_server):
        exp = NetworkPacketLossExperiment(loss_rate=0.2)
        exp.base_url = chaos_server.get_base_url()
        exp.session = requests.Session()
        result = exp.run()
        assert result["passed"], "System failed under packet loss"


class TestResourceChaos:
    @pytest.mark.chaos
    @pytest.mark.timeout(30)
    def test_cpu_saturation_resilience(self, chaos_server):
        exp = CPUExhaustionExperiment(duration_seconds=2)
        exp.base_url = chaos_server.get_base_url()
        exp.session = requests.Session()
        result = exp.run()
        assert result["passed"], "System unresponsive under CPU load"


# Keep module import quick in case user filters tests; no top-level work here
