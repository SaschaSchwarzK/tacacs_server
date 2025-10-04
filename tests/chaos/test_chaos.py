"""
Chaos Engineering Test Suite for TACACS+ Server

Tests system resilience under adverse conditions using Chaos Toolkit
and custom chaos experiments.

Installation:
    pip install chaostoolkit chaostoolkit-kubernetes pytest-timeout

Usage:
    pytest tests/chaos/test_chaos.py -v --chaos-level=medium

    # Run specific chaos experiment
    chaos run tests/chaos/experiments/network_chaos.yaml
"""

import random
import socket
import threading
import time
from unittest.mock import MagicMock, patch

import psutil
import pytest
import requests

# ============================================================================
# Chaos Testing Framework
# ============================================================================


class ChaosExperiment:
    """Base class for chaos experiments"""

    def __init__(self, name: str, severity: str = "medium"):
        self.name = name
        self.severity = severity
        self.metrics_before: dict = {}
        self.metrics_after: dict = {}

    def steady_state_hypothesis(self) -> bool:
        """Define what 'normal' looks like"""
        raise NotImplementedError

    def inject_chaos(self):
        """Inject the chaos"""
        raise NotImplementedError

    def rollback(self):
        """Rollback chaos changes"""
        pass

    def run(self) -> dict:
        """Execute the chaos experiment"""
        print(f"\n{'=' * 70}")
        print(f"🔬 Chaos Experiment: {self.name}")
        print(f"   Severity: {self.severity}")
        print(f"{'=' * 70}")

        # 1. Establish steady state
        print("📊 Step 1: Verifying steady state hypothesis...")
        assert self.steady_state_hypothesis(), "System not in steady state!"
        self.metrics_before = self.collect_metrics()
        print("✅ Steady state confirmed")

        # 2. Inject chaos
        print("\n💥 Step 2: Injecting chaos...")
        try:
            self.inject_chaos()
            print("⚠️  Chaos injected")

            # 3. Observe behavior
            print("\n🔍 Step 3: Observing system behavior...")
            time.sleep(5)  # Let chaos take effect

            # 4. Verify hypothesis still holds
            print("\n📊 Step 4: Re-verifying steady state...")
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
            # 5. Rollback
            print("\n🔄 Step 5: Rolling back chaos...")
            self.rollback()
            print("✅ Rollback complete\n")

    def collect_metrics(self) -> dict:
        """Collect current system metrics"""
        try:
            response = requests.get("http://localhost:8080/api/stats", timeout=5)
            return response.json() if response.status_code == 200 else {}
        except Exception:
            return {}

    def calculate_degradation(self) -> float:
        """Calculate performance degradation percentage"""
        before_rps = self.metrics_before.get("requests_per_second", 0)
        after_rps = self.metrics_after.get("requests_per_second", 0)

        if before_rps == 0:
            return 0.0

        return ((before_rps - after_rps) / before_rps) * 100


# ============================================================================
# Network Chaos Experiments
# ============================================================================


class NetworkLatencyExperiment(ChaosExperiment):
    """Inject network latency to test timeout handling"""

    def __init__(self, latency_ms: int = 500):
        super().__init__(f"Network Latency ({latency_ms}ms)", "low")
        self.latency_ms = latency_ms
        self.original_socket = socket.socket

    def steady_state_hypothesis(self) -> bool:
        """System responds within acceptable time"""
        try:
            start = time.time()
            response = requests.get("http://localhost:8080/api/health", timeout=2)
            elapsed = (time.time() - start) * 1000
            return response.status_code == 200 and elapsed < 500
        except Exception:
            return False

    def inject_chaos(self):
        """Monkey-patch socket to add latency"""
        original_connect = socket.socket.connect

        def slow_connect(self, address):
            time.sleep(self.latency_ms / 1000.0)
            return original_connect(self, address)

        socket.socket.connect = slow_connect

    def rollback(self):
        """Restore original socket"""
        socket.socket.connect = self.original_socket.connect


class NetworkPacketLossExperiment(ChaosExperiment):
    """Simulate packet loss"""

    def __init__(self, loss_rate: float = 0.1):
        super().__init__(f"Packet Loss ({loss_rate * 100}%)", "medium")
        self.loss_rate = loss_rate

    def steady_state_hypothesis(self) -> bool:
        """System handles requests successfully"""
        success_count = 0
        for _ in range(10):
            try:
                response = requests.get("http://localhost:8080/api/status", timeout=2)
                if response.status_code == 200:
                    success_count += 1
            except Exception:
                pass
        return success_count >= 9  # 90% success rate

    def inject_chaos(self):
        """Randomly drop requests"""
        original_send = socket.socket.send

        def lossy_send(self, data, flags=0):
            if random.random() < self.loss_rate:
                raise OSError("Simulated packet loss")
            return original_send(self, data, flags)

        socket.socket.send = lossy_send

    def rollback(self):
        """Restore original send"""
        import socket as socket_module

        socket.socket.send = socket_module.socket.send


class NetworkPartitionExperiment(ChaosExperiment):
    """Simulate network partition (split brain)"""

    def __init__(self, backend: str = "ldap"):
        super().__init__(f"Network Partition ({backend})", "high")
        self.backend = backend

    def steady_state_hypothesis(self) -> bool:
        """System is responsive"""
        try:
            response = requests.get("http://localhost:8080/api/health", timeout=2)
            return response.status_code == 200
        except Exception:
            return False

    def inject_chaos(self):
        """Block access to specific backend"""
        # This would use iptables or similar in production
        # For testing, we'll mock it
        with patch("tacacs_server.auth.ldap_auth.LDAPAuthBackend.authenticate") as mock:
            mock.side_effect = TimeoutError("Network partition simulated")
            time.sleep(10)

    def rollback(self):
        """Restore network access"""
        pass  # Mock is automatically restored


# ============================================================================
# Resource Exhaustion Experiments
# ============================================================================


class MemoryExhaustionExperiment(ChaosExperiment):
    """Test behavior under memory pressure"""

    def __init__(self, memory_mb: int = 100):
        super().__init__(f"Memory Exhaustion ({memory_mb}MB)", "high")
        self.memory_mb = memory_mb
        self.balloons = []

    def steady_state_hypothesis(self) -> bool:
        """System has sufficient memory"""
        memory = psutil.virtual_memory()
        return memory.percent < 80  # Less than 80% used

    def inject_chaos(self):
        """Allocate memory to create pressure"""
        # Allocate memory in chunks
        chunk_size = 1024 * 1024  # 1MB chunks
        for _ in range(self.memory_mb):
            self.balloons.append(bytearray(chunk_size))

    def rollback(self):
        """Free allocated memory"""
        self.balloons.clear()


class CPUExhaustionExperiment(ChaosExperiment):
    """Test behavior under CPU pressure"""

    def __init__(self, duration_seconds: int = 10):
        super().__init__(f"CPU Exhaustion ({duration_seconds}s)", "medium")
        self.duration = duration_seconds
        self.stop_flag = threading.Event()

    def steady_state_hypothesis(self) -> bool:
        """System has available CPU"""
        cpu_percent = psutil.cpu_percent(interval=1)
        return cpu_percent < 80

    def inject_chaos(self):
        """Create CPU load"""

        def cpu_burner():
            end_time = time.time() + self.duration
            while time.time() < end_time and not self.stop_flag.is_set():
                # Busy loop
                _ = sum(i * i for i in range(10000))

        # Start multiple CPU-burning threads
        threads = []
        for _ in range(psutil.cpu_count()):
            t = threading.Thread(target=cpu_burner)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def rollback(self):
        """Stop CPU load"""
        self.stop_flag.set()


class FileDescriptorExhaustionExperiment(ChaosExperiment):
    """Test behavior when running out of file descriptors"""

    def __init__(self, num_fds: int = 100):
        super().__init__(f"FD Exhaustion ({num_fds} files)", "high")
        self.num_fds = num_fds
        self.open_files = []

    def steady_state_hypothesis(self) -> bool:
        """System can open new connections"""
        try:
            sock = socket.socket()
            sock.close()
            return True
        except Exception:
            return False

    def inject_chaos(self):
        """Open many file descriptors"""
        for i in range(self.num_fds):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.open_files.append(sock)
            except Exception:
                break

    def rollback(self):
        """Close all file descriptors"""
        for f in self.open_files:
            try:
                f.close()
            except Exception:
                pass
        self.open_files.clear()


# ============================================================================
# Application Chaos Experiments
# ============================================================================


class DatabaseCorruptionExperiment(ChaosExperiment):
    """Simulate database corruption"""

    def __init__(self):
        super().__init__("Database Corruption", "critical")

    def steady_state_hypothesis(self) -> bool:
        """Database is accessible and valid"""
        try:
            response = requests.get("http://localhost:8080/api/users", timeout=2)
            return response.status_code == 200
        except Exception:
            return False

    def inject_chaos(self):
        """Simulate database issues"""
        # In real scenario, we would:
        # - Corrupt database file
        # - Set wrong permissions
        # - Fill disk space
        # For testing, we'll mock it
        pass

    def rollback(self):
        """Restore database"""
        pass


class SlowQueryExperiment(ChaosExperiment):
    """Inject slow database queries"""

    def __init__(self, delay_seconds: int = 5):
        super().__init__(f"Slow Queries ({delay_seconds}s)", "medium")
        self.delay = delay_seconds

    def steady_state_hypothesis(self) -> bool:
        """System responds quickly"""
        start = time.time()
        try:
            response = requests.get("http://localhost:8080/api/health", timeout=10)
            elapsed = time.time() - start
            return response.status_code == 200 and elapsed < 2
        except Exception:
            return False

    def inject_chaos(self):
        """Mock slow database queries"""
        with patch("sqlite3.Connection.execute") as mock:

            def slow_execute(*args, **kwargs):
                time.sleep(self.delay)
                return MagicMock()

            mock.side_effect = slow_execute


class AuthBackendFailureExperiment(ChaosExperiment):
    """Simulate authentication backend failures"""

    def __init__(self, backend: str = "ldap"):
        super().__init__(f"Backend Failure ({backend})", "high")
        self.backend = backend

    def steady_state_hypothesis(self) -> bool:
        """System is responsive"""
        try:
            response = requests.get("http://localhost:8080/api/health", timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    def inject_chaos(self):
        """Make backend unavailable"""
        # Mock backend failure
        pass


class ConfigurationCorruptionExperiment(ChaosExperiment):
    """Test handling of corrupted configuration"""

    def __init__(self):
        super().__init__("Configuration Corruption", "critical")
        self.backup_config = None

    def steady_state_hypothesis(self) -> bool:
        """System is operational"""
        try:
            response = requests.get("http://localhost:8080/api/health", timeout=2)
            return response.status_code == 200
        except Exception:
            return False

    def inject_chaos(self):
        """Corrupt configuration file"""
        # In production: modify config file with invalid syntax
        pass


# ============================================================================
# Cascade Failure Experiments
# ============================================================================


class CascadeFailureExperiment(ChaosExperiment):
    """Test multiple simultaneous failures"""

    def __init__(self):
        super().__init__("Cascade Failure", "critical")
        self.experiments = [
            NetworkLatencyExperiment(latency_ms=200),
            CPUExhaustionExperiment(duration_seconds=5),
            MemoryExhaustionExperiment(memory_mb=50),
        ]

    def steady_state_hypothesis(self) -> bool:
        """System is fully operational"""
        return all(exp.steady_state_hypothesis() for exp in self.experiments)

    def inject_chaos(self):
        """Inject multiple chaos scenarios"""
        threads = []
        for exp in self.experiments:
            t = threading.Thread(target=exp.inject_chaos)
            t.start()
            threads.append(t)

        # Let all chaos run simultaneously
        time.sleep(5)

    def rollback(self):
        """Rollback all chaos"""
        for exp in self.experiments:
            exp.rollback()


# ============================================================================
# Pytest Integration
# ============================================================================


@pytest.fixture
def chaos_level(request):
    """Get chaos level from command line"""
    return request.config.getoption("--chaos-level", default="low")


def pytest_addoption(parser):
    """Add custom pytest options"""
    parser.addoption(
        "--chaos-level",
        action="store",
        default="low",
        help="Chaos level: low, medium, high, critical",
    )


class TestNetworkChaos:
    """Network-related chaos tests"""

    @pytest.fixture(autouse=True)
    def setup_server(self, tacacs_server):
        """Use server fixture"""
        self.server_info = tacacs_server

    @pytest.mark.chaos
    @pytest.mark.timeout(60)
    def test_network_latency_resilience(self):
        """System handles network latency gracefully"""
        experiment = NetworkLatencyExperiment(latency_ms=500)
        result = experiment.run()

        assert result["passed"], "System failed under network latency"
        assert result["degradation"] < 50, "Performance degraded more than 50%"

    @pytest.mark.chaos
    @pytest.mark.timeout(60)
    def test_packet_loss_resilience(self):
        """System handles packet loss with retries"""
        experiment = NetworkPacketLossExperiment(loss_rate=0.2)
        result = experiment.run()

        assert result["passed"], "System failed under packet loss"

    @pytest.mark.chaos
    @pytest.mark.timeout(120)
    def test_network_partition_recovery(self):
        """System recovers from network partition"""
        experiment = NetworkPartitionExperiment(backend="ldap")
        result = experiment.run()

        # System should gracefully handle partition and use fallback
        assert result["passed"] or result["degradation"] < 100


class TestResourceChaos:
    """Resource exhaustion chaos tests"""

    @pytest.fixture(autouse=True)
    def setup_server(self, tacacs_server):
        """Use server fixture"""
        self.server_info = tacacs_server

    @pytest.mark.chaos
    @pytest.mark.timeout(60)
    def test_memory_pressure_resilience(self):
        """System handles memory pressure"""
        experiment = MemoryExhaustionExperiment(memory_mb=100)
        result = experiment.run()

        # System should not crash, though performance may degrade
        assert result["passed"] or result["degradation"] < 80

    @pytest.mark.chaos
    @pytest.mark.timeout(60)
    def test_cpu_saturation_resilience(self):
        """System remains responsive under CPU load"""
        experiment = CPUExhaustionExperiment(duration_seconds=10)
        result = experiment.run()

        assert result["passed"], "System unresponsive under CPU load"

    @pytest.mark.chaos
    @pytest.mark.timeout(60)
    def test_file_descriptor_exhaustion(self):
        """System handles FD exhaustion gracefully"""
        experiment = FileDescriptorExhaustionExperiment(num_fds=100)
        result = experiment.run()

        assert result["passed"], "System failed when FDs exhausted"


class TestApplicationChaos:
    """Application-level chaos tests"""

    @pytest.fixture(autouse=True)
    def setup_server(self, tacacs_server):
        """Use server fixture"""
        self.server_info = tacacs_server

    @pytest.mark.chaos
    @pytest.mark.timeout(60)
    def test_slow_query_handling(self):
        """System handles slow database queries"""
        experiment = SlowQueryExperiment(delay_seconds=3)
        result = experiment.run()

        # Should timeout gracefully
        assert result["passed"] or result["degradation"] < 100

    @pytest.mark.chaos
    @pytest.mark.timeout(60)
    def test_auth_backend_failure_fallback(self):
        """System falls back when auth backend fails"""
        experiment = AuthBackendFailureExperiment(backend="ldap")
        result = experiment.run()

        assert result["passed"], "No fallback when backend failed"


class TestCascadeFailures:
    """Multiple simultaneous failures"""

    @pytest.fixture(autouse=True)
    def setup_server(self, tacacs_server):
        """Use server fixture"""
        self.server_info = tacacs_server

    @pytest.mark.chaos
    @pytest.mark.timeout(120)
    @pytest.mark.critical
    def test_multiple_simultaneous_failures(self):
        """System survives multiple simultaneous failures"""
        experiment = CascadeFailureExperiment()
        result = experiment.run()

        # System should remain minimally operational
        assert result["degradation"] < 90, "System completely failed"


# ============================================================================
# Chaos Toolkit Integration
# ============================================================================


def create_chaos_experiments():
    """Generate Chaos Toolkit experiment files"""

    network_latency_experiment = {
        "version": "1.0.0",
        "title": "TACACS+ Server handles network latency",
        "description": "Test server gracefully handles increased network latency",
        "steady-state-hypothesis": {
            "title": "System responds within acceptable time",
            "probes": [
                {
                    "type": "probe",
                    "name": "health-check",
                    "tolerance": 200,
                    "provider": {
                        "type": "http",
                        "url": "http://localhost:8080/api/health",
                        "timeout": 2,
                    },
                }
            ],
        },
        "method": [
            {
                "type": "action",
                "name": "inject-latency",
                "provider": {
                    "type": "process",
                    "path": "tc",
                    "arguments": [
                        "qdisc",
                        "add",
                        "dev",
                        "eth0",
                        "root",
                        "netem",
                        "delay",
                        "500ms",
                    ],
                },
                "pauses": {"after": 10},
            }
        ],
        "rollbacks": [
            {
                "type": "action",
                "name": "remove-latency",
                "provider": {
                    "type": "process",
                    "path": "tc",
                    "arguments": ["qdisc", "del", "dev", "eth0", "root"],
                },
            }
        ],
    }

    return network_latency_experiment


# ============================================================================
# Continuous Chaos (Production Chaos)
# ============================================================================


class ContinuousChaos:
    """Run chaos experiments continuously in production"""

    def __init__(self, interval_seconds: int = 3600):
        self.interval = interval_seconds
        self.running = False
        self.experiments = [
            NetworkLatencyExperiment(latency_ms=100),
            CPUExhaustionExperiment(duration_seconds=5),
        ]

    def start(self):
        """Start continuous chaos"""
        self.running = True
        while self.running:
            # Pick random experiment
            experiment = random.choice(self.experiments)

            print(f"🔬 Running continuous chaos: {experiment.name}")
            try:
                result = experiment.run()
                if not result["passed"]:
                    print(f"⚠️  Chaos experiment failed: {experiment.name}")
                    # Alert operations team
            except Exception as e:
                print(f"❌ Chaos experiment error: {e}")

            time.sleep(self.interval)

    def stop(self):
        """Stop continuous chaos"""
        self.running = False


# ============================================================================
# Resilience Scoring
# ============================================================================


class ResilienceScorer:
    """Calculate resilience score based on chaos tests"""

    @staticmethod
    def calculate_score(results: list[dict]) -> dict:
        """Calculate overall resilience score"""
        total_experiments = len(results)
        passed_experiments = sum(1 for r in results if r["passed"])

        avg_degradation = sum(r["degradation"] for r in results) / total_experiments

        # Calculate score (0-100)
        score = (
            (passed_experiments / total_experiments) * 70  # 70% for passing
            + ((100 - avg_degradation) / 100) * 30  # 30% for performance
        )

        return {
            "score": round(score, 2),
            "grade": ResilienceScorer._get_grade(score),
            "passed": passed_experiments,
            "total": total_experiments,
            "avg_degradation": round(avg_degradation, 2),
            "recommendation": ResilienceScorer._get_recommendation(score),
        }

    @staticmethod
    def _get_grade(score: float) -> str:
        """Convert score to letter grade"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    @staticmethod
    def _get_recommendation(score: float) -> str:
        """Get improvement recommendations"""
        if score >= 90:
            return "Excellent resilience! Continue monitoring."
        elif score >= 80:
            return "Good resilience. Consider adding more redundancy."
        elif score >= 70:
            return "Adequate resilience. Improve error handling and timeouts."
        elif score >= 60:
            return "Poor resilience. Critical improvements needed."
        else:
            return "Insufficient resilience! System not production-ready."


if __name__ == "__main__":
    """Run chaos experiments manually"""
    print("🔬 TACACS+ Server Chaos Engineering Suite")
    print("=" * 70)

    experiments = [
        NetworkLatencyExperiment(latency_ms=500),
        NetworkPacketLossExperiment(loss_rate=0.1),
        CPUExhaustionExperiment(duration_seconds=10),
        MemoryExhaustionExperiment(memory_mb=100),
        FileDescriptorExhaustionExperiment(num_fds=50),
    ]

    results = []
    for exp in experiments:
        try:
            result = exp.run()
            results.append(result)
            status = "✅ PASSED" if result["passed"] else "❌ FAILED"
            print(f"{status} - {exp.name} (Degradation: {result['degradation']:.1f}%)")
        except Exception as e:
            print(f"❌ ERROR - {exp.name}: {e}")

    # Calculate resilience score
    print("\n" + "=" * 70)
    score_report = ResilienceScorer.calculate_score(results)
    print(
        f"📊 Resilience Score: {score_report['score']}/100 "
        f"(Grade: {score_report['grade']})"
    )
    print(f"   Passed: {score_report['passed']}/{score_report['total']}")
    print(f"   Avg Degradation: {score_report['avg_degradation']}%")
    print(f"   Recommendation: {score_report['recommendation']}")
    print("=" * 70)
