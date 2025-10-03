"""
Load Testing Suite for TACACS+ Server using Locust

Installation:
    pip install locust

Usage:
    # Web UI mode
    locust -f tests/performance/locustfile.py --host=http://localhost:8080
    
    # Headless mode
    locust -f tests/performance/locustfile.py --host=http://localhost:8080 \
           --users 100 --spawn-rate 10 --run-time 5m --headless
    
    # Distributed mode (master)
    locust -f tests/performance/locustfile.py --master
    
    # Distributed mode (worker)
    locust -f tests/performance/locustfile.py --worker --master-host=localhost
"""

import hashlib
import logging
import random
import socket
import struct
import time

from locust import HttpUser, LoadTestShape, between, events, tag, task
from locust.exception import StopUser

logger = logging.getLogger(__name__)


# ============================================================================
# TACACS+ Protocol Implementation for Load Testing
# ============================================================================


class TACACSPacket:
    """TACACS+ packet builder for load testing"""

    AUTHEN_START = 0x01
    AUTHEN_REPLY = 0x02
    AUTHEN_CONTINUE = 0x03

    TAC_PLUS_AUTHEN = 0x01
    TAC_PLUS_AUTHOR = 0x02
    TAC_PLUS_ACCT = 0x03

    def __init__(self, version=0xC0, seq_no=1, session_id=None, secret="tacacs123"):
        self.version = version
        self.type = self.TAC_PLUS_AUTHEN
        self.seq_no = seq_no
        self.session_id = session_id or random.randint(1, 0xFFFFFFFF)
        self.secret = secret.encode()

    def create_authen_start(self, username: str, password: str) -> bytes:
        """Create authentication start packet"""
        user_bytes = username.encode()
        pass_bytes = password.encode()

        # Build packet body
        body = struct.pack(
            "!BBBBBBBB",
            0x01,  # action (LOGIN)
            0x01,  # priv_lvl
            0x01,  # authen_type (ASCII)
            0x01,  # service (LOGIN)
            len(user_bytes),
            len(pass_bytes),
            0,  # port_len
            0,  # rem_addr_len
        )
        body += user_bytes + pass_bytes

        # Encrypt body
        encrypted_body = self._encrypt(body, self.seq_no)

        # Build header
        header = struct.pack(
            "!BBBBII",
            self.version,
            self.type,
            self.seq_no,
            0,  # flags
            self.session_id,
            len(encrypted_body),
        )

        return header + encrypted_body

    def _encrypt(self, body: bytes, seq_no: int) -> bytes:
        """TACACS+ encryption"""
        pad = b""
        while len(pad) < len(body):
            md5_input = (
                self.session_id.to_bytes(4, "big")
                + self.secret
                + self.version.to_bytes(1, "big")
                + seq_no.to_bytes(1, "big")
                + pad
            )
            pad += hashlib.md5(md5_input).digest()

        encrypted = bytes(a ^ b for a, b in zip(body, pad[: len(body)]))
        return encrypted


# ============================================================================
# Custom Locust Users for Different Test Scenarios
# ============================================================================


class TACACSUser(HttpUser):
    """Base class for TACACS+ protocol testing"""

    wait_time = between(1, 3)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tacacs_socket = None
        self.tacacs_host = "localhost"
        self.tacacs_port = 49
        self.tacacs_secret = "tacacs123"

    def on_start(self):
        """Initialize TACACS+ connection"""
        self.connect_tacacs()

    def on_stop(self):
        """Clean up TACACS+ connection"""
        if self.tacacs_socket:
            self.tacacs_socket.close()

    def connect_tacacs(self):
        """Establish TACACS+ socket connection"""
        try:
            self.tacacs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tacacs_socket.settimeout(5)
            self.tacacs_socket.connect((self.tacacs_host, self.tacacs_port))
        except Exception as e:
            logger.error(f"Failed to connect to TACACS+: {e}")
            raise StopUser()

    @task
    @tag("tacacs", "authentication")
    def authenticate_tacacs(self):
        """Test TACACS+ authentication"""
        username = f"testuser{random.randint(1, 100)}"
        password = "testpass123"

        packet_builder = TACACSPacket(secret=self.tacacs_secret)
        packet = packet_builder.create_authen_start(username, password)

        start_time = time.time()
        try:
            self.tacacs_socket.sendall(packet)
            response = self.tacacs_socket.recv(4096)

            total_time = int((time.time() - start_time) * 1000)

            if len(response) > 0:
                events.request.fire(
                    request_type="TACACS+",
                    name="authenticate",
                    response_time=total_time,
                    response_length=len(response),
                    exception=None,
                    context={},
                )
            else:
                events.request.fire(
                    request_type="TACACS+",
                    name="authenticate",
                    response_time=total_time,
                    response_length=0,
                    exception=Exception("Empty response"),
                    context={},
                )
        except Exception as e:
            total_time = int((time.time() - start_time) * 1000)
            events.request.fire(
                request_type="TACACS+",
                name="authenticate",
                response_time=total_time,
                response_length=0,
                exception=e,
                context={},
            )


class APIUser(HttpUser):
    """Test REST API endpoints"""

    wait_time = between(0.5, 2)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth_token = None

    def on_start(self):
        """Login to get auth token"""
        self.login()

    @tag("api", "auth")
    def login(self):
        """Authenticate with admin API"""
        response = self.client.post(
            "/api/admin/login", json={"username": "admin", "password": "admin123"}
        )
        if response.status_code == 200:
            self.auth_token = response.json().get("token")

    @task(10)
    @tag("api", "read")
    def get_status(self):
        """Get server status - most common operation"""
        self.client.get("/api/status")

    @task(5)
    @tag("api", "read")
    def get_devices(self):
        """List devices"""
        headers = (
            {"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
        )
        self.client.get("/api/devices", headers=headers)

    @task(5)
    @tag("api", "read")
    def get_users(self):
        """List users"""
        headers = (
            {"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
        )
        self.client.get("/api/users", headers=headers)

    @task(3)
    @tag("api", "read")
    def get_accounting(self):
        """Get accounting records"""
        headers = (
            {"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
        )
        self.client.get("/api/accounting?limit=50", headers=headers)

    @task(2)
    @tag("api", "read")
    def get_metrics(self):
        """Get Prometheus metrics"""
        self.client.get("/metrics")

    @task(1)
    @tag("api", "write")
    def create_device(self):
        """Create new device - write operation"""
        headers = (
            {"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
        )
        device_data = {
            "name": f"device-{random.randint(1000, 9999)}",
            "ip_address": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "device_group_id": 1,
            "enabled": True,
        }
        self.client.post("/api/devices", json=device_data, headers=headers)


class DashboardUser(HttpUser):
    """Simulate dashboard users with WebSocket connections"""

    wait_time = between(5, 15)

    @task
    @tag("dashboard", "websocket")
    def view_dashboard(self):
        """Load dashboard page"""
        self.client.get("/")

    @task(3)
    @tag("dashboard", "api")
    def poll_stats(self):
        """Poll statistics (simulating dashboard refresh)"""
        self.client.get("/api/stats")
        self.client.get("/api/health")


class MixedWorkloadUser(HttpUser):
    """Realistic mixed workload simulation"""

    wait_time = between(2, 8)

    tasks = {
        APIUser: 7,  # 70% API calls
        DashboardUser: 2,  # 20% dashboard users
        TACACSUser: 1,  # 10% TACACS+ auth
    }


# ============================================================================
# Test Scenarios and Profiles
# ============================================================================


class SteadyStateLoadTest(HttpUser):
    """Steady state: normal operational load"""

    wait_time = between(2, 5)
    # Use APIUser tasks for steady state
    tasks = [APIUser.get_status, APIUser.get_devices]


class StressTest(HttpUser):
    """Stress test: push system to limits"""

    wait_time = between(0.1, 0.5)  # Very aggressive
    tasks = [APIUser.get_status, TACACSUser.authenticate_tacacs]


class SpikeTest(HttpUser):
    """Spike test: sudden traffic increase"""

    wait_time = between(0, 1)
    tasks = [APIUser.get_status]


# ============================================================================
# Custom Events and Monitoring
# ============================================================================


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when test starts"""
    logger.info("Load test starting...")
    logger.info(f"Target host: {environment.host}")
    logger.info(f"Number of users: {environment.runner.target_user_count}")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when test stops - generate report"""
    logger.info("Load test completed")

    stats = environment.stats
    logger.info(f"Total requests: {stats.total.num_requests}")
    logger.info(f"Total failures: {stats.total.num_failures}")
    logger.info(f"Average response time: {stats.total.avg_response_time:.2f}ms")
    logger.info(f"Max response time: {stats.total.max_response_time:.2f}ms")
    logger.info(f"Requests per second: {stats.total.total_rps:.2f}")

    # Check if we meet SLA (example: 95th percentile < 100ms)
    if stats.total.get_response_time_percentile(0.95) > 100:
        logger.warning("⚠️  SLA violation: 95th percentile exceeds 100ms")
    else:
        logger.info("✅ SLA met: 95th percentile within 100ms")


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, **kwargs):
    """Log slow requests"""
    if response_time > 1000:  # > 1 second
        logger.warning(
            f"Slow request detected: {request_type} {name} took {response_time}ms"
        )


# ============================================================================
# Custom Load Shapes
# ============================================================================


class StepLoadShape(LoadTestShape):
    """
    Step load pattern: gradually increase load in steps

    Simulates gradual traffic increase (e.g., business hours)
    """

    step_time = 60  # Each step lasts 60 seconds
    step_load = 10  # Add 10 users per step
    spawn_rate = 5
    time_limit = 600  # 10 minutes total

    def tick(self):
        run_time = self.get_run_time()

        if run_time > self.time_limit:
            return None

        current_step = run_time // self.step_time
        return (current_step * self.step_load, self.spawn_rate)


class SpikeLoadShape(LoadTestShape):
    """
    Spike load pattern: sudden traffic spikes

    Simulates DDoS attacks or viral traffic
    """

    stages = [
        {"duration": 60, "users": 10, "spawn_rate": 5},
        {"duration": 120, "users": 100, "spawn_rate": 50},  # SPIKE
        {"duration": 180, "users": 10, "spawn_rate": 10},
        {"duration": 240, "users": 200, "spawn_rate": 100},  # BIGGER SPIKE
        {"duration": 300, "users": 10, "spawn_rate": 10},
    ]

    def tick(self):
        run_time = self.get_run_time()

        for stage in self.stages:
            if run_time < stage["duration"]:
                return (stage["users"], stage["spawn_rate"])

        return None


class BusinessHoursShape(LoadTestShape):
    """
    Business hours pattern: realistic daily traffic

    Simulates typical enterprise usage patterns
    """

    def tick(self):
        run_time = self.get_run_time()

        # Simulate 24-hour period in 10 minutes (each minute = 2.4 hours)
        hour_of_day = (run_time / 25) % 24  # 25 seconds per hour

        if 0 <= hour_of_day < 6:  # Night
            return (5, 1)
        elif 6 <= hour_of_day < 9:  # Morning ramp-up
            return (int(20 + hour_of_day * 10), 5)
        elif 9 <= hour_of_day < 17:  # Business hours
            return (100, 10)
        elif 17 <= hour_of_day < 20:  # Evening ramp-down
            return (int(100 - (hour_of_day - 17) * 20), 5)
        else:  # Late evening
            return (10, 2)


# ============================================================================
# Performance Benchmarks and SLAs
# ============================================================================


class PerformanceValidator:
    """Validate performance against SLAs"""

    SLA_REQUIREMENTS = {
        "avg_response_time": 50,  # 50ms average
        "p95_response_time": 100,  # 95th percentile < 100ms
        "p99_response_time": 500,  # 99th percentile < 500ms
        "error_rate": 0.01,  # < 1% error rate
        "min_rps": 100,  # Minimum 100 requests/sec
    }

    @staticmethod
    def validate_sla(stats):
        """Check if performance meets SLA"""
        violations = []

        if (
            stats.total.avg_response_time
            > PerformanceValidator.SLA_REQUIREMENTS["avg_response_time"]
        ):
            violations.append(
                f"Average response time: {stats.total.avg_response_time:.2f}ms"
            )

        p95 = stats.total.get_response_time_percentile(0.95)
        if p95 > PerformanceValidator.SLA_REQUIREMENTS["p95_response_time"]:
            violations.append(f"95th percentile: {p95:.2f}ms")

        p99 = stats.total.get_response_time_percentile(0.99)
        if p99 > PerformanceValidator.SLA_REQUIREMENTS["p99_response_time"]:
            violations.append(f"99th percentile: {p99:.2f}ms")

        if stats.total.num_requests > 0:
            error_rate = stats.total.num_failures / stats.total.num_requests
            if error_rate > PerformanceValidator.SLA_REQUIREMENTS["error_rate"]:
                violations.append(f"Error rate: {error_rate * 100:.2f}%")

        if stats.total.total_rps < PerformanceValidator.SLA_REQUIREMENTS["min_rps"]:
            violations.append(f"RPS: {stats.total.total_rps:.2f}")

        return violations


@events.quitting.add_listener
def on_quitting(environment, **kwargs):
    """Final validation before exit"""
    violations = PerformanceValidator.validate_sla(environment.stats)

    if violations:
        logger.error("❌ SLA VIOLATIONS DETECTED:")
        for v in violations:
            logger.error(f"  - {v}")
        environment.process_exit_code = 1
    else:
        logger.info("✅ All SLA requirements met")
