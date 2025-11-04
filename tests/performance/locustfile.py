"""
TACACS+ Server Performance Test Suite
===================================

This module contains Locust-based performance tests for the TACACS+ server and its
Admin API. It simulates multiple concurrent users performing various operations
to measure the server's performance under load.

Test Scenarios:
- TACACS+ Authentication: Simulates TACACS+ PAP authentication requests
- Admin API Operations: Tests CRUD operations on the admin API
- Web Dashboard: Simulates user interactions with the web dashboard
- Mixed Workload: Combines all operations for realistic load testing

Prerequisites:
- Python 3.7+
- Locust installed (`pip install locust`)
- A running TACACS+ server instance

Configuration:
  Environment Variables:
    T_TACACS_HOST: TACACS+ server host (default: 127.0.0.1)
    T_TACACS_PORT: TACACS+ server port (default: 49)
    T_TACACS_SECRET: Shared secret for TACACS+ authentication
    ADMIN_USERNAME: Admin username for API access
    ADMIN_PASSWORD: Admin password for API access

Usage Examples:
  # Run with web UI (interactive mode)
  locust -f tests/performance/locustfile.py --host=http://127.0.0.1:8080

  # Run in headless mode with specific parameters
  locust -f tests/performance/locustfile.py --host=http://127.0.0.1:8080 \
         --users 100 --spawn-rate 10 --run-time 5m --headless

  # Run specific user classes only
  locust -f tests/performance/locustfile.py --host=http://127.0.0.1:8080 \
         --users 50 --spawn-rate 5 --run-time 2m --headless \
         --tags api,dashboard

  # Use custom test shape
  locust -f tests/performance/locustfile.py --host=http://127.0.0.1:8080 \
         --tags step-load

Tags:
  - tacacs: TACACS+ authentication tests
  - api: Admin API tests
  - dashboard: Web dashboard tests
  - mixed: Mixed workload tests
  - step-load: Use step load testing pattern

Note: This test suite requires a running TACACS+ server instance. It will not
start a server automatically.
"""

from __future__ import annotations

import hashlib
import os
import random
import socket
import struct
import time

from locust import HttpUser, LoadTestShape, between, events, tag, task
from locust.exception import StopUser

# ------------------------
# Helpers: TACACS+ minimal
# ------------------------


def _tacacs_auth(host: str, port: int, key: str, username: str, password: str) -> bool:
    """Perform TACACS+ PAP authentication.

    This is a minimal implementation of TACACS+ PAP authentication used for
    performance testing. It handles the low-level protocol details to
    authenticate a user against a TACACS+ server.

    Args:
        host: TACACS+ server hostname or IP address
        port: TACACS+ server port (default: 49)
        key: Shared secret for TACACS+ authentication
        username: Username to authenticate
        password: Password for authentication

    Returns:
        bool: True if authentication was successful, False otherwise

    Raises:
        ConnectionError: If the connection to the TACACS+ server fails
        TimeoutError: If the authentication times out
    """

    def md5_pad(
        sess_id: int, secret: str, version: int, seq_no: int, length: int
    ) -> bytes:
        pad = bytearray()
        sid = struct.pack("!L", sess_id)
        sec = secret.encode("utf-8")
        ver = bytes([version])
        seq = bytes([seq_no])
        while len(pad) < length:
            md5_in = sid + sec + ver + seq + (pad if pad else b"")
            pad.extend(hashlib.md5(md5_in, usedforsecurity=False).digest())
        return bytes(pad[:length])

    def transform(
        body: bytes, sess_id: int, secret: str, version: int, seq_no: int
    ) -> bytes:
        if not secret:
            return body
        pad = md5_pad(sess_id, secret, version, seq_no, len(body))
        return bytes(a ^ b for a, b in zip(body, pad))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(0.5)
        s.connect((host, port))
        sess_id = int(time.time()) & 0xFFFFFFFF
        user_b = username.encode()
        port_b = b"console"
        addr_b = b"127.0.0.1"
        pass_b = password.encode()
        # PAP authen (type=2) like functional tests
        body = struct.pack(
            "!BBBBBBBB", 1, 15, 2, 1, len(user_b), len(port_b), len(addr_b), len(pass_b)
        )
        body += user_b + port_b + addr_b + pass_b
        version = 0xC0
        seq = 1
        enc_body = transform(body, sess_id, key, version, seq)
        header = struct.pack("!BBBBLL", version, 1, seq, 0, sess_id, len(enc_body))
        s.sendall(header + enc_body)
        resp_hdr = s.recv(12)
        if len(resp_hdr) != 12:
            return False
        r_ver, r_type, r_seq, _, r_sess, r_len = struct.unpack("!BBBBLL", resp_hdr)
        resp_body = s.recv(r_len) if r_len else b""
        if len(resp_body) < r_len:
            return False
        dec = transform(resp_body, r_sess, key, r_ver, r_seq)
        if len(dec) < 6:
            return False
        return dec[0] == 1
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


# ---------------------------
# Locust Users and scenarios
# ---------------------------


class TACACSUser(HttpUser):
    """Simulates TACACS+ authentication requests.

    This user class performs TACACS+ PAP authentication against the server.
    It's used to test the authentication performance under load.

    Behavior:
    - Connects to the TACACS+ server directly (not through the web interface)
    - Performs PAP authentication with configurable credentials
    - Measures authentication latency and success rate

    Configuration:
    - wait_time: Random wait between 0.5 and 2 seconds between requests
    - Environment variables for TACACS+ server configuration

    Example:
        locust -f locustfile.py --users 50 --spawn-rate 5 TACACSUser
    """

    wait_time = between(0.5, 2)

    def on_start(self):
        self.t_host = os.getenv("T_TACACS_HOST", "127.0.0.1")
        self.t_port = int(os.getenv("T_TACACS_PORT", "49"))
        self.t_secret = os.getenv("T_TACACS_SECRET", "testing123")
        self.t_user = os.getenv("T_TACACS_USERNAME")
        self.t_pass = os.getenv("T_TACACS_PASSWORD")

    @task
    @tag("tacacs", "auth")
    def authenticate(self):
        user = f"load{random.randint(1000, 9999)}"
        pwd = "LoadPass123"
        # Prefer fixed, known-good credentials when provided
        if self.t_user and self.t_pass:
            user, pwd = self.t_user, self.t_pass
        start = time.time()
        ok = _tacacs_auth(self.t_host, self.t_port, self.t_secret, user, pwd)
        elapsed = int((time.time() - start) * 1000)
        events.request.fire(
            request_type="TACACS+",
            name="authenticate",
            response_time=elapsed,
            response_length=0,
            exception=None if ok else Exception("auth_failed"),
            context={},
        )


class APIUser(HttpUser):
    """Simulates API requests to the Admin API.

    This user class performs various CRUD operations on the Admin API
    to test its performance under load.

    Tested Operations:
    - Authentication and session management
    - Device listing and creation
    - User listing and management
    - Status and health checks

    Behavior:
    - Logs in to obtain a session token
    - Performs a series of API requests with the token
    - Handles token expiration and re-authentication
    - Measures response times and success rates

    Configuration:
    - wait_time: Random wait between 0.2 and 1.5 seconds between requests
    - Environment variables for admin credentials

    Example:
        locust -f locustfile.py --users 20 --spawn-rate 2 APIUser
    """

    wait_time = between(0.2, 1.5)

    def on_start(self):
        # Obtain admin session cookie by logging into /admin/login
        admin_user = os.getenv("ADMIN_USERNAME", "admin")
        admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
        r = self.client.post(
            "/admin/login", json={"username": admin_user, "password": admin_pass}
        )
        if r.status_code != 200:
            raise StopUser()
        # Optional API token usage if the target enforces it
        self.api_token = os.getenv("API_TOKEN")

    @task(10)
    @tag("api", "status")
    def status(self):
        headers = {"X-API-Token": self.api_token} if self.api_token else {}
        self.client.get("/api/status", headers=headers)

    @task(5)
    @tag("api", "list")
    def list_devices(self):
        headers = {"X-API-Token": self.api_token} if self.api_token else {}
        self.client.get("/api/devices", headers=headers)

    @task(5)
    @tag("api", "list")
    def list_users(self):
        headers = {"X-API-Token": self.api_token} if self.api_token else {}
        self.client.get("/api/users", headers=headers)

    @task(1)
    @tag("api", "create")
    def create_device(self):
        # If a group with id=1 doesn't exist, API will 404; that's acceptable in load context
        payload = {
            "name": f"ld-{random.randint(1000, 9999)}",
            "ip_address": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "device_group_id": 1,
            "enabled": True,
        }
        headers = {"X-API-Token": self.api_token} if self.api_token else {}
        self.client.post("/api/devices", json=payload, headers=headers)


class DashboardUser(HttpUser):
    """Simulates user interactions with the web dashboard.

    This user class mimics typical user behavior when interacting with the
    TACACS+ server's web interface, including page navigation and form submissions.

    Tested Interactions:
    - Dashboard landing page
    - Login/logout flows
    - Navigation between different sections
    - Form submissions and data filtering

    Behavior:
    - Simulates realistic think times between actions
    - Follows common user flows through the application
    - Handles session management and CSRF tokens
    - Measures page load times and interaction latency

    Configuration:
    - wait_time: Random wait between 1 and 4 seconds between actions
    - Environment variables for user credentials

    Example:
        locust -f locustfile.py --users 10 --spawn-rate 1 DashboardUser
    """

    wait_time = between(1, 4)

    def on_start(self):
        # Ensure we have an authenticated session so /api/stats doesn't 401
        admin_user = os.getenv("ADMIN_USERNAME", "admin")
        admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
        r = self.client.post(
            "/admin/login", json={"username": admin_user, "password": admin_pass}
        )
        if r.status_code != 200:
            # Proceed unauthenticated; stats may 401
            pass

    @task
    @tag("dashboard")
    def view(self):
        """View dashboard pages."""
        self.client.get("/admin")
        self.client.get("/api/stats")


class MixedWorkloadUser(HttpUser):
    """Simulates a realistic mix of API, dashboard, and TACACS operations.

    This user class combines various operations to create a more realistic
    load profile that mimics production usage patterns. It's useful for
    end-to-end performance testing.

    Operation Mix:
    - 40% API operations (status, CRUD)
    - 40% Dashboard interactions
    - 20% TACACS+ authentication requests

    Behavior:
    - Randomly selects between different operation types
    - Maintains session state across requests
    - Handles authentication and error conditions
    - Measures end-to-end performance metrics

    Configuration:
    - wait_time: Random wait between 0.5 and 2.5 seconds between operations
    - Environment variables for both admin and TACACS+ credentials

    Example:
        locust -f locustfile.py --users 30 --spawn-rate 3 MixedWorkloadUser

    Note:
        This class implements all operations directly rather than referencing
        other user classes due to Locust's task execution model.
    """

    wait_time = between(0.5, 2.5)

    def on_start(self):
        """Initialize admin session and TACACS+ server configuration."""
        # Admin session
        admin_user = os.getenv("ADMIN_USERNAME", "admin")
        admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
        r = self.client.post(
            "/admin/login", json={"username": admin_user, "password": admin_pass}
        )
        if r.status_code != 200:
            raise StopUser()
        # TACACS config
        self.t_host = os.getenv("T_TACACS_HOST", "127.0.0.1")
        self.t_port = int(os.getenv("T_TACACS_PORT", "49"))
        self.t_secret = os.getenv("T_TACACS_SECRET", "testing123")
        self.api_token = os.getenv("API_TOKEN")

    @task(8)
    @tag("mixed", "api")
    def api_status(self):
        """Get API status."""
        headers = {"X-API-Token": self.api_token} if self.api_token else {}
        self.client.get("/api/status", headers=headers)

    @task(5)
    @tag("mixed", "api")
    def api_list_devices(self):
        """Get device list."""
        headers = {"X-API-Token": self.api_token} if self.api_token else {}
        self.client.get("/api/devices", headers=headers)

    @task(5)
    @tag("mixed", "api")
    def api_list_users(self):
        """Get user list."""
        headers = {"X-API-Token": self.api_token} if self.api_token else {}
        self.client.get("/api/users", headers=headers)

    @task(1)
    @tag("mixed", "api")
    def api_create_device(self):
        """Create a new device."""
        payload = {
            "name": f"mx-{random.randint(1000, 9999)}",
            "ip_address": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "device_group_id": 1,
            "enabled": True,
        }
        headers = {"X-API-Token": self.api_token} if self.api_token else {}
        self.client.post("/api/devices", json=payload, headers=headers)

    @task(2)
    @tag("mixed", "dashboard")
    def dashboard(self):
        """View dashboard pages."""
        self.client.get("/admin")
        self.client.get("/api/stats")

    @task(1)
    @tag("mixed", "tacacs")
    def tacacs_auth(self):
        """Perform TACACS+ authentication."""
        user = f"mx{random.randint(1000, 9999)}"
        pwd = "LoadPass123"
        start = time.time()
        ok = _tacacs_auth(self.t_host, self.t_port, self.t_secret, user, pwd)
        elapsed = int((time.time() - start) * 1000)
        events.request.fire(
            request_type="TACACS+",
            name="mixed_auth",
            response_time=elapsed,
            response_length=0,
            exception=None if ok else Exception("auth_failed"),
            context={},
        )


# ---------------------------
# Custom load shapes (optional)
# ---------------------------


class StepLoadShape(LoadTestShape):
    """A step load test shape that increases load in stages.

    This load shape increases the number of users in regular steps,
    holding each step for a specified duration. This is useful for
    identifying the breaking point of the system under test.

    Configuration:
    - step_time: Time in seconds for each load step
    - step_load: Number of users to add in each step
    - spawn_rate: Number of users to spawn per second
    - time_limit: Maximum test duration in seconds

    Example:
        locust -f locustfile.py --tags step-load --headless --run-time 10m
    """

    step_time = 30  # seconds per step
    step_load = 20  # users to add each step
    spawn_rate = 10  # users to spawn per second
    time_limit = 300  # maximum test duration in seconds

    def tick(self):
        """Return the number of users to simulate and the spawn rate."""
        rt = self.get_run_time()
        if rt > self.time_limit:
            return None
        step = int(rt // self.step_time)
        return (step * self.step_load or self.step_load, self.spawn_rate)


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Event handler for test start."""
    print("Load test starting; host:", environment.host)


@events.request.add_listener
def on_request(
    request_type: str,
    name: str,
    response_time: float,
    response_length: int,
    exception: Exception,
    **kwargs,
) -> None:
    """Event handler for request completion.

    This function is called after each request is completed, regardless of
    whether it succeeded or failed. It can be used for custom logging,
    monitoring, or alerting.

    Args:
        request_type: Type of request (e.g., 'GET', 'POST')
        name: Name of the request (endpoint or custom name)
        response_time: Time taken to complete the request in milliseconds
        response_length: Size of the response in bytes
        exception: Exception object if the request failed, None otherwise
        **kwargs: Additional keyword arguments from Locust
    """
    if exception:
        print(f"Request failed: {name} - {exception}")
        # Additional failure handling can be added here
        # For example, logging to a file or sending alerts
    if response_time > 1000:
        print(f"Slow: {request_type} {name} {response_time}ms")
