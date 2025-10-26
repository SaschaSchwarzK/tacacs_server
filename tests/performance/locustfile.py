"""
Locust load tests for the real TACACS+ server and Admin API.

How to run (requires a running server):

  # Web UI
  locust -f tests/performance/locustfile.py --host=http://127.0.0.1:8080

  # Headless
  locust -f tests/performance/locustfile.py --host=http://127.0.0.1:8080 \
         --users 100 --spawn-rate 10 --run-time 5m --headless

Environment knobs (optional):
  T_TACACS_HOST, T_TACACS_PORT, T_TACACS_SECRET
  ADMIN_USERNAME, ADMIN_PASSWORD

This file does NOT spin up a server. It targets whatever is running at --host
and the TACACS host/port variables.
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
    """Minimal TACACS+ PAP authenticate."""

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
        self.client.get("/admin")
        self.client.get("/api/stats")


class MixedWorkloadUser(HttpUser):
    """Single user mixing API, dashboard, and TACACS operations.

    Avoids referencing other User classes as tasks (unsupported by Locust).
    """

    wait_time = between(0.5, 2.5)

    def on_start(self):
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
        headers = {"X-API-Token": self.api_token} if self.api_token else {}
        self.client.get("/api/status", headers=headers)

    @task(5)
    @tag("mixed", "api")
    def api_list_devices(self):
        headers = {"X-API-Token": self.api_token} if self.api_token else {}
        self.client.get("/api/devices", headers=headers)

    @task(5)
    @tag("mixed", "api")
    def api_list_users(self):
        headers = {"X-API-Token": self.api_token} if self.api_token else {}
        self.client.get("/api/users", headers=headers)

    @task(1)
    @tag("mixed", "api")
    def api_create_device(self):
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
        self.client.get("/admin")
        self.client.get("/api/stats")

    @task(1)
    @tag("mixed", "tacacs")
    def tacacs_auth(self):
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
    step_time = 30
    step_load = 20
    spawn_rate = 10
    time_limit = 300

    def tick(self):
        rt = self.get_run_time()
        if rt > self.time_limit:
            return None
        step = int(rt // self.step_time)
        return (step * self.step_load or self.step_load, self.spawn_rate)


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    print("Load test starting; host:", environment.host)


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, **kwargs):
    # simple signal for slow calls
    if response_time > 1000:
        print(f"Slow: {request_type} {name} {response_time}ms")
