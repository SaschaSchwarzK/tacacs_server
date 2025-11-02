"""
Test configuration and fixtures - Real server instances only, no mocks
"""

from __future__ import annotations

import configparser
import os
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, cast

import pytest
import requests
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from requests.exceptions import RequestException


@pytest.fixture(autouse=True, scope="session")
def _backup_env_roots(tmp_path_factory: pytest.TempPathFactory):
    """Force backup roots to temp dirs for all tests."""
    import os as _os

    backup_root = tmp_path_factory.mktemp("backups_root")
    temp_root = tmp_path_factory.mktemp("backups_tmp")
    _os.environ["BACKUP_ROOT"] = str(backup_root)
    _os.environ["BACKUP_TEMP"] = str(temp_root)
    yield


def _find_free_port() -> int:
    """Find an available port on localhost"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        addr = cast(tuple[str, int], s.getsockname())
        port: int = addr[1]
        return port


def _wait_for_port(host: str, port: int, timeout: float = 30.0) -> bool:
    """Wait for a port to become available"""
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


class ServerInstance:
    """Manages a real server instance with isolated resources"""

    def __init__(
        self,
        work_dir: Path,
        config: dict[str, Any],
        enable_tacacs: bool = True,
        enable_radius: bool = False,
        enable_admin_api: bool = False,
        enable_admin_web: bool = False,
    ):
        self.work_dir = work_dir
        self.config_dict = config
        self.enable_tacacs = enable_tacacs
        self.enable_radius = enable_radius
        self.enable_admin_api = enable_admin_api
        self.enable_admin_web = enable_admin_web

        # Ports
        # TACACS+ may start even if not explicitly enabled by config defaults.
        # Always allocate a free port and write it to config to avoid conflicts.
        self.tacacs_port = _find_free_port()
        self.radius_auth_port = _find_free_port() if enable_radius else None
        self.radius_acct_port = _find_free_port() if enable_radius else None
        self.web_port = (
            _find_free_port() if (enable_admin_api or enable_admin_web) else None
        )

        # Paths
        self.config_path = work_dir / "tacacs.conf"
        self.log_path = work_dir / "logs" / "server.log"
        self.auth_db = work_dir / "data" / "local_auth.db"
        self.devices_db = work_dir / "data" / "devices.db"
        self.accounting_db = work_dir / "data" / "accounting.db"
        # Expose additional database paths for tests/diagnostics
        self.metrics_history_db = work_dir / "data" / "metrics.db"
        self.audit_trail_db = work_dir / "data" / "audit.db"

        # Process
        self.process: subprocess.Popen | None = None
        self.log_file: Any = None

        # Server info
        self.admin_username = config.get("admin_username", "admin")
        self.admin_password = config.get("admin_password", "admin123")
        self.api_token = os.environ.get("TEST_API_TOKEN", "test-token")

    def _create_config_file(self):
        """Create config file from settings"""
        cfg = configparser.ConfigParser(interpolation=None)

        # Server section (always set a dedicated port to avoid conflicts)
        cfg.add_section("server")
        cfg["server"]["host"] = "127.0.0.1"
        cfg["server"]["port"] = str(self.tacacs_port)
        cfg["server"]["log_level"] = self.config_dict.get("log_level", "INFO")
        # Merge server overrides if provided
        try:
            server_overrides = self.config_dict.get("server") or {}
            for key, value in server_overrides.items():
                cfg["server"][str(key)] = str(value)
        except Exception:
            pass

        # RADIUS section
        if self.enable_radius:
            cfg.add_section("radius")
            cfg["radius"]["enabled"] = "true"
            cfg["radius"]["host"] = "127.0.0.1"
            cfg["radius"]["auth_port"] = str(self.radius_auth_port)
            cfg["radius"]["acct_port"] = str(self.radius_acct_port)
            cfg["radius"]["share_backends"] = self.config_dict.get(
                "radius_share_backends", "true"
            )
            cfg["radius"]["share_accounting"] = self.config_dict.get(
                "radius_share_accounting", "true"
            )
        else:
            cfg.add_section("radius")
            cfg["radius"]["enabled"] = "false"

        # Admin section (for Web UI and API)
        if self.enable_admin_api or self.enable_admin_web:
            cfg.add_section("admin")
            cfg["admin"]["username"] = self.admin_username
            # Generate password hash
            try:
                import bcrypt

                password_hash = bcrypt.hashpw(
                    self.admin_password.encode(), bcrypt.gensalt()
                ).decode()
            except Exception:
                # Fallback hash for "admin123"
                password_hash = (
                    "$2b$12$vj2m47XxypTDfG/ZOaUeP.a2lROwySqp7kWzb7OmV/UNHtcOFnA2G"
                )
            cfg["admin"]["password_hash"] = password_hash
            cfg["admin"]["session_timeout_minutes"] = "60"
        else:
            # No password hash = admin disabled
            cfg.add_section("admin")
            cfg["admin"]["username"] = self.admin_username
            cfg["admin"]["password_hash"] = ""

        # Monitoring section (Web UI / API)
        if self.enable_admin_api or self.enable_admin_web:
            cfg.add_section("monitoring")
            cfg["monitoring"]["enabled"] = "true"
            cfg["monitoring"]["web_host"] = "127.0.0.1"
            cfg["monitoring"]["web_port"] = str(self.web_port)
        else:
            cfg.add_section("monitoring")
            cfg["monitoring"]["enabled"] = "false"

        # Auth section
        cfg.add_section("auth")
        cfg["auth"]["backends"] = self.config_dict.get("auth_backends", "local")
        cfg["auth"]["local_auth_db"] = str(self.auth_db)

        # Database section
        cfg.add_section("database")
        cfg["database"]["accounting_db"] = str(self.accounting_db)
        cfg["database"]["metrics_history_db"] = str(self.metrics_history_db)
        cfg["database"]["audit_trail_db"] = str(self.audit_trail_db)
        # Allow overriding database paths from test config
        try:
            db_overrides = self.config_dict.get("database") or {}
            for key, value in db_overrides.items():
                cfg["database"][str(key)] = str(value)
                # Keep internal paths in sync with overrides to avoid mismatches
                try:
                    ov = Path(str(value))
                    resolved = self.work_dir / ov if not ov.is_absolute() else ov
                    if str(key) == "accounting_db":
                        self.accounting_db = resolved
                    elif str(key) == "metrics_history_db":
                        self.metrics_history_db = resolved
                    elif str(key) == "audit_trail_db":
                        self.audit_trail_db = resolved
                except Exception:
                    # Do not fail config creation on path normalization errors
                    pass
        except Exception:
            pass

        # Devices section
        cfg.add_section("devices")
        cfg["devices"]["database"] = str(self.devices_db)
        cfg["devices"]["default_group"] = "default"

        # Security section
        cfg.add_section("security")
        cfg["security"]["encryption_required"] = self.config_dict.get(
            "encryption_required", "false"
        )
        cfg["security"]["max_connections_per_ip"] = "1000"
        # Allow overriding security settings from test config
        try:
            sec_overrides = self.config_dict.get("security") or {}
            for key, value in sec_overrides.items():
                cfg["security"][str(key)] = str(value)
        except Exception:
            pass

        # Logging section
        cfg.add_section("logging")
        cfg["logging"]["log_file"] = str(self.log_path)
        cfg["logging"]["log_level"] = self.config_dict.get("log_level", "INFO")
        # Merge logging overrides if provided
        try:
            logging_overrides = self.config_dict.get("logging") or {}
            for key, value in logging_overrides.items():
                cfg["logging"][str(key)] = str(value)
        except Exception:
            pass

        # Add or merge any additional custom sections from config_dict
        for section_name, section_data in self.config_dict.items():
            if isinstance(section_data, dict):
                if not cfg.has_section(section_name):
                    cfg.add_section(section_name)
                for key, value in section_data.items():
                    cfg[section_name][str(key)] = str(value)

        # Write config file
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with self.config_path.open("w") as f:
            cfg.write(f)

        # Debug: print config file contents for proxy protocol tests
        if "proxy_protocol" in self.config_dict:
            print(f"\n=== CONFIG FILE ({self.config_path}) ===")
            print(self.config_path.read_text())
            print("=== END CONFIG ===\n")

    def start(self):
        """Start the server instance"""
        # Create necessary directories
        (self.work_dir / "data").mkdir(parents=True, exist_ok=True)
        (self.work_dir / "logs").mkdir(parents=True, exist_ok=True)

        # Create config file
        self._create_config_file()

        # Open log file
        self.log_file = open(self.log_path, "w+")

        # Prepare environment
        env = os.environ.copy()

        # Add credentials only via environment
        if "okta_api_token" in self.config_dict:
            env["OKTA_API_TOKEN"] = self.config_dict["okta_api_token"]
        if "ldap_bind_password" in self.config_dict:
            env["LDAP_BIND_PASSWORD"] = self.config_dict["ldap_bind_password"]
        # No test-time environment overrides here; use server defaults/config only

        if self.enable_admin_api or self.enable_admin_web:
            env["API_TOKEN"] = self.api_token

        # Start server process
        cmd = [
            "python",
            "-m",
            "tacacs_server.main",
            "--config",
            str(self.config_path),
        ]

        self.process = subprocess.Popen(
            cmd,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            env=env,
            cwd=str(self.work_dir),
        )

        # Wait for server to start
        # TACACS+ may run regardless of enable_tacacs; wait for the configured port
        if self.tacacs_port:
            if not _wait_for_port("127.0.0.1", self.tacacs_port, timeout=30):
                self.stop()
                log_contents = self.get_logs()
                raise RuntimeError(
                    f"TACACS+ server failed to start on port {self.tacacs_port}\n"
                    f"Log:\n{log_contents[-2000:]}"
                )

        if (self.enable_admin_api or self.enable_admin_web) and self.web_port:
            if not _wait_for_port("127.0.0.1", self.web_port, timeout=30):
                self.stop()
                log_contents = self.get_logs()
                raise RuntimeError(
                    f"Web server failed to start on port {self.web_port}\n"
                    f"Log:\n{log_contents[-2000:]}"
                )

        # Give server a moment to fully initialize
        time.sleep(0.5)

    def stop(self):
        """Stop the server instance"""
        if self.process:
            try:
                if hasattr(os, "killpg"):
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                else:
                    self.process.terminate()
                self.process.wait(timeout=10)
            except Exception:
                try:
                    if hasattr(os, "killpg"):
                        os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                    else:
                        self.process.kill()
                except Exception:
                    pass
            finally:
                self.process = None

        if self.log_file:
            try:
                self.log_file.close()
            except Exception:
                pass
            finally:
                self.log_file = None

    def get_logs(self) -> str:
        """Get server logs"""
        if self.log_path.exists():
            return self.log_path.read_text()
        return ""

    def get_base_url(self) -> str:
        """Get base URL for web API"""
        if self.web_port:
            return f"http://127.0.0.1:{self.web_port}"
        return ""

    def login_admin(self) -> requests.Session:
        """Create authenticated admin session"""
        session = requests.Session()
        session.headers.update({"X-API-Token": self.api_token})
        base_url = self.get_base_url()
        if not base_url:
            raise RuntimeError("Admin Web server not enabled")

        last_exc: RequestException | RuntimeError | None = None

        # Retry a few times to avoid races with uvicorn binding/startup
        last_exc = None
        # Proactively wait for the port on each attempt in case uvicorn is still binding
        for attempt in range(6):
            # Ensure the port is listening before attempting login
            if self.web_port:
                _wait_for_port("127.0.0.1", self.web_port, timeout=2)
            try:
                response = session.post(
                    f"{self.get_base_url()}/admin/login",
                    json={
                        "username": self.admin_username,
                        "password": self.admin_password,
                    },
                    timeout=5,
                )
                if response.status_code == 200:
                    # Keep header and add cookie for authenticated admin routes
                    return session
                last_exc = RuntimeError(
                    f"Admin login failed: {response.status_code} {response.text}"
                )
            except requests.exceptions.RequestException as e:
                last_exc = e
            # Exponential backoff with a small cap to give the server time to settle
            time.sleep(min(0.2 * (attempt + 1), 1.0))
        # If still failing, raise the last error
        if last_exc:
            # Attach recent logs to aid debugging
            logs_tail = self.get_logs()[-2000:]
            raise RuntimeError(
                f"Admin login failed after retries: {last_exc}\n--- recent server log tail ---\n{logs_tail}"
            )
        return session

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


@pytest.fixture
def api_session() -> requests.Session:
    """Session configured with Bearer token for /api endpoints.

    Uses TEST_API_TOKEN from the environment (default 'test-token').
    """
    s = requests.Session()
    token = os.environ.get("TEST_API_TOKEN", "test-token")
    s.headers.update({"Authorization": f"Bearer {token}"})
    return s


@pytest.fixture
def temp_work_dir(tmp_path):
    """Create a temporary work directory for a test"""
    work_dir = tmp_path / "server_instance"
    work_dir.mkdir(parents=True, exist_ok=True)
    yield work_dir
    # Cleanup happens automatically via tmp_path


@pytest.fixture
def server_factory(temp_work_dir):
    """
    Factory fixture to create server instances with custom configuration.

    Usage:
        def test_something(server_factory):
            server = server_factory(
                config={"log_level": "DEBUG"},
                enable_tacacs=True,
                enable_admin_api=True
            )
            with server:
                # Test code here
                logs = server.get_logs()
    """
    created_servers = []

    def _create_server(
        config: dict[str, Any] | None = None,
        enable_tacacs: bool = True,
        enable_radius: bool = False,
        enable_admin_api: bool = False,
        enable_admin_web: bool = False,
    ) -> ServerInstance:
        config = config or {}
        server = ServerInstance(
            work_dir=temp_work_dir,
            config=config,
            enable_tacacs=enable_tacacs,
            enable_radius=enable_radius,
            enable_admin_api=enable_admin_api,
            enable_admin_web=enable_admin_web,
        )
        created_servers.append(server)
        return server

    yield _create_server

    # Cleanup all created servers
    for server in created_servers:
        try:
            server.stop()
        except Exception:
            pass


@pytest.fixture
def basic_server(server_factory):
    """
    A basic TACACS+ server with no optional features.

    Usage:
        def test_basic_auth(basic_server):
            with basic_server:
                # Server is running
                assert basic_server.tacacs_port is not None
                logs = basic_server.get_logs()
    """
    return server_factory(
        enable_tacacs=True,
        enable_radius=False,
        enable_admin_api=False,
        enable_admin_web=False,
    )


@pytest.fixture
def full_server(server_factory):
    """
    A full-featured server with all components enabled.

    Usage:
        def test_full_stack(full_server):
            with full_server:
                # All features available
                session = full_server.login_admin()
                logs = full_server.get_logs()
    """
    return server_factory(
        enable_tacacs=True,
        enable_radius=True,
        enable_admin_api=True,
        enable_admin_web=True,
    )


# Backup service initialization is now handled per-test or via server_factory
# The autouse fixture was causing issues with config isolation between tests


@pytest.fixture(scope="session")
def ftp_server(tmp_path_factory):
    """Fixture that sets up a test FTP server in a separate thread."""
    import socket

    # Create a temporary directory for the FTP server's root
    ftp_root = tmp_path_factory.mktemp("ftp_root")

    # Set up the FTP server
    authorizer = DummyAuthorizer()
    authorizer.add_user("testuser", "testpass", str(ftp_root), perm="elradfmw")

    handler = FTPHandler
    handler.authorizer = authorizer

    # Find an available port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        port = s.getsockname()[1]
        # The socket will be closed when exiting the context

    address = ("127.0.0.1", port)
    server = FTPServer(address, handler)

    # Start the server in a separate thread
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    # Yield the server info
    yield {
        "host": "localhost",
        "port": port,
        "username": "testuser",
        "password": "testpass",
        "root": str(ftp_root),
    }

    # Cleanup
    server.close_all()
    if server_thread.is_alive():
        server_thread.join(timeout=1.0)


# Clean up all temporary files at the end of the session
@pytest.fixture(scope="session", autouse=True)
def cleanup_test_artifacts():
    """Remove any test artifacts left behind"""
    yield

    import glob

    patterns = [
        "data/test_*.db*",
        "data/*test*.db*",
    ]

    for pattern in patterns:
        for file_path in glob.glob(pattern):
            try:
                Path(file_path).unlink(missing_ok=True)
            except Exception:
                pass
