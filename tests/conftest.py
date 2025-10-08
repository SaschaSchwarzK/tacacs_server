"""
Test configuration and fixtures
"""

from __future__ import annotations

import configparser
import glob
import hashlib
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import requests

from tacacs_server.auth.local_store import LocalAuthStore
from tacacs_server.auth.local_user_service import LocalUserService


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _resolve_path(base_dir: Path, path_value: str) -> Path:
    candidate = Path(path_value).expanduser()
    if not candidate.is_absolute():
        candidate = (base_dir / candidate).resolve()
    return candidate


def _update_config_paths(
    cfg: configparser.ConfigParser, base_dir: Path, work_dir: Path
) -> dict[Path, Path]:
    """Update config paths to point to isolated copies and return mapping."""
    mapping: dict[Path, Path] = {}

    auth_original = _resolve_path(
        base_dir, cfg.get("auth", "local_auth_db", fallback="data/local_auth.db")
    )
    auth_new = work_dir / auth_original.name
    cfg.setdefault("auth", {})
    cfg["auth"]["local_auth_db"] = str(auth_new)
    mapping[auth_original] = auth_new

    # Ensure admin credentials in file config so AdminSessionManager picks them up
    cfg.setdefault("admin", {})
    import hashlib

    cfg["admin"]["username"] = "admin"
    cfg["admin"]["password_hash"] = hashlib.sha256(b"AdminPass123!").hexdigest()

    devices_original = _resolve_path(
        base_dir, cfg.get("devices", "database", fallback="data/devices.db")
    )
    devices_new = work_dir / devices_original.name
    cfg.setdefault("devices", {})
    cfg["devices"]["database"] = str(devices_new)
    mapping[devices_original] = devices_new

    database_section = cfg.setdefault("database", {})
    account_original = _resolve_path(
        base_dir, database_section.get("accounting_db", "data/tacacs_accounting.db")
    )
    account_new = work_dir / account_original.name
    database_section["accounting_db"] = str(account_new)
    mapping[account_original] = account_new

    metrics_original = _resolve_path(
        base_dir, database_section.get("metrics_history_db", "data/metrics_history.db")
    )
    metrics_new = work_dir / metrics_original.name
    database_section["metrics_history_db"] = str(metrics_new)
    mapping[metrics_original] = metrics_new

    audit_original = _resolve_path(
        base_dir, database_section.get("audit_trail_db", "data/audit_trail.db")
    )
    audit_new = work_dir / audit_original.name
    database_section["audit_trail_db"] = str(audit_new)
    mapping[audit_original] = audit_new

    cfg.setdefault("logging", {})
    log_original = _resolve_path(
        base_dir, cfg["logging"].get("log_file", "logs/tacacs.log")
    )
    log_new = work_dir / "logs" / log_original.name
    cfg["logging"]["log_file"] = str(log_new)
    mapping[log_original] = log_new

    # Set dynamic ports for TACACS/RADIUS to avoid privileged ports in CI
    cfg.setdefault("server", {})
    # Always override to non-privileged random port for tests
    cfg["server"]["port"] = str(_find_free_port())
    cfg.setdefault("radius", {})
    if cfg["radius"].get("enabled", "false").lower() == "true":
        if not cfg["radius"].get("auth_port"):
            cfg["radius"]["auth_port"] = str(_find_free_port())
        if not cfg["radius"].get("acct_port"):
            cfg["radius"]["acct_port"] = str(_find_free_port())

    # Enable web monitoring/admin API consistently in tests
    cfg.setdefault("monitoring", {})
    cfg["monitoring"]["enabled"] = "true"
    cfg["monitoring"]["web_host"] = cfg["monitoring"].get("web_host", "127.0.0.1")
    cfg["monitoring"]["web_port"] = cfg["monitoring"].get("web_port", "8080")

    return mapping


def _ensure_parent_dirs(paths: list[Path]) -> None:
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)


@pytest.fixture(scope="session", autouse=True)
def isolated_test_environment(tmp_path_factory):
    """Use a temporary configuration and databases for all tests."""
    work_dir = Path(tmp_path_factory.mktemp("tacacs-test-env"))
    base_config = Path("config/tacacs.conf")

    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(base_config)
    path_mapping = _update_config_paths(cfg, base_config.parent, work_dir)
    _ensure_parent_dirs(list(path_mapping.values()))

    config_path = work_dir / "tacacs_test.conf"
    with config_path.open("w") as config_file:
        cfg.write(config_file)

    for original, new in path_mapping.items():
        if original.exists():
            shutil.copy2(original, new)

    original_env = os.environ.get("TACACS_CONFIG")
    os.environ["TACACS_CONFIG"] = str(config_path)

    # Ensure admin credentials also available via env so defaults pick them up
    _admin_user_prev = os.environ.get("ADMIN_USERNAME")
    _admin_hash_prev = os.environ.get("ADMIN_PASSWORD_HASH")
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD_HASH"] = hashlib.sha256(b"AdminPass123!").hexdigest()

    auth_db_path = Path(cfg["auth"]["local_auth_db"])

    try:
        yield {
            "config_path": config_path,
            "work_dir": work_dir,
            "auth_db": auth_db_path,
        }
    finally:
        if original_env is None:
            os.environ.pop("TACACS_CONFIG", None)
        else:
            os.environ["TACACS_CONFIG"] = original_env
        if _admin_user_prev is None:
            os.environ.pop("ADMIN_USERNAME", None)
        else:
            os.environ["ADMIN_USERNAME"] = _admin_user_prev
        if _admin_hash_prev is None:
            os.environ.pop("ADMIN_PASSWORD_HASH", None)
        else:
            os.environ["ADMIN_PASSWORD_HASH"] = _admin_hash_prev


@pytest.fixture
def test_db():
    """Create a temporary test database"""
    import uuid

    temp_dir = tempfile.mkdtemp()
    # Use unique filename to avoid any conflicts
    db_path = Path(temp_dir) / f"test_{uuid.uuid4().hex[:8]}.db"

    yield str(db_path)

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def user_service(test_db):
    """Create a LocalUserService with test database"""
    return LocalUserService(test_db)


@pytest.fixture
def auth_store(test_db):
    """Create a LocalAuthStore with test database"""
    return LocalAuthStore(test_db)


@pytest.fixture
def test_user(user_service):
    """Create a test user"""
    import uuid

    username = f"testuser_{uuid.uuid4().hex[:8]}"
    return user_service.create_user(username, password="TestPass123")


@pytest.fixture
def server_process():
    """Mock server process for integration tests."""
    return {"host": "127.0.0.1", "port": 49, "secret": "test123"}


@pytest.fixture(scope="session")
def tacacs_server():
    """Start TACACS+ server for tests that need it"""
    server_process = None
    try:
        # Start server in background
        server_process = subprocess.Popen(
            [
                "python",
                "-m",
                "tacacs_server.main",
                "--config",
                os.environ.get("TACACS_CONFIG", "config/tacacs.conf"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )

        # Wait for server to be ready (use configured TACACS port)
        import socket

        cfg_check = configparser.ConfigParser(interpolation=None)
        cfg_check.read(os.environ.get("TACACS_CONFIG", "config/tacacs.conf"))
        tacacs_port = int(cfg_check.get("server", "port", fallback="5049"))

        for _ in range(60):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(("127.0.0.1", tacacs_port))
                sock.close()
                if result == 0:
                    break
            except Exception:
                pass
            time.sleep(1)
        else:
            raise RuntimeError("Server failed to start within 60 seconds")

        # Optionally probe web port
        try:
            import requests

            for _ in range(30):
                try:
                    r = requests.get("http://127.0.0.1:8080/api/health", timeout=1)
                    if r.status_code == 200:
                        break
                except Exception:
                    pass
                time.sleep(1)
        except Exception:
            pass

        os.environ["TEST_TACACS_PORT"] = str(tacacs_port)
        os.environ["TEST_WEB_PORT"] = "8080"

        yield {"host": "127.0.0.1", "port": tacacs_port, "web_port": 8080}

    finally:
        # Stop server
        if server_process:
            try:
                if hasattr(os, "killpg"):
                    os.killpg(os.getpgid(server_process.pid), signal.SIGTERM)
                else:
                    server_process.terminate()
                server_process.wait(timeout=10)
            except Exception:
                try:
                    if hasattr(os, "killpg"):
                        os.killpg(os.getpgid(server_process.pid), signal.SIGKILL)
                    else:
                        server_process.kill()
                except Exception:
                    pass


@pytest.fixture
def live_server(tacacs_server):
    """Alias for tacacs_server fixture for backward compatibility"""
    return tacacs_server


@pytest.fixture
def run_test_client():
    """Mock test client runner."""

    def _run_client(host, port, secret, username, password):
        from types import SimpleNamespace

        return SimpleNamespace(
            returncode=0, stdout="✓ Authentication PASSED", stderr=""
        )

    return _run_client


def pytest_sessionfinish(session, exitstatus):
    """Clean up test databases after all tests complete"""
    patterns = [
        "data/test_*.db*",
        "data/*test*.db*",
        "data/tmp_*.db*",
        "data/*_[a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9].db*",
        "data/change_users_*.db*",
        "data/reload_users_*.db*",
        "data/seed_users_*.db*",
        "data/users_*.db*",
        "data/radius_auth_*.db*",
    ]

    for pattern in patterns:
        for file_path in glob.glob(pattern):
            try:
                Path(file_path).unlink(missing_ok=True)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Global default timeout for all requests calls in tests
# ---------------------------------------------------------------------------
_ORIG_REQUEST = requests.Session.request
_ORIG_SOCKET_CONNECT = socket.socket.connect
_ORIG_SOCKET_SEND = socket.socket.send


@pytest.fixture(autouse=True)
def _default_requests_timeout(monkeypatch):
    """Ensure every HTTP request in tests is bounded by a timeout.

    Tests can still override by passing timeout explicitly.
    """

    def _timed_request(self, method, url, **kwargs):
        if "timeout" not in kwargs or kwargs["timeout"] is None:
            kwargs["timeout"] = 5
        return _ORIG_REQUEST(self, method, url, **kwargs)

    monkeypatch.setattr(requests.Session, "request", _timed_request, raising=True)


@pytest.fixture(autouse=True)
def _restore_socket_after_test():
    """Ensure socket monkeypatches are restored after each test.

    Guards against cross-test leakage from chaos/security monkeypatches.
    """
    try:
        yield
    finally:
        try:
            socket.socket.connect = _ORIG_SOCKET_CONNECT
            socket.socket.send = _ORIG_SOCKET_SEND
        except Exception:
            pass
