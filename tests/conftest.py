"""
Test configuration and fixtures
"""

from __future__ import annotations

import configparser
import glob
import hashlib
import os
import os as _os  # Ensure early env defaults for imported tests
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

# Set test port defaults early so modules that read env at import time get them
_os.environ.setdefault("TEST_TACACS_PORT", "5049")
_os.environ.setdefault("TEST_WEB_PORT", "8080")

import pytest
import requests

from tacacs_server.auth.local_store import LocalAuthStore
from tacacs_server.auth.local_user_service import LocalUserService


@pytest.fixture(scope="session", autouse=True)
def _sync_security_test_config_with_server(tacacs_server):
    """Set SecurityConfig.TACACS_PORT to the actual started server port.

    This avoids mismatch when the server binds a random free port in tests.
    """
    try:
        from tests.security.test_security_pentest import SecurityConfig as _SecCfg

        # Update env and module constants to the actual started server
        os.environ["TEST_TACACS_PORT"] = str(tacacs_server["port"])
        os.environ["TACACS_WEB_BASE"] = (
            f"http://{tacacs_server['host']}:{tacacs_server['web_port']}"
        )
        _SecCfg.TACACS_PORT = int(tacacs_server["port"])
        _SecCfg.TACACS_HOST = tacacs_server["host"]
    except Exception:
        pass


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
    cfg["admin"]["username"] = "admin"
    # Prefer bcrypt for admin auth (AdminSessionManager requires bcrypt)
    try:
        import bcrypt as _bcrypt

        _admin_hash = _bcrypt.hashpw(b"AdminPass123!", _bcrypt.gensalt()).decode()
    except Exception:
        # Fallback to a precomputed bcrypt hash for "AdminPass123!" (cost 12)
        _admin_hash = "$2b$12$wq0c0mQzq1s9sR3q5mFQJe3sEXp5b8fQnUe3k6sTn6ZpI9b0m0vX."
    cfg["admin"]["password_hash"] = _admin_hash

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

    # Ensure sections exist (actual ports are set by isolated_test_environment)
    cfg.setdefault("server", {})
    cfg.setdefault("radius", {})
    if cfg["radius"].get("enabled", "false").lower() == "true":
        if not cfg["radius"].get("auth_port"):
            cfg["radius"]["auth_port"] = str(_find_free_port())
        if not cfg["radius"].get("acct_port"):
            cfg["radius"]["acct_port"] = str(_find_free_port())

    # Enable web monitoring/admin API consistently in tests. Port is set later
    # by isolated_test_environment to 8080 for suite compatibility.
    cfg.setdefault("monitoring", {})
    cfg["monitoring"]["enabled"] = "true"
    cfg["monitoring"]["web_host"] = "127.0.0.1"

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
    # Use non-privileged, random free ports in tests to avoid conflicts
    if not cfg.has_section("server"):
        cfg.add_section("server")
    tacacs_port = _find_free_port()
    cfg.set("server", "port", str(tacacs_port))
    if not cfg["server"].get("host"):
        cfg.set("server", "host", "127.0.0.1")
    # Bind to localhost for tests
    if not cfg["server"].get("host"):
        cfg.set("server", "host", "127.0.0.1")

    # Enable RADIUS with high, random ports for tests to include RADIUS suites
    if not cfg.has_section("radius"):
        cfg.add_section("radius")
    try:
        rad_auth_port = _find_free_port()
        rad_acct_port = _find_free_port()
    except Exception:
        rad_auth_port = 49152
        rad_acct_port = 49153
    cfg.set("radius", "enabled", "true")
    cfg.set("radius", "auth_port", str(rad_auth_port))
    cfg.set("radius", "acct_port", str(rad_acct_port))
    cfg.set("radius", "host", "127.0.0.1")
    cfg.set("radius", "share_backends", "true")
    cfg.set("radius", "share_accounting", "true")
    # Relax security knobs for parallel/concurrent tests
    if not cfg.has_section("security"):
        cfg.add_section("security")
    # Allow unencrypted TACACS for explicit unencrypted integration tests
    cfg.set("security", "encryption_required", "false")
    # Lift per-IP connection cap (respect validation: 1-1000)
    cfg.set("security", "max_connections_per_ip", "1000")
    # Make rate limit permissive to avoid throttling tests
    cfg.set("security", "rate_limit_requests", "1000000")
    cfg.set("security", "rate_limit_window", "1")
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
    # Propagate chosen ports for any tests that read env
    os.environ["TEST_TACACS_PORT"] = str(tacacs_port)
    # Pick a free web monitoring port as well to avoid collisions
    try:
        # Choose a fresh free port regardless of previous value to avoid conflicts
        web_port = _find_free_port()
    except Exception:
        web_port = 8080
    cfg["monitoring"]["web_port"] = str(web_port)
    os.environ["TEST_WEB_PORT"] = str(web_port)
    # Update config file with selected web port
    with config_path.open("w") as config_file:
        cfg.write(config_file)

    # Ensure admin credentials also available via env so defaults pick them up
    _admin_user_prev = os.environ.get("ADMIN_USERNAME")
    _admin_hash_prev = os.environ.get("ADMIN_PASSWORD_HASH")
    _secure_prev = os.environ.get("SECURE_COOKIES")
    _api_token_prev = os.environ.get("API_TOKEN")
    _api_required_prev = os.environ.get("API_TOKEN_REQUIRED")
    os.environ["ADMIN_USERNAME"] = "admin"
    try:
        import bcrypt as _bcrypt

        _hash = _bcrypt.hashpw(b"AdminPass123!", _bcrypt.gensalt()).decode()
    except Exception:
        # Fallback to a precomputed bcrypt hash for "AdminPass123!" (cost 12)
        _hash = "$2b$12$wq0c0mQzq1s9sR3q5mFQJe3sEXp5b8fQnUe3k6sTn6ZpI9b0m0vX."
    os.environ["ADMIN_PASSWORD_HASH"] = _hash

    auth_db_path = Path(cfg["auth"]["local_auth_db"])

    try:
        # Expose for any external tooling that wants to collect artifacts
        os.environ["TACACS_TEST_WORKDIR"] = str(work_dir)
        # Ensure cookies are not marked secure in HTTP test env
        os.environ["SECURE_COOKIES"] = "false"
        # Enable API and enforce token on all /api/* endpoints during tests
        os.environ["API_TOKEN"] = os.environ.get("TEST_API_TOKEN", "test-token")
        # Expose the selected local auth DB path explicitly for other fixtures
        os.environ["TACACS_TEST_AUTH_DB"] = str(auth_db_path)
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
        if _secure_prev is None:
            os.environ.pop("SECURE_COOKIES", None)
        else:
            os.environ["SECURE_COOKIES"] = _secure_prev
        if _api_token_prev is None:
            os.environ.pop("API_TOKEN", None)
        else:
            os.environ["API_TOKEN"] = _api_token_prev
        os.environ.pop("TACACS_TEST_AUTH_DB", None)
        # Clean up the temporary working directory (databases, logs)
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass


@pytest.fixture
def test_db():
    """Create a temporary test database in the allowed workdir.

    Some components (accounting DB) enforce that DB files reside under the
    server's working directory. Place ephemeral DBs under TACACS_TEST_WORKDIR
    when available to satisfy that constraint.
    """
    import uuid

    workdir = os.environ.get("TACACS_TEST_WORKDIR")
    if workdir:
        # Place under server workdir's data/ to satisfy allowed-path checks
        base = Path(workdir) / "data"
        base.mkdir(parents=True, exist_ok=True)
    else:
        base = Path(tempfile.mkdtemp())
    # Use unique filename to avoid any conflicts
    db_path = base / f"test_{uuid.uuid4().hex[:8]}.db"

    yield str(db_path)

    # Cleanup only if we created a standalone temp dir
    if not workdir:
        shutil.rmtree(base, ignore_errors=True)


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
def tacacs_server(isolated_test_environment):
    """Start TACACS+ server for tests that need it"""
    server_process = None
    try:
        # Reuse the session-scoped TACACS_CONFIG produced by isolated_test_environment
        # Use the config produced by isolated_test_environment to ensure
        # consistent DB/ports across tests and subprocess.
        session_cfg_path = isolated_test_environment.get("config_path")
        if not session_cfg_path or not Path(session_cfg_path).exists():
            # Fallback to env if dict missing (defensive)
            session_cfg_path = os.environ.get("TACACS_CONFIG")
            if not session_cfg_path or not Path(session_cfg_path).exists():
                raise RuntimeError(
                    "Session TACACS_CONFIG not set; cannot start server for tests"
                )
        cfg_path = Path(str(session_cfg_path))
        cfg_check = configparser.ConfigParser(interpolation=None)
        cfg_check.read(session_cfg_path)

        # Make minimal, safe adjustments for a local test run
        if not cfg_check.has_section("server"):
            cfg_check.add_section("server")
        cfg_check.set("server", "host", "127.0.0.1")
        # If the session config chose a privileged/occupied port, switch to a free one
        try:
            port_val = int(cfg_check.get("server", "port", fallback="49"))
        except Exception:
            port_val = 49
        if port_val < 1024:
            cfg_check.set("server", "port", str(_find_free_port()))

        if not cfg_check.has_section("radius"):
            cfg_check.add_section("radius")
        cfg_check.set("radius", "enabled", "false")

        if not cfg_check.has_section("monitoring"):
            cfg_check.add_section("monitoring")
        cfg_check.set("monitoring", "enabled", "true")
        cfg_check.set("monitoring", "web_host", "127.0.0.1")
        cfg_check.set("monitoring", "web_port", str(_find_free_port()))

        # Ensure admin auth is present (bcrypt or known fallback)
        if not cfg_check.has_section("admin"):
            cfg_check.add_section("admin")
        cfg_check.set("admin", "username", "admin")
        try:
            import bcrypt as _bcrypt
            _file_hash = _bcrypt.hashpw(b"AdminPass123!", _bcrypt.gensalt()).decode()
        except Exception:
            _file_hash = "$2b$12$wq0c0mQzq1s9sR3q5mFQJe3sEXp5b8fQnUe3k6sTn6ZpI9b0m0vX."
        cfg_check.set("admin", "password_hash", _file_hash)

        # Persist changes back to the same session config
        with cfg_path.open("w") as f:
            cfg_check.write(f)

        # DEBUG: show effective config + auth DB path
        try:
            print(f"[SERVER-DEBUG] server_cfg={cfg_path}")
            print(f"[SERVER-DEBUG] server_auth_db={cfg_check.get('auth','local_auth_db')}")
        except Exception:
            pass

        # Start server in background, capture logs for debugging in CI
        env_log = os.environ.get("TACACS_TEST_LOG", "").strip()
        if env_log:
            candidate = Path(env_log)
            log_path = (
                candidate / "tacacs_server.log" if candidate.is_dir() else candidate
            )
        else:
            log_path = Path(tempfile.mkdtemp()) / "tacacs_server.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "w+")
        # Ensure API token is available for subprocess (enables /api/*)
        if not os.environ.get("API_TOKEN"):
            os.environ["API_TOKEN"] = os.environ.get("TEST_API_TOKEN", "test-token")

        cmd = [
            "python",
            "-m",
            "tacacs_server.main",
            "--config",
            str(cfg_path),
        ]
        # Pass current environment to subprocess explicitly
        server_process = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=log_file,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            env=dict(os.environ),
        )

        # Wait for server to be ready (use configured TACACS port)
        import socket

        cfg_check = configparser.ConfigParser(interpolation=None)
        cfg_check.read(str(cfg_path))
        tacacs_port = int(cfg_check.get("server", "port", fallback="5049"))
        web_port = int(cfg_check.get("monitoring", "web_port", fallback="8080"))
        # Determine application log file from config (server writes here via logging)
        app_log_file = None
        try:
            app_log_file = cfg_check.get("logging", "log_file", fallback=None)
        except Exception:
            app_log_file = None

        for _ in range(180):  # up to ~90s with 0.5s sleeps
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(("127.0.0.1", tacacs_port))
                sock.close()
                if result == 0:
                    break
            except Exception:
                pass
            # If the process died, stop waiting and surface logs
            if server_process.poll() is not None:
                # Capture both subprocess stdio and application log file tails
                try:
                    log_file.seek(0)
                    contents = log_file.read()[-4000:]
                except Exception:
                    contents = ""
                app_tail = ""
                if app_log_file:
                    try:
                        with open(app_log_file, "r") as _af:
                            app_tail = _af.read()[-4000:]
                    except Exception:
                        app_tail = ""
                raise RuntimeError(
                    "Server process exited early.\n" \
                    + (f"Subprocess stdio tail:\n{contents}\n" if contents else "") \
                    + (f"Application log tail ({app_log_file}):\n{app_tail}" if app_tail else "")
                )
            time.sleep(0.5)
        else:
            try:
                log_file.seek(0)
                contents = log_file.read()[-4000:]
            except Exception:
                contents = ""
            app_tail = ""
            if app_log_file:
                try:
                    with open(app_log_file, "r") as _af:
                        app_tail = _af.read()[-4000:]
                except Exception:
                    app_tail = ""
            msg = "Server failed to start within timeout.\n"
            if contents:
                msg += f"Subprocess stdio tail:\n{contents}\n"
            if app_tail:
                msg += f"Application log tail ({app_log_file}):\n{app_tail}"
            raise RuntimeError(msg)

        # Optionally probe web port
        try:
            import requests

            for _ in range(40):
                try:
                    r = requests.get(
                        f"http://127.0.0.1:{web_port}/api/health", timeout=1
                    )
                    if r.status_code == 200:
                        break
                except Exception:
                    pass
                time.sleep(0.5)
        except Exception:
            pass

        os.environ["TEST_TACACS_PORT"] = str(tacacs_port)
        os.environ["TEST_WEB_PORT"] = str(web_port)
        os.environ["TACACS_WEB_BASE"] = f"http://127.0.0.1:{web_port}"
        os.environ["TACACS_SERVER_PORT"] = str(tacacs_port)
        os.environ["TACACS_LOG_PATH"] = str(log_path)

        # Debug: Show resolved ports and log file for combined runs
        print(
            f"[TEST-BOOT] TACACS 127.0.0.1:{tacacs_port} | Web 127.0.0.1:{web_port}"
        )
        print(f"[TEST-BOOT] Log file: {log_path}")

        yield {
            "host": "127.0.0.1",
            "port": tacacs_port,
            "web_port": web_port,
            "pid": server_process.pid if server_process else None,
            "log_path": str(log_path),
        }

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


# ------------------------------
# RADIUS live test fixture
# ------------------------------


@pytest.fixture(scope="session")
def radius_enabled_server():
    """Start an in-process RADIUS server (auth + acct) for integration tests.

    - Binds to 127.0.0.1 on random free ports
    - Registers a local test client for 127.0.0.1/32 with secret 'radsecret'
    - Does not require authentication backends for basic reject/accept flow tests
    """
    from tacacs_server.radius.server import RADIUSServer

    auth_port = _find_free_port()
    acct_port = _find_free_port()
    server = RADIUSServer(host="127.0.0.1", port=auth_port, accounting_port=acct_port)
    # Register local client
    server.add_client("127.0.0.1/32", secret="radsecret", name="local-test")
    # Attach a local backend and seed a test user for PASS paths
    try:
        from tacacs_server.auth.local import LocalAuthBackend
        from tacacs_server.auth.local_user_service import LocalUserService

        # Use a temporary DB under the test workdir
        db_path = str(
            (
                Path(os.environ.get("TACACS_TEST_WORKDIR", "."))
                / "radius_local_auth.db"
            ).resolve()
        )
        lus = LocalUserService(db_path)
        # Create user 'radiususer' with password 'radiuspass'
        try:
            lus.create_user("radiususer", password="radiuspass", privilege_level=1)
        except Exception:
            pass
        backend = LocalAuthBackend(db_path, service=lus)
        server.add_auth_backend(backend)
    except Exception:
        # Backend optional; tests can still assert Reject behavior
        pass
    # Start threads
    server.start()

    # Wait briefly for sockets to bind
    time.sleep(0.2)

    yield {
        "host": "127.0.0.1",
        "auth_port": auth_port,
        "acct_port": acct_port,
        "secret": "radsecret",
        "server": server,
    }

    try:
        server.stop()
    except Exception:
        pass


# Export RADIUS env for live test to run against in-process server
@pytest.fixture(scope="session", autouse=True)
def _export_radius_env_for_live(radius_enabled_server):
    try:
        os.environ["TEST_RADIUS_HOST"] = radius_enabled_server["host"]
        os.environ["TEST_RADIUS_PORT"] = str(radius_enabled_server["auth_port"])
        os.environ["TEST_RADIUS_SECRET"] = radius_enabled_server["secret"]
        # Seed default credentials expected by the live test
        os.environ.setdefault("TEST_RADIUS_USER", "radiususer")
        os.environ.setdefault("TEST_RADIUS_PASS", "radiuspass")
        yield
    finally:
        pass


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

    # Lightweight request pacing to avoid bursting admin/API endpoints when
    # suites run together. Targets only localhost admin/API calls.
    import threading as _th
    _pace_lock = getattr(_default_requests_timeout, "_pace_lock", None) or _th.Lock()
    _last_ts = getattr(_default_requests_timeout, "_last_ts", 0.0)
    setattr(_default_requests_timeout, "_pace_lock", _pace_lock)

    def _timed_request(self, method, url, **kwargs):
        orig_url = url
        if "timeout" not in kwargs or kwargs["timeout"] is None:
            kwargs["timeout"] = 5
        # Optional small pacing for localhost admin/API requests to reduce
        # burst load during combined suites. Tunable via TEST_HTTP_PACING_MS.
        try:
            from urllib.parse import urlparse as _urlparse
            parsed = _urlparse(url)
            # Conservative default pacing for localhost admin/API requests
            _http_default = 10
            if os.environ.get("RUN_PERF_TESTS"):
                _http_default = 20
            pacing_ms = int(os.environ.get("TEST_HTTP_PACING_MS", str(_http_default)) or _http_default)
            if pacing_ms and parsed.hostname in ("127.0.0.1", "localhost") and (
                "/admin/" in parsed.path or parsed.path.startswith("/api/")
            ):
                import time as _time
                with _pace_lock:
                    last = getattr(_default_requests_timeout, "_last_ts", 0.0)
                    now = _time.monotonic()
                    min_gap = pacing_ms / 1000.0
                    delta = now - last
                    if delta < min_gap:
                        _time.sleep(min_gap - delta)
                    setattr(_default_requests_timeout, "_last_ts", _time.monotonic())
        except Exception:
            pass
        # Inject API token header for /api/* requests unless explicitly provided
        try:
            if "/api/" in url:
                headers = kwargs.get("headers") or {}
                if (
                    "X-API-Token" not in {k.title(): v for k, v in headers.items()}
                    and "Authorization" not in headers
                ):
                    headers["X-API-Token"] = os.environ.get(
                        "TEST_API_TOKEN", "test-token"
                    )
                    kwargs["headers"] = headers
            # Remap localhost URLs to the active admin web port
            try:
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(url)
                if parsed.scheme in ("http", "https") and parsed.hostname in ("localhost", "127.0.0.1"):
                    # Prefer explicit TACACS_WEB_BASE if provided
                    base = os.environ.get("TACACS_WEB_BASE", "").strip()
                    new_port = None
                    if base:
                        try:
                            b = urlparse(base)
                            if b.port:
                                new_port = str(b.port)
                        except Exception:
                            pass
                    if not new_port:
                        new_port = os.environ.get("TEST_WEB_PORT")
                    if new_port:
                        netloc = f"{parsed.hostname}:{new_port}"
                        url = urlunparse(parsed._replace(netloc=netloc))
            except Exception:
                pass
        except Exception:
            pass
        try:
            return _ORIG_REQUEST(self, method, url, **kwargs)
        except Exception as _exc:
            # Emit consolidated diagnostics on request failures
            try:
                twp = os.environ.get("TEST_WEB_PORT")
                twb = os.environ.get("TACACS_WEB_BASE")
                tsp = os.environ.get("TEST_TACACS_PORT")
                logp = os.environ.get("TACACS_LOG_PATH")
                print(
                    f"[HTTP-ERROR] {method} {orig_url} -> {url} | "
                    f"TEST_WEB_PORT={twp} TACACS_WEB_BASE={twb} TEST_TACACS_PORT={tsp}"
                )
                if logp:
                    try:
                        with open(logp, "r") as _lf:
                            tail = _lf.read()[-1000:]
                        print(f"[HTTP-ERROR] server log tail:\n{tail}")
                    except Exception:
                        pass
            except Exception:
                pass
            raise

    monkeypatch.setattr(requests.Session, "request", _timed_request, raising=True)


@pytest.fixture(autouse=True)
def _pace_tacacs_connect():
    """Optionally pace TCP connect() to the TACACS port to avoid bursts.

    Controlled by env var TEST_TACACS_PACING_MS (int milliseconds). If set,
    applies a minimal inter-connect gap only for connections to
    (127.0.0.1, TEST_TACACS_PORT). This helps keep concurrent accepts under
    the server's per-IP cap during combined suites without changing prod code.
    """
    try:
        # Conservative default pacing for TACACS connect bursts
        _tac_default = 2
        if os.environ.get("RUN_PERF_TESTS"):
            _tac_default = 4
        pacing_ms = int(os.environ.get("TEST_TACACS_PACING_MS", str(_tac_default)) or _tac_default)
    except Exception:
        pacing_ms = 0
    if pacing_ms <= 0:
        # no pacing requested
        yield
        return
    try:
        tac_port_env = os.environ.get("TEST_TACACS_PORT")
        tac_port = int(tac_port_env) if tac_port_env else None
    except Exception:
        tac_port = None

    import threading as _th
    import time as _time

    pace_lock = _th.Lock()
    last_ts = {"t": 0.0}

    def _paced_connect(self, address):
        try:
            if (
                tac_port
                and isinstance(address, tuple)
                and address[0] == "127.0.0.1"
                and address[1] == tac_port
            ):
                min_gap = pacing_ms / 1000.0
                with pace_lock:
                    now = _time.monotonic()
                    delta = now - last_ts["t"]
                    if delta < min_gap:
                        _time.sleep(min_gap - delta)
                    last_ts["t"] = _time.monotonic()
        except Exception:
            pass
        return _ORIG_SOCKET_CONNECT(self, address)

    # Apply monkeypatch
    socket.socket.connect = _paced_connect
    try:
        yield
    finally:
        # Restore original connect in _restore_socket_after_test fixture as well
        pass

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
