import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tacacs_server.auth.local_user_service import LocalUserService


def _venv_python(root: Path) -> str:
    candidate = root / ".venv" / "bin" / "python"
    return str(candidate) if candidate.exists() else sys.executable

@pytest.fixture(scope="session")
def project_root() -> Path:
    return Path(__file__).parent.parent

@pytest.fixture(scope="session")
def venv_python(project_root: Path) -> str:
    return _venv_python(project_root)

@pytest.fixture(scope="session")
def server_config_file(tmp_path_factory, project_root: Path) -> Path:
    cfg_dir = tmp_path_factory.mktemp("tacacs_test_cfg")
    cfg = cfg_dir / "tacacs_test.conf"

    # Seed a local auth database with a known test user (admin / admin123)
    auth_db = cfg_dir / "local_auth.db"
    service = LocalUserService(auth_db)
    service.create_user("admin", password="admin123", enabled=True)

    # Use a shared secret that the test client will use
    shared_secret = "testsecret"

    device_db = cfg_dir / "devices.db"

    cfg.write_text(f"""[server]
host = 127.0.0.1
port = 49249
secret_key = {shared_secret}
log_level = INFO

[logging]
log_file =
log_format = %(asctime)s - %(name)s - %(levelname)s - %(message)s
log_rotation = false
max_log_size = 10MB
backup_count = 1

[auth]
backends = local
local_auth_db = {auth_db.as_posix()}

[devices]
database = {device_db.as_posix()}
default_group = default
""")
    return cfg

def _wait_for_tcp(host: str, port: int, timeout: float = 10.0) -> bool:
    """Try to connect to host:port until timeout; returns True if reachable."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except Exception:
            time.sleep(0.1)
    return False

@pytest.fixture(scope="session")
def server_process(project_root: Path, venv_python: str, server_config_file: Path):
    host = "127.0.0.1"
    port = 49249
    # read secret from the generated config so we yield the correct value
    import configparser
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(server_config_file)
    secret = cp.get("server", "secret_key", fallback="testsecret")

    # start server via package entrypoint (no top-level main.py required)
    cmd = [venv_python, "-m", "tacacs_server.main", "--config", str(server_config_file)]
    env = os.environ.copy()
    p = subprocess.Popen(
        cmd, cwd=str(project_root), stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT, text=True, env=env
    )
    try:
        if not _wait_for_tcp(host, port, timeout=15.0):
            out = ""
            try:
                if p.stdout:
                    out = "".join(p.stdout.readlines(200))
            except Exception:
                pass
            p.kill()
            raise RuntimeError(
                f"Server did not start listening on {host}:{port} in time. "
                f"Output:\n{out}"
            )
        yield {"process": p, "host": host, "port": port, "secret": secret}
    finally:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(5)
            except Exception:
                p.kill()

@pytest.fixture
def run_test_client(venv_python: str, project_root: Path):
    """
    Helper to run tests/tests_client.py (or scripts/tacacs_client.py) 
    with the venv python.
    Returns a callable: result = run_test_client(host, port, secret, username, password)
    """
    def _run(
        host: str, port: int, secret: str, username: str = "admin", 
        password: str = "admin123", timeout: int = 15
    ):
        # try tests/test_client.py first, fallback to scripts/tacacs_client.py
        candidates = [
            project_root / "tests" / "test_client.py", 
            project_root / "scripts" / "tacacs_client.py"
        ]
        script = next((str(p) for p in candidates if p.exists()), None)
        if script is None:
            raise FileNotFoundError(
                "No TACACS+ client script found in tests/ or scripts/"
            )
        cmd = [venv_python, script, host, str(port), secret, username, password]
        return subprocess.run(
            cmd, cwd=str(project_root), capture_output=True, 
            text=True, timeout=timeout
        )
    return _run
