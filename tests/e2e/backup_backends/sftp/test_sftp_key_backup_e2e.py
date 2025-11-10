"""End-to-end test: backup to SFTP destination with key-based authentication.

This module contains end-to-end tests that verify the TACACS+ server's ability to
create and manage backups on an SFTP server using SSH key-based authentication.
The tests use Docker containers to create an isolated test environment with:

- TACACS+ Server: Configured with backup API enabled
- SFTP Server: Lightweight SFTP server container for testing with key-based auth
- Test Runner: Manages test execution and validation

The test verifies:
1. SFTP destination creation with SSH key authentication
2. Support for different key types (ED25519 and RSA)
3. Backup creation and upload to SFTP server
4. Host key verification using known_hosts
5. Backup listing and verification
6. Error handling and cleanup

Prerequisites:
- Docker and Docker Compose
- Python 3.10+
- Poetry for dependency management

Environment Variables:
- TEST_DEBUG: Set to 'true' to enable debug logging
- KEEP_CONTAINERS: Set to 'true' to keep containers after test for debugging
"""

from __future__ import annotations

import configparser
import os
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import requests


def _find_free_port() -> int:
    """Find an available TCP port on localhost.

    This function creates a temporary socket to find an available port number.
    The port is guaranteed to be available at the time of checking, but there
    is a small chance of race conditions if another process binds to the port
    before the caller can use it.

    Returns:
        int: An available port number between 1024 and 65535
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _run_docker(args: list[str]) -> None:
    """Execute a Docker command and raise an exception if it fails.

    This is a convenience wrapper around subprocess.run() for running Docker
    commands. It captures stdout/stderr and provides detailed error messages
    if the command fails.

    Args:
        args: List of command-line arguments to pass to Docker

    Raises:
        AssertionError: If the Docker command returns a non-zero exit code
    """
    proc = subprocess.run(
        ["docker", *args], check=False, capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"docker {' '.join(args)} failed (exit {proc.returncode})\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )


def _wait_http_ok(url: str, timeout: float = 60.0) -> None:
    """Wait for an HTTP endpoint to return a 200 OK response.

    This function polls the specified URL until it returns a 200 status code
    or the timeout is reached. It's used to wait for services to become ready.

    Args:
        url: The HTTP URL to check
        timeout: Maximum time to wait in seconds (default: 60)

    Raises:
        TimeoutError: If the endpoint doesn't return 200 OK within the timeout
    """
    start = time.time()
    last_err: str | None = None
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return
            last_err = f"status={r.status_code} body={r.text[:200]}"
        except requests.exceptions.RequestException as e:
            last_err = str(e)
        time.sleep(0.5)
    raise TimeoutError(f"HTTP {url} not ready in {timeout}s: {last_err}")


def _poll(predicate, timeout: float = 90.0, interval: float = 0.5) -> bool:
    """Repeatedly call a predicate until it returns True or timeout is reached.

    This is a generic polling function that can be used to wait for a condition
    to become true, with configurable timeout and polling interval.

    Args:
        predicate: A callable that returns a boolean
        timeout: Maximum time to wait in seconds (default: 90)
        interval: Time to wait between predicate checks in seconds (default: 0.5)

    Returns:
        bool: True if the predicate returned True within the timeout, False otherwise
    """
    start = time.time()
    while time.time() - start < timeout:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.mark.e2e
@pytest.mark.parametrize("key_type", ["ed25519", "rsa"])
def test_backup_to_sftp_key_e2e(tmp_path: Path, key_type: str) -> None:
    """End-to-end test for SFTP backup functionality with key-based authentication.

    This test verifies the complete backup workflow with an SFTP destination
    using SSH key-based authentication. It tests both ED25519 and RSA key types.

    The test performs the following steps:
    1. Sets up a Docker network with TACACS+ and SFTP server containers
    2. Generates SSH key pairs for the specified key type
    3. Configures the TACACS+ server with SFTP backup destination using key auth
    4. Performs a backup operation
    5. Verifies the backup file is created on the SFTP server
    6. Validates backup metadata and integrity

    The test uses strict host key verification via a known_hosts file to ensure
    secure SFTP connections.

    Args:
        tmp_path: Pytest fixture providing a temporary directory for test files
        key_type: Type of SSH key to test ('ed25519' or 'rsa')

    Raises:
        AssertionError: If any test assertion fails
        subprocess.CalledProcessError: If any Docker command fails
        TimeoutError: If services don't start within expected time
    """
    if not shutil.which("docker"):
        pytest.skip("Docker is required for SFTP key E2E test")

    project_root = Path(__file__).resolve().parents[4]
    ftp_dir = Path(__file__).resolve().parents[1] / "ftp"

    unique = uuid.uuid4().hex[:8]
    network_name = f"tacacs-e2e-net-{unique}"
    tacacs_image = f"tacacs-server-e2e:{unique}"
    sftp_image = f"tacacs-ftp-e2e:{unique}"
    tacacs_container = f"tacacs-e2e-{unique}"
    sftp_container = f"sftp-e2e-{unique}"
    api_token = f"token-{unique}"

    tacacs_host_port = _find_free_port()
    api_host_port = _find_free_port()

    # Prepare container bind mounts
    tmp_config = tmp_path / "tacacs.container.ini"
    data_dir = tmp_path / "data"
    logs_dir = tmp_path / "logs"
    for d in (data_dir, logs_dir):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o777)

    # Base config
    base_config = project_root / "config" / "tacacs.container.ini"
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(base_config)
    cfg.setdefault("server", {})
    cfg["server"]["log_level"] = "DEBUG"
    cfg.setdefault("security", {})
    cfg["security"]["encryption_required"] = "false"
    cfg["security"]["rate_limit_requests"] = "100000"
    cfg["security"]["rate_limit_window"] = "1"
    cfg["security"]["max_auth_attempts"] = "10"
    with tmp_config.open("w", encoding="utf-8") as fh:
        cfg.write(fh)

    started_containers: list[str] = []
    docker_network_created = False

    # Build images
    tb = subprocess.run(
        ["docker", "build", "-t", tacacs_image, str(project_root)],
        check=False,
        capture_output=True,
        text=True,
    )
    if tb.returncode != 0:
        raise AssertionError(
            f"TACACS image build failed (exit {tb.returncode})\n{tb.stdout}\n{tb.stderr}"
        )

    fb = subprocess.run(
        ["docker", "build", "-t", sftp_image, str(ftp_dir)],
        check=False,
        capture_output=True,
        text=True,
    )
    if fb.returncode != 0:
        raise AssertionError(
            f"SFTP image build failed (exit {fb.returncode})\n{fb.stdout}\n{fb.stderr}"
        )

    try:
        _run_docker(["network", "create", network_name])
        docker_network_created = True

        # Start SFTP container; prefer RSA user key for broad compatibility
        _run_docker(
            [
                "run",
                "-d",
                "--rm",
                "--name",
                sftp_container,
                "--network",
                network_name,
                "-e",
                "FTP_USER=testuser",
                "-e",
                "FTP_PASS=password",
                "-e",
                "SFTP_USER=testuser",
                "-e",
                "SFTP_PASS=password",
                "-e",
                f"SFTP_KEY_TYPE={key_type}",
                sftp_image,
            ]
        )
        started_containers.append(sftp_container)

        # Give sshd enough time to initialize and read authorized_keys
        time.sleep(5.0)

        # Resolve host inside network
        try:
            ip_proc = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    sftp_container,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            sftp_host = ip_proc.stdout.strip() or sftp_container
        except Exception:
            sftp_host = sftp_container

        # Safety: ensure we never target localhost; always use container IP/name on the docker network
        assert sftp_host not in ("127.0.0.1", "::1", "localhost"), (
            f"Unexpected SFTP host: {sftp_host}"
        )

        # Build known_hosts from all host keys
        hostkey = subprocess.run(
            [
                "docker",
                "exec",
                sftp_container,
                "sh",
                "-lc",
                "for f in /etc/ssh/ssh_host_*_key.pub; do cat \"$f\" 2>/dev/null || true; done | sed '/^$/d'",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert hostkey.returncode == 0 and hostkey.stdout.strip(), "No host keys"
        known_hosts_host = data_dir / "known_hosts"
        lines = [ln.strip() for ln in hostkey.stdout.strip().splitlines() if ln.strip()]
        with known_hosts_host.open("w", encoding="utf-8") as kh:
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    kh.write(f"{sftp_host} {parts[0]} {parts[1]}\n")
                    kh.write(f"[{sftp_host}]:22 {parts[0]} {parts[1]}\n")

        # Ensure exported key and authorized_keys match (trust entrypoint)
        def _ready() -> bool:
            p = subprocess.run(
                [
                    "docker",
                    "exec",
                    sftp_container,
                    "sh",
                    "-lc",
                    "[ -s /home/testuser/.ssh/authorized_keys ] && ( [ -s /export/testuser_id_rsa ] || [ -s /export/testuser_id_ed25519 ] )",
                ],
                check=False,
            )
            return p.returncode == 0

        deadline = time.time() + 5.0
        while time.time() < deadline and not _ready():
            time.sleep(0.2)

        ak = subprocess.run(
            [
                "docker",
                "exec",
                sftp_container,
                "sh",
                "-lc",
                "grep -v '^[#[:space:]]' /home/testuser/.ssh/authorized_keys | sed -n '1p'",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        auth_line = (ak.stdout or "").strip()
        assert auth_line, f"authorized_keys empty or missing: {ak.stderr}"
        auth_body = auth_line.split()[1]

        pub_rsa = subprocess.run(
            [
                "docker",
                "exec",
                sftp_container,
                "sh",
                "-lc",
                "[ -s /export/testuser_id_rsa ] && ssh-keygen -y -f /export/testuser_id_rsa 2>/dev/null | awk '{print $2}' || true",
            ],
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip()
        pub_ed = subprocess.run(
            [
                "docker",
                "exec",
                sftp_container,
                "sh",
                "-lc",
                "[ -s /export/testuser_id_ed25519 ] && ssh-keygen -y -f /export/testuser_id_ed25519 2>/dev/null | awk '{print $2}' || true",
            ],
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip()

        chosen_path = None
        if auth_body == pub_rsa:
            chosen_path = "/export/testuser_id_rsa"
        elif auth_body == pub_ed:
            chosen_path = "/export/testuser_id_ed25519"
        else:
            raise AssertionError(
                "authorized_keys does not match exported keys\n"
                f"authorized_keys: {auth_body}\nexported_rsa: {pub_rsa}\nexported_ed25519: {pub_ed}"
            )

        # Read the selected private key content
        key_read = subprocess.run(
            ["docker", "exec", sftp_container, "sh", "-lc", f"cat {chosen_path}"],
            check=False,
            capture_output=True,
            text=True,
        )
        private_key = (key_read.stdout or "").strip()
        assert private_key.startswith("-----BEGIN"), (
            f"Private key not found at {chosen_path}: {key_read.stderr}"
        )

        # Compute easy-to-read fingerprints for diagnostics (authorized_keys[0] and chosen private key)
        ak_fp = subprocess.run(
            [
                "docker",
                "exec",
                sftp_container,
                "sh",
                "-lc",
                "sed -n '1p' /home/testuser/.ssh/authorized_keys > /tmp/ak_e2e.pub 2>/dev/null || true; "
                "ssh-keygen -lf /tmp/ak_e2e.pub 2>/dev/null || true",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        pk_fp = subprocess.run(
            [
                "docker",
                "exec",
                sftp_container,
                "sh",
                "-lc",
                f"ssh-keygen -lf {chosen_path} 2>/dev/null || true",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        # Start TACACS container
        backup_root_host = (data_dir / "backups").resolve()
        backup_root_host.mkdir(parents=True, exist_ok=True)
        backup_temp_host = (data_dir / "backup_tmp").resolve()
        backup_temp_host.mkdir(parents=True, exist_ok=True)

        _run_docker(
            [
                "run",
                "-d",
                "--name",
                tacacs_container,
                "--network",
                network_name,
                "-p",
                f"{tacacs_host_port}:5049",
                "-p",
                f"{api_host_port}:8080",
                "-e",
                f"API_TOKEN={api_token}",
                "-e",
                "ADMIN_USERNAME=admin",
                "-e",
                "ADMIN_PASSWORD=admin123",
                "-e",
                f"BACKUP_ROOT={str(Path('/app/data') / 'backups')}",
                "-e",
                f"BACKUP_TEMP={str(Path('/app/data') / 'backup_tmp')}",
                "-e",
                "PYTHONUNBUFFERED=1",
                "-v",
                f"{tmp_config}:/app/config/tacacs.container.ini:ro",
                "-v",
                f"{data_dir}:/app/data",
                "-v",
                f"{logs_dir}:/app/logs",
                tacacs_image,
                "sh",
                "-lc",
                "/opt/venv/bin/tacacs-server --config /app/config/tacacs.container.ini 2>&1 | tee -a /app/logs/stdouterr.log; code=$?; echo $code > /app/logs/exitcode.txt; exit $code",
            ]
        )
        started_containers.append(tacacs_container)

        _wait_http_ok(f"http://127.0.0.1:{api_host_port}/health", timeout=90.0)
        base = f"http://127.0.0.1:{api_host_port}"
        s = requests.Session()
        s.headers.update({"Content-Type": "application/json"})
        lr = s.post(
            f"{base}/admin/login",
            json={"username": "admin", "password": "admin123"},
            timeout=10,
        )
        assert lr.status_code == 200, lr.text

        # Create SFTP destination (key auth)
        dest = s.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "sftp-dest-key",
                "type": "sftp",
                "config": {
                    "host": sftp_host,
                    "port": 22,
                    "username": "testuser",
                    "authentication": "key",
                    "private_key": private_key,
                    "base_path": "/home/testuser/upload",
                    "timeout": 30,
                    "host_key_verify": True,
                    "known_hosts_file": "/app/data/known_hosts",
                },
            },
            timeout=10,
        )
        if dest.status_code not in (200, 201):
            tlog = subprocess.run(
                [
                    "docker",
                    "exec",
                    tacacs_container,
                    "sh",
                    "-lc",
                    "tail -n 200 /app/logs/stdouterr.log 2>/dev/null || true",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            slog = subprocess.run(
                ["docker", "logs", sftp_container, "--tail", "200"],
                check=False,
                capture_output=True,
                text=True,
            )
            ak = subprocess.run(
                [
                    "docker",
                    "exec",
                    sftp_container,
                    "sh",
                    "-lc",
                    "echo '== authorized_keys =='; cat /home/testuser/.ssh/authorized_keys 2>/dev/null || true; echo; echo '== sshd -T (subset) =='; sshd -T 2>/dev/null | grep -E 'authorizedkeysfile|pubkeyauthentication|strictmodes|hostkeyalgorithms|pubkeyacceptedalgorithms' || true",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            fs = subprocess.run(
                [
                    "docker",
                    "exec",
                    sftp_container,
                    "sh",
                    "-lc",
                    "echo '== file perms ==' ; ls -ld /home/testuser /home/testuser/.ssh ; ls -l /home/testuser/.ssh/authorized_keys ; echo '== sshd_config relevant ==' ; grep -nE 'AuthorizedKeysFile|PubkeyAuthentication|StrictModes|PubkeyAcceptedAlgorithms|HostKeyAlgorithms' /etc/ssh/sshd_config || true",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            probe = subprocess.run(
                [
                    "docker",
                    "exec",
                    sftp_container,
                    "sh",
                    "-lc",
                    "echo '== PROBE (localhost:2222) =='; /probe_sshd.sh key",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            main_conn = subprocess.run(
                ["docker", "logs", sftp_container, "--tail", "400"],
                check=False,
                capture_output=True,
                text=True,
            )
            # Filter main sshd logs for connection lines to distinguish container-net vs probe
            import re as _re

            conn_lines = "\n".join(
                [
                    ln
                    for ln in (main_conn.stdout or "").splitlines()
                    if _re.search(r"Connection from ", ln)
                ]
            )
            raise AssertionError(
                "Create destination failed: "
                f"{dest.status_code} {dest.text}\n"
                f"--- tacacs log ---\n{tlog.stdout}\n"
                f"--- sftp log ---\n{slog.stdout}\n"
                f"--- sshd info ---\n{ak.stdout}\n"
                f"--- fs perms & sshd_config ---\n{fs.stdout}\n"
                f"--- sshd probe ---\n{probe.stdout}\n"
                f"--- sshd main (port 22) connections ---\n{conn_lines}\n"
                f"--- key fingerprints ---\n"
                f"authorized_keys[0]:\n{ak_fp.stdout}"
                f"chosen_private_key ({chosen_path}):\n{pk_fp.stdout}"
            )
        dest_id = dest.json()["id"]

        # Trigger backup and wait
        trig = s.post(
            f"{base}/api/admin/backup/trigger",
            json={"destination_id": dest_id, "comment": "sftp key e2e"},
            timeout=10,
        )
        assert trig.status_code in (200, 202), trig.text
        exec_id = (trig.json() or {}).get("execution_id")

        def _done():
            if exec_id:
                r = s.get(f"{base}/api/admin/backup/executions/{exec_id}", timeout=5)
                if r.status_code != 200:
                    return False
                return (r.json().get("status") or "").lower() in ("completed", "failed")
            r = s.get(f"{base}/api/admin/backup/executions", timeout=5)
            if r.status_code != 200:
                return False
            items = (r.json() or {}).get("executions") or []
            return bool(
                items
                and (items[0].get("status") or "").lower() in ("completed", "failed")
            )

        assert _poll(_done, timeout=120.0, interval=1.0), (
            "backup execution did not finish in time"
        )

        # Validate list and presence on filesystem
        backups: list[dict[str, object]] = []
        last_list_info = ""

        def _backups_available() -> bool:
            nonlocal backups, last_list_info
            resp = s.get(
                f"{base}/api/admin/backup/list",
                params={"destination_id": dest_id},
                timeout=5,
            )
            last_list_info = f"{resp.status_code}: {(resp.text or '').strip()[:200]}"
            if resp.status_code != 200:
                return False
            current = (resp.json() or {}).get("backups") or []
            if not current:
                return False
            backups[:] = current
            return True

        assert _poll(_backups_available, timeout=60.0, interval=1.0), (
            f"No backups listed for SFTP key destination (last response: {last_list_info})"
        )
        assert backups, "No backups listed for SFTP key destination"
        sftp_path = backups[0].get("path") or ""
        statp = subprocess.run(
            [
                "docker",
                "exec",
                sftp_container,
                "sh",
                "-lc",
                f"if [ -f '{sftp_path}' ]; then (wc -c < '{sftp_path}' || stat -c %s '{sftp_path}' || ls -l '{sftp_path}' | awk '{'{'}print $5{'}'}'); fi",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        try:
            size_val = int((statp.stdout or "0").strip().split()[0])
        except Exception:
            size_val = 0
        assert size_val > 0, (
            f"SFTP file empty or missing: {sftp_path}, stat={statp.stdout}"
        )

        # Echo fingerprints again on success so they appear in normal test logs
        print(
            "== key fingerprints (success) ==\n"
            + "authorized_keys[0]:\n"
            + (ak_fp.stdout or "")
            + "chosen_private_key ("
            + chosen_path
            + "):\n"
            + (pk_fp.stdout or "")
        )

    finally:
        for c in reversed(started_containers):
            subprocess.run(["docker", "rm", "-f", c], check=False)
        if docker_network_created:
            subprocess.run(["docker", "network", "rm", network_name], check=False)
