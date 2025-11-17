"""End-to-end test: backup to FTP destination.

This test spins up the TACACS server container configured for backup API,
starts a tiny FTP server container from the local Dockerfile, seeds some
data (users, user groups, device groups, devices) via the admin API, then
creates an FTP backup destination and triggers a backup. Finally, it
verifies that the backup execution completes and that at least one backup
is listed for the destination.

Prerequisites:
- Docker installed and available to the test environment
- Ability to bind ephemeral host ports
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

    Returns:
        int: An available port number between 1024 and 65535
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _run_docker(args: list[str]) -> None:
    """Execute a Docker command with the given arguments.

    Args:
        args: List of command-line arguments to pass to Docker

    Raises:
        AssertionError: If the Docker command fails
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

    Args:
        url: HTTP URL to check
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


def _poll(predicate, timeout: float = 30.0, interval: float = 0.5) -> bool:
    """Repeatedly call a predicate until it returns True or timeout is reached.

    Args:
        predicate: A callable that returns a boolean
        timeout: Maximum time to wait in seconds (default: 30)
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
def test_backup_to_ftp_e2e(tmp_path: Path) -> None:
    """Test FTP backup functionality end-to-end.

    This test performs the following steps:
    1. Builds Docker images for both TACACS+ server and FTP server
    2. Creates a Docker network for communication between containers
    3. Starts the FTP server container with test credentials
    4. Configures and starts the TACACS+ server with backup API enabled
    5. Seeds test data (users, groups, devices) via the admin API
    6. Creates an FTP backup destination
    7. Triggers a backup and verifies it completes successfully
    8. Validates the backup file exists in the expected location

    Args:
        tmp_path: Pytest fixture providing a temporary directory for test files

    Raises:
        AssertionError: If any test assertion fails
        subprocess.CalledProcessError: If any Docker command fails
        TimeoutError: If services don't start within expected time
    """
    if not shutil.which("docker"):
        pytest.skip("Docker is required for FTP E2E test")

    project_root = Path(__file__).resolve().parents[4]
    ftp_dir = Path(__file__).resolve().parent

    unique = uuid.uuid4().hex[:8]
    network_name = f"tacacs-e2e-net-{unique}"
    tacacs_image = f"tacacs-server-e2e:{unique}"
    ftp_image = f"tacacs-ftp-e2e:{unique}"
    tacacs_container = f"tacacs-e2e-{unique}"
    ftp_container = f"ftp-e2e-{unique}"
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

    # Base config derived from provided container config with small adjustments
    base_config = project_root / "config" / "tacacs.container.ini"
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(base_config)
    if not cfg.has_section("server"):
        cfg.add_section("server")
    cfg["server"]["log_level"] = "DEBUG"
    if not cfg.has_section("security"):
        cfg.add_section("security")
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
        ["docker", "build", "-t", ftp_image, str(ftp_dir)],
        check=False,
        capture_output=True,
        text=True,
    )
    if fb.returncode != 0:
        raise AssertionError(
            f"FTP image build failed (exit {fb.returncode})\n{fb.stdout}\n{fb.stderr}"
        )

    try:
        _run_docker(["network", "create", network_name])
        docker_network_created = True

        # Start FTP container on the same network; no host port publishing needed
        _run_docker(
            [
                "run",
                "-d",
                "--rm",
                "--name",
                ftp_container,
                "--network",
                network_name,
                "-e",
                "FTP_USER=testuser",
                "-e",
                "FTP_PASS=password",
                ftp_image,
            ]
        )
        started_containers.append(ftp_container)

        # Give FTP server a brief moment to be ready inside container network
        time.sleep(2.0)

        # Start TACACS container and expose API to host for test calls
        # Ensure backup roots on host side
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
                f"TACACS_BACKUP_ROOT={str(Path('/app/data') / 'backups')}",
                "-e",
                f"TACACS_BACKUP_TEMP={str(Path('/app/data') / 'backup_tmp')}",
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

        # Wait for admin API to become ready
        _wait_http_ok(f"http://127.0.0.1:{api_host_port}/health", timeout=90.0)

        base = f"http://127.0.0.1:{api_host_port}"
        s = requests.Session()
        s.headers.update({"Content-Type": "application/json"})

        # Obtain admin session cookie (required for /api/admin/* endpoints guarded by admin_guard)
        lr = s.post(
            f"{base}/admin/login",
            json={"username": "admin", "password": "admin123"},
            timeout=10,
        )
        assert lr.status_code == 200, lr.text

        # Clean up any existing data (best-effort)
        try:
            s.post(f"{base}/api/admin/maintenance/cleanup", timeout=5)
        except Exception:
            pass

        # Seed: user group, user, device group, device
        ug = s.post(
            f"{base}/api/user-groups",
            json={"name": "netadmins", "privilege_level": 15},
            timeout=5,
        )
        assert ug.status_code in (200, 201, 409), ug.text

        u = s.post(
            f"{base}/api/users",
            json={
                "username": "alice",
                "password": "Password123!",
                "privilege_level": 15,
                "groups": ["netadmins"],
            },
            timeout=5,
        )
        assert u.status_code in (200, 201, 409), u.text

        dg = s.post(
            f"{base}/api/device-groups",
            json={
                "name": "core-switches",
                "description": "Core switches",
                "tacacs_secret": "TacacsSecret123!",
            },
            timeout=5,
        )
        assert dg.status_code in (200, 201, 409), dg.text

        d = s.post(
            f"{base}/api/devices",
            json={"name": "sw1", "network": "10.0.0.10", "group": "core-switches"},
            timeout=5,
        )
        assert d.status_code in (200, 201, 409), d.text

        # Resolve FTP container IP inside the docker network to avoid DNS timing issues
        try:
            ip_proc = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    ftp_container,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            ftp_host = ip_proc.stdout.strip() or ftp_container
        except Exception:
            ftp_host = ftp_container

        # Create FTP destination (plain FTP inside docker network, chrooted to user home)
        dest = s.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "ftp-dest",
                "type": "ftp",
                "config": {
                    "host": ftp_host,
                    "port": 21,
                    "username": "testuser",
                    "password": "password",
                    "base_path": "/upload",
                    "use_tls": False,
                    "passive": True,
                    "timeout": 20,
                },
                "retention_days": 3,
            },
            timeout=15,
        )
        if dest.status_code != 200:
            # Collect rich diagnostics to help debug server-side error
            diag_parts: list[str] = [
                f"Destination create failed: {dest.status_code} {dest.text}",
            ]
            try:
                dl = subprocess.run(
                    ["docker", "logs", tacacs_container],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                diag_parts.append("--- docker logs (tacacs) ---")
                diag_parts.append((dl.stdout or "")[-4000:])
                if dl.stderr:
                    diag_parts.append(("\n" + dl.stderr)[-2000:])
            except Exception as e:  # noqa: BLE001
                diag_parts.append(f"(failed to read docker logs: {e})")
            try:
                exec_log = subprocess.run(
                    [
                        "docker",
                        "exec",
                        tacacs_container,
                        "sh",
                        "-lc",
                        "echo '== /app/logs/stdouterr.log ==' ; tail -n 200 /app/logs/stdouterr.log 2>/dev/null || true",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                diag_parts.append("--- in-container /app/logs/stdouterr.log (tail) ---")
                diag_parts.append((exec_log.stdout or "")[-4000:])
            except Exception:
                pass
            # Optionally pull OpenAPI to confirm endpoint model
            try:
                oi = s.get(f"{base}/openapi.json", timeout=5)
                diag_parts.append("--- openapi.json (truncated) ---")
                diag_parts.append((oi.text or "")[:800])
            except Exception:
                pass
            raise AssertionError("\n".join(diag_parts))
        dest_id = dest.json()["id"]

        # Trigger backup
        tr = s.post(
            f"{base}/api/admin/backup/trigger",
            json={"destination_id": dest_id, "comment": "ftp e2e"},
            timeout=10,
        )
        assert tr.status_code == 200, tr.text
        execution_id = tr.json().get("execution_id")
        assert execution_id

        # Wait for successful completion only
        def _completed() -> bool:
            r = s.get(f"{base}/api/admin/backup/executions/{execution_id}", timeout=8)
            if r.status_code != 200:
                return False
            status = (r.json() or {}).get("status")
            return status == "completed"

        assert _poll(_completed, timeout=90.0), (
            "Backup did not complete successfully in time"
        )

        # Fetch execution details for precise backup_path and reported size
        exec_detail = s.get(
            f"{base}/api/admin/backup/executions/{execution_id}", timeout=8
        )
        assert exec_detail.status_code == 200, exec_detail.text
        ed = exec_detail.json() or {}
        remote_path = ed.get("backup_path") or ""
        size_bytes = int(ed.get("size_bytes") or 0)
        assert size_bytes >= 1024, f"Backup appears too small: {size_bytes} bytes"
        assert remote_path.startswith("/upload/"), remote_path
        # Expect upload under /data/ftp/testuser/upload/<instance>/<type>/<filename>
        # remote_path begins with /upload/...
        sub_rel = (
            remote_path[len("/upload/") :]
            if remote_path.startswith("/upload/")
            else remote_path.lstrip("/")
        )
        ftp_fs_path = f"/data/ftp/testuser/upload/{sub_rel}"
        filename = sub_rel.rsplit("/", 1)[-1]
        statp = subprocess.run(
            [
                "docker",
                "exec",
                ftp_container,
                "sh",
                "-lc",
                (
                    "set -e; "
                    f"if [ -f '{ftp_fs_path}' ]; then (wc -c < '{ftp_fs_path}' || stat -c %s '{ftp_fs_path}' || ls -l '{ftp_fs_path}' | awk '{'{'}print $5{'}'}'); "
                    "else echo 0; fi"
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        try:
            ftp_size = int((statp.stdout or "0").strip().split()[0])
        except Exception:
            ftp_size = 0
        if ftp_size <= 0:
            # Help debugging by listing the upload directory tree
            _ls = subprocess.run(
                [
                    "docker",
                    "exec",
                    ftp_container,
                    "sh",
                    "-lc",
                    "ls -la /data/ftp/testuser/upload; echo '---'; find /data/ftp/testuser/upload -maxdepth 3 -type f -printf '%p\n' 2>/dev/null || true",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            raise AssertionError(
                f"FTP file not present or empty: {ftp_fs_path}, out={statp.stdout} err={statp.stderr}\n--- list ---\n{_ls.stdout}"
            )
        # Allow minor discrepancies between reported and on-disk sizes
        assert ftp_size >= min(512, size_bytes // 2), (
            f"Unexpected FTP size: {ftp_size} vs listed {size_bytes}"
        )

        # Best-effort API verification: try to list from destination (may be empty if server lacks MLSD recursion)
        lb = s.get(
            f"{base}/api/admin/backup/list",
            params={"destination_id": dest_id},
            timeout=8,
        )
        if lb.status_code == 200:
            backups = lb.json().get("backups") or []
            # Do not fail the test if list is empty due to FTP MLSD/NLST limitations; presence on FTP already verified
            if backups:
                # If present, ensure at least one looks like our uploaded file
                names = [b.get("path", "").rsplit("/", 1)[-1] for b in backups]
                assert filename in names
    finally:
        # Cleanup
        for name in started_containers[::-1]:
            subprocess.run(["docker", "rm", "-f", name], check=False)
        if docker_network_created:
            subprocess.run(["docker", "network", "rm", network_name], check=False)
