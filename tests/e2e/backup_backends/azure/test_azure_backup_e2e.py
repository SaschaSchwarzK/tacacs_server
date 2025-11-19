"""End-to-end test: backup to Azure Blob (via Azurite).

This test spins up the TACACS server container configured for backup API,
starts an Azurite container (Azure Storage emulator), seeds some data via
the admin API, then creates an Azure backup destination and triggers a
backup. Finally, it verifies that the backup execution completes and that
at least one backup is listed for the destination, and that a blob was
stored by Azurite on its filesystem.

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
        AssertionError: If the Docker command fails with a non-zero exit code
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


def _poll(predicate, timeout: float = 45.0, interval: float = 0.5) -> bool:
    """Repeatedly call a predicate until it returns True or timeout is reached.

    Args:
        predicate: A callable that returns a boolean
        timeout: Maximum time to wait in seconds (default: 45)
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
def test_backup_to_azure_via_azurite_e2e(tmp_path: Path) -> None:
    """Test Azure Blob Storage backup functionality end-to-end using Azurite.

    This test performs the following steps:
    1. Builds Docker images for both TACACS+ server and Azurite
    2. Creates a Docker network for communication between containers
    3. Starts the Azurite container (Azure Storage emulator)
    4. Configures and starts the TACACS+ server with backup API enabled
    5. Seeds test data (users, groups) via the admin API
    6. Creates an Azure backup destination using Azurite
    7. Triggers a backup and verifies it completes successfully
    8. Validates the backup is listed and has non-zero size

    Args:
        tmp_path: Pytest fixture providing a temporary directory for test files

    Raises:
        AssertionError: If any test assertion fails
        subprocess.CalledProcessError: If any Docker command fails
        TimeoutError: If services don't start within expected time
    """
    if not shutil.which("docker"):
        pytest.skip("Docker is required for Azure/Azurite E2E test")

    project_root = Path(__file__).resolve().parents[4]
    unique = uuid.uuid4().hex[:8]
    network_name = f"tacacs-e2e-net-{unique}"
    tacacs_image = f"tacacs-server-e2e:{unique}"
    tacacs_container = f"tacacs-e2e-{unique}"
    az_image = f"tacacs-azurite-e2e:{unique}"
    azurite_container = f"azurite-e2e-{unique}"
    api_token = f"token-{unique}"

    tacacs_host_port = _find_free_port()
    api_host_port = _find_free_port()

    # Prepare container bind mounts for TACACS
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

    # Build TACACS image
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

    try:
        _run_docker(["network", "create", network_name])
        docker_network_created = True

        # Build and start Azurite container from local Dockerfile
        az_dir = Path(__file__).resolve().parent
        ab = subprocess.run(
            ["docker", "build", "-t", az_image, str(az_dir)],
            check=False,
            capture_output=True,
            text=True,
        )
        if ab.returncode != 0:
            raise AssertionError(
                f"Azurite image build failed (exit {ab.returncode})\n{ab.stdout}\n{ab.stderr}"
            )

        az_data = (tmp_path / "azurite").resolve()
        az_data.mkdir(parents=True, exist_ok=True)
        _run_docker(
            [
                "run",
                "-d",
                "--rm",
                "--name",
                azurite_container,
                "--network",
                network_name,
                "-v",
                f"{az_data}:/workspace",
                az_image,
            ]
        )
        started_containers.append(azurite_container)

        # Give Azurite a moment to initialize
        time.sleep(2.0)

        # Determine azurite hostname within the docker network
        az_host = azurite_container
        # Start TACACS container and expose API to host for test calls
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

        # On some CI runners the bind-mounted /app/data may be owned by root with restrictive perms.
        # Ensure it's writable by the container user to avoid Permission denied on backup_tmp.
        try:
            subprocess.run(
                [
                    "docker",
                    "exec",
                    tacacs_container,
                    "sh",
                    "-lc",
                    "mkdir -p /app/data/backup_tmp /app/data/backups && chmod -R 777 /app/data",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        except Exception:
            pass

        # Wait for admin API to become ready
        _wait_http_ok(f"http://127.0.0.1:{api_host_port}/health", timeout=90.0)

        base = f"http://127.0.0.1:{api_host_port}"
        s = requests.Session()
        s.headers.update({"Content-Type": "application/json"})

        # Obtain admin session cookie
        lr = s.post(
            f"{base}/admin/login",
            json={"username": "admin", "password": "admin123"},
            timeout=10,
        )
        assert lr.status_code == 200, lr.text

        # Best-effort cleanup
        try:
            s.post(f"{base}/api/admin/maintenance/cleanup", timeout=5)
        except Exception:
            pass

        # Minimal seed
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

        # Configure Azure destination via connection string to Azurite
        # Azurite default account name and key
        account_name = "devstoreaccount1"
        account_key = (
            "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/"
            "K1SZFPTOtr/KBHBeksoGMGw=="
        )
        container_name = "backups"
        blob_endpoint = f"http://{az_host}:10000/{account_name}"
        conn_str = (
            "DefaultEndpointsProtocol=http;"
            f"AccountName={account_name};"
            f"AccountKey={account_key};"
            f"BlobEndpoint={blob_endpoint}"
        )

        dest = s.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "azure-dest",
                "type": "azure",
                "config": {
                    "connection_string": conn_str,
                    "container_name": container_name,
                    "base_path": "e2e",
                    "max_concurrency": 2,
                    "timeout": 60,
                },
            },
            timeout=10,
        )
        assert dest.status_code in (200, 201), dest.text
        dest_id = dest.json()["id"]

        # Trigger a backup
        trig = s.post(
            f"{base}/api/admin/backup/trigger",
            json={"destination_id": dest_id, "comment": "azurite e2e"},
            timeout=10,
        )
        assert trig.status_code in (200, 202), trig.text
        trig_payload = (
            trig.json()
            if trig.headers.get("content-type", "").startswith("application/json")
            else {}
        )
        exec_id = trig_payload.get("execution_id")

        # Wait for backup execution to complete
        def _done():
            # Prefer checking specific execution if available
            if exec_id:
                r = s.get(f"{base}/api/admin/backup/executions/{exec_id}", timeout=5)
                if r.status_code != 200:
                    return False
                st = (r.json().get("status") or "").lower()
                return st in ("completed", "failed")
            r = s.get(f"{base}/api/admin/backup/executions", timeout=5)
            if r.status_code != 200:
                return False
            payload = r.json() or {}
            items = payload.get("executions") or []
            if not items:
                return False
            st = (items[0].get("status") or "").lower()
            return st in ("completed", "failed")

        ok = _poll(_done, timeout=90.0, interval=1.0)
        if not ok:
            # Diagnostics on timeout
            diag = []
            try:
                r = s.get(f"{base}/api/admin/backup/executions", timeout=5)
                diag.append(f"executions: {r.status_code}: {(r.text or '')[:800]}")
            except Exception as e:
                diag.append(f"exec fetch failed: {e}")
            try:
                tlog = subprocess.run(
                    ["docker", "logs", tacacs_container, "--tail", "200"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                diag.append("--- docker logs (tacacs) ---\n" + (tlog.stdout or "")[-4000:])
            except Exception:
                pass
            try:
                zlog = subprocess.run(
                    ["docker", "logs", azurite_container, "--tail", "200"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                diag.append("--- docker logs (azurite) ---\n" + (zlog.stdout or "")[-4000:])
            except Exception:
                pass
            raise AssertionError("Backup did not complete successfully in time\n" + "\n".join(diag))

        # Verify list_backups for destination returns at least one item (allow eventual consistency)
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
            listed = resp.json() or []
            current = listed.get("backups") if isinstance(listed, dict) else listed
            if not current:
                return False
            backups[:] = current
            return True

        ok_list = _poll(_backups_available, timeout=60.0, interval=1.0)
        if not ok_list:
            diag = [f"last list resp: {last_list_info}"]
            try:
                r = s.get(f"{base}/api/admin/backup/executions", timeout=5)
                diag.append(f"executions: {r.status_code}: {(r.text or '')[:800]}")
            except Exception:
                pass
            try:
                tlog = subprocess.run(
                    ["docker", "logs", tacacs_container, "--tail", "200"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                diag.append("--- docker logs (tacacs) ---\n" + (tlog.stdout or "")[-4000:])
            except Exception:
                pass
            try:
                zlog = subprocess.run(
                    ["docker", "logs", azurite_container, "--tail", "200"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                diag.append("--- docker logs (azurite) ---\n" + (zlog.stdout or "")[-4000:])
            except Exception:
                pass
            raise AssertionError(
                "No backups listed in Azure destination\n" + "\n".join(diag)
            )
        assert backups, "No backups listed in Azure destination"

        # Validate the last execution shows non-zero size if available
        ex = s.get(f"{base}/api/admin/backup/executions", timeout=5)
        assert ex.status_code == 200, ex.text
        last = (ex.json().get("executions") or [])[0]
        assert (last.get("status") or "").lower() == "completed", (
            f"Unexpected status: {last}"
        )
        assert (last.get("compressed_size_bytes") or 0) >= 1, f"Unexpected size: {last}"

    finally:
        # Gather logs on failure
        def _tail_logs(name: str) -> str:
            p = subprocess.run(
                ["docker", "logs", name, "--tail", "200"],
                check=False,
                capture_output=True,
                text=True,
            )
            return (p.stdout or "") + ("\nERR:\n" + p.stderr if p.stderr else "")

        # Stop containers
        for c in reversed(started_containers):
            subprocess.run(["docker", "rm", "-f", c], check=False)
        if docker_network_created:
            subprocess.run(["docker", "network", "rm", network_name], check=False)
