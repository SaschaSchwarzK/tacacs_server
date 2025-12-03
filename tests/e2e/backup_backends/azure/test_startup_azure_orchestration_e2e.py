"""End-to-end tests for Azure Blob Storage integration during server startup.

This module contains tests that verify the TACACS+ server's ability to:
- Download configuration files from Azure Blob Storage on startup
- Restore from backups stored in Azure Blob Storage
- Handle various Azure authentication methods
- Fall back to default configurations when needed

Tests in this module use Azurite (Azure Storage Emulator) to simulate Azure Blob
Storage without requiring actual Azure credentials.

Note:
    These tests require Docker to be installed and running on the host system.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest


def _find_free_port() -> int:
    """Find an available TCP port on localhost.

    Returns:
        int: An available port number that can be used for binding.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _run_docker(args: list[str]) -> None:
    """Execute a docker command and raise an exception if it fails.

    Args:
        args: List of command-line arguments to pass to 'docker'.

    Raises:
        AssertionError: If the docker command returns a non-zero exit code.
    """
    proc = subprocess.run(
        ["docker", *args], check=False, capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"docker {' '.join(args)} failed (exit {proc.returncode})\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )


def _wait_port(host: str, port: int, timeout: float = 60.0) -> None:
    """Wait until a TCP port becomes available or timeout is reached.

    Args:
        host: Hostname or IP address to connect to.
        port: TCP port number to check.
        timeout: Maximum time in seconds to wait for the port to become available.

    Raises:
        TimeoutError: If the port doesn't become available within the timeout.
    """
    start = time.time()
    last_err: str | None = None
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError as e:
            last_err = str(e)
            time.sleep(0.2)
    raise TimeoutError(f"Port {host}:{port} not ready in {timeout}s: {last_err}")


@pytest.mark.e2e
def test_startup_downloads_config_from_azure_via_azurite(tmp_path: Path) -> None:
    """Verify server downloads config from Azure Blob Storage on startup.

    This test verifies that the TACACS+ server can:
    1. Connect to Azure Blob Storage (via Azurite)
    2. Download a configuration file during startup
    3. Use the downloaded configuration to start the server

    The test uses Azurite as a local Azure Storage emulator to avoid
    requiring real Azure credentials.

    Args:
        tmp_path: Pytest fixture providing a temporary directory for test data.

    Raises:
        AssertionError: If the server fails to download or use the config.
        TimeoutError: If the server doesn't start within the expected time.
    """
    if not shutil.which("docker"):
        pytest.skip("Docker is required for Azure/Azurite E2E test")

    project_root = Path(__file__).resolve().parents[4]
    unique = uuid.uuid4().hex[:8]
    network_name = f"tacacs-e2e-net-{unique}"
    tacacs_image = f"tacacs-server-e2e:{unique}"
    tacacs_container = f"tacacs-e2e-{unique}"
    uploader_container = f"tacacs-uploader-{unique}"
    az_image = f"tacacs-azurite-e2e:{unique}"
    azurite_container = f"azurite-e2e-{unique}"

    tacacs_host_port = _find_free_port()

    # Prepare directories
    data_dir = tmp_path / "data"
    logs_dir = tmp_path / "logs"
    for d in (data_dir, logs_dir):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o777)

    started_containers: list[str] = []
    docker_network_created = False

    # Build TACACS image (server image)
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
        # Docker network
        _run_docker(["network", "create", network_name])
        docker_network_created = True

        # Build Azurite image and run container
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

        time.sleep(2.0)  # Azurite init

        # Prepare a minimal config blob content to be downloaded by startup orchestration
        config_blob = tmp_path / "tacacs.conf"
        config_blob.write_text(
            """
[server]
host=0.0.0.0
port=8049
log_level=DEBUG

[auth]
backends=local

[security]
encryption_required=false
            """.strip()
        )

        # Upload config to Azurite using the same tacacs image (has azure libs)
        account_name = "devstoreaccount1"
        account_key = (
            "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/"
            "K1SZFPTOtr/KBHBeksoGMGw=="
        )
        container_name = "config"
        blob_endpoint = f"http://{azurite_container}:10000/{account_name}"
        queue_endpoint = f"http://{azurite_container}:10001/{account_name}"
        table_endpoint = f"http://{azurite_container}:10002/{account_name}"
        conn_str = (
            "DefaultEndpointsProtocol=http;"
            f"AccountName={account_name};"
            f"AccountKey={account_key};"
            f"BlobEndpoint={blob_endpoint};"
            f"QueueEndpoint={queue_endpoint};"
            f"TableEndpoint={table_endpoint}"
        )
        remote_blob = "config/tacacs.conf"

        _run_docker(
            [
                "run",
                "--rm",
                "--name",
                uploader_container,
                "--network",
                network_name,
                "-v",
                f"{config_blob}:/tmp/tacacs.conf:ro",
                "-e",
                f"CONN_STR={conn_str}",
                "-e",
                f"CONTAINER={container_name}",
                "-e",
                f"BLOB={remote_blob}",
                "-e",
                "LOCAL_PATH=/tmp/tacacs.conf",
                tacacs_image,
                "sh",
                "-lc",
                "/opt/venv/bin/python - <<'PY'\nfrom azure.storage.blob import BlobServiceClient\nimport os\nconn=os.environ['CONN_STR']\ncont=os.environ['CONTAINER']\nblob=os.environ['BLOB']\npath=os.environ['LOCAL_PATH']\nbsc=BlobServiceClient.from_connection_string(conn)\ncc=bsc.get_container_client(cont)\ntry: cc.create_container()\nexcept Exception: pass\nbc=cc.get_blob_client(blob)\nwith open(path,'rb') as f: bc.upload_blob(f, overwrite=True)\nprint('OK')\nPY",
            ]
        )

        # Start the TACACS container WITHOUT explicit --config so startup orchestration runs
        _run_docker(
            [
                "run",
                "-d",
                "--name",
                tacacs_container,
                "--network",
                network_name,
                "-p",
                f"{tacacs_host_port}:8049",
                "-e",
                "AZURE_STORAGE_ACCOUNT=devstoreaccount1",
                "-e",
                f"AZURE_ACCOUNT_KEY={account_key}",
                "-e",
                f"AZURE_CONNECTION_STRING={conn_str}",
                "-e",
                f"AZURE_STORAGE_CONTAINER={container_name}",
                "-e",
                "AZURE_CONFIG_PATH=config",
                "-e",
                "AZURE_CONFIG_FILE=tacacs.conf",
                "-e",
                f"TACACS_BACKUP_TEMP={str(Path('/app/data') / 'backup_tmp')}",
                "-e",
                f"TACACS_BACKUP_ROOT={str(Path('/app/data') / 'backups')}",
                "-e",
                "PYTHONUNBUFFERED=1",
                "-v",
                f"{data_dir}:/app/data",
                "-v",
                f"{logs_dir}:/app/logs",
                tacacs_image,
                "sh",
                "-lc",
                "/opt/venv/bin/tacacs-server 2>&1 | tee -a /app/logs/stdouterr.log; code=$?; echo $code > /app/logs/exitcode.txt; exit $code",
            ]
        )
        started_containers.append(tacacs_container)

        # Wait for TACACS port to accept connections (server ready)
        _wait_port("127.0.0.1", tacacs_host_port, timeout=90.0)

        # Verify via container logs that startup orchestration downloaded the config
        def _logs_contain_markers() -> tuple[bool, str]:
            """Check container logs for expected success markers.

            Returns:
                tuple[bool, str]: (True, logs) if markers found, (False, logs) otherwise.
            """
            p = subprocess.run(
                ["docker", "logs", tacacs_container],
                check=False,
                capture_output=True,
                text=True,
            )
            logs = (p.stdout or "") + ("\nERR:\n" + p.stderr if p.stderr else "")
            ok = ("Config file downloaded from Azure storage" in logs) or (
                "Using Azure-downloaded config" in logs
            )
            return ok, logs

        ok = False
        last_logs = ""
        start = time.time()
        # Allow more time for emulator/SDK readiness on slower hosts
        while time.time() - start < 40.0 and not ok:
            ok, last_logs = _logs_contain_markers()
            if ok:
                break
            time.sleep(0.5)
        if not ok:
            # Diagnostics to aid debugging in CI environments
            diags = []
            diags.append("==== docker logs (tail) ====")
            diags.append(last_logs[-2000:])
            for cmd in [
                ["env"],
                [
                    "/opt/venv/bin/python",
                    "-c",
                    "import azure.storage.blob as b; print(getattr(b,'__version__','?'))",
                ],
                ["getent", "hosts", azurite_container],
            ]:
                p = subprocess.run(
                    ["docker", "exec", tacacs_container, *cmd],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                diags.append(f"==== docker exec {' '.join(cmd)} rc={p.returncode} ====")
                diags.append(
                    (p.stdout or "") + ("\nERR:\n" + p.stderr if p.stderr else "")
                )
            raise AssertionError(
                "Did not find Azure config markers in logs.\n" + "\n".join(diags)
            )

    finally:
        # Stop containers
        for c in reversed(started_containers):
            subprocess.run(["docker", "rm", "-f", c], check=False)
        if docker_network_created:
            subprocess.run(["docker", "network", "rm", network_name], check=False)


@pytest.mark.e2e
def test_startup_restores_backup_from_azure_via_azurite(tmp_path: Path) -> None:
    """Verify server restores from Azure Blob Storage backup on startup.

    This test verifies that the TACACS+ server can:
    1. Connect to Azure Blob Storage (via Azurite)
    2. Discover and download the most recent backup
    3. Restore the backup to the data directory
    4. Start successfully using the restored data

    The test uses Azurite as a local Azure Storage emulator to avoid
    requiring real Azure credentials.

    Args:
        tmp_path: Pytest fixture providing a temporary directory for test data.

    Raises:
        AssertionError: If backup restoration fails or server doesn't use restored data.
        TimeoutError: If the server doesn't start within the expected time.
    """
    if not shutil.which("docker"):
        pytest.skip("Docker is required for Azure/Azurite E2E test")

    project_root = Path(__file__).resolve().parents[4]
    unique = uuid.uuid4().hex[:8]
    network_name = f"tacacs-e2e-net-{unique}"
    tacacs_image = f"tacacs-server-e2e:{unique}"
    tacacs_container = f"tacacs-e2e-{unique}"
    uploader_container = f"tacacs-uploader-{unique}"
    az_image = f"tacacs-azurite-e2e:{unique}"
    azurite_container = f"azurite-e2e-{unique}"

    tacacs_host_port = _find_free_port()

    data_dir = tmp_path / "data"
    logs_dir = tmp_path / "logs"
    for d in (data_dir, logs_dir):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o777)

    started_containers: list[str] = []
    docker_network_created = False

    # Build TACACS image (server image)
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

        # Build and run Azurite
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

        time.sleep(2.0)

        # Create a small tar.gz backup archive locally
        archive = tmp_path / "e2e_restore.tar.gz"
        # Create content file
        content = tmp_path / "restored.txt"
        content.write_text("ok", encoding="utf-8")
        import tarfile

        with tarfile.open(archive, "w:gz") as tar:
            tar.add(str(content), arcname="restored.txt")

        # Upload archive to Azurite under base_path "backups" (default)
        account_name = "devstoreaccount1"
        account_key = (
            "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/"
            "K1SZFPTOtr/KBHBeksoGMGw=="
        )
        container_name = "backups"
        blob_endpoint = f"http://{azurite_container}:10000/{account_name}"
        queue_endpoint = f"http://{azurite_container}:10001/{account_name}"
        table_endpoint = f"http://{azurite_container}:10002/{account_name}"
        conn_str = (
            "DefaultEndpointsProtocol=http;"
            f"AccountName={account_name};"
            f"AccountKey={account_key};"
            f"BlobEndpoint={blob_endpoint};"
            f"QueueEndpoint={queue_endpoint};"
            f"TableEndpoint={table_endpoint}"
        )
        remote_blob = "backups/e2e_restore.tar.gz"

        _run_docker(
            [
                "run",
                "--rm",
                "--name",
                uploader_container,
                "--network",
                network_name,
                "-v",
                f"{archive}:/tmp/e2e_restore.tar.gz:ro",
                "-e",
                f"CONN_STR={conn_str}",
                "-e",
                f"CONTAINER={container_name}",
                "-e",
                f"BLOB={remote_blob}",
                "-e",
                "LOCAL_PATH=/tmp/e2e_restore.tar.gz",
                tacacs_image,
                "sh",
                "-lc",
                "/opt/venv/bin/python - <<'PY'\nfrom azure.storage.blob import BlobServiceClient\nimport os\nconn=os.environ['CONN_STR']\ncont=os.environ['CONTAINER']\nblob=os.environ['BLOB']\npath=os.environ['LOCAL_PATH']\nbsc=BlobServiceClient.from_connection_string(conn)\ncc=bsc.get_container_client(cont)\ntry: cc.create_container()\nexcept Exception: pass\nbc=cc.get_blob_client(blob)\nwith open(path,'rb') as f: bc.upload_blob(f, overwrite=True)\nprint('OK')\nPY",
            ]
        )

        # Start TACACS container; orchestration should restore the backup
        _run_docker(
            [
                "run",
                "-d",
                "--name",
                tacacs_container,
                "--network",
                network_name,
                "-p",
                f"{tacacs_host_port}:8049",
                "-e",
                "AZURE_STORAGE_ACCOUNT=devstoreaccount1",
                "-e",
                f"AZURE_ACCOUNT_KEY={account_key}",
                "-e",
                f"AZURE_CONNECTION_STRING={conn_str}",
                "-e",
                f"AZURE_STORAGE_CONTAINER={container_name}",
                # Default AZURE_BACKUP_PATH is "backups"; aligns with remote blob path
                "-e",
                f"TACACS_BACKUP_TEMP={str(Path('/app/data') / 'backup_tmp')}",
                "-e",
                f"TACACS_BACKUP_ROOT={str(Path('/app/data') / 'backups')}",
                "-e",
                "PYTHONUNBUFFERED=1",
                "-v",
                f"{data_dir}:/app/data",
                "-v",
                f"{logs_dir}:/app/logs",
                tacacs_image,
                "sh",
                "-lc",
                "/opt/venv/bin/tacacs-server 2>&1 | tee -a /app/logs/stdouterr.log; code=$?; echo $code > /app/logs/exitcode.txt; exit $code",
            ]
        )
        started_containers.append(tacacs_container)

        # Wait for TACACS port to accept connections (server ready)
        _wait_port("127.0.0.1", tacacs_host_port, timeout=90.0)

        # Wait for restore marker in logs to ensure extraction completed
        def _logs_contain_restore_marker() -> tuple[bool, str]:
            p = subprocess.run(
                ["docker", "logs", tacacs_container],
                check=False,
                capture_output=True,
                text=True,
            )
            logs = (p.stdout or "") + ("\nERR:\n" + p.stderr if p.stderr else "")
            ok = "Backup restored successfully from Azure storage" in logs
            return ok, logs

        ok = False
        last_logs = ""
        start = time.time()
        while time.time() - start < 40.0 and not ok:
            ok, last_logs = _logs_contain_restore_marker()
            if ok:
                break
            time.sleep(0.5)
        assert ok, (
            f"Did not find backup restore marker in logs. Tail:\n{last_logs[-2000:]}"
        )

        # Verify restored file content
        cp = subprocess.run(
            ["docker", "exec", tacacs_container, "cat", "/app/data/restored.txt"],
            check=False,
            capture_output=True,
            text=True,
        )
        if cp.returncode != 0:
            # Diagnostics to aid debugging
            ls = subprocess.run(
                ["docker", "exec", tacacs_container, "ls", "-la", "/app/data"],
                check=False,
                capture_output=True,
                text=True,
            )
            raise AssertionError(
                "Expected restored file inside container.\n"
                + f"cat rc={cp.returncode} out=\n{cp.stdout}\nerr=\n{cp.stderr}\n"
                + f"ls -la /app/data rc={ls.returncode} out=\n{ls.stdout}\nerr=\n{ls.stderr}\n"
            )
        assert (cp.stdout or "").strip() == "ok"

    finally:
        for c in reversed(started_containers):
            subprocess.run(["docker", "rm", "-f", c], check=False)
        if docker_network_created:
            subprocess.run(["docker", "network", "rm", network_name], check=False)
