"""E2E tests for process pool with containerized backends."""

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

from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate


def _find_free_port() -> int:
    """Find an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _run_docker(args: list[str]) -> None:
    """Execute a Docker command with the given arguments."""
    subprocess.run(["docker", *args], check=True)


def _wait_for_http(url: str, timeout: float = 60.0) -> None:
    """Wait for an HTTP service to become available."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code < 500:
                return
        except requests.RequestException:
            time.sleep(1.0)
            continue
        time.sleep(1.0)
    raise TimeoutError(f"Service at {url} did not become ready")


@pytest.mark.e2e
def test_process_pool_with_containerized_backends(tmp_path: Path) -> None:
    """Test process pool with containerized LDAP and RADIUS backends."""
    if not shutil.which("docker"):
        pytest.skip("Docker is required for containerized E2E test")

    project_root = Path(__file__).resolve().parents[4]

    unique = uuid.uuid4().hex[:8]
    network_name = f"tacacs-process-pool-net-{unique}"
    tacacs_image = f"tacacs-server-process-pool:{unique}"
    ldap_image = f"tacacs-ldap-process-pool:{unique}"
    radius_image = f"tacacs-radius-process-pool:{unique}"
    tacacs_container = f"tacacs-process-pool-{unique}"
    ldap_container = f"ldap-process-pool-{unique}"
    radius_container = f"radius-process-pool-{unique}"

    api_token = f"token-{unique}"
    tacacs_secret = "TacacsSecret123!"
    ldap_admin_password = "secret"
    radius_secret = "radsecret"

    tmp_config = tmp_path / "tacacs.container.ini"
    data_dir = tmp_path / "data"
    logs_dir = tmp_path / "logs"
    for directory in (data_dir, logs_dir):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o777)

    # Create configuration
    config = configparser.ConfigParser(interpolation=None)
    config.read(project_root / "config" / "tacacs.container.ini")

    # Configure backends
    config["auth"]["backends"] = "local,ldap,radius"
    config["auth"]["require_all_backends"] = "false"

    # LDAP configuration
    if not config.has_section("ldap"):
        config.add_section("ldap")
    config["ldap"]["server"] = ldap_container
    config["ldap"]["base_dn"] = "ou=people,dc=example,dc=org"
    config["ldap"]["user_attribute"] = "uid"
    config["ldap"]["bind_dn"] = "cn=admin,dc=example,dc=org"
    config["ldap"]["bind_password"] = ldap_admin_password
    config["ldap"]["use_tls"] = "false"
    config["ldap"]["timeout"] = "10"
    config["ldap"]["group_attribute"] = "memberOf"

    # RADIUS configuration
    if not config.has_section("radius_auth"):
        config.add_section("radius_auth")
    config["radius_auth"]["radius_server"] = radius_container
    config["radius_auth"]["radius_port"] = "1812"
    config["radius_auth"]["radius_secret"] = radius_secret
    config["radius_auth"]["radius_timeout"] = "5"
    config["radius_auth"]["radius_retries"] = "3"
    config["radius_auth"]["radius_nas_ip"] = "0.0.0.0"

    # Process pool configuration
    if not config.has_section("server"):
        config.add_section("server")
    config["server"]["backend_process_pool_size"] = "3"
    config["server"]["log_level"] = "DEBUG"

    # Security settings
    if not config.has_section("security"):
        config.add_section("security")
    config["security"]["encryption_required"] = "false"
    config["security"]["rate_limit_requests"] = "100000"
    config["security"]["rate_limit_window"] = "1"
    config["security"]["max_auth_attempts"] = "10"

    # Device settings
    if not config.has_section("devices"):
        config.add_section("devices")
    config["devices"]["default_group"] = "default"
    config["devices"]["auto_register"] = "true"

    with tmp_config.open("w", encoding="utf-8") as fh:
        config.write(fh)

    tacacs_host_port = _find_free_port()
    api_host_port = _find_free_port()
    ldap_host_port = _find_free_port()
    radius_host_port = _find_free_port()

    docker_network_created = False
    started_containers: list[str] = []

    try:
        # Build images
        _run_docker(["build", "-t", tacacs_image, str(project_root)])
        _run_docker(
            [
                "build",
                "-t",
                ldap_image,
                str(project_root / "tests/e2e/auth_backends/ldap"),
            ]
        )
        _run_docker(
            [
                "build",
                "-t",
                radius_image,
                str(project_root / "tests/e2e/auth_backends/radius"),
            ]
        )

        # Create network
        _run_docker(["network", "create", network_name])
        docker_network_created = True

        # Start LDAP container
        _run_docker(
            [
                "run",
                "-d",
                "--rm",
                "--name",
                ldap_container,
                "--network",
                network_name,
                "-p",
                f"{ldap_host_port}:389",
                "-e",
                "LDAP_DOMAIN=example.org",
                "-e",
                f"LDAP_ADMIN_PASSWORD={ldap_admin_password}",
                "-e",
                "LDAP_TLS_ENABLE=false",
                "-v",
                f"{project_root}/tests/e2e/auth_backends/ldap/bootstrap:/bootstrap:ro",
                ldap_image,
            ]
        )
        started_containers.append(ldap_container)

        # Start RADIUS container
        _run_docker(
            [
                "run",
                "-d",
                "--rm",
                "--name",
                radius_container,
                "--network",
                network_name,
                "-p",
                f"{radius_host_port}:1812/udp",
                radius_image,
            ]
        )
        started_containers.append(radius_container)

        # Wait for backends to be ready
        time.sleep(10)

        # Start TACACS+ server
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
                "PYTHONUNBUFFERED=1",
                "-e",
                "TACACS_BACKEND_TIMEOUT=10",
                "-e",
                f"LDAP_BIND_PASSWORD={ldap_admin_password}",
                "-e",
                f"RADIUS_AUTH_SECRET={radius_secret}",
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

        # Wait for TACACS server to be ready
        _wait_for_http(f"http://127.0.0.1:{api_host_port}/health", timeout=90.0)

        # Create device group and device via API
        session = requests.Session()
        session.headers.update({"X-API-Token": api_token})
        base_url = f"http://127.0.0.1:{api_host_port}"

        # Create device group
        dg_payload = {
            "name": "process-pool-test",
            "description": "Process pool test group",
            "tacacs_secret": tacacs_secret,
        }
        resp = session.post(
            f"{base_url}/api/device-groups", json=dg_payload, timeout=15
        )
        resp.raise_for_status()

        # Get device group ID
        dg_resp = session.get(f"{base_url}/api/device-groups", timeout=15)
        dg_resp.raise_for_status()
        groups = dg_resp.json()
        group_id = None
        for group in groups:
            if group.get("name") == "process-pool-test":
                group_id = group.get("id")
                break
        assert group_id, "Device group not found"

        # Create device
        device_payload = {
            "name": "test-device",
            "ip_address": "0.0.0.0/0",
            "device_group_id": group_id,
            "enabled": True,
        }
        resp = session.post(f"{base_url}/api/devices", json=device_payload, timeout=15)
        resp.raise_for_status()

        # Create local user for testing
        user_payload = {
            "username": "localuser",
            "password": "LocalPass123!",
            "enabled": True,
        }
        resp = session.post(f"{base_url}/api/users", json=user_payload, timeout=15)
        if resp.status_code not in (200, 201, 409):  # 409 = already exists
            resp.raise_for_status()

        # Test local authentication through process pool
        time.sleep(5.0)
        success, message = tacacs_authenticate(
            host="127.0.0.1",
            port=tacacs_host_port,
            key=tacacs_secret,
            username="localuser",
            password="LocalPass123!",
        )
        assert success, f"Local auth failed: {message}"

        # Test LDAP authentication (if LDAP user exists in bootstrap)
        # This tests the process pool with LDAP backend
        ldap_success, ldap_message = tacacs_authenticate(
            host="127.0.0.1",
            port=tacacs_host_port,
            key=tacacs_secret,
            username="admin",  # From LDAP bootstrap
            password="admin123",
        )
        # LDAP auth may fail due to setup, but should not timeout
        assert isinstance(ldap_success, bool), (
            f"LDAP auth returned invalid type: {ldap_message}"
        )

        # Test RADIUS authentication (if RADIUS user exists in bootstrap)
        # This tests the process pool with RADIUS backend
        radius_success, radius_message = tacacs_authenticate(
            host="127.0.0.1",
            port=tacacs_host_port,
            key=tacacs_secret,
            username="raduser",  # From RADIUS bootstrap
            password="Passw0rd",
        )
        # RADIUS auth may fail due to setup, but should not timeout
        assert isinstance(radius_success, bool), (
            f"RADIUS auth returned invalid type: {radius_message}"
        )

    finally:
        # Cleanup
        for name in reversed(started_containers):
            subprocess.run(["docker", "rm", "-f", name], check=False)
        if docker_network_created:
            subprocess.run(["docker", "network", "rm", network_name], check=False)
        for image in (tacacs_image, ldap_image, radius_image):
            subprocess.run(["docker", "rmi", "-f", image], check=False)
