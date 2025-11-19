"""Containerized E2E for process-pool authentication across supported backends.

Purpose
-------
- Validate that the TACACS+ server runs in a Dockerized environment with a working
  process pool and that supported backends authenticate via worker processes without
  falling back to the thread pool.
- Assert positive evidence (worker-only markers: ``process_pool.handled``) and absence
  of negative evidence (no process-pool fallback) in the container logs.

Environment assumptions
-----------------------
- Requires Docker. Skips if Docker is unavailable.
- Starts an ephemeral network and three containers: TACACS server, FreeRADIUS, OpenLDAP.
- Okta is excluded by default; it is only enabled when E2E_OKTA=1 and Okta env values
  are provided. This keeps the test hermetic and avoids external network dependencies.

Log sources
-----------
- Both stdout/stderr and file-based ``/app/logs/tacacs.log`` are read to assert markers,
  because some structured logs are written to file inside the container.
"""

from __future__ import annotations

import configparser
import os
import shutil
import socket
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import requests

from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate


@pytest.mark.e2e
def test_tacacs_server_with_containerized_process_pool(tmp_path: Path) -> None:
    """Run TACACS+ server with process pool in containers and assert pool usage.

    Steps
    -----
    - Build and run containers (server, LDAP, RADIUS) in an ephemeral Docker network.
    - Configure server with process-pool size and enable monitoring for health checks.
    - Provision a local user and a device/device-group via the HTTP API.
    - For each backend (local, radius, ldap; optionally okta if enabled):
      - Capture logs before a concurrent auth burst.
      - Run a small burst of concurrent authentication requests.
      - Assert no log lines indicate process-pool fallback since the snapshot.
      - Assert presence of the worker-only handled marker for the backend.

    Rationale
    ---------
    Positive + negative log assertions provide strong evidence that authentication
    occurs in worker processes rather than the thread fallback. File logs are included
    to avoid missing structured entries that do not go to stdout.
    """

    if not shutil.which("docker"):
        pytest.skip("Docker is required for this E2E test")

    # Find project root by looking for Dockerfile
    current = Path(__file__).resolve()
    project_root = None
    for parent in current.parents:
        if (parent / "Dockerfile").exists() and (parent / "pyproject.toml").exists():
            project_root = parent
            break

    if not project_root:
        raise RuntimeError(
            f"Could not find project root with Dockerfile from {current}"
        )

    process_pool_dir = Path(__file__).resolve().parent / "process_pool"

    unique = uuid.uuid4().hex[:8]
    network_name = f"tacacs-e2e-net-{unique}"
    tacacs_image = f"tacacs-server-e2e:{unique}"
    radius_image = f"freeradius-e2e:{unique}"
    ldap_image = "osixia/openldap:1.5.0"
    tacacs_container = f"tacacs-e2e-{unique}"
    radius_container = f"freeradius-e2e-{unique}"
    ldap_container = f"openldap-e2e-{unique}"
    api_token = f"token-{unique}"

    tacacs_secret = "TacacsSecret123!"
    radius_secret = "radsecret"

    tmp_config = tmp_path / "tacacs.container.ini"
    data_dir = tmp_path / "data"
    logs_dir = tmp_path / "logs"
    for directory in (data_dir, logs_dir):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o777)

    print(f"T̳A̳C̳A̳C̳S̳ ̳L̳o̳g̳s̳ ̳D̳i̳r̳e̳c̳t̳o̳r̳y̳:̳ ̳{logs_dir}")

    # Read and update config
    config = configparser.ConfigParser()
    config_path = process_pool_dir / "tacacs.container.ini"
    read_files = config.read(str(config_path))

    if not read_files:
        raise RuntimeError(f"Failed to read config from {config_path}")

    # Update backends and process pool
    enable_okta_flag = os.getenv("E2E_OKTA", "0") == "1"
    okta_org = os.getenv("OKTA_ORG_URL")
    okta_token = os.getenv("OKTA_API_TOKEN")
    enable_okta = enable_okta_flag and bool(okta_org) and bool(okta_token)
    if not enable_okta:
        reasons: list[str] = []
        if not enable_okta_flag:
            reasons.append("E2E_OKTA=1 not set")
        if not okta_org:
            reasons.append("OKTA_ORG_URL missing")
        if not okta_token:
            reasons.append("OKTA_API_TOKEN missing")
        print(f"WARNING: Okta backend test excluded ({'; '.join(reasons)})")
    else:
        print("INFO: Okta backend test enabled")
    if enable_okta:
        config["auth"]["backends"] = "local,ldap,radius,okta"
    else:
        config["auth"]["backends"] = "local,ldap,radius"
    config["server"]["backend_process_pool_size"] = "3"
    # Ensure monitoring web server is enabled for /health endpoint
    if not config.has_section("monitoring"):
        config.add_section("monitoring")
    config["monitoring"]["enabled"] = "true"
    config["monitoring"]["web_host"] = "0.0.0.0"
    config["monitoring"]["web_port"] = "8080"

    # Update container hostnames
    config["ldap"]["server"] = ldap_container
    config["radius_auth"]["radius_server"] = radius_container
    # Write concrete Okta values (avoid ${VAR} placeholders not expanded by loader)
    if enable_okta:
        if not config.has_section("okta"):
            config.add_section("okta")
        config["okta"]["org_url"] = os.getenv("OKTA_ORG_URL", "")
        config["okta"]["api_token"] = os.getenv("OKTA_API_TOKEN", "")

    with tmp_config.open("w", encoding="utf-8") as fh:
        config.write(fh)

    tacacs_host_port = _find_free_port()
    api_host_port = _find_free_port()

    docker_network_created = False
    started_containers: list[str] = []

    try:
        _run_docker(["build", "--no-cache", "-t", tacacs_image, str(project_root)])
        _run_docker(
            [
                "build",
                "--no-cache",
                "-t",
                radius_image,
                str(process_pool_dir.parent / "process_pool_radius"),
            ]
        )

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
                "-e",
                "LDAP_ORGANISATION=Example Inc.",
                "-e",
                "LDAP_DOMAIN=example.org",
                "-e",
                "LDAP_BASE_DN=dc=example,dc=org",
                "-e",
                "LDAP_ADMIN_PASSWORD=adminpassword",
                ldap_image,
            ]
        )
        started_containers.append(ldap_container)
        _wait_for_ldap_ready(ldap_container)
        _ensure_ldap_base(ldap_container)
        _verify_ldap_base_present(ldap_container)
        _create_ldap_ou(ldap_container)
        _create_ldap_user(ldap_container, "ldapuser", "LdapPass123!")

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
                "freeradius-e2e:" + unique,
            ]
        )
        started_containers.append(radius_container)
        _wait_for_radius_logs(radius_container)

        # Start TACACS+ container
        tacacs_cmd = [
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
            "TACACS_BACKEND_PROCESS_POOL_SIZE=2",
            "-e",
            "LDAP_BIND_PASSWORD=adminpassword",
            "-e",
            f"RADIUS_AUTH_SECRET={radius_secret}",
            "-e",
            f"OKTA_ORG_URL={os.getenv('OKTA_ORG_URL', 'https://dev-test.okta.com')}",
            "-e",
            f"OKTA_API_TOKEN={os.getenv('OKTA_API_TOKEN', 'test_token')}",
            "-v",
            f"{tmp_config}:/app/config/tacacs.container.ini:ro",
            "-v",
            f"{data_dir}:/app/data",
            "-v",
            f"{logs_dir}:/app/logs",
            tacacs_image,
            "sh",
            "-lc",
            "/opt/venv/bin/tacacs-server --config /app/config/tacacs.container.ini",
        ]

        print(
            f"Starting TACACS container with: docker {' '.join(_redact_sensitive_args(tacacs_cmd))}"
        )
        _run_docker(tacacs_cmd)
        started_containers.append(tacacs_container)

        # Check TACACS container logs before waiting
        time.sleep(3)
        logs_result = subprocess.run(
            ["docker", "logs", tacacs_container], capture_output=True, text=True
        )
        print(f"TACACS container logs:\n{logs_result.stdout}\n{logs_result.stderr}")

        _wait_for_http(f"http://127.0.0.1:{api_host_port}/health", timeout=90.0)

        session = requests.Session()
        session.headers.update({"X-API-Token": api_token})
        base_url = f"http://127.0.0.1:{api_host_port}"

        # Setup Local User
        user_payload = {
            "username": "localuser",
            "password": "LocalPassword123!",
            "enabled": True,
        }
        resp = session.post(f"{base_url}/api/users", json=user_payload, timeout=15)
        resp.raise_for_status()

        # Setup Device Group and Device
        dg_payload = {"name": "test-group", "tacacs_secret": tacacs_secret}
        resp = session.post(
            f"{base_url}/api/device-groups", json=dg_payload, timeout=15
        )
        resp.raise_for_status()
        group_id = resp.json()["id"]

        device_payload = {
            "name": "test-device",
            "ip_address": "0.0.0.0/0",
            "device_group_id": group_id,
        }
        resp = session.post(f"{base_url}/api/devices", json=device_payload, timeout=15)
        resp.raise_for_status()

        time.sleep(5)

        # Test backends (limit burst size to avoid hitting auth rate limiter)
        # Verify each backend runs via process pool (no fallback to threading)
        local_logs_before = _get_container_logs(tacacs_container)
        _run_concurrent_auth_test(
            "local",
            tacacs_host_port,
            tacacs_secret,
            "localuser",
            "LocalPassword123!",
            num_requests=3,
            max_workers=3,
        )
        _assert_no_pool_fallback_since(
            tacacs_container, local_logs_before, backend_label="local"
        )
        _assert_worker_handled_since(
            tacacs_container, local_logs_before, backend_label="local"
        )
        time.sleep(0.2)
        radius_logs_before = _get_container_logs(tacacs_container)
        _run_concurrent_auth_test(
            "RADIUS",
            tacacs_host_port,
            tacacs_secret,
            "raduser",
            "Passw0rd",
            num_requests=3,
            max_workers=3,
        )
        _assert_no_pool_fallback_since(
            tacacs_container, radius_logs_before, backend_label="radius"
        )
        _assert_worker_handled_since(
            tacacs_container, radius_logs_before, backend_label="radius"
        )
        time.sleep(0.2)
        ldap_logs_before = _get_container_logs(tacacs_container)
        _run_concurrent_auth_test(
            "LDAP",
            tacacs_host_port,
            tacacs_secret,
            "ldapuser",
            "LdapPass123!",
            num_requests=3,
            max_workers=3,
        )
        _assert_no_pool_fallback_since(
            tacacs_container, ldap_logs_before, backend_label="ldap"
        )
        _assert_worker_handled_since(
            tacacs_container, ldap_logs_before, backend_label="ldap"
        )
        time.sleep(0.2)
        if enable_okta:
            okta_logs_before = _get_container_logs(tacacs_container)
            _run_concurrent_auth_test(
                "Okta",
                tacacs_host_port,
                tacacs_secret,
                "testuser",
                "TestPass123!",
                num_requests=3,
                max_workers=3,
            )
            _assert_no_pool_fallback_since(
                tacacs_container, okta_logs_before, backend_label="okta"
            )
            _assert_worker_handled_since(
                tacacs_container, okta_logs_before, backend_label="okta"
            )

    finally:
        # List files in logs_dir
        log_files = list(logs_dir.glob("**/*"))
        print(f"--- Files in {logs_dir} ---")
        for f in log_files:
            print(f)
        print("--- End of file list ---")

        # Print logs
        for log_file in log_files:
            if log_file.is_file():
                print(f"--- Contents of {log_file} ---")
                with log_file.open("r", encoding="utf-8") as f:
                    print(f.read())
                print(f"--- End of log file {log_file} ---")

        for name in reversed(started_containers):
            # The following line is commented out to allow for debugging of the container
            subprocess.run(
                ["docker", "rm", "-f", name], check=False, capture_output=True
            )
            # pass
        if docker_network_created:
            subprocess.run(
                ["docker", "network", "rm", network_name],
                check=False,
                capture_output=True,
            )
        subprocess.run(
            ["docker", "rmi", "-f", tacacs_image, radius_image],
            check=False,
            capture_output=True,
        )


def _run_concurrent_auth_test(
    backend_name: str,
    port: int,
    secret: str,
    username: str,
    password: str,
    num_requests: int = 20,
    max_workers: int = 10,
):
    """Run concurrent authentication test."""
    print(f"--- Running concurrent auth test for {backend_name} backend ---")

    def auth_worker(user_id):
        # Retry on transient rate limiting
        attempts = 0
        last_message = ""
        while attempts < 6:
            success, message = tacacs_authenticate(
                host="127.0.0.1",
                port=port,
                key=secret,
                username=username,
                password=password,
            )
            if success:
                return success, message, user_id
            last_message = message or ""
            if "rate limit exceeded" in last_message:
                # brief backoff before retrying
                import time as _t

                _t.sleep(0.1)
                attempts += 1
                continue
            break
        return False, last_message or message, user_id

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(auth_worker, i) for i in range(num_requests)]
        results = [f.result() for f in futures]

    assert len(results) == num_requests
    for success, message, user_id in results:
        assert success, (
            f"Concurrent auth failed for {backend_name} worker {user_id}: {message}"
        )
    print(f"--- {backend_name} backend test successful ---")


def _redact_sensitive_args(args: list[str]) -> list[str]:
    """Redact sensitive arguments from docker command for logging."""
    SENSITIVE_KEYS = [
        "API_TOKEN",
        "RADIUS_AUTH_SECRET",
        "LDAP_BIND_PASSWORD",
        "OKTA_API_TOKEN",
    ]
    redacted = []
    i = 0
    while i < len(args):
        arg = args[i]
        # If the argument is "-e" and followed by KEY=VALUE, check redaction
        if arg == "-e" and i + 1 < len(args):
            next_arg = args[i + 1]
            for key in SENSITIVE_KEYS:
                if next_arg.startswith(f"{key}="):
                    # redact value from KEY=VALUE
                    redacted.append(arg)
                    redacted.append(f"{key}=<REDACTED>")
                    i += 2
                    break
            else:
                redacted.append(arg)
                redacted.append(next_arg)
                i += 2
            continue
        # Also cover KEY=VALUE passed as a standalone arg (not via -e)
        for key in SENSITIVE_KEYS:
            if arg.startswith(f"{key}="):
                redacted.append(f"{key}=<REDACTED>")
                break
        else:
            redacted.append(arg)
        i += 1
    return redacted


def _run_docker(args: list[str]) -> None:
    """Execute a Docker command."""
    result = subprocess.run(["docker", *args], capture_output=True, text=True)
    if result.returncode != 0:
        # enable only for debug
        # print(f"Docker command failed: {' '.join(_redact_sensitive_args(args))}")
        # print(f"STDOUT: {result.stdout}")
        # print(f"STDERR: {result.stderr}")
        raise subprocess.CalledProcessError(
            result.returncode, result.args, result.stdout, result.stderr
        )


def _get_container_logs(container: str) -> str:
    """Fetch full logs for a container (stdout+stderr)."""
    pr = subprocess.run(
        ["docker", "logs", container], check=False, capture_output=True, text=True
    )
    docker_out = (pr.stdout or "") + (pr.stderr or "")
    # Also include file-based logs written to /app/logs/tacacs.log inside the container
    pr2 = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "sh",
            "-lc",
            "cat /app/logs/tacacs.log 2>/dev/null || true",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    file_out = (pr2.stdout or "") + ("\n" + pr2.stderr if pr2.stderr else "")
    return docker_out + "\n" + file_out


def _assert_no_pool_fallback_since(
    container: str, before_logs: str, backend_label: str
) -> None:
    """Assert no process-pool fallback occurred in logs appended since before_logs."""
    current = _get_container_logs(container)
    suffix = (
        current[len(before_logs) :] if len(current) >= len(before_logs) else current
    )
    fallback_msg = "Backend not supported in process pool"
    assert fallback_msg not in suffix, (
        f"Process-pool fallback detected for {backend_label} in new log output"
    )


def _assert_worker_handled_since(
    container: str, before_logs: str, backend_label: str
) -> None:
    """Assert that a worker-only handled marker appears for the backend since before_logs."""
    current = _get_container_logs(container)
    suffix = (
        current[len(before_logs) :] if len(current) >= len(before_logs) else current
    )
    needle = f"process_pool.handled backend={backend_label}"
    assert needle in suffix, (
        f"Expected worker-handled marker '{needle}' not found in new log output for {backend_label}"
    )


def _find_free_port() -> int:
    """Find an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_http(url: str, timeout: float = 60.0) -> None:
    """Wait for an HTTP service to become available."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code < 500:
                return
        except requests.RequestException:
            # print(f"Still waiting for {url}: {e}")
            time.sleep(1.0)
            continue
        time.sleep(1.0)
    raise TimeoutError(f"Service at {url} did not become ready")


def _wait_for_radius_logs(container: str, timeout: float = 30.0) -> None:
    """Wait for FreeRADIUS container to be ready."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        pr = subprocess.run(
            ["docker", "logs", container], check=False, capture_output=True, text=True
        )
        logs = (pr.stdout or "") + ("\n" + pr.stderr if pr.stderr else "")
        if "Ready to process requests" in logs:
            return
        time.sleep(0.5)
    raise TimeoutError("FreeRADIUS not ready")


def _wait_for_ldap_ready(container: str, timeout: float = 120.0) -> None:
    """Wait for OpenLDAP to start and accept admin binds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        # Try admin bind search of root DSE
        pr = subprocess.run(
            [
                "docker",
                "exec",
                container,
                "ldapsearch",
                "-x",
                "-D",
                "cn=admin,dc=example,dc=org",
                "-w",
                "adminpassword",
                "-b",
                "",
                "-s",
                "base",
                "namingContexts",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if pr.returncode == 0:
            return
        time.sleep(0.5)
    raise TimeoutError("OpenLDAP admin bind not ready")


def _create_ldap_ou(container: str) -> None:
    """Create ou=people organizational unit in LDAP."""
    ldif = """dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people
"""
    # Attempt create; okay if already exists
    res = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            container,
            "ldapadd",
            "-H",
            "ldap://127.0.0.1",
            "-x",
            "-D",
            "cn=admin,dc=example,dc=org",
            "-w",
            "adminpassword",
        ],
        input=ldif,
        check=False,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0 and "Already exists" not in (res.stderr or "") + (
        res.stdout or ""
    ):
        raise RuntimeError(
            f"Failed to create ou=people: rc={res.returncode} out={res.stdout} err={res.stderr}"
        )


def _ensure_ldap_base(container: str) -> None:
    """Ensure base DN dc=example,dc=org exists; create if missing.

    Some image variants may delay base creation; proactively add it if ldapsearch
    returns err=32.
    """
    # Always try to add the base; ignore if it already exists
    base_ldif = """dn: dc=example,dc=org
objectClass: top
objectClass: dcObject
objectClass: organization
o: Example Inc.
dc: example
"""
    res = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            container,
            "ldapadd",
            "-H",
            "ldap://127.0.0.1",
            "-x",
            "-D",
            "cn=admin,dc=example,dc=org",
            "-w",
            "adminpassword",
        ],
        input=base_ldif,
        check=False,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0 and "Already exists" not in (res.stderr or "") + (
        res.stdout or ""
    ):
        # One more retry after short sleep (race during initial provisioning)
        time.sleep(1.0)
        res2 = subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                container,
                "ldapadd",
                "-H",
                "ldap://127.0.0.1",
                "-x",
                "-D",
                "cn=admin,dc=example,dc=org",
                "-w",
                "adminpassword",
            ],
            input=base_ldif,
            check=False,
            capture_output=True,
            text=True,
        )
        if res2.returncode != 0 and "Already exists" not in (res2.stderr or "") + (
            res2.stdout or ""
        ):
            raise RuntimeError(
                f"Failed to create base DN: rc={res2.returncode} out={res2.stdout} err={res2.stderr}"
            )


def _verify_ldap_base_present(container: str, timeout: float = 20.0) -> None:
    """Verify base DN is present in namingContexts (admin bind)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        pr = subprocess.run(
            [
                "docker",
                "exec",
                container,
                "ldapsearch",
                "-x",
                "-D",
                "cn=admin,dc=example,dc=org",
                "-w",
                "adminpassword",
                "-b",
                "",
                "-s",
                "base",
                "namingContexts",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if pr.returncode == 0 and "namingContexts: dc=example,dc=org" in (
            pr.stdout or ""
        ):
            return
        time.sleep(0.5)
    raise TimeoutError("LDAP base DN not present")


def _create_ldap_user(container: str, username: str, password: str) -> None:
    """Create a test user in LDAP."""
    ldif = f"""dn: uid={username},ou=people,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: {username}
sn: {username}
givenName: Test
cn: Test {username}
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/{username}
userPassword: {password}
"""
    res = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            container,
            "ldapadd",
            "-H",
            "ldap://127.0.0.1",
            "-x",
            "-D",
            "cn=admin,dc=example,dc=org",
            "-w",
            "adminpassword",
        ],
        input=ldif,
        check=False,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"Failed to create LDAP user: rc={res.returncode} out={res.stdout} err={res.stderr}"
        )
