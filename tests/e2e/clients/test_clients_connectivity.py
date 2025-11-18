"""E2E connectivity tests: TACACS and RADIUS client containers can reach server.

This test focuses on network reachability and basic protocol exchange rather than
end-to-end auth success. TACACS client is allowed to treat "authentication rejected"
as a successful connectivity signal.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest


@pytest.mark.e2e
def test_clients_can_connect_to_tacacs(tmp_path: Path) -> None:
    if not shutil.which("docker"):
        pytest.skip("Docker is required for client connectivity e2e tests")

    project_root = Path(__file__).resolve().parents[3]
    unique = str(int(time.time() * 1000))[-6:]
    network_name = f"clients-net-{unique}"
    server_image = f"tacacs-server-e2e:{unique}"
    server_container = f"tacacs-server-{unique}"
    unified_image = f"unified-client:{unique}"
    proxy_image = f"tacacs-proxy:{unique}"

    api_port = _find_free_port()
    tacacs_port = _find_free_port()
    api_token = f"token-{unique}"

    # Build server and client images
    _run(["docker", "build", "-t", server_image, str(project_root)])
    _run(
        [
            "docker",
            "build",
            "-t",
            unified_image,
            str(project_root / "tests/e2e/clients/unified"),
        ]
    )
    _run(
        [
            "docker",
            "build",
            "-t",
            proxy_image,
            str(project_root / "tests/e2e/clients/proxies"),
        ]
    )

    proxy1 = None
    proxy2 = None
    try:
        _run(["docker", "network", "create", network_name])

        # Start server minimally; rely on default config and just expose ports
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                server_container,
                "--network",
                network_name,
                "-p",
                f"{tacacs_port}:5049",
                "-p",
                f"{api_port}:8080",
                "-e",
                f"API_TOKEN={api_token}",
                "-e",
                "TACACS_RADIUS_ENABLED=true",
                server_image,
                "sh",
                "-lc",
                "/opt/venv/bin/tacacs-server --config /app/config/tacacs.container.ini",
            ]
        )

        # Wait for HTTP health
        _wait_http(f"http://127.0.0.1:{api_port}/health", 60)

        # Prime server via HTTP API: create users, device group, device
        import requests

        base_url = f"http://127.0.0.1:{api_port}"
        sess = requests.Session()
        sess.headers.update(
            {"X-API-Token": api_token, "content-type": "application/json"}
        )

        # Create two users: one accepted, one rejected (either wrong password or disabled)
        _api_post(
            sess,
            f"{base_url}/api/users",
            {
                "username": "user_accept",
                "password": "GoodPass1!",
                "privilege_level": 15,
                "service": "exec",
                "groups": [],
                "enabled": True,
                "description": "E2E accepted user",
            },
            tolerate_exists=True,
        )

        _api_post(
            sess,
            f"{base_url}/api/users",
            {
                "username": "user_reject",
                "password": "BadPass1!",
                "privilege_level": 1,
                "service": "exec",
                "groups": [],
                "enabled": True,
                "description": "E2E rejected user (we will send wrong password)",
            },
            tolerate_exists=True,
        )

        # Create device group with TACACS secret and a device covering all IPs
        # Use a unique group name per test run to avoid collisions with
        # any pre-existing data in the container's device database.
        group_name = f"e2e-clients-{unique}"
        _api_post(
            sess,
            f"{base_url}/api/device-groups",
            {
                "name": group_name,
                "description": "Clients group",
                "tacacs_secret": "TacacsSecret123!",
                "radius_secret": "testing123",
            },
            tolerate_exists=True,
        )

        # Resolve group id
        dg_list = sess.get(f"{base_url}/api/device-groups", timeout=10)
        dg_list.raise_for_status()
        group_map = {
            str(it.get("name", "")).lower(): int(it.get("id", 0))
            for it in dg_list.json()
            if isinstance(it, dict)
        }
        gid = group_map.get(group_name.lower())
        assert gid, f"Device group {group_name} not found"

        _api_post(
            sess,
            f"{base_url}/api/devices",
            {
                "name": "e2e-any",
                "ip_address": "0.0.0.0/0",
                "device_group_id": gid,
                "enabled": True,
            },
            tolerate_exists=True,
        )

        # Phase 1: direct to server (two clients do TACACS and RADIUS)
        _assert_cmd(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                network_name,
                "--entrypoint",
                "",
                unified_image,
                "sh",
                "-lc",
                f"python /app/client.py --mode tacacs --host {server_container} --port 5049 --secret TacacsSecret123! --username user_accept --password GoodPass1!",
            ],
            server_container,
            label="tacacs_direct_accept",
            expect_zero=True,
        )

        _assert_cmd(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                network_name,
                "--entrypoint",
                "",
                unified_image,
                "sh",
                "-lc",
                f"python /app/client.py --mode tacacs --host {server_container} --port 5049 --secret TacacsSecret123! --username user_reject --password WrongPass!",
            ],
            server_container,
            label="tacacs_direct_reject",
            expect_zero=False,
        )

        _assert_cmd(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                network_name,
                "--entrypoint",
                "",
                unified_image,
                "sh",
                "-lc",
                f"python /app/client.py --mode radius --host {server_container} --port 1812 --secret testing123 --username user_accept --password GoodPass1!",
            ],
            server_container,
            label="radius_direct_accept",
            expect_zero=True,
        )

        _assert_cmd(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                network_name,
                "--entrypoint",
                "",
                unified_image,
                "sh",
                "-lc",
                f"python /app/client.py --mode radius --host {server_container} --port 1812 --secret testing123 --username user_reject --password WrongPass!",
            ],
            server_container,
            label="radius_direct_reject",
            expect_zero=False,
        )

        # End of direct tests; proxies are covered in a dedicated test.

    finally:
        for name in (proxy1, proxy2, server_container):
            if name:
                subprocess.run(["docker", "rm", "-f", name], check=False)
        subprocess.run(["docker", "network", "rm", network_name], check=False)
        subprocess.run(["docker", "rmi", unified_image], check=False)
        subprocess.run(["docker", "rmi", proxy_image], check=False)
        subprocess.run(["docker", "rmi", server_image], check=False)


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def _run_capture(cmd: list[str]) -> str:
    p = subprocess.run(cmd, check=False, capture_output=True, text=True)
    return (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")


def _run_return(cmd: list[str]) -> int:
    p = subprocess.run(cmd, check=False)
    return p.returncode


def _assert_cmd(
    cmd: list[str], server_container: str, label: str, expect_zero: bool
) -> None:
    p = subprocess.run(cmd, check=False, capture_output=True, text=True)
    rc = p.returncode
    out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    if (expect_zero and rc != 0) or ((not expect_zero) and rc == 0):
        # Grab server logs for context
        try:
            logs = subprocess.run(
                ["docker", "logs", "--tail", "500", server_container],
                check=False,
                capture_output=True,
                text=True,
            )
            server_logs = (logs.stdout or "") + (
                "\n" + logs.stderr if logs.stderr else ""
            )
            # Also try to include the internal tacacs.log from the container for
            # richer diagnostics (e.g., TACACS/RADIUS details).
            extra = subprocess.run(
                [
                    "docker",
                    "exec",
                    server_container,
                    "sh",
                    "-lc",
                    "tail -n 200 /app/logs/tacacs.log 2>/dev/null || echo '(no /app/logs/tacacs.log)'",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            extra_logs = (extra.stdout or "") + (
                "\n" + extra.stderr if extra.stderr else ""
            )
            server_logs = f"{server_logs}\n--- /app/logs/tacacs.log ---\n{extra_logs}"
            # Additionally, try to snapshot device inventory and RADIUS clients
            # from inside the container for deeper diagnostics (e.g., whether
            # per-group secrets are wired through to RADIUS/TACACS).
            try:
                script = """
from tacacs_server.devices.store import DeviceStore
ds = DeviceStore("/app/data/devices.db")
print("=== DEVICE GROUPS ===")
for g in ds.list_groups():
    try:
        print(g.id, g.name, "tacacs_secret=", bool(getattr(g, "tacacs_secret", None)), "radius_secret=", bool(getattr(g, "radius_secret", None)))
    except Exception as exc:
        print("group_error", exc)
print("=== DEVICES ===")
for d in ds.list_devices():
    try:
        grp = d.group.name if d.group else None
        print(d.id, d.name, str(d.network), "group=", grp)
    except Exception as exc:
        print("device_error", exc)
print("=== RADIUS CLIENTS ===")
for c in ds.iter_radius_clients():
    try:
        sec = getattr(c, "secret", "")
        print(str(c.network), "secret_len=", len(sec), "name=", c.name, "group=", getattr(c, "group", None))
    except Exception as exc:
        print("radius_client_error", exc)
"""
                device_snapshot = subprocess.run(
                    [
                        "docker",
                        "exec",
                        server_container,
                        "sh",
                        "-lc",
                        "/opt/venv/bin/python - << 'PY'\n" + script + "\nPY",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                device_logs = (device_snapshot.stdout or "") + (
                    "\n" + device_snapshot.stderr if device_snapshot.stderr else ""
                )
                server_logs = f"{server_logs}\n--- device store / radius snapshot ---\n{device_logs}"
            except Exception:
                # Best-effort; if this fails, keep original logs.
                pass
        except Exception:
            server_logs = "(failed to read server docker logs)"
        raise AssertionError(
            f"{label} failed (rc={rc}).\n--- client output ---\n{out}\n--- server logs ---\n{server_logs}"
        )


def _find_free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout: float) -> None:
    import time

    import requests

    end = time.time() + timeout
    while time.time() < end:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 500:
                return
        except Exception:
            pass
        time.sleep(1)
    raise TimeoutError(f"Service {url} not healthy in time")


def _api_post(sess, url: str, payload: dict, tolerate_exists: bool = False) -> None:
    import requests as _r

    r = sess.post(url, json=payload, timeout=15)
    if (
        tolerate_exists
        and r.status_code in (400, 409)
        and "already exists" in (r.text or "")
    ):
        return
    try:
        r.raise_for_status()
    except _r.HTTPError as e:
        raise AssertionError(f"POST {url} failed: {r.status_code} {r.text}") from e
