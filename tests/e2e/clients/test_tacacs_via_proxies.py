"""E2E: TACACS via two HAProxy instances — one per client."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest
import requests


@pytest.mark.e2e
def test_tacacs_via_two_proxies(tmp_path: Path) -> None:
    if not shutil.which("docker"):
        pytest.skip("Docker is required for proxy e2e tests")

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

        # Prepare config with PROXY protocol enabled and mount it
        import configparser

        base_cfg_path = project_root / "config" / "tacacs.container.ini"
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(base_cfg_path)
        if not cfg.has_section("server"):
            cfg.add_section("server")
        cfg.set("server", "log_level", "DEBUG")
        if not cfg.has_section("proxy_protocol"):
            cfg.add_section("proxy_protocol")
        cfg.set("proxy_protocol", "enabled", "true")
        # Allow any proxy source (our test HAProxy containers) and do not reject invalid headers strictly
        cfg.set("proxy_protocol", "validate_sources", "false")
        cfg.set("proxy_protocol", "reject_invalid", "false")
        tmp_cfg = tmp_path / "tacacs.container.proxy.ini"
        with tmp_cfg.open("w", encoding="utf-8") as fh:
            cfg.write(fh)

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
                f"{tacacs_port}:8049",
                "-p",
                f"{api_port}:8080",
                "-e",
                f"API_TOKEN={api_token}",
                "-v",
                f"{tmp_cfg}:/app/config/tacacs.container.ini:ro",
                server_image,
                "sh",
                "-lc",
                "/opt/venv/bin/tacacs-server --config /app/config/tacacs.container.ini",
            ]
        )

        _wait_http(f"http://127.0.0.1:{api_port}/health", 60)

        base_url = f"http://127.0.0.1:{api_port}"
        sess = requests.Session()
        sess.headers.update(
            {"X-API-Token": api_token, "content-type": "application/json"}
        )

        # Users and groups
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
            },
            tolerate_exists=True,
        )
        # Group for real clients (correct secret)
        _api_post(
            sess,
            f"{base_url}/api/device-groups",
            {
                "name": "e2e-clients",
                "description": "Clients",
                "tacacs_secret": "TacacsSecret123!",
            },
            tolerate_exists=True,
        )
        # Group for proxies (wrong secret) — if PROXY v2 is not honored, requests will match these /32 entries and fail
        _api_post(
            sess,
            f"{base_url}/api/device-groups",
            {
                "name": "proxy-devices",
                "description": "Proxies",
                "tacacs_secret": "WrongSecret456!",
            },
            tolerate_exists=True,
        )
        dg = sess.get(f"{base_url}/api/device-groups", timeout=10).json()
        gids = {
            str(i.get("name", "")).lower(): int(i.get("id", 0))
            for i in dg
            if isinstance(i, dict)
        }
        gid_clients = gids.get("e2e-clients")
        gid_proxies = gids.get("proxy-devices")
        assert gid_clients and gid_proxies, "Device groups not found"
        # Catch-all for real clients (longest-prefix wins against proxy /32 if PROXY v2 is honored)
        _api_post(
            sess,
            f"{base_url}/api/devices",
            {
                "name": "any",
                "ip_address": "0.0.0.0/0",
                "device_group_id": gid_clients,
                "enabled": True,
            },
            tolerate_exists=True,
        )

        # Proxies
        proxy1 = f"proxy1-{unique}"
        proxy2 = f"proxy2-{unique}"
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                proxy1,
                "--network",
                network_name,
                "-e",
                f"BACKEND_HOST={server_container}",
                proxy_image,
            ]
        )
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                proxy2,
                "--network",
                network_name,
                "-e",
                f"BACKEND_HOST={server_container}",
                proxy_image,
            ]
        )

        time.sleep(1.0)

        # TACACS via proxy1 (name and inspect client IP)
        client1 = f"client1-{unique}"
        # Run client and emit its container IP on stdout for reliable capture
        p1 = subprocess.run(
            [
                "docker",
                "run",
                "--name",
                client1,
                "--network",
                network_name,
                "--entrypoint",
                "",
                unified_image,
                "sh",
                "-lc",
                f"ip=$(hostname -i | awk '{{print $1}}'); echo CLIENT_IP=$ip; python /app/client.py --mode tacacs --host {proxy1} --port 8049 --secret TacacsSecret123! --username user_accept --password GoodPass1!",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        out1 = (p1.stdout or "") + ("\n" + p1.stderr if p1.stderr else "")
        if p1.returncode != 0:
            raise AssertionError(
                f"tacacs_proxy1_accept failed (rc={p1.returncode}).\n--- client output ---\n{out1}\n--- server logs ---\n"
                + _logs(server_container, 1000)
            )
        # Register proxy1 IP as a /32 device with wrong secret; without PROXY v2, longest-prefix match will pick this and auth should fail
        proxy1_ip = _ip(proxy1)
        if proxy1_ip:
            _api_post(
                sess,
                f"{base_url}/api/devices",
                {
                    "name": "proxy1",
                    "ip_address": f"{proxy1_ip}/32",
                    "device_group_id": gid_proxies,
                    "enabled": True,
                },
                tolerate_exists=True,
            )
        subprocess.run(["docker", "rm", "-f", client1], check=False)
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
                f"python /app/client.py --mode tacacs --host {proxy1} --port 8049 --secret TacacsSecret123! --username user_reject --password WrongPass!",
            ],
            server_container,
            label="tacacs_proxy1_reject",
            expect_zero=False,
        )

        # TACACS via proxy2
        time.sleep(0.5)
        client2 = f"client2-{unique}"
        p2 = subprocess.run(
            [
                "docker",
                "run",
                "--name",
                client2,
                "--network",
                network_name,
                "--entrypoint",
                "",
                unified_image,
                "sh",
                "-lc",
                f"ip=$(hostname -i | awk '{{print $1}}'); echo CLIENT_IP=$ip; python /app/client.py --mode tacacs --host {proxy2} --port 8049 --secret TacacsSecret123! --username user_accept --password GoodPass1!",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        out2 = (p2.stdout or "") + ("\n" + p2.stderr if p2.stderr else "")
        if p2.returncode != 0:
            raise AssertionError(
                f"tacacs_proxy2_accept failed (rc={p2.returncode}).\n--- client output ---\n{out2}\n--- server logs ---\n"
                + _logs(server_container, 1000)
            )
        # Register proxy2 IP as a /32 device with wrong secret
        proxy2_ip = _ip(proxy2)
        if proxy2_ip:
            _api_post(
                sess,
                f"{base_url}/api/devices",
                {
                    "name": "proxy2",
                    "ip_address": f"{proxy2_ip}/32",
                    "device_group_id": gid_proxies,
                    "enabled": True,
                },
                tolerate_exists=True,
            )
        subprocess.run(["docker", "rm", "-f", client2], check=False)
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
                f"python /app/client.py --mode tacacs --host {proxy2} --port 8049 --secret TacacsSecret123! --username user_reject --password WrongPass!",
            ],
            server_container,
            label="tacacs_proxy2_reject",
            expect_zero=False,
        )

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


def _ip(name: str) -> str:
    p = subprocess.run(
        [
            "docker",
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            name,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return p.stdout.strip()


def _assert_cmd(
    cmd: list[str], server_container: str, label: str, expect_zero: bool
) -> None:
    p = subprocess.run(cmd, check=False, capture_output=True, text=True)
    rc = p.returncode
    out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    if (expect_zero and rc != 0) or ((not expect_zero) and rc == 0):
        logs = subprocess.run(
            ["docker", "logs", "--tail", "1000", server_container],
            check=False,
            capture_output=True,
            text=True,
        )
        server_logs = (logs.stdout or "") + ("\n" + logs.stderr if logs.stderr else "")
        raise AssertionError(
            f"{label} failed (rc={rc}).\n--- client output ---\n{out}\n--- server logs ---\n{server_logs}"
        )


def _wait_http(url: str, timeout: float) -> None:
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


def _find_free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _api_post(sess, url: str, payload: dict, tolerate_exists: bool = False) -> None:
    r = sess.post(url, json=payload, timeout=15)
    if (
        tolerate_exists
        and r.status_code in (400, 409)
        and "already exists" in (r.text or "")
    ):
        return
    r.raise_for_status()


def _exec(name: str, cmd: str) -> str:
    try:
        p = subprocess.run(
            ["docker", "exec", name, "sh", "-lc", cmd],
            check=False,
            capture_output=True,
            text=True,
        )
        return (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    except Exception:
        return "(exec failed)"


def _logs(name: str, tail: int = 1000) -> str:
    try:
        p = subprocess.run(
            ["docker", "logs", "--tail", str(tail), name],
            check=False,
            capture_output=True,
            text=True,
        )
        return (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    except Exception:
        return "(failed to read logs)"
