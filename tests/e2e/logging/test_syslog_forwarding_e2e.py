"""
E2E test to verify syslog forwarding from the TACACS server container to a remote syslog listener.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest


def _run_docker(args: list[str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["docker", *args], check=False, capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"docker {' '.join(args)} failed (exit {proc.returncode})\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


@pytest.mark.e2e
def test_syslog_forwarding_e2e(tmp_path: Path):
    """Spin up TACACS server and a UDP syslog listener container and verify log delivery."""
    if shutil.which("docker") is None:
        pytest.skip("Docker is required for syslog e2e test")

    unique = uuid.uuid4().hex[:8]
    token = f"syslog-e2e-{unique}"
    net_name = f"tacacs-syslog-net-{unique}"
    syslog_container = f"syslog-e2e-{unique}"
    tacacs_image = f"tacacs-server-e2e:{unique}"
    tacacs_container = f"tacacs-e2e-{unique}"

    try:
        # Build TACACS server image from repo Dockerfile
        _run_docker(
            [
                "build",
                "-f",
                "Dockerfile",
                "-t",
                tacacs_image,
                ".",
            ]
        )

        # Create isolated network
        _run_docker(["network", "create", net_name])

        # Start a minimal syslog receiver (UDP 5514) writing to /var/log/remote.log
        _run_docker(
            [
                "run",
                "-d",
                "--name",
                syslog_container,
                "--network",
                net_name,
                "alpine",
                "sh",
                "-c",
                "apk add --no-cache busybox-extras >/dev/null && nc -kul -p 5514 > /var/log/remote.log",
            ]
        )

        # Prepare TACACS config with syslog enabled pointing to the syslog container
        cfg_dir = tmp_path / "config"
        data_dir = tmp_path / "data"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)
        cfg_path = cfg_dir / "tacacs.conf"

        default_cfg = Path("config/tacacs.conf").read_text().splitlines()
        in_syslog = False
        with cfg_path.open("w", encoding="utf-8") as f:
            for line in default_cfg:
                stripped = line.strip()
                if stripped.startswith("[") and stripped.endswith("]"):
                    in_syslog = stripped.lower() == "[syslog]"
                    f.write(line + "\n")
                    continue
                if in_syslog:
                    if stripped.startswith("enabled"):
                        f.write("enabled = true\n")
                        continue
                    if stripped.startswith("host"):
                        f.write(f"host = {syslog_container}\n")
                        continue
                    if stripped.startswith("port"):
                        f.write("port = 5514\n")
                        continue
                f.write(line + "\n")

        # Run TACACS server container
        _run_docker(
            [
                "run",
                "-d",
                "--name",
                tacacs_container,
                "--network",
                net_name,
                "-v",
                f"{cfg_path}:/app/config/tacacs.conf:ro",
                "-v",
                f"{data_dir}:/app/data",
                tacacs_image,
                "tacacs-server",
                "--config",
                "/app/config/tacacs.conf",
            ]
        )

        # Emit a log entry from inside the TACACS container
        emit = _run_docker(
            [
                "exec",
                tacacs_container,
                "python",
                "-c",
                (
                    "from tacacs_server.utils.logger import get_logger; "
                    f'get_logger("syslog.e2e").info("{token}")'
                ),
            ]
        )
        emit_stdout = emit.stdout
        emit_stderr = emit.stderr

        # Poll syslog receiver for the token
        found = False
        last_out = ""
        for _ in range(10):
            out = _run_docker(
                ["exec", syslog_container, "cat", "/var/log/remote.log"]
            ).stdout or ""
            last_out = out
            if token in out:
                found = True
                break
            time.sleep(1)

        tacacs_logs = _run_docker(
            ["exec", tacacs_container, "sh", "-c", "cat /app/logs/tacacs.log 2>/dev/null || true"]
        ).stdout

        assert found, (
            "Syslog receiver did not see token; "
            f"token={token} "
            f"emit_stdout={emit_stdout!r} emit_stderr={emit_stderr!r} "
            f"receiver_out={last_out[-500:]!r} "
            f"tacacs_logs_tail={tacacs_logs[-500:]!r}"
        )
    finally:
        for name in (tacacs_container, syslog_container):
            _run_docker(["rm", "-f", name])
        try:
            _run_docker(["network", "rm", net_name])
        except AssertionError:
            pass
        _run_docker(["rmi", "-f", tacacs_image])
