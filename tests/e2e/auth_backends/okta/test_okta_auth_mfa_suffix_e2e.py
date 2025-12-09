"""
Lightweight Okta E2E that verifies MFA suffix parsing does not break auth when MFA is disabled.

Prereqs: same as other Okta E2E tests (OKTA_E2E=1, OKTA_ORG_URL, OKTA_API_TOKEN, prepared config).
Runs only against the AuthN API with mfa_enabled=false to ensure no suffix stripping occurs.
"""

from __future__ import annotations

import configparser
import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest

from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True)


@pytest.mark.e2e
def test_okta_auth_mfa_disabled_suffix(tmp_path: Path) -> None:
    """Ensure trailing digits are not stripped when mfa_enabled=false (no OTP/push expected)."""
    if os.getenv("OKTA_E2E") != "1":
        pytest.skip("Set OKTA_E2E=1 to run Okta E2E tests against a real org")

    project_root = Path(__file__).resolve().parents[4]
    base_cfg_path = project_root / "config" / "tacacs.container.ini"
    okta_cfg_path = project_root / "config" / "okta.generated.conf"
    manifest_path = project_root / "okta_test_data.json"

    # Okta creds from env
    org_url = os.getenv("OKTA_ORG_URL")
    api_token = os.getenv("OKTA_API_TOKEN")
    if not org_url or not api_token:
        pytest.skip("Set OKTA_ORG_URL and OKTA_API_TOKEN to run Okta E2E prep")

    try:
        import importlib

        okta_prepare_org = importlib.import_module("tools.okta_prepare_org")
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"tools/okta_prepare_org.py not available or failed to import: {e}")

    try:
        rc = okta_prepare_org.main(
            [
                "--org-url",
                org_url,
                "--api-token",
                api_token,
                "--output",
                str(manifest_path),
                "--no-app",
                "--create-service-app",
                "--service-auth-method",
                "private_key_jwt",
                "--service-private-key-out",
                str(project_root / "okta_service_private_key.pem"),
                "--service-public-jwk-out",
                str(project_root / "okta_service_public_jwk.json"),
                "--write-backend-config",
                str(okta_cfg_path),
            ]
        )
    except SystemExit as se:
        rc = int(se.code)
    if rc != 0:
        pytest.skip(f"tools/okta_prepare_org.py failed with exit code {rc}")

    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(base_cfg_path)
    cfg["auth"]["backends"] = "okta"
    cfg["auth"]["require_all_backends"] = "false"
    cfg.setdefault("server", {})
    cfg["server"]["log_level"] = "DEBUG"
    cfg.setdefault("security", {})
    cfg["security"]["encryption_required"] = "false"
    # Merge okta section and force mfa_enabled=false
    ocp = configparser.ConfigParser(interpolation=None)
    ocp.read(okta_cfg_path)
    if "okta" not in ocp:
        pytest.skip("okta.generated.conf does not contain [okta] section")
    okta_sec = dict(ocp["okta"])
    okta_sec["mfa_enabled"] = "false"
    # Prefer trusting env for proxies/CA so Okta is reachable in CI
    okta_sec["trust_env"] = "true"
    okta_sec.setdefault("verify_tls", "true")
    if not cfg.has_section("okta"):
        cfg.add_section("okta")
    for k, v in okta_sec.items():
        cfg["okta"][k] = v

    tmp_config = tmp_path / "tacacs.container.ini"
    with tmp_config.open("w", encoding="utf-8") as fh:
        cfg.write(fh)

    data_dir = tmp_path / "data"
    logs_dir = tmp_path / "logs"
    data_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(data_dir, 0o777)
    os.chmod(logs_dir, 0o777)

    unique = uuid.uuid4().hex[:8]
    tacacs_image = f"tacacs-server-e2e:{unique}"
    tacacs_container = f"tacacs-okta-e2e-suffix-{unique}"
    api_token = f"token-{unique}"
    tacacs_host_port = 8049
    api_host_port = 8080

    build = _run(["docker", "build", "-t", tacacs_image, str(project_root)])
    if build.returncode != 0:
        pytest.fail(f"TACACS image build failed:\n{build.stdout}\n{build.stderr}")

    run_cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        tacacs_container,
        "-p",
        f"{tacacs_host_port}:8049",
        "-p",
        f"{api_host_port}:8080",
        "-e",
        f"API_TOKEN={api_token}",
        "-e",
        "LOG_LEVEL=DEBUG",
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
    run = _run(run_cmd)
    if run.returncode != 0:
        pytest.fail(f"Failed to start TACACS container:\n{run.stdout}\n{run.stderr}")

    started = [tacacs_container]

    try:
        # Load manifest for test user and expected group
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        op = (manifest.get("users") or {}).get("operator") or {}
        operator_login = op.get("login") or os.getenv("OKTA_OPERATOR_LOGIN")
        if not operator_login:
            pytest.skip("No operator login in manifest and no OKTA_OPERATOR_LOGIN set")
        operator_password = os.getenv("OKTA_OPERATOR_PASSWORD")
        if not operator_password:
            pytest.skip("OKTA_OPERATOR_PASSWORD not set (required for this check)")

        # Append digits to simulate OTP suffix; should NOT be stripped when mfa_enabled=false
        password_with_suffix = operator_password + "123456"

        ok, msg = tacacs_authenticate(
            host="127.0.0.1",
            port=tacacs_host_port,
            key="testing123",
            username=operator_login,
            password=password_with_suffix,
        )
        assert ok, f"Auth failed when MFA disabled (expected success): {msg}"
    finally:
        for c in reversed(started):
            subprocess.run(["docker", "rm", "-f", c], check=False)
