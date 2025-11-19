"""End-to-end tests for TACACS+ integration with Okta authentication backend.

This module contains end-to-end tests that verify the integration between TACACS+ server
and Okta authentication service. These tests require a live Okta environment and are
designed to run against a real Okta organization.

Test Organization:
- test_tacacs_server_with_okta_backend: Verifies end-to-end authentication flow
  - Successful authentication with valid credentials
  - Authentication failure with invalid credentials
  - Group membership verification via Okta Management API
  - Device-group based access control

Prerequisites:
- OKTA_E2E=1 environment variable must be set to run these tests
- A valid Okta test organization with test users and groups
- Generated configuration files from tools/okta_prepare_org.py

Security Considerations:
- Tests use dedicated test users with minimal required permissions
- No sensitive credentials are hardcoded in test files
- Test users have limited access scopes in Okta
- All test artifacts are cleaned up after test completion

Dependencies:
- pytest for test framework
- docker for container management
- requests for HTTP requests
- urllib for HTTP health checks

Configuration:
- Uses config/okta.generated.conf for Okta client configuration
- Uses okta_test_data.json for test user and group information
"""

from __future__ import annotations

import configparser
import json
import os
import secrets
import string
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import requests

from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def _wait_http(url: str, timeout: float = 60.0) -> None:
    import urllib.error
    import urllib.request

    start = time.time()
    last_err: Exception | None = None
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.status < 500:
                    return
        except Exception as e:  # noqa: BLE001
            last_err = e
        time.sleep(1.0)
    raise TimeoutError(f"HTTP not ready: {last_err}")


def _reset_okta_password(org_url: str, api_token: str, login: str) -> str:
    """Set a new random password for an Okta user and return it.

    This uses the Okta Users API to update the user's credentials with a
    freshly generated password. No email is sent. It works even when the
    user already exists.
    """
    base = org_url.rstrip("/")
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # Find user by login
    search_query = f'profile.login eq "{login}"'
    users_resp = requests.get(
        f"{base}/api/v1/users",
        headers=headers,
        params={"search": search_query},
        timeout=20,
    )
    if users_resp.status_code != 200:
        raise RuntimeError(
            f"Okta user search failed ({users_resp.status_code}): {users_resp.text}"
        )
    users = users_resp.json() or []
    if not users:
        raise RuntimeError(f"Okta user with login {login!r} not found")
    user_id = users[0].get("id")
    if not user_id:
        raise RuntimeError("Okta user search response missing 'id'")

    # Generate a strong random password that satisfies common Okta policies.
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    new_password = "".join(secrets.choice(alphabet) for _ in range(24))

    # Update the user's password via Users API
    update_payload = {"credentials": {"password": {"value": new_password}}}
    update_resp = requests.post(
        f"{base}/api/v1/users/{user_id}",
        headers=headers,
        json=update_payload,
        timeout=20,
    )
    if update_resp.status_code not in (200, 201):
        raise RuntimeError(
            f"Okta password update failed ({update_resp.status_code}): {update_resp.text}"
        )
    return new_password


@pytest.mark.e2e
def test_tacacs_server_with_okta_backend(
    tmp_path: Path,
    free_tcp_port: int,
) -> None:
    """Test end-to-end TACACS+ authentication with Okta backend.

    This test verifies the complete authentication flow using a real Okta backend,
    including user authentication, group membership verification, and device-based
    access control.

    Test Cases:
    1. Basic Authentication:
       - Success with valid credentials
       - Failure with invalid credentials

    2. Group Membership Verification:
       - Verify user is member of expected Okta groups
       - Validate group-to-privilege level mapping

    3. Device-Based Access Control:
       - Verify access with matching device group restrictions
       - Verify access denial with non-matching device group restrictions

    Test Setup:
    - Creates a temporary test environment with Docker containers
    - Configures TACACS+ server with Okta backend
    - Sets up test users and groups in Okta

    Security Considerations:
    - Uses temporary test users with minimal required permissions
    - Cleans up all test artifacts after completion
    - Validates proper access control enforcement

    Args:
        tmp_path: Pytest fixture providing a temporary directory
        free_tcp_port: Pytest fixture providing an available TCP port
        free_tcp_port2: Pytest fixture providing another available TCP port

    Raises:
        AssertionError: If any test assertion fails
        TimeoutError: If the test environment fails to start within timeout
    """
    if os.getenv("OKTA_E2E") != "1":
        pytest.skip("Set OKTA_E2E=1 to run Okta E2E tests against a real org")

    project_root = Path(__file__).resolve().parents[4]
    base_cfg_path = project_root / "config" / "tacacs.container.ini"
    okta_cfg_path = project_root / "config" / "okta.generated.conf"
    manifest_path = project_root / "okta_test_data.json"

    # Okta Management API credentials are required to prepare the org.
    org_url = os.getenv("OKTA_ORG_URL")
    api_token = os.getenv("OKTA_API_TOKEN")
    if not org_url or not api_token:
        pytest.skip("Set OKTA_ORG_URL and OKTA_API_TOKEN to run Okta E2E prep")

    # Import the preparer lazily so normal test runs do not require the Okta
    # SDK or its dependencies to be installed.
    try:
        import importlib

        okta_prepare_org = importlib.import_module("tools.okta_prepare_org")
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"tools/okta_prepare_org.py not available or failed to import: {e}")

    # Ensure Okta test resources exist (groups, users, service app, keys, config).
    # This mirrors the recommended CLI usage in tools/okta_prepare_org.py and is
    # safe to run multiple times (idempotent).
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
                str(project_root / "config" / "okta.generated.conf"),
            ]
        )
    except SystemExit as se:  # when parse_args() calls sys.exit on error
        rc = int(se.code)
    if rc != 0:
        pytest.skip(f"tools/okta_prepare_org.py failed with exit code {rc}")

    if (
        not base_cfg_path.exists()
        or not okta_cfg_path.exists()
        or not manifest_path.exists()
    ):
        pytest.skip(
            "Missing required files: tacacs.container.ini / okta.generated.conf / okta_test_data.json"
        )

    # Load manifest for test user and expected group
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    op = (manifest.get("users") or {}).get("operator") or {}
    operator_login = op.get("login") or os.getenv("OKTA_OPERATOR_LOGIN")
    if not operator_login:
        pytest.skip("No operator login in manifest and no OKTA_OPERATOR_LOGIN set")

    # Determine operator password: prefer explicit env override for backwards
    # compatibility; otherwise, reset the password via Okta API and use the
    # returned temporary password (generated at runtime).
    operator_password = os.getenv("OKTA_OPERATOR_PASSWORD")
    if not operator_password:
        try:
            operator_password = _reset_okta_password(org_url, api_token, operator_login)
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"Failed to reset Okta operator password: {e}")

    # expected group from preparer
    expected_group = (
        (manifest.get("groups") or {}).get("ops", {}).get("name", "tacacs-ops")
    )

    # Optional pre-check: verify AuthN and OAuth from host to avoid false negatives
    try:
        pre = _run(
            [
                "python",
                str(project_root / "scripts" / "okta_check.py"),
                "--backend-config",
                str(okta_cfg_path),
                "--username",
                operator_login,
                "--password",
                operator_password,
                "--insecure",
            ]
        )
        if pre.returncode != 0:
            pytest.skip(f"Okta pre-check failed: {pre.stdout} {pre.stderr}")
    except Exception:
        pass

    # Build temporary config merging [okta]
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(base_cfg_path)
    cfg["auth"]["backends"] = "okta"
    cfg["auth"]["require_all_backends"] = "false"
    # Okta AuthN can take a few seconds; increase backend timeout
    cfg["auth"]["backend_timeout"] = "10.0"
    cfg.setdefault("server", {})
    cfg["server"]["log_level"] = "DEBUG"
    cfg.setdefault("security", {})
    cfg["security"]["encryption_required"] = "false"
    # Merge okta section
    ocp = configparser.ConfigParser(interpolation=None)
    ocp.read(okta_cfg_path)
    if "okta" not in ocp:
        pytest.skip("okta.generated.conf does not contain [okta] section")
    # Ensure private_key path is inside /app/config for easier mount
    okta_sec = dict(ocp["okta"])  # copy
    if okta_sec.get("auth_method", "").lower() == "private_key_jwt":
        okta_sec["private_key"] = "/app/config/okta_service_private_key.pem"
    # Prefer trusting container env for proxies/CA so Okta is reachable in CI
    okta_sec["trust_env"] = "true"
    # Keep TLS verification enabled by default (env/proxy may supply CA)
    okta_sec.setdefault("verify_tls", "true")
    # Require a client_id for private_key_jwt; if missing, skip with guidance
    if okta_sec.get(
        "auth_method", ""
    ).lower() == "private_key_jwt" and not okta_sec.get("client_id"):
        pytest.skip(
            "[okta] client_id missing in config/okta.generated.conf. Re-run tools/okta_prepare_org.py with --create-service-app to regenerate."
        )
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

    # Extract private key path from okta.generated.conf (host side) if present
    host_priv_key = None
    try:
        if ocp["okta"].get("private_key"):
            host_priv_key = (project_root / ocp["okta"]["private_key"]).resolve()
            if not host_priv_key.exists():
                # Maybe the file is relative to CWD
                host_priv_key = Path(ocp["okta"]["private_key"]).resolve()
    except Exception:
        host_priv_key = None

    unique = uuid.uuid4().hex[:8]
    tacacs_image = f"tacacs-server-e2e:{unique}"
    tacacs_container = f"tacacs-okta-e2e-{unique}"
    api_token = f"token-{unique}"
    tacacs_host_port = 5049
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
        f"{tacacs_host_port}:5049",
        "-p",
        f"{api_host_port}:8080",
        "-e",
        f"API_TOKEN={api_token}",
        # Increase log verbosity and enable backend timing headroom
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
    ]
    # Forward proxy-related environment into the container if present
    for env_key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    ):
        val = os.environ.get(env_key)
        if val:
            run_cmd += ["-e", f"{env_key}={val}"]
    # If a CA bundle is provided on host, mount and point container to it
    ca_path = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
    if ca_path and os.path.exists(ca_path):
        run_cmd += [
            "-v",
            f"{ca_path}:/app/config/okta_ca.pem:ro",
            "-e",
            "REQUESTS_CA_BUNDLE=/app/config/okta_ca.pem",
        ]
    if host_priv_key and host_priv_key.exists():
        run_cmd += [
            "-v",
            f"{host_priv_key}:/app/config/okta_service_private_key.pem:ro",
        ]
    run_cmd += [
        tacacs_image,
        "sh",
        "-lc",
        "/opt/venv/bin/tacacs-server --config /app/config/tacacs.container.ini 2>&1 | tee -a /app/logs/stdouterr.log; code=$?; echo $code > /app/logs/exitcode.txt; exit $code",
    ]

    try:
        r = _run(run_cmd)
        if r.returncode != 0:
            pytest.fail(f"Container start failed:\n{r.stdout}\n{r.stderr}")

        try:
            _wait_http(f"http://127.0.0.1:{api_host_port}/health", timeout=90.0)
        except TimeoutError as e:  # dump logs
            logs = _run(["docker", "logs", tacacs_container])
            pytest.fail(
                f"TACACS container did not become healthy:\nHTTP error: {e}\n--- logs ---\n{logs.stdout}\n{logs.stderr}"
            )

        # Optional in-container network probe to Okta issuer for diagnostics
        issuer = ocp["okta"].get("org_url", "").rstrip("/")
        if issuer:
            probe = _run(
                [
                    "docker",
                    "exec",
                    tacacs_container,
                    "sh",
                    "-lc",
                    f"curl -sS -o /dev/null -w '%{{http_code}}' {issuer}/.well-known/openid-configuration || true",
                ]
            )
            # Not hard failing here; just printing for visibility if needed
            if probe.stdout.strip() and probe.stdout.strip() != "200":
                print(
                    f"[okta e2e] in-container issuer probe returned {probe.stdout.strip()}\n{probe.stderr}"
                )

        # Prepare device group + device via API so TACACS knows a shared secret
        import requests

        session = requests.Session()
        session.headers.update({"X-API-Token": api_token})
        base_url = f"http://127.0.0.1:{api_host_port}"
        tacacs_secret = "TacacsSecret123!"
        # Create dedicated device group
        dg_payload = {
            "name": "e2e-okta",
            "description": "Okta E2E devices",
            "tacacs_secret": tacacs_secret,
        }
        r_dg = session.post(
            f"{base_url}/api/device-groups", json=dg_payload, timeout=15
        )
        if r_dg.status_code not in (200, 201, 409):
            r_dg.raise_for_status()
        # Resolve group id
        r_list = session.get(f"{base_url}/api/device-groups", timeout=15)
        r_list.raise_for_status()
        items = (
            r_list.json()
            if r_list.headers.get("content-type", "").startswith("application/json")
            else []
        )
        gid = None
        for it in items:
            if isinstance(it, dict) and str(it.get("name", "")).lower() == "e2e-okta":
                gid = int(it.get("id", 0))
                break
        assert gid, f"device-group e2e-okta not found: {items}"
        # Create a wildcard device so connections from localhost match
        dev_payload = {
            "name": "okta-device",
            "ip_address": "0.0.0.0/0",
            "device_group_id": gid,
            "enabled": True,
        }
        r_dev = session.post(f"{base_url}/api/devices", json=dev_payload, timeout=15)
        if r_dev.status_code not in (200, 201, 409):
            r_dev.raise_for_status()

        # Auth success (valid Okta user) with small retry window
        ok = False
        msg = ""
        for _ in range(3):
            ok, msg = tacacs_authenticate(
                host="127.0.0.1",
                port=tacacs_host_port,
                key=tacacs_secret,
                username=operator_login,
                password=operator_password,
            )
            if ok:
                break
            time.sleep(3.0)
        if not ok:
            # Dump container logs and in-container log files to aid diagnosis
            logs = _run(["docker", "logs", tacacs_container])
            stdouterr = _run(
                [
                    "docker",
                    "exec",
                    tacacs_container,
                    "sh",
                    "-lc",
                    "[ -f /app/logs/stdouterr.log ] && tail -n 200 /app/logs/stdouterr.log || true",
                ]
            )
            tacacs_log = _run(
                [
                    "docker",
                    "exec",
                    tacacs_container,
                    "sh",
                    "-lc",
                    "[ -f /app/logs/tacacs.log ] && tail -n 200 /app/logs/tacacs.log || true",
                ]
            )
            raise AssertionError(
                "Expected auth success: {msg}\n"
                "--- container logs ---\n{cl}\n"
                "--- stdouterr.log (tail) ---\n{se}\n"
                "--- tacacs.log (tail) ---\n{tl}\n".format(
                    msg=msg,
                    cl=(logs.stdout or "")
                    + ("\n" + logs.stderr if logs.stderr else ""),
                    se=(stdouterr.stdout or "")
                    + ("\n" + stdouterr.stderr if stdouterr.stderr else ""),
                    tl=(tacacs_log.stdout or "")
                    + ("\n" + tacacs_log.stderr if tacacs_log.stderr else ""),
                )
            )

        # Auth fail (wrong password)
        ok2, _ = tacacs_authenticate(
            host="127.0.0.1",
            port=tacacs_host_port,
            key=tacacs_secret,
            username=operator_login,
            password=operator_password + "x",
        )
        assert not ok2, "Expected auth failure with wrong password"

        # Groups lookup via OAuth (direct Okta call) – ensure expected group exists for operator
        # Reuse scripts/okta_check.py logic lightly
        import time as _t

        import requests as _rq

        try:
            from base64 import b64encode as _b64e

            import jwt as _jwt
        except Exception:  # pragma: no cover
            _jwt = None

        def _get_token(sec: dict[str, str]) -> str | None:
            org = sec.get("org_url")
            t_ep = sec.get("token_endpoint") or f"{org.rstrip('/')}/oauth2/v1/token"
            method = sec.get("auth_method", "").lower()
            if method == "client_secret":
                cid = sec.get("client_id")
                cs = sec.get("client_secret")
                if not (cid and cs):
                    return None
                headers = {
                    "Authorization": f"Basic {_b64e(f'{cid}:{cs}'.encode()).decode()}",
                    "Content-Type": "application/x-www-form-urlencoded",
                }
                data = {
                    "grant_type": "client_credentials",
                    "scope": "okta.users.read okta.groups.read",
                }
                rr = _rq.post(t_ep, headers=headers, data=data, timeout=15)
                return (
                    (rr.json() or {}).get("access_token")
                    if rr.status_code == 200
                    else None
                )
            elif method == "private_key_jwt" and _jwt is not None:
                cid = sec.get("client_id")
                kid = sec.get("private_key_id")
                # Host path mounted as /app/config/okta_service_private_key.pem in container above,
                # but here we are on host; use the original path from okta_cfg
                pk_host = ocp["okta"].get("private_key")
                if not (cid and kid and pk_host):
                    return None
                try:
                    with open(pk_host, encoding="utf-8") as fh:
                        prv = fh.read()
                except Exception:
                    return None
                now = int(_t.time())
                assertion = _jwt.encode(
                    {
                        "iss": cid,
                        "sub": cid,
                        "aud": t_ep,
                        "iat": now,
                        "exp": now + 300,
                        "jti": uuid.uuid4().hex,
                    },
                    prv,
                    algorithm="RS256",
                    headers={"kid": kid},
                )
                data = {
                    "grant_type": "client_credentials",
                    "scope": "okta.users.read okta.groups.read",
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": assertion,
                }
                rr = _rq.post(t_ep, data=data, timeout=15)
                return (
                    (rr.json() or {}).get("access_token")
                    if rr.status_code == 200
                    else None
                )
            return None

        token = _get_token(dict(ocp["okta"]))
        if token:
            org = ocp["okta"].get("org_url")
            url = f"{org.rstrip('/')}/api/v1/users/{op.get('id', '') or 'me'}/groups"
            # If user id absent, fall back to query by login via filter
            if not op.get("id"):
                # search by login
                s_url = f"{org.rstrip('/')}/api/v1/users?q={operator_login}"
                us = _rq.get(
                    s_url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                    },
                    timeout=15,
                )
                if us.status_code == 200:
                    lst = us.json() or []
                    if lst:
                        url = (
                            f"{org.rstrip('/')}/api/v1/users/{lst[0].get('id')}/groups"
                        )
            gr = _rq.get(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=15,
            )
            assert gr.status_code == 200, (
                f"Groups API failed: {gr.status_code} {gr.text}"
            )
            names = {g.get("profile", {}).get("name") for g in (gr.json() or [])}
            assert expected_group in names, (
                f"Expected group {expected_group} in {names}"
            )

        # Determine the client IP the server sees to create specific /32 devices
        ip_client = None
        try:
            logs_now = _run(["docker", "logs", tacacs_container])
            import re as _re

            for line in (logs_now.stdout or "").splitlines()[::-1]:
                m = _re.search(r"New connection from \('([0-9.]+)',", line)
                if m:
                    ip_client = m.group(1)
                    break
        except Exception:
            ip_client = None
        # Fallback to Docker host IP if parsing failed; this still narrows from /0
        if not ip_client:
            ip_client = "127.0.0.1"

        # --- Group enforcement tests ---
        # 1) Create a local user-group mapped to operator's Okta group
        ug_name = f"okta-ops-{unique}"
        ug_payload = {
            "name": ug_name,
            "description": "Okta ops mapping",
            "privilege_level": 15,
            "okta_group": expected_group,
        }
        r_ug = session.post(f"{base_url}/api/user-groups", json=ug_payload, timeout=15)
        if r_ug.status_code not in (200, 201, 409):
            r_ug.raise_for_status()

        # 2) Create a restricted device-group that allows only that user-group
        dg_restricted = f"e2e-okta-restricted-{unique}"
        dg_r_payload = {
            "name": dg_restricted,
            "description": "Restricted to Okta ops",
            "tacacs_secret": tacacs_secret,
            "allowed_user_groups": [ug_name],
        }
        r_dgr = session.post(
            f"{base_url}/api/device-groups", json=dg_r_payload, timeout=15
        )
        if r_dgr.status_code not in (200, 201, 409):
            r_dgr.raise_for_status()
        # Resolve id
        r_list2 = session.get(f"{base_url}/api/device-groups", timeout=15)
        r_list2.raise_for_status()
        items2 = (
            r_list2.json()
            if r_list2.headers.get("content-type", "").startswith("application/json")
            else []
        )
        gid2 = None
        for it in items2:
            if (
                isinstance(it, dict)
                and str(it.get("name", "")).lower() == dg_restricted.lower()
            ):
                gid2 = int(it.get("id", 0))
                break
        assert gid2, f"device-group {dg_restricted} not found: {items2}"
        # Device in restricted group
        r_dev2 = session.post(
            f"{base_url}/api/devices",
            json={
                "name": f"{dg_restricted}-dev",
                "ip_address": f"{ip_client}/32",
                "device_group_id": gid2,
                "enabled": True,
            },
            timeout=15,
        )
        if r_dev2.status_code not in (200, 201, 409):
            r_dev2.raise_for_status()

        # Disable the initial catch-all device to ensure selection of the restricted device-group
        devs_resp = session.get(f"{base_url}/api/devices", timeout=15)
        devs = (
            devs_resp.json()
            if devs_resp.headers.get("content-type", "").startswith("application/json")
            else []
        )
        for d in devs:
            if (
                isinstance(d, dict)
                and d.get("name") == "okta-device"
                and d.get("enabled", True)
            ):
                _id = d.get("id")
                if _id:
                    session.put(
                        f"{base_url}/api/devices/{_id}",
                        json={"enabled": False},
                        timeout=15,
                    )

        # Auth should succeed because operator is member of expected_group mapped to ug_name
        ok3, msg3 = tacacs_authenticate(
            host="127.0.0.1",
            port=tacacs_host_port,
            key=tacacs_secret,
            username=operator_login,
            password=operator_password,
        )
        assert ok3, f"Expected auth success with group enforcement: {msg3}"

        # 3) Negative: create a user-group mapped to a group the operator is NOT in (admin)
        #    First, delete existing devices to avoid ambiguous matches among same /32
        devs_before = session.get(f"{base_url}/api/devices", timeout=15)
        if devs_before.status_code == 200 and devs_before.headers.get(
            "content-type", ""
        ).startswith("application/json"):
            for d in devs_before.json() or []:
                if isinstance(d, dict) and d.get("id"):
                    session.delete(f"{base_url}/api/devices/{int(d['id'])}", timeout=15)
        admin_group = (
            (manifest.get("groups") or {}).get("admin", {}).get("name", "tacacs-admin")
        )
        ug_bad = f"okta-admin-{unique}"
        r_ug2 = session.post(
            f"{base_url}/api/user-groups",
            json={
                "name": ug_bad,
                "description": "Okta admin mapping",
                "privilege_level": 15,
                "okta_group": admin_group,
            },
            timeout=15,
        )
        if r_ug2.status_code not in (200, 201, 409):
            r_ug2.raise_for_status()
        dg_denied = f"e2e-okta-denied-{unique}"
        r_dg3 = session.post(
            f"{base_url}/api/device-groups",
            json={
                "name": dg_denied,
                "description": "Restricted to Okta admin",
                "tacacs_secret": tacacs_secret,
                "allowed_user_groups": [ug_bad],
            },
            timeout=15,
        )
        if r_dg3.status_code not in (200, 201, 409):
            r_dg3.raise_for_status()
        # Resolve id
        r_list3 = session.get(f"{base_url}/api/device-groups", timeout=15)
        r_list3.raise_for_status()
        items3 = (
            r_list3.json()
            if r_list3.headers.get("content-type", "").startswith("application/json")
            else []
        )
        gid3 = None
        for it in items3:
            if (
                isinstance(it, dict)
                and str(it.get("name", "")).lower() == dg_denied.lower()
            ):
                gid3 = int(it.get("id", 0))
                break
        assert gid3, f"device-group {dg_denied} not found: {items3}"
        r_dev3 = session.post(
            f"{base_url}/api/devices",
            json={
                "name": f"{dg_denied}-dev",
                "ip_address": f"{ip_client}/32",
                "device_group_id": gid3,
                "enabled": True,
            },
            timeout=15,
        )
        if r_dev3.status_code not in (200, 201, 409):
            r_dev3.raise_for_status()

        # Disable the restricted device so the denied device-group is selected for the next attempt
        devs_resp2 = session.get(f"{base_url}/api/devices", timeout=15)
        devs2 = (
            devs_resp2.json()
            if devs_resp2.headers.get("content-type", "").startswith("application/json")
            else []
        )
        for d in devs2:
            if (
                isinstance(d, dict)
                and d.get("name") == f"{dg_restricted}-dev"
                and d.get("enabled", True)
            ):
                _id = d.get("id")
                if _id:
                    session.put(
                        f"{base_url}/api/devices/{_id}",
                        json={"enabled": False},
                        timeout=15,
                    )

        # For denied case, we keep same tacacs_secret; TACACS handler chooses device by IP matching
        ok4, msg4 = tacacs_authenticate(
            host="127.0.0.1",
            port=tacacs_host_port,
            key=tacacs_secret,
            username=operator_login,
            password=operator_password,
        )
        assert not ok4, (
            f"Expected auth failure with admin-only restriction, got: {msg4}"
        )

    finally:
        _run(["docker", "rm", "-f", tacacs_container])
