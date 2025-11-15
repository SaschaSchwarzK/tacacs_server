"""E2E test for TACACS+ with real Okta backend.

This test starts the TACACS container configured with the Okta backend and uses
the generated backend config (config/okta.generated.conf) and manifest
(okta_test_data.json) produced by tools/okta_prepare_org.py.

The test is skipped by default and only runs when OKTA_E2E=1 is set.
It performs:
 - Auth success with known Okta user
 - Auth failure with wrong password
 - Groups lookup via OAuth (Management API) to ensure expected group is present
"""

from __future__ import annotations

import configparser
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def _wait_http(url: str, timeout: float = 60.0) -> None:
    import urllib.request
    import urllib.error

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


@pytest.mark.e2e
def test_tacacs_server_with_okta_backend(tmp_path: Path) -> None:
    if os.getenv("OKTA_E2E") != "1":
        pytest.skip("Set OKTA_E2E=1 to run Okta E2E tests against a real org")

    project_root = Path(__file__).resolve().parents[4]
    base_cfg_path = project_root / "config" / "tacacs.container.ini"
    okta_cfg_path = project_root / "config" / "okta.generated.conf"
    manifest_path = project_root / "okta_test_data.json"

    if not base_cfg_path.exists() or not okta_cfg_path.exists() or not manifest_path.exists():
        pytest.skip("Missing required files: tacacs.container.ini / okta.generated.conf / okta_test_data.json")

    # Load manifest for test user and expected group
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    op = (manifest.get("users") or {}).get("operator") or {}
    operator_login = op.get("login") or os.getenv("OKTA_OPERATOR_LOGIN")
    operator_password = os.getenv("OKTA_OPERATOR_PASSWORD")
    if not operator_password:
        pytest.skip("Set OKTA_OPERATOR_PASSWORD to run Okta E2E auth")
    if not operator_login:
        pytest.skip("No operator login in manifest and no OKTA_OPERATOR_LOGIN set")
    # expected group from preparer
    expected_group = (manifest.get("groups") or {}).get("ops", {}).get("name", "tacacs-ops")

    # Optional pre-check: verify AuthN and OAuth from host to avoid false negatives
    try:
        pre = _run([
            "python",
            str(project_root / "scripts" / "okta_check.py"),
            "--backend-config",
            str(okta_cfg_path),
            "--username",
            operator_login,
            "--password",
            operator_password,
            "--insecure",
        ])
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
    if okta_sec.get("auth_method", "").lower() == "private_key_jwt" and not okta_sec.get("client_id"):
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
                host_priv_key = (Path(ocp["okta"]["private_key"]).resolve())
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
        "-e", f"API_TOKEN={api_token}",
        # Increase log verbosity and enable backend timing headroom
        "-e", "LOG_LEVEL=DEBUG",
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
    for env_key in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
        val = os.environ.get(env_key)
        if val:
            run_cmd += ["-e", f"{env_key}={val}"]
    # If a CA bundle is provided on host, mount and point container to it
    ca_path = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
    if ca_path and os.path.exists(ca_path):
        run_cmd += ["-v", f"{ca_path}:/app/config/okta_ca.pem:ro", "-e", "REQUESTS_CA_BUNDLE=/app/config/okta_ca.pem"]
    if host_priv_key and host_priv_key.exists():
        run_cmd += ["-v", f"{host_priv_key}:/app/config/okta_service_private_key.pem:ro"]
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
            probe = _run([
                "docker","exec", tacacs_container, "sh","-lc",
                f"curl -sS -o /dev/null -w '%{{http_code}}' {issuer}/.well-known/openid-configuration || true"
            ])
            # Not hard failing here; just printing for visibility if needed
            if probe.stdout.strip() and probe.stdout.strip() != "200":
                print(f"[okta e2e] in-container issuer probe returned {probe.stdout.strip()}\n{probe.stderr}")

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
        r_dg = session.post(f"{base_url}/api/device-groups", json=dg_payload, timeout=15)
        if r_dg.status_code not in (200, 201, 409):
            r_dg.raise_for_status()
        # Resolve group id
        r_list = session.get(f"{base_url}/api/device-groups", timeout=15)
        r_list.raise_for_status()
        items = r_list.json() if r_list.headers.get("content-type", "").startswith("application/json") else []
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
            stdouterr = _run([
                "docker","exec", tacacs_container, "sh","-lc",
                "[ -f /app/logs/stdouterr.log ] && tail -n 200 /app/logs/stdouterr.log || true"
            ])
            tacacs_log = _run([
                "docker","exec", tacacs_container, "sh","-lc",
                "[ -f /app/logs/tacacs.log ] && tail -n 200 /app/logs/tacacs.log || true"
            ])
            raise AssertionError(
                "Expected auth success: {msg}\n"
                "--- container logs ---\n{cl}\n"
                "--- stdouterr.log (tail) ---\n{se}\n"
                "--- tacacs.log (tail) ---\n{tl}\n".format(
                    msg=msg,
                    cl=(logs.stdout or "") + ("\n" + logs.stderr if logs.stderr else ""),
                    se=(stdouterr.stdout or "") + ("\n" + stdouterr.stderr if stdouterr.stderr else ""),
                    tl=(tacacs_log.stdout or "") + ("\n" + tacacs_log.stderr if tacacs_log.stderr else ""),
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
        import configparser as _cp
        import requests as _rq
        import time as _t
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
                cid = sec.get("client_id"); cs = sec.get("client_secret")
                if not (cid and cs):
                    return None
                headers = {"Authorization": f"Basic {_b64e(f'{cid}:{cs}'.encode()).decode()}", "Content-Type": "application/x-www-form-urlencoded"}
                data = {"grant_type": "client_credentials", "scope": "okta.users.read okta.groups.read"}
                rr = _rq.post(t_ep, headers=headers, data=data, timeout=15)
                return (rr.json() or {}).get("access_token") if rr.status_code == 200 else None
            elif method == "private_key_jwt" and _jwt is not None:
                cid = sec.get("client_id"); kid = sec.get("private_key_id"); pk = "/app/config/okta_service_private_key.pem"
                # Host path mounted as /app/config/okta_service_private_key.pem in container above,
                # but here we are on host; use the original path from okta_cfg
                pk_host = ocp["okta"].get("private_key")
                if not (cid and kid and pk_host):
                    return None
                try:
                    with open(pk_host, "r", encoding="utf-8") as fh:
                        prv = fh.read()
                except Exception:
                    return None
                now = int(_t.time())
                assertion = _jwt.encode({"iss": cid, "sub": cid, "aud": t_ep, "iat": now, "exp": now + 300, "jti": uuid.uuid4().hex}, prv, algorithm="RS256", headers={"kid": kid})
                data = {"grant_type": "client_credentials", "scope": "okta.users.read okta.groups.read", "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": assertion}
                rr = _rq.post(t_ep, data=data, timeout=15)
                return (rr.json() or {}).get("access_token") if rr.status_code == 200 else None
            return None

        token = _get_token(dict(ocp["okta"]))
        if token:
            org = ocp["okta"].get("org_url")
            url = f"{org.rstrip('/')}/api/v1/users/{op.get('id', '') or 'me'}/groups"
            # If user id absent, fall back to query by login via filter
            if not op.get("id"):
                # search by login
                s_url = f"{org.rstrip('/')}/api/v1/users?q={operator_login}"
                us = _rq.get(s_url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}, timeout=15)
                if us.status_code == 200:
                    lst = us.json() or []
                    if lst:
                        url = f"{org.rstrip('/')}/api/v1/users/{lst[0].get('id')}/groups"
            gr = _rq.get(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}, timeout=15)
            assert gr.status_code == 200, f"Groups API failed: {gr.status_code} {gr.text}"
            names = {g.get("profile", {}).get("name") for g in (gr.json() or [])}
            assert expected_group in names, f"Expected group {expected_group} in {names}"

    finally:
        _run(["docker", "rm", "-f", tacacs_container])
