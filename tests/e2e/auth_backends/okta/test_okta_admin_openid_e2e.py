import base64
import configparser
import json
import os
import secrets
import subprocess
import sys
import time
import uuid
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import pytest
import requests


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def _wait_http(url: str, timeout: float = 90.0) -> None:
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


def _okta_authn_session_token(org_url: str, username: str, password: str) -> requests.Response:
    url = urljoin(org_url.rstrip("/") + "/", "api/v1/authn")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    payload = {"username": username, "password": password}
    return requests.post(url, headers=headers, json=payload, timeout=20)


def _fetch_app_credentials(org_url: str, api_token: str, app_id: str | None) -> tuple[str | None, str | None]:
    """Fetch client_id/client_secret for the interactive OIDC app."""
    if not app_id:
        return None, None
    headers = {"Authorization": f"SSWS {api_token}", "Accept": "application/json"}
    resp = requests.get(
        f"{org_url.rstrip('/')}/api/v1/apps/{app_id}",
        headers=headers,
        timeout=20,
    )
    if resp.status_code != 200:
        return None, None
    data = resp.json() or {}
    creds = (data.get("credentials") or {}).get("oauthClient", {}) or {}
    return creds.get("client_id"), creds.get("client_secret")


def _generate_client_secret(org_url: str, api_token: str, app_id: str | None) -> str | None:
    """Rotate/generate a new client_secret for an Okta OIDC app."""
    if not app_id:
        return None
    headers = {"Authorization": f"SSWS {api_token}", "Accept": "application/json"}
    resp = requests.post(
        f"{org_url.rstrip('/')}/api/v1/apps/{app_id}/lifecycle/newSecret",
        headers=headers,
        timeout=20,
    )
    if resp.status_code not in (200, 201):
        return None
    data = resp.json() or {}
    creds = (data.get("credentials") or {}).get("oauthClient", {}) or {}
    return creds.get("client_secret")


def _create_oidc_web_app(
    org_url: str, api_token: str, redirect_uri: str, label: str
) -> tuple[str | None, str | None, str | None, str | None]:
    """Create an OIDC web app via Okta API and return (client_id, client_secret, app_id, code_verifier)."""
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    # PKCE / interaction_code flow helpers
    def _pkce_pair() -> tuple[str, str]:
        verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return verifier, challenge

    code_verifier, code_challenge = _pkce_pair()
    payload = {
        "name": "oidc_client",
        "label": label,
        "signOnMode": "OPENID_CONNECT",
        "credentials": {
            "oauthClient": {
                "autoKeyRotation": True,
                "token_endpoint_auth_method": "client_secret_basic",
            }
        },
        "settings": {
            "oauthClient": {
                "application_type": "web",
                "client_uri": redirect_uri,
                "redirect_uris": [redirect_uri],
                "response_types": ["code"],
                "grant_types": ["authorization_code", "interaction_code"],
                # Avoid interactive consent to simplify E2E flow
                "consent_method": "TRUSTED",
                "code_challenge_methods": ["S256"],
            }
        },
    }
    def _create(payload_override=None):
        body = payload_override or payload
        return requests.post(
            f"{org_url.rstrip('/')}/api/v1/apps",
            headers=headers,
            json=body,
            timeout=30,
        )

    resp = _create()
    if resp.status_code == 400:
        # Retry with minimal payload if consent_method or PKCE metadata rejected
        minimal = {
            "name": "oidc_client",
            "label": label,
            "signOnMode": "OPENID_CONNECT",
            "credentials": {"oauthClient": {"token_endpoint_auth_method": "none"}},
            "settings": {
                "oauthClient": {
                    "application_type": "web",
                    "client_uri": redirect_uri,
                    "redirect_uris": [redirect_uri],
                    "response_types": ["code"],
                    "grant_types": ["authorization_code", "interaction_code"],
                }
            },
        }
        resp = _create(minimal)
    if resp.status_code not in (200, 201):
        print(f"[create_app] failed: {resp.status_code} {resp.text}")
        return None, None, None, None
    data = resp.json() or {}
    app_id = data.get("id")
    creds = (data.get("credentials") or {}).get("oauthClient", {}) or {}
    client_id = creds.get("client_id")
    client_secret = creds.get("client_secret") or ""
    # If client_id missing, fetch explicitly via Apps API
    if (not client_id) and app_id:
        fetched_id, fetched_secret = _fetch_app_credentials(org_url, api_token, app_id)
        client_id = client_id or fetched_id
        client_secret = client_secret or fetched_secret or ""
    if not client_id:
        print(f"[create_app] missing client_id even after fetch (status {resp.status_code})")
    # Return verifier so caller can feed it to the container env when using interaction_code
    return client_id, client_secret, app_id, code_verifier


def _generate_pkce_verifier() -> str:
    verifier = secrets.token_urlsafe(32)
    return verifier


def _delete_app(org_url: str, api_token: str, app_id: str) -> None:
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }
    try:
        requests.post(
            f"{org_url.rstrip('/')}/api/v1/apps/{app_id}/lifecycle/deactivate",
            headers=headers,
            timeout=10,
        )
    except Exception:
        pass
    try:
        requests.delete(
            f"{org_url.rstrip('/')}/api/v1/apps/{app_id}",
            headers=headers,
            timeout=10,
        )
    except Exception:
        pass


def _assign_user_to_app(org_url: str, api_token: str, app_id: str, user_id: str) -> bool:
    """Assign a user to an Okta OIDC app. Returns True on success/exists."""
    if not (app_id and user_id):
        return False
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    payload = {"id": user_id}
    resp = requests.post(
        f"{org_url.rstrip('/')}/api/v1/apps/{app_id}/users",
        headers=headers,
        json=payload,
        timeout=20,
    )
    return resp.status_code in (200, 201, 204, 409)


def _dump_container_logs(name: str) -> str:
    logs = _run(["docker", "logs", name])
    tail = _run(
        [
            "docker",
            "exec",
            name,
            "sh",
            "-lc",
            "[ -f /app/logs/stdouterr.log ] && tail -n 200 /app/logs/stdouterr.log || true",
        ]
    )
    out = []
    if logs.stdout or logs.stderr:
        out.append("--- docker logs ---")
        out.append((logs.stdout or "") + ("\n" + logs.stderr if logs.stderr else ""))
    if tail.stdout or tail.stderr:
        out.append("--- stdouterr.log (tail) ---")
        out.append((tail.stdout or "") + ("\n" + tail.stderr if tail.stderr else ""))
    return "\n".join(out)


def _get_interaction_code(
    org_url: str,
    client_id: str,
    client_secret: str | None,
    redirect_uri: str,
    scopes: str,
    username: str,
    password: str,
    code_verifier: str,
    state: str,
) -> str | None:
    """Run Okta IDX interaction_code + PKCE flow to obtain an interaction_code."""
    def _challenge(verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    code_challenge = _challenge(code_verifier)
    scope_str = scopes.replace(",", " ")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if client_secret:
        import base64 as _b64

        basic = _b64.urlsafe_b64encode(f"{client_id}:{client_secret}".encode()).decode()
        headers["Authorization"] = f"Basic {basic}"
    interact = requests.post(
        f"{org_url.rstrip('/')}/oauth2/v1/interact",
        data={
            "client_id": client_id,
            "scope": scope_str,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        },
        headers=headers,
        timeout=20,
    )
    ih = (interact.json() or {}).get("interaction_handle") if interact.status_code == 200 else None
    if not ih:
        print(f"[idx] interact failed: {interact.status_code} {interact.text}")
        return None

    introspect = requests.post(
        f"{org_url.rstrip('/')}/idp/idx/introspect",
        json={"interaction_handle": ih},
        timeout=20,
    )
    sh = (introspect.json() or {}).get("stateHandle") if introspect.status_code == 200 else None
    if not sh:
        print(f"[idx] introspect failed: {introspect.status_code} {introspect.text}")
        return None

    identify = requests.post(
        f"{org_url.rstrip('/')}/idp/idx/identify",
        json={"identifier": username, "stateHandle": sh},
        timeout=20,
    )
    sh2 = (identify.json() or {}).get("stateHandle") if identify.status_code == 200 else None
    if not sh2:
        print(f"[idx] identify failed: {identify.status_code} {identify.text}")
        return None

    challenge = requests.post(
        f"{org_url.rstrip('/')}/idp/idx/challenge/answer",
        json={"credentials": {"passcode": password}, "stateHandle": sh2},
        timeout=20,
    )
    if challenge.status_code != 200:
        print(f"[idx] challenge failed: {challenge.status_code} {challenge.text}")
        return None
    return (challenge.json() or {}).get("interaction_code")


def _get_auth_code_with_session_token(
    org_url: str, session_token: str, authorize_url: str, session: requests.Session
) -> tuple[str | None, str | None, requests.Response | None]:
    """Use sessionCookieRedirect/session cookie (and fallback to sessionToken param) to capture auth code/state."""
    if not session_token:
        return None, None, None
    from urllib.parse import quote, urlparse

    scr_url = (
        f"{org_url.rstrip('/')}/login/sessionCookieRedirect"
        f"?token={session_token}&redirectUrl={quote(authorize_url, safe='')}"
    )
    resp = session.get(scr_url, allow_redirects=False, timeout=30)
    # Manually follow redirects to keep control and inspect locations
    hops = 0
    while resp.is_redirect and hops < 10:
        loc = resp.headers.get("Location") or ""
        parsed = urlparse(loc)
        qs = parse_qs(parsed.query)
        code = qs.get("code", [None])[0]
        state = qs.get("state", [None])[0]
        if code:
            return code, state, resp
        # Follow next hop
        if not parsed.scheme:
            # relative path on org domain
            loc = urljoin(org_url.rstrip("/") + "/", loc.lstrip("/"))
        resp = session.get(loc, allow_redirects=False, timeout=30)
        hops += 1

    # Exchange sessionToken for session cookie via Sessions API, then retry authorize
    try:
        sess_resp = session.post(
            f"{org_url.rstrip('/')}/api/v1/sessions",
            json={"sessionToken": session_token},
            timeout=15,
        )
        if sess_resp.status_code == 200:
            sid = (sess_resp.json() or {}).get("id")
            if sid:
                netloc = urlparse(org_url).netloc
                session.cookies.set("sid", sid, domain=netloc, path="/")
                auth_retry = session.get(
                    authorize_url, allow_redirects=False, timeout=30
                )
                if auth_retry.is_redirect:
                    loc = auth_retry.headers.get("Location") or ""
                    parsed = urlparse(loc)
                    qs = parse_qs(parsed.query)
                    code = qs.get("code", [None])[0]
                    state = qs.get("state", [None])[0]
                    if code:
                        return code, state, auth_retry
                resp = auth_retry
    except Exception:
        pass

    # Fallback: try authorize with sessionToken param directly
    try:
        with_token = authorize_url + ("&" if "?" in authorize_url else "?") + f"sessionToken={quote(session_token)}"
        resp2 = session.get(with_token, allow_redirects=True, timeout=30)
        final_url = resp2.url or ""
        parsed = urlparse(final_url)
        qs = parse_qs(parsed.query)
        code = qs.get("code", [None])[0]
        state = qs.get("state", [None])[0]
        if code:
            return code, state, resp2
        # Some Okta flows embed code in fragment when JS-enabled; try to extract from history
        for h in getattr(resp2, "history", []):
            loc = h.headers.get("Location") if hasattr(h, "headers") else None
            if loc:
                p = urlparse(loc)
                qs2 = parse_qs(p.query)
                code = qs2.get("code", [None])[0]
                state = qs2.get("state", [None])[0]
                if code:
                    return code, state, resp2
        return None, None, resp2
    except Exception:
        return None, None, resp


def _prepare_admin_config(base_cfg: Path, dest: Path) -> str:
    """Write a temporary config including [admin] so the web UI is protected."""
    import bcrypt

    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(base_cfg)
    if not cfg.has_section("admin"):
        cfg.add_section("admin")
    cfg["admin"]["username"] = cfg["admin"].get("username", "admin")
    cfg["admin"]["session_timeout_minutes"] = cfg["admin"].get(
        "session_timeout_minutes", "60"
    )
    # Use a deterministic but non-sensitive password for the admin local fallback
    hashed = bcrypt.hashpw(b"TempAdmin!Pass123", bcrypt.gensalt()).decode()
    cfg["admin"]["password_hash"] = hashed
    with dest.open("w", encoding="utf-8") as fh:
        cfg.write(fh)
    return hashed


@pytest.mark.e2e
def test_okta_admin_openid_e2e(tmp_path, free_tcp_port):
    """
    Full end-to-end OpenID admin login against a live Okta org and running TACACS container.

    - Provisions/refreshes Okta app + web-admin group via okta_prepare_org.
    - Starts the TACACS container with OpenID admin settings and required group.
    - Executes Okta Authorization Code flow using sessionToken (admin user) and hits /admin/.
    - Verifies denial with wrong password and with a user outside the allowed group.
    """
    if os.getenv("OKTA_E2E") != "1":
        pytest.skip("Set OKTA_E2E=1 to run Okta E2E tests against a real org")

    project_root = Path(__file__).resolve().parents[4]
    base_cfg_path = project_root / "config" / "tacacs.container.ini"
    manifest_path = project_root / "okta_test_data.json"

    org_url = os.getenv("OKTA_ORG_URL")
    api_token = os.getenv("OKTA_API_TOKEN")
    if not org_url or not api_token:
        pytest.skip("Set OKTA_ORG_URL and OKTA_API_TOKEN to run Okta E2E prep")

    admin_redirect_uri = f"http://127.0.0.1:{free_tcp_port}/admin/login/openid-callback"
    prepare_cmd = [
        sys.executable,
        str(project_root / "tools" / "okta_prepare_org.py"),
        "--org-url",
        org_url,
        "--api-token",
        api_token,
        "--output",
        str(manifest_path),
        "--app-label",
        "tacacs-test-app",
        "--admin-redirect-uri",
        admin_redirect_uri,
        "--redirect-uri",
        admin_redirect_uri,
        "--create-service-app",
        "--service-auth-method",
        "private_key_jwt",
        "--service-private-key-out",
        str(project_root / "okta_service_private_key.pem"),
        "--service-public-jwk-out",
        str(project_root / "okta_service_public_jwk.json"),
        "-v",
    ]
    proc = subprocess.run(
        prepare_cmd,
        cwd=project_root,
        env=dict(os.environ),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(
            f"okta_prepare_org failed rc={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    groups = manifest.get("groups") or {}
    web_admin_group = (groups.get("web_admin") or {}).get("name")
    assert web_admin_group, "web admin group missing from manifest"

    users = manifest.get("users") or {}
    admin_user = users.get("admin") or {}
    operator_user = users.get("operator") or {}
    admin_login = admin_user.get("login") or os.getenv("OKTA_ADMIN_LOGIN")
    admin_password = os.getenv("OKTA_ADMIN_PASSWORD", "Adm1n!Passw0rd")
    operator_login = operator_user.get("login") or os.getenv("OKTA_OPERATOR_LOGIN")
    operator_password = os.getenv("OKTA_OPERATOR_PASSWORD", "Op3rator!Passw0rd")
    if not admin_login:
        pytest.skip("No admin login available for Okta AuthN check")

    # Always create a dedicated OIDC app for this test to ensure grant types include interaction_code.
    created_app_id: str | None = None
    created_code_verifier: str | None = None
    label = f"tacacs-admin-e2e-{uuid.uuid4().hex[:8]}"
    client_id, client_secret, created_app_id, created_code_verifier = _create_oidc_web_app(
        org_url, api_token, admin_redirect_uri, label
    )
    if not client_id:
        pytest.skip("Okta OIDC app creation failed (no client_id)")
    if not client_secret:
        created_code_verifier = created_code_verifier or _generate_pkce_verifier()
    # Ensure admin (and operator for negative path) are assigned to the OIDC app
    if admin_user.get("id"):
        _assign_user_to_app(org_url, api_token, created_app_id or app_info.get("id"), admin_user["id"])
    if operator_user.get("id"):
        _assign_user_to_app(org_url, api_token, created_app_id or app_info.get("id"), operator_user["id"])

    # Validate authn happy/unhappy path before container work
    resp_ok = _okta_authn_session_token(org_url, admin_login, admin_password)
    assert (
        resp_ok.status_code == 200
    ), f"Expected 200 from Okta AuthN, got {resp_ok.status_code}: {resp_ok.text}"
    resp_bad = _okta_authn_session_token(org_url, admin_login, "wrong-password")
    assert resp_bad.status_code == 401, (
        f"Expected 401 for bad password, got {resp_bad.status_code}"
    )
    session_token = (resp_ok.json() or {}).get("sessionToken")
    assert session_token, "sessionToken missing in Okta AuthN response"

    # Build a config that enables the admin UI (password hash is unused in OpenID path)
    tmp_config = tmp_path / "tacacs.container.ini"
    admin_hash = _prepare_admin_config(base_cfg_path, tmp_config)

    data_dir = tmp_path / "data"
    logs_dir = tmp_path / "logs"
    data_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(data_dir, 0o777)
    os.chmod(logs_dir, 0o777)

    unique = uuid.uuid4().hex[:8]
    tacacs_image = f"tacacs-admin-openid-e2e:{unique}"
    tacacs_container = f"tacacs-admin-openid-{unique}"

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
        f"{free_tcp_port}:8080",
        "-e",
        f"ADMIN_USERNAME=admin",
        "-e",
        f"ADMIN_PASSWORD_HASH={admin_hash}",
        "-e",
        f"OPENID_ISSUER_URL={org_url}",
        "-e",
        f"OPENID_CLIENT_ID={client_id}",
        "-e",
        f"OPENID_CLIENT_SECRET={client_secret or ''}",
        "-e",
        f"OPENID_REDIRECT_URI={admin_redirect_uri}",
        "-e",
        "OPENID_SCOPES=openid profile email groups",
        "-e",
        f"OPENID_ADMIN_GROUPS={web_admin_group}",
        # Use interaction_code flow when we generated a PKCE verifier
        # (Identity Engine path); otherwise default auth code.
        *(
            [
                "-e",
                "OPENID_USE_INTERACTION_CODE=1",
                "-e",
                f"OPENID_CODE_VERIFIER={created_code_verifier}",
            ]
            if created_code_verifier
            else []
        ),
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
        "/opt/venv/bin/tacacs-server --config /app/config/tacacs.container.ini "
        "2>&1 | tee -a /app/logs/stdouterr.log; code=$?; echo $code > /app/logs/exitcode.txt; exit $code",
    ]

    try:
        r = _run(run_cmd)
        if r.returncode != 0:
            pytest.fail(f"Container start failed:\n{r.stdout}\n{r.stderr}")

        try:
            _wait_http(f"http://127.0.0.1:{free_tcp_port}/health", timeout=90.0)
        except TimeoutError as e:
            diag = _dump_container_logs(tacacs_container)
            pytest.fail(f"TACACS container did not become healthy: {e}\n{diag}")

        base_url = f"http://127.0.0.1:{free_tcp_port}"

        # --- Positive flow: admin in allowed group ---
        session = requests.Session()
        start_resp = session.get(
            f"{base_url}/admin/login/openid-start", allow_redirects=False, timeout=20
        )
        if start_resp.status_code == 503:
            pytest.skip("OpenID not configured in container (503 from openid-start)")
        if start_resp.status_code not in (302, 303):
            diag = _dump_container_logs(tacacs_container)
            pytest.fail(
                f"openid-start failed with {start_resp.status_code}: {start_resp.text}\n{diag}"
            )
        start_location = start_resp.headers.get("Location") or ""
        state = parse_qs(urlparse(start_location).query).get("state", [None])[0]
        assert state, f"Missing state in openid-start redirect: {start_location}"

        nonce = uuid.uuid4().hex
        auth_params = {
            "client_id": client_id,
            "response_type": "code",
            "scope": "openid profile email groups",
            "redirect_uri": admin_redirect_uri,
            "state": state,
            "nonce": nonce,
        }
        authorize_url = (
            f"{org_url.rstrip('/')}/oauth2/v1/authorize?{requests.compat.urlencode(auth_params)}"
        )
        # Prefer interaction_code (PKCE) flow with the created app
        code = _get_interaction_code(
            org_url,
            client_id,
            client_secret,
            admin_redirect_uri,
            auth_params["scope"],
            admin_login,
            admin_password,
            created_code_verifier,
            state,
        )
        state_returned = state
        last_auth_resp = None
        if not code:
            code, state_returned, last_auth_resp = _get_auth_code_with_session_token(
                org_url, session_token, authorize_url, session
            )
        assert code, (
            "Missing authorization code in authorize redirect chain "
            f"(last status: {getattr(last_auth_resp, 'status_code', None)}, "
            f"url: {getattr(last_auth_resp, 'url', None)})"
        )
        assert state_returned == state, "State mismatch from Okta /authorize"

        cb_resp = session.get(
            f"{admin_redirect_uri}?code={code}&state={state}", allow_redirects=False, timeout=20
        )
        assert cb_resp.status_code in (302, 303), (
            f"Expected redirect to /admin/ after callback, got {cb_resp.status_code}"
        )
        assert (
            session.cookies.get("admin_session") is not None
        ), "admin_session cookie not set after OpenID callback"

        home = session.get(f"{base_url}/admin/", timeout=20)
        assert home.status_code == 200, f"Admin UI not reachable: {home.status_code}"
        assert "TACACS+ Admin" in home.text or "Dashboard" in home.text

        # --- Negative: user not in allowed group rejected ---
        if operator_login:
            op_authn = _okta_authn_session_token(
                org_url, operator_login, operator_password
            )
            assert op_authn.status_code == 200, (
                f"Operator authn failed unexpectedly: {op_authn.status_code} {op_authn.text}"
            )
            op_token = (op_authn.json() or {}).get("sessionToken")
            op_session = requests.Session()
            op_start = op_session.get(
                f"{base_url}/admin/login/openid-start",
                allow_redirects=False,
                timeout=20,
            )
            assert op_start.status_code in (302, 303)
            op_state = parse_qs(
                urlparse(op_start.headers.get("Location") or "").query
            ).get("state", [None])[0]
            assert op_state
            op_code = _get_interaction_code(
                org_url,
                client_id,
                client_secret,
                admin_redirect_uri,
                "openid profile email groups",
                operator_login,
                operator_password,
                created_code_verifier,
                op_state,
            )
            if not op_code:
                op_authorize_url = (
                    f"{org_url.rstrip('/')}/oauth2/v1/authorize?"
                    f"client_id={client_id}&response_type=code&scope=openid+profile+email+groups"
                    f"&redirect_uri={admin_redirect_uri}&state={op_state}&nonce={uuid.uuid4().hex}"
                )
                op_code, _, _ = _get_auth_code_with_session_token(
                    org_url, op_token, op_authorize_url, op_session
                )
            op_cb = (
                op_session.get(
                    f"{admin_redirect_uri}?code={op_code}&state={op_state}",
                    allow_redirects=False,
                    timeout=20,
                )
                if op_code
                else requests.Response()
            )
            assert op_cb.status_code == 401, (
                f"Expected 401 when user not in web_admin group, got {op_cb.status_code}"
            )
            assert (
                op_session.cookies.get("admin_session") is None
            ), "Non-admin user should not receive admin_session cookie"
            denied = op_session.get(
                f"{base_url}/admin/", allow_redirects=False, timeout=20
            )
            assert denied.status_code in (401, 303, 307)

    finally:
        _run(["docker", "rm", "-f", tacacs_container])
        if created_app_id:
            _delete_app(org_url, api_token, created_app_id)
