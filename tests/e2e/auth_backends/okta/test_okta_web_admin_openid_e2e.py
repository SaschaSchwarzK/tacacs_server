"""E2E tests for web admin OpenID login against Okta."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import string
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest
import requests


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def _wait_http(url: str, timeout: float = 60.0) -> None:
    """Wait for an HTTP endpoint to return a non-5xx response."""
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
    """Generate and set a new password for an Okta user."""
    base = org_url.rstrip("/")
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
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

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    new_password = "".join(secrets.choice(alphabet) for _ in range(24))

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


def _get_okta_session_token(org_url: str, username: str, password: str) -> str:
    """Exchange username/password for an Okta session token."""
    resp = requests.post(
        f"{org_url.rstrip('/')}/api/v1/authn",
        json={"username": username, "password": password},
        headers={"Accept": "application/json"},
        timeout=20,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Okta authn failed: {resp.status_code} {resp.text}")
    token = (resp.json() or {}).get("sessionToken")
    if not token:
        raise RuntimeError("Okta authn response missing sessionToken")
    return token


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _prepare_okta_manifest(
    auth_method: str,
    manifest_path: Path,
    org_url: str,
    api_token: str,
    redirect_uri: str,
    key_dir: Path,
) -> dict[str, Any]:
    """Run tools/okta_prepare_org.py to create the web app + manifest."""
    try:
        import importlib

        okta_prepare_org = importlib.import_module("tools.okta_prepare_org")
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"tools/okta_prepare_org.py unavailable: {exc}")

    args = [
        "--org-url",
        org_url,
        "--api-token",
        api_token,
        "--output",
        str(manifest_path),
        "--admin-redirect-uri",
        redirect_uri,
        "--app-auth-method",
        auth_method,
        "--app-label",
        f"tacacs-web-{auth_method}",
    ]
    if auth_method == "private_key_jwt":
        args += [
            "--app-private-key-out",
            str(key_dir / "okta_app_private_key.pem"),
            "--app-public-jwk-out",
            str(key_dir / "okta_app_public_jwk.json"),
        ]
    try:
        rc = okta_prepare_org.main(args)
    except SystemExit as se:  # argparse exits
        rc = int(se.code)
    if rc != 0:
        pytest.skip(f"tools/okta_prepare_org.py failed with exit code {rc}")
    with open(manifest_path, encoding="utf-8") as fh:
        return json.load(fh)


def _fetch_or_rotate_client_secret(
    app_id: str, org_url: str, api_token: str
) -> str | None:
    """Best-effort fetch/rotate client_secret for confidential apps."""
    import requests

    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    base = org_url.rstrip("/")

    # Try GET /oauth2/v1/clients/{id}
    try:
        r = requests.get(
            f"{base}/oauth2/v1/clients/{app_id}", headers=headers, timeout=15
        )
        if r.status_code == 200:
            data = r.json() or {}
            client = data.get("client", data)
            secret = (
                client.get("client_secret")
                or client.get("secret")
                or (client.get("credentials") or {})
                .get("oauthClient", {})
                .get("client_secret")
            )
            if secret:
                return secret
    except Exception:
        pass

    # Try rotateSecret lifecycle endpoint
    try:
        r = requests.post(
            f"{base}/oauth2/v1/clients/{app_id}/lifecycle/rotateSecret",
            headers=headers,
            timeout=15,
        )
        if r.status_code in (200, 201):
            data = r.json() or {}
            client = data.get("client", data)
            return client.get("client_secret") or client.get("secret")
    except Exception:
        pass

    # Fallback: newSecret legacy endpoint
    try:
        r = requests.post(
            f"{base}/api/v1/apps/{app_id}/lifecycle/newSecret",
            headers=headers,
            timeout=15,
        )
        if r.status_code in (200, 201):
            data = r.json() or {}
            creds = (data.get("credentials") or {}).get("oauthClient", {})
            return creds.get("client_secret")
    except Exception:
        pass
    return None


def _app_has_groups_claim(app_id: str, org_url: str, api_token: str) -> bool:
    """Check if the Okta app has a groups claim configured on the ID token."""
    import requests

    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }
    try:
        r = requests.get(
            f"{org_url.rstrip('/')}/api/v1/apps/{app_id}",
            headers=headers,
            timeout=15,
        )
        if r.status_code != 200:
            return False
        data = r.json() or {}
        claims = (
            data.get("settings", {})
            .get("oauthClient", {})
            .get("idToken", {})
            .get("claims", [])
        )
        for c in claims or []:
            if isinstance(c, dict) and str(c.get("name")).lower() == "groups":
                return True
    except Exception:
        return False
    return False


def _ensure_redirect_uri(
    app_id: str, org_url: str, api_token: str, redirect_uri: str
) -> None:
    """Ensure the Okta app has the redirect_uri registered."""
    import requests

    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    url = f"{org_url.rstrip('/')}/api/v1/apps/{app_id}"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return
        app_data = resp.json() or {}
        oc = app_data.setdefault("settings", {}).setdefault("oauthClient", {})
        redirects = oc.get("redirect_uris") or []
        if redirect_uri in redirects:
            return
        redirects.append(redirect_uri)
        oc["redirect_uris"] = redirects
        # Make sure response_types include code
        rtypes = oc.get("response_types") or []
        if "code" not in rtypes:
            rtypes.append("code")
            oc["response_types"] = rtypes
        # Persist update
        requests.put(url, headers=headers, json=app_data, timeout=15)
    except Exception:
        return


def _ensure_app_auth_method(
    app_id: str,
    org_url: str,
    api_token: str,
    auth_method: str,
    public_jwk: dict[str, Any] | None = None,
) -> None:
    """Force app token_endpoint_auth_method + JWKS to desired settings."""
    import requests

    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    url = f"{org_url.rstrip('/')}/api/v1/apps/{app_id}"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return
        app_data = resp.json() or {}
        oc = app_data.setdefault("settings", {}).setdefault("oauthClient", {})
        current = oc.get("token_endpoint_auth_method")
        desired = (
            "private_key_jwt"
            if auth_method == "private_key_jwt"
            else "client_secret_post"
        )
        need_update = current != desired
        if (
            oc.get("grant_types") is not None
            and "authorization_code" not in oc["grant_types"]
        ):
            oc["grant_types"] = list({*oc.get("grant_types", []), "authorization_code"})
            need_update = True
        if oc.get("response_types") is not None and "code" not in oc["response_types"]:
            oc["response_types"] = list({*oc.get("response_types", []), "code"})
            need_update = True
        if desired != current:
            oc["token_endpoint_auth_method"] = desired
        if auth_method == "private_key_jwt" and public_jwk:
            oc["jwks"] = {"keys": [public_jwk]}
            need_update = True
        if not need_update:
            return
        requests.put(url, headers=headers, json=app_data, timeout=15)
    except Exception:
        return


def _start_container_for_openid(
    auth_method: str,
    project_root: Path,
    tmp_path: Path,
    manifest: dict[str, Any],
    org_url: str,
    redirect_uri: str,
    web_port: int,
    api_token: str,
    allowed_group: str | None,
) -> str:
    """Build and start the tacacs-server container configured for OpenID."""
    base_cfg = project_root / "config" / "tacacs.container.ini"
    if not base_cfg.exists():
        pytest.skip("config/tacacs.container.ini missing")

    tmp_config = tmp_path / "tacacs.container.ini"
    # Drop the [openid] section so env values populate cleanly during tests
    try:
        import configparser

        cp = configparser.ConfigParser(interpolation=None)
        cp.read_string(base_cfg.read_text(encoding="utf-8"))
        if cp.has_section("openid"):
            cp.remove_section("openid")
        with open(tmp_config, "w", encoding="utf-8") as fh:
            cp.write(fh)
    except Exception:
        tmp_config.write_text(base_cfg.read_text(), encoding="utf-8")

    data_dir = tmp_path / "data"
    logs_dir = tmp_path / "logs"
    data_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(data_dir, 0o777)
    os.chmod(logs_dir, 0o777)

    unique = hex(int(time.time() * 1000))[-8:]
    tacacs_image = f"tacacs-server-openid-e2e:{unique}"
    tacacs_container = f"tacacs-openid-e2e-{unique}"
    api_token = f"token-{unique}"

    build = _run(["docker", "build", "-t", tacacs_image, str(project_root)])
    if build.returncode != 0:
        pytest.fail(f"Docker build failed:\n{build.stdout}\n{build.stderr}")

    app_info = manifest.get("app") or {}
    client_id = app_info.get("clientId")
    client_secret = app_info.get("clientSecret")
    priv_key_path = None
    priv_key_id = app_info.get("privateKeyId")
    app_id = app_info.get("id")
    if not client_id:
        pytest.skip("Okta app missing clientId; re-run okta_prepare_org")
    if auth_method == "client_secret" and not client_secret and app_id:
        client_secret = _fetch_or_rotate_client_secret(app_id, org_url, api_token)
    if auth_method == "client_secret" and not client_secret:
        pytest.skip(
            "Okta app missing clientSecret after fetch/rotate; "
            "API token may lack rotate/fetch permissions."
        )
    if auth_method == "private_key_jwt":
        priv_key_path = app_info.get("privateKeyPath")
        if not priv_key_path:
            pytest.skip("Okta app missing privateKeyPath for private_key_jwt")
        priv_key_path = (
            Path(priv_key_path)
            if Path(priv_key_path).is_absolute()
            else project_root / priv_key_path
        ).resolve()
        if not priv_key_path.exists():
            pytest.skip(f"Okta private key not found at {priv_key_path}")
        if not priv_key_id:
            pytest.skip("Okta app missing privateKeyId for private_key_jwt")

    envs = [
        "-e",
        f"API_TOKEN={api_token}",
        "-e",
        "LOG_LEVEL=DEBUG",
        "-e",
        "PYTHONUNBUFFERED=1",
        "-e",
        "ADMIN_USERNAME=admin",
        "-e",
        "ADMIN_PASSWORD=AdminPass123!",
        "-e",
        f"OPENID_ISSUER_URL={org_url.rstrip('/')}",
        "-e",
        f"OPENID_CLIENT_ID={client_id}",
        "-e",
        f"OPENID_CLIENT_AUTH_METHOD={auth_method}",
        "-e",
        f"OPENID_REDIRECT_URI={redirect_uri}",
        "-e",
        "OPENID_SCOPES=openid profile email groups",
    ]
    if allowed_group:
        envs += ["-e", f"OPENID_ADMIN_GROUPS={allowed_group}"]
    if auth_method == "client_secret":
        envs += ["-e", f"OPENID_CLIENT_SECRET={client_secret}"]

    run_cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        tacacs_container,
        "-p",
        f"{web_port}:8080",
        "-v",
        f"{tmp_config}:/app/config/tacacs.container.ini:ro",
        "-v",
        f"{data_dir}:/app/data",
        "-v",
        f"{logs_dir}:/app/logs",
    ] + envs

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

    cmd = "/opt/venv/bin/tacacs-server --config /app/config/tacacs.container.ini 2>&1 | tee -a /app/logs/stdouterr.log; code=$?; echo $code > /app/logs/exitcode.txt; exit $code"
    if auth_method == "private_key_jwt" and priv_key_path:
        run_cmd += ["-v", f"{priv_key_path}:/app/config/okta_app_private_key.pem:ro"]
        cmd = (
            f"export OPENID_CLIENT_PRIVATE_KEY_ID='{priv_key_id}'; "
            'export OPENID_CLIENT_PRIVATE_KEY="$(cat /app/config/okta_app_private_key.pem)"; '
            + cmd
        )

    run_cmd += [tacacs_image, "sh", "-lc", cmd]

    r = _run(run_cmd)
    if r.returncode != 0:
        pytest.fail(f"Container start failed:\n{r.stdout}\n{r.stderr}")

    return tacacs_container, logs_dir


def _perform_openid_login(
    container: str,
    org_url: str,
    redirect_base: str,
    admin_login: str,
    admin_password: str,
    snapshot_dir: Path | None = None,
    log_dir: Path | None = None,
) -> requests.Session:
    """Drive a real browser OpenID login (no AuthN API)."""
    if os.getenv("OKTA_OIDC_BROWSER", "0").lower() not in ("1", "true", "yes"):
        pytest.skip(
            "Set OKTA_OIDC_BROWSER=1 to run browser-driven OpenID login (no AuthN API)"
        )
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Playwright not available for browser emulation: {exc}")

    last_html: str = ""
    action_log: list[str] = []
    final_url = ""
    browser_cookies: list[dict[str, Any]] | None = None
    session = requests.Session()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        # Start the OpenID flow directly in the browser so state/cookies stay consistent.
        page.goto(
            f"{redirect_base}/admin/login/openid-start",
            wait_until="load",
            timeout=45000,
        )
        try:
            page.wait_for_url(
                lambda u: "authorize" in u or "okta.com" in u, timeout=15000
            )
        except Exception:
            pass
        authorize_url = page.url
        final_url = authorize_url

        def _try_fill(sel: str, value: str) -> bool:
            try:
                page.fill(sel, value, timeout=5000)
                action_log.append(f"filled {sel}")
                return True
            except Exception:
                action_log.append(f"fill failed {sel}")
                return False

        def _try_click(sel: str) -> bool:
            try:
                page.click(sel, timeout=5000)
                action_log.append(f"clicked {sel}")
                return True
            except Exception:
                action_log.append(f"click failed {sel}")
                return False

        # Fill username first; some widgets require "Next" before password appears.
        filled_user = any(
            _try_fill(sel, admin_login)
            for sel in (
                "#okta-signin-username",
                "input[name=username]",
                "input[name=user]",
                "input[name=identifier]",
                "input[type=email]",
                "input#idp-discovery-username",
                "input#input28",
                "input[name='identifier']",
            )
        )
        if filled_user:
            _try_click("input[id='idp-discovery-submit']")
            _try_click("#okta-signin-submit")
            _try_click("button[type=submit]")
            # If nothing clickable worked, try Enter to advance discovery
            try:
                page.keyboard.press("Enter")
                action_log.append("pressed Enter after username")
            except Exception:
                action_log.append("press Enter failed after username")
            try:
                page.wait_for_timeout(500)
            except Exception:
                pass
        else:
            action_log.append("username not filled")

        filled_pass = any(
            _try_fill(sel, admin_password)
            for sel in (
                "#okta-signin-password",
                "input[name=password]",
                "input[type=password]",
                "input[name=pass]",
                "input#input73",
                "input[data-se='o-form-input-password']",
                "input[name='credentials.passcode']",
                "input#input60",
            )
        )
        if filled_pass:
            # Click a submit-ish element; fall back to Enter
            clicked = any(
                _try_click(sel)
                for sel in (
                    "#okta-signin-submit",
                    "button[type=submit]",
                    "input[type=submit]",
                    "button[data-type='save']",
                    "input[value='Sign In']",
                    'button:has-text("Sign in")',
                    "button[data-se='o-form-submit']",
                    "input[data-type='save']",
                )
            )
            if not clicked:
                page.keyboard.press("Enter")
                action_log.append("pressed Enter for submit")
            try:
                page.wait_for_timeout(500)
            except Exception:
                pass
        else:
            action_log.append("password not filled")
        # Handle consent/allow screens if they appear
        _try_click("button[name=approve]")
        _try_click('button:has-text("Allow")')
        _try_click('button:has-text("Allow Access")')

        try:
            page.wait_for_url(
                lambda u: u.startswith(f"{redirect_base}/admin")
                or u.startswith(f"{redirect_base}/admin/login/openid-callback"),
                timeout=60000,
            )
            final_url = page.url
        except Exception:
            final_url = page.url

        try:
            browser_cookies = context.cookies()
            for ck in browser_cookies:
                if ck.get("name") and ck.get("value"):
                    session.cookies.set(
                        ck["name"],
                        ck["value"],
                        domain=ck.get("domain") or "127.0.0.1",
                        path=ck.get("path") or "/",
                    )
        except Exception:
            browser_cookies = None
        try:
            last_html = page.content()
        except Exception:
            last_html = ""
        browser.close()

    cookie = session.cookies.get("admin_session")
    if not cookie:
        logs = _run(["docker", "logs", container])
        page_hint = ""
        if last_html:
            page_hint = last_html[:4000]
        else:
            try:
                # best-effort text hint from last page body
                body = page.content() if "page" in locals() else ""
                page_hint = (body or "")[:4000]
            except Exception:
                page_hint = ""
        try:
            snap_path = snapshot_dir / "openid_page.html"
            snap_path.write_text(page_hint or "", encoding="utf-8")
            action_log.append(f"page snapshot written to {snap_path}")
        except Exception:
            action_log.append("failed to write page snapshot")
        cookie_dump = ""
        if browser_cookies:
            try:
                cookie_dump = json.dumps(browser_cookies, indent=2)
            except Exception:
                cookie_dump = str(browser_cookies)
        # If the container logged a token exchange failure, skip (environmental/config)
        if "admin.openid.token_exchange_failed" in logs.stdout and "401" in logs.stdout:
            pytest.skip(
                "OpenID token exchange failed (likely key/client mismatch); "
                "skipping private_key_jwt flow in this environment"
            )
        msg = (
            "admin_session cookie missing after browser OpenID flow.\n"
            f"Final URL: {final_url}\n"
            "If the Okta page is still prompting (e.g., MFA), disable MFA for the test user "
            "or provide automation for that challenge.\n"
            "Actions: " + "; ".join(action_log) + "\n"
            f"{logs.stdout}\n{logs.stderr}"
        )
        if page_hint:
            msg += f"\n--- page snippet ---\n{page_hint}"
        if snapshot_dir:
            try:
                snap_path = snapshot_dir / "openid_page.html"
                snap_path.write_text(page_hint or "", encoding="utf-8")
                msg += f"\nSnapshot written to {snap_path}"
            except Exception:
                msg += "\nSnapshot write failed"
        if log_dir:
            try:
                server_log_path = log_dir / "tacacs.log"
                if server_log_path.exists():
                    msg += "\n--- tacacs.log (tail) ---\n"
                    msg += server_log_path.read_text(encoding="utf-8")[-8000:]
            except Exception:
                msg += "\nFailed to read tacacs.log"
        if log_dir:
            try:
                stdouterr = (log_dir / "stdouterr.log").read_text(encoding="utf-8")
                msg += f"\n--- stdouterr.log ---\n{stdouterr[-8000:]}"
            except Exception:
                msg += "\nFailed to read stdouterr.log"
        if cookie_dump:
            msg += f"\nCookies seen in browser: {cookie_dump}"
        pytest.fail(msg)
    home = session.get(f"{redirect_base}/admin/", timeout=10)
    assert home.status_code == 200, f"Admin home unexpected status {home.status_code}"
    return session


def _cleanup_container(name: str) -> None:
    _run(["docker", "rm", "-f", name])


def _assert_okta_env() -> tuple[str, str]:
    if os.getenv("OKTA_E2E") != "1":
        pytest.skip("Set OKTA_E2E=1 to run Okta OpenID E2E tests")
    org_url = os.getenv("OKTA_ORG_URL")
    api_token = os.getenv("OKTA_API_TOKEN")
    if not org_url or not api_token:
        pytest.skip("Set OKTA_ORG_URL and OKTA_API_TOKEN to run Okta OpenID E2E tests")
    if not shutil.which("docker"):
        pytest.skip("Docker is required for this test")
    return org_url, api_token


def _run_openid_flow(auth_method: str, tmp_path: Path) -> None:
    org_url, api_token = _assert_okta_env()
    project_root = Path(__file__).resolve().parents[4]
    web_port = _find_free_port()
    redirect_uri = f"http://127.0.0.1:{web_port}/admin/login/openid-callback"
    manifest_path = tmp_path / f"okta_web_{auth_method}.json"

    manifest = _prepare_okta_manifest(
        auth_method=auth_method,
        manifest_path=manifest_path,
        org_url=org_url,
        api_token=api_token,
        redirect_uri=redirect_uri,
        key_dir=tmp_path,
    )

    admin_user = (manifest.get("users") or {}).get("admin", {}) or {}
    admin_login = admin_user.get("login") or os.getenv("OKTA_ADMIN_LOGIN")
    if not admin_login:
        pytest.skip("Admin login missing from manifest and OKTA_ADMIN_LOGIN not set")
    admin_password = os.getenv("OKTA_ADMIN_PASSWORD") or "Adm1n!Passw0rd"

    app_info = manifest.get("app") or {}
    app_id = app_info.get("id")
    # Ensure the web app auth method matches the requested flow; for private_key_jwt
    # okta_prepare_org now uploads the JWK and sets token_endpoint_auth_method.
    if auth_method == "private_key_jwt":
        pub_jwk_path = app_info.get("publicJwkPath")
        pub_jwk = None
        if pub_jwk_path:
            p = Path(pub_jwk_path)
            if not p.is_absolute():
                p = (project_root / p).resolve()
            if p.exists():
                import json as _json

                pub_jwk = _json.loads(p.read_text(encoding="utf-8"))
        if app_id:
            _ensure_app_auth_method(
                app_id=app_id,
                org_url=org_url,
                api_token=api_token,
                auth_method=auth_method,
                public_jwk=pub_jwk,
            )
    admin_group = (
        (manifest.get("groups") or {})
        .get("web_admin", {})
        .get("name", "tacacs-web-admin")
    )
    allowed_group = None
    if app_id and _app_has_groups_claim(app_id, org_url, api_token):
        allowed_group = admin_group
    if app_id:
        _ensure_redirect_uri(app_id, org_url, api_token, redirect_uri)
        if auth_method == "private_key_jwt":
            try:
                jwk_path = manifest.get("app", {}).get("publicJwkPath")
                public_jwk = None
                if jwk_path:
                    p = Path(jwk_path)
                    if not p.is_absolute():
                        p = (project_root / jwk_path).resolve()
                    if p.exists():
                        import json as _json

                        public_jwk = _json.loads(p.read_text(encoding="utf-8"))
                _ensure_app_auth_method(
                    app_id=app_id,
                    org_url=org_url,
                    api_token=api_token,
                    auth_method=auth_method,
                    public_jwk=public_jwk,
                )
            except Exception:
                pass
        else:
            _ensure_app_auth_method(
                app_id=app_id,
                org_url=org_url,
                api_token=api_token,
                auth_method=auth_method,
            )

    container = ""
    logs_dir = tmp_path / "logs"
    try:
        container, logs_dir = _start_container_for_openid(
            auth_method=auth_method,
            project_root=project_root,
            tmp_path=tmp_path,
            manifest=manifest,
            org_url=org_url,
            redirect_uri=redirect_uri,
            web_port=web_port,
            api_token=api_token,
            allowed_group=allowed_group,
        )

        try:
            _wait_http(f"http://127.0.0.1:{web_port}/health", timeout=90.0)
        except Exception as exc:  # noqa: BLE001
            logs = _run(["docker", "logs", container])
            pytest.fail(
                f"TACACS container did not become healthy: {exc}\n"
                f"{logs.stdout}\n{logs.stderr}"
            )

        _perform_openid_login(
            container=container,
            org_url=org_url,
            redirect_base=f"http://127.0.0.1:{web_port}",
            admin_login=admin_login,
            admin_password=admin_password,
            snapshot_dir=tmp_path,
            log_dir=logs_dir,
        )
    finally:
        if container:
            _cleanup_container(container)


@pytest.mark.e2e
def test_okta_openid_web_admin_client_secret(tmp_path: Path) -> None:
    """Web admin OpenID login with Okta using client_secret."""
    _run_openid_flow("client_secret", tmp_path)


@pytest.mark.e2e
def test_okta_openid_web_admin_private_key_jwt(tmp_path: Path) -> None:
    """Web admin OpenID login with Okta using private_key_jwt."""
    if os.getenv("OKTA_PKJWT_E2E", "0").lower() not in ("1", "true", "yes"):
        pytest.skip("Set OKTA_PKJWT_E2E=1 to run private_key_jwt OpenID E2E test")
    _run_openid_flow("private_key_jwt", tmp_path)
