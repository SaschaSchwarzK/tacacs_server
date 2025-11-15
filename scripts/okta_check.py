#!/usr/bin/env python3
"""
Okta connectivity checker for this repo.

Performs:
- AuthN API login (username/password) and prints resulting user id
- Management API group lookup via:
  - OAuth2 client_credentials (Bearer token) using a backend config, or
  - SSWS token (legacy) if provided

Inputs:
- --backend-config config/okta.generated.conf (INI [okta])
- --manifest okta_test_data.json (optional, to default username)
- Or environment: OKTA_ORG, OKTA_API_TOKEN
"""

import argparse
import configparser
import getpass
import json
import os
import sys
import time
from urllib.parse import urljoin

import requests

try:
    import jwt  # PyJWT
except Exception:  # pragma: no cover
    jwt = None


def pretty(o):
    try:
        return json.dumps(o, indent=2, ensure_ascii=False)
    except Exception:
        return str(o)


# Legacy ROPC removed


def authn_request(org, username, password, verify=True):
    """Okta AuthN API (returns sessionToken on success)."""
    url = urljoin(org.rstrip("/") + "/", "api/v1/authn")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    payload = {"username": username, "password": password}
    r = requests.post(url, headers=headers, json=payload, verify=verify, timeout=15)
    return r


# Userinfo not used in AuthN flow


def okta_groups_api(org, api_token, okta_user_id, verify=True):
    # Requires Management API SSWS token
    url = urljoin(org.rstrip("/") + "/", f"api/v1/users/{okta_user_id}/groups")
    headers = {"Authorization": f"SSWS {api_token}", "Accept": "application/json"}
    r = requests.get(url, headers=headers, verify=verify, timeout=10)
    return r


def okta_groups_api_bearer(org, bearer_token, okta_user_id, verify=True):
    url = urljoin(org.rstrip("/") + "/", f"api/v1/users/{okta_user_id}/groups")
    headers = {"Authorization": f"Bearer {bearer_token}", "Accept": "application/json"}
    return requests.get(url, headers=headers, verify=verify, timeout=10)


def _read_backend_config(path: str) -> dict:
    cp = configparser.ConfigParser()
    cp.read(path)
    if "okta" not in cp:
        return {}
    sec = cp["okta"]
    return {k: v for k, v in sec.items()}


def _get_oauth_token(cfg: dict, verify=True) -> str | None:
    """Obtain OAuth2 token via client_credentials using cfg from [okta]."""
    org = cfg.get("org_url") or cfg.get("okta_org_url")
    if not org:
        return None
    token_endpoint = cfg.get("token_endpoint") or f"{org.rstrip('/')}/oauth2/v1/token"
    method = (cfg.get("auth_method") or "").strip().lower()
    if method == "client_secret":
        cid = cfg.get("client_id")
        csec = cfg.get("client_secret")
        if not (cid and csec):
            return None
        # Basic auth header
        from base64 import b64encode

        basic = b64encode(f"{cid}:{csec}".encode()).decode("ascii")
        headers = {
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "grant_type": "client_credentials",
            "scope": "okta.users.read okta.groups.read",
        }
        r = requests.post(
            token_endpoint, headers=headers, data=data, verify=verify, timeout=15
        )
        if r.status_code == 200:
            return (r.json() or {}).get("access_token")
        return None
    elif method == "private_key_jwt":
        if jwt is None:
            print("PyJWT is required for private_key_jwt", file=sys.stderr)
            return None
        cid = cfg.get("client_id")
        pk_path = cfg.get("private_key")
        kid = cfg.get("private_key_id")
        if not (cid and pk_path and kid):
            return None
        try:
            with open(pk_path, encoding="utf-8") as f:
                private_key = f.read()
        except Exception:
            return None
        now = int(time.time())
        claims = {
            "iss": cid,
            "sub": cid,
            "aud": token_endpoint,
            "iat": now,
            "exp": now + 300,
            "jti": os.urandom(16).hex(),
        }
        assertion = jwt.encode(
            claims, private_key, algorithm="RS256", headers={"kid": kid}
        )
        data = {
            "grant_type": "client_credentials",
            "scope": "okta.users.read okta.groups.read",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        }
        r = requests.post(token_endpoint, data=data, verify=verify, timeout=15)
        if r.status_code == 200:
            return (r.json() or {}).get("access_token")
        return None
    return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org", help="Okta org URL (or set OKTA_ORG env)")
    p.add_argument(
        "--backend-config",
        help="Path to backend config INI (e.g., config/okta.generated.conf)",
    )
    p.add_argument(
        "--manifest", help="Path to okta_test_data.json (optional, to pick username)"
    )
    p.add_argument(
        "--api-token",
        help="Okta Management API token (SSWS) or set OKTA_API_TOKEN env",
    )
    p.add_argument("--username", help="Username (login)")
    p.add_argument("--password", help="Password (otherwise prompt)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    args = p.parse_args()

    cfg: dict = {}
    if args.backend_config and os.path.exists(args.backend_config):
        cfg = _read_backend_config(args.backend_config)
    org = args.org or cfg.get("org_url") or os.getenv("OKTA_ORG")
    api_token = args.api_token or os.getenv("OKTA_API_TOKEN")
    verify = not args.insecure

    if not org:
        print(
            "ERROR: OKTA org URL must be provided via --org or OKTA_ORG.",
            file=sys.stderr,
        )
        sys.exit(2)

    username = args.username or os.getenv("OKTA_USERNAME")
    # Try manifest for default username if not provided
    if not username and args.manifest and os.path.exists(args.manifest):
        try:
            with open(args.manifest, encoding="utf-8") as f:
                m = json.load(f)
            users = m.get("users") or {}
            op = users.get("operator") or {}
            username = op.get("login") or username
        except Exception:
            pass
    username = username or input("Username: ").strip()
    password = (
        args.password
        or os.getenv("OKTA_PASSWORD")
        or getpass.getpass("Password (will not be echoed): ")
    )

    # Always AuthN flow
    print(f"\n-> AuthN API request to {org}, verify_tls={verify}")
    ar = authn_request(org, username, password, verify=verify)
    print("AuthN response:", ar.status_code)
    try:
        ad = ar.json()
        print(pretty({k: v for k, v in ad.items() if k != "_links"}))
    except Exception:
        print("[Response content redacted]")
        ad = {}

    if ar.status_code != 200 or str((ad or {}).get("status", "")).upper() != "SUCCESS":
        print("\nAuthentication failed via AuthN API.")
        sys.exit(1)

    okta_user_id = None
    try:
        okta_user_id = (ad.get("_embedded") or {}).get("user", {}).get("id")
    except Exception:
        okta_user_id = None
    print(f"\nAuthentication successful. okta_user_id={okta_user_id}")

    # Management API via OAuth or SSWS
    if okta_user_id:
        # Prefer OAuth from backend config if available
        bearer = None
        if cfg:
            bearer = _get_oauth_token(cfg, verify=verify)
        if bearer:
            print("\n-> Okta Groups API via OAuth bearer token")
            gr = okta_groups_api_bearer(org, bearer, okta_user_id, verify=verify)
            print("Groups API response:", gr.status_code)
            try:
                print(pretty(gr.json()))
            except Exception:
                print(gr.text)
        elif api_token:
            print(f"\n-> Okta Groups API (SSWS): users/{okta_user_id}/groups")
            gr = okta_groups_api(org, api_token, okta_user_id, verify=verify)
            print("Groups API response:", gr.status_code)
            try:
                print(pretty(gr.json()))
            except Exception:
                print(gr.text)
        else:
            print(
                "\nNote: No OAuth/SSWS credentials available — skipping Management API groups lookup."
            )
    else:
        print(
            "\nNote: AuthN response did not include user id — cannot call groups endpoint."
        )
    # ROPC path removed entirely

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
