#!/usr/bin/env python3
"""
Einfacher Okta-Checker: Token (password grant), userinfo und groups abrufen und
ausgeben.

Konfiguration:
  - OKTA_ORG (z.B. https://dev-xxxxx.okta.com) oder --org
  - OKTA_CLIENT_ID oder --client-id
  - OKTA_API_TOKEN (SSWS) optional für Groups-API oder --api-token
Optionen:
  --username USER     (oder wird interaktiv abgefragt)
  --insecure          (Verifikationsprüfung deaktivieren)
Beispiel:
  OKTA_ORG=https://dev-xxx.okta.com OKTA_CLIENT_ID=xxx OKTA_API_TOKEN=ssws-token \
    /path/to/python scripts/okta_check.py --username admin
"""
import argparse
import getpass
import json
import os
import sys
from urllib.parse import urljoin

import requests


def pretty(o):
    try:
        return json.dumps(o, indent=2, ensure_ascii=False)
    except Exception:
        return str(o)


def token_request(org, client_id, username, password, verify=True):
    token_url = urljoin(org.rstrip('/') + '/', "oauth2/default/v1/token")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": client_id,
        "scope": "openid profile groups",
    }
    r = requests.post(token_url, headers=headers, data=data, verify=verify, timeout=15)
    return r


def authn_request(org, username, password, verify=True):
    """Fallback: Okta Authn API (returns sessionToken on success)."""
    url = urljoin(org.rstrip('/') + '/', "api/v1/authn")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    payload = {"username": username, "password": password}
    r = requests.post(url, headers=headers, json=payload, verify=verify, timeout=15)
    return r


def userinfo_request(org, access_token, verify=True):
    url = urljoin(org.rstrip('/') + '/', "oauth2/default/v1/userinfo")
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    r = requests.get(url, headers=headers, verify=verify, timeout=10)
    return r

def okta_groups_api(org, api_token, okta_sub, verify=True):
    # Requires Management API SSWS token
    url = urljoin(org.rstrip('/') + '/', f"api/v1/users/{okta_sub}/groups")
    headers = {"Authorization": f"SSWS {api_token}", "Accept": "application/json"}
    r = requests.get(url, headers=headers, verify=verify, timeout=10)
    return r

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org", help="Okta org URL (or set OKTA_ORG env)")
    p.add_argument(
        "--client-id", help="Okta OAuth client id (or set OKTA_CLIENT_ID env)"
    )
    p.add_argument(
        "--api-token",
        help="Okta Management API token (SSWS) or set OKTA_API_TOKEN env",
    )
    p.add_argument("--username", help="Username (login)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    args = p.parse_args()

    org = args.org or os.getenv("OKTA_ORG")
    client_id = args.client_id or os.getenv("OKTA_CLIENT_ID")
    api_token = args.api_token or os.getenv("OKTA_API_TOKEN")
    verify = not args.insecure

    if not org or not client_id:
        print(
            "ERROR: OKTA org URL and client_id must be provided via args or env "
            "(OKTA_ORG, OKTA_CLIENT_ID).",
            file=sys.stderr,
        )
        sys.exit(2)

    username = args.username or os.getenv('OKTA_USERNAME') or input("Username: ").strip()
    password = os.getenv('OKTA_PASSWORD') or getpass.getpass("Password (will not be echoed): ")

    print(f"\n-> Token request to {org} (client_id={client_id}), verify_tls={verify}")
    r = token_request(org, client_id, username, password, verify=verify)
    print("Token endpoint response:", r.status_code)
    try:
        tr = r.json()
        # Redact sensitive fields from output
        safe_response = {k: v for k, v in tr.items() if k not in ['access_token', 'refresh_token', 'id_token']}
        if 'access_token' in tr:
            safe_response['access_token'] = '[REDACTED]'
        print(pretty(safe_response))
    except Exception:
        print("[Response content redacted]")

    if r.status_code != 200:
        # If client not allowed to use password grant -> try Authn API fallback
        err = None
        try:
            err = tr.get("error")
        except Exception:
            pass
        if err == "unauthorized_client" or r.status_code in (400, 401):
            print(
                "\nToken endpoint refused password grant. "
                "Trying Authn API (/api/v1/authn) as fallback..."
            )
            ar = authn_request(org, username, password, verify=verify)
            print("Authn API response:", ar.status_code)
            try:
                print(pretty(ar.json()))
            except Exception:
                print(ar.text)
        else:
            print("\nToken request did not succeed. Aborting further calls.")
            sys.exit(1)

    access_token = tr.get("access_token")
    expires_in = tr.get("expires_in")
    print(f"\nAuthentication: {'successful' if access_token else 'failed'}")

    if access_token:
        print("\n-> Userinfo request")
        ur = userinfo_request(org, access_token, verify=verify)
        print("Userinfo response:", ur.status_code)
        try:
            print(pretty(ur.json()))
        except Exception:
            print(ur.text)

        # try groups API if api_token available and userinfo contains sub
        okta_sub = None
        try:
            ui = ur.json()
            okta_sub = ui.get("sub")
        except Exception:
            pass

        if api_token and okta_sub:
            print(
                f"\n-> Okta Groups API: users/{okta_sub}/groups "
                "(requires SSWS token)"
            )
            gr = okta_groups_api(org, api_token, okta_sub, verify=verify)
            print("Groups API response:", gr.status_code)
            try:
                print(pretty(gr.json()))
            except Exception:
                print(gr.text)
        else:
            if not api_token:
                print(
                    "\nNote: No OKTA API token provided — "
                    "cannot call Management Groups API."
                )
            if not okta_sub:
                print(
                    "\nNote: userinfo did not contain 'sub' — "
                    "cannot call groups endpoint reliably."
                )

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
