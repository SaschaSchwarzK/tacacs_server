#!/usr/bin/env python3
"""
Einfacher Okta-Checker: AuthN API (/api/v1/authn) verwenden,
bei Erfolg Benutzer-ID ausgeben und optional Gruppen abrufen.

Konfiguration:
  - OKTA_ORG (z.B. https://dev-xxxxx.okta.com) oder --org
  - OKTA_API_TOKEN (SSWS) optional für Groups-API oder --api-token
Optionen:
  --username USER     (oder wird interaktiv abgefragt)
  --insecure          (Verifikationsprüfung deaktivieren)
Beispiel:
  OKTA_ORG=https://dev-xxx.okta.com OKTA_API_TOKEN=ssws-token \
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


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org", help="Okta org URL (or set OKTA_ORG env)")
    # client-id not needed
    p.add_argument(
        "--api-token",
        help="Okta Management API token (SSWS) or set OKTA_API_TOKEN env",
    )
    p.add_argument("--username", help="Username (login)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    # ropc option removed
    args = p.parse_args()

    org = args.org or os.getenv("OKTA_ORG")
    api_token = args.api_token or os.getenv("OKTA_API_TOKEN")
    verify = not args.insecure

    if not org:
        print(
            "ERROR: OKTA org URL must be provided via --org or OKTA_ORG.",
            file=sys.stderr,
        )
        sys.exit(2)

    username = (
        args.username or os.getenv("OKTA_USERNAME") or input("Username: ").strip()
    )
    password = os.getenv("OKTA_PASSWORD") or getpass.getpass(
        "Password (will not be echoed): "
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

    if api_token and okta_user_id:
        print(
            f"\n-> Okta Groups API: users/{okta_user_id}/groups (requires SSWS token)"
        )
        gr = okta_groups_api(org, api_token, okta_user_id, verify=verify)
        print("Groups API response:", gr.status_code)
        try:
            print(pretty(gr.json()))
        except Exception:
            print(gr.text)
    else:
        if not api_token:
            print(
                "\nNote: No OKTA API token provided — cannot call Management Groups API."
            )
        if not okta_user_id:
            print(
                "\nNote: AuthN response did not include user id — cannot call groups endpoint."
            )
    # ROPC path removed entirely

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
