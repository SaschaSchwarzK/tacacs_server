#!/usr/bin/env python3
"""
Okta Self-Test Helper

Two modes:
1) Direct mode (when --org or OKTA_ORG is given): Calls AuthN API directly,
   optionally fetches groups using OKTA_API_TOKEN/--api-token. This does not
   use the server config, and is ideal for quick checks.
2) Config mode (default): Loads your server config, instantiates the Okta
   backend, and performs an AuthN login using the same code path as the server.
   Useful to validate your exact server setup (group mapping, cache, etc.).

Usage examples:
  # Direct mode
  OKTA_ORG=https://your.okta.com OKTA_API_TOKEN=ssws-... \
    python scripts/okta_selftest.py --username alice

  # Config mode
  python scripts/okta_selftest.py --config config/tacacs.conf --username alice

Notes:
- Does not store or log passwords. Only prints safe attributes.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Any
from urllib.parse import urljoin

import requests

from tacacs_server.config.config import TacacsConfig


def _print_kv(title: str, data: dict[str, Any]) -> None:
    print(title)
    for k, v in data.items():
        print(f"  {k}: {v}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Okta setup self-test")
    parser.add_argument(
        "--config",
        default="config/tacacs.conf",
        help="Path to server configuration (default: config/tacacs.conf)",
    )
    parser.add_argument("--org", help="Okta org URL (or OKTA_ORG)")
    parser.add_argument("--api-token", help="Okta API token (or OKTA_API_TOKEN)")
    parser.add_argument(
        "--insecure", action="store_true", help="Disable TLS verification"
    )
    parser.add_argument("--username", help="Username to authenticate")
    parser.add_argument(
        "--require-mfa",
        action="store_true",
        help="Fail if Okta does not challenge with MFA when OTP/push suffix is used",
    )
    args = parser.parse_args()

    # ENV overrides for direct mode
    org = args.org or os.getenv("OKTA_ORG")
    api_token = args.api_token or os.getenv("OKTA_API_TOKEN")
    verify_tls = not args.insecure
    username = (
        args.username or os.getenv("OKTA_USERNAME") or input("Username: ").strip()
    )
    password = os.getenv("OKTA_PASSWORD") or getpass.getpass("Password (not echoed): ")

    if org:
        # Direct mode
        authn_url = urljoin(org.rstrip("/") + "/", "api/v1/authn")
        print("Direct mode: calling AuthN API")
        # Simple MFA via password suffix: OTP digits or ' push'
        base_password = password
        requested_otp: str | None = None
        requested_push = False
        # Default conventions match backend defaults
        mfa_otp_digits = int(os.getenv("OKTA_TEST_OTP_DIGITS", "6") or 6)
        mfa_push_keyword = (
            (os.getenv("OKTA_TEST_PUSH_KEYWORD", "push") or "push").strip().lower()
        )
        if isinstance(password, str):
            pw = password
            pws = pw.strip()
            kw = (mfa_push_keyword or "").lower()
            if kw:
                candidates = [
                    " " + kw,
                    "+" + kw,
                    ":" + kw,
                    "/" + kw,
                    "." + kw,
                    "-" + kw,
                    "#" + kw,
                    "@" + kw,
                    kw,
                ]
                pws_l = pws.lower()
                for suf in candidates:
                    if pws_l.endswith(suf):
                        requested_push = True
                        cut = len(pws) - len(suf)
                        base_password = pws[:cut]
                        break
            if not requested_push:
                if (
                    mfa_otp_digits >= 4
                    and len(pws) > mfa_otp_digits
                    and pws[-mfa_otp_digits:].isdigit()
                ):
                    requested_otp = pws[-mfa_otp_digits:]
                    base_password = pws[:-mfa_otp_digits]
        try:
            r = requests.post(
                authn_url,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json={"username": username, "password": base_password},
                verify=verify_tls,
                timeout=15,
            )
        except Exception as exc:
            print(f"ERROR: AuthN request failed: {exc}", file=sys.stderr)
            return 2
        print(f"AuthN status: {r.status_code}")
        try:
            body = r.json()
        except Exception:
            body = {}
        status = str(body.get("status", "")).upper()
        if r.status_code != 200:
            print("Result: FAILED")
            return 1
        if status == "MFA_REQUIRED":
            state_token = body.get("stateToken")
            factors = (body.get("_embedded") or {}).get("factors", [])
            if not state_token or not isinstance(factors, list):
                print("Result: FAILED (MFA required; missing stateToken/factors)")
                return 1
            if requested_otp:
                verify_href = None
                for f in factors:
                    try:
                        if f.get("factorType") in (
                            "token:software:totp",
                            "token:hotp",
                        ) and "verify" in (f.get("_links") or {}):
                            verify_href = f["_links"]["verify"]["href"]
                            break
                    except Exception:
                        continue
                if not verify_href:
                    print("Result: FAILED (no TOTP factor to verify provided OTP)")
                    return 1
                v = requests.post(
                    verify_href,
                    json={"stateToken": state_token, "passCode": requested_otp},
                    headers={"Accept": "application/json"},
                    verify=verify_tls,
                    timeout=15,
                )
                if v.status_code not in (200, 201):
                    print(f"Result: FAILED (OTP verify HTTP {v.status_code})")
                    return 1
                body = {}
                try:
                    body = v.json() or {}
                except Exception:
                    pass
                if str(body.get("status", "")).upper() != "SUCCESS":
                    print("Result: FAILED (OTP verify did not reach SUCCESS)")
                    return 1
                status = "SUCCESS"
            elif requested_push:
                verify_href = None
                for f in factors:
                    try:
                        if (
                            f.get("factorType") == "push"
                            and f.get("provider") == "OKTA"
                            and "verify" in (f.get("_links") or {})
                        ):
                            verify_href = f["_links"]["verify"]["href"]
                            break
                    except Exception:
                        continue
                if not verify_href:
                    print("Result: FAILED (no Okta Verify push factor)")
                    return 1
                current = requests.post(
                    verify_href,
                    json={"stateToken": state_token},
                    headers={"Accept": "application/json"},
                    verify=verify_tls,
                    timeout=15,
                )
                timeout_s = int(os.getenv("OKTA_TEST_MFA_TIMEOUT", "25") or 25)
                poll_iv = float(os.getenv("OKTA_TEST_MFA_POLL", "2.0") or 2.0)
                import time as _time

                start = _time.time()
                while (_time.time() - start) < max(5, timeout_s):
                    d = {}
                    try:
                        d = current.json() or {}
                    except Exception:
                        pass
                    st = str(d.get("status", "")).upper()
                    if st == "SUCCESS":
                        body = d
                        status = "SUCCESS"
                        break
                    poll_href = verify_href
                    try:
                        poll_href = (
                            d.get("_links", {}).get("next", {}).get("href", verify_href)
                        )
                    except Exception:
                        poll_href = verify_href
                    _time.sleep(max(0.5, poll_iv))
                    current = requests.post(
                        poll_href,
                        json={"stateToken": state_token},
                        headers={"Accept": "application/json"},
                        verify=verify_tls,
                        timeout=15,
                    )
                else:
                    print("Result: FAILED (push timeout)")
                    return 1
            else:
                print(
                    "Result: FAILED (MFA required; append OTP digits or ' push' to password)"
                )
                return 1
        elif (requested_otp or requested_push) and status == "SUCCESS":
            # Okta policy did not require MFA for this transaction
            print(
                "Warning: MFA suffix provided but Okta did not require MFA (policy returned SUCCESS)"
            )
            if args.require_mfa:
                print("Result: FAILED due to --require-mfa")
                return 1
        if status != "SUCCESS":
            print("Result: FAILED")
            return 1
        okta_user_id = None
        try:
            okta_user_id = (body.get("_embedded") or {}).get("user", {}).get("id")
        except Exception:
            okta_user_id = None
        print(f"Result: SUCCESS (okta_user_id={okta_user_id})")
        # Optional groups
        if api_token and okta_user_id:
            groups_url = urljoin(
                org.rstrip("/") + "/", f"api/v1/users/{okta_user_id}/groups"
            )
            try:
                gr = requests.get(
                    groups_url,
                    headers={
                        "Authorization": f"SSWS {api_token}",
                        "Accept": "application/json",
                    },
                    verify=verify_tls,
                    timeout=15,
                )
                if gr.status_code == 200:
                    print("Groups:")
                    for g in gr.json():
                        name = str((g or {}).get("profile", {}).get("name", ""))
                        if name:
                            print(f"  - {name}")
                else:
                    print(f"Groups API request failed: {gr.status_code}")
            except Exception as exc:
                print(f"Groups API request error: {exc}")
        return 0

    # Config mode
    try:
        cfg = TacacsConfig(args.config)
    except Exception as exc:
        print(
            f"ERROR: Failed to load configuration {args.config}: {exc}", file=sys.stderr
        )
        return 2

    # Build backends and find Okta
    okta_backend = None
    try:
        for be in cfg.create_auth_backends():
            if getattr(be, "name", "").lower() == "okta":
                okta_backend = be
                break
    except Exception as exc:
        print(f"ERROR: Failed to create auth backends: {exc}", file=sys.stderr)
        return 2

    if okta_backend is None:
        print(
            "ERROR: Okta backend not configured. Ensure [auth].backends includes 'okta' and [okta] section exists.",
            file=sys.stderr,
        )
        return 2

    # Show a quick summary of Okta settings (non-sensitive)
    try:
        stats = okta_backend.get_stats()  # type: ignore[attr-defined]
    except Exception:
        stats = {}
    flags = stats.get("flags", {}) if isinstance(stats, dict) else {}
    summary = {
        "org_url": stats.get("org_url"),
        "verify_tls": stats.get("verify_tls"),
        "authn_enabled": flags.get("authn_enabled", True),
        "require_group_for_auth": flags.get("require_group_for_auth", False),
        "strict_group_mode": flags.get("strict_group_mode", False),
    }
    _print_kv("Okta Backend Summary:", summary)

    print("\nAuthenticating via Okta AuthN API (backend)...")
    # Detect MFA suffix usage (to support --require-mfa consistency)
    requested_otp_cfg: str | None = None
    requested_push_cfg = False
    try:
        pw_in = password if isinstance(password, str) else ""
        pws = pw_in.strip()
        # Use same defaults as backend unless overridden in env for testing
        mfa_otp_digits = int(os.getenv("OKTA_TEST_OTP_DIGITS", "6") or 6)
        mfa_push_keyword = (
            (os.getenv("OKTA_TEST_PUSH_KEYWORD", "push") or "push").strip().lower()
        )
        kw = mfa_push_keyword
        if kw:
            for suf in [
                " " + kw,
                "+" + kw,
                ":" + kw,
                "/" + kw,
                "." + kw,
                "-" + kw,
                "#" + kw,
                "@" + kw,
                kw,
            ]:
                if pws.lower().endswith(suf):
                    requested_push_cfg = True
                    break
        if (
            not requested_push_cfg
            and mfa_otp_digits >= 4
            and len(pws) > mfa_otp_digits
            and pws[-mfa_otp_digits:].isdigit()
        ):
            requested_otp_cfg = pws[-mfa_otp_digits:]
    except Exception:
        requested_push_cfg = False
        requested_otp_cfg = None
    try:
        ok = okta_backend.authenticate(username, password)  # type: ignore[attr-defined]
    except Exception as exc:
        print(f"ERROR: Authentication call failed: {exc}", file=sys.stderr)
        return 1

    if not ok:
        print("Result: FAILED")
        return 1

    # If user requested MFA via suffix but backend still reports success, Okta policy likely didn't require MFA
    if args.require_mfa and (requested_push_cfg or requested_otp_cfg):
        print(
            "Warning: MFA suffix provided but backend returned SUCCESS — Okta did not require MFA for this transaction"
        )
        return 1

    attrs = {}
    try:
        attrs = okta_backend.get_user_attributes(username)  # type: ignore[attr-defined]
    except Exception:
        attrs = {}

    safe_attrs = {
        k: v
        for k, v in (attrs or {}).items()
        if k not in {"access_token", "token_response"}
    }
    print("Result: SUCCESS")
    print("Attributes:")
    for k, v in safe_attrs.items():
        print(f"  {k}: {v}")

    # If possible, also show groups based on config's api_token
    try:
        okta_cfg = dict(cfg.config.get("okta", {}))  # type: ignore[attr-defined]
    except Exception:
        okta_cfg = {}
    api_token_cfg = okta_cfg.get("api_token") or os.getenv("OKTA_API_TOKEN")
    org_url = (
        stats.get("org_url") if isinstance(stats, dict) else None
    ) or okta_cfg.get("org_url")
    okta_user_id = safe_attrs.get("okta_user_id")
    if org_url and api_token_cfg and okta_user_id:
        from urllib.parse import urljoin as _urljoin

        groups_url = _urljoin(
            str(org_url).rstrip("/") + "/", f"api/v1/users/{okta_user_id}/groups"
        )
        try:
            gr = requests.get(
                groups_url,
                headers={
                    "Authorization": f"SSWS {api_token_cfg}",
                    "Accept": "application/json",
                },
                verify=stats.get("verify_tls", True)
                if isinstance(stats, dict)
                else True,
                timeout=15,
            )
            if gr.status_code == 200:
                groups = []
                print("Groups (from config api_token):")
                for g in gr.json():
                    name = str((g or {}).get("profile", {}).get("name", ""))
                    if name:
                        groups.append(name)
                        print(f"  - {name}")
            else:
                print(f"Groups API request failed: {gr.status_code}")
        except Exception as exc:
            print(f"Groups API request error: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
