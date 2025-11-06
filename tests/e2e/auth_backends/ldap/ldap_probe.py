#!/usr/bin/env python3
"""LDAP Probe Utility for TACACS+ Server Testing

This module provides a command-line utility to probe and debug LDAP server connections
used by the TACACS+ server. It can:
 - Resolve a user's DN by uid
 - Verify user credentials by binding as the user
 - List groups where the user is a member
 - Test LDAP server connectivity and authentication

Features:
- Supports both plain and SSL/TLS connections
- Compatible with OpenLDAP and other LDAPv3 servers
- Detailed error reporting and debug output

Environment Variables:
    LDAP_SERVER: Default LDAP server hostname
    LDAP_PORT: Default LDAP port (default: 389 or 636 for SSL)
    LDAP_BASE_DN: Default base DN for searches
    LDAP_ADMIN_DN: Default admin DN for binding
    LDAP_ADMIN_PASSWORD: Default admin password

Example Usage:
  # Test connection with admin credentials
  python ldap_probe.py --host 127.0.0.1 --port 389 \
      --base-dn "dc=example,dc=org" --admin-dn "cn=admin,dc=example,dc=org" \
      --admin-password secret

  # Test user authentication with SSL
  python ldap_probe.py --host ldap.example.com --port 636 --use-ssl \
      --base-dn "dc=example,dc=org" --admin-dn "cn=admin,dc=example,dc=org" \
      --admin-password secret --uid testuser --password userpass
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
from typing import List, Optional

try:
    import ldap3
    from ldap3.core.exceptions import LDAPException
except Exception as e:  # pragma: no cover
    print(f"Fatal: ldap3 is required: {e}", file=sys.stderr)
    sys.exit(2)


def _server(host: str, port: int, use_ssl: bool, timeout: float, insecure: bool) -> ldap3.Server:
    # Some environments/backends expect integer timeouts
    int_timeout = int(timeout)
    tls = None
    if use_ssl:
        # Allow toggling cert validation for dev/ephemeral self-signed certs
        tls = ldap3.Tls(validate=ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED)
    return ldap3.Server(host=host, port=port, use_ssl=use_ssl, get_info=ldap3.ALL, connect_timeout=int_timeout, tls=tls)


def admin_bind(host: str, port: int, use_ssl: bool, admin_dn: str, admin_password: str, timeout: float, insecure: bool, start_tls: bool) -> ldap3.Connection:
    """Bind to LDAP server with admin credentials.

    Args:
        host: LDAP server hostname or IP address
        port: LDAP server port
        use_ssl: Whether to use SSL/TLS for the connection
        admin_dn: Distinguished Name for admin authentication
        admin_password: Password for admin authentication
        timeout: Connection timeout in seconds
        insecure: If True, skip certificate verification
        start_tls: If True, issue StartTLS after connection

    Returns:
        ldap3.Connection: Active LDAP connection on success

    Raises:
        ldap3.core.exceptions.LDAPException: If connection or bind fails
        ValueError: If authentication fails
    """
    srv = _server(host, port, use_ssl, timeout, insecure)
    int_timeout = int(timeout)
    conn = ldap3.Connection(srv, user=admin_dn, password=admin_password, receive_timeout=int_timeout)
    if start_tls:
        # For StartTLS we must not use SSL at socket open, but then upgrade
        if use_ssl:
            raise ValueError("StartTLS requires --use-ssl to be false")
        if not conn.open():
            raise RuntimeError("Failed to open LDAP connection for StartTLS")
        if not conn.start_tls():
            raise RuntimeError(f"StartTLS failed: {conn.result}")
    if not conn.bind():
        raise RuntimeError(f"Admin bind failed: {conn.result}")
    return conn


def find_user_dn(conn: ldap3.Connection, base_dn: str, uid: str) -> Optional[str]:
    """Find a user's DN by their UID.

    Args:
        conn: Active LDAP connection
        base_dn: Base DN to search under
        uid: User ID to search for

    Returns:
        str: Distinguished Name of the user

    Raises:
        ValueError: If user is not found or multiple users match
    """
    ok = conn.search(search_base=base_dn, search_filter=f"(uid={uid})", attributes=["cn", "uid"])
    if not ok or not conn.entries:
        return None
    # First entry DN
    return str(conn.entries[0].entry_dn)


def verify_user_password(host: str, port: int, use_ssl: bool, user_dn: str, password: str, timeout: float, insecure: bool, start_tls: bool) -> bool:
    """Verify a user's password by attempting to bind with their credentials.

    Args:
        host: LDAP server hostname or IP address
        port: LDAP server port
        use_ssl: Whether to use SSL/TLS for the connection
        user_dn: User's Distinguished Name
        password: User's password to verify
        timeout: Connection timeout in seconds
        insecure: If True, skip certificate verification
        start_tls: If True, issue StartTLS after connection

    Returns:
        bool: True if authentication succeeded, False otherwise
    """
    srv = _server(host, port, use_ssl, timeout, insecure)
    int_timeout = int(timeout)
    conn = ldap3.Connection(srv, user=user_dn, password=password, receive_timeout=int_timeout)
    try:
        if start_tls:
            if use_ssl:
                raise ValueError("StartTLS requires --use-ssl to be false")
            if not conn.open():
                return False
            if not conn.start_tls():
                return False
        return bool(conn.bind())
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def user_groups(conn: ldap3.Connection, base_dn: str, user_dn: str) -> List[str]:
    """List groups where the specified user is a member.

    Args:
        conn: Active LDAP connection
        base_dn: Base DN to search for groups
        user_dn: User's Distinguished Name to find groups for

    Returns:
        list[str]: List of group entries with their attributes
    """
    # Our test directory creates groupOfUniqueNames entries under ou=groups
    groups_base = f"ou=groups,{base_dn}"
    flt = f"(uniqueMember={user_dn})"
    ok = conn.search(search_base=groups_base, search_filter=flt, attributes=["cn"])
    if not ok or not conn.entries:
        return []
    return [str(e.cn.value) for e in conn.entries if getattr(e, "cn", None) is not None]


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Probe LDAP for user existence, password check, and groups")
    p.add_argument("--host", default="127.0.0.1", help="LDAP host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=389, help="LDAP port (389 or 636)")
    p.add_argument("--use-ssl", action="store_true", help="Use SSL (LDAPS)")
    p.add_argument("--timeout", type=float, default=5.0, help="Connect/receive timeout seconds (default: 5.0)")
    p.add_argument("--base-dn", required=True, help="Base DN, e.g., dc=example,dc=org")
    p.add_argument("--admin-dn", required=True, help="Admin DN, e.g., cn=admin,dc=example,dc=org")
    p.add_argument("--admin-password", required=True, help="Admin password")
    p.add_argument("--uid", required=True, help="User uid to check, e.g., adminA")
    p.add_argument("--password", required=True, help="User password to verify")
    p.add_argument("--insecure", action="store_true", help="Disable cert validation for SSL/StartTLS")
    p.add_argument("--start-tls", action="store_true", help="Use StartTLS on plain LDAP connection (use --port 389, do not pass --use-ssl)")
    args = p.parse_args(argv)

    result = {
        "host": args.host,
        "port": args.port,
        "use_ssl": args.use_ssl,
        "base_dn": args.base_dn,
        "uid": args.uid,
        "user_dn": None,
        "password_ok": False,
        "groups": [],
        "errors": [],
    }

    try:
        conn = admin_bind(args.host, args.port, args.use_ssl, args.admin_dn, args.admin_password, args.timeout, args.insecure, args.start_tls)
    except Exception as e:
        result["errors"].append(f"admin_bind: {e}")
        print(json.dumps(result, indent=2))
        return 1

    try:
        dn = find_user_dn(conn, args.base_dn, args.uid)
        result["user_dn"] = dn
        if not dn:
            result["errors"].append("user_not_found")
            print(json.dumps(result, indent=2))
            return 2

        result["password_ok"] = verify_user_password(args.host, args.port, args.use_ssl, dn, args.password, args.timeout, args.insecure, args.start_tls)
        try:
            result["groups"] = user_groups(conn, args.base_dn, dn)
        except LDAPException as e:
            result["errors"].append(f"groups_query: {e}")

        print(json.dumps(result, indent=2))
        return 0 if result["password_ok"] else 3
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
