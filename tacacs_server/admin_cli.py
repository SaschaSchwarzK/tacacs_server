from __future__ import annotations

import argparse
import csv
import getpass
import os
import sys
from pathlib import Path

from tacacs_server.auth.local_store import LocalAuthStore
from tacacs_server.config.config import TacacsConfig
from tacacs_server.utils.password_hash import (
    LegacyPasswordMigrator,
    PasswordHasher,
)


def cmd_check_config(args: argparse.Namespace) -> int:
    cfg = TacacsConfig(args.config)
    issues = cfg.validate_config()
    if issues:
        print("Configuration validation failed:")
        for i in issues:
            print(f"  - {i}")
        return 1
    print("Configuration is valid")
    return 0


def cmd_generate_bcrypt(args: argparse.Namespace) -> int:
    password = args.password
    if not password:
        if args.stdin:
            password = sys.stdin.readline().rstrip("\n")
        else:
            password = getpass.getpass("Enter password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Passwords do not match", file=sys.stderr)
                return 1
    try:
        h = PasswordHasher.hash_password(password)
        print(h)
        return 0
    except Exception as e:
        print(f"Failed to generate bcrypt hash: {e}", file=sys.stderr)
        return 1


def _audit_hashes(db_path: Path) -> tuple[int, int, int, int]:
    store = LocalAuthStore(str(db_path))
    total = bcrypt_count = legacy_count = unknown = 0
    for u in store.list_users():
        total += 1
        h = u.password_hash or ""
        if PasswordHasher.is_bcrypt_hash(h):
            bcrypt_count += 1
        elif LegacyPasswordMigrator.is_legacy_hash(h):
            legacy_count += 1
        elif not h:
            unknown += 1
        else:
            unknown += 1
    return total, bcrypt_count, legacy_count, unknown


def cmd_audit_hashes(args: argparse.Namespace) -> int:
    cfg = TacacsConfig(args.config)
    db_path = Path(cfg.get_local_auth_db()).resolve()
    total, bcrypt_count, legacy_count, unknown = _audit_hashes(db_path)
    print("Password Hash Audit")
    print("====================")
    print(f"Database: {db_path}")
    print(f"Total users:   {total}")
    print(f"bcrypt:        {bcrypt_count}")
    print(f"legacy sha256: {legacy_count}")
    print(f"unknown:       {unknown}")
    return 1 if legacy_count > 0 else 0


def cmd_migrate_hashes(args: argparse.Namespace) -> int:
    """Migrate legacy SHA-256 hashes to bcrypt using a CSV of username,password.

    The CSV must have headers: username,password
    Only users whose legacy hash matches the supplied password will be updated.
    """
    cfg = TacacsConfig(args.config)
    db_path = Path(cfg.get_local_auth_db()).resolve()
    store = LocalAuthStore(str(db_path))
    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"CSV not found: {csv_path}", file=sys.stderr)
        return 1

    updated = 0
    skipped = 0
    with csv_path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            username = (row.get("username") or "").strip()
            password = row.get("password") or ""
            if not username:
                continue
            user = store.get_user(username)
            if not user or not user.password_hash:
                skipped += 1
                continue
            legacy_hash = user.password_hash
            if not LegacyPasswordMigrator.is_legacy_hash(legacy_hash):
                skipped += 1
                continue
            # Verify legacy hash with supplied password
            if not LegacyPasswordMigrator.verify_legacy_password(password, legacy_hash):
                skipped += 1
                continue
            # Migrate
            new_hash = PasswordHasher.hash_password(password)
            store.set_user_password(username, password=None, password_hash=new_hash)
            updated += 1

    print(f"Migrated users: {updated}; skipped: {skipped}")
    return 0 if updated > 0 else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tacacs-admin", description="Admin CLI for TACACS+ server"
    )
    p.add_argument(
        "--config",
        "-c",
        default=os.environ.get("TACACS_CONFIG", "config/tacacs.conf"),
        help="Path to config file",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub_check = sub.add_parser(
        "check-config", help="Validate configuration and report issues"
    )
    sub_check.set_defaults(func=cmd_check_config)

    sub_bcrypt = sub.add_parser(
        "generate-bcrypt", help="Generate a bcrypt hash for a password"
    )
    sub_bcrypt.add_argument(
        "--password", help="Password (use stdin or prompt if omitted)"
    )
    sub_bcrypt.add_argument(
        "--stdin", action="store_true", help="Read password from stdin (single line)"
    )
    sub_bcrypt.set_defaults(func=cmd_generate_bcrypt)

    sub_audit = sub.add_parser(
        "audit-hashes", help="Audit password hashes in local auth DB"
    )
    sub_audit.set_defaults(func=cmd_audit_hashes)

    sub_mig = sub.add_parser(
        "migrate-hashes",
        help="Migrate legacy hashes to bcrypt using a CSV of username,password",
    )
    sub_mig.add_argument(
        "--csv", required=True, help="CSV file with username,password headers"
    )
    sub_mig.set_defaults(func=cmd_migrate_hashes)

    return p


from typing import Any, Callable, Protocol, cast


class _Cmd(Protocol):
    def __call__(self, args: argparse.Namespace) -> int: ...


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = cast(_Cmd, getattr(args, "func"))
    return func(args)


if __name__ == "__main__":
    raise SystemExit(main())
