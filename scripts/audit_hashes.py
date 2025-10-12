"""Audit local user password hash formats and report legacy usage.

Usage:
  poetry run python scripts/audit_hashes.py [-c CONFIG]

Exits with code 0 if no legacy hashes found, 1 otherwise.
Prints a summary of total users, bcrypt users, legacy (SHA-256-like) users, and unknown formats.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from tacacs_server.auth.local_store import LocalAuthStore
from tacacs_server.config.config import TacacsConfig
from tacacs_server.utils.password_hash import LegacyPasswordMigrator, PasswordHasher


def is_bcrypt(hash_str: str | None) -> bool:
    return bool(hash_str) and PasswordHasher.is_bcrypt_hash(hash_str)  # type: ignore[arg-type]


def is_legacy_sha256(hash_str: str | None) -> bool:
    return bool(hash_str) and LegacyPasswordMigrator.is_legacy_hash(hash_str)  # type: ignore[arg-type]


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit password hash formats")
    parser.add_argument(
        "-c",
        "--config",
        default=os.environ.get("TACACS_CONFIG", "config/tacacs.conf"),
        help="Path to tacacs configuration file",
    )
    args = parser.parse_args()

    cfg = TacacsConfig(args.config)
    db_path = Path(cfg.get_local_auth_db()).resolve()
    store = LocalAuthStore(str(db_path))

    total = 0
    bcrypt_count = 0
    legacy_count = 0
    unknown = 0

    for user in store.list_users():
        total += 1
        h = user.password_hash or ""
        if is_bcrypt(h):
            bcrypt_count += 1
        elif is_legacy_sha256(h):
            legacy_count += 1
        elif not h:
            # No hash set; skip but count as unknown state
            unknown += 1
        else:
            unknown += 1

    print("Password Hash Audit")
    print("====================")
    print(f"Database: {db_path}")
    print(f"Total users:   {total}")
    print(f"bcrypt:        {bcrypt_count}")
    print(f"legacy sha256: {legacy_count}")
    print(f"unknown:       {unknown}")

    if legacy_count > 0:
        print("\nERROR: Legacy SHA-256 hashes detected. Migrate to bcrypt.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
