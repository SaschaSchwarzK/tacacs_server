"""Utility to prune local auth users, keeping only a whitelist.

Usage examples:
  poetry run python scripts/cleanup_users.py --keep admin alice
  TACACS_CONFIG=path/to/tacacs.conf poetry run python scripts/cleanup_users.py --keep admin alice
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from tacacs_server.auth.local_store import LocalAuthStore
from tacacs_server.config.config import TacacsConfig


def main() -> int:
    parser = argparse.ArgumentParser(description="Prune local users in auth DB")
    parser.add_argument(
        "--config",
        "-c",
        default=os.environ.get("TACACS_CONFIG", "config/tacacs.conf"),
        help="Path to tacacs config (defaults to TACACS_CONFIG or config/tacacs.conf)",
    )
    parser.add_argument(
        "--keep",
        nargs="+",
        required=True,
        help="Usernames to keep (all others will be deleted)",
    )
    args = parser.parse_args()

    # Load config to get DB path
    cfg = TacacsConfig(args.config)
    db_path = Path(cfg.get_local_auth_db()).resolve()

    store = LocalAuthStore(str(db_path))
    keep_set = {u.strip() for u in args.keep if u and u.strip()}

    users = store.list_users()
    removed = 0
    for user in users:
        if user.username not in keep_set:
            if store.delete_user(user.username):
                removed += 1

    print(f"Pruned local users in {db_path}. Kept {len(keep_set)}; removed {removed}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
