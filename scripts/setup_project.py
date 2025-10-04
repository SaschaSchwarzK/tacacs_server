#!/usr/bin/env python3
"""
Create runtime directories (config, data, logs, scripts) and optionally move the
TACACS+ client script.
Run from project root.
"""

import argparse
import shutil
from pathlib import Path

DEFAULT_DIRS = ["config", "data", "logs", "scripts"]


def ensure_dirs(root: Path):
    for d in DEFAULT_DIRS:
        p = root / d
        p.mkdir(parents=True, exist_ok=True)
        print("ensured:", p)


def move_test_client_if_present(root: Path):
    src = root / "tests" / "test_client.py"
    dst = root / "scripts" / "tacacs_client.py"
    if src.exists() and not dst.exists():
        shutil.move(str(src), str(dst))
        dst.chmod(0o755)
        print(f"moved {src} -> {dst}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root", type=Path, default=Path.cwd())
    ap.add_argument(
        "--move-test-client",
        action="store_true",
        help="Move tests/test_client.py -> scripts/tacacs_client.py",
    )
    args = ap.parse_args()
    root = args.project_root.resolve()
    ensure_dirs(root)
    if args.move_test_client:
        move_test_client_if_present(root)
    print("Done.")


if __name__ == "__main__":
    main()
