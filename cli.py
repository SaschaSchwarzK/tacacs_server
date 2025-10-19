#!/usr/bin/env python3
"""Console entrypoint: delegates to package main with legacy fallback."""

from __future__ import annotations

from typing import cast

from tacacs_server.utils.logger import configure, get_logger

logger = get_logger(__name__)


def main() -> int:
    configure()
    try:
        # Prefer async runtime by default; allow TACACS_SYNC=true to force legacy
        import os
        use_sync = str(os.environ.get("TACACS_SYNC", "")).lower() in ("1", "true", "yes")
        if use_sync:
            import tacacs_server.main as pkg_main
        else:
            import tacacs_server.main_async as pkg_main

        rc = pkg_main.main()
        return cast(int, rc)
    except Exception as exc:
        logger.error("Failed to start tacacs-server", error=str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
