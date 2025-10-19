#!/usr/bin/env python3
"""
Package CLI entrypoint used by poetry script 'tacacs-server'.
"""

import os
from tacacs_server.utils.logger import configure, get_logger

logger = get_logger(__name__)


def main():
    configure()
    try:
        # Default to async runtime; allow opting into legacy sync with TACACS_SYNC=true
        use_sync = str(os.environ.get("TACACS_SYNC", "")).lower() in ("1", "true", "yes")
        if use_sync:
            from . import main as pkg_main
        else:
            from . import main_async as pkg_main

        return pkg_main.main()
    except Exception as _:
        logger.error("Could not start tacacs-server", exc_info=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
