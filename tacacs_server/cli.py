#!/usr/bin/env python3
"""
Package CLI entrypoint used by poetry script 'tacacs-server'.
"""

from tacacs_server.utils.logger import configure, get_logger

logger = get_logger(__name__)


def main():
    configure()
    try:
        # Expect tacacs_server/main.py to implement a main() function
        from . import main as pkg_main

        return pkg_main.main()
    except Exception as _:
        logger.error("Could not start tacacs-server", exc_info=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
