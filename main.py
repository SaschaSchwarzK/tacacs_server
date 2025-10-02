#!/usr/bin/env python3
"""
Legacy top-level entrypoint shim -> delegates to tacacs_server.main.main()
"""

from tacacs_server.utils.logger import configure, get_logger

logger = get_logger(__name__)


def main():
    configure()
    try:
        from tacacs_server import main as pkg_main
        return pkg_main.main()
    except Exception as e:
        logger.exception("Failed to start tacacs_server main", error=str(e))
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
