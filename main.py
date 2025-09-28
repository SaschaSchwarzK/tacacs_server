#!/usr/bin/env python3
"""
Legacy top-level entrypoint shim -> delegates to tacacs_server.main.main()
"""
import sys
import logging

def main():
    logging.basicConfig(level=logging.INFO)
    try:
        from tacacs_server import main as pkg_main
        return pkg_main.main()
    except Exception as e:
        logging.getLogger(__name__).exception("Failed to start tacacs_server main: %s", e)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())