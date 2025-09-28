#!/usr/bin/env python3
"""
Package CLI entrypoint used by poetry script 'tacacs-server'.
"""
import logging

def main():
    logging.basicConfig(level=logging.INFO)
    try:
        # Expect tacacs_server/main.py to implement a main() function
        from . import main as pkg_main
        return pkg_main.main()
    except Exception as exc:
        logging.getLogger(__name__).error("Could not start tacacs-server: %s", exc)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())