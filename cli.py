#!/usr/bin/env python3
"""
Console entrypoint: tries to run package main, falls back to top-level main if present.
"""
import logging
import sys

def main():
    logging.basicConfig(level=logging.INFO)
    try:
        # Importiere das Paket‑Main (erwartet tacacs_server/main.py oder tacacs_server/main/__init__.py)
        import tacacs_server.main as pkg_main
        return pkg_main.main()
    except Exception as exc:
        logging.getLogger(__name__).error("Failed to start tacacs-server: %s", exc)
        # fallback: try legacy top-level main module
        try:
            import main as legacy_main  # top-level main.py (legacy)
            return legacy_main.main()
        except Exception as exc2:





    raise SystemExit(main())if __name__ == "__main__":            return 1            logging.getLogger(__name__).debug("fallback to legacy main failed: %s", exc2)            logging.getLogger(__name__).debug("fallback to legacy main failed: %s", exc2)
            return 1

if __name__ == "__main__":
    raise SystemExit(main())