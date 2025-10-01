#!/usr/bin/env python3
"""Console entrypoint: delegates to package main with legacy fallback."""

from __future__ import annotations

from tacacs_server.utils.logger import configure, get_logger

logger = get_logger(__name__)


def main() -> int:
    configure()
    try:
        import tacacs_server.main as pkg_main

        return pkg_main.main()
    except Exception as exc:
        logger.error("Failed to start tacacs-server", error=str(exc))
        try:
            import main as legacy_main

            return legacy_main.main()
        except Exception as exc2:
            logger.debug("Fallback to legacy main failed", error=str(exc2))
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
