"""
Minimal liveness probe for TACACS+ / RADIUS.

Usage examples:
  python -m tacacs_server.healthcheck --check tacacs
  python -m tacacs_server.healthcheck --check both --timeout 1.0
"""

from __future__ import annotations

import argparse
import os
import socket
import sys


def tcp_connect(host: str, port: int, timeout: float) -> None:
    """Attempt a TCP connect; raises on failure."""
    with socket.create_connection((host, port), timeout=timeout):
        return


def udp_probe(host: str, port: int, timeout: float) -> None:
    """Best-effort UDP probe for RADIUS liveness.

    Sends a tiny datagram and expects no error. We do not require a reply,
    since UDP liveness is inherently flaky.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b"\x00", (host, port))
    finally:
        try:
            s.close()
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Container liveness healthcheck")
    parser.add_argument(
        "--tacacs-host", default=os.getenv("TACACS_HOST", "127.0.0.1")
    )
    parser.add_argument(
        "--tacacs-port", type=int, default=int(os.getenv("TACACS_PORT", "49"))
    )
    parser.add_argument(
        "--radius-host", default=os.getenv("RADIUS_HOST", "127.0.0.1")
    )
    parser.add_argument(
        "--radius-port", type=int, default=int(os.getenv("RADIUS_PORT", "1812"))
    )
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument(
        "--check",
        choices=["tacacs", "radius", "both"],
        default=os.getenv("HEALTH_CHECK", "tacacs"),
    )
    args = parser.parse_args()

    try:
        if args.check in ("tacacs", "both"):
            tcp_connect(args.tacacs_host, args.tacacs_port, args.timeout)
        if args.check in ("radius", "both"):
            udp_probe(args.radius_host, args.radius_port, args.timeout)
    except Exception as e:  # pragma: no cover - simple container probe
        print(f"healthcheck failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

