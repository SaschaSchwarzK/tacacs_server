#!/usr/bin/env python3
import argparse
import subprocess
import sys

from pathlib import Path


def run_tacacs(host: str, port: int, secret: str, username: str, password: str) -> int:
    script = Path("/app/tacacs_client.py")
    cmd = [sys.executable, str(script), "--host", host, "--port", str(port), "--secret", secret, "--username", username, "--password", password]
    return subprocess.call(cmd)


def run_radius(host: str, port: int, secret: str, username: str, password: str) -> int:
    import os
    import socket
    import hashlib
    import secrets as _secrets
    # Build minimal RADIUS Access-Request with User-Name and User-Password (RFC 2865)
    CODE_ACCESS_REQUEST = 1
    ID = _secrets.randbits(8)
    RA = os.urandom(16)

    def _attr(t: int, v: bytes) -> bytes:
        l = 2 + len(v)
        return bytes([t, l]) + v

    # PAP password obfuscation: p1 = MD5(secret + RA); c1 = p ^ p1; (no multi-block for short pw)
    p = password.encode("utf-8")
    # pad to 16
    if len(p) % 16 != 0:
        p = p + b"\x00" * (16 - (len(p) % 16))
    m = hashlib.md5()
    m.update(secret.encode("utf-8"))
    m.update(RA)
    p1 = m.digest()
    c1 = bytes(a ^ b for a, b in zip(p[:16], p1))
    attrs = b"".join([
        _attr(1, username.encode("utf-8")),  # User-Name
        _attr(2, c1),  # User-Password (single block)
    ])
    length = 20 + len(attrs)
    header = bytes([CODE_ACCESS_REQUEST, ID]) + length.to_bytes(2, "big") + RA
    pkt = header + attrs

    # Send/receive
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(pkt, (host, port))
        data, _ = s.recvfrom(4096)
        if not data or len(data) < 20:
            print("radius: no response or too short", flush=True)
            return 1
        code = data[0]
        if code == 2:
            print("radius: access-accept", flush=True)
            return 0
        elif code == 3:
            print("radius: access-reject", flush=True)
            return 1
        else:
            print(f"radius: unexpected code={code}", flush=True)
            return 1
    except Exception as e:
        print(f"radius: error {e}", flush=True)
        return 1
    finally:
        try:
            s.close()
        except Exception:
            pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["tacacs", "radius"], required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    args = ap.parse_args()

    if args.mode == "tacacs":
        return run_tacacs(args.host, args.port, args.secret, args.username, args.password)
    else:
        return run_radius(args.host, args.port, args.secret, args.username, args.password)


if __name__ == "__main__":
    raise SystemExit(main())
