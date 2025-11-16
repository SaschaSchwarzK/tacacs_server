#!/usr/bin/env python3
"""
Spawn a child process that performs an HTTP POST to 127.0.0.1:PORT and prints results.

Usage:
  1) In one terminal:
       python tools/webhook_post_test/server_post_receiver.py 9999
  2) In another terminal:
       python tools/webhook_post_test/post_from_child.py 9999

This helps detect whether subprocess networking to loopback is blocked by the harness.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404: test helper uses controlled local subprocess
import sys
import textwrap


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    url = f"http://127.0.0.1:{port}/test"
    py = sys.executable
    child_code = textwrap.dedent(
        f"""
        import json, urllib.request
        data = json.dumps({{'msg':'hello from child'}}).encode('utf-8')
        req = urllib.request.Request('{url}', data=data, headers={{'Content-Type':'application/json'}}, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=2) as resp:
                body = resp.read().decode('utf-8', errors='replace')
                print('CHILD_STATUS', resp.status)
                print('CHILD_BODY', body)
        except Exception as e:
            print('CHILD_ERROR', type(e).__name__, str(e))
        """
    )
    print(f"[PARENT] Spawning child to POST to {url}")
    # Controlled args; no shell; safe in test helper
    res = subprocess.run([py, "-c", child_code], capture_output=True, text=True)  # nosec B603
    print("[PARENT] Child return code:", res.returncode)
    print("[PARENT] Child stdout:\n" + res.stdout)
    print("[PARENT] Child stderr:\n" + res.stderr)
    # Also try from parent for comparison
    try:
        import urllib.request

        data = json.dumps({"msg": "hello from parent"}).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=2) as resp:  # nosec B310: local http URL used for test
            body = resp.read().decode("utf-8", errors="replace")
            print("PARENT_STATUS", resp.status)
            print("PARENT_BODY", body)
    except Exception as e:
        print("PARENT_ERROR", type(e).__name__, str(e))


if __name__ == "__main__":
    main()
