import os
import socket

import pytest

from tests.radius.client import (
    build_access_request,
    send_and_recv,
)


def _env(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name)
    return val if (val is not None and val.strip() != "") else default


@pytest.mark.integration
def test_live_access_request_with_message_authenticator_roundtrip():
    """Live check: if env points to a running RADIUS server with a configured client,
    send an Access-Request with Message-Authenticator and expect a response.

    Required env:
      - TEST_RADIUS_HOST
      - TEST_RADIUS_PORT
      - TEST_RADIUS_SECRET
      - TEST_RADIUS_USER
      - TEST_RADIUS_PASS
    """
    host = _env("TEST_RADIUS_HOST")
    port_s = _env("TEST_RADIUS_PORT")
    secret = _env("TEST_RADIUS_SECRET")
    user = _env("TEST_RADIUS_USER")
    pwd = _env("TEST_RADIUS_PASS")

    if not all([host, port_s, secret, user, pwd]):
        pytest.skip("Live RADIUS integration env not configured")

    port = int(port_s)  # type: ignore[arg-type]
    secret_b = secret.encode("utf-8")  # type: ignore[union-attr]

    # Build Access-Request that includes Message-Authenticator by adding a zeroed attr
    req, req_auth = build_access_request(user, pwd, secret_b)
    # Insert a zeroed Message-Authenticator attribute at the end (type 80, len 18, 16 zero bytes)
    req = req + bytes([80, 18]) + (b"\x00" * 16)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2.0)
        res = send_and_recv(s, req, (host, port))
        assert res is not None, (
            "No response (server not reachable or invalid client configuration)"
        )
        code, data = res
        # Accept (2) or Reject (3) are both valid outcomes here
        assert code in (2, 3)
