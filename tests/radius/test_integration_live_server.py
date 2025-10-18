import socket

import pytest

from tests.radius.client import build_access_request, send_and_recv


@pytest.mark.integration
def test_radius_live_accept_or_reject(radius_enabled_server):
    host = radius_enabled_server["host"]
    port = radius_enabled_server["auth_port"]
    secret = radius_enabled_server["secret"].encode("utf-8")

    # Known seeded user in fixture: radiususer / radiuspass
    pkt, _ = build_access_request("radiususer", "radiuspass", secret)
    # Add a zeroed Message-Authenticator to exercise MA path
    pkt += bytes([80, 18]) + (b"\x00" * 16)

    before = radius_enabled_server["server"].get_stats()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        res = send_and_recv(s, pkt, (host, port))
        assert res is not None
        code, _ = res
        # Accept (2) expected if backend attached successfully, otherwise Reject (3)
        assert code in (2, 3)
    after = radius_enabled_server["server"].get_stats()
    # auth_requests increments by 1
    assert after["auth_requests"] == before["auth_requests"] + 1
    if code == 2:
        assert after["auth_accepts"] == before["auth_accepts"] + 1
    else:
        assert after["auth_rejects"] == before["auth_rejects"] + 1
