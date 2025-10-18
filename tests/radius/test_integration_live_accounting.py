import socket

import pytest

from tests.radius.client import build_accounting_request, send_and_recv


@pytest.mark.integration
def test_accounting_request_success(radius_enabled_server):
    host = radius_enabled_server["host"]
    port = radius_enabled_server["acct_port"]
    secret = radius_enabled_server["secret"].encode("utf-8")

    # Minimal Accounting-Request (START) with valid Request Authenticator
    # Attr: Acct-Status-Type (40) length 6 value 1
    attrs = bytes([40, 6, 0, 0, 0, 1])
    pkt = build_accounting_request(secret, attrs=attrs)
    before = radius_enabled_server["server"].get_stats()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        res = send_and_recv(s, pkt, (host, port))
        assert res is not None
        code, _ = res
        # Accounting-Response code is 5
        assert code == 5
    after = radius_enabled_server["server"].get_stats()
    assert after["acct_requests"] == before["acct_requests"] + 1
    assert after["acct_responses"] == before["acct_responses"] + 1


@pytest.mark.integration
def test_accounting_request_tampered_authenticator_dropped(radius_enabled_server):
    host = radius_enabled_server["host"]
    port = radius_enabled_server["acct_port"]
    secret = radius_enabled_server["secret"].encode("utf-8")

    attrs = bytes([40, 6, 0, 0, 0, 1])
    pkt = bytearray(build_accounting_request(secret, attrs=attrs))
    # Corrupt one byte in the Request Authenticator (offset 4..20)
    pkt[10] ^= 0xFF
    before = radius_enabled_server["server"].get_stats()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1.5)
        res = send_and_recv(s, bytes(pkt), (host, port))
        # Server should drop invalid packet (no response)
        assert res is None
    after = radius_enabled_server["server"].get_stats()
    # Invalid authenticator should be dropped and counted as invalid_packets
    assert after["invalid_packets"] == before["invalid_packets"] + 1
