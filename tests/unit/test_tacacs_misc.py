"""
Unit tests for miscellaneous TACACS+ protocol components and utilities.

This module contains tests for various TACACS+ protocol components that don't have
enough test coverage to warrant their own dedicated test modules. It includes tests
for network handling, packet parsing, proxy protocol support, session management,
statistics tracking, and validation logic.
"""

import socket
import struct

import pytest

import tests.unit.tacacs_stubs as tacacs_stubs
from tacacs_server.tacacs.constants import (
    TAC_PLUS_FLAGS,
    TAC_PLUS_PACKET_TYPE,
    TAC_PLUS_VERSION,
)
from tacacs_server.tacacs.network import NetworkHandler
from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.tacacs.proxy import ProxyHandler, ProxyProtocolV2Parser
from tacacs_server.tacacs.session import SessionManager
from tacacs_server.tacacs.stats import StatsManager
from tacacs_server.tacacs.structures import (
    _extract_string,
    parse_acct_request,
    parse_authen_start,
    parse_author_request,
)
from tacacs_server.tacacs.validator import PacketValidator

_STUB_MODULE = tacacs_stubs


class DummySocket:
    """Mock socket for testing network operations.

    This class simulates a socket with predefined responses for testing
    network-related functionality without requiring actual network access.

    Args:
        responses: List of byte strings to return on subsequent recv() calls
    """

    def __init__(self, responses):
        self.responses = list(responses)

    def recv(self, amount):
        if not self.responses:
            return b""
        return self.responses.pop(0)

    def shutdown(self, *args):
        raise OSError("shutdown failed")

    def close(self):
        raise OSError("close failed")


def test_network_recv_exact_success():
    """Test successful exact data reception from socket.

    Verifies that recv_exact correctly assembles data from multiple
    socket recv() calls into a complete message.
    """
    sock = DummySocket([b"ab", b"cdef"])
    assert NetworkHandler.recv_exact(sock, 6) == b"abcdef"


def test_network_recv_exact_none_on_short():
    """Test recv_exact returns None on premature socket close.

    Ensures that recv_exact properly handles cases where the socket
    is closed before all requested data is received.
    """
    sock = DummySocket([b""])
    assert NetworkHandler.recv_exact(sock, 4) is None


def test_network_safe_close_socket_handles_errors():
    """Test error handling in safe_close_socket.

    Verifies that safe_close_socket doesn't raise exceptions when
    closing a problematic socket.
    """
    sock = DummySocket([])
    NetworkHandler.safe_close_socket(sock)


def test_network_enable_tcp_keepalive_handles_options():
    """Test TCP keepalive option configuration.

    Verifies that enable_tcp_keepalive correctly handles socket options
    and continues even if some options are not supported.
    """
    calls = []

    class Keeper:
        def setsockopt(self, level, optname, value):
            calls.append((level, optname, value))
            if optname == getattr(socket, "TCP_KEEPALIVE", None):
                raise OSError("keepalive failed")

    NetworkHandler.enable_tcp_keepalive(Keeper(), 1, 2, 3)
    assert calls and calls[0][1] == socket.SO_KEEPALIVE


def test_packet_pack_unpack_encrypt_roundtrip():
    """Test TACACS+ packet serialization and encryption.

    Verifies that packet header packing/unpacking and body
    encryption/decryption work correctly in a round-trip.
    """
    msg = b"payload"
    p = TacacsPacket(
        version=0xC0,
        packet_type=1,
        seq_no=3,
        flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        session_id=0x11112222,
        length=len(msg),
        body=msg,
    )
    header = p.pack_header()
    assert header == struct.pack(
        "!BBBBLL",
        0xC0,
        1,
        3,
        TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        0x11112222,
        len(msg),
    )
    unpacked = TacacsPacket.unpack_header(header, max_length=1000)
    assert unpacked.session_id == 0x11112222

    p.flags = 0
    encrypted = p.encrypt_body("secret")
    assert encrypted != msg
    assert p.decrypt_body("secret", encrypted) == msg

    assert str(p).startswith("TacacsPacket(")


def test_packet_unpack_header_errors():
    """Test error handling in packet header parsing.

    Verifies that invalid packet headers raise appropriate exceptions.
    """
    with pytest.raises(Exception):
        TacacsPacket.unpack_header(b"\x00")
    data = struct.pack("!BBBBLL", 0xC0, 1, 1, 0, 0, 99999)
    with pytest.raises(Exception):
        TacacsPacket.unpack_header(data, max_length=1)


def test_proxy_parse_valid_header():
    """Test parsing of valid PROXY protocol v2 headers.

    Verifies that the proxy protocol parser correctly extracts
    connection information from valid PROXY v2 headers.
    """
    first12 = ProxyProtocolV2Parser.SIGNATURE
    ver_cmd = bytes([0x21])  # version=2 command=1(Proxy)
    fam_proto = bytes([0x11])  # family=INET (IPv4), proto=STREAM
    addr = b"\x01\x01\x01\x01" + b"\x02\x02\x02\x02" + struct.pack("!HH", 123, 321)
    addr_len = len(addr)
    addr_len_bytes = struct.pack("!H", addr_len)

    responses = [ver_cmd + fam_proto + addr_len_bytes, addr]

    def receiver(amount):
        if not responses:
            return b""
        return responses.pop(0)

    handler = ProxyHandler()
    info, consumed, buffered = handler.parse_proxy_header(first12, receiver)
    assert info is not None
    assert consumed == 16 + addr_len
    assert info.src_addr == "1.1.1.1"


def test_proxy_parse_invalid_header():
    """Test handling of invalid PROXY protocol headers.

    Verifies that the proxy handler correctly identifies and rejects
    malformed or invalid PROXY protocol headers.
    """
    handler = ProxyHandler()
    info, consumed, buffered = handler.parse_proxy_header(b"broken", lambda _n: b"")
    assert info is None
    assert consumed == 0


def test_proxy_validate_source_logic(monkeypatch):
    """Test source IP validation in proxy handler.

    Verifies that the proxy handler correctly validates source IPs
    against allowed networks and handles various edge cases.
    """
    proxy_handler = ProxyHandler(validate_sources=True, device_store=None)
    assert proxy_handler.validate_proxy_source("127.0.0.1") is True

    class FakeStore:
        def list_proxies(self):
            from ipaddress import ip_network

            return [type("P", (), {"network": ip_network("10.0.0.0/8")})()]

    proxy_handler.device_store = FakeStore()
    assert proxy_handler.validate_proxy_source("10.0.0.1") is True
    assert proxy_handler.validate_proxy_source("192.0.2.1") is False

    class FailingStore:
        def list_proxies(self):
            raise RuntimeError("boom")

    proxy_handler.device_store = FailingStore()
    assert proxy_handler.validate_proxy_source("1.2.3.4") is True


def test_session_manager_secret_resolution():
    """Test TACACS+ session secret resolution.

    Verifies that the session manager correctly resolves TACACS+ secrets
    from various sources (device, group, metadata) with proper fallback.
    """
    mgr = SessionManager(max_sessions=5)

    class Group:
        tacacs_secret = "group-secret"

    class Device:
        group = Group()

    secret = mgr.get_or_create_secret(42, Device(), "fallback")
    assert secret == "group-secret"

    class GroupMeta:
        metadata = {"tacacs_secret": "meta-secret"}

    class DeviceMeta:
        group = GroupMeta()

    secret = mgr.get_or_create_secret(43, DeviceMeta(), "fallback")
    assert secret == "meta-secret"

    mgr.cleanup_session(42)
    mgr.cleanup_sessions({43})

    assert mgr.validate_sequence(1, 1)
    assert not mgr.validate_sequence(1, 2)
    assert mgr.validate_sequence(1, 3)


def test_stats_manager_behavior(monkeypatch):
    """Test statistics collection and management.

    Verifies that the StatsManager correctly tracks and updates
    various TACACS+ server metrics.
    """
    mgr = StatsManager()
    mgr.increment("auth_requests", 2)
    assert mgr.stats["auth_requests"] == 2

    mgr.record_connection_type(True)
    mgr.record_connection_type(False)
    assert mgr.stats["connections_proxied"] == 1
    assert mgr.stats["connections_direct"] == 1

    mgr.stats["connections_active"] = 5
    mgr._prom_update_active = lambda value: None
    mgr.update_active_connections(-3)
    assert mgr.get_active_connections() == 2

    mgr._prom_update_active = lambda value: (_ for _ in ()).throw(ValueError("boom"))
    mgr.update_active_connections(1)

    before = mgr.stats["connections_active"]
    mgr.reset()
    assert mgr.stats["connections_active"] == before


def test_structures_extract_string_edge_cases():
    """Test edge cases in string extraction.

    Verifies that _extract_string handles edge cases like
    empty buffers and invalid positions correctly.
    """
    assert _extract_string(b"", 0, -1) == ("", 0)
    assert _extract_string(b"", -1, 0) == ("", -1)


def test_structures_parsing():
    """Test parsing of TACACS+ authentication and authorization structures.

    Verifies that the various TACACS+ message parsers correctly
    handle valid messages and raise exceptions for invalid ones.
    """
    user = "alice"
    port = "ttyS0"
    rem = "10.0.0.5"
    data = b"payload"

    header = struct.pack(
        "!BBBBBBBB", 1, 1, 1, 1, len(user), len(port), len(rem), len(data)
    )
    body = header + user.encode() + port.encode() + rem.encode() + data
    auth_start = parse_authen_start(body)
    assert auth_start["user"] == user
    with pytest.raises(Exception):
        parse_authen_start(b"\x00")

    args = [b"foo=bar", b"empty"]
    arg_lens = bytes([len(a) for a in args])
    header = struct.pack(
        "!BBBBBBBB", 1, 1, 1, 1, len(user), len(port), len(rem), len(args)
    )
    author_body = (
        header
        + user.encode()
        + port.encode()
        + rem.encode()
        + arg_lens
        + b"".join(args)
    )
    author = parse_author_request(author_body)
    assert author["args"]["foo"] == "bar"

    acct_header = struct.pack(
        "!BBBBBBBBB", 0, 1, 1, 1, 1, len(user), len(port), len(rem), len(args)
    )
    acct_body = (
        acct_header
        + arg_lens
        + user.encode()
        + port.encode()
        + rem.encode()
        + b"".join(args)
    )
    acct = parse_acct_request(acct_body)
    assert "foo" in acct["args"]


def test_validator_logic():
    """Test TACACS+ packet validation.

    Verifies that the packet validator correctly identifies invalid
    TACACS+ packets based on version, type, and sequence number.
    """
    val = PacketValidator()
    pkt = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
    )
    assert val.validate_header(pkt)

    pkt.version = 0x00
    assert not val.validate_header(pkt)
    pkt.version = TAC_PLUS_VERSION
    pkt.packet_type = 0
    assert not val.validate_header(pkt)
    pkt.packet_type = TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN
    pkt.seq_no = 2
    assert not val.validate_header(pkt)

    val._log_invalid_version(1, 2)
    val._log_invalid_type(1, 2)
    val._log_invalid_sequence(1, 2)
