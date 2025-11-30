"""Networking utility coverage for RADIUS UDP sockets."""

import socket

import pytest


def test_udp_socket_creation_and_reuseaddr():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Set SO_REUSEADDR
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        opt = sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
        # Some OSes return truthy non-1 values; just assert nonzero
        assert opt != 0
    finally:
        sock.close()


def test_bind_and_timeout_handling():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.1)
    try:
        sock.bind(("127.0.0.1", 0))
        addr = sock.getsockname()
        assert addr[0] == "127.0.0.1"
        assert addr[1] > 0
        # No data available; recvfrom should timeout
        with pytest.raises(socket.timeout):
            sock.recvfrom(1024)
    finally:
        sock.close()


def test_receive_buffer_sizing_and_incomplete_reads():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    addr = sock.getsockname()
    try:
        peer.sendto(b"hello", addr)
        data, src = sock.recvfrom(3)
        # recvfrom with size=3 should read up to 3 bytes and drop the rest for UDP
        assert data == b"hel"
    finally:
        sock.close()
        peer.close()


def test_address_parsing_ipv4_ipv6_support():
    # IPv4 socket
    s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s4.close()
    # IPv6 socket may not be available on all systems; skip if it fails
    try:
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s6.close()
    except OSError:
        pytest.skip("IPv6 socket not available")


def test_socket_binding_to_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        assert sock.getsockname()[1] > 0
    finally:
        sock.close()


def test_socket_timeout_behavior():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.05)
    sock.bind(("127.0.0.1", 0))
    try:
        with pytest.raises(socket.timeout):
            sock.recvfrom(10)
    finally:
        sock.close()


def test_incomplete_packet_recovery():
    """Ensure short recvfrom does not break subsequent reads."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    addr = listener.getsockname()
    try:
        sender.sendto(b"abc", addr)
        data, _ = listener.recvfrom(2)
        assert data == b"ab"
        # Next recv should still work
        sender.sendto(b"xyz", addr)
        data2, _ = listener.recvfrom(3)
        assert data2 == b"xyz"
    finally:
        listener.close()
        sender.close()


def test_udp_buffer_sizing():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        default_buf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, default_buf * 2)
        updated = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        assert updated >= default_buf
    finally:
        sock.close()


def test_socket_close_on_shutdown():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.close()
    with pytest.raises(OSError):
        sock.getsockname()
