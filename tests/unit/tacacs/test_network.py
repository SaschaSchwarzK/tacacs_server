"""Unit tests for TACACS network utilities."""

import socket

from tacacs_server.tacacs.network import NetworkHandler


class TimeoutSocket:
    """Dummy socket that tracks timeout set/restore behavior."""

    def __init__(self, payload: bytes):
        self._payload = payload
        self._timeouts: list[float | None] = []
        self._current_timeout: float | None = 5.0

    def gettimeout(self):
        return self._current_timeout

    def settimeout(self, value):
        self._current_timeout = value
        self._timeouts.append(value)

    def recv(self, amount: int) -> bytes:
        data, self._payload = self._payload[:amount], self._payload[amount:]
        return data

    @property
    def timeouts(self) -> list[float | None]:
        return self._timeouts


class ResetSocket:
    """Dummy socket that simulates a connection reset."""

    def recv(self, _amount: int) -> bytes:
        raise OSError("connection reset by peer")


class EOFsocket:
    """Dummy socket that immediately signals EOF."""

    def recv(self, _amount: int) -> bytes:
        return b""


def test_socketpair_connection_fragmented_recv():
    """Ensure recv_exact assembles fragmented data across a real socketpair."""
    srv, cli = socket.socketpair()
    try:
        message = b"hello world"
        cli.sendall(message[:5])
        cli.sendall(message[5:])
        assert NetworkHandler.recv_exact(srv, len(message)) == message
    finally:
        NetworkHandler.safe_close_socket(cli)
        NetworkHandler.safe_close_socket(srv)


def test_recv_exact_timeout_sets_and_restores_timeout():
    """Verify timeout argument sets and restores socket timeout."""
    payload = b"abcd"
    sock = TimeoutSocket(payload)
    result = NetworkHandler.recv_exact(sock, len(payload), timeout=1.0)
    assert result == payload
    assert sock.gettimeout() == 5.0  # restored to original
    assert 1.0 in sock.timeouts


def test_recv_exact_returns_none_on_connection_reset():
    """Connection reset during recv returns None instead of raising."""
    assert NetworkHandler.recv_exact(ResetSocket(), 4) is None


def test_recv_exact_returns_none_on_eof():
    """EOF (empty read) returns None."""
    assert NetworkHandler.recv_exact(EOFsocket(), 4) is None


def test_safe_close_socket_swallows_errors():
    """safe_close_socket should not raise even if shutdown/close fail."""
    class BadClose:
        def shutdown(self, *_args):
            raise OSError("shutdown failed")

        def close(self):
            raise OSError("close failed")

    NetworkHandler.safe_close_socket(BadClose())
