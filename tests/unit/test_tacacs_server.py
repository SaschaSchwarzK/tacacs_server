import logging
import socket
from types import SimpleNamespace

import pytest

from tacacs_server.tacacs.server import TacacsServer


class FakeSocket:
    """Minimal socket stand-in for server setup tests."""

    def __init__(self, should_bind_fail: bool = False, should_listen_fail: bool = False):
        self.should_bind_fail = should_bind_fail
        self.should_listen_fail = should_listen_fail
        self.bound = None
        self.listen_backlog = None
        self.closed = False
        self.shutdown_called = False
        self.options = []

    def setsockopt(self, level, optname, value):
        self.options.append((level, optname, value))
        return 0

    def bind(self, address):
        self.bound = address
        if self.should_bind_fail:
            raise OSError("bind failed")
        return 0

    def listen(self, backlog):
        self.listen_backlog = backlog
        if self.should_listen_fail:
            raise OSError("listen failed")
        return 0

    def shutdown(self, how):
        self.shutdown_called = True

    def close(self):
        self.closed = True


def _make_server(monkeypatch, fake_socket: FakeSocket):
    """Helper to build a server instance with socket patched."""

    def _fake_socket_factory(*args, **kwargs):
        return fake_socket

    monkeypatch.setattr(socket, "socket", _fake_socket_factory)
    # Avoid running the accept loop in start() during tests
    monkeypatch.setattr(TacacsServer, "_accept_loop", lambda self: None)
    return TacacsServer()


def test_setup_server_socket_success(monkeypatch):
    fake = FakeSocket()
    server = _make_server(monkeypatch, fake)

    server._setup_server_socket()

    assert fake.bound == (server.host if not server.enable_ipv6 else "::", server.port)
    assert fake.listen_backlog == server.listen_backlog
    server.graceful_shutdown()


def test_setup_server_socket_bind_failure(monkeypatch, caplog):
    fake = FakeSocket(should_bind_fail=True)
    server = _make_server(monkeypatch, fake)

    with caplog.at_level(logging.ERROR), pytest.raises(OSError):
        server._setup_server_socket()

    # Ensure error was logged with event field
    assert any(
        rec.__dict__.get("event") == "tacacs.socket.bind_failed"
        or "Failed to bind TACACS+ socket" in rec.getMessage()
        for rec in caplog.records
    )
    server.graceful_shutdown()


def test_start_already_running(monkeypatch, caplog):
    server = _make_server(monkeypatch, FakeSocket())
    server.running = True

    with caplog.at_level(logging.WARNING):
        server.start()

    assert any("already running" in rec.getMessage() for rec in caplog.records)
    server.graceful_shutdown()


def test_start_requires_backend(monkeypatch):
    server = _make_server(monkeypatch, FakeSocket())
    server.auth_backends.clear()
    with pytest.raises(RuntimeError):
        server.start()
    server.graceful_shutdown()


def test_check_database_health_unhealthy(monkeypatch):
    server = _make_server(monkeypatch, FakeSocket())
    server.db_logger = SimpleNamespace(ping=lambda: False)

    result = server._check_database_health()

    assert result["status"] == "unhealthy"
    assert "error" in result
    server.graceful_shutdown()


def test_check_database_health_exception(monkeypatch):
    server = _make_server(monkeypatch, FakeSocket())

    def _raise():
        raise RuntimeError("boom")

    server.db_logger = SimpleNamespace(ping=_raise)

    result = server._check_database_health()

    assert result["status"] == "unhealthy"
    assert result["error"] == "Database error"
    server.graceful_shutdown()
