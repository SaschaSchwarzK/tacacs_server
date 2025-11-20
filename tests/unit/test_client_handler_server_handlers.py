"""
Unit tests for TACACS+ client handler and server components.

This module contains tests for the core TACACS+ server functionality including:
- Client connection handling and request processing
- Authentication, Authorization, and Accounting (AAA) operations
- Proxy and device management
- Server configuration and health monitoring
- Statistics collection and reporting

The tests use mock objects and fixtures to isolate functionality and ensure
reliable test execution without external dependencies.
"""

import logging
import struct

import pytest

from tacacs_server.tacacs.client_handler import ClientHandler
from tacacs_server.tacacs.constants import (
    TAC_PLUS_ACCT_STATUS,
    TAC_PLUS_AUTHEN_STATUS,
    TAC_PLUS_AUTHOR_STATUS,
    TAC_PLUS_FLAGS,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.handlers import AAAHandlers
from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.tacacs.server import TacacsServer
from tacacs_server.tacacs.session import SessionManager
from tacacs_server.tacacs.stats import StatsManager
from tacacs_server.tacacs.validator import PacketValidator
from tests.unit.tacacs_stubs import PROMETHEUS_ACTIVE, PROMETHEUS_COMMANDS, StubDBLogger


@pytest.fixture(autouse=True)
def clear_prometheus_records():
    """Fixture to clear Prometheus test data between tests.

    Ensures test isolation by cleaning up global state.
    """
    PROMETHEUS_COMMANDS.clear()
    PROMETHEUS_ACTIVE.clear()
    yield
    PROMETHEUS_COMMANDS.clear()
    PROMETHEUS_ACTIVE.clear()


class DummyLimiter:
    """Mock rate limiter for testing connection limits.

    Implements the rate limiter interface without actual rate limiting.
    """

    def acquire(self, ip):
        """Simulate acquiring a connection slot."""
        return True

    def release(self, ip):
        """Simulate releasing a connection slot."""
        pass


class HandlerStub:
    """Stub implementation of AAA handlers for testing.

    Allows controlling the response statuses for authentication,
    authorization, and accounting operations.
    """

    def __init__(self):
        """Initialize with default success statuses."""
        self.auth_status = TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS
        self.author_status = TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
        self.acct_status = TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS
        self.error_called = False

    def handle_authentication(self, packet, device):
        """Handle authentication request with configurable status."""
        pkt = TacacsPacket()
        pkt.body = bytes([self.auth_status])
        return pkt

    def _create_auth_response(self, *args, **kwargs):
        """Create an error response and track the error."""
        self.error_called = True
        return TacacsPacket(body=b"error")

    def handle_authorization(self, packet, device):
        """Handle authorization request with configurable status."""
        pkt = TacacsPacket()
        pkt.body = bytes([self.author_status])
        return pkt

    def handle_accounting(self, packet, device):
        """Handle accounting request with configurable status."""
        pkt = TacacsPacket()
        pkt.body = struct.pack("!HHH", 0, 0, self.acct_status)
        return pkt


def _build_client_handler(stats, handler_stub, **kwargs):
    """Create a ClientHandler instance with test configuration.

    Args:
        stats: StatsManager instance for tracking metrics
        handler_stub: Mock handler for AAA operations
        **kwargs: Additional configuration overrides

    Returns:
        Configured ClientHandler instance
    """
    validator = PacketValidator(1024)
    session_mgr = SessionManager()
    return ClientHandler(
        handlers=handler_stub,
        session_manager=session_mgr,
        stats_manager=stats,
        validator=validator,
        conn_limiter=DummyLimiter(),
        **kwargs,
    )


def test_client_handler_encryption_and_logger():
    """Test encryption requirements and logger enrichment.

    Verifies:
    - Encryption requirement checking
    - Error response generation
    - Logger enrichment with session context
    """
    stats = StatsManager()
    handler_stub = HandlerStub()
    handler = _build_client_handler(
        stats,
        handler_stub,
        device_auto_register=True,
        device_store=None,
        proxy_handler=None,
    )

    packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
    )

    assert handler._check_encryption_required(packet, logging.getLogger("test"))
    response = handler._create_encryption_error_response(packet)
    assert handler_stub.error_called
    assert isinstance(response, TacacsPacket)

    base_logger = logging.LoggerAdapter(logging.getLogger("tacacs"), {})
    enriched = handler._enrich_logger(base_logger, 0x10)
    assert isinstance(enriched, logging.LoggerAdapter)
    assert enriched.extra.get("session_id") == "0x00000010"


def test_client_handler_auth_authorization_accounting():
    """Test core AAA operations and statistics tracking.

    Verifies:
    - Authentication success/failure handling
    - Authorization result recording
    - Accounting status updates
    - Statistics counter updates
    """
    stats = StatsManager()
    handler_stub = HandlerStub()
    handler_stub.auth_status = TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS
    handler = _build_client_handler(
        stats,
        handler_stub,
        encryption_required=False,
        device_auto_register=False,
        device_store=None,
        proxy_handler=None,
    )

    packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        flags=0,
    )

    handler._handle_authentication(packet, None, logging.getLogger("client"))
    assert stats.stats["auth_requests"] == 1
    assert stats.stats["auth_success"] == 1

    recorded = []
    handler._record_command_metric = lambda result: recorded.append(result)

    handler_stub.author_status = TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
    handler._handle_authorization(packet, None)
    assert recorded[-1] == "granted"
    assert stats.stats["author_success"] == 1

    handler_stub.author_status = TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL
    handler._handle_authorization(packet, None)
    assert recorded[-1] == "denied"
    assert stats.stats["author_failures"] == 1

    handler_stub.acct_status = TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS
    handler._handle_accounting(packet, None)
    assert stats.stats["acct_success"] == 1

    handler_stub.acct_status = TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR
    handler._handle_accounting(packet, None)
    assert stats.stats["acct_failures"] == 1


def test_client_handler_proxy_and_device_handling():
    """Test proxy validation and device management.

    Verifies:
    - Proxy source IP validation
    - Device auto-registration
    - Device lookup and resolution
    """
    stats = StatsManager()
    handler_stub = HandlerStub()
    proxy_handler = type(
        "ProxyStub",
        (),
        {"validate_proxy_source": lambda self, ip: False},
    )()

    handler = _build_client_handler(
        stats,
        handler_stub,
        proxy_handler=proxy_handler,
        device_store=None,
        device_auto_register=False,
    )

    logger = logging.LoggerAdapter(logging.getLogger("proxy"), {})
    assert not handler._validate_proxy("1.1.1.1", ("1.1.1.1", 1234), logger)
    assert stats.stats["proxy_rejected_unknown"] == 1

    class FakeDeviceStore:
        """Mock device store for testing device management."""

        def __init__(self):
            self.device = None

        def find_device_for_ip(self, ip):
            """Find device by IP address."""
            return self.device

        def find_device_for_identity(self, client_ip, proxy_ip):
            """Find device by client and proxy IPs."""
            return self.device

        def ensure_device(self, name, network, group):
            """Create and register a new device."""
            device = type(
                "Device",
                (),
                {"name": name, "group": type("Group", (), {"name": group})()},
            )()
            self.device = device
            return device

    device_store = FakeDeviceStore()
    handler_auto = _build_client_handler(
        stats,
        handler_stub,
        device_store=device_store,
        device_auto_register=True,
        proxy_handler=None,
    )
    result = handler_auto._resolve_device("10.0.0.1", None, logging.getLogger("device"))
    assert result is device_store.device


@pytest.fixture
def aaa_handler():
    """Fixture providing a configured AAAHandlers instance for testing.

    Automatically cleans up resources after test completion.
    """
    handler = AAAHandlers([], StubDBLogger(), backend_process_pool_size=0)
    yield handler
    handler._backend_executor.shutdown(wait=False)


def test_handlers_helpers_and_serialization(aaa_handler):
    """Test utility methods and configuration serialization.

    Verifies:
    - Sensitive data redaction
    - Type conversion helpers
    - Username tracking
    - Backend configuration serialization
    """
    handler = aaa_handler
    redacted = handler._redact_args(
        {"password": "secret", "token": "t" * 30, "count": "123456789012"}
    )
    assert redacted["password"] == "***"
    assert redacted["token"] == "***"
    assert redacted["count"] == "***"

    assert handler._safe_int("5") == 5
    assert handler._safe_int("abc", default=9) == 9
    assert handler._safe_user(None) == "<unknown>"

    handler._remember_username(10, "alice")
    assert handler.session_usernames[10] == "alice"

    handler._log_auth_result(10, "alice", None, True, detail="backend=foo")
    handler._log_auth_result(10, None, None, False)

    class LocalBackend:
        """Mock local backend configuration."""

        name = "local"
        db_path = "sqlite:///:memory:"

    class LDAPBackend:
        """Mock LDAP backend configuration."""

        name = "ldap"
        ldap_server = "ldap.example"
        base_dn = "dc=example,dc=com"
        bind_dn = "cn=bind"
        bind_password = "pwd"
        user_attribute = "uid"
        use_tls = True
        timeout = 7

    assert handler._serialize_backend_config(LocalBackend())["type"] == "local"
    assert (
        handler._serialize_backend_config(LDAPBackend())["ldap_server"]
        == "ldap.example"
    )


@pytest.fixture
def tacacs_server(monkeypatch):
    """Fixture providing a configured TacacsServer instance for testing.

    Automatically cleans up resources after test completion.
    """
    monkeypatch.setenv("TACACS_BACKEND_PROCESS_POOL_SIZE", "0")
    server = TacacsServer()
    yield server
    server.graceful_shutdown(timeout_seconds=0.1)


def test_server_connection_limits_and_config(monkeypatch, tacacs_server):
    """Test server configuration and connection limit handling.

    Verifies:
    - Configuration loading from multiple sources
    - Environment variable overrides
    - Connection limit enforcement
    """

    class ConfigObj:
        def get_security_config(self):
            return {"max_connections_per_ip": "3"}

    server = tacacs_server
    server.config = ConfigObj()
    assert server._get_max_connections_per_ip() == 3

    monkeypatch.setenv("TACACS_MAX_CONN_PER_IP", "15")
    server.config = {}
    assert server._get_max_connections_per_ip() == 15
    monkeypatch.delenv("TACACS_MAX_CONN_PER_IP", raising=False)

    class NewConfig:
        def get_security_config(self):
            return {"max_connections_per_ip": "6"}

        def get_server_config(self):
            return {"backend_process_pool_size": 2}

    server.set_config(NewConfig())
    assert server.conn_limiter.max_per_ip == 6


def test_server_backend_pool_and_health(monkeypatch, tacacs_server):
    """Test backend process pool and health monitoring.

    Verifies:
    - Process pool size configuration
    - Database health checks
    - Memory usage reporting
    """
    server = tacacs_server

    class Config:
        def get_server_config(self):
            return {"backend_process_pool_size": "5"}

    server.config = Config()
    monkeypatch.setenv("TACACS_BACKEND_PROCESS_POOL_SIZE", "2")
    assert server._get_backend_process_pool_size() == 5

    class UnhealthyDB:
        def ping(self):
            return False

        def get_statistics(self, days=1):
            return {}

    server.db_logger = UnhealthyDB()
    assert server._check_database_health()["status"] == "unhealthy"

    class HealthyDB:
        def ping(self):
            return True

        def get_statistics(self, days=1):
            return {"total_records": 8}

    server.db_logger = HealthyDB()
    assert server._check_database_health()["status"] == "healthy"
    assert server._get_memory_usage()["rss_mb"] >= 0


def test_server_stats_and_device_lookup(tacacs_server):
    """Test statistics collection and device resolution.

    Verifies:
    - Active session counting
    - Device lookup functionality
    - Health status reporting
    """
    server = tacacs_server
    server.handlers.auth_sessions = {1: {}, "1_cmd": {}}
    stats = server.get_stats()
    assert stats["active_auth_sessions"] == 2

    class DeviceStore:
        def find_device_for_ip(self, ip):
            return type("Dev", (), {"name": "dev"})

    sock_holder = type("Sock", (), {})()
    server.device_store = DeviceStore()
    server._early_device_lookup(sock_holder, "127.0.0.1")
    assert hasattr(sock_holder, "selected_device")
    assert server.get_health_status()["database_status"]["status"] in {
        "healthy",
        "unhealthy",
    }
