"""
Tests for TACACS+ Authorization functionality
"""

import struct
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from tacacs_server.auth.base import AuthenticationBackend
from tacacs_server.tacacs.constants import (
    TAC_PLUS_AUTHOR_STATUS,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.handlers import AAAHandlers
from tacacs_server.tacacs.packet import TacacsPacket


class MockAuthBackend(AuthenticationBackend):
    """Mock authentication backend for testing"""

    def __init__(self, name: str = "mock"):
        self.name = name
        self.users = {
            "admin": {
                "enabled": True,
                "groups": ["admin"],
                "privilege_level": 15,
            },
            "user": {
                "enabled": True,
                "groups": ["users"],
                "privilege_level": 1,
            },
            "disabled_user": {
                "enabled": False,
                "groups": ["users"],
                "privilege_level": 1,
            },
        }

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        return username in self.users

    def get_user_attributes(self, username: str) -> dict[str, Any]:
        return self.users.get(username, {})


@pytest.fixture
def mock_db_logger():
    """Mock database logger"""
    return MagicMock()


@pytest.fixture
def mock_user_group_service():
    """Mock user group service"""
    service = MagicMock()

    # Return different privilege levels based on group name
    def get_group_mock(group_name):
        if group_name == "admin":
            return MagicMock(privilege_level=15)
        elif group_name == "users":
            return MagicMock(privilege_level=1)
        else:
            return MagicMock(privilege_level=1)

    service.get_group.side_effect = get_group_mock
    return service


@pytest.fixture
def aaa_handlers(mock_db_logger, mock_user_group_service):
    """Create AAAHandlers instance with mock backend"""
    backend = MockAuthBackend()
    handlers = AAAHandlers([backend], mock_db_logger)
    handlers.set_local_user_group_service(mock_user_group_service)
    return handlers


def create_authorization_packet(
    username: str,
    command: str = "show version",
    service: str = "shell",
    privilege_level: int = 15,
    session_id: int = 12345,
) -> TacacsPacket:
    """Create a TACACS+ authorization packet"""
    user_bytes = username.encode("utf-8")
    port_bytes = b"console"
    rem_addr_bytes = b"127.0.0.1"

    # Build arguments
    args = []
    if service == "shell" and command:
        args.append(f"service={service}".encode())
        args.append(f"cmd={command}".encode())
    else:
        args.append(f"service={service}".encode())

    # Authorization packet body - correct TACACS+ format
    body = struct.pack(
        "!BBBBBBBB",
        6,  # authen_method: TACACSPLUS
        privilege_level,  # priv_lvl
        1,  # authen_type: ASCII
        1,  # authen_service: LOGIN
        len(user_bytes),
        len(port_bytes),
        len(rem_addr_bytes),
        len(args),
    )

    # Add user, port, rem_addr first
    body += user_bytes
    body += port_bytes
    body += rem_addr_bytes

    # Then add argument lengths
    for arg in args:
        body += struct.pack("!B", len(arg))

    # Finally add arguments
    for arg in args:
        body += arg

    return TacacsPacket(
        version=0xC0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
        seq_no=1,
        flags=0,
        session_id=session_id,
        length=len(body),
        body=body,
    )


def test_authorization_success_admin_user(aaa_handlers):
    """Test successful authorization for admin user"""
    packet = create_authorization_packet("admin", "show version")

    response = aaa_handlers.handle_authorization(packet)

    assert response.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR
    assert response.seq_no == 2

    # Parse response body
    status, arg_cnt, msg_len, data_len = struct.unpack("!BBHH", response.body[:6])
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD


def test_authorization_success_limited_user(aaa_handlers):
    """Test successful authorization for limited user with allowed command"""
    packet = create_authorization_packet("user", "show interfaces", privilege_level=1)

    response = aaa_handlers.handle_authorization(packet)

    status, _, _, _ = struct.unpack("!BBHH", response.body[:6])
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD


def test_authorization_fail_command_not_allowed(aaa_handlers):
    """Test authorization failure for command not allowed"""
    packet = create_authorization_packet(
        "user", "configure terminal", privilege_level=1
    )

    response = aaa_handlers.handle_authorization(packet)

    status, _, _, _ = struct.unpack("!BBHH", response.body[:6])
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL


def test_authorization_fail_insufficient_privilege(aaa_handlers):
    """Test authorization failure for insufficient privilege level"""
    packet = create_authorization_packet("user", "show version", privilege_level=15)

    response = aaa_handlers.handle_authorization(packet)

    status, _, _, _ = struct.unpack("!BBHH", response.body[:6])
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL


def test_authorization_fail_disabled_user(aaa_handlers):
    """Test authorization failure for disabled user"""
    packet = create_authorization_packet("disabled_user", "show version")

    response = aaa_handlers.handle_authorization(packet)

    status, _, _, _ = struct.unpack("!BBHH", response.body[:6])
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL


def test_authorization_fail_user_not_found(aaa_handlers):
    """Test authorization failure for non-existent user"""
    packet = create_authorization_packet("nonexistent", "show version")

    response = aaa_handlers.handle_authorization(packet)

    status, _, _, _ = struct.unpack("!BBHH", response.body[:6])
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL


def test_authorization_with_device_group_policy(aaa_handlers):
    """Test authorization with device group policy"""
    # Mock device with group
    device = MagicMock()
    device.group = MagicMock()
    device.group.name = "switches"
    device.group.allowed_user_groups = ["admin"]

    packet = create_authorization_packet("admin", "show version")

    response = aaa_handlers.handle_authorization(packet, device)

    status, _, _, _ = struct.unpack("!BBHH", response.body[:6])
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD


def test_authorization_fail_device_group_policy(aaa_handlers):
    """Test authorization failure due to device group policy"""
    # Mock device with restricted group
    device = MagicMock()
    device.group = MagicMock()
    device.group.name = "restricted"
    device.group.allowed_user_groups = ["operators"]  # admin not in allowed groups

    packet = create_authorization_packet("admin", "show version")

    response = aaa_handlers.handle_authorization(packet, device)

    status, _, _, _ = struct.unpack("!BBHH", response.body[:6])
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL


def test_authorization_exec_service(aaa_handlers):
    """Test authorization for exec service"""
    packet = create_authorization_packet("admin", "", service="exec")

    response = aaa_handlers.handle_authorization(packet)

    status, _, _, _ = struct.unpack("!BBHH", response.body[:6])
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD


def test_authorization_invalid_packet(aaa_handlers):
    """Test authorization with invalid packet"""
    packet = TacacsPacket(
        version=0xC0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
        seq_no=1,
        flags=0,
        session_id=12345,
        length=4,
        body=b"test",  # Too short
    )

    response = aaa_handlers.handle_authorization(packet)

    status, _, _, _ = struct.unpack("!BBHH", response.body[:6])
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_ERROR


def test_authorization_backend_exception(aaa_handlers):
    """Test authorization when backend raises exception"""
    with patch.object(
        aaa_handlers.auth_backends[0],
        "get_user_attributes",
        side_effect=Exception("Backend error"),
    ):
        packet = create_authorization_packet("admin", "show version")

        response = aaa_handlers.handle_authorization(packet)

        status, _, _, _ = struct.unpack("!BBHH", response.body[:6])
        assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL


def test_authorization_response_attributes(aaa_handlers):
    """Test that authorization response includes proper attributes"""
    packet = create_authorization_packet("admin", "show version")

    response = aaa_handlers.handle_authorization(packet)

    # Parse response to check attributes
    status, arg_cnt, msg_len, data_len = struct.unpack("!BBHH", response.body[:6])
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
    assert arg_cnt > 0  # Should have attributes

    # Parse attributes
    offset = 6
    arg_lengths = []
    for _ in range(arg_cnt):
        arg_lengths.append(response.body[offset])
        offset += 1

    # Skip server message
    offset += msg_len

    # Parse attributes
    attributes = {}
    for arg_len in arg_lengths:
        arg_str = response.body[offset : offset + arg_len].decode("utf-8")
        if "=" in arg_str:
            key, value = arg_str.split("=", 1)
            attributes[key] = value
        offset += arg_len

    # Should include privilege level
    assert "priv-lvl" in attributes
    assert attributes["priv-lvl"] == "15"


def test_authorization_high_privilege_user_bypass(aaa_handlers):
    """Test that high privilege users (15) can bypass command restrictions"""
    # Admin user has privilege 15, should be able to run any command
    packet = create_authorization_packet("admin", "configure terminal")

    response = aaa_handlers.handle_authorization(packet)

    status, _, _, _ = struct.unpack("!BBHH", response.body[:6])
    assert status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
