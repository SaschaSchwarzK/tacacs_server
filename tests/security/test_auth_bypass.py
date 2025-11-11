"""
TACACS+ Authentication Bypass Security Tests

This module contains tests designed to identify potential authentication bypass
vulnerabilities in the TACACS+ server implementation. These tests focus on
malicious or malformed inputs that might circumvent the authentication process,
leading to unauthorized access.

Test Coverage:
- Malformed authentication requests (e.g., invalid packet structure, lengths)
- Exploitation of unsupported authentication types
- Session ID manipulation attempts
- Rate limiting bypass attempts (if applicable)
- Edge cases for username and password validation
"""

import socket
import struct
from unittest.mock import patch

import pytest

from tacacs_server.tacacs.constants import (
    TAC_PLUS_AUTHEN_STATUS,
    TAC_PLUS_AUTHEN_TYPE,
    TAC_PLUS_HEADER_SIZE,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.utils.exceptions import ProtocolError


# Helper function to send a raw TACACS+ packet and receive a response
def send_raw_tacacs_packet(
    host: str, port: int, secret: str, request_packet: TacacsPacket
) -> TacacsPacket | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        # Pack and encrypt the request packet
        packed_request = request_packet.pack(secret)
        sock.sendall(packed_request)

        # Receive response header
        response_header_bytes = sock.recv(TAC_PLUS_HEADER_SIZE)
        if not response_header_bytes:
            return None
        response_packet = TacacsPacket.unpack_header(response_header_bytes)

        # Receive response body
        response_body_bytes = sock.recv(response_packet.length)
        if not response_body_bytes:
            return None

        # Decrypt the response body
        response_packet.body = response_packet.decrypt_body(secret, response_body_bytes)
        return response_packet
    except (TimeoutError, ConnectionResetError, ProtocolError) as e:
        pytest.fail(f"Network or protocol error during raw packet send: {e}")
    except Exception as e:
        pytest.fail(f"Unexpected error during raw packet send: {e}")
    finally:
        sock.close()


@pytest.fixture
def tacacs_server_with_user(server_factory):
    """
    Fixture to set up a TACACS+ server with a local user for testing.
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        from tacacs_server.devices.store import DeviceStore

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user(
            "testuser", password="Testpassword1", privilege_level=1
        )

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )
        yield server


def test_auth_bypass_unsupported_authen_type(tacacs_server_with_user):
    """
    Test sending an unsupported authentication type to check for bypass.
    The server should respond with an error, not proceed with authentication.
    """
    server = tacacs_server_with_user
    host = "127.0.0.1"
    port = server.tacacs_port
    secret = "secret"

    # Craft an AUTHEN START packet with an unsupported authentication type (e.g., 0xFF)
    # This uses the structure from parse_authen_start in structures.py
    # action, priv_lvl, authen_type, service, ulen, plen, rlen, dlen
    # We'll use a dummy user/pass for the body, but the authen_type is the focus
    unsupported_authen_type = 0xFF
    user = "testuser"
    password = "Testpassword1"
    body_data = b"".join(
        [
            struct.pack(
                "!BBBBBBBB",
                1,
                1,
                unsupported_authen_type,
                1,
                len(user),
                len(password),
                0,
                0,
            ),
            user.encode("utf-8"),
            password.encode("utf-8"),
        ]
    )

    request_packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        session_id=12345,
        body=body_data,
    )

    response_packet = send_raw_tacacs_packet(host, port, secret, request_packet)

    assert response_packet is not None
    assert response_packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN
    # Expect an error status for unsupported type
    status = struct.unpack("!B", response_packet.body[0:1])[0]
    assert status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR
    server_msg_len = struct.unpack("!H", response_packet.body[2:4])[0]
    server_msg = response_packet.body[5 : 5 + server_msg_len].decode("utf-8")
    assert "Unsupported authentication type" in server_msg


def test_auth_bypass_malformed_authen_start_lengths(tacacs_server_with_user):
    """
    Test sending a malformed AUTHEN START packet where lengths in the body
    do not match the actual data provided, attempting to cause parsing errors
    or overflows.
    """
    server = tacacs_server_with_user
    host = "127.0.0.1"
    port = server.tacacs_port
    secret = "secret"

    # Craft an AUTHEN START packet with incorrect lengths
    # ulen, plen, rlen, dlen are set to values that don't match actual data
    user_data = b"testuser"
    pass_data = b"Testpassword1"
    # Set ulen to be too long, plen to be too short
    malformed_ulen = len(user_data) + 10
    malformed_plen = len(pass_data) - 5

    body_data = b"".join(
        [
            struct.pack(
                "!BBBBBBBB",
                1,
                1,
                TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
                1,
                malformed_ulen,
                malformed_plen,
                0,
                0,
            ),
            user_data,
            pass_data,
        ]
    )

    request_packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        session_id=12346,
        body=body_data,
    )

    response_packet = send_raw_tacacs_packet(host, port, secret, request_packet)

    assert response_packet is not None
    assert response_packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN
    status = struct.unpack("!B", response_packet.body[0:1])[0]
    # Expect an error status due to ProtocolError during parsing
    assert status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR
    server_msg_len = struct.unpack("!H", response_packet.body[2:4])[0]
    server_msg = response_packet.body[5 : 5 + server_msg_len].decode("utf-8")
    assert "authen_start too short" in server_msg or "ProtocolError" in server_msg


def test_auth_bypass_empty_username_pap(tacacs_server_with_user):
    """
    Test authentication with an empty username using PAP.
    Should result in authentication failure.
    """
    server = tacacs_server_with_user
    host = "127.0.0.1"
    port = server.tacacs_port
    secret = "secret"

    user = ""
    password = "Testpassword1"
    body_data = b"".join(
        [
            struct.pack(
                "!BBBBBBBB",
                1,
                1,
                TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
                1,
                len(user),
                len(password),
                0,
                0,
            ),
            user.encode("utf-8"),
            password.encode("utf-8"),
        ]
    )

    request_packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        session_id=12347,
        body=body_data,
    )

    response_packet = send_raw_tacacs_packet(host, port, secret, request_packet)

    assert response_packet is not None
    assert response_packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN
    status = struct.unpack("!B", response_packet.body[0:1])[0]
    assert status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL
    server_msg_len = struct.unpack("!H", response_packet.body[2:4])[0]
    server_msg = response_packet.body[5 : 5 + server_msg_len].decode("utf-8")
    assert "invalid username format" in server_msg


def test_auth_bypass_empty_password_pap(tacacs_server_with_user):
    """
    Test authentication with an empty password using PAP.
    Should result in authentication failure.
    """
    server = tacacs_server_with_user
    host = "127.0.0.1"
    port = server.tacacs_port
    secret = "secret"

    user = "testuser"
    password = ""
    body_data = b"".join(
        [
            struct.pack(
                "!BBBBBBBB",
                1,
                1,
                TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
                1,
                len(user),
                len(password),
                0,
                0,
            ),
            user.encode("utf-8"),
            password.encode("utf-8"),
        ]
    )

    request_packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        session_id=12348,
        body=body_data,
    )

    response_packet = send_raw_tacacs_packet(host, port, secret, request_packet)

    assert response_packet is not None
    assert response_packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN
    status = struct.unpack("!B", response_packet.body[0:1])[0]
    assert status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL
    server_msg_len = struct.unpack("!H", response_packet.body[2:4])[0]
    server_msg = response_packet.body[5 : 5 + server_msg_len].decode("utf-8")
    assert "empty password" in server_msg


def test_auth_bypass_long_password_pap(tacacs_server_with_user):
    """
    Test authentication with an excessively long password using PAP.
    Should result in authentication failure due to password length limits.
    """
    server = tacacs_server_with_user
    host = "127.0.0.1"
    port = server.tacacs_port
    secret = "secret"

    user = "testuser"
    # Create a password longer than MAX_PASSWORD_LENGTH (255 in constants.py)
    long_password = "A" * 300
    body_data = b"".join(
        [
            struct.pack(
                "!BBBBBBBB",
                1,
                1,
                TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
                1,
                len(user),
                len(long_password),
                0,
                0,
            ),
            user.encode("utf-8"),
            long_password.encode("utf-8"),
        ]
    )

    request_packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        session_id=12349,
        body=body_data,
    )

    response_packet = send_raw_tacacs_packet(host, port, secret, request_packet)

    assert response_packet is not None
    assert response_packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN
    status = struct.unpack("!B", response_packet.body[0:1])[0]
    assert status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL
    server_msg_len = struct.unpack("!H", response_packet.body[2:4])[0]
    server_msg = response_packet.body[5 : 5 + server_msg_len].decode("utf-8")
    assert "password too long" in server_msg


@patch("tacacs_server.tacacs.handlers.AuthRateLimiter.is_allowed", return_value=False)
def test_auth_bypass_rate_limit_denial(mock_is_allowed, tacacs_server_with_user):
    """
    Test that authentication is denied when the rate limiter prevents it.
    This simulates a rate limit being hit.
    """
    server = tacacs_server_with_user
    host = "127.0.0.1"
    port = server.tacacs_port
    secret = "secret"

    user = "testuser"
    password = "Testpassword1"
    body_data = b"".join(
        [
            struct.pack(
                "!BBBBBBBB",
                1,
                1,
                TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
                1,
                len(user),
                len(password),
                0,
                0,
            ),
            user.encode("utf-8"),
            password.encode("utf-8"),
        ]
    )

    request_packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        session_id=12350,
        body=body_data,
    )

    response_packet = send_raw_tacacs_packet(host, port, secret, request_packet)

    assert response_packet is not None
    assert response_packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN
    status = struct.unpack("!B", response_packet.body[0:1])[0]
    assert status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL
    server_msg_len = struct.unpack("!H", response_packet.body[2:4])[0]
    server_msg = response_packet.body[5 : 5 + server_msg_len].decode("utf-8")
    assert "rate limit exceeded" in server_msg
    mock_is_allowed.assert_called_once()


def test_auth_bypass_invalid_session_id_continue(tacacs_server_with_user):
    """
    Test sending an AUTHEN CONTINUE packet with an invalid/unknown session ID.
    Should result in an error, not a bypass.
    """
    server = tacacs_server_with_user
    host = "127.0.0.1"
    port = server.tacacs_port
    secret = "secret"

    # Craft an AUTHEN CONTINUE packet with a session ID that was never started
    user_data = b"testuser"
    password_data = b"Testpassword1"
    body_data = b"".join(
        [
            # action, priv_lvl, authen_type, service, ulen, plen, rlen, dlen
            # These fields are less relevant for CONTINUE, but still part of the structure
            struct.pack(
                "!BBBBBBBB",
                1,
                1,
                TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
                1,
                len(user_data),
                len(password_data),
                0,
                0,
            ),
            user_data,
            password_data,
        ]
    )

    request_packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=2,  # Indicate a continue packet
        session_id=99999,  # Invalid session ID
        body=body_data,
    )

    response_packet = send_raw_tacacs_packet(host, port, secret, request_packet)

    assert response_packet is not None
    assert response_packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN
    status = struct.unpack("!B", response_packet.body[0:1])[0]
    assert status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR
    server_msg_len = struct.unpack("!H", response_packet.body[2:4])[0]
    server_msg = response_packet.body[5 : 5 + server_msg_len].decode("utf-8")
    assert "Invalid session" in server_msg


def test_auth_bypass_incorrect_password_then_valid_session_id_reuse(
    tacacs_server_with_user,
):
    """
    Test an authentication bypass attempt by trying to reuse a session ID
    from a previously failed authentication attempt.
    The server should not allow authentication with a reused session ID after a failure.
    """
    server = tacacs_server_with_user
    host = "127.0.0.1"
    port = server.tacacs_port
    secret = "secret"
    session_id_to_reuse = 54321  # A unique session ID for this test

    # --- First attempt: Fail authentication with incorrect password ---
    user = "testuser"
    incorrect_password = "WrongPassword"
    body_data_fail = b"".join(
        [
            struct.pack(
                "!BBBBBBBB",
                1,
                1,
                TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
                1,
                len(user),
                len(incorrect_password),
                0,
                0,
            ),
            user.encode("utf-8"),
            incorrect_password.encode("utf-8"),
        ]
    )

    request_packet_fail = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        session_id=session_id_to_reuse,
        body=body_data_fail,
    )

    response_packet_fail = send_raw_tacacs_packet(
        host, port, secret, request_packet_fail
    )

    assert response_packet_fail is not None
    assert response_packet_fail.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN
    status_fail = struct.unpack("!B", response_packet_fail.body[0:1])[0]
    assert status_fail == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL

    # --- Second attempt: Try to authenticate with correct credentials, reusing the session ID ---
    correct_password = "Testpassword1"
    body_data_success = b"".join(
        [
            struct.pack(
                "!BBBBBBBB",
                1,
                1,
                TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
                1,
                len(user),
                len(correct_password),
                0,
                0,
            ),
            user.encode("utf-8"),
            correct_password.encode("utf-8"),
        ]
    )

    request_packet_success = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,  # New start packet, but reusing session_id
        session_id=session_id_to_reuse,
        body=body_data_success,
    )

    response_packet_success = send_raw_tacacs_packet(
        host, port, secret, request_packet_success
    )

    assert response_packet_success is not None
    assert response_packet_success.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN
    status_success = struct.unpack("!B", response_packet_success.body[0:1])[0]
    # Expect an error or fail, as the session ID should not be reusable for a new auth attempt
    # after a previous failure, or it should be treated as a new session.
    # The server should not allow a successful authentication here.
    assert status_success != TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS
    assert status_success in [
        TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR,
        TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL,
    ]
    server_msg_len = struct.unpack("!H", response_packet_success.body[2:4])[0]
    server_msg = response_packet_success.body[5 : 5 + server_msg_len].decode("utf-8")
    assert "Invalid session" in server_msg or "Authentication failed" in server_msg
