"""
TACACS+ Protocol Compliance Functional Tests

This module contains functional tests to verify the TACACS+ server's compliance
with RFC 8907 specifications. These tests focus on ensuring the server correctly
handles various protocol elements, including valid and invalid packet structures,
versioning, and other fundamental aspects of the TACACS+ protocol.

Test Coverage:
- Correct handling of TACACS+ protocol versioning.
- Graceful error handling for non-compliant packets.
"""

import socket
import struct

import pytest

from tacacs_server.tacacs.constants import (
    TAC_PLUS_AUTHEN_TYPE,
    TAC_PLUS_HEADER_SIZE,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.utils.exceptions import ProtocolError


# Helper function to send a raw TACACS+ packet and receive a response
# Copied from test_auth_bypass.py for now, consider refactoring to a shared utility
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
def tacacs_server_minimal(server_factory):
    """
    Fixture to set up a minimal TACACS+ server for protocol compliance testing.
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )
    with server:
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )
        yield server


def test_protocol_compliance_invalid_version(tacacs_server_minimal):
    """
    Test sending a TACACS+ packet with an invalid version number.
    RFC 8907 specifies version 0xC0. The server should reject packets
    with other versions.
    """
    server = tacacs_server_minimal
    host = "127.0.0.1"
    port = server.tacacs_port
    secret = "secret"

    # Craft a packet with an invalid version (e.g., 0xC1 instead of 0xC0)
    invalid_version = 0xC1
    # Minimal body for an authentication start request
    user = "testuser"
    password = "testpassword"
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
        version=invalid_version,  # Invalid version
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        session_id=12345,
        body=body_data,
    )

    # Expect the server to close the connection or send an error
    # The exact behavior might vary, but it should not proceed with authentication
    # and ideally, it should log an error.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        packed_request = request_packet.pack(secret)
        sock.sendall(packed_request)

        # Try to receive a response. If the server closes the connection,
        # recv will return an empty bytes object.
        response_header_bytes = sock.recv(TAC_PLUS_HEADER_SIZE)
        assert not response_header_bytes, (
            "Server should not respond to invalid version or close connection"
        )

    except ConnectionResetError:
        # This is an expected outcome: server closed the connection
        pass
    except TimeoutError:
        # This is also an expected outcome: server didn't respond within timeout
        pass
    except Exception as e:
        pytest.fail(f"Unexpected error during invalid version test: {e}")
    finally:
        sock.close()

    # In test_protocol_compliance.py, update the log checking part:
    logs = server.get_logs()
    print("Log content:", logs)  # Debug output

    # Check for the actual log message we're seeing
    assert any(
        "Invalid packet header" in log and "version=0xc1" in log.lower()
        for log in logs.splitlines()
    ), f"Expected invalid version in logs, got: {logs}"
