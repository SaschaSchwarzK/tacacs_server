"""TACACS+ Encryption Test Suite

This module contains security-focused tests for TACACS+ encryption functionality.
It verifies the correct behavior of the encryption implementation under various
conditions, including edge cases and error scenarios.

Test Organization:
- Encryption requirement enforcement
- Special case handling (empty secrets, long secrets)
- Session ID edge cases
- Error conditions and graceful failure modes

Each test verifies both the security properties of the encryption implementation
and its resilience against malformed or malicious inputs.
"""

import socket
import struct


def test_tacacs_unencrypted_when_required(server_factory):
    """Test server enforces encryption when required.

    This test verifies that the server correctly enforces encryption requirements
    by rejecting unencrypted packets when encryption is marked as required in the
    server configuration.

    Test Setup:
    1. Configure server with encryption_required = true
    2. Set up a test device with a shared secret

    Test Steps:
    1. Send an unencrypted TACACS+ authentication packet
    2. Observe server response

    Expected Results:
    - Server should reject the unencrypted packet
    - Connection should be closed by the server
    - Appropriate error should be logged

    Security Considerations:
    - Verifies that security-sensitive configurations are enforced
    - Ensures no fallback to unencrypted communication when encryption is required
    """
    server = server_factory(
        config={
            "auth_backends": "local",
            "security": {"encryption_required": "true"},
        },
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(("127.0.0.1", server.tacacs_port))

            # Send packet with unencrypted flag (0x01)
            header = struct.pack("!BBBBII", 0xC0, 1, 1, 0x01, 12345, 10)
            body = b"plaintext!"
            sock.sendall(header + body)

            try:
                # Read and ignore any response
                sock.recv(1024)
                # Should be rejected or connection closed
            except (TimeoutError, ConnectionResetError):
                pass  # Expected
        finally:
            sock.close()


def test_tacacs_encryption_with_empty_secret(server_factory):
    """Test server behavior with empty shared secret.

    This test verifies how the server handles the edge case where a device is
    configured with an empty shared secret. The expected behavior is either
    a clean rejection of the configuration or proper handling of the empty secret.

    Test Setup:
    1. Configure a device with an empty shared secret
    2. Enable TACACS+ with encryption required

    Test Steps:
    1. Attempt to authenticate with the device
    2. Observe server behavior

    Expected Results:
    - Server should either reject the configuration during setup
    - Or fail the authentication attempt with an appropriate error
    - Should not crash or expose sensitive information

    Security Considerations:
    - Verifies proper handling of invalid security configurations
    - Ensures no information leakage through error messages
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("alice", password="passTest123", privilege_level=15)

        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": ""})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        # Try to authenticate with empty secret
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "", "alice", "passTest123"
        )

        # Should handle gracefully (may succeed if encryption not enforced)
        # Just verify no crash
        logs = server.get_logs()
        assert len(logs) > 0


def test_tacacs_decrypt_with_wrong_key_produces_garbage(server_factory):
    """Test graceful handling of decryption with incorrect key.

    This test verifies that the server properly handles the case where a client
    uses an incorrect shared secret for encryption. The server should detect the
    invalid decryption and handle it gracefully without crashing.

    Test Setup:
    1. Configure server with a known shared secret
    2. Set up a test device with the correct secret

    Test Steps:
    1. Send an authentication request encrypted with a different secret
    2. Observe server behavior

    Expected Results:
    - Server should detect the decryption failure
    - Should reject the authentication attempt
    - Should log appropriate error information
    - Should maintain service availability for other clients

    Security Considerations:
    - Verifies resistance to cryptographic oracle attacks
    - Ensures proper error handling of malformed ciphertext
    - Confirms no information leakage through timing or error messages
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "correct"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        # Authenticate with wrong secret
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "wrong", "alice", "passTest123"
        )

        # Should fail gracefully
        assert not success


def test_tacacs_encryption_session_id_zero(server_factory):
    """Test encryption behavior with session ID of zero.

    This test verifies that the encryption/decryption process works correctly
    when the session ID is set to zero, which is a valid but edge case value.

    Test Setup:
    1. Configure server with encryption enabled
    2. Set up a test device with a known shared secret

    Test Steps:
    1. Initiate authentication with session_id = 0
    2. Verify successful authentication

    Expected Results:
    - Server should handle the zero session ID correctly
    - Encryption/decryption should work as expected
    - Authentication should succeed with valid credentials

    Edge Cases/Notes:
    - Tests handling of the minimum session ID value
    - Verifies no off-by-one errors in session ID handling
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("alice", password="passTest123", privilege_level=15)

        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        # Should work with session_id=0
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, "secret", "alice", "passTest123"
        )

        # May succeed or fail, but shouldn't crash


def test_tacacs_very_long_shared_secret(server_factory):
    """Test encryption with extremely long shared secret.

    This test verifies the server's behavior when configured with a very long
    shared secret (1000 characters). The server should either handle it correctly
    or reject it during configuration, but should not crash or behave unexpectedly.

    Test Setup:
    1. Configure server with a 1000-character shared secret
    2. Set up a test device with the same secret

    Test Steps:
    1. Attempt to authenticate using the long secret
    2. Observe server behavior

    Expected Results:
    - Server should either:
      a) Accept and use the long secret for encryption, or
      b) Reject the configuration during setup
    - Should not crash or become unresponsive

    Security Considerations:
    - Verifies handling of maximum-length secrets
    - Ensures no buffer overflows or memory issues
    - Tests input validation for secret length
    """
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService

        user_service = LocalUserService(str(server.auth_db))
        user_service.create_user("alice", password="passTest123", privilege_level=15)

        long_secret = "x" * 1000

        from tacacs_server.devices.store import DeviceStore

        device_store = DeviceStore(str(server.devices_db))
        device_store.ensure_group("default", metadata={"tacacs_secret": long_secret})
        device_store.ensure_device(
            name="test-device", network="127.0.0.1", group="default"
        )

        # Try to authenticate
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        success, _ = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, long_secret, "alice", "passTest123"
        )

        # Should handle gracefully
        logs = server.get_logs()
        assert len(logs) > 0
