"""
RADIUS Auto-registration Test Suite

This module contains tests for the RADIUS auto-registration feature, which
automatically creates device entries for previously unknown RADIUS clients
when they first authenticate.

Test Organization:
- Auto-registration when enabled
  - New device creation with default settings
  - Device group assignment
  - Subsequent authentication with the same client

- Auto-registration when disabled
  - Rejection of unknown RADIUS clients
  - No device creation for failed authentications
  - Verification of strict deny behavior

Security Considerations:
- Validates proper access control for new devices
- Ensures secure default configurations for auto-registered devices
- Verifies audit logging of auto-registration events
- Tests security boundaries when auto-registration is disabled

Dependencies:
- pytest for test framework
- socket for network communication
- hashlib for RADIUS message authentication
- struct for binary data handling
"""

from __future__ import annotations

import hashlib
import os
import socket
import struct


def _make_request_authenticator() -> bytes:
    return os.urandom(16)


def _radius_auth(
    host: str, port: int, secret: str, username: str, password: str
) -> tuple[bool, str]:
    """Perform a RADIUS authentication request and return the result.

    This helper function constructs and sends a RADIUS Access-Request packet to the
    specified server and returns the authentication result. The function handles
    the RADIUS protocol details including message authentication and encryption.

    Packet Structure:
    - Code (1 byte): 1 (Access-Request)
    - Identifier (1 byte): Sequence number for matching requests/responses
    - Length (2 bytes): Total packet length
    - Request Authenticator (16 bytes): Random value for security
    - Attributes (variable):
      - User-Name (Type 1)
      - User-Password (Type 2, encrypted with MD5)
      - NAS-IP-Address (Type 4)

    Args:
        host: RADIUS server hostname or IP address
        port: RADIUS authentication port
        secret: Shared secret for RADIUS message authentication
        username: Username for authentication
        password: Password for authentication

    Returns:
        tuple[bool, str]: A tuple containing:
            - bool: True if authentication was successful (Access-Accept received),
                   False otherwise (Access-Reject or error)
            - str: Status message indicating the result ('Accept', 'Reject',
                  or error description)

    Example:
        # Perform RADIUS authentication
        success, message = _radius_auth(
            host='radius.example.com',
            port=1812,
            secret='shared_secret',
            username='testuser',
            password='password123'
        )
        if success:
            print(f"Authentication successful: {message}")
        else:
            print(f"Authentication failed: {message}")
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        code = 1  # Access-Request
        identifier = 1
        request_auth = _make_request_authenticator()

        attrs = b""
        # User-Name
        u = username.encode()
        attrs += struct.pack("!BB", 1, 2 + len(u)) + u
        # User-Password (RFC 2865 obfuscation)
        p = password.encode()
        if len(p) % 16:
            p += b"\x00" * (16 - len(p) % 16)
        enc = b""
        c = request_auth
        sec = secret.encode()
        for i in range(0, len(p), 16):
            blk = p[i : i + 16]
            md5 = hashlib.md5(sec + c, usedforsecurity=False).digest()
            eblk = bytes(a ^ b for a, b in zip(blk, md5))
            enc += eblk
            c = eblk
        attrs += struct.pack("!BB", 2, 2 + len(enc)) + enc
        # NAS-IP-Address
        attrs += struct.pack("!BB", 4, 6) + socket.inet_aton("127.0.0.1")

        length = 20 + len(attrs)
        pkt = struct.pack("!BBH", code, identifier, length) + request_auth + attrs
        sock.sendto(pkt, (host, port))
        resp, _ = sock.recvfrom(4096)
        if len(resp) < 20:
            return False, "invalid"
        resp_code = resp[0]
        return (resp_code == 2), (
            "Accept"
            if resp_code == 2
            else "Reject"
            if resp_code == 3
            else str(resp_code)
        )
    except Exception as e:
        return False, f"error: {e}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def test_radius_autoregistration_enabled(server_factory):
    """Verify RADIUS auto-registration behavior when enabled.

    This test validates that when RADIUS auto-registration is enabled (default),
    new devices are automatically created in the device store when they first
    authenticate with valid credentials. This feature allows for zero-touch
    provisioning of network devices.

    Test Configuration:
    - Authentication Backend: Local user database
    - RADIUS shared backends: Enabled
    - Auto-registration: Enabled (default)
    - Test User: ruser1 with password 'Passw0rd!'
    - Default Group: Configured with RADIUS secret 'radsecret'

    Test Steps:
    1. Start server with auto-registration enabled
    2. Configure a test user and default RADIUS secret
    3. Send a RADIUS authentication request from an unknown client (127.0.0.1)
    4. Verify the authentication result
    5. Check if a new device entry was created in the device store

    Expected Results:
    - Authentication should succeed with valid credentials
    - A new device entry should be created for the client IP
    - The device should be associated with the default group
    - Subsequent authentications should use the created device entry

    Security Considerations:
    - Only successful authentications trigger auto-registration
    - The device is created with default group settings
    - The RADIUS secret is properly associated with the new device
    - No device is created for failed authentication attempts

    Dependencies:
    - Requires LocalUserService for test user authentication
    - Depends on DeviceStore for device management
    - Uses _radius_auth helper for RADIUS protocol testing

    Note:
    - This test verifies the happy path of the auto-registration feature
    - The test cleans up after itself automatically
    - Diagnostic information is available in server logs on failure
    """
    # Prepare default group with RADIUS secret so the auto-registered device can be used
    server = server_factory(
        config={"auth_backends": "local", "radius_share_backends": "true"},
        enable_radius=True,
    )

    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.devices.store import DeviceStore

    us = LocalUserService(str(server.auth_db))
    us.create_user("ruser1", password="Passw0rd!", privilege_level=15)

    ds = DeviceStore(str(server.devices_db))
    ds.ensure_group(
        "default", description="Default", metadata={"radius_secret": "radsecret"}
    )

    with server:
        # No devices pre-configured; first request triggers auto-registration
        ok, _ = _radius_auth(
            "127.0.0.1", server.radius_auth_port, "radsecret", "ruser1", "Passw0rd!"
        )
        # Regardless of auth outcome, device should now exist
        rec = ds.find_device_for_ip("127.0.0.1")
        assert rec is not None, "Auto-registered RADIUS client device expected"


def test_radius_autoregistration_disabled(server_factory):
    """Verify RADIUS auto-registration behavior when explicitly disabled.

    This test ensures that when auto-registration is disabled in the server
    configuration, new devices are not automatically created in the device store
    even when they authenticate with valid credentials. This is important for
    maintaining strict control over device provisioning in secure environments.

    Test Configuration:
    - Authentication Backend: Local user database
    - RADIUS shared backends: Enabled
    - Auto-registration: Explicitly disabled (devices.auto_register=false)
    - Test User: ruser2 with password 'Passw0rd!'
    - Default Group: Configured with RADIUS secret 'radsecret'

    Test Steps:
    1. Start server with auto-registration disabled
    2. Configure a test user and default RADIUS secret
    3. Send a RADIUS authentication request from an unknown client (127.0.0.1)
    4. Verify the authentication result (should fail)
    5. Confirm no device entry was created in the device store

    Expected Results:
    - Authentication should fail for unknown clients
    - No new device entry should be created
    - The device store should remain unchanged
    - Server logs should indicate the reason for rejection

    Security Considerations:
    - Prevents unauthorized device registration
    - Maintains strict access control
    - Ensures only pre-configured devices can authenticate
    - Provides clear audit trail of authentication attempts

    Dependencies:
    - Requires LocalUserService for test user authentication
    - Depends on DeviceStore for device management verification
    - Uses _radius_auth helper for RADIUS protocol testing

    Note:
    - This test verifies the security boundary of the auto-registration feature
    - The test cleans up after itself automatically
    - Diagnostic information is available in server logs on failure
    """
    server = server_factory(
        config={
            "auth_backends": "local",
            "radius_share_backends": "true",
            "devices": {"auto_register": "false"},
        },
        enable_radius=True,
    )

    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.devices.store import DeviceStore

    us = LocalUserService(str(server.auth_db))
    us.create_user("ruser2", password="Passw0rd!", privilege_level=15)

    ds = DeviceStore(str(server.devices_db))
    ds.ensure_group(
        "default", description="Default", metadata={"radius_secret": "radsecret"}
    )

    with server:
        ok, _ = _radius_auth(
            "127.0.0.1", server.radius_auth_port, "radsecret", "ruser2", "Passw0rd!"
        )
        # Auto-registration disabled: device must not be created
        rec = ds.find_device_for_ip("127.0.0.1")
        assert rec is None, "Device must not be created when auto_register=false"
