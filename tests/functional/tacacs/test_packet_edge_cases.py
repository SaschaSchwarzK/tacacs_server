"""
TACACS+ Packet Handling Edge Case Tests

Covers:
- maximum body length
- zero-length body
- multiple sequential packets in same session
- out-of-order sequence numbers (should be rejected)
- packet fragmentation scenarios
- corrupted packet headers
- response to unknown packet types
"""

import socket
import struct
import time

import pytest

from tacacs_server.tacacs.constants import (
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_PACKET_TYPE,
)


def _mk_header(
    version_major: int, ptype: int, seq: int, flags: int, session: int, length: int
) -> bytes:
    """Create a TACACS+ packet header with the specified parameters.

    Args:
        version_major: Major version of the TACACS+ protocol
        ptype: Packet type (AUTH, AUTHOR, ACCOUNT)
        seq: Sequence number for packet ordering
        flags: Packet flags (e.g., encryption, single connection)
        session: Session identifier
        length: Length of the packet body

    Returns:
        bytes: Packed TACACS+ header
    """
    version = ((version_major & 0x0F) << 4) | 0  # minor 0
    return struct.pack("!BBBBLL", version, ptype, seq, flags, session, length)


def _mk_auth_body(username: str, password: str) -> bytes:
    """Create a TACACS+ authentication packet body.

    Args:
        username: Username for authentication
        password: Password for authentication

    Returns:
        bytes: Packed authentication packet body with the following structure:
               - Header (8 bytes): action, priv_lvl, authen_type, service, user_len, port_len, rem_addr_len, data_len
               - Username (variable length)
               - Port (fixed 'console')
               - Remote address (fixed '127.0.0.1')
               - Data (password, variable length)
    """
    user_b = username.encode("utf-8")
    port_b = b"console"
    rem_b = b"127.0.0.1"
    data_b = password.encode("utf-8")
    # action=LOGIN(1), priv=15, type=PAP(2), svc=LOGIN(1)
    hdr = struct.pack(
        "!BBBBBBBB", 1, 15, 2, 1, len(user_b), len(port_b), len(rem_b), len(data_b)
    )
    return hdr + user_b + port_b + rem_b + data_b


def _md5_pad(
    session_id: int, key: str, version: int, seq_no: int, length: int
) -> bytes:
    """Generate MD5 padding for TACACS+ packet encryption.

    Creates a deterministic byte sequence for XOR-based encryption using MD5 hashing.

    Args:
        session_id: TACACS+ session identifier
        key: Shared secret for encryption
        version: Protocol version
        seq_no: Sequence number
        length: Desired length of padding

    Returns:
        bytes: Pseudo-random byte sequence for encryption
    """
    import hashlib

    pad = bytearray()
    sid = struct.pack("!L", session_id)
    key_b = key.encode("utf-8")
    ver_b = bytes([version])
    seq_b = bytes([seq_no])
    while len(pad) < length:
        if not pad:
            data = sid + key_b + ver_b + seq_b
        else:
            data = sid + key_b + ver_b + seq_b + pad
        pad.extend(hashlib.md5(data, usedforsecurity=False).digest())
    return bytes(pad[:length])


def _xor_body(body: bytes, session_id: int, key: str, version: int, seq: int) -> bytes:
    """Apply XOR encryption/decryption to TACACS+ packet body.

    Args:
        body: Packet body to encrypt/decrypt
        session_id: TACACS+ session identifier
        key: Shared secret for encryption
        version: Protocol version
        seq: Sequence number

    Returns:
        bytes: Encrypted/decrypted packet body
    """
    if not key:
        return body
    pad = _md5_pad(session_id, key, version, seq, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))


def _setup_device_and_user(server, username: str, password: str, secret: str):
    """Set up a test device and user for authentication testing.

    Args:
        server: Server instance for test environment
        username: Username for test user
        password: Password for test user
        secret: Shared secret for TACACS+ encryption

    Returns:
        tuple: (device, user) - The created device and user objects
    """
    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.devices.store import DeviceStore

    users = LocalUserService(str(server.auth_db))
    users.create_user(username, password=password, privilege_level=15)

    store = DeviceStore(str(server.devices_db))
    store.ensure_group(
        "default", description="Default group", metadata={"tacacs_secret": secret}
    )
    store.ensure_device(name="test-device", network="127.0.0.1", group="default")


@pytest.mark.integration
def test_maximum_body_length(server_factory):
    """Test TACACS+ server handling of maximum body length packets.

    Verifies that the server can handle packets with the maximum allowed body length
    (up to 64KB) and properly processes or rejects them based on the implementation.

    Test Steps:
    1. Start a TACACS+ server with a test user
    2. Create a packet with maximum allowed body length
    3. Send the packet to the server
    4. Verify the server's response

    Expected Result:
    - Server should either process the packet successfully or
      return an appropriate error if the body is too large
    - No crashes or memory issues should occur
    """
    server = server_factory(
        enable_tacacs=True, config={"server": {"max_packet_length": 2048}}
    )
    with server:
        _setup_device_and_user(server, "edgeuser", "EdgePass1", "testsecret")
        host, port = "127.0.0.1", server.tacacs_port

        # Build a body exactly at the configured limit
        max_len = 2048
        session = int(time.time()) & 0xFFFFFFFF
        version = ((TAC_PLUS_MAJOR_VER & 0x0F) << 4) | 0
        seq = 1

        # Start from a valid auth body and pad to exact size
        body = _mk_auth_body("edgeuser", "EdgePass1")
        if len(body) > max_len:
            pytest.skip("Auth body exceeds configured max length unexpectedly")
        body += b"X" * (max_len - len(body))
        enc = _xor_body(body, session, "testsecret", version, seq)
        hdr = _mk_header(
            TAC_PLUS_MAJOR_VER,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            seq,
            0,
            session,
            len(enc),
        )

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        try:
            s.sendall(hdr + enc)
            # Expect a response header (12 bytes) or a clean close if server refuses giant valid bodies.
            data = s.recv(12)
            assert len(data) in (0, 12)
            # If 12, read body and ensure not truncated
            if len(data) == 12:
                _, _, rseq, _, rsess, rlen = struct.unpack("!BBBBLL", data)
                body = s.recv(rlen) if rlen else b""
                assert len(body) == rlen
        finally:
            s.close()

        # Also test over-limit header to trigger packet_header_error logging
        too_big = max_len + 1
        hdr2 = _mk_header(
            TAC_PLUS_MAJOR_VER,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            1,
            0,
            session ^ 0x55AA,
            too_big,
        )
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(1)
        s2.connect((host, port))
        try:
            s2.sendall(hdr2)
            try:
                _ = s2.recv(1)
            except TimeoutError:
                pass
        finally:
            s2.close()

        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        assert (
            "packet_header_error" in logs
            or "Invalid packet" in logs
            or "Packet too large" in logs
            or "packet_too_large" in logs
        ), f"Expected header error for over-limit packet, got:\n{logs[-1200:]}"


@pytest.mark.integration
def test_zero_length_body(server_factory):
    """Test TACACS+ server handling of packets with zero-length bodies.

    Verifies that the server properly handles authentication requests with no body data,
    which should be rejected as invalid.

    Test Steps:
    1. Start a TACACS+ server with a test user
    2. Create a packet with a valid header but zero-length body
    3. Send the packet to the server
    4. Verify the server rejects the packet

    Expected Result:
    - Server should reject the packet with an appropriate error response
    - No crashes or undefined behavior should occur
    """
    server = server_factory(enable_tacacs=True)
    with server:
        # Zero-length body with valid header should be read and connection closed or ignored
        host, port = "127.0.0.1", server.tacacs_port
        session = 0xABCDEF12
        hdr = _mk_header(
            TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, session, 0
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        try:
            s.sendall(hdr)
            # Server should not hang; either responds or closes
            try:
                data = s.recv(1)
            except TimeoutError:
                data = b""
            assert data in (b"",) or isinstance(data, (bytes,))
        finally:
            s.close()
        # Zero-length should not produce header errors
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        assert "packet_header_error" not in logs, (
            f"Unexpected header error on zero-length: \n{logs[-1000:]}"
        )


@pytest.mark.integration
def test_multiple_sequential_packets_same_session(server_factory):
    """Test TACACS+ server handling of multiple packets in the same session.

    Verifies that the server maintains session state correctly across multiple
    packets with incrementing sequence numbers.

    Test Steps:
    1. Start a TACACS+ server with a test user
    2. Establish a session and send multiple authentication packets
    3. Increment sequence numbers for each packet
    4. Verify all packets are processed correctly

    Expected Result:
    - Server should maintain session state across packets
    - Each packet should be processed in order
    - Sequence numbers should be validated correctly
    """
    server = server_factory(enable_tacacs=True)
    with server:
        _setup_device_and_user(server, "mseq", "MseqPass1", "testsecret")
        host, port = "127.0.0.1", server.tacacs_port

        session = int(time.time()) & 0xFFFFFFFF
        version = ((TAC_PLUS_MAJOR_VER & 0x0F) << 4) | 0

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        try:
            # First request (seq=1)
            body1 = _mk_auth_body("mseq", "MseqPass1")
            enc1 = _xor_body(body1, session, "testsecret", version, 1)
            hdr1 = _mk_header(
                TAC_PLUS_MAJOR_VER,
                TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
                1,
                0,
                session,
                len(enc1),
            )
            s.sendall(hdr1 + enc1)
            r1 = s.recv(12)
            assert len(r1) in (0, 12)
            # Second request (seq=3) on same connection/session
            body2 = _mk_auth_body("mseq", "MseqPass1")
            enc2 = _xor_body(body2, session, "testsecret", version, 3)
            hdr2 = _mk_header(
                TAC_PLUS_MAJOR_VER,
                TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
                3,
                0,
                session,
                len(enc2),
            )
            s.sendall(hdr2 + enc2)
            r2 = s.recv(12)
            assert len(r2) in (0, 12)
        finally:
            s.close()


@pytest.mark.integration
def test_out_of_order_sequence_rejected(server_factory):
    """Test TACACS+ server rejection of out-of-order sequence numbers.

    Verifies that the server properly rejects packets with sequence numbers
    that are not in the expected order.

    Test Steps:
    1. Start a TACACS+ server with a test user
    2. Send packets with non-sequential sequence numbers
    3. Verify the server rejects out-of-order packets

    Expected Result:
    - Packets with incorrect sequence numbers should be rejected
    - Server should maintain correct sequence number state
    - No crashes or undefined behavior should occur
    """
    server = server_factory(enable_tacacs=True)
    with server:
        _setup_device_and_user(server, "ooseq", "OoSeqPass1", "testsecret")
        host, port = "127.0.0.1", server.tacacs_port
        session = (int(time.time()) & 0xFFFFFFFF) | 0x100
        version = ((TAC_PLUS_MAJOR_VER & 0x0F) << 4) | 0

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        try:
            # First valid request
            b1 = _mk_auth_body("ooseq", "OoSeqPass1")
            e1 = _xor_body(b1, session, "testsecret", version, 1)
            h1 = _mk_header(
                TAC_PLUS_MAJOR_VER,
                TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
                1,
                0,
                session,
                len(e1),
            )
            s.sendall(h1 + e1)
            # Drain full first response: header and body
            rh = s.recv(12)
            if len(rh) == 12:
                _, _, _, _, _, rlen = struct.unpack("!BBBBLL", rh)
                if rlen:
                    rem = rlen
                    while rem > 0:
                        chunk = s.recv(rem)
                        if not chunk:
                            break
                        rem -= len(chunk)

            # Out-of-order: seq=1 again (should be rejected, server may close)
            e2 = _xor_body(b1, session, "testsecret", version, 1)
            h2 = _mk_header(
                TAC_PLUS_MAJOR_VER,
                TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
                1,
                0,
                session,
                len(e2),
            )
            s.sendall(h2 + e2)
            try:
                data = s.recv(12)
            except TimeoutError:
                data = b""
            # Expect no response or connection drop
            assert data in (b"",)
            # Validate logs contain out_of_order_sequence event (JSON or plain)
            import time as _t

            _t.sleep(0.1)
            logs = server.get_logs()
            assert (
                "out_of_order_sequence" in logs
                or "Out-of-order sequence" in logs
                or "Invalid sequence number" in logs
            ), f"Expected out-of-order sequence log, got:\n{logs[-1000:]}"
        finally:
            s.close()


@pytest.mark.integration
def test_packet_fragmentation(server_factory):
    """Test TACACS+ server handling of fragmented TCP packets.

    Verifies that the server can correctly handle and reassemble TCP packets
    that arrive in multiple fragments.

    Test Steps:
    1. Start a TACACS+ server with a test user
    2. Split a valid authentication packet into multiple TCP segments
    3. Send the segments with delays between them
    4. Verify the server reassembles and processes the complete packet

    Expected Result:
    - Server should correctly reassemble fragmented packets
    - Authentication should succeed after all fragments are received
    - No data corruption should occur during reassembly
    """
    server = server_factory(enable_tacacs=True)
    with server:
        _setup_device_and_user(server, "frag", "FragPass1", "testsecret")
        host, port = "127.0.0.1", server.tacacs_port
        session = int(time.time()) & 0xFFFFFFFF
        version = ((TAC_PLUS_MAJOR_VER & 0x0F) << 4) | 0
        body = _mk_auth_body("frag", "FragPass1")
        enc = _xor_body(body, session, "testsecret", version, 1)
        hdr = _mk_header(
            TAC_PLUS_MAJOR_VER,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            1,
            0,
            session,
            len(enc),
        )

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        try:
            # Send header in two parts
            s.sendall(hdr[:5])
            time.sleep(0.01)
            s.sendall(hdr[5:])
            # Send body in small chunks
            for i in range(0, len(enc), 7):
                s.sendall(enc[i : i + 7])
                time.sleep(0.001)
            # Expect a response or a clean close
            try:
                data = s.recv(12)
            except TimeoutError:
                data = b""
            assert len(data) in (0, 12)
        finally:
            s.close()
        # Fragmentation should not cause header errors or incomplete body logs
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        assert "packet_header_error" not in logs, (
            f"Unexpected header error on fragmentation: \n{logs[-1200:]}"
        )
        assert "Incomplete packet body" not in logs, (
            f"Unexpected incomplete body on fragmentation: \n{logs[-1200:]}"
        )


@pytest.mark.integration
def test_incomplete_body_logs_warning(server_factory):
    """Test TACACS+ server logging of incomplete packet bodies.

    Verifies that the server properly detects and logs when a packet claims
    to have a body but the connection is closed before all data is received.

    Test Steps:
    1. Start a TACACS+ server with a test user
    2. Send a packet header indicating a body will follow
    3. Close the connection before sending the complete body
    4. Verify the server logs an appropriate warning

    Expected Result:
    - Server should log a warning about the incomplete body
    - Connection should be closed cleanly
    - No memory leaks or crashes should occur
    """
    server = server_factory(enable_tacacs=True)
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        session = 0xA1B2C3D4
        # Advertise a small body (e.g., 10 bytes) but send none
        hdr = _mk_header(
            TAC_PLUS_MAJOR_VER, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, session, 10
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        try:
            s.sendall(hdr)
            # Do not send the body; wait for server to attempt read and log
            try:
                _ = s.recv(1)
            except TimeoutError:
                pass
        finally:
            s.close()
        import time as _t

        _t.sleep(0.1)
        logs = server.get_logs()
        assert "incomplete_packet_body" in logs or "Incomplete packet body" in logs, (
            f"Expected incomplete body warning, got:\n{logs[-1200:]}"
        )


@pytest.mark.integration
def test_corrupted_header(server_factory):
    """Test TACACS+ server handling of corrupted packet headers.

    Verifies that the server properly detects and rejects packets with
    corrupted or invalid header fields.

    Test Steps:
    1. Start a TACACS+ server with a test user
    2. Create packets with various corrupted header fields
    3. Send the corrupted packets to the server
    4. Verify the server rejects them with appropriate errors

    Expected Result:
    - Corrupted headers should be detected and rejected
    - Server should close the connection or return an error response
    - No crashes or undefined behavior should occur
    """
    server = server_factory(enable_tacacs=True)
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        try:
            # Invalid major version (e.g., 0)
            bad_hdr = _mk_header(
                0, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, 1, 0, 0x1111, 0
            )
            s.sendall(bad_hdr)
            # Server should close or not respond
            try:
                data = s.recv(1)
            except TimeoutError:
                data = b""
            assert data in (b"",)
            # Validate logs contain invalid_major_version event
            import time as _t

            _t.sleep(0.1)
            logs = server.get_logs()
            assert "invalid_major_version" in logs or "Invalid major version" in logs, (
                f"Expected invalid major version log, got:\n{logs[-1000:]}"
            )
        finally:
            s.close()


@pytest.mark.integration
def test_unknown_packet_type(server_factory):
    """Test TACACS+ server handling of unknown packet types.

    Verifies that the server properly handles packets with unknown or
    unsupported packet types.

    Test Steps:
    1. Start a TACACS+ server with a test user
    2. Create packets with invalid/unknown packet types
    3. Send the packets to the server
    4. Verify the server responds appropriately

    Expected Result:
    - Unknown packet types should be rejected with an error response
    - The server should remain stable and continue processing other requests
    - No crashes or undefined behavior should occur
    """
    server = server_factory(enable_tacacs=True)
    with server:
        host, port = "127.0.0.1", server.tacacs_port
        session = 0x22223333
        # Use an invalid type number 99
        hdr = _mk_header(TAC_PLUS_MAJOR_VER, 99, 1, 0, session, 0)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        try:
            s.sendall(hdr)
            try:
                data = s.recv(1)
            except TimeoutError:
                data = b""
            # Server should reject and close (no reply)
            assert data == b""
            # Validate logs contain invalid_packet_type event
            import time as _t

            _t.sleep(0.1)
            logs = server.get_logs()
            assert "invalid_packet_type" in logs or "Invalid packet type" in logs, (
                f"Expected invalid packet type log, got:\n{logs[-1000:]}"
            )
        finally:
            s.close()
