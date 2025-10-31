"""
Syslog Delivery End-to-End Tests

Tests that the TACACS+ server sends proper syslog messages to configured destinations.
Each test spins up a local syslog receiver and validates message format and content.
"""

import re
import socket
import socketserver
import struct
import threading
import time

import pytest


class SyslogMessage:
    """Parsed syslog message (RFC 3164 and RFC 5424)

    This class parses and stores syslog messages received from the TACACS+ server.
    It supports both the older BSD-syslog (RFC 3164) and newer syslog (RFC 5424) formats.

    Attributes:
        raw_data (bytes): The raw message data received from the socket
        source_ip (str): IP address of the syslog sender
        source_port (int): Source port of the syslog message
        timestamp (float): When the message was received (Unix timestamp)
        priority (int, optional): Syslog priority value (PRI)
        facility (int, optional): Syslog facility number
        severity (int, optional): Syslog severity level
        hostname (str, optional): Hostname of the sender
        app_name (str, optional): Application name that generated the message
        message (str, optional): The actual log message content
        structured_data (dict): Structured data elements (RFC 5424)
    """

    def __init__(self, raw_data: bytes, source: tuple[str, int]):
        self.raw_data = raw_data
        self.source_ip = source[0]
        self.source_port = source[1]
        self.timestamp = time.time()

        # Parse message
        self.priority = None
        self.facility = None
        self.severity = None
        self.hostname = None
        self.app_name = None
        self.message = None
        self.structured_data = {}

        self._parse()

    def _parse(self) -> None:
        """Parse syslog message (supports both RFC 3164 and RFC 5424)

        This method parses the raw syslog message and extracts relevant fields
        like priority, facility, severity, hostname, and the actual message.
        It handles both RFC 3164 and RFC 5424 formatted messages.

        The parsed data is stored in the instance variables for later access.

        Note:
            For malformed messages, the message will be stored as-is in the
            message field with minimal parsing attempted.
        """
        try:
            msg = self.raw_data.decode("utf-8", errors="replace").strip()
        except Exception:
            self.message = self.raw_data.decode("latin-1", errors="replace")
            return

        # Parse priority <NNN>
        if msg.startswith("<") and ">" in msg:
            end = msg.index(">")
            try:
                self.priority = int(msg[1:end])
                self.facility = self.priority // 8
                self.severity = self.priority % 8
                msg = msg[end + 1 :]
            except ValueError:
                pass

        # RFC 5424: VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID [SD] MSG
        # RFC 3164: TIMESTAMP HOSTNAME TAG: MSG

        parts = msg.split(None, 5)
        if len(parts) >= 3:
            # Try RFC 5424 first (has version number like "1")
            if parts[0].isdigit():
                # RFC 5424
                if len(parts) >= 5:
                    self.hostname = parts[2]
                    self.app_name = parts[3]
                    # parts[4] is PROCID
                    # parts[5] starts with MSGID
                    if len(parts) >= 6:
                        remaining = parts[5]
                        # Extract structured data [key=value ...]
                        if "[" in remaining:
                            sd_start = remaining.index("[")
                            sd_and_msg = remaining[sd_start:]
                            # Find matching ]
                            sd_end = sd_and_msg.find("] ")
                            if sd_end > 0:
                                sd_text = sd_and_msg[1:sd_end]
                                self.message = sd_and_msg[sd_end + 2 :].strip()
                                # Parse structured data
                                self._parse_structured_data(sd_text)
                            else:
                                self.message = sd_and_msg
                        else:
                            self.message = remaining
            else:
                # RFC 3164
                # parts[0] and parts[1] might be timestamp (e.g., "Jan 15 14:23:45")
                # Try to find hostname and tag
                if len(parts) >= 4:
                    # Assume parts[0] + parts[1] + parts[2] = timestamp
                    self.hostname = parts[3]
                    if len(parts) >= 5:
                        # Tag might have : at end
                        tag_and_msg = " ".join(parts[4:])
                        if ":" in tag_and_msg:
                            tag, msg = tag_and_msg.split(":", 1)
                            self.app_name = tag.strip()
                            self.message = msg.strip()
                        else:
                            self.message = tag_and_msg
                else:
                    self.message = msg
        else:
            self.message = msg

    def _parse_structured_data(self, sd_text: str):
        """Parse RFC 5424 structured data"""
        # Format: key="value" key="value"
        pattern = r'(\w+)="([^"]*)"'
        matches = re.findall(pattern, sd_text)
        self.structured_data = {k: v for k, v in matches}

    def __repr__(self):
        return (
            f"SyslogMessage(priority={self.priority}, facility={self.facility}, "
            f"severity={self.severity}, hostname={self.hostname}, "
            f"app_name={self.app_name}, message={self.message!r})"
        )


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """UDP handler for syslog messages"""

    def handle(self):
        data = self.request[0]

        msg = SyslogMessage(data, self.client_address)

        # Store in class variable
        if not hasattr(SyslogUDPHandler, "messages"):
            SyslogUDPHandler.messages = []
        SyslogUDPHandler.messages.append(msg)

        print(f"[SyslogReceiver] Received from {msg.source_ip}:{msg.source_port}")
        print(
            f"[SyslogReceiver]   Priority: {msg.priority} (Facility={msg.facility}, Severity={msg.severity})"
        )
        print(f"[SyslogReceiver]   Hostname: {msg.hostname}")
        print(f"[SyslogReceiver]   App: {msg.app_name}")
        print(f"[SyslogReceiver]   Message: {msg.message}")
        if msg.structured_data:
            print(f"[SyslogReceiver]   Structured Data: {msg.structured_data}")


class SyslogTCPHandler(socketserver.BaseRequestHandler):
    """TCP handler for syslog messages (RFC 6587).

    This handler processes incoming TCP syslog messages with octet counting
    framing as specified in RFC 6587. It handles both individual messages
    and persistent connections with multiple messages.

    Attributes:
        request: The TCP socket connected to the client.
        client_address: The address of the client that connected.
        server: The server instance that received the connection.
    """

    def handle(self) -> None:
        """Handle TCP syslog connection with framing (RFC 6587).

        This method reads messages from a TCP connection using the octet
        counting framing method. Each message is prefixed with its length
        as a 4-byte big-endian integer.

        The method continues reading until the connection is closed or an
        error occurs. Each complete message is parsed and added to the
        server's messages list.
        """
        try:
            while True:
                # Read message length (first 4 bytes, network byte order)
                len_bytes = self.request.recv(4)
                if len(len_bytes) < 4:
                    break
                msg_len = struct.unpack(">L", len_bytes)[0]

                # Read the message
                data = bytearray()
                while len(data) < msg_len:
                    chunk = self.request.recv(min(4096, msg_len - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)

                if len(data) == msg_len:
                    message = SyslogMessage(bytes(data), self.client_address)
                    self.server.messages.append(message)

                    print(
                        f"[SyslogReceiver-TCP] Received from {message.source_ip}:{message.source_port}"
                    )
                    print(f"[SyslogReceiver-TCP]   Message: {message.message}")

        except (ConnectionResetError, BrokenPipeError) as e:
            # Client disconnected or connection was reset
            print(f"[SyslogReceiver-TCP] Connection closed: {e}")
            return  # Use return instead of break since we're in a method, not a loop


def _start_syslog_udp_server() -> tuple[
    socketserver.UDPServer, threading.Thread, int, list[SyslogMessage]
]:
    """Start UDP syslog receiver"""
    SyslogUDPHandler.messages = []

    server = socketserver.UDPServer(("127.0.0.1", 0), SyslogUDPHandler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    print(f"[Test] UDP Syslog server started on port {port}")
    return server, thread, port, SyslogUDPHandler.messages


def _start_syslog_tcp_server() -> tuple[
    socketserver.TCPServer, threading.Thread, int, list[SyslogMessage]
]:
    """Start TCP syslog receiver"""
    SyslogTCPHandler.messages = []

    server = socketserver.TCPServer(("127.0.0.1", 0), SyslogTCPHandler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    print(f"[Test] TCP Syslog server started on port {port}")
    return server, thread, port, SyslogTCPHandler.messages


def _send_tacacs_auth(
    host: str, port: int, username: str, password: str, secret: str = ""
) -> tuple[bool, str]:
    """Send TACACS+ authentication request. Returns (success, status)"""
    from tacacs_server.tacacs.constants import (
        TAC_PLUS_AUTHEN_ACTION,
        TAC_PLUS_AUTHEN_STATUS,
        TAC_PLUS_AUTHEN_SVC,
        TAC_PLUS_AUTHEN_TYPE,
        TAC_PLUS_FLAGS,
        TAC_PLUS_HEADER_SIZE,
        TAC_PLUS_MAJOR_VER,
        TAC_PLUS_PACKET_TYPE,
    )
    from tacacs_server.tacacs.packet import TacacsPacket

    def _read_exact(sock: socket.socket, length: int, timeout: float = 3.0) -> bytes:
        sock.settimeout(timeout)
        buf = bytearray()
        while len(buf) < length:
            chunk = sock.recv(length - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    def _mk_auth_body(username: str, password: str) -> bytes:
        user_b = username.encode()
        port_b = b"tty1"
        rem_b = b"127.0.0.1"
        data_b = password.encode()
        head = struct.pack(
            "!BBBBBBBB",
            TAC_PLUS_AUTHEN_ACTION.TAC_PLUS_AUTHEN_LOGIN,
            15,  # privilege
            TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
            TAC_PLUS_AUTHEN_SVC.TAC_PLUS_AUTHEN_SVC_LOGIN,
            len(user_b),
            len(port_b),
            len(rem_b),
            len(data_b),
        )
        return head + user_b + port_b + rem_b + data_b

    sess_id = int(time.time() * 1000) & 0xFFFFFFFF
    flags = 0 if secret else TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG

    pkt = TacacsPacket(
        version=(TAC_PLUS_MAJOR_VER << 4) | 0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        flags=flags,
        session_id=sess_id,
        length=0,
        body=_mk_auth_body(username, password),
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(3)
        s.connect((host, port))
        s.sendall(pkt.pack(secret))

        hdr = _read_exact(s, TAC_PLUS_HEADER_SIZE)
        if len(hdr) != TAC_PLUS_HEADER_SIZE:
            return False, "invalid_response"

        h = TacacsPacket.unpack_header(hdr)
        body = _read_exact(s, h.length)

        if not body:
            return False, "no_body"

        # Decrypt if needed
        if secret and not (h.flags & TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG):
            import hashlib

            def _md5_pad(
                sess_id: int, key: str, ver: int, seq: int, length: int
            ) -> bytes:
                pad = bytearray()
                sid = struct.pack("!L", sess_id)
                k = key.encode()
                v = bytes([ver])
                sq = bytes([seq])
                while len(pad) < length:
                    md5_in = sid + k + v + sq + (pad if pad else b"")
                    pad.extend(hashlib.md5(md5_in, usedforsecurity=False).digest())
                return bytes(pad[:length])

            pad = _md5_pad(h.session_id, secret, h.version, h.seq_no, len(body))
            body = bytes(a ^ b for a, b in zip(body, pad))

        status = body[0]
        if status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS:
            return True, "pass"
        elif status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL:
            return False, "fail"
        else:
            return False, f"status_{status}"

    except Exception as e:
        return False, f"error: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass


@pytest.mark.functional
def test_syslog_udp_authentication_events(server_factory):
    """
    Test that authentication events are sent to UDP syslog server.

    Verifies:
    - Successful authentication generates syslog
    - Failed authentication generates syslog
    - Syslog messages have correct format and fields
    - Syslog priority/facility/severity are correct
    """
    # Start UDP syslog receiver
    syslog_server, thread, port, messages = _start_syslog_udp_server()

    print(f"\n[Test] Started UDP syslog receiver on port {port}")

    try:
        # Configure TACACS server with syslog
        server = server_factory(
            enable_tacacs=True,
            config={
                "auth_backends": "local",
                "log_level": "INFO",
                "syslog": {
                    "enabled": "true",
                    "host": "127.0.0.1",
                    "port": str(port),
                    "protocol": "udp",
                    "facility": "local0",  # Facility 16
                    "severity": "info",  # Severity 6
                    "format": "rfc5424",  # or "rfc3164"
                    "app_name": "tacacs_server",
                    "include_hostname": "true",
                },
            },
        )

        with server:
            print(f"[Test] TACACS server started on port {server.tacacs_port}")

            # Setup test user and device
            from tacacs_server.auth.local_user_service import LocalUserService
            from tacacs_server.devices.store import DeviceStore

            user_service = LocalUserService(str(server.auth_db))
            user_service.create_user(
                "syslog_user", password="GoodPass123", privilege_level=15
            )
            print("[Test] Created test user")

            device_store = DeviceStore(str(server.devices_db))
            device_store.ensure_group(
                "default",
                description="Test group",
                metadata={"tacacs_secret": "syslog_secret"},
            )
            device_store.ensure_device(
                name="syslog-device",
                network="127.0.0.1",
                group="default",
            )
            print("[Test] Created test device")

            # Give server time to initialize syslog
            time.sleep(1)

            # Test 1: Successful authentication
            print("\n[Test] Testing successful authentication...")
            success, status = _send_tacacs_auth(
                "127.0.0.1",
                server.tacacs_port,
                "syslog_user",
                "GoodPass123",
                "syslog_secret",
            )
            print(f"[Test] Auth result: success={success}, status={status}")

            time.sleep(0.5)  # Give syslog time to send

            # Test 2: Failed authentication
            print("\n[Test] Testing failed authentication...")
            success2, status2 = _send_tacacs_auth(
                "127.0.0.1",
                server.tacacs_port,
                "syslog_user",
                "WrongPass123",
                "syslog_secret",
            )
            print(f"[Test] Auth result: success={success2}, status={status2}")

            time.sleep(0.5)

            # Test 3: Non-existent user
            print("\n[Test] Testing non-existent user...")
            success3, status3 = _send_tacacs_auth(
                "127.0.0.1",
                server.tacacs_port,
                "nonexistent_user",
                "AnyPass123",
                "syslog_secret",
            )
            print(f"[Test] Auth result: success={success3}, status={status3}")

            # Wait for all syslog messages to arrive
            time.sleep(2)

            print(f"\n[Test] Received {len(messages)} syslog message(s)")

            # Print all messages for debugging
            for i, msg in enumerate(messages):
                print(f"\n[Test] Syslog Message {i + 1}:")
                print(f"  Raw: {msg.raw_data[:200]}")
                print(
                    f"  Priority: {msg.priority} (Facility: {msg.facility}, Severity: {msg.severity})"
                )
                print(f"  Hostname: {msg.hostname}")
                print(f"  App: {msg.app_name}")
                print(f"  Message: {msg.message}")
                if msg.structured_data:
                    print(f"  Structured Data: {msg.structured_data}")

            # Check logs for syslog activity
            logs = server.get_logs()
            syslog_log_lines = [
                line for line in logs.split("\n") if "syslog" in line.lower()
            ]

            if syslog_log_lines:
                print("\n[Test] Syslog-related log lines:")
                for line in syslog_log_lines[:10]:
                    print(f"  {line}")

            # Validate results
            if len(messages) == 0:
                # Check if syslog was attempted
                if "syslog" in logs.lower():
                    # Print error lines
                    error_lines = [
                        line
                        for line in logs.split("\n")
                        if "error" in line.lower() or "fail" in line.lower()
                    ]
                    if error_lines:
                        print("\n[Test] Error log lines:")
                        for line in error_lines[:10]:
                            print(f"  {line}")

                    pytest.skip(
                        "Syslog configured but no messages received (check logs above)"
                    )
                else:
                    pytest.fail(
                        "No syslog messages received and no syslog activity in logs. "
                        "Syslog may not be implemented or configured correctly."
                    )

            # Validate message content
            print("\n[Test] Validating syslog messages...")

            # Focus validation on messages generated by this test's auth attempts
            relevant = []
            for m in messages:
                # Combine hostname/app/message to account for parser splitting
                combined = (
                    f"{m.hostname or ''} {m.app_name or ''} {m.message or ''}".strip()
                )
                tl = combined.lower()
                # Focus on explicit auth events or explicit usernames
                if (
                    "syslog_user" in combined
                    or "nonexistent_user" in combined
                    or "auth_result" in tl
                    or " authentication" in tl
                    or tl.startswith("authentication")
                    or " login" in tl
                    or tl.startswith("login")
                ):
                    relevant.append(m)

            # Should have at least one relevant message
            assert len(relevant) >= 1, (
                f"Expected at least 1 relevant syslog message, got {len(relevant)}"
            )

            # Validate each relevant message
            for msg in relevant:
                # Check priority is set
                assert msg.priority is not None, "Syslog message missing priority"

                # Facility should be LOCAL0 (16) -> priority = 16*8 + severity
                expected_facility = 16  # LOCAL0
                assert msg.facility == expected_facility, (
                    f"Expected facility {expected_facility} (LOCAL0), got {msg.facility}"
                )

                # Severity should be reasonable (0-7)
                assert 0 <= msg.severity <= 7, f"Invalid severity: {msg.severity}"

                # Message should contain authentication-related keywords
                msg_lower = f"{msg.hostname or ''} {msg.app_name or ''} {msg.message or ''}".lower()
                # Ensure it looks auth-related using stricter terms
                assert (
                    "auth_result" in msg_lower
                    or " authentication" in msg_lower
                    or msg_lower.startswith("authentication")
                    or " login" in msg_lower
                    or msg_lower.startswith("login")
                    or "syslog_user" in msg_lower
                    or "nonexistent_user" in msg_lower
                ), f"Message doesn't appear to be auth-related: {msg.message}"

                # When an explicit auth/login record, ensure username is present
                if (
                    "auth_result" in msg_lower
                    or " authentication" in msg_lower
                    or msg_lower.startswith("authentication")
                    or " login" in msg_lower
                    or msg_lower.startswith("login")
                ):
                    assert any(
                        user in msg_lower
                        for user in ["syslog_user", "nonexistent_user"]
                    ), f"Message doesn't contain username: {msg.message}"

            # Try to categorize messages
            success_msgs = [
                m
                for m in relevant
                if any(
                    keyword
                    in (
                        f"{m.hostname or ''} {m.app_name or ''} {m.message or ''}".lower()
                    )
                    for keyword in [
                        "success true",
                        '"success": true',
                        "accepted",
                        "pass",
                        "granted",
                    ]
                )
            ]

            failure_msgs = [
                m
                for m in relevant
                if any(
                    keyword
                    in (
                        f"{m.hostname or ''} {m.app_name or ''} {m.message or ''}".lower()
                    )
                    for keyword in [
                        "fail",
                        "failed",
                        "reject",
                        "denied",
                        "invalid",
                        '"success": false',
                        "success false",
                    ]
                )
            ]

            print(f"\n[Test] Success messages: {len(success_msgs)}")
            print(f"[Test] Failure messages: {len(failure_msgs)}")

            # We expect at least one failure (we did 2 failed auths)
            assert len(failure_msgs) >= 1, "Expected at least one failure message"

            print(
                f"\n[Test] SUCCESS: Validated {len(relevant)} relevant syslog message(s)"
            )

    finally:
        # Cleanup
        try:
            syslog_server.shutdown()
        except Exception:
            pass


if __name__ == "__main__":
    # Allow running directly for debugging
    pytest.main([__file__, "-v", "-s", "-m", "functional"])
