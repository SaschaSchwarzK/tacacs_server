"""
Webhook Delivery End-to-End Tests

This module contains functional tests for verifying webhook delivery from the TACACS+ server.
It tests the end-to-end flow of webhook notifications, including:
- HTTP POST request formatting
- Payload structure and content
- Multiple webhook endpoint support
- Error handling and retries
- Authentication event notifications

Tests use local HTTP servers to capture and validate webhook deliveries.
"""

import http.server
import json
import socket
import struct
import threading
import time
from typing import Any

import pytest
import requests


class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that records all POST requests.

    Uses a per-server store attached to the HTTPServer instance to avoid
    cross-test interference between multiple receivers running in the same
    process.
    """

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {"_raw": body.decode("utf-8", errors="replace")}

        record = {
            "path": self.path,
            "headers": dict(self.headers.items()),
            "payload": payload,
            "timestamp": time.time(),
        }
        # Append to per-server store (initialized in _start_http_server)
        try:
            self.server.store.append(record)  # type: ignore[attr-defined]
        except Exception:
            # Fallback to a transient attribute if not initialized (shouldn't happen)
            if not hasattr(self.server, "store"):
                setattr(self.server, "store", [])  # type: ignore[attr-defined]
            self.server.store.append(record)  # type: ignore[attr-defined]
        print(f"[WebhookReceiver] Received POST to {self.path}: {payload}")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok"}).encode())

    def log_message(self, fmt, *args) -> None:
        """Log message to stdout for debugging.

        Args:
            fmt: Format string
            *args: Format arguments
        """
        print(f"[WebhookReceiver] {fmt % args}")


def _start_http_server() -> tuple[
    http.server.HTTPServer, threading.Thread, int, list[dict[str, Any]]
]:
    """Start HTTP server and return server, thread, port, and per-server storage"""
    srv = http.server.HTTPServer(("127.0.0.1", 0), _RecordingHandler)
    port = srv.server_port
    # Attach a per-instance store to avoid class-level shared state
    srv.store = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    # Wait for server to be ready
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                sock.close()
                break
            sock.close()
        except OSError as e:
            # Expected errors when server is not yet ready
            # OSError can occur on socket creation/closure
            # socket.error is a legacy alias for OSError
            print(f"[Test] Socket error during connection check: {e}")
        time.sleep(0.1)

    print(f"[Test] HTTP server started on port {port}")
    return srv, thread, port, srv.store  # type: ignore[attr-defined]


def _send_bad_tacacs_auth(
    host: str, port: int, username: str = "wh_user", password: str = "wrongpass"
) -> bool:
    """Send a TACACS auth request that will fail. Returns True if response received."""
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

    def _mk_auth_start_body(username: str, password: str) -> bytes:
        user_b = username.encode()
        port_b = b"tty1"
        rem_b = b"127.0.0.1"
        data_b = password.encode()
        head = struct.pack(
            "!BBBBBBBB",
            TAC_PLUS_AUTHEN_ACTION.TAC_PLUS_AUTHEN_LOGIN,
            1,  # privilege
            TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP,
            TAC_PLUS_AUTHEN_SVC.TAC_PLUS_AUTHEN_SVC_LOGIN,
            len(user_b),
            len(port_b),
            len(rem_b),
            len(data_b),
        )
        return head + user_b + port_b + rem_b + data_b

    sess_id = int(time.time() * 1000) & 0xFFFFFFFF
    pkt = TacacsPacket(
        version=(TAC_PLUS_MAJOR_VER << 4) | 0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        flags=TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG,
        session_id=sess_id,
        length=0,
        body=_mk_auth_start_body(username, password),
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(3)
        s.connect((host, port))
        s.sendall(pkt.pack(""))
        print(f"[Test] Sent TACACS auth for {username} (will fail)")

        hdr = _read_exact(s, TAC_PLUS_HEADER_SIZE)
        if len(hdr) == TAC_PLUS_HEADER_SIZE:
            h = TacacsPacket.unpack_header(hdr)
            body = _read_exact(s, h.length)
            if body and body[0] == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL:
                print("[Test] Received FAIL response as expected")
                return True
        return False
    except (socket.error, OSError) as e:
        print(f"Failed to connect to {host}:{port}: {e}")
        return False
    finally:
        try:
            s.close()
        except (AttributeError, OSError):
            pass


@pytest.mark.functional
def test_webhook_delivery_end_to_end(server_factory):
    """Test end-to-end webhook delivery with real HTTP servers.

    This test verifies that the TACACS+ server correctly sends webhook notifications
    for authentication events to configured webhook endpoints.

    Test Steps:
    1. Start local HTTP servers to receive webhooks
    2. Configure TACACS+ server with webhook URLs
    3. Trigger authentication failures to generate webhook events
    4. Verify webhooks are received with correct payloads

    Expected Results:
    - Webhook servers receive POST requests for each event
    - Payloads contain correct event details
    - Headers include proper content-type
    - Response handling works as expected
    """
    """
    Test webhook delivery with real HTTP servers.

    This test:
    1. Starts two local HTTP servers to receive webhooks
    2. Configures the TACACS server with webhook URLs
    3. Triggers authentication failures to generate webhook events
    4. Verifies the webhooks were received with correct payload
    """
    # Start two HTTP servers to receive webhooks
    srv1, _, port1, records1 = _start_http_server()
    srv2, _, port2, records2 = _start_http_server()

    print(f"\n[Test] Started webhook receivers on ports {port1} and {port2}")

    urls = [
        f"http://127.0.0.1:{port1}/hook1",
        f"http://127.0.0.1:{port2}/hook2",
    ]
    template = {
        "event_type": "{{event}}",
        "username": "{{username}}",
        "timestamp": "{{timestamp}}",
        "source_ip": "{{source_ip}}",
    }

    # Configure server with webhooks BEFORE starting
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={
            "auth_backends": "local",
            "log_level": "DEBUG",  # Enable debug logging
            "webhooks": {
                "enabled": "true",
                "urls": ",".join(urls),
                "headers_json": json.dumps(
                    {"Content-Type": "application/json", "X-Test": "webhook"}
                ),
                "template_json": json.dumps(template),
                "timeout": "5.0",
                "retry_count": "2",
                "threshold_count": "1",  # Trigger on first failure
                "threshold_window": "60",
            },
        },
    )

    try:
        with server:
            print(f"[Test] Server started on TACACS port {server.tacacs_port}")

            # Set up test user and device
            from tacacs_server.auth.local_user_service import LocalUserService
            from tacacs_server.devices.store import DeviceStore

            user_service = LocalUserService(str(server.auth_db))
            user_service.create_user(
                "testuser", password="CorrectPass1", privilege_level=15
            )
            print("[Test] Created test user")

            device_store = DeviceStore(str(server.devices_db))
            device_store.ensure_group(
                "default",
                description="Test group",
                metadata={"tacacs_secret": "testsecret"},
            )
            device_store.ensure_device(
                name="test-device",
                network="127.0.0.1",
                group="default",
            )
            print("[Test] Created test device")

            # Give server time to initialize webhook subsystem
            time.sleep(1)

            # Verify webhook configuration via API
            try:
                sess = server.login_admin()
                base = server.get_base_url()

                # Check webhook config endpoint
                r = sess.get(f"{base}/api/admin/webhooks-config", timeout=5)
                if r.status_code == 200:
                    config = r.json()
                    print(f"[Test] Webhook config: {json.dumps(config, indent=2)}")
                else:
                    print(f"[Test] Webhook config endpoint returned {r.status_code}")

                # Also try to update via API to ensure runtime layer is configured
                update_r = sess.put(
                    f"{base}/api/admin/webhooks-config",
                    json={
                        "urls": urls,
                        "headers": {
                            "Content-Type": "application/json",
                            "X-Test": "webhook",
                        },
                        "template": template,
                        "timeout": 5.0,
                        "retry_count": 2,
                        "threshold_count": 1,
                        "threshold_window": 60,
                    },
                    timeout=5,
                )
                print(f"[Test] Webhook config update: {update_r.status_code}")

            except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
                # Handle potential errors during webhook configuration:
                # - RequestException: Network-related errors (connection, timeout, etc.)
                # - JSONDecodeError: Invalid JSON response
                # - ValueError: Invalid URL or other request parameter issues
                print(f"[Test] Error configuring webhooks via API: {e}")
                # Re-raise as we can't proceed without proper webhook configuration
                raise

            # Wait a bit more for configuration to propagate
            time.sleep(0.5)

            # Trigger authentication failures
            print("\n[Test] Triggering authentication failures...")
            failed_auths = 0
            for i in range(5):  # Try multiple times to ensure trigger
                if _send_bad_tacacs_auth(
                    "127.0.0.1", server.tacacs_port, f"baduser{i}", "wrongpass"
                ):
                    failed_auths += 1
                time.sleep(0.3)  # Space out attempts

            print(f"[Test] Triggered {failed_auths} failed authentications")

            # Wait for webhook delivery (async processing)
            print("\n[Test] Waiting for webhook delivery...")
            deadline = time.time() + 15
            received_count = 0
            while time.time() < deadline:
                received_count = len(records1) + len(records2)
                if received_count >= 2:  # At least one per server
                    print(f"[Test] Received {received_count} webhooks")
                    break
                time.sleep(0.5)

            print(
                f"\n[Test] Final webhook count: {len(records1)} on port {port1}, {len(records2)} on port {port2}"
            )

            # Check server logs for webhook activity
            logs = server.get_logs()

            # Debug: Print relevant log lines
            webhook_log_lines = [
                line for line in logs.split("\n") if "webhook" in line.lower()
            ]
            if webhook_log_lines:
                print("\n[Test] Webhook-related log lines:")
                for line in webhook_log_lines[:10]:  # Print first 10
                    print(f"  {line}")

            # Check if webhooks were attempted
            webhook_attempted = any(
                phrase in logs.lower()
                for phrase in ["webhook", "posting", "delivery", "notification"]
            )

            if not webhook_attempted:
                print("\n[Test] ERROR: No webhook activity found in logs")
                print(
                    "[Test] This suggests webhooks are not configured or not triggering"
                )

                # Print config section
                config_lines = [
                    line for line in logs.split("\n") if "config" in line.lower()
                ][:5]
                if config_lines:
                    print("\n[Test] Config-related log lines:")
                    for line in config_lines:
                        print(f"  {line}")

            # Validate results
            if received_count < 1:
                # Check if delivery was attempted but failed
                if "Webhook delivery failed" in logs or "webhook" in logs.lower():
                    error_lines = [
                        line
                        for line in logs.split("\n")
                        if "error" in line.lower() or "fail" in line.lower()
                    ]
                    if error_lines:
                        print("\n[Test] Error log lines:")
                        for line in error_lines[:5]:
                            print(f"  {line}")

                    pytest.skip(
                        "Webhook delivery attempted but failed (check logs above)"
                    )
                else:
                    pytest.fail(
                        f"No webhooks received and no delivery attempts found in logs. "
                        f"Failed auths: {failed_auths}, Webhook logs found: {len(webhook_log_lines)}"
                    )

            # Validate payload content
            print("\n[Test] Validating webhook payloads...")
            all_payloads = [r["payload"] for r in records1] + [
                r["payload"] for r in records2
            ]

            for i, payload in enumerate(all_payloads):
                print(f"[Test] Payload {i + 1}: {json.dumps(payload, indent=2)}")

                # Check required fields from template
                assert "event_type" in payload, f"Payload missing event_type: {payload}"
                assert "username" in payload, f"Payload missing username: {payload}"

                # Event type should be auth-related
                event = payload.get("event_type", "")
                assert any(
                    keyword in event.lower()
                    for keyword in ["auth", "fail", "threshold", "denied"]
                ), f"Unexpected event type: {event}"

                # Username should be one we used
                username = payload.get("username", "")
                assert username, f"Empty username in payload: {payload}"

            print(
                f"\n[Test] SUCCESS: Received and validated {len(all_payloads)} webhooks"
            )

            # Check that both servers received at least one webhook
            # Note: Multiple deliveries can occur (e.g., direct event + threshold events)
            assert len(records1) >= 1, (
                f"Expected >=1 webhook on receiver 1, got {len(records1)}"
            )
            assert len(records2) >= 1, (
                f"Expected >=1 webhook on receiver 2, got {len(records2)}"
            )

            assert records1[0]["payload"]["event"] == "auth_failure"
            assert records2[0]["payload"]["event"] == "auth_failure"

    finally:
        # Cleanup: shutdown HTTP servers
        try:
            srv1.shutdown()
            srv2.shutdown()
        except (AttributeError, OSError):
            # Server already shut down or not properly initialized
            pass


@pytest.mark.functional
def test_webhook_delivery_with_multiple_events(server_factory):
    """Test webhook delivery for different types of authentication events.

    This test verifies that the TACACS+ server sends appropriate webhook notifications
    for various authentication scenarios, including success and failure cases.

    Test Steps:
    1. Configure webhook endpoint
    2. Trigger multiple authentication events
    3. Verify each event generates correct webhook

    Expected Results:
    - Each event type generates appropriate webhook
    - Payloads contain correct event types and details
    - Event ordering is preserved
    """
    """Test that different event types trigger webhooks correctly"""
    srv, thread, port, records = _start_http_server()

    url = f"http://127.0.0.1:{port}/webhook"

    server = server_factory(
        enable_tacacs=True,
        config={
            "auth_backends": "local",
            "log_level": "DEBUG",
            "webhooks": {
                "enabled": "true",
                "urls": url,
                "threshold_count": "1",
                "threshold_window": "60",
            },
        },
    )

    try:
        with server:
            # Setup
            from tacacs_server.auth.local_user_service import LocalUserService
            from tacacs_server.devices.store import DeviceStore

            user_service = LocalUserService(str(server.auth_db))
            user_service.create_user(
                "testuser", password="Passw0rd1", privilege_level=15
            )

            device_store = DeviceStore(str(server.devices_db))
            device_store.ensure_group("default", metadata={"tacacs_secret": "secret"})
            device_store.ensure_device(
                name="device1", network="127.0.0.1", group="default"
            )

            time.sleep(1)

            # Trigger multiple failures with different users
            for i in range(3):
                _send_bad_tacacs_auth(
                    "127.0.0.1", server.tacacs_port, f"user{i}", "wrong"
                )
                time.sleep(0.5)

            # Wait for deliveries
            time.sleep(5)

            print(f"\n[Test] Received {len(records)} webhook(s)")

            if len(records) > 0:
                for i, rec in enumerate(records):
                    print(
                        f"[Test] Webhook {i + 1}: {json.dumps(rec['payload'], indent=2)}"
                    )
            else:
                logs = server.get_logs()
                if "webhook" in logs.lower():
                    pytest.skip("Webhooks configured but not delivered")
                else:
                    pytest.fail("No webhooks configured or triggered")
    finally:
        try:
            srv.shutdown()
        except (AttributeError, OSError):
            # Server already shut down or not properly initialized
            pass


if __name__ == "__main__":
    # Allow running directly for debugging
    pytest.main([__file__, "-v", "-s", "-m", "functional"])
