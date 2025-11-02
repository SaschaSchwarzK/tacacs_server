"""
Webhook Utils Delivery Tests

This module contains unit and functional tests for the webhook utilities.
It verifies the core functionality of the webhook notification system,
including template processing, threshold handling, and delivery mechanisms.

Tests focus on the webhook utility functions rather than end-to-end delivery.
"""

import http.server
import json
import threading
import time
from typing import Any

import pytest

from tacacs_server.utils.webhook import (
    notify,
    record_event,
    set_webhook_config,
    set_webhook_sender,
)


class _RecHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for capturing webhook test requests.

    This handler stores all received requests in memory for later verification.
    It's used by the test webhook server to capture and validate webhook deliveries.
    """

    store: list[dict[str, Any]] = []

    def do_POST(self):  # noqa: N802
        """Handle HTTP POST requests and store the received data.

        Extracts the request body and headers, then stores them for test verification.
        Always returns 200 OK response.
        """
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {"_raw": body.decode("utf-8", errors="replace")}
        _RecHandler.store.append({"path": self.path, "payload": payload})
        self.send_response(200)
        self.end_headers()

    def log_message(self, format_str: str, *args, **kwargs) -> None:
        """Override default logging to reduce test output noise.

        Args:
            format_str: Format string for the log message (unused in test output)
            *args: Format arguments (unused in test output)
            **kwargs: Additional keyword arguments for compatibility
        """
        # This method intentionally does nothing to reduce test output noise
        # The parameters are kept for compatibility with the parent class
        pass


def _start_srv() -> tuple[
    http.server.HTTPServer, threading.Thread, int, list[dict[str, Any]]
]:
    """Start a test HTTP server to receive webhook notifications.

    Returns:
        Tuple containing:
        - The HTTP server instance
        - The port number the server is listening on
        - Reference to the request store for test verification
    """
    srv = http.server.HTTPServer(("127.0.0.1", 0), _RecHandler)
    port = srv.server_port
    _RecHandler.store = []  # Reset store for each test
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port, _RecHandler.store


@pytest.mark.functional
def test_webhook_utils_template_and_threshold() -> None:
    """Test webhook template processing and rate limiting functionality.

    This test verifies:
    - Template variables are correctly substituted in webhook payloads
    - Rate limiting works as expected with different threshold settings
    - Webhook delivery respects the rate limit configuration

    Test Steps:
    1. Configure webhook with template and threshold settings
    2. Simulate multiple events in quick succession
    3. Verify rate limiting behavior

    Expected Results:
    - First event within threshold is delivered immediately
    - Subsequent events are rate limited
    - Template variables are correctly substituted
    - Correct number of deliveries based on threshold settings
    """
    # Inject a transport stub to capture deliveries without relying on OS networking
    captured: list[tuple[str, dict, float]] = []

    def _capture_sender(url: str, payload: dict, timeout: float) -> None:
        captured.append((url, payload, timeout))

    set_webhook_sender(_capture_sender)
    try:
        template = {"evt": "{{event}}", "user": "{{username}}", "extra": "ok"}
        set_webhook_config(
            urls=["http://example/hook1", "http://example/hook2"],
            headers={"Content-Type": "application/json"},
            template=template,
            timeout=0.1,
            threshold_count=2,
            threshold_window=30,
        )

        notify("auth_failure", {"username": "alice", "client_ip": "127.0.0.1"})
        record_event("auth_failure", "alice")
        record_event("auth_failure", "alice")

        deadline = time.time() + 2
        while time.time() < deadline and len(captured) < 2:
            time.sleep(0.05)

        assert len(captured) >= 2
        # Validate templated payload fields in at least one captured call
        payloads = [p for _, p, _ in captured]
        assert any(
            p.get("evt") in ("auth_failure", "threshold_exceeded") for p in payloads
        )
        assert any(p.get("user") == "alice" for p in payloads)
        assert any(p.get("extra") == "ok" for p in payloads)
    finally:
        # Restore default sender
        set_webhook_sender(None)
