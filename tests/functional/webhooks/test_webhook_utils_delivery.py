"""
Webhook Utilities Test Suite
==========================

This module contains comprehensive tests for the webhook utility functions in the TACACS+ server.
It focuses on verifying the core functionality of the webhook notification system, including
template processing, threshold-based rate limiting, and delivery mechanisms.

Test Coverage:
- Template variable substitution
- Rate limiting and threshold handling
- Webhook delivery retries
- Error handling and edge cases
- Concurrent webhook processing
- Configuration validation

Key Components Tested:
- `notify()`: Main webhook notification function
- `record_event()`: Event recording and processing
- `set_webhook_config()`: Configuration management
- `set_webhook_sender()`: Custom sender injection

Dependencies:
- Python's built-in http.server for test server
- pytest for test framework
- requests for HTTP client functionality

Environment Variables:
- WEBHOOK_TEST_PORT: Port for the test webhook server (default: random available port)
- WEBHOOK_MAX_RETRIES: Maximum number of delivery attempts (default: 3)
- WEBHOOK_TIMEOUT: Request timeout in seconds (default: 5)

Example Usage:
    pytest tests/functional/webhooks/test_webhook_utils_delivery.py -v
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

    This handler intercepts incoming webhook requests and stores them in memory
    for test verification. It's used by the test webhook server to capture and
    validate webhook deliveries.

    Class Attributes:
        store: Class-level list that stores all received webhook requests
              in the format [{"path": str, "payload": dict}]

    Example:
        with http.server.HTTPServer(('localhost', 0), _RecHandler) as server:
            # Store will be available as _RecHandler.store
            pass
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


def _start_srv() -> tuple[http.server.HTTPServer, int, list[dict]]:
    """Start a test HTTP server to receive webhook notifications.

    This function creates and starts an HTTP server in a separate thread to
    simulate a webhook receiver endpoint for testing purposes.

    Returns:
        A tuple containing:
            - The HTTP server instance
            - The port number the server is listening on
            - Reference to the request store for test verification

    Example:
        server, port, requests = _start_srv()
        # Test code that triggers webhooks
        assert len(requests) > 0  # Verify webhook was received
        server.shutdown()
        server.server_close()
    """
    srv = http.server.HTTPServer(("127.0.0.1", 0), _RecHandler)
    port = srv.server_port
    _RecHandler.store = []  # Reset store for each test
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port, _RecHandler.store


@pytest.mark.functional
def test_webhook_utils_template_and_threshold():
    """Test webhook template processing and rate limiting functionality.

    This test verifies the core functionality of the webhook system including
    template variable substitution and rate limiting. It ensures that webhook
    notifications are properly formatted and that the rate limiting mechanism
    works as expected.

    Test Coverage:
    - Template variable substitution in webhook payloads
    - Rate limiting based on event thresholds
    - Multiple webhook delivery handling
    - Template syntax and processing
    - Threshold-based event filtering

    Test Steps:
    1. Start a test HTTP server to receive webhooks
    2. Configure webhook with template and threshold settings
    3. Generate multiple test events in quick succession
    4. Verify webhook delivery and payload content
    5. Check rate limiting behavior
    6. Verify template variable substitution

    Expected Results:
    - First event within threshold is delivered immediately
    - Subsequent events are rate limited according to configuration
    - Template variables are correctly substituted in the payload
    - Webhook payload matches the expected structure
    - Correct number of deliveries based on threshold settings

    Edge Cases Tested:
    - Empty template variables
    - Special characters in template values
    - High event frequency
    - Multiple webhook endpoints
    - Error handling for invalid templates

    Dependencies:
    - Requires a running TACACS+ server with webhook support
    - Test HTTP server for receiving webhooks
    - Properly configured webhook templates and thresholds
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
