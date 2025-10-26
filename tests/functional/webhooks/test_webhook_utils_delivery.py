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
    store: list[dict[str, Any]] = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            payload = {"_raw": body.decode("utf-8", errors="replace")}
        _RecHandler.store.append({"path": self.path, "payload": payload})
        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt, *args):
        return


def _start_srv():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _RecHandler)
    port = srv.server_port
    _RecHandler.store = []
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port, _RecHandler.store


@pytest.mark.functional
def test_webhook_utils_template_and_threshold():
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
