"""Unit tests for web middleware behaviors."""

import json

from fastapi.testclient import TestClient

from tacacs_server.exceptions import RateLimitExceededError
from tacacs_server.utils import logging_config
from tacacs_server.web import app_setup, web_app


def test_request_logging_and_tracing(caplog):
    """Request middleware logs both request and response with correlation id."""
    logging_config._get_host.cache_clear()
    caplog.set_level("DEBUG", logger="tacacs_server.web.web_app")
    caplog.set_level("DEBUG", logger="tacacs_server.web.web_app")
    app = web_app.create_app()

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/ping", headers={"X-Correlation-ID": "test-corr"})
    assert resp.status_code == 200
    messages = "\n".join(caplog.messages)
    assert "HTTP request" in messages
    assert "HTTP response" in messages


def test_error_response_formatting():
    """Unhandled exceptions return structured JSON with error metadata."""
    logging_config._get_host.cache_clear()
    app = app_setup.create_app()

    @app.get("/boom")
    async def boom():
        raise RuntimeError("kaboom")

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/boom")
    assert resp.status_code == 500
    payload = resp.json()
    assert payload["error"] == "Internal server error"
    assert payload["details"] == "An unexpected error occurred"
    assert "error_id" in payload and payload["error_id"]
    assert "timestamp" in payload


def test_rate_limit_error_payload():
    """Rate limit errors propagate structured payload."""
    logging_config._get_host.cache_clear()
    app = web_app.create_app()

    @app.get("/limited")
    async def limited():
        raise RateLimitExceededError("Too many", details={"remaining": 0})

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/limited")
    assert resp.status_code == 429
    body = resp.json()
    assert body["error"] == "rate_limit_exceeded"
    assert body["detail"]["remaining"] == 0


def test_cors_preflight_includes_expected_headers():
    """CORS middleware should echo origin and allow credentials."""
    logging_config._get_host.cache_clear()
    app = app_setup.create_app()
    app.add_api_route("/cors", lambda: {"ok": True}, methods=["GET", "OPTIONS"])

    client = TestClient(app)
    resp = client.options(
        "/cors",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "https://example.com"
    assert resp.headers.get("access-control-allow-credentials") == "true"


def test_gzip_compression_applied_for_large_responses():
    """GZip middleware compresses sufficiently large payloads."""
    logging_config._get_host.cache_clear()
    app = app_setup.create_app()

    @app.get("/large")
    async def large():
        return json.dumps({"data": "x" * 1500})

    client = TestClient(app)
    resp = client.get("/large", headers={"Accept-Encoding": "gzip"})
    assert resp.status_code == 200
    assert resp.headers.get("content-encoding") == "gzip"
