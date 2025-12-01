"""Unit tests for structured logging configuration utilities."""

import io
import json
import logging

from tacacs_server.utils import logging_config


def test_configure_logging_sets_level_and_formatter(monkeypatch):
    """configure_logging should attach formatter and honor level."""
    logging_config._get_host.cache_clear()
    monkeypatch.setattr(logging_config, "_get_host", lambda: "test-host")
    stream = io.StringIO()
    logging_config.configure_logging(level=logging.DEBUG, stream=stream, reset=True)
    logger = logging_config.get_logger("test.logger")

    logger.debug("hello", extra={"event": "test_event"})
    stream_value = stream.getvalue().strip()
    assert stream_value, "Expected log output"
    payload = json.loads(stream_value)
    assert payload["level"] == "DEBUG"
    assert payload["event"] == "test_event"
    assert payload["message"] == "hello"


def test_structured_formatter_includes_context_and_error(monkeypatch):
    """StructuredJSONFormatter should merge context and error details."""
    logging_config._get_host.cache_clear()
    monkeypatch.setattr(logging_config, "_get_host", lambda: "test-host")
    fmt = logging_config.StructuredJSONFormatter()
    base_logger = logging.getLogger("structured")
    base_logger.propagate = False
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(fmt)
    base_logger.handlers = [handler]
    base_logger.setLevel(logging.INFO)

    try:
        raise ValueError("boom")
    except ValueError:
        base_logger.info(
            "oops",
            extra={"event": "err_evt", "trace_id": "trace-123", "component": "x"},
            exc_info=True,
        )

    payload = json.loads(buf.getvalue())
    assert payload["trace_id"] == "trace-123"
    assert payload["component"] == "x"
    assert payload["event"] == "err_evt"
    assert payload["error"]["message"] == "boom"
