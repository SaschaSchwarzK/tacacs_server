"""Structured logging configuration helpers."""

from __future__ import annotations

import json
import logging
import socket
import time
import traceback
import os
from collections.abc import Iterable, MutableMapping
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "configure_logging",
    "get_logger",
    "get_structured_logger",
    "bind_context",
    "clear_context",
    "logging_context",
    "StructuredJSONFormatter",
    "StructuredLoggerAdapter",
]

_STANDARD_ATTRS: Iterable[str] = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "message",
    "context",
    "taskName",
}

_context: ContextVar[dict[str, Any]] = ContextVar(
    "structured_logging_context", default={}
)
_logging_configured = False
_CACHED_HOSTNAME = None


def _get_host() -> str:
    global _CACHED_HOSTNAME
    if _CACHED_HOSTNAME:
        return _CACHED_HOSTNAME
    # Prefer container-provided hostname; no DNS lookup
    host = os.getenv("HOSTNAME")
    if host:
        _CACHED_HOSTNAME = host
        return host
    # Try /etc/hostname (fast, local)
    try:
        with open("/etc/hostname", "r", encoding="utf-8") as fh:
            host = fh.read().strip() or None
            if host:
                _CACHED_HOSTNAME = host
                return host
    except Exception:
        pass
    # Fallback to socket.gethostname (does not require DNS)
    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown"
    _CACHED_HOSTNAME = host
    return host


def _json_default(value: Any) -> str:
    return repr(value)


class StructuredJSONFormatter(logging.Formatter):
    """Formatter that renders log records as JSON."""

    def __init__(self, *, utc: bool = True) -> None:
        super().__init__()
        self.utc = utc

    def format(self, record: logging.LogRecord) -> str:
        # RFC3339Nano-like timestamp
        ts = datetime.now(UTC if self.utc else None).isoformat()
        # Monotonic milliseconds
        t_monotonic_ms = int(time.monotonic() * 1000)

        # Base schema fields per docs/logging.json
        payload: dict[str, Any] = {
            "schema": "log.v1",
            "ts": ts,
            "t_monotonic_ms": t_monotonic_ms,
            "level": record.levelname,
            "message": record.getMessage(),
            "service": getattr(record, "service", None) or "tacacs_server",
            "env": getattr(record, "env", None)
            or (os.getenv("ENV") or os.getenv("APP_ENV") or "dev"),
            "host": _get_host(),
            "trace_id": getattr(record, "trace_id", None) or "",
            "span_id": getattr(record, "span_id", None) or "",
            "correlation_id": getattr(record, "correlation_id", None) or "",
        }

        # Include event if provided
        evt = getattr(record, "event", None)
        if evt:
            payload["event"] = evt

        # Merge structured context
        context = getattr(record, "context", None) or _context.get()
        if context:
            # Bring context.top-level keys into payload without nesting under 'context'
            for k, v in dict(context).items():
                if k not in payload:
                    payload[k] = v

        # Copy safe extras (flatten into payload)
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key.startswith("_"):
                continue
            # Avoid overwriting base fields unless explicitly set
            if key in payload and payload[key] not in (None, ""):
                continue
            payload[key] = value

        # Exceptions
        if record.exc_info:
            payload["error"] = {
                "type": str(getattr(record.exc_info[0], "__name__", "")),
                "message": str(record.exc_info[1]),
                "stack": "".join(traceback.format_exception(*record.exc_info)).strip(),
            }
        elif record.exc_text:
            payload["error"] = {"message": record.exc_text}

        if record.stack_info:
            payload["stack"] = record.stack_info

        return json.dumps(payload, default=_json_default, ensure_ascii=True)


class StructuredLoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that merges thread-local context with static context."""

    def process(
        self, msg: str, kwargs: MutableMapping[str, Any]
    ) -> tuple[str, MutableMapping[str, Any]]:
        extra = kwargs.setdefault("extra", {})

        custom_fields = {
            key: kwargs.pop(key)
            for key in list(kwargs.keys())
            if key not in {"exc_info", "stack_info", "extra"}
        }
        if custom_fields:
            for key, value in custom_fields.items():
                extra.setdefault(key, value)

        context_data = _context.get()
        if context_data or self.extra:
            extra_map: dict[str, Any] = dict(self.extra or {})
            merged_context = {**dict(context_data), **extra_map}
            extra.setdefault("context", merged_context)
        return msg, kwargs


def configure_logging(
    level: int = logging.INFO,
    *,
    stream: Any | None = None,
    handlers: Iterable[logging.Handler] | None = None,
    formatter: logging.Formatter | None = None,
    reset: bool = True,
) -> None:
    """Configure root logging with structured JSON output."""

    global _logging_configured

    formatter = formatter or StructuredJSONFormatter()

    resolved_handlers: Iterable[logging.Handler]
    if handlers:
        resolved_handlers = handlers
    else:
        stream_handler = logging.StreamHandler(stream)
        resolved_handlers = (stream_handler,)

    root = logging.getLogger()
    if reset:
        root.handlers = []

    for handler in resolved_handlers:
        if handler.level == logging.NOTSET:
            handler.setLevel(level)
        if handler.formatter is None:
            handler.setFormatter(formatter)
        root.addHandler(handler)

    root.setLevel(level)
    _logging_configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a logger, ensuring configuration exists."""
    if not _logging_configured:
        configure_logging()
    return logging.getLogger(name)


def get_structured_logger(name: str, **context: Any) -> StructuredLoggerAdapter:
    """Return a structured logger adapter with optional static context."""
    logger = get_logger(name)
    context = {k: v for k, v in context.items() if v is not None}
    return StructuredLoggerAdapter(logger, context)


def bind_context(**kwargs: Any) -> Token:
    """Bind key/value pairs to the contextual log scope."""
    current = dict(_context.get())
    for key, value in kwargs.items():
        if value is not None:
            current[key] = value
    return _context.set(current)


def clear_context(token: Token | None = None) -> None:
    """Clear contextual information, optionally using a context token."""
    if token is not None:
        _context.reset(token)
    else:
        _context.set({})


@contextmanager
def logging_context(**kwargs: Any):
    """Context manager that binds log context for the enclosed block."""
    token = bind_context(**kwargs)
    try:
        yield
    finally:
        clear_context(token)
