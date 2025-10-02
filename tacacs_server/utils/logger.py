"""Project-wide logging helpers built on structured logging utilities."""

from __future__ import annotations

import logging
from typing import Any

from .logging_config import (
    StructuredJSONFormatter,
    bind_context,
    clear_context,
    get_structured_logger,
    logging_context,
)
from .logging_config import (
    configure_logging as _configure_logging,
)

__all__ = [
    "configure",
    "get_logger",
    "bind_context",
    "clear_context",
    "logging_context",
    "StructuredJSONFormatter",
]


def configure(*, level: int = logging.INFO, handlers: list[logging.Handler] | None = None) -> None:
    """Configure structured logging for the application."""
    _configure_logging(level=level, handlers=handlers)


def get_logger(name: str, **context: Any) -> logging.Logger:
    """Return a structured logger adapter for the provided name."""
    return get_structured_logger(name, **context)
