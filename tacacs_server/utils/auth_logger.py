"""Unified authentication event logging utilities for TACACS+ and RADIUS."""
from __future__ import annotations

import logging
from typing import Optional

_logger = logging.getLogger("tacacs_server.auth.events")


def _format_context(client: Optional[str], group: Optional[str]) -> str:
    if group:
        return f" ({group})"
    if client:
        return f" ({client})"
    return ""


def log_request(protocol: str, username: Optional[str], client: Optional[str] = None, group: Optional[str] = None, extra: Optional[str] = None) -> None:
    user = username if username else "<unknown>"
    suffix = _format_context(client, group)
    message = f"{protocol} auth request: user={user}{suffix}"
    if extra:
        message = f"{message} {extra}"
    _logger.debug(message)


def log_success(protocol: str, username: Optional[str], client: Optional[str] = None, group: Optional[str] = None) -> None:
    user = username if username else "<unknown>"
    suffix = _format_context(client, group)
    _logger.info("%s authentication success: %s%s", protocol, user, suffix)


def log_failure(protocol: str, username: Optional[str], client: Optional[str] = None, group: Optional[str] = None, reason: Optional[str] = None) -> None:
    user = username if username else "<unknown>"
    suffix = _format_context(client, group)
    if reason:
        _logger.warning("%s authentication failed: %s%s (%s)", protocol, user, suffix, reason)
    else:
        _logger.warning("%s authentication failed: %s%s", protocol, user, suffix)
