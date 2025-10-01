"""Unified authentication event logging utilities for TACACS+ and RADIUS."""
from __future__ import annotations

from typing import Optional

from tacacs_server.utils.logger import get_logger

_logger = get_logger("tacacs_server.auth.events", component="auth")


def _build_context(
    protocol: str,
    username: Optional[str],
    client: Optional[str],
    group: Optional[str],
) -> dict[str, Optional[str]]:
    return {
        "protocol": protocol,
        "username": username or "<unknown>",
        "client": client,
        "group": group,
    }


def log_request(
    protocol: str,
    username: Optional[str],
    client: Optional[str] = None,
    group: Optional[str] = None,
    extra: Optional[str] = None,
) -> None:
    payload = _build_context(protocol, username, client, group)
    if extra:
        payload["details"] = extra
    _logger.debug("Authentication request", **payload)


def log_success(
    protocol: str,
    username: Optional[str],
    client: Optional[str] = None,
    group: Optional[str] = None,
) -> None:
    payload = _build_context(protocol, username, client, group)
    _logger.info("Authentication success", **payload)


def log_failure(
    protocol: str,
    username: Optional[str],
    client: Optional[str] = None,
    group: Optional[str] = None,
    reason: Optional[str] = None,
) -> None:
    payload = _build_context(protocol, username, client, group)
    if reason:
        payload["reason"] = reason
    _logger.warning("Authentication failure", **payload)
