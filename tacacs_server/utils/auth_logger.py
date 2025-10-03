"""Unified authentication event logging utilities for TACACS+ and RADIUS."""

from __future__ import annotations

from tacacs_server.utils.logger import get_logger

_logger = get_logger("tacacs_server.auth.events", component="auth")


def _build_context(
    protocol: str,
    username: str | None,
    client: str | None,
    group: str | None,
) -> dict[str, str | None]:
    return {
        "protocol": protocol,
        "username": username or "<unknown>",
        "client": client,
        "group": group,
    }


def log_request(
    protocol: str,
    username: str | None,
    client: str | None = None,
    group: str | None = None,
    extra: str | None = None,
) -> None:
    payload = _build_context(protocol, username, client, group)
    if extra:
        payload["details"] = extra
    _logger.debug("Authentication request", extra=payload)


def log_success(
    protocol: str,
    username: str | None,
    client: str | None = None,
    group: str | None = None,
) -> None:
    payload = _build_context(protocol, username, client, group)
    _logger.info("Authentication success", extra=payload)


def log_failure(
    protocol: str,
    username: str | None,
    client: str | None = None,
    group: str | None = None,
    reason: str | None = None,
) -> None:
    payload = _build_context(protocol, username, client, group)
    if reason:
        payload["reason"] = reason
    _logger.warning("Authentication failure", extra=payload)
