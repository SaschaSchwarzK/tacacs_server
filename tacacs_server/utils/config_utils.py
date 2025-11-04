"""
Configuration utilities for TACACS+ server.

This module provides thread-safe access to the server's configuration.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import Request

    from tacacs_server.config.config import TacacsConfig

# Thread-local storage for configuration (per-context) and a global fallback
_config: ContextVar[TacacsConfig | None] = ContextVar("config", default=None)
_config_global: TacacsConfig | None = None


def set_config(config: TacacsConfig | None) -> None:
    """Set the current configuration.

    Args:
        config: The configuration object to set, or None to clear it.
    """
    global _config_global
    _config.set(config)
    _config_global = config


def get_config() -> TacacsConfig | None:
    """Get the current configuration.

    Returns:
        The current configuration, or None if not set.
    """
    # Use context-local when present; fall back to global for new threads
    cfg = _config.get()
    return cfg if cfg is not None else _config_global


# Context variables for tracking config changes
_config_user: ContextVar[str] = ContextVar("config_user", default="system")
_config_source_ip: ContextVar[str] = ContextVar("config_source_ip", default="")


def get_config_change_user() -> str:
    """Get the username associated with the current config change."""
    return _config_user.get()


def get_config_change_source_ip() -> str | None:
    """Get the source IP associated with the current config change."""
    val = _config_source_ip.get()
    return val if val else None


def set_config_change_user(user: str) -> None:
    """Set the username associated with the current config change."""
    _config_user.set(user or "system")


def set_config_change_source_ip(ip: str | None) -> None:
    """Set the source IP associated with the current config change."""
    _config_source_ip.set(ip or "")


# Admin authentication dependency
_admin_auth_dependency: Callable[[Request], Awaitable[None]] | None = None


def set_admin_auth_dependency(
    dependency: Callable[[Request], Awaitable[None]] | None,
) -> None:
    """Set the admin authentication dependency function.

    Args:
        dependency: The dependency function to set, or None to clear it.
    """
    global _admin_auth_dependency
    _admin_auth_dependency = dependency


def get_admin_auth_dependency_func() -> Callable[[Request], Awaitable[None]] | None:
    """Get the current admin authentication dependency function.

    Returns:
        The current admin authentication dependency function, or None if not set.
    """
    return _admin_auth_dependency


# Optional: access the admin session manager used by the web admin UI
def get_admin_session_manager() -> Any | None:
    """Return the active AdminSessionManager if available.

    Provided for modules that cannot import from web.web directly without cycles.
    """
    try:
        from tacacs_server.web.web import get_admin_session_manager as _get

        return _get()
    except Exception:
        return None
