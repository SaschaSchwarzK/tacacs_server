"""Dependency container for TACACS server components."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Services:
    """Shared services container passed into server/handlers instead of globals."""

    config: Any
    device_store: Any | None = None
    device_service: Any | None = None
    local_user_service: Any | None = None
    local_user_group_service: Any | None = None
    admin_session_manager: Any | None = None
    backup_service: Any | None = None
    radius_server: Any | None = None
    command_engine: Any | None = None
