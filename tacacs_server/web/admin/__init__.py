"""Admin web interface components."""

from .routers import admin_router
from .auth import get_admin_auth_dependency

__all__ = ["admin_router", "get_admin_auth_dependency"]
