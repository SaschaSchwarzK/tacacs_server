"""Admin web interface components."""

from .auth import get_admin_auth_dependency
from .routers import admin_router

__all__ = ["admin_router", "get_admin_auth_dependency"]
