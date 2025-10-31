"""Admin web interface components.

Expose the admin UI router from the dedicated `web_admin` module to keep a
clean separation: `web_admin` for HTML UI and `web_api` for JSON API.
"""

from .auth import get_admin_auth_dependency
from ..web_admin import router as admin_router

__all__ = ["admin_router", "get_admin_auth_dependency"]
