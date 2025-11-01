"""Admin web interface components.

Expose the admin UI router from the dedicated `web_admin` module to keep a
clean separation: `web_admin` for HTML UI and `web_api` for JSON API.
"""

from ..web_admin import router as admin_router
from .auth import get_admin_auth_dependency

__all__ = ["admin_router", "get_admin_auth_dependency"]
