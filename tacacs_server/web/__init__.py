"""Web subsystem for TACACS+ server.

Avoid heavy imports at package import time to prevent circular import issues
during test collection. Import submodules directly, e.g.:

    from tacacs_server.web.web import TacacsMonitoringAPI
"""

"""Simplified Web Interface"""
from .web_app import create_app

__all__ = ["create_app"]
