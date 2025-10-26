"""Web subsystem for TACACS+ server.

Avoid heavy imports at package import time to prevent circular import issues
during test collection. Import submodules directly, e.g.:

    from tacacs_server.web.monitoring import TacacsMonitoringAPI
"""

__all__ = []
