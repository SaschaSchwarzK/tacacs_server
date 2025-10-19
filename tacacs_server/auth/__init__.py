# Package: tacacs_server.auth
# Export available backend classes with safe, lazy imports to avoid import-time failures
from __future__ import annotations

__all__ = ["LocalAuthBackend", "LDAPAuthBackend", "OktaAuthBackend"]

try:
    from .local import LocalAuthBackend  # type: ignore
except Exception:  # pragma: no cover
    LocalAuthBackend = None  # type: ignore

try:
    from .ldap_auth import LDAPAuthBackend  # type: ignore
except Exception:  # pragma: no cover
    LDAPAuthBackend = None  # type: ignore

try:
    from .okta_auth import OktaAuthBackend  # type: ignore
except Exception:  # pragma: no cover
    OktaAuthBackend = None  # type: ignore
