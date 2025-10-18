"""
Custom exceptions for TACACS+ server.

Includes a small, consistent hierarchy and back-compat aliases
for previously used names in the codebase/tests.
"""


class TacacsError(Exception):
    """Base TACACS+ exception."""

    pass


# Backwards-compat alias (older code imported TacacsException)
TacacsException = TacacsError


class AuthenticationError(TacacsError):
    """Authentication specific error"""

    pass


class AuthorizationError(TacacsError):
    """Authorization specific error"""

    pass


class ConfigurationError(TacacsError):
    """Configuration specific error"""

    pass


class DatabaseError(TacacsError):
    """Database specific error"""

    pass


class ValidationError(TacacsError):
    """Input validation error"""

    pass


class ProtocolError(TacacsError, ValueError):
    """TACACS+ protocol parsing/validation error.

    Subclasses ValueError to remain compatible with existing callers/tests
    that expect ValueError from low-level parsers.
    """

    pass


# Optional aliases using the naming suggested in discussions
TacacsProtocolError = ProtocolError
TacacsAuthError = AuthenticationError
TacacsConfigError = ConfigurationError
