# tacacs_server/exceptions.py
"""
Custom exceptions for the TACACS+ server.
"""

from typing import Any


class TacacsServerError(Exception):
    """Base exception for all TACACS+ server errors."""

    status_code = 500
    error_code = "server_error"

    def __init__(self, message: str, details: dict | None = None):
        self.message = message
        self.details = details or {}
        super().__init__(message)


# Config exceptions
class ConfigError(TacacsServerError):
    """Base exception for configuration-related errors."""

    status_code = 500
    error_code = "config_error"


class ConfigValidationError(ConfigError):
    """Raised when configuration validation fails."""

    status_code = 400
    error_code = "config_validation_error"

    def __init__(
        self, message: str, field: str | None = None, value: Any = None, **kwargs: Any
    ):
        details = {"field": field, "value": value, **kwargs}
        super().__init__(message, details)
        self.field = field
        self.value = value


# Authentication/Authorization exceptions
class AuthenticationError(TacacsServerError):
    """Raised when authentication fails."""

    status_code = 401
    error_code = "authentication_error"


class AuthorizationError(TacacsServerError):
    """Raised when authorization is denied."""

    status_code = 403
    error_code = "authorization_error"


# Resource exceptions
class ResourceNotFoundError(TacacsServerError):
    """Raised when a requested resource is not found."""

    status_code = 404
    error_code = "not_found"


# Rate limiting
class RateLimitExceededError(TacacsServerError):
    """Raised when rate limits are exceeded."""

    status_code = 429
    error_code = "rate_limit_exceeded"


# Service availability
class ServiceUnavailableError(TacacsServerError):
    """Raised when a required service is unavailable."""

    status_code = 503
    error_code = "service_unavailable"
