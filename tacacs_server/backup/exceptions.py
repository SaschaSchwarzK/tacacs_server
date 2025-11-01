"""Backup-specific exception types with structured metadata.

These exceptions are designed to carry an error code and optional details
dictionary to facilitate structured logging and consistent error handling
across destinations and the backup service.
"""

from __future__ import annotations

from typing import Any


class BackupError(Exception):
    """Base exception for backup-related errors.

    Args:
        message: Human-readable error message
        code: Stable machine-readable error code (e.g., "backup_error")
        details: Optional structured context/details for logging
    """

    def __init__(
        self, message: str, code: str = "backup_error", details: dict | None = None
    ):
        self.code = code
        self.details = details or {}
        super().__init__(message)


class BackupValidationError(BackupError):
    """Raised when backup validation fails.

    Args:
        message: Reason the validation failed
        field: Optional field/key associated with the failure
        value: Optional offending value for diagnostics (non-sensitive only)
    """

    def __init__(self, message: str, field: str | None = None, value: Any = None):
        details = {"field": field, "value": value}
        super().__init__(f"Validation failed: {message}", "validation_error", details)


class BackupStorageError(BackupError):
    """Raised when there are issues with backup storage (upload/download/list/delete)."""
