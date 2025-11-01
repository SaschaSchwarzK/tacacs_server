"""Admin authentication helpers."""

from __future__ import annotations

from tacacs_server.utils.logger import get_logger
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, status

from tacacs_server.exceptions import AuthenticationError

logger = get_logger(__name__)


class AdminAuthConfig:
    """Runtime configuration for admin auth."""

    def __init__(
        self, username: str, password_hash: str, session_timeout_minutes: int = 60
    ) -> None:
        if not username or not isinstance(username, str):
            raise ValueError("Username must be a non-empty string")
        if not password_hash or not isinstance(password_hash, str):
            raise ValueError("Password hash must be a non-empty string")
        if not isinstance(session_timeout_minutes, int) or session_timeout_minutes <= 0:
            raise ValueError("Session timeout must be a positive integer")

        self.username = username.strip()
        self.password_hash = password_hash
        self.session_timeout = timedelta(minutes=session_timeout_minutes)


class AdminSessionManager:
    """Simple in-memory session store."""

    def __init__(self, config: AdminAuthConfig) -> None:
        self.config = config
        self._session_token: str | None = None
        self._session_expiry: datetime | None = None

    def login(self, username: str, password: str) -> str:
        if username != self.config.username:
            raise AuthenticationError("Invalid credentials")
        if not self._verify_password(password):
            raise AuthenticationError("Invalid credentials")

        self._session_token = secrets.token_urlsafe(32)
        self._session_expiry = datetime.now(UTC) + self.config.session_timeout
        return self._session_token

    def logout(self) -> None:
        self._session_token = None
        self._session_expiry = None

    def validate(self, token: str) -> bool:
        if not token or token != self._session_token:
            return False
        if not self._session_expiry or datetime.now(UTC) > self._session_expiry:
            self.logout()
            return False
        return True

    def _verify_password(self, password: str) -> bool:
        """Verify admin password using bcrypt.

        - Returns True on successful match, False on mismatch or internal error.
        - Emits precise log messages for: missing bcrypt, unsupported hash,
          mismatch, and unexpected errors.
        """
        cfg_hash = self.config.password_hash or ""

        # Only bcrypt hashes are supported for admin auth
        if not cfg_hash.startswith(("$2a$", "$2b$", "$2y$")):
            logger.warning(
                "Admin login rejected: unsupported admin hash format configured; bcrypt required"
            )
            raise AuthenticationError(
                "Legacy admin password hashes are not supported. Please migrate ADMIN_PASSWORD_HASH to bcrypt."
            )

        # Import bcrypt explicitly and provide clear diagnostics
        try:
            import bcrypt
        except Exception as exc:  # ImportError or runtime linking error
            logger.error("Admin login failed: bcrypt module unavailable: %s", exc)
            return False

        try:
            ok = bcrypt.checkpw(password.encode("utf-8"), cfg_hash.encode("utf-8"))
        except Exception as exc:
            logger.error("Admin login failed: bcrypt verification error: %s", exc)
            return False

        if not ok:
            logger.warning("Admin login failed: password mismatch for configured user")
            return False

        return True


def get_admin_auth_dependency(session_manager: AdminSessionManager):
    async def dependency(request: Request) -> None:
        token = request.cookies.get("admin_session")
        if not token or not session_manager.validate(token):
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                detail="Unauthorized",
                headers={"Location": "/admin/login"},
            )

    return dependency
