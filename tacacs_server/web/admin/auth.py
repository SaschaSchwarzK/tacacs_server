"""Admin authentication helpers."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from fastapi import HTTPException, Request, status


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
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )
        if not self._verify_password(password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )

        self._session_token = secrets.token_urlsafe(32)
        self._session_expiry = datetime.utcnow() + self.config.session_timeout
        return self._session_token

    def logout(self) -> None:
        self._session_token = None
        self._session_expiry = None

    def validate(self, token: str) -> bool:
        if not token or token != self._session_token:
            return False
        if not self._session_expiry or datetime.utcnow() > self._session_expiry:
            self.logout()
            return False
        return True

    def _verify_password(self, password: str) -> bool:
        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(password_hash, self.config.password_hash)


def get_admin_auth_dependency(session_manager: AdminSessionManager):
    async def dependency(request: Request) -> None:
        token = request.cookies.get("admin_session")
        if not token or not session_manager.validate(token):
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT, 
                detail="Unauthorized", 
                headers={"Location": "/admin/login"}
            )

    return dependency
