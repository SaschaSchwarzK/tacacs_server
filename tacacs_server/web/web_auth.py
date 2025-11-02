"""
Simplified Authentication Module
Handles both admin web sessions and API token authentication
"""

import os
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, status

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class AuthConfig:
    """Authentication configuration"""

    def __init__(
        self,
        admin_username: str,
        admin_password_hash: str,
        api_token: str | None = None,
        session_timeout_minutes: int = 60,
    ):
        self.admin_username = admin_username
        self.admin_password_hash = admin_password_hash
        self.api_token = api_token or os.getenv("API_TOKEN")
        self.session_timeout = timedelta(minutes=session_timeout_minutes)


class SessionManager:
    """Simple in-memory session management"""

    def __init__(self, config: AuthConfig):
        self.config = config
        self._sessions: dict[str, datetime] = {}

    def create_session(self, username: str, password: str) -> str:
        """Create new session after verifying credentials"""
        if not self._verify_credentials(username, password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        token = secrets.token_urlsafe(32)
        self._sessions[token] = datetime.now(UTC) + self.config.session_timeout
        logger.info(
            "Admin session created",
            event="admin.session.created",
            service="web",
            component="web_auth",
            user_ref=username,
            session_id="[opaque]",
        )
        return token

    def validate_session(self, token: str) -> bool:
        """Check if session token is valid"""
        if not token or token not in self._sessions:
            return False

        expiry = self._sessions[token]
        if datetime.now(UTC) > expiry:
            self._sessions.pop(token, None)
            return False

        return True

    def delete_session(self, token: str):
        """Remove session"""
        self._sessions.pop(token, None)

    def _verify_credentials(self, username: str, password: str) -> bool:
        """Verify username and password"""
        if username != self.config.admin_username:
            return False

        try:
            import bcrypt

            return bcrypt.checkpw(
                password.encode("utf-8"),
                self.config.admin_password_hash.encode("utf-8"),
            )
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False


# Global instances (set by main app)
_auth_config: AuthConfig | None = None
_session_manager: SessionManager | None = None


def init_auth(
    admin_username: str,
    admin_password_hash: str,
    api_token: str | None = None,
    session_timeout: int = 60,
):
    """Initialize authentication system"""
    global _auth_config, _session_manager
    _auth_config = AuthConfig(
        admin_username, admin_password_hash, api_token, session_timeout
    )
    _session_manager = SessionManager(_auth_config)
    logger.info(
        "Authentication system initialized",
        event="auth.init",
        service="web",
        component="web_auth",
        admin_user=admin_username,
        api_token_configured=bool(api_token or os.getenv("API_TOKEN")),
    )


def get_session_manager() -> SessionManager | None:
    """Get session manager instance"""
    return _session_manager


def get_auth_config() -> AuthConfig | None:
    """Get auth config instance"""
    return _auth_config


# Dependency functions for FastAPI routes
async def require_admin_session(request: Request):
    """Require valid admin session (for web UI)"""
    if not _session_manager:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication not configured",
        )

    token = request.cookies.get("admin_session")
    if not token or not _session_manager.validate_session(token):
        # Redirect to login for HTML requests
        if "text/html" in request.headers.get("accept", ""):
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": "/admin/login"},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
        )


async def require_api_token(request: Request):
    """Require valid API token (for API endpoints)

    Accepts either the token configured at init_auth or, if missing,
    the current value of the API_TOKEN environment variable. This makes
    bearer-token auth robust in test environments that set API_TOKEN
    via monkeypatch after app init.
    """
    configured = _auth_config.api_token if _auth_config else None
    env_token = os.getenv("API_TOKEN")
    expected = configured or env_token
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API not configured",
        )

    # Check X-API-Token header
    token = request.headers.get("X-API-Token")

    # Fall back to Authorization Bearer
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
    if not token or token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API token",
        )


async def require_admin_or_api(request: Request):
    """Allow either admin session OR API token"""
    # Try session first
    token = request.cookies.get("admin_session")
    if token and _session_manager and _session_manager.validate_session(token):
        return

    # Try API token
    try:
        await require_api_token(request)
    except HTTPException:
        # Both failed, redirect or reject
        if "text/html" in request.headers.get("accept", ""):
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": "/admin/login"},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
