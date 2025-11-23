"""
Simplified Authentication Module
Handles both admin web sessions (password + OpenID) and API token authentication
"""

import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import Optional

from fastapi import HTTPException, Request, status

from tacacs_server.utils.logger import get_logger
from tacacs_server.web.openid_auth import OpenIDManager, OpenIDConfig

logger = get_logger(__name__)


class AuthConfig:
    """Authentication configuration"""

    def __init__(
        self,
        admin_username: str,
        admin_password_hash: str,
        api_token: str | None = None,
        session_timeout_minutes: int = 60,
        openid_config: Optional[OpenIDConfig] = None,
    ):
        self.admin_username = admin_username
        self.admin_password_hash = admin_password_hash
        self.api_token = api_token or os.getenv("API_TOKEN")
        self.session_timeout = timedelta(minutes=session_timeout_minutes)
        self.openid_config = openid_config


class SessionManager:
    """In-memory session management with support for both password and OpenID auth."""

    def __init__(self, config: AuthConfig):
        self.config = config
        # Maps session_token -> (expiry, email/username)
        # For password auth: email/username is the admin username
        # For OpenID auth: email/username is the user's email
        self._sessions: dict[str, tuple[datetime, str]] = {}
        self.openid_manager: Optional[OpenIDManager] = None
        if config.openid_config:
            self.openid_manager = OpenIDManager(config.openid_config)

    def create_password_session(self, username: str, password: str) -> str:
        """Create session after verifying password credentials"""
        if not self._verify_credentials(username, password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        token = secrets.token_urlsafe(32)
        expiry = datetime.now(UTC) + self.config.session_timeout
        self._sessions[token] = (expiry, username)
        logger.info(
            "Admin session created via password",
            event="admin.session.created",
            service="web",
            component="web_auth",
            user_email=username,
            auth_method="password",
            session_id="[opaque]",
        )
        return token

    def create_openid_session(self, code: str) -> tuple[str, str]:
        """Create session from OpenID authorization code. Returns (session_token, user_email)"""
        if not self.openid_manager:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OpenID not configured",
            )

        try:
            openid_session_token, user_email = self.openid_manager.create_session(code)
            # Map OpenID session token to our session store
            expiry = datetime.now(UTC) + self.config.session_timeout
            self._sessions[openid_session_token] = (expiry, user_email)
            logger.info(
                "Admin session created via OpenID",
                event="admin.session.created",
                service="web",
                component="web_auth",
                user_email=user_email,
                auth_method="openid",
                session_id="[opaque]",
            )
            return openid_session_token, user_email
        except ValueError as e:
            # Preserve validation feedback (e.g., user not in allowed groups) for the caller/UI.
            logger.error(
                "OpenID session creation failed",
                event="admin.openid.session_error",
                service="web",
                component="web_auth",
                error=str(e),
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
            )
        except Exception as e:
            logger.error(
                "OpenID session creation failed",
                event="admin.openid.session_error",
                service="web",
                component="web_auth",
                error=str(e),
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OpenID authentication failed",
            )

    def validate_session(self, token: str) -> Optional[str]:
        """
        Validate session token and return user email/identifier if valid.
        
        Returns:
            user email if valid, None if invalid/expired
        """
        if not token or token not in self._sessions:
            return None

        expiry, user_identifier = self._sessions[token]
        if datetime.now(UTC) > expiry:
            self._sessions.pop(token, None)
            return None

        return user_identifier

    def delete_session(self, token: str):
        """Remove session"""
        if token in self._sessions:
            _, user_identifier = self._sessions.pop(token)
            logger.info(
                "Admin session deleted",
                event="admin.session.deleted",
                service="web",
                component="web_auth",
                user_email=user_identifier,
                session_id="[opaque]",
            )

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
    openid_config: Optional[OpenIDConfig] = None,
):
    """Initialize authentication system"""
    global _auth_config, _session_manager
    if openid_config:
        env_groups = os.getenv("OPENID_ADMIN_GROUPS", "")
        if env_groups and not getattr(openid_config, "allowed_groups", None):
            openid_config.allowed_groups = [
                g.strip() for g in env_groups.split(",") if g.strip()
            ]
    _auth_config = AuthConfig(
        admin_username, admin_password_hash, api_token, session_timeout, openid_config
    )
    _session_manager = SessionManager(_auth_config)
    logger.info(
        "Authentication system initialized",
        event="auth.init",
        service="web",
        component="web_auth",
        admin_user=admin_username,
        api_token_configured=bool(api_token or os.getenv("API_TOKEN")),
        openid_enabled=openid_config is not None,
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
        if "text/html" in request.headers.get("accept", ""):
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": "/admin/login"},
            )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication not configured",
        )

    token = request.cookies.get("admin_session")
    user_email = _session_manager.validate_session(token) if token else None
    
    if not user_email:
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
