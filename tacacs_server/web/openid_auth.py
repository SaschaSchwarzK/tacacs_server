"""
OpenID Connect (OIDC) Authentication Module
Handles OAuth2/OIDC token exchange and user session mapping.
"""

import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

import requests
from requests.exceptions import RequestException

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class OpenIDConfig:
    """OpenID Connect provider configuration."""

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: str = "openid profile email",
        token_endpoint: Optional[str] = None,
        userinfo_endpoint: Optional[str] = None,
        session_timeout_minutes: int = 60,
        allowed_groups: Optional[list[str]] = None,
        use_interaction_code: bool = False,
        code_verifier: Optional[str] = None,
    ):
        """
        Args:
            issuer_url: OIDC provider issuer URL (e.g., https://accounts.google.com)
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret
            redirect_uri: Redirect URI registered with provider (e.g., https://app.local/admin/callback)
            scopes: Space-separated scopes to request
            token_endpoint: Custom token endpoint URL (auto-discovered if None)
            userinfo_endpoint: Custom userinfo endpoint URL (auto-discovered if None)
            session_timeout_minutes: Session expiry in minutes
        """
        cleaned_issuer = (issuer_url or "").strip().rstrip("/")
        if not cleaned_issuer.startswith("http"):
            raise ValueError(f"Invalid issuer_url: {issuer_url!r}")
        if "…" in cleaned_issuer or cleaned_issuer.startswith("..."):
            raise ValueError(f"issuer_url looks truncated/placeholder: {issuer_url!r}")
        self.issuer_url = cleaned_issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.session_timeout = timedelta(minutes=session_timeout_minutes)
        self.allowed_groups = allowed_groups or []
        self.use_interaction_code = use_interaction_code
        self.code_verifier = code_verifier
        
        # Endpoints - will be auto-discovered from .well-known/openid-configuration if not provided
        self._token_endpoint = token_endpoint
        self._userinfo_endpoint = userinfo_endpoint
        self._authorization_endpoint: Optional[str] = None
        self._endpoints_loaded = False

    def _load_endpoints(self) -> None:
        """Auto-discover token and userinfo endpoints from OIDC metadata."""
        if self._endpoints_loaded:
            return
        
        try:
            metadata_url = f"{self.issuer_url}/.well-known/openid-configuration"
            resp = requests.get(metadata_url, timeout=5)
            resp.raise_for_status()
            metadata = resp.json()
            
            if not self._token_endpoint:
                self._token_endpoint = metadata.get("token_endpoint")
            if not self._userinfo_endpoint:
                self._userinfo_endpoint = metadata.get("userinfo_endpoint")
            if not self._authorization_endpoint:
                self._authorization_endpoint = metadata.get("authorization_endpoint")
            
            self._endpoints_loaded = True
            logger.debug(
                "OpenID endpoints discovered",
                event="admin.openid.discovery",
                metadata_url=metadata_url,
            )
        except RequestException as e:
            logger.error(
                "Failed to discover OpenID endpoints",
                event="admin.openid.discovery_failed",
                error=str(e),
                metadata_url=f"{self.issuer_url}/.well-known/openid-configuration",
            )
            raise

    @property
    def token_endpoint(self) -> str:
        """Get token endpoint, auto-discovering if needed."""
        self._load_endpoints()
        if not self._token_endpoint:
            raise RuntimeError("Token endpoint not configured and could not be auto-discovered")
        return self._token_endpoint

    @property
    def userinfo_endpoint(self) -> str:
        """Get userinfo endpoint, auto-discovering if needed."""
        self._load_endpoints()
        if not self._userinfo_endpoint:
            raise RuntimeError("Userinfo endpoint not configured and could not be auto-discovered")
        return self._userinfo_endpoint


class OpenIDSession:
    """Represents an authenticated user session."""

    def __init__(self, email: str, access_token: str, expires_at: datetime):
        self.email = email
        self.access_token = access_token
        self.expires_at = expires_at

    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.now(UTC) >= self.expires_at


class OpenIDManager:
    """Manages OpenID Connect authentication and user sessions."""

    def __init__(self, config: OpenIDConfig):
        self.config = config
        self._sessions: dict[str, OpenIDSession] = {}

    def get_authorization_url(self, state: str) -> str:
        """Generate authorization URL for redirect to OIDC provider."""
        # Ensure endpoints are loaded so we use the discovered authorization_endpoint when available
        try:
            self.config._load_endpoints()
        except Exception:
            pass
        params: dict[str, str] = {
            "client_id": self.config.client_id,
            "response_type": "code",
            "scope": self.config.scopes,
            "redirect_uri": self.config.redirect_uri,
            "state": state,
        }
        # Include PKCE code_challenge when a code_verifier is supplied (public clients)
        if self.config.code_verifier:
            try:
                import hashlib
                import base64

                digest = hashlib.sha256(self.config.code_verifier.encode("ascii")).digest()
                challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
                params["code_challenge"] = challenge
                params["code_challenge_method"] = "S256"
            except Exception:
                logger.warning("Failed to compute PKCE code_challenge; continuing without it")
        # Prefer discovered authorization_endpoint; fallback to standard Okta path
        auth_base = (
            getattr(self.config, "_authorization_endpoint", None)
            or f"{self.config.issuer_url}/oauth2/v1/authorize"
        )
        return f"{auth_base}?{urlencode(params)}"

    def exchange_code_for_token(self, code: str) -> dict:
        """
        Exchange authorization code for access token.
        
        Returns:
            dict with 'access_token', 'token_type', 'expires_in', 'id_token', etc.
        """
        grant_type = (
            "interaction_code" if self.config.use_interaction_code else "authorization_code"
        )
        payload = {
            "grant_type": grant_type,
            "code": code,
            "client_id": self.config.client_id,
        }
        if self.config.client_secret:
            payload["client_secret"] = self.config.client_secret
        # For both interaction_code and auth code with PKCE, include code_verifier when provided.
        if self.config.code_verifier:
            payload["code_verifier"] = self.config.code_verifier
        payload["redirect_uri"] = self.config.redirect_uri
        
        try:
            resp = requests.post(self.config.token_endpoint, data=payload, timeout=10)
            resp.raise_for_status()
            token_response = resp.json()
            logger.debug(
                "OpenID token exchange successful",
                event="admin.openid.token_exchange",
            )
            return token_response
        except RequestException as e:
            logger.error(
                "OpenID token exchange failed",
                event="admin.openid.token_exchange_failed",
                error=str(e),
            )
            raise

    def get_user_info(self, access_token: str) -> dict:
        """
        Fetch user info using access token.
        
        Returns:
            dict with 'sub', 'email', 'name', etc.
        """
        headers = {"Authorization": f"Bearer {access_token}"}
        
        try:
            resp = requests.get(self.config.userinfo_endpoint, headers=headers, timeout=10)
            resp.raise_for_status()
            user_info = resp.json()
            logger.debug(
                "OpenID user info retrieved",
                event="admin.openid.userinfo",
                user_email=user_info.get("email", "unknown"),
            )
            return user_info
        except RequestException as e:
            logger.error(
                "Failed to fetch OpenID user info",
                event="admin.openid.userinfo_failed",
                error=str(e),
            )
            raise

    def create_session(self, code: str) -> tuple[str, str]:
        """
        Complete OIDC flow: exchange code for token, get user info, create session.
        
        Args:
            code: Authorization code from OIDC provider
            
        Returns:
            (session_token, user_email)
        """
        # Exchange code for access token
        token_response = self.exchange_code_for_token(code)
        access_token = token_response.get("access_token")
        expires_in = token_response.get("expires_in", 3600)
        
        # Get user info
        user_info = self.get_user_info(access_token)
        email = user_info.get("email")
        user_groups_raw = user_info.get("groups") or []
        if isinstance(user_groups_raw, str):
            user_groups = [g.strip() for g in user_groups_raw.split(",") if g.strip()]
        else:
            user_groups = [str(g) for g in user_groups_raw] if user_groups_raw else []

        if not email:
            raise ValueError("User info missing 'email' claim")

        # Emit the groups returned by the IdP to aid troubleshooting when group checks fail.
        try:
            logger.debug(
                "OpenID userinfo groups received",
                event="admin.openid.userinfo.groups",
                user_email=email,
                groups=user_groups,
                allowed_groups=self.config.allowed_groups,
            )
        except Exception:
            pass  # Logging failure should not break auth

        if self.config.allowed_groups:
            if not any(g in self.config.allowed_groups for g in user_groups):
                logger.warning(
                    "OpenID user not in allowed groups",
                    event="admin.openid.group_reject",
                    user_email=email,
                    groups=user_groups,
                    allowed_groups=self.config.allowed_groups,
                )
                raise ValueError("User not in allowed OpenID group")
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        session = OpenIDSession(email, access_token, expires_at)
        self._sessions[session_token] = session
        
        logger.info(
            "OpenID session created",
            event="admin.openid.session_created",
            user_email=email,
        )
        return session_token, email

    def validate_session(self, session_token: str) -> Optional[str]:
        """
        Validate session token and return user email if valid.
        
        Returns:
            user email if valid, None if invalid/expired
        """
        session = self._sessions.get(session_token)
        
        if not session:
            return None
        
        if session.is_expired():
            self._sessions.pop(session_token, None)
            logger.debug(
                "OpenID session expired",
                event="admin.openid.session_expired",
                user_email=session.email,
            )
            return None
        
        return session.email

    def delete_session(self, session_token: str) -> None:
        """Remove session."""
        if session_token in self._sessions:
            session = self._sessions.pop(session_token)
            logger.info(
                "OpenID session deleted",
                event="admin.openid.session_deleted",
                user_email=session.email,
            )

    def cleanup_expired_sessions(self) -> int:
        """Remove all expired sessions. Returns count of removed sessions."""
        expired = [
            token for token, session in self._sessions.items() if session.is_expired()
        ]
        for token in expired:
            self._sessions.pop(token, None)
        
        if expired:
            logger.debug(
                "Cleaned up expired OpenID sessions",
                event="admin.openid.session_cleanup",
                count=len(expired),
            )
        return len(expired)
