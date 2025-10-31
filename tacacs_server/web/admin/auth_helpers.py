from __future__ import annotations

import logging
from fastapi import HTTPException, Request, status

from tacacs_server.web.web_auth import get_session_manager as get_admin_session_manager

logger = logging.getLogger("tacacs.admin.auth")


def check_admin_auth(request: Request) -> None:
    """Check admin authentication without consuming request body.

    Validates the `admin_session` cookie against the configured session manager.
    Raises appropriate HTTPException on failure. Does not read the request body.
    """
    session_token = request.cookies.get("admin_session")
    try:
        logger.info(
            "check_admin_auth: path=%s method=%s has_cookie=%s content_type=%s accept=%s",
            getattr(request.url, "path", ""),
            getattr(request, "method", ""),
            bool(session_token),
            request.headers.get("content-type", ""),
            request.headers.get("accept", ""),
        )
    except Exception:
        pass
    if not session_token:
        logger.warning("check_admin_auth: missing admin_session cookie")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )

    session_mgr = get_admin_session_manager()
    if not session_mgr:
        logger.error("check_admin_auth: no session manager configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication not available",
        )

    ok = session_mgr.validate_session(session_token)
    if not ok:
        logger.warning("check_admin_auth: session invalid or expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )
    else:
        logger.debug("check_admin_auth: session valid")
