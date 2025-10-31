from __future__ import annotations

from fastapi import HTTPException, Request, status

from tacacs_server.web.web import get_admin_session_manager


def check_admin_auth(request: Request) -> None:
    """Check admin authentication without consuming request body.

    Validates the `admin_session` cookie against the configured session manager.
    Raises appropriate HTTPException on failure. Does not read the request body.
    """
    session_token = request.cookies.get("admin_session")
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )

    session_mgr = get_admin_session_manager()
    if not session_mgr:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication not available",
        )

    if not session_mgr.validate_session(session_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )
