from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from tacacs_server.exceptions import ConfigValidationError, TacacsServerError


def install_exception_handlers(app: FastAPI) -> None:
    """Install handlers that translate TacacsServerError to JSON responses."""

    @app.exception_handler(TacacsServerError)
    async def _handle_tacacs_error(request: Request, exc: TacacsServerError):
        # Special-case validation errors to match test expectations
        if isinstance(exc, ConfigValidationError):
            detail: dict[str, Any] = {
                "validation_errors": exc.details.get("errors")
                if isinstance(exc.details, dict)
                else None
            }
            return JSONResponse(status_code=exc.status_code, content={"detail": detail})

        payload: dict[str, Any] = {
            "error": exc.error_code,
            "message": exc.message,
            "details": exc.details,
            "timestamp": datetime.now(UTC).isoformat(),
            "path": str(request.url.path),
        }
        return JSONResponse(
            status_code=getattr(exc, "status_code", 500), content=payload
        )
