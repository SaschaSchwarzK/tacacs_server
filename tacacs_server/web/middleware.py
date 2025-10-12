"""Reusable web middleware helpers (security headers, etc.)."""

from __future__ import annotations

import os

from fastapi import FastAPI

DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:;"
)


def install_security_headers(app: FastAPI) -> None:
    """Install a lightweight middleware that sets common security headers.

    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - Referrer-Policy: no-referrer
    - Content-Security-Policy: configurable via CSP_POLICY env, defaults relaxed
    - Strict-Transport-Security: only when HTTPS or X-Forwarded-Proto=https
    """

    csp_policy = os.getenv("CSP_POLICY", DEFAULT_CSP)
    hsts_max_age = os.getenv("HSTS_MAX_AGE", "31536000")

    @app.middleware("http")
    async def _security_headers(request, call_next):
        resp = await call_next(request)
        # Core headers
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Content-Security-Policy", csp_policy)
        # HSTS only when behind TLS
        fwd = request.headers.get("x-forwarded-proto", "").lower()
        if request.url.scheme == "https" or fwd == "https":
            resp.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={hsts_max_age}; includeSubDomains",
            )
        return resp
