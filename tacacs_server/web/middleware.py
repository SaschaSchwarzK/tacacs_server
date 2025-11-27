"""Reusable web middleware helpers (security headers, etc.)."""

from __future__ import annotations

import os

from fastapi import FastAPI

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_CSP = (
    "default-src 'self'; "
    # Allow inline scripts for the admin UI templates (modals, buttons).
    # For stricter environments, override via CSP_POLICY env and use nonces.
    "script-src 'self' 'unsafe-inline'; "
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
    - Cache-Control/Pragma: no-store (avoid caching sensitive admin/API content)
    - Permissions-Policy: deny active sensors by default
    - COOP/COEP/CORP: tighten isolation to mitigate Spectre-type attacks
    - Strict-Transport-Security: only when HTTPS or X-Forwarded-Proto=https
    """

    csp_policy = os.getenv("CSP_POLICY", DEFAULT_CSP)
    hsts_max_age = os.getenv("HSTS_MAX_AGE", "31536000")
    _coep_exempt_paths = {"/docs", "/redoc", "/rapidoc", "/openapi.json", "/openapi.yaml", "/api/docs", "/api/redoc"}

    @app.middleware("http")
    async def _security_headers(request, call_next):
        resp = await call_next(request)

        # Core security headers
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Content-Security-Policy", csp_policy)
        resp.headers.setdefault("X-XSS-Protection", "1; mode=block")
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Pragma", "no-cache")
        resp.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        if request.url.path not in _coep_exempt_paths:
            resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
            resp.headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
            resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

        # HSTS for HTTPS or when forwarded as HTTPS
        fwd = request.headers.get("x-forwarded-proto", "").lower()
        if request.url.scheme == "https" or fwd == "https":
            resp.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={hsts_max_age}; includeSubDomains",
            )

        # Enhanced removal: strip all identifying headers
        HEADERS_TO_REMOVE = [
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-aspnetmvc-version",
            "x-runtime",
            "x-version",
            "x-generator",
        ]
        try:
            for h_to_remove in HEADERS_TO_REMOVE:
                for key in list(resp.headers.keys()):
                    if key.lower() == h_to_remove.lower():
                        del resp.headers[key]
        except Exception as exc:
            logger.warning("Failed to remove default headers: %s", exc)

        # Fallback: if a Server header still appears, replace with generic
        try:
            has_server = any(k.lower() == "server" for k in resp.headers.keys())
            if has_server:
                for key in list(resp.headers.keys()):
                    if key.lower() == "server":
                        del resp.headers[key]
                resp.headers["Server"] = "AAA-Server"
        except Exception as exc:
            logger.warning("Failed to scrub Server header: %s", exc)

        return resp
