"""Security headers, request-ID tracing, and sanitized error middleware."""

import uuid

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

from cyberq.core.config import get_settings

settings = get_settings()
logger = structlog.get_logger("cyberq.api")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforces bank-grade HTTP response security headers."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Request tracing
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)

        # Append standard security headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # Prevent caching of API responses containing sensitive regulatory data
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"

        if settings.COOKIE_SECURE or settings.is_production():
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        if settings.STRICT_CSP:
            # Bank-grade strict CSP: no external CDNs, no fonts from Google, no unhashed inline scripts
            csp_directives = [
                "default-src 'self'",
                "script-src 'self'",
                "style-src 'self' 'unsafe-inline'",  # Tailwind/Radix inline styles
                "img-src 'self' data:",
                "font-src 'self'",
                "connect-src 'self'",
                "object-src 'none'",
                "frame-ancestors 'none'",
                "base-uri 'self'",
                "form-action 'self'",
            ]
            response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        return response
