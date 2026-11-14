"""Sanitized error handling for FastAPI application.

Ensures that internal stack traces, personal paths, environment variables,
and cryptographic secrets are never exposed to API consumers in error payloads.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger("network_anomaly.api")

# Patterns that must never appear in error outputs
SENSITIVE_PATTERNS = ["key", "secret", "token", "password", "auth", "credential"]


class ModelNotReadyError(HTTPException):
    """Raised when verified ML model artifacts are missing or unready and fallback disabled."""

    def __init__(
        self,
        detail: str = "Verified inference model is not ready and heuristic fallback is disabled.",
    ):
        super().__init__(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail)


def _sanitize_message(message: str) -> str:
    """Strip or redact sensitive tokens from outgoing error messages."""
    lower = message.lower()
    for pattern in SENSITIVE_PATTERNS:
        if f"{pattern}=" in lower or f"{pattern}:" in lower or f'"{pattern}"' in lower:
            return "Request contained invalid parameters or sensitive data."
    # Prevent traceback leaks
    if "traceback (most recent call last)" in lower or 'file "' in lower:
        return "Internal server processing failure."
    return message


def register_error_handlers(app: FastAPI) -> None:
    """Register fail-safe sanitized exception handlers on the FastAPI app."""

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "HTTPException",
                "detail": _sanitize_message(detail),
                "status_code": exc.status_code,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = []
        for err in exc.errors():
            loc = " -> ".join(str(part) for part in err.get("loc", []))
            msg = err.get("msg", "Validation error")
            errors.append(f"{loc}: {msg}")
        joined = "; ".join(errors)
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "ValidationError",
                "detail": _sanitize_message(joined),
                "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
            },
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "BadRequest",
                "detail": _sanitize_message(str(exc)),
                "status_code": status.HTTP_400_BAD_REQUEST,
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled API exception on %s: %s", request.url.path, exc, exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "InternalServerError",
                "detail": "An unexpected error occurred. No sensitive details are exposed.",
                "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
            },
        )
