"""FastAPI application factory and middleware wiring for CYBERQ."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from cyberq.api.health import router as health_router
from cyberq.api.middleware import SecurityHeadersMiddleware
from cyberq.api.routes_admin import router as admin_router
from cyberq.api.routes_audit import router as audit_router
from cyberq.api.routes_auth import router as auth_router
from cyberq.api.routes_decisions import router as decisions_router
from cyberq.api.routes_exposure import router as exposure_router
from cyberq.api.routes_filings import router as filings_router
from cyberq.api.routes_incidents import router as incidents_router
from cyberq.api.routes_intake import router as intake_router
from cyberq.api.routes_telemetry import router as telemetry_router
from cyberq.api.routes_verification import router as verification_router
from cyberq.api.routes.reports import router as reports_router
from cyberq.core.config import get_settings
from cyberq.core.database import init_db
from cyberq.core.logging import configure_logging

settings = get_settings()
logger = structlog.get_logger("cyberq.api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    configure_logging()
    init_db()
    try:
        from cyberq.core.database import SessionLocal
        from cyberq.core.demo_seed import seed_demo_data

        with SessionLocal() as session:
            seed_demo_data(session)
    except Exception as e:
        logger.warning("seed_demo_data_skipped", error=str(e))
    logger.info("cyberq_startup", env=settings.ENV.value, version=settings.APP_VERSION)
    yield
    logger.info("cyberq_shutdown")


def create_app() -> FastAPI:
    is_prod = settings.is_production()
    app = FastAPI(
        title="CYBERQ API",
        version=settings.APP_VERSION,
        docs_url="/docs" if not is_prod else None,
        redoc_url=None,
        openapi_url="/openapi.json" if not is_prod else None,
        lifespan=lifespan,
    )

    # Attach bank-grade security middleware
    app.add_middleware(SecurityHeadersMiddleware)

    # Standardized error handling preventing internal leaks
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        request_id = request.headers.get("X-Request-ID")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error_code": "VALIDATION_ERROR",
                "message": "Input validation failed",
                "request_id": request_id,
                "details": jsonable_encoder(exc.errors()),
            },
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        request_id = request.headers.get("X-Request-ID")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error_code": f"HTTP_{exc.status_code}",
                "message": exc.detail if isinstance(exc.detail, str) else "Request error",
                "request_id": request_id,
                "detail": exc.detail,
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = request.headers.get("X-Request-ID")
        logger.error("unhandled_server_exception", error=str(exc), request_id=request_id)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error_code": "INTERNAL_SERVER_ERROR",
                "message": "An internal server error occurred. Please contact the system administrator.",
                "request_id": request_id,
            },
        )

    # Routes
    app.include_router(health_router)
    app.include_router(admin_router, prefix="/api/v1")
    app.include_router(telemetry_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(audit_router, prefix="/api/v1")
    app.include_router(incidents_router, prefix="/api/v1")
    app.include_router(intake_router, prefix="/api/v1")
    app.include_router(filings_router, prefix="/api/v1")
    app.include_router(decisions_router, prefix="/api/v1")
    app.include_router(exposure_router, prefix="/api/v1")
    app.include_router(verification_router, prefix="/api/v1")
    app.include_router(reports_router, prefix="/api/v1")

    # Serve compiled production frontend if available
    web_dist = Path(__file__).resolve().parent.parent.parent.parent.parent / "web" / "dist"
    if web_dist.is_dir():
        assets_dir = web_dist / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        @app.get("/{full_path:path}")
        async def serve_frontend_spa(full_path: str) -> FileResponse:
            if (
                full_path.startswith("api/")
                or full_path == "api"
                or full_path in ("docs", "redoc", "openapi.json")
            ):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Not found"
                )
            target = web_dist / full_path
            if target.is_file():
                return FileResponse(target)
            index_file = web_dist / "index.html"
            if index_file.is_file():
                return FileResponse(index_file)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Frontend file not found"
            )

    return app


app = create_app()
