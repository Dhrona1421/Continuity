from __future__ import annotations

import logging
import re
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.memory import router as memory_router
from app.api.novabank import router as novabank_router
from app.api.routes import router
from app.api.visualizations import router as visualizations_router
from app.api.web_security import router as web_security_router
from app.core.bootstrap import seed_foundation
from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.logging import configure_logging
from app.services.detection import sync_rules
from app.services.web_detection import sync_web_rules

configure_logging()
logger = logging.getLogger(__name__)
CORRELATION_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")


@asynccontextmanager
async def lifespan(_: FastAPI):
    with SessionLocal() as db:
        seed_foundation(db)
        sigma_count = sync_rules(db)
        web_count = sync_web_rules(db)
        logger.info(
            "Continuity startup completed with %d Sigma-compatible and %d web detection rules",
            sigma_count,
            web_count,
        )
    yield


settings = get_settings()
app = FastAPI(
    title="Continuity Security Operations API",
    version="0.1.0",
    description="Security operations with Hindsight institutional memory and safe, policy-controlled response",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Correlation-ID",
        "X-GhostSOC-Token",
        "Idempotency-Key",
    ],
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    supplied = request.headers.get("X-Correlation-ID", "")
    correlation_id = supplied if CORRELATION_PATTERN.fullmatch(supplied) else str(uuid.uuid4())
    request.state.correlation_id = correlation_id
    started = time.monotonic()
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    logger.info(
        "%s %s -> %s in %.1fms",
        request.method,
        request.url.path,
        response.status_code,
        (time.monotonic() - started) * 1000,
        extra={"correlation_id": correlation_id},
    )
    return response


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": f"HTTP_{exc.status_code}",
                "message": str(exc.detail),
                "correlation_id": getattr(request.state, "correlation_id", None),
            }
        },
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = [{"location": list(item["loc"]), "message": item["msg"], "type": item["type"]} for item in exc.errors()]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed",
                "details": errors,
                "correlation_id": getattr(request.state, "correlation_id", None),
            }
        },
    )


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    correlation_id = getattr(request.state, "correlation_id", None)
    logger.exception("Unhandled request error", extra={"correlation_id": correlation_id})
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An internal error occurred",
                "correlation_id": correlation_id,
            }
        },
    )


app.include_router(router)
app.include_router(memory_router)
app.include_router(novabank_router)
app.include_router(web_security_router)
app.include_router(visualizations_router)


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {"service": "Continuity Security Operations API", "docs": "/docs", "health": "/api/v1/health"}
