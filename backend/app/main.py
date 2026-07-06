"""FastAPI application entrypoint."""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import (
    accounts,
    assets,
    assistant,
    audit,
    auth,
    tags,
    users,
    connectors,
    connector_agents,
    credentials as credentials_api,
    dashboard,
    exceptions_api,
    exports,
    findings,
    password_policy,
    rules,
    scans,
    scan_profiles,
    schedules,
)
from app.config import get_settings, validate_startup_settings
from app.services.scheduler import build_scheduler

settings = get_settings()

logging.basicConfig(level=settings.log_level)
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        (
            structlog.processors.JSONRenderer()
            if settings.log_json
            else structlog.dev.ConsoleRenderer()
        ),
    ]
)
log = structlog.get_logger("adpct")


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_startup_settings(settings)
    log.info("adpct.startup", env=settings.env)
    scheduler = build_scheduler()
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)
    log.info("adpct.shutdown")


app = FastAPI(
    title="Account Discovery & Privilege Classification Tool",
    description="Internal platform for discovering and classifying privileged accounts.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-XSS-Protection": "1; mode=block",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    ),
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for header, value in _SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


@app.middleware("http")
async def access_log(request: Request, call_next):
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        log.exception("request.error", path=request.url.path, method=request.method)
        return JSONResponse(
            status_code=500, content={"detail": "Internal server error", "type": "server_error"}
        )
    elapsed_ms = (time.perf_counter() - start) * 1000
    log.info(
        "request",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        ms=round(elapsed_ms, 2),
    )
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/status")
def app_status() -> dict[str, str | bool]:
    return {
        "env": settings.env,
        "demo_mode": settings.demo_mode,
        "collector_mode": settings.collector_mode,
    }


# Routers
PREFIX = "/api/v1"
app.include_router(auth.router, prefix=PREFIX)
app.include_router(users.router, prefix=PREFIX)
app.include_router(assets.router, prefix=PREFIX)
app.include_router(assets.group_router, prefix=PREFIX)
app.include_router(connectors.router, prefix=PREFIX)
app.include_router(credentials_api.router, prefix=PREFIX)
app.include_router(scans.router, prefix=PREFIX)
app.include_router(scan_profiles.router, prefix=PREFIX)
app.include_router(schedules.router, prefix=PREFIX)
app.include_router(accounts.router, prefix=PREFIX)
app.include_router(findings.router, prefix=PREFIX)
app.include_router(rules.router, prefix=PREFIX)
app.include_router(exceptions_api.router, prefix=PREFIX)
app.include_router(exports.router, prefix=PREFIX)
app.include_router(dashboard.router, prefix=PREFIX)
app.include_router(audit.router, prefix=PREFIX)
app.include_router(assistant.router, prefix=PREFIX)
app.include_router(tags.router, prefix=PREFIX)
app.include_router(connector_agents.router, prefix=PREFIX)
app.include_router(password_policy.router, prefix=PREFIX)
