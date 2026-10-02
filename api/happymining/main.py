"""FastAPI application factory."""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import __version__
from .config import Settings, get_settings
from .db import get_engine
from .errors import AppError
from .logging_setup import configure_logging, request_id_var
from .security import constant_time_equal

log = logging.getLogger("happymining.api")

REQUESTS = Counter("hm_http_requests_total", "HTTP requests", ["method", "route", "status"])
LATENCY = Histogram("hm_http_request_seconds", "HTTP request duration", ["method", "route"])

DEVICE_BODY_LIMIT = 256 * 1024
DEFAULT_BODY_LIMIT = 1024 * 1024

DASHBOARD_DIR = Path(__file__).resolve().parents[2] / "dashboard"


def error_body(code: str, message: str) -> dict:
    return {"error": {"code": code, "message": message, "request_id": request_id_var.get()}}


class BodyLimitMiddleware:
    """Reject oversized request bodies before they are buffered."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        limit = (
            DEVICE_BODY_LIMIT
            if path.startswith(("/api/v1/device", "/api/v1/devices/enroll"))
            else DEFAULT_BODY_LIMIT
        )
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            await self._reject(send)
            return
        received = 0
        too_large = False

        async def limited_receive() -> Message:
            # Past the limit the application is told the client went away. It
            # must never be handed a truncated body as if it were complete: the
            # part already received could be a valid request on its own.
            nonlocal received, too_large
            if too_large:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    too_large = True
                    return {"type": "http.disconnect"}
            return message

        sent = False

        async def guarded_send(message: Message) -> None:
            nonlocal sent
            if too_large and not sent:
                sent = True
                await self._reject(send)
                return
            if not too_large:
                await send(message)

        await self.app(scope, limited_receive, guarded_send)

    @staticmethod
    async def _reject(send: Send) -> None:
        response = JSONResponse(
            error_body("payload_too_large", "The request body is too large."), status_code=413
        )
        await send({"type": "http.response.start", "status": 413, "headers": response.raw_headers})
        await send({"type": "http.response.body", "body": response.body})


class HostGuardMiddleware:
    """Host header allowlist, with ``/healthz`` exempt.

    Health probes come from inside the deployment (the container's own
    HEALTHCHECK, the reverse proxy) and address the service by an internal
    name. ``/healthz`` returns nothing but a static "ok", so it does not need
    the protection the allowlist gives every other route.
    """

    def __init__(self, app: ASGIApp, allowed_hosts: list[str]):
        self.app = app
        self.guarded = TrustedHostMiddleware(app, allowed_hosts=allowed_hosts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path") == "/healthz":
            await self.app(scope, receive, send)
            return
        await self.guarded(scope, receive, send)


def _route_label(request: Request) -> str:
    route = request.scope.get("route")
    return getattr(route, "path", "unmatched")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    log.info(
        "starting",
        extra={
            "mode": settings.mode,
            "provider": settings.provider,
            "version": __version__,
            "payouts_enabled": settings.payouts_enabled,
            "provider_mutations_enabled": settings.provider_mutations_enabled,
        },
    )
    # A DEMO process never opens a LIVE database, and the reverse. Checked
    # here, against the database itself, before the first request is served.
    from .services.system import ensure_database_mode

    ensure_database_mode(settings)
    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    # The DEMO / LIVE guard. A bad configuration never starts.
    settings.validate_for_startup()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="HappyMining OS API",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.is_demo else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.is_demo else None,
    )
    app.state.settings = settings

    app.add_middleware(BodyLimitMiddleware)
    if settings.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "Idempotency-Key"],
            max_age=600,
        )
    app.add_middleware(HostGuardMiddleware, allowed_hosts=settings.allowed_hosts or ["localhost"])

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = uuid.uuid4().hex
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        status = 500
        try:
            try:
                response = await call_next(request)
            except Exception as exc:
                # Handled here, inside the middleware, so that a 500 still gets
                # its request id and the security headers below.
                log.exception("unhandled error", extra={"error_type": type(exc).__name__})
                response = JSONResponse(error_body("internal_error", "Internal error."), status_code=500)
            status = response.status_code
        finally:
            elapsed = time.perf_counter() - started
            route = _route_label(request)
            REQUESTS.labels(request.method, route, str(status)).inc()
            LATENCY.labels(request.method, route).observe(elapsed)
            if route not in ("/healthz", "/metrics"):
                log.info(
                    "request",
                    extra={
                        "method": request.method,
                        "route": route,
                        "status": status,
                        "duration_ms": round(elapsed * 1000, 1),
                    },
                )
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = request_id
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
        )
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if settings.cookie_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    # --- error envelope ----------------------------------------------------

    def _wants_html(request: Request) -> bool:
        return not request.url.path.startswith("/api/")

    @app.exception_handler(AppError)
    async def app_error(request: Request, exc: AppError):
        if _wants_html(request):
            from .dashboard import TEMPLATES

            return TEMPLATES.TemplateResponse(
                request,
                "error.html",
                {"status": exc.status_code, "error_message": exc.message, "request_id": request_id_var.get()},
                status_code=exc.status_code,
                headers=exc.headers,
            )
        return JSONResponse(
            error_body(exc.code, exc.message), status_code=exc.status_code, headers=exc.headers
        )

    from .dashboard import LoginRequired

    @app.exception_handler(LoginRequired)
    async def login_required(_: Request, __: LoginRequired):
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError):
        # Field paths and reasons only. Submitted values are never echoed back.
        problems = [
            ".".join(str(p) for p in err.get("loc", ()) if p != "body")
            + ": "
            + str(err.get("msg", "invalid"))
            for err in exc.errors()[:5]
        ]
        return JSONResponse(
            error_body("invalid_request", "; ".join(problems) or "Invalid request."), status_code=422
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException):
        codes = {404: "not_found", 405: "method_not_allowed", 413: "payload_too_large"}
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return JSONResponse(
            error_body(codes.get(exc.status_code, "http_error"), message), status_code=exc.status_code
        )

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception):
        log.exception("unhandled error", extra={"error_type": type(exc).__name__})
        return JSONResponse(error_body("internal_error", "Internal error."), status_code=500)

    # --- health ------------------------------------------------------------

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", include_in_schema=False)
    def readyz():
        """Ready only when the database answers and the schema is at the expected revision."""
        from .migrate import expected_revision

        try:
            with get_engine().connect() as conn:
                current = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
        except Exception:
            return JSONResponse({"status": "not_ready", "database": "unreachable"}, status_code=503)
        expected = expected_revision()
        if current != expected:
            return JSONResponse(
                {
                    "status": "not_ready",
                    "database": "ok",
                    "schema": "migration pending",
                    "current": current,
                    "expected": expected,
                },
                status_code=503,
            )
        return {"status": "ready", "mode": settings.mode, "schema": current}

    @app.get("/metrics", include_in_schema=False)
    def metrics(request: Request):
        token = settings.metrics_token.get_secret_value() if settings.metrics_token else ""
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not token or not constant_time_equal(supplied, token):
            return PlainTextResponse("metrics require HM_METRICS_TOKEN\n", status_code=403)
        return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)

    # --- routers -----------------------------------------------------------

    from .dashboard import router as dashboard_router
    from .routers import auth, device, fleet, money, provider

    app.include_router(auth.router)
    app.include_router(device.router)
    app.include_router(fleet.router)
    app.include_router(provider.router)
    app.include_router(money.router)
    app.include_router(dashboard_router)
    static_dir = DASHBOARD_DIR / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
    return app


def app_factory() -> FastAPI:
    """Entry point for ``uvicorn happymining.main:app_factory --factory``."""
    return create_app()
