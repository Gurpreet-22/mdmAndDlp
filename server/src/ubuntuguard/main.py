"""FastAPI application factory.

Run with uvicorn's factory mode, so importing this module has no side effects
and in particular opens no database connection:

    uvicorn ubuntuguard.main:create_app --factory --host 127.0.0.1 --port 8000

Binding to 127.0.0.1 is part of the design, not a dev convenience. The device
plane's identity comes from headers nginx sets, so the application must be
reachable only through nginx. See `security/device_auth.py`.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from ubuntuguard import problems
from ubuntuguard.config import Settings
from ubuntuguard.problems import FieldError

logger = logging.getLogger("ubuntuguard")

REQUEST_ID_HEADER = "X-Request-Id"

#: Client-supplied request ids are echoed so a caller can correlate, but they
#: are bounded and sanitised: the value reaches logs and the audit trail, and an
#: unbounded header there would be a log-injection vector.
MAX_REQUEST_ID_LENGTH = 64
_REQUEST_ID_SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def _sanitise_request_id(value: str | None) -> str:
    """Echo a client's request id, or substitute a fresh one.

    Over-long values are REPLACED rather than truncated. Truncating would map
    two different client ids onto the same server id whenever they share a
    64-character prefix, so correlation would quietly break in exactly the
    situation where someone is relying on it.
    """
    if not value or len(value) > MAX_REQUEST_ID_LENGTH:
        return uuid.uuid4().hex
    if all(character in _REQUEST_ID_SAFE for character in value):
        return value
    return uuid.uuid4().hex


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a request id to every request, response and log line."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = _sanitise_request_id(request.headers.get(REQUEST_ID_HEADER))
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Response headers appropriate to a JSON API served over HTTPS."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # API responses carry device inventory and audit records; caching them
        # in a shared proxy or browser store is not worth the latency saving.
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open the database engine on startup and dispose of it on shutdown.

    Deliberately does NOT fail startup when the database is absent. The process
    should come up and report the problem on /readyz, because a container that
    exits immediately tells an operator far less than one that answers "not
    ready, database unreachable".
    """
    settings: Settings = app.state.settings

    if settings.allow_any_login:
        # Loud on purpose. The one way this setting causes real harm is by being
        # forgotten, so it says so on every single startup.
        logger.warning(
            "AUTHENTICATION IS DISABLED: %s/auth/login accepts any email and "
            "password and grants super_admin. Placeholder for SSO - unset "
            "UBUNTUGUARD_ALLOW_ANY_LOGIN before exposing this server to anything.",
            settings.api_prefix,
        )

    if settings.database_url is not None:
        from ubuntuguard.api.resolvers import DbDeviceResolver, DbTokenResolver
        from ubuntuguard.db import create_db_engine, create_session_factory

        try:
            app.state.engine = create_db_engine(settings)
            app.state.session_factory = create_session_factory(app.state.engine)
            app.state.token_resolver = DbTokenResolver(app.state.session_factory)
            app.state.device_resolver = DbDeviceResolver(app.state.session_factory)
            logger.info("database engine created")
        except Exception:
            logger.exception("could not create the database engine")
            app.state.engine = None
    else:
        app.state.engine = None
        logger.warning("no database configured; /readyz will report not ready")

    # Key material is loaded once, not per request: a filesystem error should
    # not surface as an authentication failure, and the permission check should
    # not be paid on every call.
    try:
        from ubuntuguard.services.keys import ensure_keys

        app.state.keys = ensure_keys(settings)
        logger.info("key material loaded")
    except Exception as exc:  # noqa: BLE001 - reported via /readyz, not fatal
        app.state.keys = None
        app.state.keys_error = str(exc)
        logger.warning("key material not available: %s", exc)

    yield

    engine = getattr(app.state, "engine", None)
    if engine is not None:
        engine.dispose()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    app = FastAPI(
        lifespan=_lifespan,
        title="UbuntuGuard API",
        version="0.1.0",
        description=(
            "MDM and DLP control plane for Ubuntu laptops. Two authentication "
            "planes: bearer tokens for admins, mTLS client certificates for "
            "devices. The protocol carries declarative data only - there is no "
            "field anywhere that holds a command, script or path."
        ),
        openapi_url=f"{settings.api_prefix}/openapi.json",
        docs_url=f"{settings.api_prefix}/docs" if not settings.is_production else None,
        redoc_url=None,
    )

    app.state.settings = settings
    # Populated by the lifespan when a database is configured. Left as None so
    # the dependencies return 503 rather than pretending nobody is authenticated.
    app.state.session_factory = None
    app.state.token_resolver = None
    app.state.device_resolver = None
    app.state.keys = None

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIdMiddleware)

    _register_exception_handlers(app)
    _register_health_routes(app)

    from ubuntuguard.api.v1 import build_router

    app.include_router(build_router(), prefix=settings.api_prefix)

    return app


def _register_exception_handlers(app: FastAPI) -> None:
    async def handle_problem(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, problems.ProblemError)  # noqa: S101 - handler contract
        if exc.audit_detail:
            # The reason the request really failed goes to the log and, for
            # security-relevant actions, to the audit table. It never goes to
            # the client, whose response stays deliberately vague.
            logger.warning(
                "request refused",
                extra={
                    "request_id": getattr(request.state, "request_id", None),
                    "code": exc.code,
                    "reason": exc.audit_detail,
                    "path": request.url.path,
                },
            )
        return problems.problem_from_request(request, exc)

    async def handle_validation(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, RequestValidationError)  # noqa: S101 - handler contract
        fields = [
            FieldError(
                field=".".join(str(part) for part in error.get("loc", ()) if part != "body"),
                message=str(error.get("msg", "invalid")),
            )
            for error in exc.errors()
        ]
        return problems.problem_from_request(request, problems.validation_failed(fields))

    async def handle_http_exception(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, StarletteHTTPException)  # noqa: S101 - handler contract
        # Starlette's own 404 and 405 would otherwise return {"detail": ...} and
        # break the single error model the generated client relies on.
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        error = problems.ProblemError(
            code,
            status=exc.status_code,
            title=str(exc.detail) if exc.detail else "Request failed",
            detail=str(exc.detail) if exc.detail else None,
        )
        return problems.problem_from_request(request, error)

    async def handle_unexpected(request: Request, exc: Exception) -> Response:
        # Logged with the traceback, returned as a fixed message. An unhandled
        # error must not hand the caller a stack trace, a SQL fragment or a
        # connection string.
        logger.exception(
            "unhandled exception",
            extra={
                "request_id": getattr(request.state, "request_id", None),
                "path": request.url.path,
            },
        )
        return problems.problem_from_request(request, problems.internal_error())

    app.add_exception_handler(problems.ProblemError, handle_problem)
    app.add_exception_handler(RequestValidationError, handle_validation)
    app.add_exception_handler(StarletteHTTPException, handle_http_exception)
    app.add_exception_handler(Exception, handle_unexpected)


def _register_health_routes(app: FastAPI) -> None:
    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        """Liveness. Deliberately carries no version or build information.

        An unauthenticated endpoint that names the running version tells an
        attacker which advisories to read.
        """
        return JSONResponse({"status": "ok"})

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request) -> Response:
        """Readiness: can this process actually serve traffic?

        Reports not-ready, with the reason, when the database is unreachable or
        unconfigured. Saying "ok" while unable to authenticate anybody would
        make a load balancer route traffic into a hole.
        """
        settings: Settings = request.app.state.settings
        checks: dict[str, str] = {}

        if settings.database_url is None:
            checks["database"] = "not configured"
        else:
            engine = getattr(request.app.state, "engine", None)
            if engine is None:
                checks["database"] = "engine not initialised"
            else:
                from ubuntuguard.db import audit_role_is_append_only, check_connectivity

                try:
                    check_connectivity(engine)
                    checks["database"] = "ok"
                except Exception as exc:  # noqa: BLE001 - reported, not raised
                    checks["database"] = f"unreachable: {type(exc).__name__}"

                checks["keys"] = (
                    "ok"
                    if getattr(request.app.state, "keys", None) is not None
                    else "FAILED: "
                    + str(getattr(request.app.state, "keys_error", "key material not loaded"))
                )

                if checks["database"] == "ok":
                    # The append-only guarantee lives in the GRANTs, not in this
                    # code, so a deployment can lose it without any error: a
                    # migration that recreates audit_logs, or someone pointing
                    # the app at the owner role. Reporting not-ready makes that
                    # visible instead of merely true-but-unnoticed.
                    try:
                        if audit_role_is_append_only(engine):
                            checks["audit_append_only"] = "ok"
                        else:
                            checks["audit_append_only"] = (
                                "FAILED: the connected role holds UPDATE or DELETE on "
                                "audit_logs; re-apply sql/02-grants.sql"
                            )
                            logger.error(
                                "audit log is not append-only for the connected database role"
                            )
                    except Exception as exc:  # noqa: BLE001 - reported, not raised
                        checks["audit_append_only"] = f"unknown: {type(exc).__name__}"

        # Reported alongside the checks rather than inside them: an insecure
        # setting should be impossible to miss, but it does not make the process
        # unable to serve traffic, and failing readiness would just stop the
        # dev server that deliberately turned it on.
        warnings = []
        if settings.allow_any_login:
            warnings.append(
                "AUTHENTICATION IS DISABLED: any email and password is accepted and "
                "granted super_admin"
            )

        ready = all(value == "ok" for value in checks.values())
        body: dict[str, object] = {"status": "ready" if ready else "not_ready", "checks": checks}
        if warnings:
            body["warnings"] = warnings
        if ready:
            return JSONResponse(body)
        return JSONResponse(status_code=503, content=body, media_type="application/json")
