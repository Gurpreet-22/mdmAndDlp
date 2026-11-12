"""Authentication routes.

The refresh token travels as an httpOnly cookie, never in a response body, so
JavaScript in the dashboard cannot read it and an XSS bug cannot exfiltrate it.
The access token does go in the body, because the dashboard has to attach it to
requests - which is also why it lives only 15 minutes.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from ubuntuguard import problems
from ubuntuguard.api.deps import Principal, get_principal, get_session
from ubuntuguard.config import Settings
from ubuntuguard.constants import REFRESH_TOKEN_TTL_SECONDS
from ubuntuguard.schemas import AuthModeResponse, LoginRequest, MeResponse, TokenResponse
from ubuntuguard.security.rbac import capabilities_for
from ubuntuguard.services import auth

logger = logging.getLogger("ubuntuguard")

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "ubuntuguard_refresh"
#: Scoped to the auth routes, so the cookie is not sent on every API call and a
#: compromised unrelated endpoint never sees it.
REFRESH_COOKIE_PATH = "/api/v1/auth"


def _set_refresh_cookie(response: Response, settings: Settings, value: str) -> None:
    response.set_cookie(
        REFRESH_COOKIE,
        value,
        max_age=REFRESH_TOKEN_TTL_SECONDS,
        httponly=True,
        # Secure is conditional only so local development over http works. In
        # production it is on, and production is the case that matters.
        secure=settings.is_production,
        samesite="strict",
        path=REFRESH_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        REFRESH_COOKIE,
        httponly=True,
        secure=settings.is_production,
        samesite="strict",
        path=REFRESH_COOKIE_PATH,
    )


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post(
    "/login",
    response_model=TokenResponse,
    responses={401: {"description": "Authentication failed"}},
)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> TokenResponse:
    """Exchange credentials for an access token and a refresh cookie.

    Every failure returns the identical body: wrong password, unknown account,
    locked account and disabled account are indistinguishable. Only the audit
    log records which it was.
    """
    settings: Settings = request.app.state.settings
    shared = {
        "request_id": getattr(request.state, "request_id", None),
        "source_ip": _client_ip(request),
        "user_agent": request.headers.get("user-agent"),
    }

    if settings.allow_any_login:
        logger.warning(
            "login accepted WITHOUT authentication for %s; UBUNTUGUARD_ALLOW_ANY_LOGIN is on",
            body.email,
        )
        result = auth.login_without_authentication(session, email=body.email, **shared)
    else:
        result = auth.login(session, email=body.email, password=body.password, **shared)

    _set_refresh_cookie(response, settings, result.refresh.plaintext)
    return TokenResponse(access_token=result.access.plaintext, expires_in=result.access_expires_in)


@router.get("/mode", response_model=AuthModeResponse)
def auth_mode(request: Request) -> AuthModeResponse:
    """How this server authenticates, so the login page can say so.

    Unauthenticated, and safe to be: the very next login request would reveal
    the same thing, and the dashboard has to know whether to warn the operator
    that the credentials it is collecting are being ignored.
    """
    settings: Settings = request.app.state.settings
    return AuthModeResponse(any_login=settings.allow_any_login)


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> TokenResponse:
    """Rotate the refresh token and issue a new access token.

    Single use. Presenting one twice revokes the whole family, because at that
    point either an attacker holds a stolen copy or the client is replaying, and
    there is no way to tell which.
    """
    presented = request.cookies.get(REFRESH_COOKIE)
    if not presented:
        raise problems.not_authenticated()

    result = auth.refresh_session(
        session,
        refresh_plaintext=presented,
        request_id=getattr(request.state, "request_id", None),
    )
    _set_refresh_cookie(response, request.app.state.settings, result.refresh.plaintext)
    return TokenResponse(access_token=result.access.plaintext, expires_in=result.access_expires_in)


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> Response:
    """Revoke the token family and clear the cookie.

    Succeeds even without a valid token. Logging out is not a place to tell a
    caller whether the token they sent was real.
    """
    auth.logout(
        session,
        refresh_plaintext=request.cookies.get(REFRESH_COOKIE),
        request_id=getattr(request.state, "request_id", None),
    )
    _clear_refresh_cookie(response, request.app.state.settings)
    return Response(status_code=204, headers=dict(response.headers))


@router.get("/me", response_model=MeResponse)
def me(principal: Principal = Depends(get_principal)) -> MeResponse:
    """The current user and the capabilities their role holds.

    The dashboard uses the capability list to hide controls. The server still
    checks every call, because a hidden button is not a security boundary.
    """
    return MeResponse(
        user_id=principal.user_id,  # type: ignore[arg-type]
        email=principal.email,
        role=principal.role.value,
        capabilities=sorted(capability.value for capability in capabilities_for(principal.role)),
    )
