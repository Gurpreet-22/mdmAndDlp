"""RFC 9457 problem responses.

One error shape for the whole API, so the generated TypeScript client has a
single error model to branch on. Clients branch on `code`, which is a stable
string; `title` and `detail` are for humans and may be reworded freely.

Two properties this module exists to guarantee:

- Authentication failures are indistinguishable. A wrong password, an unknown
  account and a locked account all produce the identical body. Only the audit
  log records which it was. Otherwise login becomes an account-enumeration
  oracle no matter how good the password hashing is.
- No problem response ever carries a token, password, key, certificate or
  signature. `detail` is always a string this module controls, never a rendered
  exception that might have a secret in it.
"""

from __future__ import annotations

from typing import Any, Final

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

#: RFC 9457 wants `type` to be a URI. It is never dereferenced; it just has to
#: be stable and unique per problem kind.
PROBLEM_BASE_URI: Final[str] = "https://ubuntuguard.invalid/problems/"

CONTENT_TYPE: Final[str] = "application/problem+json"


class FieldError(BaseModel):
    """One validation failure, for a form to highlight."""

    field: str
    message: str


class Problem(BaseModel):
    """RFC 9457 problem detail."""

    type: str
    title: str
    status: int
    code: str
    detail: str | None = None
    request_id: str | None = None
    fields: list[FieldError] | None = None
    #: Seconds until a rate-limited or locked-out caller may retry.
    retry_after: int | None = Field(default=None)


class ProblemError(Exception):
    """Raise this anywhere; the registered handler renders it.

    `audit_detail` never reaches the client. It is the place to record why the
    request really failed when the response has to stay vague, which is what
    keeps the audit log useful without leaking to the caller.
    """

    def __init__(
        self,
        code: str,
        *,
        status: int,
        title: str,
        detail: str | None = None,
        fields: list[FieldError] | None = None,
        retry_after: int | None = None,
        audit_detail: str | None = None,
    ) -> None:
        super().__init__(f"{status} {code}")
        self.code = code
        self.status = status
        self.title = title
        self.detail = detail
        self.fields = fields
        self.retry_after = retry_after
        self.audit_detail = audit_detail

    def to_problem(self, request_id: str | None = None) -> Problem:
        return Problem(
            type=PROBLEM_BASE_URI + self.code.replace("_", "-"),
            title=self.title,
            status=self.status,
            code=self.code,
            detail=self.detail,
            request_id=request_id,
            fields=self.fields,
            retry_after=self.retry_after,
        )


# --------------------------------------------------------------------------- #
# Constructors for the problems the API actually returns.
# Using functions rather than ad-hoc raises keeps the wording consistent and,
# for the auth cases, keeps it IDENTICAL.
# --------------------------------------------------------------------------- #

#: The single body returned for every authentication failure. Deliberately
#: says nothing about which part was wrong.
_INVALID_CREDENTIALS_DETAIL: Final[str] = "Authentication failed."


def invalid_credentials(audit_detail: str | None = None) -> ProblemError:
    """Wrong password, unknown account, locked account, disabled account.

    All four return this. `audit_detail` carries the real reason to the audit
    log, where it belongs.
    """
    return ProblemError(
        "invalid_credentials",
        status=401,
        title="Authentication failed",
        detail=_INVALID_CREDENTIALS_DETAIL,
        audit_detail=audit_detail,
    )


def not_authenticated() -> ProblemError:
    return ProblemError(
        "not_authenticated",
        status=401,
        title="Authentication required",
        detail="A valid access token is required.",
    )


def forbidden(audit_detail: str | None = None) -> ProblemError:
    """Authenticated but lacking the capability.

    The response does not name the missing capability: letting a caller probe
    for it would hand them a map of the RBAC matrix.
    """
    return ProblemError(
        "forbidden",
        status=403,
        title="Forbidden",
        detail="This account is not permitted to perform that action.",
        audit_detail=audit_detail,
    )


def device_not_authenticated(code: str, audit_detail: str | None = None) -> ProblemError:
    """Device-plane mTLS failure. `code` is a reason code from `device_auth`."""
    return ProblemError(
        code,
        status=401,
        title="Device authentication failed",
        detail="A valid client certificate is required.",
        audit_detail=audit_detail,
    )


def not_found(resource: str) -> ProblemError:
    return ProblemError(
        "not_found",
        status=404,
        title="Not found",
        detail=f"No such {resource}.",
    )


def conflict(code: str, detail: str) -> ProblemError:
    return ProblemError(code, status=409, title="Conflict", detail=detail)


def validation_failed(fields: list[FieldError]) -> ProblemError:
    return ProblemError(
        "validation_failed",
        status=422,
        title="Validation failed",
        detail="One or more fields are invalid.",
        fields=fields,
    )


def rate_limited(retry_after: int) -> ProblemError:
    return ProblemError(
        "rate_limited",
        status=429,
        title="Too many requests",
        detail="Slow down and retry later.",
        retry_after=retry_after,
    )


def service_unavailable(detail: str) -> ProblemError:
    return ProblemError(
        "service_unavailable",
        status=503,
        title="Service unavailable",
        detail=detail,
    )


def internal_error() -> ProblemError:
    """Returned for any unhandled exception.

    Fixed wording on purpose. An unexpected failure must not leak a stack
    trace, a SQL fragment or a connection string to the caller; the detail goes
    to the server log under the same request id.
    """
    return ProblemError(
        "internal_error",
        status=500,
        title="Internal server error",
        detail="The request could not be completed.",
    )


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render(problem: Problem) -> JSONResponse:
    """Serialize a problem, omitting unset fields and setting Retry-After."""
    headers: dict[str, str] = {}
    if problem.retry_after is not None:
        headers["Retry-After"] = str(problem.retry_after)
    if problem.request_id is not None:
        headers["X-Request-Id"] = problem.request_id

    return JSONResponse(
        status_code=problem.status,
        content=problem.model_dump(exclude_none=True),
        media_type=CONTENT_TYPE,
        headers=headers,
    )


def problem_from_request(request: Request, error: ProblemError) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    return render(error.to_problem(request_id=request_id))


#: Declared on the v1 router so `Problem` lands in the OpenAPI components and the
#: generated TypeScript client gets a typed error model.
#:
#: Without this the schema is absent entirely: FastAPI only emits models it sees
#: in a route signature, and these are raised rather than returned. The dashboard
#: build caught it, which is the point of generating the client from the schema
#: rather than hand-writing types that drift.
#:
#: "default" rather than enumerating every status: any unlisted status returns a
#: problem document, and listing nine of them on all 18 routes would bury the
#: successful responses in the docs.
ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    "default": {
        "model": Problem,
        "description": "RFC 9457 problem document. Branch on `code`, never on `detail`.",
    }
}
