"""Problem response tests.

The indistinguishable-auth-failures test is the one with teeth. The brief asks
for generic error messages on login; this is what makes that concrete and keeps
it from regressing the first time someone adds a helpful "no such user".
"""

from __future__ import annotations

import json

import pytest

from ubuntuguard import problems
from ubuntuguard.problems import CONTENT_TYPE, FieldError, ProblemError, render


def body_of(error: ProblemError, request_id: str | None = None) -> dict:
    response = render(error.to_problem(request_id=request_id))
    return json.loads(bytes(response.body))


def test_problem_has_the_rfc_9457_members() -> None:
    payload = body_of(problems.not_found("device"), request_id="req-1")
    assert payload["type"].startswith("https://ubuntuguard.invalid/problems/")
    assert payload["title"] == "Not found"
    assert payload["status"] == 404
    assert payload["code"] == "not_found"
    assert payload["request_id"] == "req-1"


def test_media_type_is_problem_json() -> None:
    response = render(problems.not_found("device").to_problem())
    assert response.media_type == CONTENT_TYPE


def test_unset_fields_are_omitted_rather_than_null() -> None:
    """Keeps the generated TypeScript client's optional fields meaningful."""
    payload = body_of(problems.not_found("device"))
    assert "fields" not in payload
    assert "retry_after" not in payload
    assert "request_id" not in payload


def test_type_uri_is_derived_from_the_code() -> None:
    payload = body_of(problems.invalid_credentials())
    assert payload["type"].endswith("/invalid-credentials")


# --------------------------------------------------------------------------- #
# Authentication failures must be indistinguishable
# --------------------------------------------------------------------------- #


def test_all_authentication_failures_produce_an_identical_body() -> None:
    """Wrong password, unknown account, locked account, disabled account.

    If any of these differed, login would be an account-enumeration oracle no
    matter how carefully the password hashing was done.
    """
    bodies = [
        body_of(problems.invalid_credentials("wrong password for user 42")),
        body_of(problems.invalid_credentials("no such user bob@example.invalid")),
        body_of(problems.invalid_credentials("account locked until 12:05")),
        body_of(problems.invalid_credentials("account disabled")),
        body_of(problems.invalid_credentials()),
    ]
    assert all(candidate == bodies[0] for candidate in bodies[1:])


def test_audit_detail_never_reaches_the_client() -> None:
    """It is the reason the request really failed, for the log and the audit
    table only.
    """
    error = problems.invalid_credentials("no such user bob@example.invalid")
    rendered = json.dumps(body_of(error))
    assert "bob@example.invalid" not in rendered
    assert "no such user" not in rendered
    # Still available server-side.
    assert error.audit_detail == "no such user bob@example.invalid"


def test_forbidden_does_not_name_the_capability_or_role() -> None:
    error = problems.forbidden("role auditor lacks policy_write (user 42)")
    rendered = json.dumps(body_of(error))
    assert "auditor" not in rendered
    assert "policy_write" not in rendered
    assert "42" not in rendered


def test_device_auth_failure_keeps_the_reason_code_but_not_the_detail() -> None:
    """The code is useful for grouping failures in the dashboard; the detail
    would tell a caller which check to defeat next.
    """
    error = problems.device_not_authenticated(
        "untrusted_proxy", audit_detail="headers refused from 203.0.113.7"
    )
    payload = body_of(error)
    assert payload["code"] == "untrusted_proxy"
    assert payload["status"] == 401
    assert "203.0.113.7" not in json.dumps(payload)


def test_internal_error_has_fixed_wording() -> None:
    """No stack trace, no SQL fragment, no connection string."""
    payload = body_of(problems.internal_error())
    assert payload["status"] == 500
    assert payload["detail"] == "The request could not be completed."


# --------------------------------------------------------------------------- #
# Other problem kinds
# --------------------------------------------------------------------------- #


def test_validation_failure_lists_the_offending_fields() -> None:
    error = problems.validation_failed(
        [FieldError(field="heartbeat_seconds", message="must be at least 30")]
    )
    payload = body_of(error)
    assert payload["status"] == 422
    assert payload["fields"][0]["field"] == "heartbeat_seconds"


def test_rate_limit_sets_the_retry_after_header() -> None:
    response = render(problems.rate_limited(retry_after=42).to_problem())
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "42"


def test_request_id_is_also_a_header() -> None:
    """So it can be read without parsing the body."""
    response = render(problems.not_found("device").to_problem(request_id="req-9"))
    assert response.headers["X-Request-Id"] == "req-9"


def test_conflict_carries_a_specific_code() -> None:
    payload = body_of(problems.conflict("enrollment_token_consumed", "Already used."))
    assert payload["status"] == 409
    assert payload["code"] == "enrollment_token_consumed"


@pytest.mark.parametrize(
    ("factory", "status"),
    [
        (lambda: problems.not_authenticated(), 401),
        (lambda: problems.invalid_credentials(), 401),
        (lambda: problems.forbidden(), 403),
        (lambda: problems.not_found("x"), 404),
        (lambda: problems.rate_limited(1), 429),
        (lambda: problems.service_unavailable("down"), 503),
        (lambda: problems.internal_error(), 500),
    ],
)
def test_status_codes(factory: object, status: int) -> None:
    assert factory().status == status  # type: ignore[operator]


def test_problem_error_is_raisable_and_carries_its_code() -> None:
    with pytest.raises(ProblemError) as caught:
        raise problems.not_found("device")
    assert caught.value.code == "not_found"
    assert caught.value.status == 404
