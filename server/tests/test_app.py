"""Application wiring tests: middleware, error shape, health, RBAC on routes.

No database. Token resolution sits behind a Protocol, so the authorisation
wiring is exercised with a fake resolver and FastAPI dependency overrides -
which is the point of putting it behind a Protocol.
"""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from ubuntuguard import problems
from ubuntuguard.api.deps import Principal, get_principal, require_capability
from ubuntuguard.config import Settings
from ubuntuguard.main import create_app
from ubuntuguard.problems import CONTENT_TYPE
from ubuntuguard.security.rbac import Capability, Role


class FakeTokenResolver:
    """Resolves exactly one token, so route authorisation can be tested."""

    def __init__(self, token_hash: str, principal: Principal | None) -> None:
        self._token_hash = token_hash
        self._principal = principal

    def resolve_access_token(self, token_hash: str) -> Principal | None:
        return self._principal if token_hash == self._token_hash else None


def build_app(settings: Settings | None = None) -> FastAPI:
    """App plus a few routes that exist only to exercise the plumbing."""
    app = create_app(settings or Settings())

    @app.get("/test/boom")
    async def boom() -> dict[str, str]:
        raise RuntimeError("database password is hunter2 and the token is abc123")

    @app.get("/test/problem")
    async def problem() -> dict[str, str]:
        raise problems.not_found("device")

    @app.get("/test/policy-write")
    async def policy_write(
        principal: Principal = Depends(require_capability(Capability.POLICY_WRITE)),
    ) -> dict[str, str]:
        return {"role": principal.role.value}

    @app.get("/test/audit-export")
    async def audit_export(
        principal: Principal = Depends(require_capability(Capability.AUDIT_EXPORT)),
    ) -> dict[str, str]:
        return {"role": principal.role.value}

    return app


@pytest.fixture
def client() -> TestClient:
    # raise_server_exceptions=False so the unhandled-exception handler runs,
    # rather than the test client re-raising past it.
    return TestClient(build_app(), raise_server_exceptions=False)


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #


def test_healthz_is_unauthenticated_and_says_nothing_about_the_build(
    client: TestClient,
) -> None:
    """An unauthenticated endpoint naming the version tells an attacker which
    advisories to read.
    """
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    body = response.text.lower()
    for leak in ("0.1.0", "version", "python", "postgres", "commit"):
        assert leak not in body


def test_readyz_reports_not_ready_without_a_database(client: TestClient) -> None:
    """Reporting ready while unable to authenticate anybody would make a load
    balancer route traffic into a hole.
    """
    response = client.get("/readyz")
    assert response.status_code == 503
    payload = response.json()
    assert payload["status"] == "not_ready"
    assert payload["checks"]["database"] == "not configured"


def test_readyz_reports_ready_when_every_check_passes() -> None:
    """Database reachable, audit log append-only, and key material loaded."""
    app = build_app()
    app.state.settings = Settings(database_url="postgresql+psycopg://a:b@localhost/c")
    app.state.engine = object()
    app.state.keys = object()

    import ubuntuguard.db as db_module

    originals = (db_module.check_connectivity, db_module.audit_role_is_append_only)
    db_module.check_connectivity = lambda engine: None  # type: ignore[assignment]
    db_module.audit_role_is_append_only = lambda engine, role=None: True  # type: ignore[assignment]
    try:
        response = TestClient(app).get("/readyz")
        assert response.status_code == 200
        assert response.json() == {
            "status": "ready",
            "checks": {"database": "ok", "keys": "ok", "audit_append_only": "ok"},
        }
    finally:
        db_module.check_connectivity, db_module.audit_role_is_append_only = originals  # type: ignore[assignment]


def test_readyz_reports_not_ready_without_key_material() -> None:
    """A server with no signing key cannot issue a policy or a certificate.

    Reporting ready would let a load balancer send it enrollment requests it
    cannot possibly complete.
    """
    app = build_app()
    app.state.settings = Settings(database_url="postgresql+psycopg://a:b@localhost/c")
    app.state.engine = object()
    app.state.keys = None
    app.state.keys_error = "missing key material: var/ca.key"

    import ubuntuguard.db as db_module

    originals = (db_module.check_connectivity, db_module.audit_role_is_append_only)
    db_module.check_connectivity = lambda engine: None  # type: ignore[assignment]
    db_module.audit_role_is_append_only = lambda engine, role=None: True  # type: ignore[assignment]
    try:
        response = TestClient(app).get("/readyz")
        assert response.status_code == 503
        assert "var/ca.key" in response.json()["checks"]["keys"]
    finally:
        db_module.check_connectivity, db_module.audit_role_is_append_only = originals  # type: ignore[assignment]


def test_readyz_reports_not_ready_when_the_audit_log_is_mutable() -> None:
    """A deployment that lost the append-only grants must not look healthy.

    This is the operational half of a bug found during Phase 1b: a migration
    that recreates audit_logs can hand the app role UPDATE and DELETE again,
    with nothing raising anywhere.
    """
    app = build_app()
    app.state.settings = Settings(database_url="postgresql+psycopg://a:b@localhost/c")
    app.state.engine = object()

    import ubuntuguard.db as db_module

    originals = (db_module.check_connectivity, db_module.audit_role_is_append_only)
    db_module.check_connectivity = lambda engine: None  # type: ignore[assignment]
    db_module.audit_role_is_append_only = lambda engine, role=None: False  # type: ignore[assignment]
    try:
        response = TestClient(app).get("/readyz")
        assert response.status_code == 503
        payload = response.json()
        assert payload["status"] == "not_ready"
        assert "FAILED" in payload["checks"]["audit_append_only"]
        assert "02-grants.sql" in payload["checks"]["audit_append_only"]
    finally:
        db_module.check_connectivity, db_module.audit_role_is_append_only = originals  # type: ignore[assignment]


def test_readyz_reports_the_failure_when_the_database_is_unreachable() -> None:
    app = build_app()
    app.state.settings = Settings(database_url="postgresql+psycopg://a:b@localhost/c")
    app.state.engine = object()

    import ubuntuguard.db as db_module

    original = db_module.check_connectivity

    def explode(engine: object) -> None:
        raise ConnectionRefusedError("connection refused")

    db_module.check_connectivity = explode  # type: ignore[assignment]
    try:
        response = TestClient(app).get("/readyz")
        assert response.status_code == 503
        assert "ConnectionRefusedError" in response.json()["checks"]["database"]
    finally:
        db_module.check_connectivity = original  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# Request ids
# --------------------------------------------------------------------------- #


def test_request_id_is_generated_and_echoed(client: TestClient) -> None:
    response = client.get("/healthz")
    assert len(response.headers["X-Request-Id"]) == 32


def test_client_supplied_request_id_is_echoed(client: TestClient) -> None:
    response = client.get("/healthz", headers={"X-Request-Id": "trace-abc-123"})
    assert response.headers["X-Request-Id"] == "trace-abc-123"


@pytest.mark.parametrize(
    "hostile",
    [
        "abc\ndef INJECTED LOG LINE",
        "abc\r\nSet-Cookie: x=y",
        "../../etc/passwd",
        "a" * 500,
        "<script>alert(1)</script>",
    ],
)
def test_hostile_request_id_is_replaced(client: TestClient, hostile: str) -> None:
    """The value reaches log lines and audit rows, so it is sanitised."""
    response = client.get("/healthz", headers={"X-Request-Id": hostile})
    echoed = response.headers["X-Request-Id"]
    assert echoed != hostile
    assert "\n" not in echoed and "\r" not in echoed
    assert len(echoed) <= 64


def test_over_long_request_id_is_replaced_not_truncated(client: TestClient) -> None:
    """Truncation would map distinct client ids sharing a 64-character prefix
    onto one server id, breaking correlation exactly when it is being relied on.
    """
    first = client.get("/healthz", headers={"X-Request-Id": "x" * 70 + "-one"})
    second = client.get("/healthz", headers={"X-Request-Id": "x" * 70 + "-two"})
    one = first.headers["X-Request-Id"]
    two = second.headers["X-Request-Id"]
    assert one != two, "two distinct over-long ids collapsed to the same value"
    assert not one.startswith("x" * 64), "the id was truncated rather than replaced"
    assert len(one) == 32


def test_request_id_appears_in_problem_responses(client: TestClient) -> None:
    """So a user reporting an error can be matched to a server log line."""
    response = client.get("/test/problem", headers={"X-Request-Id": "corr-1"})
    assert response.json()["request_id"] == "corr-1"


# --------------------------------------------------------------------------- #
# Error shape
# --------------------------------------------------------------------------- #


def test_problem_errors_use_problem_json(client: TestClient) -> None:
    response = client.get("/test/problem")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith(CONTENT_TYPE)
    payload = response.json()
    assert payload["code"] == "not_found"
    assert payload["status"] == 404
    assert payload["type"].endswith("/not-found")


def test_unknown_route_returns_a_problem_not_fastapis_detail(client: TestClient) -> None:
    """Starlette's own 404 would be {"detail": ...} and break the single error
    model the generated TypeScript client relies on.
    """
    response = client.get("/no/such/route")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith(CONTENT_TYPE)
    assert response.json()["code"] == "not_found"


def test_wrong_method_returns_a_problem(client: TestClient) -> None:
    response = client.post("/healthz")
    assert response.status_code == 405
    assert response.json()["code"] == "method_not_allowed"


def test_unhandled_exception_leaks_nothing(client: TestClient) -> None:
    """The route raises with a password and a token in the message.

    Neither may appear in the response, and nor may a traceback or the
    exception type.
    """
    response = client.get("/test/boom")
    assert response.status_code == 500
    body = response.text
    assert "hunter2" not in body
    assert "abc123" not in body
    assert "RuntimeError" not in body
    assert "Traceback" not in body
    assert response.json()["code"] == "internal_error"


def test_security_headers_are_present(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"


# --------------------------------------------------------------------------- #
# Authentication and RBAC on real routes
# --------------------------------------------------------------------------- #


def test_missing_bearer_token_is_rejected(client: TestClient) -> None:
    response = client.get("/test/policy-write")
    assert response.status_code == 401
    assert response.json()["code"] == "not_authenticated"


@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Bearer ", "Basic abc123", "bearer", "Token abc123"],
)
def test_malformed_authorization_header_is_rejected(client: TestClient, header: str) -> None:
    response = client.get("/test/policy-write", headers={"Authorization": header})
    assert response.status_code == 401
    assert response.json()["code"] == "not_authenticated"


def test_unconfigured_resolver_reports_unavailable_not_unauthorised(
    client: TestClient,
) -> None:
    """ "The server cannot check" and "your credentials are wrong" are different
    problems, and conflating them sends operators hunting in the wrong place.
    """
    response = client.get("/test/policy-write", headers={"Authorization": "Bearer anything"})
    assert response.status_code == 503
    assert response.json()["code"] == "service_unavailable"


def test_unknown_token_is_rejected() -> None:
    from ubuntuguard.security.tokens import hash_token

    app = build_app()
    app.state.token_resolver = FakeTokenResolver(hash_token("good-token"), None)
    response = TestClient(app).get(
        "/test/policy-write", headers={"Authorization": "Bearer good-token"}
    )
    assert response.status_code == 401
    assert response.json()["code"] == "not_authenticated"


def _client_as(role: Role) -> TestClient:
    app = build_app()
    app.dependency_overrides[get_principal] = lambda: Principal(
        user_id="11111111-1111-4111-8111-111111111111",
        email="admin@example.invalid",
        role=role,
    )
    return TestClient(app)


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (Role.SUPER_ADMIN, 200),
        (Role.IT_ADMIN, 200),
        (Role.SECURITY_ANALYST, 403),
        (Role.AUDITOR, 403),
    ],
)
def test_policy_write_route_enforces_the_matrix(role: Role, expected: int) -> None:
    response = _client_as(role).get("/test/policy-write")
    assert response.status_code == expected


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (Role.SUPER_ADMIN, 200),
        (Role.IT_ADMIN, 403),
        (Role.SECURITY_ANALYST, 403),
        (Role.AUDITOR, 200),
    ],
)
def test_audit_export_route_enforces_separation_of_duties(role: Role, expected: int) -> None:
    """The contested cell, enforced at the route and not only in the matrix."""
    response = _client_as(role).get("/test/audit-export")
    assert response.status_code == expected


def test_forbidden_response_does_not_name_the_missing_capability() -> None:
    """Otherwise a caller could probe endpoints and map the RBAC matrix."""
    response = _client_as(Role.AUDITOR).get("/test/policy-write")
    assert response.status_code == 403
    body = response.text
    assert "policy_write" not in body
    assert "auditor" not in body
    assert response.json()["code"] == "forbidden"


def test_principal_repr_is_terse() -> None:
    """Identity objects end up in log lines; keep them boring."""
    principal = Principal(user_id="u-1", email="a@b.invalid", role=Role.AUDITOR)
    assert "a@b.invalid" not in repr(principal)


# --------------------------------------------------------------------------- #
# OpenAPI
# --------------------------------------------------------------------------- #


def test_openapi_is_served_under_the_api_prefix(client: TestClient) -> None:
    """The dashboard's typed client is generated from this document."""
    response = client.get("/api/v1/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "UbuntuGuard API"


def test_docs_are_disabled_in_production() -> None:
    settings = Settings(
        environment="prod",
        database_url="postgresql+psycopg://a:b@localhost/c",
        policy_signing_key_path="/etc/ubuntuguard/policy.key",
        ca_key_path="/etc/ubuntuguard/ca.key",
        ca_cert_path="/etc/ubuntuguard/ca.crt",
    )
    response = TestClient(create_app(settings)).get("/api/v1/docs")
    assert response.status_code == 404
