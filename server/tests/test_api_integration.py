"""End-to-end API tests against the live database.

These exercise the requirements the brief states explicitly and that only a
real HTTP round trip plus a real database can demonstrate: the role matrix on
actual routes, login lockout, the enrollment race, idempotent retry, clone
detection, revocation taking effect, and the audit chain surviving all of it.

Skipped with an explanation when no database is configured.

Note the deliberate opt-out from `isolate_settings_sources`. That autouse
fixture neutralises server/.env to keep unit tests deterministic; these tests
need the real configuration, so they read it from the file directly.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from ubuntuguard.config import Settings
from ubuntuguard.main import create_app
from ubuntuguard.security.rbac import Role

pytestmark = pytest.mark.postgres

SERVER_DIR = Path(__file__).resolve().parents[1]
PASSWORD = "a reasonably long passphrase"


def _env_from_file() -> dict[str, str]:
    env_file = SERVER_DIR / ".env"
    if not env_file.exists():
        pytest.skip("server/.env is missing. Create it with: ./scripts/dev_db.sh up")
    values: dict[str, str] = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("UBUNTUGUARD_") and "=" in line:
            name, _, value = line.partition("=")
            values[name.removeprefix("UBUNTUGUARD_").lower()] = value.strip()
    return values


@pytest.fixture(scope="module")
def app() -> Iterator[FastAPI]:
    values = _env_from_file()
    if "database_url" not in values:
        pytest.skip("no database URL in server/.env")
    # These tests exercise real password authentication: lockout, wrong-password
    # refusal, the identical-failure guarantee. A developer with
    # UBUNTUGUARD_ALLOW_ANY_LOGIN=1 in their .env would otherwise see four of
    # them fail for a reason that has nothing to do with the code under test.
    values["allow_any_login"] = "false"
    try:
        settings = Settings(_env_file=None, **values)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 - configuration problem, report as skip
        pytest.skip(f"could not build settings from server/.env: {exc}")

    application = create_app(settings)
    # Enter the lifespan so the engine, resolvers and key material exist.
    with TestClient(application):
        pass
    if getattr(application.state, "session_factory", None) is None:
        pytest.skip("database unreachable; is the cluster running?")
    if getattr(application.state, "keys", None) is None:
        pytest.skip("key material missing. Run: python -m ubuntuguard.cli init-keys")
    yield application


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    # client=... so the request appears to come from the trusted proxy address;
    # the device plane refuses certificate headers from anywhere else.
    with TestClient(app, client=("127.0.0.1", 54321)) as test_client:
        yield test_client


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def create_admin(app: FastAPI, role: Role) -> str:
    """Create a user directly, returning the email. Bypasses the API on purpose.

    Bootstrapping the first privileged account over HTTP would need an
    unauthenticated route that creates a super_admin, which is a backdoor
    however carefully it is guarded.
    """
    from ubuntuguard.db import session_scope
    from ubuntuguard.repositories import create_user
    from ubuntuguard.security.passwords import hash_password

    email = f"{role.value}-{uuid.uuid4().hex[:8]}@example.invalid"
    with session_scope(app.state.session_factory) as session:
        create_user(session, email=email, password_hash=hash_password(PASSWORD), role=role.value)
    return email


def login(client: TestClient, email: str, password: str = PASSWORD) -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def as_role(app: FastAPI, client: TestClient, role: Role) -> dict[str, str]:
    return bearer(login(client, create_admin(app, role)))


def make_csr(
    common_name: str = "whatever-the-client-asks-for",
) -> tuple[str, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii"), key


def enroll_body(csr_pem: str, **overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "enrollment_token": "replace-me",
        "csr_pem": csr_pem,
        "hostname": f"laptop-{uuid.uuid4().hex[:8]}",
        "agent_version": "0.1.0",
        "arch": "x86_64",
        "os": {"id": "ubuntu", "version_id": "24.04", "kernel": "6.8.0-45-generic"},
        "hardware_fingerprint": {},
        "release_build": True,
    }
    body.update(overrides)
    return body


def mint_token(client: TestClient, headers: dict[str, str], **body: object) -> tuple[str, str]:
    response = client.post("/api/v1/enrollment-tokens", headers=headers, json=body)
    assert response.status_code == 201, response.text
    payload = response.json()
    return payload["enrollment_token"], payload["id"]


def device_headers(certificate_pem: str) -> dict[str, str]:
    """The headers nginx would set for a verified client certificate."""
    from urllib.parse import quote

    return {
        "X-Client-Verify": "SUCCESS",
        "X-Client-Cert": quote(certificate_pem),
    }


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #


def test_login_returns_an_access_token_and_a_refresh_cookie(
    app: FastAPI, client: TestClient
) -> None:
    email = create_admin(app, Role.IT_ADMIN)
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["expires_in"] == 900

    cookie = response.cookies.get("ubuntuguard_refresh")
    assert cookie, "refresh token should arrive as a cookie"
    # Never in the body: JavaScript in the dashboard must not be able to read it.
    assert cookie not in response.text


def test_token_is_durable_before_the_login_response_is_returned(
    app: FastAPI, client: TestClient
) -> None:
    """Regression test for a race that reached a running server.

    The commit used to happen in the `get_session` dependency teardown, which
    FastAPI runs AFTER the response has gone to the client. A client that logged
    in and immediately used its access token could therefore be told 401,
    because the token row was not committed yet. Against a live uvicorn it
    reproduced about once in twelve attempts.

    Checking from a SEPARATE session is the point: that is what the token
    resolver uses on the next request, so it sees only committed rows.
    """
    email = create_admin(app, Role.IT_ADMIN)
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200

    from ubuntuguard.security.tokens import hash_token

    token_hash = hash_token(response.json()["access_token"])
    with app.state.session_factory() as session:
        found = session.execute(
            text("SELECT count(*) FROM auth_tokens WHERE token_hash = :h AND kind = 'access'"),
            {"h": token_hash},
        ).scalar_one()
    assert found == 1, "the access token was not committed before the response was returned"


def test_login_then_immediate_use_works_repeatedly(app: FastAPI, client: TestClient) -> None:
    """The same race from the client's point of view, with no delay between calls."""
    email = create_admin(app, Role.IT_ADMIN)
    statuses = []
    for _ in range(10):
        token = login(client, email)
        statuses.append(client.get("/api/v1/auth/me", headers=bearer(token)).status_code)
    assert statuses == [200] * 10, f"a freshly issued token was rejected: {statuses}"


def test_all_login_failures_are_indistinguishable(app: FastAPI, client: TestClient) -> None:
    """Wrong password, unknown account and disabled account, byte for byte.

    If any differed, login would be an account-enumeration oracle no matter how
    careful the password hashing is.
    """
    email = create_admin(app, Role.AUDITOR)

    wrong = client.post("/api/v1/auth/login", json={"email": email, "password": "wrong-password"})
    unknown = client.post(
        "/api/v1/auth/login",
        json={"email": f"nobody-{uuid.uuid4().hex[:8]}@example.invalid", "password": PASSWORD},
    )

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == {**unknown.json(), "request_id": wrong.json()["request_id"]}
    assert wrong.json()["code"] == "invalid_credentials"
    assert "password" not in wrong.text.lower().replace("invalid_credentials", "")


def test_failed_login_is_recorded_even_though_the_request_failed(
    app: FastAPI, client: TestClient
) -> None:
    """The session commits on a handled failure, and this is why.

    A rolled-back transaction would erase the audit row and the attempt record
    for exactly the requests worth investigating, leaving an attacker's failures
    invisible.
    """
    email = create_admin(app, Role.AUDITOR)
    client.post("/api/v1/auth/login", json={"email": email, "password": "wrong-password"})

    with app.state.session_factory() as session:
        attempts = session.execute(
            text("SELECT count(*) FROM login_attempts WHERE email = :e AND succeeded = false"),
            {"e": email},
        ).scalar_one()
        audited = session.execute(
            text("SELECT count(*) FROM audit_logs WHERE action = 'login_failed' AND actor_id = :e"),
            {"e": email},
        ).scalar_one()

    assert attempts == 1
    assert audited == 1


def test_lockout_after_five_failures_in_the_window(app: FastAPI, client: TestClient) -> None:
    email = create_admin(app, Role.IT_ADMIN)
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"email": email, "password": "wrong-password"})

    # Even the correct password is now refused, with the same opaque body.
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_credentials"
    assert "lock" not in response.text.lower()

    with app.state.session_factory() as session:
        locked = session.execute(
            text("SELECT locked_until IS NOT NULL FROM users WHERE email = :e"), {"e": email}
        ).scalar_one()
    assert locked is True


def test_me_reports_the_role_and_its_capabilities(app: FastAPI, client: TestClient) -> None:
    headers = as_role(app, client, Role.SECURITY_ANALYST)
    payload = client.get("/api/v1/auth/me", headers=headers).json()

    assert payload["role"] == "security_analyst"
    assert "usb_exception_manage" in payload["capabilities"]
    assert "audit_export" not in payload["capabilities"]
    assert "policy_write" not in payload["capabilities"]


def test_refresh_rotates_and_reuse_kills_the_family(app: FastAPI, client: TestClient) -> None:
    """Single use. A replayed refresh token ends the session.

    At that point either an attacker holds a stolen copy or the client is
    replaying, and there is no way to tell which, so the safe move is to end it.
    """
    email = create_admin(app, Role.IT_ADMIN)
    client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    original = client.cookies.get("ubuntuguard_refresh")
    assert original

    first = client.post("/api/v1/auth/refresh")
    assert first.status_code == 200
    rotated_access = first.json()["access_token"]

    # Replay the original, which has now been used.
    client.cookies.set("ubuntuguard_refresh", original, path="/api/v1/auth")
    replay = client.post("/api/v1/auth/refresh")
    assert replay.status_code == 401

    # The whole family is gone, so the access token issued by the rotation dies too.
    assert client.get("/api/v1/auth/me", headers=bearer(rotated_access)).status_code == 401

    with app.state.session_factory() as session:
        detected = session.execute(
            text("SELECT count(*) FROM audit_logs WHERE action = 'token_reuse_detected'")
        ).scalar_one()
    assert detected >= 1


def test_logout_revokes_the_access_token(app: FastAPI, client: TestClient) -> None:
    email = create_admin(app, Role.IT_ADMIN)
    token = login(client, email)
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 200

    assert client.post("/api/v1/auth/logout").status_code == 204
    # Revocation is immediate because every request re-reads the token row.
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


# --------------------------------------------------------------------------- #
# The role matrix, on real routes
# --------------------------------------------------------------------------- #

ROUTE_MATRIX: list[tuple[str, str, dict[str, int]]] = [
    # (method, path, {role: expected status})
    (
        "GET",
        "/api/v1/users",
        {"super_admin": 200, "it_admin": 403, "security_analyst": 403, "auditor": 403},
    ),
    (
        "GET",
        "/api/v1/devices",
        {"super_admin": 200, "it_admin": 200, "security_analyst": 200, "auditor": 200},
    ),
    (
        "GET",
        "/api/v1/enrollment-tokens",
        {"super_admin": 200, "it_admin": 200, "security_analyst": 403, "auditor": 403},
    ),
    (
        "GET",
        "/api/v1/audit-logs",
        {"super_admin": 200, "it_admin": 200, "security_analyst": 200, "auditor": 200},
    ),
    (
        "GET",
        "/api/v1/audit-logs:verify",
        {"super_admin": 200, "it_admin": 200, "security_analyst": 200, "auditor": 200},
    ),
    (
        "POST",
        "/api/v1/audit-logs:export",
        {"super_admin": 200, "it_admin": 403, "security_analyst": 403, "auditor": 200},
    ),
]


@pytest.mark.parametrize(("method", "path", "expected"), ROUTE_MATRIX)
def test_route_matrix(
    app: FastAPI, client: TestClient, method: str, path: str, expected: dict[str, int]
) -> None:
    """The signed-off matrix, enforced by the real routes rather than in a unit.

    Denials are asserted as explicitly as grants: "it_admin cannot export the
    audit log" is a requirement, not an absence of one.
    """
    for role_name, status in expected.items():
        headers = as_role(app, client, Role(role_name))
        response = client.request(method, path, headers=headers)
        assert response.status_code == status, (
            f"{method} {path} as {role_name}: expected {status}, got "
            f"{response.status_code} {response.text[:200]}"
        )


def test_forbidden_does_not_reveal_the_capability(app: FastAPI, client: TestClient) -> None:
    headers = as_role(app, client, Role.IT_ADMIN)
    response = client.post("/api/v1/audit-logs:export", headers=headers)
    assert response.status_code == 403
    assert "audit_export" not in response.text
    assert "it_admin" not in response.text


# --------------------------------------------------------------------------- #
# Enrollment tokens
# --------------------------------------------------------------------------- #


def test_token_plaintext_is_returned_once_and_never_listed(
    app: FastAPI, client: TestClient
) -> None:
    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, token_id = mint_token(client, headers, label="finance laptop")

    listing = client.get("/api/v1/enrollment-tokens", headers=headers)
    assert listing.status_code == 200
    body = listing.text
    assert plaintext not in body, "the token plaintext must never be listed"

    import hashlib

    assert hashlib.sha256(plaintext.encode()).hexdigest() not in body, (
        "even the hash must not be listed; combined with a captured plaintext it "
        "would confirm which token was which"
    )
    entry = next(row for row in listing.json() if row["id"] == token_id)
    assert entry["status"] == "active"
    assert entry["label"] == "finance laptop"


def test_revoking_a_consumed_token_conflicts(app: FastAPI, client: TestClient) -> None:
    """An operator revoking a token needs to know whether they were in time."""
    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, token_id = mint_token(client, headers)
    csr, _ = make_csr()
    assert (
        client.post("/api/v1/enroll", json=enroll_body(csr, enrollment_token=plaintext)).status_code
        == 201
    )

    response = client.post(f"/api/v1/enrollment-tokens/{token_id}:revoke", headers=headers)
    assert response.status_code == 409
    assert response.json()["code"] == "enrollment_token_not_revocable"


# --------------------------------------------------------------------------- #
# Device enrollment
# --------------------------------------------------------------------------- #


def test_enrollment_issues_a_certificate_bound_to_the_server_allocated_id(
    app: FastAPI, client: TestClient
) -> None:
    """The CSR asks to be called something else; the server ignores it.

    The common name IS the device identity on the mTLS path, so a client that
    could choose it could impersonate another device.
    """
    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, _ = mint_token(client, headers)
    csr, _ = make_csr(common_name="i-am-the-ceo-laptop")

    response = client.post("/api/v1/enroll", json=enroll_body(csr, enrollment_token=plaintext))
    assert response.status_code == 201, response.text
    payload = response.json()

    certificate = x509.load_pem_x509_certificate(payload["client_certificate_pem"].encode())
    common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert common_name == payload["device_id"]
    assert "i-am-the-ceo-laptop" not in certificate.subject.rfc4514_string()

    # 30 day life, renewal at the half-way point.
    lifetime = certificate.not_valid_after_utc - certificate.not_valid_before_utc
    assert lifetime.days == 30
    renew = dt.datetime.fromisoformat(payload["certificate_renew_after"])
    assert 14 <= (renew - dt.datetime.now(dt.UTC)).days <= 16

    # The agent pins these to verify policy signatures.
    assert payload["policy_public_keys"][0]["alg"] == "ed25519"
    assert payload["policy_public_keys"][0]["key_id"].startswith("ed25519:")
    assert payload["clone_suspected"] is False

    # The issued certificate chains to the advertised CA.
    ca = x509.load_pem_x509_certificate(payload["ca_chain_pem"].encode())
    ca.public_key().verify(  # type: ignore[call-arg,union-attr]
        certificate.signature,
        certificate.tbs_certificate_bytes,
        ec.ECDSA(certificate.signature_hash_algorithm),  # type: ignore[arg-type]
    )


def _audit_head(app: FastAPI) -> int:
    """The current chain head, used as a cursor.

    `GET /audit-logs` pages in ascending sequence order, so reading the tail
    means taking a cursor first rather than asking for the last N.
    """
    from ubuntuguard.db import session_scope

    with session_scope(app.state.session_factory) as session:
        value = session.execute(text("SELECT COALESCE(MAX(seq), 0) FROM audit_logs")).scalar()
    return int(value or 0)


def _audit_since(client: TestClient, headers: dict[str, str], after_seq: int) -> list[dict]:
    entries: list[dict] = []
    cursor = after_seq
    while True:
        page = client.get(
            f"/api/v1/audit-logs?after_seq={cursor}&limit=200", headers=headers
        ).json()
        if not page:
            return entries
        entries.extend(page)
        cursor = page[-1]["seq"]


@pytest.mark.parametrize(
    ("label", "csr_pem"),
    [
        # Regression: this returned 500, not 400. `load_csr_pem` only raises
        # for a CSR that will not PARSE; the key policy lives in `verify_csr`,
        # which was first reached from `issue_device_certificate` outside any
        # handler. So a weak key crashed the request instead of being refused.
        ("weak RSA", "rsa-2048"),
        # Parses as armour, is not a CSR. Long enough to clear csr_pem's
        # min_length of 64, so it reaches the handler rather than the validator.
        (
            "malformed",
            "-----BEGIN CERTIFICATE REQUEST-----\n"
            + "A" * 80
            + "\n-----END CERTIFICATE REQUEST-----\n",
        ),
        # Valid armour, valid base64, not a CSR structure.
        (
            "truncated DER",
            "-----BEGIN CERTIFICATE REQUEST-----\nMIIBXjCB\n-----END CERTIFICATE REQUEST-----\n",
        ),
    ],
)
def test_a_bad_csr_is_refused_with_400_and_does_not_burn_the_token(
    app: FastAPI, client: TestClient, label: str, csr_pem: str
) -> None:
    """400 with a reason code, no certificate, an audit row, and no 500.

    Four assertions because the bug had four symptoms. The status was wrong,
    the reason code was absent, the audit trail was missing - so a fleet-wide
    attempt to enrol weak keys left no trace - and an operator reading a 500
    concludes the server is broken rather than that their request was bad.

    The token surviving matters too: the CSR is checked before the token is
    consumed, so a client that sends a bad CSR can fix it and retry rather than
    having to ask for another token.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa

    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, token_id = mint_token(client, headers)

    if csr_pem == "rsa-2048":
        weak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr_pem = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak")]))
            .sign(weak, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
            .decode("ascii")
        )

    before = _audit_head(app)
    response = client.post("/api/v1/enroll", json=enroll_body(csr_pem, enrollment_token=plaintext))

    assert response.status_code == 400, f"{label}: got {response.status_code} {response.text}"
    payload = response.json()
    assert payload["code"] == "csr_invalid"
    # No internal exception text, no key sizes, no stack frames.
    rendered = response.text
    for leak in ("Traceback", "CsrRejectedError", "ubuntuguard.services", ".py"):
        assert leak not in rendered, f"{label}: response leaks {leak!r}"

    # No certificate was issued.
    admin = as_role(app, client, Role.IT_ADMIN)
    listing = client.get("/api/v1/enrollment-tokens", headers=admin).json()
    this_token = next(row for row in listing if row["id"] == token_id)
    assert this_token["consumed_at"] is None, f"{label}: the token was burned"
    assert this_token["status"] == "active", f"{label}: token status {this_token['status']}"

    # The failure is audited.
    entries = _audit_since(client, admin, before)
    failures = [entry for entry in entries if entry["action"] == "device_enrollment_failed"]
    assert failures, f"{label}: no device_enrollment_failed audit row"
    assert "csr rejected" in failures[-1]["detail"]["reason"]


def test_a_weak_rsa_csr_never_yields_a_certificate(app: FastAPI, client: TestClient) -> None:
    """The security property, separately from the status code.

    The 500 was a classification bug rather than a hole - the key was always
    refused - and this test is what keeps that true if the handling changes
    again.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa

    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, _ = mint_token(client, headers)
    weak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak")]))
        .sign(weak, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )

    response = client.post("/api/v1/enroll", json=enroll_body(csr, enrollment_token=plaintext))
    assert response.status_code != 201
    assert "client_certificate_pem" not in response.json()


def test_a_csr_signed_by_the_wrong_key_is_refused(app: FastAPI, client: TestClient) -> None:
    """The signature check also lives in `verify_csr`, so it moved too.

    A CSR whose signature does not match its public key proves no possession of
    the private key, which is the whole point of requiring one.
    """
    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, _ = mint_token(client, headers)

    # Build a valid CSR, then corrupt its signature in place. The structure
    # still parses, so only `is_signature_valid` can catch it.
    csr_pem, _ = make_csr()
    der = x509.load_pem_x509_csr(csr_pem.encode()).public_bytes(serialization.Encoding.DER)
    corrupted = bytearray(der)
    corrupted[-1] ^= 0xFF
    try:
        tampered = x509.load_der_x509_csr(bytes(corrupted)).public_bytes(serialization.Encoding.PEM)
    except ValueError:
        pytest.skip("flipping the last DER byte made the CSR unparseable rather than unsigned")

    response = client.post(
        "/api/v1/enroll",
        json=enroll_body(tampered.decode("ascii"), enrollment_token=plaintext),
    )
    assert response.status_code == 400
    assert response.json()["code"] == "csr_invalid"


def test_a_valid_enrollment_still_succeeds_after_the_csr_hardening(
    app: FastAPI, client: TestClient
) -> None:
    """The control for the three tests above.

    Moving `verify_csr` earlier must not have narrowed what a legitimate agent
    may present. EC P-256 is what the agent generates; the server also accepts
    P-384 and Ed25519, and all three go through the same check now.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    for label, key in (
        ("P-256", ec.generate_private_key(ec.SECP256R1())),
        ("P-384", ec.generate_private_key(ec.SECP384R1())),
    ):
        headers = as_role(app, client, Role.IT_ADMIN)
        plaintext, _ = mint_token(client, headers)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
            .decode("ascii")
        )
        response = client.post("/api/v1/enroll", json=enroll_body(csr, enrollment_token=plaintext))
        assert response.status_code == 201, f"{label}: {response.text}"

    # Ed25519 signs without a hash algorithm, so it is built separately.
    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, _ = mint_token(client, headers)
    signing_key = ed25519.Ed25519PrivateKey.generate()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(signing_key, None)
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )
    response = client.post("/api/v1/enroll", json=enroll_body(csr, enrollment_token=plaintext))
    assert response.status_code == 201, f"Ed25519: {response.text}"


def test_retrying_with_the_same_keypair_is_idempotent(app: FastAPI, client: TestClient) -> None:
    """The common real failure: the server committed, the response was lost."""
    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, _ = mint_token(client, headers)
    csr, _ = make_csr()
    body = enroll_body(csr, enrollment_token=plaintext)

    first = client.post("/api/v1/enroll", json=body)
    second = client.post("/api/v1/enroll", json=body)

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json() == second.json(), "a retry must return the identical response"


def test_same_token_with_a_different_keypair_is_refused(app: FastAPI, client: TestClient) -> None:
    """Idempotency must not become token reuse."""
    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, _ = mint_token(client, headers)
    first_csr, _ = make_csr()
    other_csr, _ = make_csr()

    assert (
        client.post(
            "/api/v1/enroll", json=enroll_body(first_csr, enrollment_token=plaintext)
        ).status_code
        == 201
    )
    second = client.post("/api/v1/enroll", json=enroll_body(other_csr, enrollment_token=plaintext))
    assert second.status_code == 401
    assert second.json()["code"] == "enrollment_token_invalid"


def test_expired_token_is_refused(app: FastAPI, client: TestClient) -> None:
    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, token_id = mint_token(client, headers, ttl_seconds=60)

    with app.state.session_factory() as session:
        session.execute(
            text(
                "UPDATE enrollment_tokens SET expires_at = now() - interval '1 minute' "
                "WHERE id = :i"
            ),
            {"i": token_id},
        )
        session.commit()

    csr, _ = make_csr()
    response = client.post("/api/v1/enroll", json=enroll_body(csr, enrollment_token=plaintext))
    assert response.status_code == 401
    assert response.json()["code"] == "enrollment_token_invalid"


def test_revoked_token_is_refused(app: FastAPI, client: TestClient) -> None:
    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, token_id = mint_token(client, headers)
    assert (
        client.post(f"/api/v1/enrollment-tokens/{token_id}:revoke", headers=headers).status_code
        == 204
    )

    csr, _ = make_csr()
    assert (
        client.post("/api/v1/enroll", json=enroll_body(csr, enrollment_token=plaintext)).status_code
        == 401
    )


def test_unknown_token_is_refused(app: FastAPI, client: TestClient) -> None:
    csr, _ = make_csr()
    response = client.post("/api/v1/enroll", json=enroll_body(csr, enrollment_token="A" * 43))
    assert response.status_code == 401


def test_malformed_csr_does_not_burn_the_token(app: FastAPI, client: TestClient) -> None:
    """A bad request must not consume a single-use credential."""
    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, token_id = mint_token(client, headers)

    bad = client.post(
        "/api/v1/enroll",
        json=enroll_body(
            "-----BEGIN CERTIFICATE REQUEST-----\n"
            + "A" * 64
            + "\n-----END CERTIFICATE REQUEST-----",
            enrollment_token=plaintext,
        ),
    )
    assert bad.status_code == 400
    assert bad.json()["code"] == "csr_invalid"

    # The token is still usable.
    csr, _ = make_csr()
    assert (
        client.post("/api/v1/enroll", json=enroll_body(csr, enrollment_token=plaintext)).status_code
        == 201
    )


def test_two_simultaneous_enrollments_yield_exactly_one_success(
    app: FastAPI, client: TestClient
) -> None:
    """The brief's requirement, over real HTTP with real contention."""
    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, _ = mint_token(client, headers)
    bodies = [enroll_body(make_csr()[0], enrollment_token=plaintext) for _ in range(6)]

    def attempt(body: dict[str, object]) -> int:
        with TestClient(app, client=("127.0.0.1", 54321)) as isolated:
            return isolated.post("/api/v1/enroll", json=body).status_code

    with ThreadPoolExecutor(max_workers=6) as pool:
        statuses = list(pool.map(attempt, bodies))

    assert statuses.count(201) == 1, f"expected exactly one success, got {statuses}"
    assert statuses.count(401) == 5


def test_clone_detection_enrolls_distinctly_and_raises_an_incident(
    app: FastAPI, client: TestClient
) -> None:
    """A reimaged laptop and a cloned VM look identical here.

    So enrollment succeeds as a distinct device and a human is told, rather than
    the server guessing and blocking a legitimate rebuild.
    """
    headers = as_role(app, client, Role.IT_ADMIN)
    machine_id_hash = uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars

    first_token, _ = mint_token(client, headers)
    second_token, _ = mint_token(client, headers)
    fingerprint = {"machine_id_hash": machine_id_hash}

    first = client.post(
        "/api/v1/enroll",
        json=enroll_body(
            make_csr()[0], enrollment_token=first_token, hardware_fingerprint=fingerprint
        ),
    )
    second = client.post(
        "/api/v1/enroll",
        json=enroll_body(
            make_csr()[0], enrollment_token=second_token, hardware_fingerprint=fingerprint
        ),
    )

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["clone_suspected"] is False
    assert second.json()["clone_suspected"] is True
    assert first.json()["device_id"] != second.json()["device_id"]

    with app.state.session_factory() as session:
        incidents = session.execute(
            text("SELECT count(*) FROM incidents WHERE kind='clone_suspected' AND device_id = :d"),
            {"d": second.json()["device_id"]},
        ).scalar_one()
        audited = session.execute(
            text(
                "SELECT count(*) FROM audit_logs WHERE action='clone_suspected' AND target_id = :d"
            ),
            {"d": second.json()["device_id"]},
        ).scalar_one()
    assert incidents == 1
    assert audited == 1


# --------------------------------------------------------------------------- #
# Device plane and revocation
# --------------------------------------------------------------------------- #


def enrol_a_device(app: FastAPI, client: TestClient) -> tuple[str, str]:
    headers = as_role(app, client, Role.IT_ADMIN)
    plaintext, _ = mint_token(client, headers)
    csr, _ = make_csr()
    payload = client.post(
        "/api/v1/enroll", json=enroll_body(csr, enrollment_token=plaintext)
    ).json()
    return payload["device_id"], payload["client_certificate_pem"]


def test_heartbeat_authenticates_by_certificate_and_updates_liveness(
    app: FastAPI, client: TestClient
) -> None:
    device_id, certificate_pem = enrol_a_device(app, client)

    response = client.post(
        "/api/v1/devices/me/heartbeat",
        headers=device_headers(certificate_pem),
        json={"agent_version": "0.1.0", "uptime_seconds": 120, "applied_policy_versions": {}},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["heartbeat_seconds"] == 60
    # No command channel: the response carries scheduling and versions only.
    assert set(payload) == {
        "server_time",
        "heartbeat_seconds",
        "heartbeat_jitter_pct",
        "certificate_renew_after",
        "available_policies",
    }

    admin = as_role(app, client, Role.IT_ADMIN)
    detail = client.get(f"/api/v1/devices/{device_id}", headers=admin).json()
    assert detail["online"] is True
    assert detail["last_heartbeat_at"] is not None


def test_certificate_headers_from_an_untrusted_peer_are_refused(app: FastAPI) -> None:
    """A genuine certificate, genuine headers, wrong source address.

    Anyone who can set X-Client-Cert on a request the app believes could
    impersonate any device, so the headers are trusted only from the proxy.
    """
    with TestClient(app, client=("127.0.0.1", 54321)) as trusted:
        _, certificate_pem = enrol_a_device(app, trusted)

    with TestClient(app, client=("203.0.113.7", 40000)) as untrusted:
        response = untrusted.post(
            "/api/v1/devices/me/heartbeat",
            headers=device_headers(certificate_pem),
            json={"agent_version": "0.1.0", "uptime_seconds": 1},
        )
    assert response.status_code == 401
    assert response.json()["code"] == "untrusted_proxy"


def test_revocation_takes_effect_on_the_next_request(app: FastAPI, client: TestClient) -> None:
    """Revocation is a per-request status check, not CRL propagation.

    So the bound is "within one request" rather than a cache-expiry race.
    """
    device_id, certificate_pem = enrol_a_device(app, client)
    headers = device_headers(certificate_pem)
    beat = {"agent_version": "0.1.0", "uptime_seconds": 1}

    assert (
        client.post("/api/v1/devices/me/heartbeat", headers=headers, json=beat).status_code == 200
    )

    admin = as_role(app, client, Role.IT_ADMIN)
    revoke = client.post(
        f"/api/v1/devices/{device_id}:revoke",
        headers=admin,
        json={"reason": "laptop reported lost by the user"},
    )
    assert revoke.status_code == 204

    after = client.post("/api/v1/devices/me/heartbeat", headers=headers, json=beat)
    assert after.status_code == 401
    assert after.json()["code"] == "device_not_active"


def test_revoke_requires_a_substantive_reason(app: FastAPI, client: TestClient) -> None:
    device_id, _ = enrol_a_device(app, client)
    admin = as_role(app, client, Role.IT_ADMIN)
    response = client.post(
        f"/api/v1/devices/{device_id}:revoke", headers=admin, json={"reason": "test"}
    )
    assert response.status_code == 422


def test_analyst_cannot_revoke_a_device(app: FastAPI, client: TestClient) -> None:
    device_id, _ = enrol_a_device(app, client)
    analyst = as_role(app, client, Role.SECURITY_ANALYST)
    response = client.post(
        f"/api/v1/devices/{device_id}:revoke",
        headers=analyst,
        json={"reason": "a perfectly good reason"},
    )
    assert response.status_code == 403


def test_device_search_filters(app: FastAPI, client: TestClient) -> None:
    device_id, _ = enrol_a_device(app, client)
    admin = as_role(app, client, Role.IT_ADMIN)
    detail = client.get(f"/api/v1/devices/{device_id}", headers=admin).json()

    hits = client.get(
        "/api/v1/devices", headers=admin, params={"q": detail["hostname"][:12]}
    ).json()
    assert any(row["id"] == device_id for row in hits)

    misses = client.get("/api/v1/devices", headers=admin, params={"os_version_id": "18.04"}).json()
    assert all(row["id"] != device_id for row in misses)


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


def test_audit_chain_verifies_after_all_this_activity(app: FastAPI, client: TestClient) -> None:
    """Every test above appended audit rows, many concurrently.

    The chain holding across all of it is what shows the advisory lock in the
    append path actually serialises writers.
    """
    headers = as_role(app, client, Role.AUDITOR)
    result = client.get("/api/v1/audit-logs:verify", headers=headers).json()
    assert result["ok"] is True, result
    assert result["checked"] > 0
    assert result["broken_at_seq"] is None


def test_audit_entries_are_readable_and_carry_no_secrets(app: FastAPI, client: TestClient) -> None:
    headers = as_role(app, client, Role.AUDITOR)
    entries = client.get("/api/v1/audit-logs", headers=headers, params={"limit": 200}).json()
    assert entries

    body = client.get("/api/v1/audit-logs", headers=headers, params={"limit": 200}).text
    assert PASSWORD not in body
    assert "password_hash" not in body
    assert "$argon2" not in body


def test_export_is_itself_audited(app: FastAPI, client: TestClient) -> None:
    headers = as_role(app, client, Role.AUDITOR)
    before = client.get("/api/v1/audit-logs:verify", headers=headers).json()["checked"]

    response = client.post("/api/v1/audit-logs:export", headers=headers, params={"limit": 10})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "seq,occurred_at,action" in response.text

    after = client.get("/api/v1/audit-logs:verify", headers=headers).json()
    assert after["checked"] > before
    assert after["ok"] is True

    with app.state.session_factory() as session:
        exports = session.execute(
            text("SELECT count(*) FROM audit_logs WHERE action = 'audit_exported'")
        ).scalar_one()
    assert exports >= 1


def test_tampering_with_an_audit_row_is_detected(app: FastAPI, client: TestClient) -> None:
    """Uses the OWNER role to simulate an attacker who bypassed the application.

    The app role cannot do this at all - PostgreSQL refuses it - which is the
    first barrier. This test exercises the second one: that a change made around
    the application is still detectable afterwards.
    """
    from sqlalchemy import create_engine

    owner_url = _env_from_file().get("migration_database_url")
    if not owner_url:
        pytest.skip("no owner URL available to simulate out-of-band tampering")

    headers = as_role(app, client, Role.AUDITOR)
    assert client.get("/api/v1/audit-logs:verify", headers=headers).json()["ok"] is True

    engine = create_engine(owner_url, future=True)
    try:
        with engine.begin() as connection:
            target = connection.execute(
                text("SELECT seq, action FROM audit_logs ORDER BY seq LIMIT 1")
            ).one()
            # The trigger blocks the owner too, so drop it for the duration.
            connection.execute(
                text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only")
            )
            connection.execute(
                text("UPDATE audit_logs SET action = 'nothing_happened' WHERE seq = :s"),
                {"s": target.seq},
            )

        broken = client.get("/api/v1/audit-logs:verify", headers=headers).json()
        assert broken["ok"] is False
        assert broken["broken_at_seq"] == target.seq
        assert "altered" in (broken["reason"] or "")
    finally:
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE audit_logs SET action = :a WHERE seq = :s"),
                {"a": target.action, "s": target.seq},
            )
            connection.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_append_only"))
        engine.dispose()

    assert client.get("/api/v1/audit-logs:verify", headers=headers).json()["ok"] is True
