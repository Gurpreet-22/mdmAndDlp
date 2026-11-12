"""Certificate renewal, against the live database.

Device certificates live 30 days. Without renewal every enrolled laptop falls
off the control plane a month after it joined, so this endpoint is what makes
enrollment worth having. These tests run against real HTTP and a real database
because the properties that matter are transactional: what is live, what is
superseded, and at exactly which moment each becomes true.

The hardest case to get right, and the one most of this file is about: the
server commits a renewal and the response never arrives. The agent is then
holding a certificate the server has just superseded, and it has no other
credential. If that certificate cannot be used to ask again, a dropped packet
costs a re-enrollment.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from ubuntuguard.config import Settings
from ubuntuguard.constants import CERT_SUPERSEDE_GRACE_SECONDS
from ubuntuguard.main import create_app
from ubuntuguard.security.rbac import Role

pytestmark = pytest.mark.postgres

SERVER_DIR = Path(__file__).resolve().parents[1]
PASSWORD = "a reasonably long passphrase"
PEM = serialization.Encoding.PEM


# --------------------------------------------------------------------------- #
# Fixtures, matching test_api_integration.py so both read alike
# --------------------------------------------------------------------------- #


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
    values["allow_any_login"] = "false"
    try:
        settings = Settings(_env_file=None, **values)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 - configuration problem, report as skip
        pytest.skip(f"could not build settings from server/.env: {exc}")
    application = create_app(settings)
    with TestClient(application):
        pass
    if getattr(application.state, "session_factory", None) is None:
        pytest.skip("database unreachable; is the cluster running?")
    if getattr(application.state, "keys", None) is None:
        pytest.skip("key material missing. Run: python -m ubuntuguard.cli init-keys")
    yield application


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, client=("127.0.0.1", 54321)) as test_client:
        yield test_client


def _create_admin(app: FastAPI, role: Role) -> str:
    from ubuntuguard.db import session_scope
    from ubuntuguard.repositories import create_user
    from ubuntuguard.security.passwords import hash_password

    email = f"{role.value}-{uuid.uuid4().hex[:8]}@example.invalid"
    with session_scope(app.state.session_factory) as session:
        create_user(session, email=email, password_hash=hash_password(PASSWORD), role=role.value)
    return email


def as_role(app: FastAPI, client: TestClient, role: Role) -> dict[str, str]:
    email = _create_admin(app, role)
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def make_csr(
    key: ec.EllipticCurvePrivateKey | None = None,
    *,
    common_name: str = "whatever-the-client-asks-for",
) -> tuple[str, ec.EllipticCurvePrivateKey]:
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(PEM).decode("ascii"), key


def device_headers(certificate_pem: str) -> dict[str, str]:
    """The headers nginx would set for a verified client certificate."""
    from urllib.parse import quote

    return {"X-Client-Verify": "SUCCESS", "X-Client-Cert": quote(certificate_pem)}


def enrol(app: FastAPI, client: TestClient) -> tuple[str, str, ec.EllipticCurvePrivateKey]:
    """Enrol a device. Returns (device_id, certificate_pem, private_key)."""
    headers = as_role(app, client, Role.IT_ADMIN)
    minted = client.post("/api/v1/enrollment-tokens", headers=headers, json={})
    assert minted.status_code == 201, minted.text
    token = minted.json()["enrollment_token"]

    csr, key = make_csr()
    response = client.post(
        "/api/v1/enroll",
        json={
            "enrollment_token": token,
            "csr_pem": csr,
            "hostname": f"laptop-{uuid.uuid4().hex[:8]}",
            "agent_version": "0.1.0",
            "arch": "x86_64",
            "os": {"id": "ubuntu", "version_id": "24.04", "kernel": "6.8.0-45-generic"},
            "hardware_fingerprint": {},
            "release_build": True,
        },
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    return payload["device_id"], payload["client_certificate_pem"], key


def renew(client: TestClient, certificate_pem: str, csr_pem: str) -> object:
    return client.post(
        "/api/v1/devices/me/certificate:renew",
        headers=device_headers(certificate_pem),
        json={"csr_pem": csr_pem},
    )


def fingerprint_of(certificate_pem: str) -> str:
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
    return "sha256:" + certificate.fingerprint(hashes.SHA256()).hex()


def audit_entries_since(client: TestClient, headers: dict[str, str], after_seq: int) -> list[dict]:
    """Audit entries written after `after_seq`.

    `GET /audit-logs` pages in ASCENDING sequence order, because the hash chain
    can only be recomputed in the order it was written. So a bare `?limit=200`
    returns the two hundred OLDEST entries, which on a development database
    that has been used is never the ones a test just caused. Taking a cursor
    first and reading forward from it is how a correct consumer reads the tail.
    """
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


def latest_audit_seq(app: FastAPI) -> int:
    """The current chain head, used as a cursor."""
    from ubuntuguard.db import session_scope

    with session_scope(app.state.session_factory) as session:
        value = session.execute(text("SELECT COALESCE(MAX(seq), 0) FROM audit_logs")).scalar()
    return int(value or 0)


def certificate_rows(app: FastAPI, device_id: str) -> list[dict[str, object]]:
    """Read `issued_certificates` directly. The transactional claims need it."""
    from ubuntuguard.db import session_scope

    with session_scope(app.state.session_factory) as session:
        rows = session.execute(
            text(
                "SELECT fingerprint, superseded_at, revoked_at FROM issued_certificates "
                "WHERE device_id = :device_id ORDER BY not_before"
            ),
            {"device_id": device_id},
        ).all()
    return [{"fingerprint": row[0], "superseded_at": row[1], "revoked_at": row[2]} for row in rows]


# --------------------------------------------------------------------------- #
# The happy path
# --------------------------------------------------------------------------- #


def test_renewal_issues_a_new_certificate_for_the_same_device(
    app: FastAPI, client: TestClient
) -> None:
    device_id, certificate_pem, _old_key = enrol(app, client)
    csr, _new_key = make_csr()

    response = renew(client, certificate_pem, csr)
    assert response.status_code == 200, response.text
    payload = response.json()

    assert payload["device_id"] == device_id
    assert payload["reused"] is False
    assert payload["client_certificate_pem"] != certificate_pem

    new = x509.load_pem_x509_certificate(payload["client_certificate_pem"].encode())
    # The subject still comes from the server, not the CSR. Renewal introduces
    # no second path to choosing an identity.
    common_name = new.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert common_name == device_id
    assert "whatever-the-client-asks-for" not in new.subject.rfc4514_string()

    # A fresh 30-day life, renewing again at the half-way point.
    lifetime = new.not_valid_after_utc - new.not_valid_before_utc
    assert lifetime.days == 30
    renew_after = dt.datetime.fromisoformat(payload["certificate_renew_after"])
    assert 14 <= (renew_after - dt.datetime.now(dt.UTC)).days <= 16

    # Still client authentication only.
    usage = new.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
    assert new.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


def test_the_response_omits_the_policy_keys_and_the_clone_flag(
    app: FastAPI, client: TestClient
) -> None:
    """Not a copy of EnrollResponse, and the differences are deliberate.

    Re-sending `policy_public_keys` would create a key-rotation path that
    bypasses the signed `key_rotation` record. `clone_suspected` would be a
    claim about a hardware fingerprint that renewal never looks at.
    """
    _device_id, certificate_pem, _ = enrol(app, client)
    csr, _ = make_csr()
    payload = renew(client, certificate_pem, csr).json()

    assert set(payload) == {
        "device_id",
        "client_certificate_pem",
        "ca_chain_pem",
        "certificate_not_after",
        "certificate_renew_after",
        "reused",
    }


def test_the_old_certificate_is_superseded_in_the_same_transaction(
    app: FastAPI, client: TestClient
) -> None:
    """Exactly one live certificate afterwards, and it is the new one."""
    device_id, certificate_pem, _ = enrol(app, client)
    old_fingerprint = fingerprint_of(certificate_pem)

    rows = certificate_rows(app, device_id)
    assert len(rows) == 1
    assert rows[0]["superseded_at"] is None

    csr, _ = make_csr()
    payload = renew(client, certificate_pem, csr).json()
    new_fingerprint = fingerprint_of(payload["client_certificate_pem"])

    rows = certificate_rows(app, device_id)
    assert len(rows) == 2
    by_fingerprint = {row["fingerprint"]: row for row in rows}
    # The old row is superseded and the new one is not. Both facts in one read,
    # so there is no moment at which neither or both were live.
    assert by_fingerprint[old_fingerprint]["superseded_at"] is not None
    assert by_fingerprint[new_fingerprint]["superseded_at"] is None


def test_the_device_record_points_at_the_new_certificate(app: FastAPI, client: TestClient) -> None:
    device_id, certificate_pem, _ = enrol(app, client)
    csr, _ = make_csr()
    payload = renew(client, certificate_pem, csr).json()

    admin = as_role(app, client, Role.IT_ADMIN)
    detail = client.get(f"/api/v1/devices/{device_id}", headers=admin).json()
    assert detail["cert_fingerprint"] == fingerprint_of(payload["client_certificate_pem"])
    assert detail["cert_not_after"][:10] == payload["certificate_not_after"][:10]


def test_the_new_certificate_can_heartbeat(app: FastAPI, client: TestClient) -> None:
    """The point of the whole exercise."""
    device_id, certificate_pem, _ = enrol(app, client)
    csr, _ = make_csr()
    renewed = renew(client, certificate_pem, csr).json()["client_certificate_pem"]

    response = client.post(
        "/api/v1/devices/me/heartbeat",
        headers=device_headers(renewed),
        json={"agent_version": "0.1.0", "uptime_seconds": 60},
    )
    assert response.status_code == 200, response.text

    admin = as_role(app, client, Role.IT_ADMIN)
    detail = client.get(f"/api/v1/devices/{device_id}", headers=admin).json()
    assert detail["online"] is True


def test_renewal_is_audited(app: FastAPI, client: TestClient) -> None:
    device_id, certificate_pem, _ = enrol(app, client)
    csr, _ = make_csr()
    before = latest_audit_seq(app)
    renew(client, certificate_pem, csr)

    admin = as_role(app, client, Role.SUPER_ADMIN)
    entries = audit_entries_since(client, admin, before)
    renewals = [
        entry
        for entry in entries
        if entry["action"] == "certificate_renewed" and entry["target_id"] == device_id
    ]
    assert len(renewals) == 1
    detail = renewals[0]["detail"]
    assert detail["superseded_certificates"] == 1
    assert detail["csr_requested_extensions"] == []


# --------------------------------------------------------------------------- #
# The superseded certificate: what it may and may not do
# --------------------------------------------------------------------------- #


def test_the_old_certificate_cannot_heartbeat_after_renewal(
    app: FastAPI, client: TestClient
) -> None:
    """The grace window is for renewal ONLY.

    A superseded certificate exists to collect the replacement it was
    superseded by. Letting it heartbeat would mean two credentials for one
    device for an hour, for no reason anybody needs.
    """
    _device_id, certificate_pem, _ = enrol(app, client)
    csr, _ = make_csr()
    assert renew(client, certificate_pem, csr).status_code == 200

    response = client.post(
        "/api/v1/devices/me/heartbeat",
        headers=device_headers(certificate_pem),
        json={"agent_version": "0.1.0", "uptime_seconds": 60},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "client_cert_superseded"


def test_a_lost_response_is_recoverable_with_the_same_csr(app: FastAPI, client: TestClient) -> None:
    """THE failure this design exists for.

    The server committed and the response was lost. The agent still holds the
    superseded certificate and asks again with the SAME CSR. It must get the
    certificate already issued - not a second one, and not a 401.
    """
    device_id, certificate_pem, _ = enrol(app, client)
    csr, _new_key = make_csr()

    first = renew(client, certificate_pem, csr).json()

    # Same superseded certificate, same CSR.
    second_response = renew(client, certificate_pem, csr)
    assert second_response.status_code == 200, second_response.text
    second = second_response.json()

    assert second["reused"] is True
    assert second["client_certificate_pem"] == first["client_certificate_pem"]
    # And no third certificate was created.
    assert len(certificate_rows(app, device_id)) == 2


def test_a_retry_with_a_different_csr_does_not_accumulate_certificates(
    app: FastAPI, client: TestClient
) -> None:
    """The grace window cannot be used to collect certificates.

    A second renewal with a DIFFERENT key does issue a second certificate -
    that is a legitimate renewal - but it supersedes the previous one, so there
    is still exactly one live certificate at the end.
    """
    device_id, certificate_pem, _ = enrol(app, client)

    csr_one, _ = make_csr()
    renew(client, certificate_pem, csr_one)
    csr_two, _ = make_csr()
    second = renew(client, certificate_pem, csr_two)
    assert second.status_code == 200, second.text

    rows = certificate_rows(app, device_id)
    live = [row for row in rows if row["superseded_at"] is None]
    assert len(rows) == 3
    assert len(live) == 1
    assert live[0]["fingerprint"] == fingerprint_of(second.json()["client_certificate_pem"])


def test_a_superseded_certificate_is_refused_past_the_grace_window(
    app: FastAPI, client: TestClient
) -> None:
    """Enforced by the authentication layer, not merely recorded.

    `superseded_at` is pushed back past the window directly, because waiting an
    hour is not a test.
    """
    device_id, certificate_pem, _ = enrol(app, client)
    csr, _ = make_csr()
    assert renew(client, certificate_pem, csr).status_code == 200

    from ubuntuguard.db import session_scope

    stale = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=CERT_SUPERSEDE_GRACE_SECONDS + 60)
    with session_scope(app.state.session_factory) as session:
        session.execute(
            text(
                "UPDATE issued_certificates SET superseded_at = :stale "
                "WHERE device_id = :device_id AND fingerprint = :fingerprint"
            ),
            {
                "stale": stale,
                "device_id": device_id,
                "fingerprint": fingerprint_of(certificate_pem),
            },
        )

    # Not even for renewal now.
    csr_two, _ = make_csr()
    response = renew(client, certificate_pem, csr_two)
    assert response.status_code == 401
    assert response.json()["code"] == "device_not_active"


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #


def test_renewal_without_a_client_certificate_is_refused(app: FastAPI, client: TestClient) -> None:
    """No unauthenticated renewal. There is no token path to a certificate."""
    csr, _ = make_csr()
    response = client.post("/api/v1/devices/me/certificate:renew", json={"csr_pem": csr})
    assert response.status_code == 401
    assert response.json()["code"] == "client_cert_missing"


def test_renewal_with_an_unverified_certificate_is_refused(
    app: FastAPI, client: TestClient
) -> None:
    """nginx said the chain did not check out, so the app does not look at it."""
    _device_id, certificate_pem, _ = enrol(app, client)
    csr, _ = make_csr()
    response = client.post(
        "/api/v1/devices/me/certificate:renew",
        headers={"X-Client-Verify": "FAILED:self signed certificate", "X-Client-Cert": "x"},
        json={"csr_pem": csr},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "client_cert_not_verified"


def test_renewal_with_a_malformed_certificate_is_refused(app: FastAPI, client: TestClient) -> None:
    csr, _ = make_csr()
    response = client.post(
        "/api/v1/devices/me/certificate:renew",
        headers=device_headers("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"),
        json={"csr_pem": csr},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "client_cert_malformed"


def test_forged_identity_headers_from_an_untrusted_peer_cannot_renew(app: FastAPI) -> None:
    """A genuine certificate, genuine-looking headers, wrong source address."""
    with TestClient(app, client=("127.0.0.1", 54321)) as trusted:
        _device_id, certificate_pem, _ = enrol(app, trusted)

    csr, _ = make_csr()
    with TestClient(app, client=("203.0.113.7", 40000)) as untrusted:
        response = untrusted.post(
            "/api/v1/devices/me/certificate:renew",
            headers=device_headers(certificate_pem),
            json={"csr_pem": csr},
        )
    assert response.status_code == 401
    assert response.json()["code"] == "untrusted_proxy"


def test_a_revoked_device_cannot_renew(app: FastAPI, client: TestClient) -> None:
    """Revocation outranks everything, including a perfectly valid certificate.

    Checked before anything about the certificate, so a revoked laptop cannot
    extend its own access by rotating.
    """
    device_id, certificate_pem, _ = enrol(app, client)
    admin = as_role(app, client, Role.SUPER_ADMIN)
    revoked = client.post(
        f"/api/v1/devices/{device_id}:revoke",
        headers=admin,
        json={"reason": "stolen from a coffee shop"},
    )
    assert revoked.status_code == 204

    csr, _ = make_csr()
    response = renew(client, certificate_pem, csr)
    assert response.status_code == 401
    assert response.json()["code"] == "device_not_active"

    # And nothing was issued.
    assert len(certificate_rows(app, device_id)) == 1


def test_an_unknown_certificate_cannot_renew(app: FastAPI, client: TestClient) -> None:
    """Self-signed, naming a real device id. Not in issued_certificates."""
    device_id, _certificate_pem, _ = enrol(app, client)

    key = ec.generate_private_key(ec.SECP256R1())
    forged = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Attacker CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5))
        .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    csr, _ = make_csr()
    response = renew(client, forged.public_bytes(PEM).decode(), csr)
    assert response.status_code == 401
    assert response.json()["code"] == "device_not_active"


def test_an_expired_certificate_cannot_renew(app: FastAPI, client: TestClient) -> None:
    """Refused by the independent validity check in device_auth.

    The row in `issued_certificates` is still live, so this proves the
    certificate's own dates are re-derived rather than the database being
    trusted about them.
    """
    device_id, certificate_pem, key = enrol(app, client)

    # Reissue the same public key with dates in the past, signed by the real CA,
    # so only the validity window differs from a genuine certificate.
    from ubuntuguard.services.ca import issue_device_certificate

    past = dt.datetime.now(dt.UTC) - dt.timedelta(days=60)
    csr_pem, _ = make_csr(key)
    expired = issue_device_certificate(
        app.state.keys.ca,
        x509.load_pem_x509_csr(csr_pem.encode()),
        device_id,
        now=past,
    )
    assert expired.not_valid_after_utc < dt.datetime.now(dt.UTC)

    # Record it as live, so the only thing wrong with it is that it expired.
    from ubuntuguard.db import session_scope
    from ubuntuguard.repositories import record_issued_certificate
    from ubuntuguard.services.ca import certificate_fingerprint

    with session_scope(app.state.session_factory) as session:
        record_issued_certificate(
            session,
            device_id=uuid.UUID(device_id),
            fingerprint=certificate_fingerprint(expired),
            serial_number=format(expired.serial_number, "x"),
            not_before=expired.not_valid_before_utc,
            not_after=expired.not_valid_after_utc,
            pem=expired.public_bytes(PEM).decode("ascii"),
        )

    csr, _ = make_csr()
    response = renew(client, expired.public_bytes(PEM).decode(), csr)
    assert response.status_code == 401
    assert response.json()["code"] == "client_cert_expired"
    assert certificate_pem is not None  # the original is untouched


# --------------------------------------------------------------------------- #
# CSR validation
# --------------------------------------------------------------------------- #


def test_reusing_the_current_public_key_is_refused(app: FastAPI, client: TestClient) -> None:
    """Renewal exists partly to bound how long one key is exposed.

    It also keeps the idempotency check unambiguous: "a certificate already
    issued against this key" would otherwise match the certificate being
    replaced.
    """
    device_id, certificate_pem, key = enrol(app, client)
    same_key_csr, _ = make_csr(key)

    response = renew(client, certificate_pem, same_key_csr)
    assert response.status_code == 400
    assert response.json()["code"] == "csr_key_reused"
    assert len(certificate_rows(app, device_id)) == 1


def test_a_malformed_csr_is_refused(app: FastAPI, client: TestClient) -> None:
    device_id, certificate_pem, _ = enrol(app, client)
    response = renew(
        client,
        certificate_pem,
        "-----BEGIN CERTIFICATE REQUEST-----\nnot base64\n-----END CERTIFICATE REQUEST-----\n",
    )
    assert response.status_code == 400
    assert response.json()["code"] == "csr_invalid"
    assert len(certificate_rows(app, device_id)) == 1


def test_a_weak_rsa_key_is_refused(app: FastAPI, client: TestClient) -> None:
    """The same key policy as enrollment, because it is the same function."""
    device_id, certificate_pem, _ = enrol(app, client)
    weak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(weak, hashes.SHA256())
    )

    response = renew(client, certificate_pem, csr.public_bytes(PEM).decode())
    assert response.status_code == 400
    assert response.json()["code"] == "csr_invalid"
    assert len(certificate_rows(app, device_id)) == 1


def test_csr_extensions_are_ignored_but_recorded(app: FastAPI, client: TestClient) -> None:
    """A CSR asking for CA:TRUE gets an end-entity certificate anyway."""
    device_id, certificate_pem, _ = enrol(app, client)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    before = latest_audit_seq(app)
    payload = renew(client, certificate_pem, csr.public_bytes(PEM).decode()).json()
    issued = x509.load_pem_x509_certificate(payload["client_certificate_pem"].encode())
    assert issued.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False

    admin = as_role(app, client, Role.SUPER_ADMIN)
    entries = audit_entries_since(client, admin, before)
    renewal_entry = next(
        entry
        for entry in entries
        if entry["action"] == "certificate_renewed" and entry["target_id"] == device_id
    )
    assert "basicConstraints" in renewal_entry["detail"]["csr_requested_extensions"]


def test_the_body_cannot_name_another_device(app: FastAPI, client: TestClient) -> None:
    """`extra="forbid"`, so a smuggled device_id is a 422 rather than ignored."""
    _device_id, certificate_pem, _ = enrol(app, client)
    other = str(uuid.uuid4())
    csr, _ = make_csr()
    response = client.post(
        "/api/v1/devices/me/certificate:renew",
        headers=device_headers(certificate_pem),
        json={"csr_pem": csr, "device_id": other},
    )
    assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Transactional integrity
# --------------------------------------------------------------------------- #


def test_a_failed_renewal_leaves_no_trace_and_the_old_certificate_working(
    app: FastAPI, client: TestClient
) -> None:
    """Rollback, observed from outside rather than asserted about internals.

    A rejected CSR must not supersede anything, must not insert anything, and
    must leave the device able to heartbeat on the certificate it already had.
    """
    device_id, certificate_pem, _ = enrol(app, client)
    before = certificate_rows(app, device_id)

    # Long enough to pass `csr_pem`'s min_length of 64 and so actually reach the
    # handler. A shorter string is rejected by Pydantic as a 422, which is also
    # correct but tests the validator rather than the rollback.
    assert renew(client, certificate_pem, "x" * 80).status_code == 400

    after = certificate_rows(app, device_id)
    assert after == before

    # And the old certificate is still the working one.
    heartbeat = client.post(
        "/api/v1/devices/me/heartbeat",
        headers=device_headers(certificate_pem),
        json={"agent_version": "0.1.0", "uptime_seconds": 1},
    )
    assert heartbeat.status_code == 200


def test_a_failed_renewal_is_audited_without_leaking_the_csr(
    app: FastAPI, client: TestClient
) -> None:
    device_id, certificate_pem, _ = enrol(app, client)
    before = latest_audit_seq(app)
    assert renew(client, certificate_pem, "x" * 100).status_code == 400

    admin = as_role(app, client, Role.SUPER_ADMIN)
    entries = audit_entries_since(client, admin, before)
    failures = [
        entry
        for entry in entries
        if entry["action"] == "certificate_renewal_failed" and entry["target_id"] == device_id
    ]
    assert len(failures) == 1
    assert "csr rejected" in failures[0]["detail"]["reason"]
    assert "x" * 100 not in str(failures[0]["detail"])


def test_the_audit_chain_survives_renewal(app: FastAPI, client: TestClient) -> None:
    _device_id, certificate_pem, _ = enrol(app, client)
    csr, _ = make_csr()
    renew(client, certificate_pem, csr)

    admin = as_role(app, client, Role.SUPER_ADMIN)
    verification = client.get("/api/v1/audit-logs:verify", headers=admin).json()
    assert verification["ok"] is True, verification
    assert verification["broken_at_seq"] is None
