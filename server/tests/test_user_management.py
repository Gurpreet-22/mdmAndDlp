"""The user-management routes over HTTP, against the live database.

Covers enable, role change, administrator password reset, the forced
password-change gate, RBAC on all four roles, and the audit rows each
operation writes.

**What this file deliberately does not cover.** The last-super_admin refusal.
Producing that state over HTTP would mean disabling the 1,282 active
super_admin accounts in the development database, which is somebody's real
data. That guard - including its PostgreSQL row locking and the concurrent
case - is tested at the service layer in `test_last_super_admin.py`, against a
throwaway schema. Everything here needs no globally unique account state.

Scratch accounts are created directly rather than over HTTP, matching
`test_api_integration`: bootstrapping a privileged account through an
unauthenticated route would be a backdoor however carefully it was guarded.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from ubuntuguard.config import Settings
from ubuntuguard.main import create_app
from ubuntuguard.security.rbac import Role

pytestmark = pytest.mark.postgres

SERVER_DIR = Path(__file__).resolve().parents[1]
PASSWORD = "a reasonably long passphrase"
NEW_PASSWORD = "an entirely different passphrase"


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
    # These tests exercise real password verification on /auth/password, which
    # the no-authentication placeholder would bypass entirely.
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
    yield application


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, client=("127.0.0.1", 54321)) as test_client:
        yield test_client


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def create_admin(app: FastAPI, role: Role, *, password: str = PASSWORD) -> tuple[str, str]:
    """Create an account directly. Returns (email, id). Bypasses the API."""
    from ubuntuguard.db import session_scope
    from ubuntuguard.repositories import create_user
    from ubuntuguard.security.passwords import hash_password

    email = f"usermgmt-{role.value}-{uuid.uuid4().hex[:8]}@example.invalid"
    with session_scope(app.state.session_factory) as session:
        user = create_user(
            session, email=email, password_hash=hash_password(password), role=role.value
        )
        session.flush()
        return email, str(user.id)


def login(client: TestClient, email: str, password: str = PASSWORD) -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def as_role(app: FastAPI, client: TestClient, role: Role) -> dict[str, str]:
    email, _ = create_admin(app, role)
    return bearer(login(client, email))


def read_user(app: FastAPI, user_id: str) -> dict[str, Any]:
    with app.state.session_factory() as session:
        row = session.execute(
            text(
                "SELECT is_active, role, must_change_password, locked_until, password_hash "
                "FROM users WHERE id = :uid"
            ),
            {"uid": user_id},
        ).fetchone()
    assert row is not None, f"user {user_id} vanished"
    return {
        "is_active": row[0],
        "role": row[1],
        "must_change_password": row[2],
        "locked_until": row[3],
        "password_hash": row[4],
    }


def live_tokens(app: FastAPI, user_id: str) -> int:
    with app.state.session_factory() as session:
        return int(
            session.execute(
                text(
                    "SELECT count(*) FROM auth_tokens WHERE user_id = :uid AND revoked_at IS NULL"
                ),
                {"uid": user_id},
            ).scalar()
            or 0
        )


def last_audit(app: FastAPI, action: str, target_id: str) -> dict[str, Any] | None:
    """The most recent audit row for an action against a target.

    `detail_json` is BYTEA - the column is bytes because the audit chain hashes
    it - so it is decoded here rather than read as JSON by the driver.
    """
    import json

    with app.state.session_factory() as session:
        row = session.execute(
            text(
                "SELECT actor_id, actor_role, detail_json FROM audit_logs "
                "WHERE action = :action AND target_id = :target "
                "ORDER BY seq DESC LIMIT 1"
            ),
            {"action": action, "target": target_id},
        ).fetchone()
    if row is None:
        return None
    return {
        "actor_id": row[0],
        "actor_role": row[1],
        "detail": json.loads(bytes(row[2]).decode("utf-8")),
    }


def disable_directly(app: FastAPI, user_id: str) -> None:
    """Disable without going through the route, for arranging a test state."""
    from ubuntuguard.db import session_scope
    from ubuntuguard.repositories import disable_user, get_user

    with session_scope(app.state.session_factory) as session:
        user = get_user(session, uuid.UUID(user_id))
        assert user is not None
        disable_user(session, user)


# --------------------------------------------------------------------------- #
# Enable
# --------------------------------------------------------------------------- #


def test_a_disabled_account_can_be_re_enabled(app: FastAPI, client: TestClient) -> None:
    """The route that closes the one-way-disable gap."""
    headers = as_role(app, client, Role.SUPER_ADMIN)
    _, target_id = create_admin(app, Role.IT_ADMIN)
    disable_directly(app, target_id)
    assert read_user(app, target_id)["is_active"] is False

    response = client.post(f"/api/v1/users/{target_id}:enable", headers=headers)
    assert response.status_code == 204, response.text
    assert read_user(app, target_id)["is_active"] is True


def test_a_re_enabled_user_can_sign_in_with_their_existing_password(
    app: FastAPI, client: TestClient
) -> None:
    """The point of enabling, proved end to end.

    Enabling is not a credential operation: the account comes back with the
    password it always had, which is what makes it a restore rather than a
    recreate.
    """
    headers = as_role(app, client, Role.SUPER_ADMIN)
    email, target_id = create_admin(app, Role.IT_ADMIN)
    disable_directly(app, target_id)

    refused = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert refused.status_code == 401

    assert client.post(f"/api/v1/users/{target_id}:enable", headers=headers).status_code == 204

    accepted = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert accepted.status_code == 200, accepted.text


def test_enabling_an_already_active_account_is_a_conflict(app: FastAPI, client: TestClient) -> None:
    headers = as_role(app, client, Role.SUPER_ADMIN)
    _, target_id = create_admin(app, Role.AUDITOR)

    response = client.post(f"/api/v1/users/{target_id}:enable", headers=headers)
    assert response.status_code == 409
    assert response.json()["code"] == "user_already_active"


def test_enabling_an_unknown_account_is_a_404(app: FastAPI, client: TestClient) -> None:
    headers = as_role(app, client, Role.SUPER_ADMIN)
    response = client.post(f"/api/v1/users/{uuid.uuid4()}:enable", headers=headers)
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


def test_enabling_is_audited_with_the_actor_and_the_target(
    app: FastAPI, client: TestClient
) -> None:
    email, actor_id = create_admin(app, Role.SUPER_ADMIN)
    headers = bearer(login(client, email))
    _, target_id = create_admin(app, Role.IT_ADMIN)
    disable_directly(app, target_id)

    assert client.post(f"/api/v1/users/{target_id}:enable", headers=headers).status_code == 204

    entry = last_audit(app, "user_enabled", target_id)
    assert entry is not None, "no user_enabled audit row was written"
    assert entry["actor_id"] == actor_id
    assert entry["actor_role"] == "super_admin"
    assert entry["detail"]["role"] == "it_admin"


@pytest.mark.parametrize("role", [Role.IT_ADMIN, Role.SECURITY_ANALYST, Role.AUDITOR])
def test_enabling_requires_manage_users(app: FastAPI, client: TestClient, role: Role) -> None:
    """Only super_admin holds `manage_users`, so only it may enable."""
    headers = as_role(app, client, role)
    _, target_id = create_admin(app, Role.AUDITOR)
    disable_directly(app, target_id)

    response = client.post(f"/api/v1/users/{target_id}:enable", headers=headers)
    assert response.status_code == 403
    assert response.json()["code"] == "forbidden"
    assert read_user(app, target_id)["is_active"] is False, "a forbidden call took effect"


def test_enabling_without_a_token_is_refused(app: FastAPI, client: TestClient) -> None:
    _, target_id = create_admin(app, Role.AUDITOR)
    response = client.post(f"/api/v1/users/{target_id}:enable")
    assert response.status_code == 401


# --------------------------------------------------------------------------- #
# Role change
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("to_role", ["super_admin", "it_admin", "security_analyst", "auditor"])
def test_a_role_can_be_changed_to_each_supported_role(
    app: FastAPI, client: TestClient, to_role: str
) -> None:
    """All four, including promotion to super_admin."""
    headers = as_role(app, client, Role.SUPER_ADMIN)
    # Start from a role that is never the target, so the change is never a no-op.
    start = Role.AUDITOR if to_role != "auditor" else Role.SECURITY_ANALYST
    _, target_id = create_admin(app, start)

    response = client.post(
        f"/api/v1/users/{target_id}:role", headers=headers, json={"role": to_role}
    )
    assert response.status_code == 204, response.text
    assert read_user(app, target_id)["role"] == to_role


def test_a_role_change_revokes_the_targets_sessions(app: FastAPI, client: TestClient) -> None:
    """A live access token carries the OLD role until it expires.

    `Principal` is built from the role at resolution time, so without
    revocation a demoted super_admin would keep `manage_users` for up to
    fifteen minutes.
    """
    headers = as_role(app, client, Role.SUPER_ADMIN)
    email, target_id = create_admin(app, Role.IT_ADMIN)
    target_token = login(client, email)
    assert live_tokens(app, target_id) >= 2

    assert (
        client.post(
            f"/api/v1/users/{target_id}:role", headers=headers, json={"role": "auditor"}
        ).status_code
        == 204
    )

    assert live_tokens(app, target_id) == 0
    # And the old token no longer works at all.
    assert client.get("/api/v1/devices", headers=bearer(target_token)).status_code == 401


def test_changing_your_own_role_is_refused(app: FastAPI, client: TestClient) -> None:
    email, actor_id = create_admin(app, Role.SUPER_ADMIN)
    headers = bearer(login(client, email))

    response = client.post(
        f"/api/v1/users/{actor_id}:role", headers=headers, json={"role": "auditor"}
    )
    assert response.status_code == 409
    assert response.json()["code"] == "cannot_change_own_role"
    assert read_user(app, actor_id)["role"] == "super_admin"


def test_setting_the_role_already_held_is_refused(app: FastAPI, client: TestClient) -> None:
    headers = as_role(app, client, Role.SUPER_ADMIN)
    _, target_id = create_admin(app, Role.IT_ADMIN)

    response = client.post(
        f"/api/v1/users/{target_id}:role", headers=headers, json={"role": "it_admin"}
    )
    assert response.status_code == 409
    assert response.json()["code"] == "role_unchanged"


def test_an_unknown_role_is_a_validation_error(app: FastAPI, client: TestClient) -> None:
    headers = as_role(app, client, Role.SUPER_ADMIN)
    _, target_id = create_admin(app, Role.AUDITOR)

    response = client.post(
        f"/api/v1/users/{target_id}:role", headers=headers, json={"role": "root"}
    )
    assert response.status_code == 422
    assert response.json()["code"] == "validation_failed"
    assert read_user(app, target_id)["role"] == "auditor"


def test_an_unknown_field_in_the_role_body_is_refused(app: FastAPI, client: TestClient) -> None:
    """`extra="forbid"` on every request model.

    Silently dropping a field lets a caller believe it sent something that was
    ignored - here, something like `{"role": "auditor", "is_active": true}`.
    """
    headers = as_role(app, client, Role.SUPER_ADMIN)
    _, target_id = create_admin(app, Role.AUDITOR)

    response = client.post(
        f"/api/v1/users/{target_id}:role",
        headers=headers,
        json={"role": "it_admin", "is_active": True},
    )
    assert response.status_code == 422


def test_a_role_change_is_audited_with_the_old_and_new_role(
    app: FastAPI, client: TestClient
) -> None:
    """The old role is the part that cannot be reconstructed afterwards."""
    email, actor_id = create_admin(app, Role.SUPER_ADMIN)
    headers = bearer(login(client, email))
    _, target_id = create_admin(app, Role.SECURITY_ANALYST)

    assert (
        client.post(
            f"/api/v1/users/{target_id}:role", headers=headers, json={"role": "auditor"}
        ).status_code
        == 204
    )

    entry = last_audit(app, "user_role_changed", target_id)
    assert entry is not None, "no user_role_changed audit row was written"
    assert entry["actor_id"] == actor_id
    assert entry["detail"]["from_role"] == "security_analyst"
    assert entry["detail"]["to_role"] == "auditor"
    assert entry["detail"]["sessions_revoked"] >= 0


@pytest.mark.parametrize("role", [Role.IT_ADMIN, Role.SECURITY_ANALYST, Role.AUDITOR])
def test_changing_a_role_requires_manage_users(
    app: FastAPI, client: TestClient, role: Role
) -> None:
    """The capability that can grant every other capability.

    An `it_admin` able to promote itself to `super_admin` would make the whole
    matrix decorative, so this is the most important denial in the file.
    """
    headers = as_role(app, client, role)
    _, target_id = create_admin(app, Role.AUDITOR)

    response = client.post(
        f"/api/v1/users/{target_id}:role", headers=headers, json={"role": "super_admin"}
    )
    assert response.status_code == 403
    assert response.json()["code"] == "forbidden"
    assert read_user(app, target_id)["role"] == "auditor", "a forbidden call took effect"


def test_a_non_super_admin_cannot_promote_itself(app: FastAPI, client: TestClient) -> None:
    """The same denial from the other direction: own id, own token."""
    email, actor_id = create_admin(app, Role.IT_ADMIN)
    headers = bearer(login(client, email))

    response = client.post(
        f"/api/v1/users/{actor_id}:role", headers=headers, json={"role": "super_admin"}
    )
    assert response.status_code == 403
    assert read_user(app, actor_id)["role"] == "it_admin"


# --------------------------------------------------------------------------- #
# Administrator password reset
# --------------------------------------------------------------------------- #


def test_an_administrator_can_reset_another_users_password(
    app: FastAPI, client: TestClient
) -> None:
    headers = as_role(app, client, Role.SUPER_ADMIN)
    email, target_id = create_admin(app, Role.IT_ADMIN)
    original = read_user(app, target_id)["password_hash"]

    response = client.post(
        f"/api/v1/users/{target_id}:reset-password",
        headers=headers,
        json={"password": NEW_PASSWORD},
    )
    assert response.status_code == 204, response.text

    after = read_user(app, target_id)
    assert after["password_hash"] != original
    assert after["must_change_password"] is True
    assert after["is_active"] is True, "a reset must not disable the account"

    # The temporary password works, and the old one does not.
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": email, "password": NEW_PASSWORD}
        ).status_code
        == 200
    )
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}).status_code
        == 401
    )


def test_the_reset_response_carries_no_credential(app: FastAPI, client: TestClient) -> None:
    """204 with an empty body.

    The administrator supplied the password, so returning it would put a live
    credential in an HTTP response for no gain.
    """
    headers = as_role(app, client, Role.SUPER_ADMIN)
    _, target_id = create_admin(app, Role.AUDITOR)

    response = client.post(
        f"/api/v1/users/{target_id}:reset-password",
        headers=headers,
        json={"password": NEW_PASSWORD},
    )
    assert response.status_code == 204
    assert response.content == b""
    assert NEW_PASSWORD not in response.text


def test_a_reset_revokes_every_session_the_user_holds(app: FastAPI, client: TestClient) -> None:
    """How the reset becomes visible to its subject.

    Without this, a user whose password an administrator reset would carry on
    working for up to fifteen minutes on their existing access token.
    """
    headers = as_role(app, client, Role.SUPER_ADMIN)
    email, target_id = create_admin(app, Role.IT_ADMIN)
    victim_token = login(client, email)
    login(client, email)  # a second session, to prove ALL families are revoked
    assert live_tokens(app, target_id) >= 4

    assert (
        client.post(
            f"/api/v1/users/{target_id}:reset-password",
            headers=headers,
            json={"password": NEW_PASSWORD},
        ).status_code
        == 204
    )

    assert live_tokens(app, target_id) == 0
    assert client.get("/api/v1/devices", headers=bearer(victim_token)).status_code == 401


def test_a_reset_is_audited_without_the_password(app: FastAPI, client: TestClient) -> None:
    """The audit log is widely readable, so it must carry no credential."""
    email, actor_id = create_admin(app, Role.SUPER_ADMIN)
    headers = bearer(login(client, email))
    target_email, target_id = create_admin(app, Role.IT_ADMIN)

    assert (
        client.post(
            f"/api/v1/users/{target_id}:reset-password",
            headers=headers,
            json={"password": NEW_PASSWORD},
        ).status_code
        == 204
    )

    entry = last_audit(app, "user_password_reset", target_id)
    assert entry is not None, "no user_password_reset audit row was written"
    assert entry["actor_id"] == actor_id
    assert entry["detail"]["email"] == target_email
    assert entry["detail"]["must_change_password"] is True

    rendered = str(entry["detail"])
    assert NEW_PASSWORD not in rendered
    assert "password_hash" not in rendered
    assert "argon2" not in rendered.lower()
    assert "$" not in rendered, "the audit detail looks like it contains a PHC hash"


@pytest.mark.parametrize(
    ("password", "reason"),
    [
        ("short", "below the 12-character minimum"),
        ("", "empty"),
        ("            ", "only whitespace"),
    ],
)
def test_a_reset_enforces_the_password_policy(
    app: FastAPI, client: TestClient, password: str, reason: str
) -> None:
    headers = as_role(app, client, Role.SUPER_ADMIN)
    _, target_id = create_admin(app, Role.AUDITOR)

    response = client.post(
        f"/api/v1/users/{target_id}:reset-password",
        headers=headers,
        json={"password": password},
    )
    assert response.status_code == 422, f"{reason} was accepted"
    assert read_user(app, target_id)["must_change_password"] is False


def test_a_reset_for_an_unknown_user_is_a_404(app: FastAPI, client: TestClient) -> None:
    headers = as_role(app, client, Role.SUPER_ADMIN)
    response = client.post(
        f"/api/v1/users/{uuid.uuid4()}:reset-password",
        headers=headers,
        json={"password": NEW_PASSWORD},
    )
    assert response.status_code == 404


@pytest.mark.parametrize("role", [Role.IT_ADMIN, Role.SECURITY_ANALYST, Role.AUDITOR])
def test_resetting_a_password_requires_manage_users(
    app: FastAPI, client: TestClient, role: Role
) -> None:
    """Otherwise any administrator could take over any account."""
    headers = as_role(app, client, role)
    email, target_id = create_admin(app, Role.AUDITOR)

    response = client.post(
        f"/api/v1/users/{target_id}:reset-password",
        headers=headers,
        json={"password": NEW_PASSWORD},
    )
    assert response.status_code == 403
    assert read_user(app, target_id)["must_change_password"] is False
    # The original password still works, so nothing was changed.
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}).status_code
        == 200
    )


# --------------------------------------------------------------------------- #
# The forced password change, enforced server-side
# --------------------------------------------------------------------------- #


def test_a_user_owing_a_password_change_is_refused_every_capability_route(
    app: FastAPI, client: TestClient
) -> None:
    """The requirement that this is enforced in the backend, not the UI.

    A direct API call with a perfectly valid access token, no browser
    involved. Every capability-guarded route the role would otherwise be
    allowed must return 403 `password_change_required`.
    """
    admin = as_role(app, client, Role.SUPER_ADMIN)
    email, target_id = create_admin(app, Role.IT_ADMIN)

    assert (
        client.post(
            f"/api/v1/users/{target_id}:reset-password",
            headers=admin,
            json={"password": NEW_PASSWORD},
        ).status_code
        == 204
    )

    # Sign in with the temporary password: this succeeds, by design. The
    # restriction is on what the session may then do.
    forced = bearer(login(client, email, NEW_PASSWORD))

    for method, path in [
        ("GET", "/api/v1/devices"),
        ("GET", "/api/v1/devices:counts"),
        ("GET", "/api/v1/enrollment-tokens"),
        ("GET", "/api/v1/audit-logs"),
    ]:
        response = client.request(method, path, headers=forced)
        assert response.status_code == 403, f"{method} {path} was reachable"
        assert response.json()["code"] == "password_change_required", f"{method} {path}"


def test_a_forced_user_cannot_mint_an_enrollment_token(app: FastAPI, client: TestClient) -> None:
    """A write route, not just reads.

    Checked separately because minting a token is the operation with the
    largest consequence an it_admin holds.
    """
    admin = as_role(app, client, Role.SUPER_ADMIN)
    email, target_id = create_admin(app, Role.IT_ADMIN)
    client.post(
        f"/api/v1/users/{target_id}:reset-password",
        headers=admin,
        json={"password": NEW_PASSWORD},
    )
    forced = bearer(login(client, email, NEW_PASSWORD))

    response = client.post("/api/v1/enrollment-tokens", headers=forced, json={"ttl_seconds": 3600})
    assert response.status_code == 403
    assert response.json()["code"] == "password_change_required"
    assert "enrollment_token" not in response.text


def test_a_forced_user_can_still_read_me_and_is_told_why(app: FastAPI, client: TestClient) -> None:
    """`/auth/me` must answer, or the dashboard cannot tell this state from a
    dead session and would loop on the login page."""
    admin = as_role(app, client, Role.SUPER_ADMIN)
    email, target_id = create_admin(app, Role.AUDITOR)
    client.post(
        f"/api/v1/users/{target_id}:reset-password",
        headers=admin,
        json={"password": NEW_PASSWORD},
    )
    forced = bearer(login(client, email, NEW_PASSWORD))

    response = client.get("/api/v1/auth/me", headers=forced)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["must_change_password"] is True
    assert body["email"] == email
    # The capability list is still reported honestly: the role is unchanged,
    # only its ability to act is suspended.
    assert body["capabilities"], "capabilities were emptied rather than suspended"


def test_a_user_who_owes_nothing_reports_false(app: FastAPI, client: TestClient) -> None:
    """Existing accounts must be unaffected. The migration default, over HTTP."""
    email, _ = create_admin(app, Role.IT_ADMIN)
    headers = bearer(login(client, email))

    response = client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["must_change_password"] is False
    # And the session works normally.
    assert client.get("/api/v1/devices", headers=headers).status_code == 200


def test_the_user_list_reports_the_flag(app: FastAPI, client: TestClient) -> None:
    """So the Administrators page can show who owes a change."""
    headers = as_role(app, client, Role.SUPER_ADMIN)
    email, target_id = create_admin(app, Role.AUDITOR)
    client.post(
        f"/api/v1/users/{target_id}:reset-password",
        headers=headers,
        json={"password": NEW_PASSWORD},
    )

    response = client.get("/api/v1/users", headers=headers, params={"q": email, "limit": 5})
    assert response.status_code == 200
    rows = [row for row in response.json() if row["id"] == target_id]
    assert rows, "the reset account is not in the list"
    assert rows[0]["must_change_password"] is True
