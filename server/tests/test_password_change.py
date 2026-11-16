"""Self-service password change: `POST /api/v1/auth/password`.

The route every role holds and the only way out of a forced change. What is
being pinned here:

- the current password is genuinely verified, so a stolen access token is not
  by itself enough to take an account over;
- policy applies to the new password, and reuse of the current one is refused;
- the session survives the change, because a forced change that signed the
  user out would be inescapable;
- every OTHER session dies, because a credential change invalidates them;
- a wrong attempt feeds the same lockout window as login, so this route is not
  an unthrottled password oracle.
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
REFRESH_COOKIE = "ubuntuguard_refresh"


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
    yield application


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, client=("127.0.0.1", 54321)) as test_client:
        yield test_client


def create_admin(
    app: FastAPI, role: Role = Role.IT_ADMIN, *, password: str = PASSWORD
) -> tuple[str, str]:
    from ubuntuguard.db import session_scope
    from ubuntuguard.repositories import create_user
    from ubuntuguard.security.passwords import hash_password

    email = f"pwchange-{role.value}-{uuid.uuid4().hex[:8]}@example.invalid"
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


def read_user(app: FastAPI, user_id: str) -> dict[str, Any]:
    with app.state.session_factory() as session:
        row = session.execute(
            text(
                "SELECT must_change_password, password_hash, locked_until "
                "FROM users WHERE id = :uid"
            ),
            {"uid": user_id},
        ).fetchone()
    assert row is not None
    return {"must_change_password": row[0], "password_hash": row[1], "locked_until": row[2]}


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


def failed_attempts(app: FastAPI, email: str) -> int:
    with app.state.session_factory() as session:
        return int(
            session.execute(
                text(
                    "SELECT count(*) FROM login_attempts WHERE email = :email AND succeeded = false"
                ),
                {"email": email},
            ).scalar()
            or 0
        )


def change(client: TestClient, headers: dict[str, str], current: str, new: str) -> Any:
    return client.post(
        "/api/v1/auth/password",
        headers=headers,
        json={"current_password": current, "new_password": new},
    )


# --------------------------------------------------------------------------- #
# The happy path
# --------------------------------------------------------------------------- #


def test_a_user_can_change_their_own_password(app: FastAPI, client: TestClient) -> None:
    email, user_id = create_admin(app)
    headers = bearer(login(client, email))
    original = read_user(app, user_id)["password_hash"]

    response = change(client, headers, PASSWORD, NEW_PASSWORD)
    assert response.status_code == 200, response.text
    assert read_user(app, user_id)["password_hash"] != original

    # The new password works and the old one does not.
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


def test_the_change_returns_a_working_session(app: FastAPI, client: TestClient) -> None:
    """Revoke-and-reissue, not revoke-and-sign-out.

    For a FORCED change this is the difference between a usable product and a
    dead end: the user would otherwise be returned to the login page by the
    very act of satisfying the requirement.
    """
    email, _ = create_admin(app)
    headers = bearer(login(client, email))

    response = change(client, headers, PASSWORD, NEW_PASSWORD)
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0

    # The returned token works immediately on a capability-guarded route.
    assert client.get("/api/v1/devices", headers=bearer(body["access_token"])).status_code == 200


def test_the_change_sets_a_fresh_refresh_cookie(app: FastAPI, client: TestClient) -> None:
    """The refresh family rotates too, or the next refresh would present a
    revoked token and be treated as theft."""
    email, _ = create_admin(app)
    headers = bearer(login(client, email))
    before = client.cookies.get(REFRESH_COOKIE)

    response = change(client, headers, PASSWORD, NEW_PASSWORD)
    assert response.status_code == 200
    assert REFRESH_COOKIE in response.cookies, "no new refresh cookie was set"
    assert response.cookies[REFRESH_COOKIE] != before

    # And it works: a refresh with the new cookie succeeds.
    assert client.post("/api/v1/auth/refresh").status_code == 200


def test_every_other_session_is_revoked(app: FastAPI, client: TestClient) -> None:
    """A credential change invalidates sessions opened with the old one.

    Three logins, then a change from the third. The first two tokens must stop
    working; the change's own replacement must not.
    """
    email, user_id = create_admin(app)
    first = login(client, email)
    second = login(client, email)
    acting = login(client, email)
    assert live_tokens(app, user_id) >= 6

    response = change(client, bearer(acting), PASSWORD, NEW_PASSWORD)
    assert response.status_code == 200
    replacement = response.json()["access_token"]

    assert client.get("/api/v1/devices", headers=bearer(first)).status_code == 401
    assert client.get("/api/v1/devices", headers=bearer(second)).status_code == 401
    assert client.get("/api/v1/devices", headers=bearer(acting)).status_code == 401
    assert client.get("/api/v1/devices", headers=bearer(replacement)).status_code == 200

    # Exactly one live pair remains: the one just issued.
    assert live_tokens(app, user_id) == 2


@pytest.mark.parametrize("role", list(Role))
def test_every_role_can_change_its_own_password(
    app: FastAPI, client: TestClient, role: Role
) -> None:
    """No capability is required, and that is deliberate.

    An `auditor` holds almost nothing, and must still be able to rotate its own
    credential.
    """
    email, _ = create_admin(app, role)
    headers = bearer(login(client, email))

    assert change(client, headers, PASSWORD, NEW_PASSWORD).status_code == 200


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #


def test_the_wrong_current_password_is_refused(app: FastAPI, client: TestClient) -> None:
    """An access token is not authority to replace a credential.

    If it were, a stolen token would be a permanent takeover rather than a
    fifteen-minute one.
    """
    email, user_id = create_admin(app)
    headers = bearer(login(client, email))
    original = read_user(app, user_id)["password_hash"]

    response = change(client, headers, "not the current password", NEW_PASSWORD)
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_credentials"
    assert read_user(app, user_id)["password_hash"] == original

    # The original password still works, so nothing changed.
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}).status_code
        == 200
    )


def test_a_wrong_attempt_feeds_the_lockout_window(app: FastAPI, client: TestClient) -> None:
    """Otherwise this route is an unthrottled oracle.

    An attacker with a stolen access token could otherwise guess the account's
    password here at unlimited speed, while the login route rate-limits them
    after five tries.
    """
    email, _ = create_admin(app)
    headers = bearer(login(client, email))
    before = failed_attempts(app, email)

    assert change(client, headers, "wrong one", NEW_PASSWORD).status_code == 401

    assert failed_attempts(app, email) == before + 1, (
        "a failed password change was not recorded as a login attempt, so it does "
        "not count towards lockout"
    )


def test_reusing_the_current_password_is_refused(app: FastAPI, client: TestClient) -> None:
    """Checked by verifying the proposal against the stored hash.

    Note the scope: this prevents reuse of the CURRENT password only. There is
    no password-history table, so reuse of an earlier password is not detected
    and is not claimed to be.
    """
    email, _ = create_admin(app)
    headers = bearer(login(client, email))

    response = change(client, headers, PASSWORD, PASSWORD)
    assert response.status_code == 409
    assert response.json()["code"] == "password_unchanged"


@pytest.mark.parametrize(
    ("new_password", "reason"),
    [
        ("short", "below the 12-character minimum"),
        ("", "empty"),
        ("           ", "only whitespace"),
    ],
)
def test_the_new_password_must_satisfy_policy(
    app: FastAPI, client: TestClient, new_password: str, reason: str
) -> None:
    email, user_id = create_admin(app)
    headers = bearer(login(client, email))
    original = read_user(app, user_id)["password_hash"]

    response = change(client, headers, PASSWORD, new_password)
    assert response.status_code == 422, f"{reason} was accepted"
    assert read_user(app, user_id)["password_hash"] == original


def test_an_unauthenticated_change_is_refused(app: FastAPI, client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert response.status_code == 401


def test_an_unknown_field_is_refused(app: FastAPI, client: TestClient) -> None:
    """`extra="forbid"`. Notably, a `user_id` field must not be accepted -
    that would turn this route into an unguarded reset for other accounts."""
    email, _ = create_admin(app)
    headers = bearer(login(client, email))

    response = client.post(
        "/api/v1/auth/password",
        headers=headers,
        json={
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
            "user_id": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 422


def test_the_response_never_echoes_a_password(app: FastAPI, client: TestClient) -> None:
    email, _ = create_admin(app)
    headers = bearer(login(client, email))

    response = change(client, headers, PASSWORD, NEW_PASSWORD)
    assert PASSWORD not in response.text
    assert NEW_PASSWORD not in response.text


# --------------------------------------------------------------------------- #
# Completing a forced change
# --------------------------------------------------------------------------- #


def _reset_by_admin(app: FastAPI, client: TestClient, target_id: str, password: str) -> None:
    from ubuntuguard.db import session_scope
    from ubuntuguard.repositories import create_user
    from ubuntuguard.security.passwords import hash_password

    admin_email = f"pwchange-admin-{uuid.uuid4().hex[:8]}@example.invalid"
    with session_scope(app.state.session_factory) as session:
        create_user(
            session,
            email=admin_email,
            password_hash=hash_password(PASSWORD),
            role=Role.SUPER_ADMIN.value,
        )
    headers = bearer(login(client, admin_email))
    response = client.post(
        f"/api/v1/users/{target_id}:reset-password",
        headers=headers,
        json={"password": password},
    )
    assert response.status_code == 204, response.text


def test_changing_the_password_clears_the_forced_flag(app: FastAPI, client: TestClient) -> None:
    """The only route that clears it, and the whole point of the mechanism."""
    email, user_id = create_admin(app)
    temporary = "a temporary administrator passphrase"
    _reset_by_admin(app, client, user_id, temporary)
    assert read_user(app, user_id)["must_change_password"] is True

    headers = bearer(login(client, email, temporary))
    response = change(client, headers, temporary, NEW_PASSWORD)
    assert response.status_code == 200, response.text

    assert read_user(app, user_id)["must_change_password"] is False


def test_the_account_works_normally_after_completing_a_forced_change(
    app: FastAPI, client: TestClient
) -> None:
    """Before: 403 on everything. After: the role's capabilities are restored.

    This is the end-to-end assertion for the whole feature.
    """
    email, user_id = create_admin(app, Role.IT_ADMIN)
    temporary = "a temporary administrator passphrase"
    _reset_by_admin(app, client, user_id, temporary)

    forced = bearer(login(client, email, temporary))
    assert client.get("/api/v1/devices", headers=forced).status_code == 403

    response = change(client, forced, temporary, NEW_PASSWORD)
    assert response.status_code == 200
    restored = bearer(response.json()["access_token"])

    assert client.get("/api/v1/devices", headers=restored).status_code == 200
    assert client.get("/api/v1/auth/me", headers=restored).json()["must_change_password"] is False


def test_a_forced_user_cannot_escape_by_reusing_the_temporary_password(
    app: FastAPI, client: TestClient
) -> None:
    """The reuse check closes the obvious shortcut.

    Otherwise a user could satisfy the forced change by submitting the
    administrator's temporary password as the new one, leaving the account on a
    credential somebody else chose and knows.
    """
    email, user_id = create_admin(app)
    temporary = "a temporary administrator passphrase"
    _reset_by_admin(app, client, user_id, temporary)

    headers = bearer(login(client, email, temporary))
    response = change(client, headers, temporary, temporary)
    assert response.status_code == 409
    assert response.json()["code"] == "password_unchanged"
    assert read_user(app, user_id)["must_change_password"] is True, (
        "the forced flag was cleared by a refused change"
    )


def test_a_forced_user_with_the_wrong_current_password_stays_forced(
    app: FastAPI, client: TestClient
) -> None:
    email, user_id = create_admin(app)
    temporary = "a temporary administrator passphrase"
    _reset_by_admin(app, client, user_id, temporary)

    headers = bearer(login(client, email, temporary))
    assert change(client, headers, "guessing", NEW_PASSWORD).status_code == 401
    assert read_user(app, user_id)["must_change_password"] is True


def test_a_lockout_is_not_cleared_by_changing_the_password(
    app: FastAPI, client: TestClient
) -> None:
    """A password change is not a successful login.

    `touch_last_login` clears `locked_until`; this route must not, or an
    attacker who learned a password could use it to escape the lockout their
    own guessing had triggered.
    """
    import datetime as dt

    from ubuntuguard.db import session_scope
    from ubuntuguard.repositories import get_user, set_user_lock

    email, user_id = create_admin(app)
    headers = bearer(login(client, email))

    locked_until = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=15)
    with session_scope(app.state.session_factory) as session:
        user = get_user(session, uuid.UUID(user_id))
        assert user is not None
        set_user_lock(session, user, locked_until)

    assert change(client, headers, PASSWORD, NEW_PASSWORD).status_code == 200
    assert read_user(app, user_id)["locked_until"] is not None, (
        "changing the password cleared a standing lockout"
    )


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


def _last_audit(app: FastAPI, action: str, target_id: str) -> dict[str, Any] | None:
    import json

    with app.state.session_factory() as session:
        row = session.execute(
            text(
                "SELECT actor_id, detail_json FROM audit_logs "
                "WHERE action = :action AND target_id = :target ORDER BY seq DESC LIMIT 1"
            ),
            {"action": action, "target": target_id},
        ).fetchone()
    if row is None:
        return None
    return {"actor_id": row[0], "detail": json.loads(bytes(row[1]).decode("utf-8"))}


def test_a_change_is_audited_without_the_password(app: FastAPI, client: TestClient) -> None:
    email, user_id = create_admin(app)
    headers = bearer(login(client, email))

    assert change(client, headers, PASSWORD, NEW_PASSWORD).status_code == 200

    entry = _last_audit(app, "password_changed", user_id)
    assert entry is not None, "no password_changed audit row was written"
    assert entry["actor_id"] == user_id, "the actor should be the user themselves"
    assert entry["detail"]["self_service"] is True
    assert entry["detail"]["completed_forced_change"] is False

    rendered = str(entry["detail"])
    assert PASSWORD not in rendered
    assert NEW_PASSWORD not in rendered
    assert "$" not in rendered, "the detail looks like it contains a PHC hash"


def test_completing_a_forced_change_is_recorded_as_such(app: FastAPI, client: TestClient) -> None:
    """Closes the loop on an administrator reset.

    The `user_password_reset` row says an administrator imposed a credential;
    this flag is the record that the account's own holder then took it back.
    Without it the log cannot distinguish a reset that was collected from one
    that was not.
    """
    email, user_id = create_admin(app)
    temporary = "a temporary administrator passphrase"
    _reset_by_admin(app, client, user_id, temporary)

    headers = bearer(login(client, email, temporary))
    assert change(client, headers, temporary, NEW_PASSWORD).status_code == 200

    entry = _last_audit(app, "password_changed", user_id)
    assert entry is not None
    assert entry["detail"]["completed_forced_change"] is True


def test_a_failed_change_is_audited(app: FastAPI, client: TestClient) -> None:
    """An authenticated session guessing its own password is worth a row."""
    email, user_id = create_admin(app)
    headers = bearer(login(client, email))

    assert change(client, headers, "wrong", NEW_PASSWORD).status_code == 401

    entry = _last_audit(app, "password_change_failed", user_id)
    assert entry is not None, "no password_change_failed audit row was written"
    assert entry["detail"]["reason"] == "wrong_current_password"


def test_the_audit_chain_survives_all_of_it(app: FastAPI, client: TestClient) -> None:
    """The hash chain must still verify after the new actions are appended."""
    email, user_id = create_admin(app, Role.SUPER_ADMIN)
    headers = bearer(login(client, email))
    change(client, headers, PASSWORD, NEW_PASSWORD)

    headers = bearer(login(client, email, NEW_PASSWORD))
    response = client.get("/api/v1/audit-logs:verify", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True, f"audit chain broken at seq {body.get('broken_at_seq')}"
