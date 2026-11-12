"""The no-authentication login placeholder.

`UBUNTUGUARD_ALLOW_ANY_LOGIN=1` makes `POST /api/v1/auth/login` accept any
address and any password, creating the account the first time it sees one. It
stands in for Microsoft SSO so the dashboard is usable before identity exists.

It is a deliberate backdoor, so most of what is asserted here is containment
rather than function:

  * off by default, and production refuses to BOOT with it on
  * the real password path is untouched while it is off
  * accounts it creates are UNREACHABLE once it is switched off, rather than
    carrying a guessable password
  * a disabled account stays disabled, so the flag cannot silently undo an
    operator's `:disable`
  * the audit log records `via: no_authentication`, so it never claims an
    address proved who it was
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from ubuntuguard.config import Settings
from ubuntuguard.main import create_app
from ubuntuguard.security import passwords

pytestmark = pytest.mark.postgres

SERVER_DIR = Path(__file__).resolve().parents[1]


def _unique_email() -> str:
    return f"anylogin-{uuid.uuid4().hex[:8]}@example.invalid"


def _settings_from_env_file(**overrides: object) -> Settings:
    """Build settings from server/.env, as test_api_integration.py does.

    The autouse `isolate_settings_sources` fixture neutralises .env to keep unit
    tests deterministic, so it is read explicitly and passed in.
    """
    env_file = SERVER_DIR / ".env"
    if not env_file.exists():
        pytest.skip("server/.env is missing. Create it with: ./scripts/dev_db.sh up")

    values: dict[str, object] = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("UBUNTUGUARD_") and "=" in line:
            name, _, value = line.partition("=")
            values[name.removeprefix("UBUNTUGUARD_").lower()] = value.strip()
    if "database_url" not in values:
        pytest.skip("no database URL in server/.env")

    # The developer's own .env may have the flag on; these tests set it
    # explicitly either way so they do not depend on local state.
    values.pop("allow_any_login", None)
    try:
        return Settings(_env_file=None, **{**values, **overrides})  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 - configuration problem, report as skip
        pytest.skip(f"could not build settings from server/.env: {exc}")


@pytest.fixture(scope="module")
def strict_settings() -> Settings:
    """Real configuration with authentication ON, the shipping default."""
    settings = _settings_from_env_file(allow_any_login=False)
    application = create_app(settings)
    with TestClient(application):
        pass
    if getattr(application.state, "session_factory", None) is None:
        pytest.skip("database unreachable; is the cluster running?")
    if getattr(application.state, "keys", None) is None:
        pytest.skip("key material missing. Run: python -m ubuntuguard.cli init-keys")
    return settings


@pytest.fixture(scope="module")
def open_settings(strict_settings: Settings) -> Settings:
    return strict_settings.model_copy(update={"allow_any_login": True})


# --------------------------------------------------------------------------- #
# Containment
# --------------------------------------------------------------------------- #


def test_the_default_is_off() -> None:
    """Anything else would make every deployment a backdoor."""
    assert Settings(_env_file=None).allow_any_login is False  # type: ignore[call-arg]


def test_production_refuses_to_start_with_it_on(tmp_path: Path) -> None:
    """The real protection: unbootable, not merely a bad default.

    Without this, the setting could reach a server by someone copying a dev
    .env file and nothing would complain.
    """
    key = tmp_path / "k.pem"
    key.write_bytes(b"not a real key")

    with pytest.raises(ValueError, match="allow_any_login must be false in production"):
        Settings(
            _env_file=None,  # type: ignore[call-arg]
            environment="prod",
            database_url="postgresql+psycopg://u:p@localhost/db",
            policy_signing_key_path=key,
            ca_key_path=key,
            ca_cert_path=key,
            allow_any_login=True,
        )


def test_dev_accepts_it() -> None:
    """The same setting must work in dev, or the placeholder is unusable."""
    assert Settings(_env_file=None, environment="dev", allow_any_login=True).allow_any_login  # type: ignore[call-arg]


def test_readyz_warns_while_it_is_on(open_settings: Settings) -> None:
    """An enabled backdoor must be visible to whoever watches the server."""
    with TestClient(create_app(open_settings)) as client:
        body = client.get("/readyz").json()
    assert any("AUTHENTICATION IS DISABLED" in w for w in body.get("warnings", []))


def test_readyz_is_silent_when_it_is_off(strict_settings: Settings) -> None:
    with TestClient(create_app(strict_settings)) as client:
        assert "warnings" not in client.get("/readyz").json()


def test_mode_endpoint_reports_the_truth(
    strict_settings: Settings, open_settings: Settings
) -> None:
    with TestClient(create_app(strict_settings)) as client:
        assert client.get("/api/v1/auth/mode").json() == {"any_login": False}
    with TestClient(create_app(open_settings)) as client:
        assert client.get("/api/v1/auth/mode").json() == {"any_login": True}


# --------------------------------------------------------------------------- #
# The real password path is unaffected while it is off
# --------------------------------------------------------------------------- #


def test_unknown_address_is_still_refused_when_off(strict_settings: Settings) -> None:
    with TestClient(create_app(strict_settings)) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": _unique_email(), "password": "anything at all"},
        )
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_credentials"


def test_no_account_is_created_when_off(strict_settings: Settings) -> None:
    """The refusal must not leave a row behind."""
    email = _unique_email()
    with TestClient(create_app(strict_settings)) as client:
        client.post("/api/v1/auth/login", json={"email": email, "password": "anything at all"})

    from ubuntuguard.db import create_db_engine, create_session_factory, session_scope
    from ubuntuguard.models import User

    factory = create_session_factory(create_db_engine(strict_settings))
    with session_scope(factory) as session:
        assert session.scalar(select(User).where(User.email == email)) is None


# --------------------------------------------------------------------------- #
# Behaviour while it is on
# --------------------------------------------------------------------------- #


def test_any_email_and_password_signs_in(open_settings: Settings) -> None:
    """The requested behaviour: type anything, get in."""
    with TestClient(create_app(open_settings)) as client:
        response = client.post(
            "/api/v1/auth/login", json={"email": _unique_email(), "password": "x"}
        )
        assert response.status_code == 200, response.text

        me = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {response.json()['access_token']}"},
        )
    assert me.status_code == 200
    assert me.json()["role"] == "super_admin"
    assert "manage_users" in me.json()["capabilities"]


def test_the_password_is_irrelevant(open_settings: Settings) -> None:
    """Two different passwords for the same address both work.

    This is the clearest statement of what the flag does: there is no
    credential, so there is nothing a second value could contradict.
    """
    email = _unique_email()
    with TestClient(create_app(open_settings)) as client:
        first = client.post("/api/v1/auth/login", json={"email": email, "password": "one"})
        second = client.post(
            "/api/v1/auth/login", json={"email": email, "password": "completely different"}
        )
    assert (first.status_code, second.status_code) == (200, 200)


def test_the_account_is_created_once_not_per_login(open_settings: Settings) -> None:
    email = _unique_email()
    with TestClient(create_app(open_settings)) as client:
        for _ in range(3):
            assert (
                client.post(
                    "/api/v1/auth/login", json={"email": email, "password": "p"}
                ).status_code
                == 200
            )

    from ubuntuguard.db import create_db_engine, create_session_factory, session_scope
    from ubuntuguard.models import User

    factory = create_session_factory(create_db_engine(open_settings))
    with session_scope(factory) as session:
        rows = session.scalars(select(User).where(User.email == email)).all()
    assert len(rows) == 1


def test_email_is_normalised(open_settings: Settings) -> None:
    """Mixed case must not create a second account for the same person."""
    local = f"Case-{uuid.uuid4().hex[:8]}"
    with TestClient(create_app(open_settings)) as client:
        upper = client.post(
            "/api/v1/auth/login", json={"email": f"{local}@Example.Invalid", "password": "p"}
        )
        assert upper.status_code == 200
        lower = client.post(
            "/api/v1/auth/login",
            json={"email": f"{local.lower()}@example.invalid", "password": "p"},
        )
    assert lower.status_code == 200

    from ubuntuguard.db import create_db_engine, create_session_factory, session_scope
    from ubuntuguard.models import User

    factory = create_session_factory(create_db_engine(open_settings))
    with session_scope(factory) as session:
        rows = session.scalars(
            select(User).where(User.email == f"{local.lower()}@example.invalid")
        ).all()
    assert len(rows) == 1


def test_a_disabled_account_stays_disabled(open_settings: Settings) -> None:
    """Otherwise the flag would silently undo every `:disable` an operator ran."""
    email = _unique_email()
    with TestClient(create_app(open_settings)) as client:
        token = client.post("/api/v1/auth/login", json={"email": email, "password": "p"}).json()[
            "access_token"
        ]
        me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).json()

        # A second super_admin does the disabling: the route refuses self-disable.
        other = client.post(
            "/api/v1/auth/login", json={"email": _unique_email(), "password": "p"}
        ).json()["access_token"]
        disabled = client.post(
            f"/api/v1/users/{me['user_id']}:disable",
            headers={"Authorization": f"Bearer {other}"},
        )
        assert disabled.status_code == 204, disabled.text

        again = client.post("/api/v1/auth/login", json={"email": email, "password": "p"})
    assert again.status_code == 401
    assert again.json()["code"] == "invalid_credentials"


# --------------------------------------------------------------------------- #
# What happens when the flag is turned back off
# --------------------------------------------------------------------------- #


def test_accounts_it_created_are_unreachable_once_it_is_off(
    open_settings: Settings, strict_settings: Settings
) -> None:
    """The property that makes this survivable.

    An account created with no password must not be reachable with a guessable
    one after real authentication is switched on. The stored hash is of 32
    random bytes nobody kept, so no input can ever verify.
    """
    email, password = _unique_email(), "the password typed at the time"
    with TestClient(create_app(open_settings)) as client:
        assert (
            client.post(
                "/api/v1/auth/login", json={"email": email, "password": password}
            ).status_code
            == 200
        )

    with TestClient(create_app(strict_settings)) as client:
        for attempt in (password, "", "x", "password", "admin"):
            response = client.post("/api/v1/auth/login", json={"email": email, "password": attempt})
            # Refused either by the schema (422, for the empty string) or by the
            # credential check (401). What matters is that nothing is a 200.
            assert response.status_code != 200, f"{attempt!r} must not authenticate"
            assert response.status_code in (401, 422), (
                f"{attempt!r} was refused with an unexpected {response.status_code}"
            )


def test_unusable_hash_is_a_real_hash_that_never_verifies() -> None:
    stored = passwords.unusable_password_hash()
    assert stored.startswith("$argon2id$")
    for attempt in ("", " ", "x", stored, "password"):
        assert passwords.verify_password(stored, attempt) is False


def test_two_unusable_hashes_differ() -> None:
    """A fixed hash would be a single value to attack across every account."""
    assert passwords.unusable_password_hash() != passwords.unusable_password_hash()


# --------------------------------------------------------------------------- #
# The audit log must not lie about it
# --------------------------------------------------------------------------- #


def _login_audit_detail(settings: Settings, email: str) -> dict[str, object]:
    """The newest `login_succeeded` detail for an address, read from the database.

    Not through `GET /api/v1/audit-logs`, which pages ASCENDING from the genesis
    entry: with hundreds of rows present, a bounded request never reaches one
    written a moment ago.
    """
    from ubuntuguard.db import create_db_engine, create_session_factory, session_scope
    from ubuntuguard.models import AuditLog

    factory = create_session_factory(create_db_engine(settings))
    with session_scope(factory) as session:
        rows = session.scalars(
            select(AuditLog)
            .where(AuditLog.action == "login_succeeded")
            .order_by(AuditLog.seq.desc())
            .limit(200)
        ).all()
        for row in rows:
            detail = json.loads((row.detail_json or b"{}").decode("utf-8"))
            if detail.get("email") == email:
                return dict(detail)
    raise AssertionError(f"no login_succeeded audit entry for {email}")


def test_audit_marks_it_as_unauthenticated(open_settings: Settings) -> None:
    """The log must not claim this address proved who it was."""
    email = _unique_email()
    with TestClient(create_app(open_settings)) as client:
        assert (
            client.post("/api/v1/auth/login", json={"email": email, "password": "p"}).status_code
            == 200
        )

    detail = _login_audit_detail(open_settings, email)
    assert detail["via"] == "no_authentication"
    assert detail["account_created"] is True


def test_a_real_login_carries_no_such_marker(strict_settings: Settings) -> None:
    """The counterpart. Without it, `via` could be absent everywhere and the
    test above would still pass."""
    from ubuntuguard.db import session_scope

    email, password = _unique_email(), "a reasonably long passphrase"
    application = create_app(strict_settings)
    with TestClient(application):
        pass
    from ubuntuguard import repositories

    with session_scope(application.state.session_factory) as session:
        repositories.create_user(
            session,
            email=email,
            password_hash=passwords.hash_password(password),
            role="it_admin",
        )
        session.commit()

    with TestClient(application) as client:
        assert (
            client.post(
                "/api/v1/auth/login", json={"email": email, "password": password}
            ).status_code
            == 200
        )

    detail = _login_audit_detail(strict_settings, email)
    assert "via" not in detail, "a genuine login must not be marked as unauthenticated"


def test_the_password_never_reaches_the_audit_log(open_settings: Settings) -> None:
    email, password = _unique_email(), "a very distinctive passphrase"
    with TestClient(create_app(open_settings)) as client:
        assert (
            client.post(
                "/api/v1/auth/login", json={"email": email, "password": password}
            ).status_code
            == 200
        )
    rendered = repr(_login_audit_detail(open_settings, email))
    assert password not in rendered
    assert "argon2" not in rendered
