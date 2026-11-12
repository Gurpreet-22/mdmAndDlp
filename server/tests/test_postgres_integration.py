"""Database-backed tests. Skipped until PostgreSQL is available.

These are written now so that `make db && make test` exercises them the moment
the database exists, rather than the requirement being remembered later. They
are **UNVALIDATED** until that run happens: they have never executed, and a
test that has never run is a hypothesis.

What they cover, all of which is impossible to check without a real server:

- migrations apply, roll all the way back, and apply again
- the application role genuinely cannot UPDATE or DELETE audit_logs
- policies are immutable through the application role
- two concurrent uses of one enrollment token yield exactly one success
- 1,000 events delivered twice are stored exactly once

Run with:
    export UBUNTUGUARD_MIGRATION_DATABASE_URL=postgresql+psycopg://ubuntuguard_owner:...@localhost/ubuntuguard
    export UBUNTUGUARD_DATABASE_URL=postgresql+psycopg://ubuntuguard_app:...@localhost/ubuntuguard
    .venv/bin/python -m pytest -m postgres
"""

from __future__ import annotations

import datetime as dt
import os
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import DatabaseError

pytestmark = pytest.mark.postgres

SERVER_DIR = Path(__file__).resolve().parents[1]

#: Opt-in for the tests that DROP every table.
#:
#: These were originally unguarded, and they quietly destroyed the whole
#: development database - including the bootstrapped admin account - during an
#: ordinary `pytest` run. `alembic downgrade base` does exactly what it says;
#: the mistake was letting it run by default. The other database tests are
#: non-destructive and still run without this flag.
#: Note the UG_ prefix rather than UBUNTUGUARD_. Two reasons, both found the
#: hard way: the `isolate_settings_sources` fixture deletes every UBUNTUGUARD_*
#: variable to keep unit tests deterministic, so the flag vanished before the
#: test could read it; and `Settings` rejects unknown UBUNTUGUARD_* variables as
#: typos, so the flag would have broken configuration loading outright. This is
#: a test-harness switch, not an application setting, so it should not share the
#: application's namespace.
DESTRUCTIVE_ENV = "UG_ALLOW_DESTRUCTIVE_TESTS"


def require_destructive_opt_in() -> None:
    if os.environ.get(DESTRUCTIVE_ENV) != "1":
        pytest.skip(
            f"this test DROPS every table. Set {DESTRUCTIVE_ENV}=1 to allow it, "
            "and expect to re-run `./scripts/dev_db.sh migrate` and "
            "`python -m ubuntuguard.cli create-admin` afterwards."
        )


def _url(variable: str) -> str:
    """Read a database URL from the environment, falling back to server/.env.

    The fallback exists so `pytest -m postgres` works straight after
    `scripts/dev_db.sh up` with no exports. The script writes .env at mode 0600
    and it is gitignored, so this reads a developer credential and never a
    committed one.
    """
    value = os.environ.get(variable)
    if not value:
        env_file = SERVER_DIR / ".env"
        if env_file.exists():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                name, separator, candidate = line.partition("=")
                if separator and name.strip() == variable:
                    value = candidate.strip()
                    break
    if not value:
        pytest.skip(
            f"{variable} is not set and server/.env has no entry for it. "
            "Create the database with: ./scripts/dev_db.sh up"
        )
    return value


def _engine_or_skip(variable: str) -> Engine:
    """Build an engine and prove it connects, skipping rather than erroring.

    A URL that is present but unusable - a stopped cluster, a stale password -
    should skip with an explanation. Letting it error turns one missing service
    into a wall of connection tracebacks that hides whatever else broke.
    """
    engine = create_engine(_url(variable), future=True, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - reported as a skip, not raised
        engine.dispose()
        pytest.skip(f"cannot connect using {variable}: {type(exc).__name__}. Is the cluster up?")
    return engine


@pytest.fixture(scope="session")
def owner_engine() -> Iterator[Engine]:
    engine = _engine_or_skip("UBUNTUGUARD_MIGRATION_DATABASE_URL")
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def app_engine() -> Iterator[Engine]:
    engine = _engine_or_skip("UBUNTUGUARD_DATABASE_URL")
    yield engine
    engine.dispose()


def _alembic_config():  # noqa: ANN202 - alembic's Config is untyped
    from alembic.config import Config

    config = Config(str(SERVER_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(SERVER_DIR / "migrations"))
    # Passed explicitly so the migration runs against the same database the
    # fixtures connected to, whether the URL came from the environment or .env.
    config.set_main_option("sqlalchemy.url", _url("UBUNTUGUARD_MIGRATION_DATABASE_URL"))
    return config


@pytest.fixture(scope="session")
def migrated(owner_engine: Engine) -> Iterator[None]:
    """Bring the schema to head once for the session."""
    from alembic import command

    command.upgrade(_alembic_config(), "head")
    yield


# --------------------------------------------------------------------------- #
# Migrations
# --------------------------------------------------------------------------- #


@pytest.mark.destructive
def test_migrations_apply_roll_back_and_reapply(owner_engine: Engine) -> None:
    """Up, all the way down, and up again.

    A downgrade that was never exercised is discovered at the worst possible
    moment. Running up twice afterwards also catches a migration that is not
    idempotent with respect to its own downgrade.

    DESTRUCTIVE: drops every table and all data.
    """
    require_destructive_opt_in()

    from alembic import command

    config = _alembic_config()
    command.upgrade(config, "head")

    with owner_engine.connect() as connection:
        tables_before = _table_names(connection)
    assert "audit_logs" in tables_before

    command.downgrade(config, "base")
    with owner_engine.connect() as connection:
        remaining = _table_names(connection)
    assert "audit_logs" not in remaining, "downgrade left tables behind"
    assert not (remaining - {"alembic_version"}), f"downgrade left {remaining}"

    command.upgrade(config, "head")
    with owner_engine.connect() as connection:
        tables_after = _table_names(connection)
    assert tables_after == tables_before


@pytest.mark.destructive
def test_append_only_survives_a_migration_cycle_without_regranting(
    owner_engine: Engine, app_engine: Engine
) -> None:
    """The fail-safe default, asserted directly.

    This is the regression test for a real bug. The first version of
    02-grants.sql granted full DML and then revoked it on the protected tables,
    so a downgrade/upgrade cycle - which DROPs and RECREATEs every table - gave
    the app role UPDATE and DELETE on audit_logs again, silently. Nothing
    errored; the guarantee simply stopped holding.

    Deliberately does NOT re-run 02-grants.sql, because the point is that
    forgetting to re-run it leaves the audit log append-only rather than
    mutable.

    DESTRUCTIVE: drops every table and all data.
    """
    require_destructive_opt_in()

    from alembic import command

    from ubuntuguard.db import audit_role_is_append_only

    config = _alembic_config()
    command.downgrade(config, "base")
    command.upgrade(config, "head")

    assert audit_role_is_append_only(app_engine) is True, (
        "a migration cycle restored UPDATE/DELETE on audit_logs; the default "
        "privilege is not fail-safe"
    )

    # Put the operational grants back for the rest of the session: the safe
    # default is correct, but it does not grant the UPDATE and DELETE that the
    # operational tables legitimately need.
    _reapply_grants()


def _reapply_grants() -> None:
    """Run sql/02-grants.sql through psql.

    Shelling out rather than executing the file through SQLAlchemy: it contains
    psql meta-commands and a dollar-quoted function body whose semicolons would
    defeat any naive statement splitter.
    """
    url = _url("UBUNTUGUARD_MIGRATION_DATABASE_URL").replace(
        "postgresql+psycopg://", "postgresql://"
    )
    psql = shutil.which("psql")
    if psql is None:
        pytest.skip("psql is not on PATH, so the grants cannot be re-applied")
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [psql, url, "-v", "ON_ERROR_STOP=1", "-q", "-f", str(SERVER_DIR / "sql" / "02-grants.sql")],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"re-applying grants failed: {result.stderr[-500:]}")


def _table_names(connection) -> set[str]:  # noqa: ANN001 - sqlalchemy Connection
    rows = connection.execute(
        text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
        )
    )
    return {row[0] for row in rows}


def test_schema_matches_the_models(owner_engine: Engine, migrated: None) -> None:
    """Alembic autogenerate must see no pending changes.

    This is what catches a model edited without a migration, which would
    otherwise surface as a column-not-found error in production.
    """
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from ubuntuguard.models import Base

    with owner_engine.connect() as connection:
        context = MigrationContext.configure(connection)
        diff = compare_metadata(context, Base.metadata)
    assert not diff, f"schema and models disagree: {diff}"


# --------------------------------------------------------------------------- #
# The append-only guarantee
# --------------------------------------------------------------------------- #


def test_app_role_cannot_modify_audit_logs(app_engine: Engine, migrated: None) -> None:
    """The requirement, asserted against a real server.

    The application role holds SELECT and INSERT here and nothing else, so
    PostgreSQL refuses the UPDATE and the DELETE regardless of what the
    application code tries to do.
    """
    # Deliberately inserts NOTHING.
    #
    # An earlier version of this test inserted a row directly, with a made-up
    # prev_hash and entry_hash, to have something to try to UPDATE. That wrote
    # around `services.audit.append` - the one thing its docstring says must not
    # happen - and permanently broke the hash chain, which only surfaced later
    # as an unrelated test failure.
    #
    # The insert was never needed: PostgreSQL checks table privileges before it
    # looks at rows, so an UPDATE matching nothing is still refused for lack of
    # the privilege. `test_app_role_can_append_through_the_service` covers the
    # INSERT side without corrupting anything.
    for statement in (
        "UPDATE audit_logs SET action = 'tampered'",
        "DELETE FROM audit_logs",
        "TRUNCATE audit_logs",
    ):
        with pytest.raises(DatabaseError) as caught, app_engine.begin() as connection:
            connection.execute(text(statement))
        message = str(caught.value).lower()
        assert "permission denied" in message or "append-only" in message, (
            f"{statement} was not refused; got: {message[:200]}"
        )


def test_app_role_cannot_modify_policies(app_engine: Engine, migrated: None) -> None:
    """Policy versions are immutable; a change is a new row."""
    for statement in ("UPDATE policies SET version = version + 1", "DELETE FROM policies"):
        with pytest.raises(DatabaseError), app_engine.begin() as connection:
            connection.execute(text(statement))


def test_app_role_can_append_through_the_service(app_engine: Engine, migrated: None) -> None:
    """Append-only must still allow appending, and the chain must stay valid.

    Goes through `services.audit.append` rather than raw SQL, so the row is
    properly chained. That is the only sanctioned way to write this table.
    """
    from sqlalchemy.orm import Session

    from ubuntuguard.services import audit

    with Session(app_engine) as session:
        before = audit.head_seq(session)
        audit.append(
            session,
            action="login_succeeded",
            actor_id="integration-test",
            detail={"source": "test_app_role_can_append_through_the_service"},
        )
        session.commit()

        assert audit.head_seq(session) == before + 1
        result = audit.verify(session)
        assert result.ok is True, f"chain broken at seq {result.broken_at_seq}: {result.reason}"


def test_app_role_cannot_modify_login_attempts(app_engine: Engine, migrated: None) -> None:
    """Login attempts are evidence of brute forcing; the app only appends."""
    for statement in ("UPDATE login_attempts SET succeeded = true", "DELETE FROM login_attempts"):
        with pytest.raises(DatabaseError), app_engine.begin() as connection:
            connection.execute(text(statement))


def test_app_role_cannot_create_tables(app_engine: Engine, migrated: None) -> None:
    """No DDL rights. Migrations run as the owner for exactly this reason."""
    with pytest.raises(DatabaseError), app_engine.begin() as connection:
        connection.execute(text("CREATE TABLE should_not_exist (id int)"))


def test_app_role_can_still_do_its_job(app_engine: Engine, migrated: None) -> None:
    """The restrictive default must not have broken the legitimate writes.

    Deny-by-default is only correct if the exceptions are actually granted;
    without this, a typo in the grant list would look like a security win.
    """
    device_id = uuid.uuid4()
    with app_engine.begin() as connection:
        connection.execute(
            text("INSERT INTO devices (id, hostname) VALUES (:id, :hostname)"),
            {"id": device_id, "hostname": "grant-check"},
        )
        # Heartbeats need UPDATE on devices.
        connection.execute(
            text("UPDATE devices SET last_heartbeat_at = now() WHERE id = :id"),
            {"id": device_id},
        )
        # Incident status transitions need UPDATE on incidents.
        incident_id = uuid.uuid4()
        connection.execute(
            text(
                "INSERT INTO incidents (id, kind, summary, opened_at, updated_at) "
                "VALUES (:id, 'usb_blocked', 'check', now(), now())"
            ),
            {"id": incident_id},
        )
        connection.execute(
            text("UPDATE incidents SET status = 'acknowledged' WHERE id = :id"),
            {"id": incident_id},
        )


def test_startup_check_agrees(app_engine: Engine, migrated: None) -> None:
    """The helper the application uses at startup must reach the same verdict."""
    from ubuntuguard.db import audit_role_is_append_only

    assert audit_role_is_append_only(app_engine) is True


# --------------------------------------------------------------------------- #
# Concurrency
# --------------------------------------------------------------------------- #


def test_two_simultaneous_token_uses_yield_exactly_one_success(
    owner_engine: Engine, app_engine: Engine, migrated: None
) -> None:
    """The brief's requirement, under real contention.

    Single use is one statement:
        UPDATE enrollment_tokens SET consumed_at = now()
         WHERE id = :id AND consumed_at IS NULL RETURNING id
    Two callers racing therefore produce exactly one RETURNING row. A
    read-then-write would let both through.
    """
    token_id = uuid.uuid4()
    user_id = _seed_user(owner_engine)

    with app_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO enrollment_tokens "
                "(id, token_hash, created_by, expires_at) "
                "VALUES (:id, :hash, :user_id, now() + interval '24 hours')"
            ),
            {"id": token_id, "hash": uuid.uuid4().hex * 2, "user_id": user_id},
        )

    def consume() -> bool:
        with app_engine.begin() as connection:
            row = connection.execute(
                text(
                    "UPDATE enrollment_tokens SET consumed_at = now() "
                    " WHERE id = :id AND consumed_at IS NULL RETURNING id"
                ),
                {"id": token_id},
            ).first()
        return row is not None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: consume(), range(8)))

    assert sum(results) == 1, f"expected exactly one success, got {sum(results)}"


def test_one_thousand_events_delivered_twice_are_stored_once(
    owner_engine: Engine, app_engine: Engine, migrated: None
) -> None:
    """At-least-once transport, exactly-once storage.

    The agent-generated event_id is the primary key, so re-delivery collides
    and ON CONFLICT DO NOTHING is the whole deduplication mechanism.
    """
    device_id = _seed_device(owner_engine)
    event_ids = [uuid.uuid4() for _ in range(1000)]
    now = dt.datetime.now(dt.UTC)

    rows = [
        {
            "event_id": event_id,
            "device_id": device_id,
            "kind": "usb",
            "event_type": "usb_inserted",
            "occurred_at": now,
            "payload": "{}",
        }
        for event_id in event_ids
    ]
    insert = text(
        "INSERT INTO events "
        "(event_id, device_id, kind, event_type, occurred_at, payload) "
        "VALUES (:event_id, :device_id, :kind, :event_type, :occurred_at, "
        "CAST(:payload AS jsonb)) "
        "ON CONFLICT (event_id) DO NOTHING"
    )

    for _ in range(2):  # the same batch delivered twice
        with app_engine.begin() as connection:
            connection.execute(insert, rows)

    with app_engine.connect() as connection:
        stored = connection.execute(
            text("SELECT count(*) FROM events WHERE device_id = :d"), {"d": device_id}
        ).scalar_one()
    assert stored == 1000


def _seed_user(engine: Engine) -> uuid.UUID:
    user_id = uuid.uuid4()
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users (id, email, password_hash, role) "
                "VALUES (:id, :email, 'x', 'it_admin')"
            ),
            {"id": user_id, "email": f"{user_id}@example.invalid"},
        )
    return user_id


def _seed_device(engine: Engine) -> uuid.UUID:
    device_id = uuid.uuid4()
    with engine.begin() as connection:
        # enrolled_at is required for status 'active': the
        # ck_devices_enrolled_at_matches_status constraint added in
        # 0002_device_registration makes "active but never enrolled"
        # unrepresentable, which is the state this insert used to create.
        connection.execute(
            text(
                "INSERT INTO devices (id, status, hostname, enrolled_at) "
                "VALUES (:id, 'active', :hostname, now())"
            ),
            {"id": device_id, "hostname": f"host-{str(device_id)[:8]}"},
        )
    return device_id
