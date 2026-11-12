"""Migration tests that need no database.

Alembic's offline mode renders the DDL without connecting, so quite a lot is
checkable here: that the migration imports and executes, that it emits a
CREATE for every model table, that the downgrade emits a matching DROP, and
that the columns the security design depends on come out with the right types.

What this does NOT prove is that PostgreSQL accepts the DDL, or that an
up/down/up cycle leaves the schema identical. Those need a real server and live
in `test_postgres_integration.py`.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from ubuntuguard.models import Base

SERVER_DIR = Path(__file__).resolve().parents[1]
MODEL_TABLES = sorted(table.name for table in Base.metadata.sorted_tables)


#: A syntactically valid URL that is never connected to. Passed directly to the
#: Alembic config rather than through the environment: setting
#: UBUNTUGUARD_MIGRATION_DATABASE_URL here leaked into the PostgreSQL tests and
#: made them attempt a real connection instead of skipping.
OFFLINE_URL = "postgresql+psycopg://offline:offline@localhost:5432/ubuntuguard"


def alembic_config():  # noqa: ANN201 - Alembic's Config is untyped
    from alembic.config import Config

    config = Config(str(SERVER_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(SERVER_DIR / "migrations"))
    config.set_main_option("sqlalchemy.url", OFFLINE_URL)
    return config


def render(direction: str) -> str:
    from alembic import command

    config = alembic_config()
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        if direction == "up":
            command.upgrade(config, "head", sql=True)
        else:
            command.downgrade(config, "head:base", sql=True)
    return buffer.getvalue()


@pytest.fixture(scope="module")
def upgrade_sql() -> str:
    return render("up")


@pytest.fixture(scope="module")
def downgrade_sql() -> str:
    return render("down")


# --------------------------------------------------------------------------- #
# A migration exists and runs
# --------------------------------------------------------------------------- #


def test_revisions_form_a_single_linear_chain() -> None:
    """Exactly one root, exactly one head, and no branches.

    This replaces an earlier assertion that exactly ONE revision file existed,
    which was a Phase 0 guard against the initial schema being split across
    several files. It stopped being meaningful the moment a legitimate second
    revision was added, but the property actually worth protecting still holds:
    a branched or multi-headed history makes `upgrade head` ambiguous, and a
    missing link makes `downgrade base` impossible.
    """
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(alembic_config())
    revisions = list(script.walk_revisions())
    assert revisions, "no migration revisions found"

    heads = script.get_heads()
    assert len(heads) == 1, f"expected a single head, found {heads}"

    roots = [revision.revision for revision in revisions if revision.down_revision is None]
    assert len(roots) == 1, f"expected a single root revision, found {roots}"

    # Walking from head reaches every revision, so nothing is orphaned.
    assert len(revisions) == len({revision.revision for revision in revisions}), (
        "duplicate revision ids"
    )


def test_upgrade_renders_without_error(upgrade_sql: str) -> None:
    assert "CREATE TABLE" in upgrade_sql
    assert upgrade_sql.strip().startswith("BEGIN")
    assert upgrade_sql.strip().endswith("COMMIT;")


def test_downgrade_renders_without_error(downgrade_sql: str) -> None:
    assert "DROP TABLE" in downgrade_sql


# --------------------------------------------------------------------------- #
# Coverage: every model table, both directions
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("table", MODEL_TABLES)
def test_every_model_table_is_created(table: str, upgrade_sql: str) -> None:
    """Catches a model added without regenerating the migration."""
    assert f"CREATE TABLE {table} " in upgrade_sql


@pytest.mark.parametrize("table", MODEL_TABLES)
def test_every_model_table_is_dropped(table: str, downgrade_sql: str) -> None:
    """A downgrade that leaves tables behind is not a downgrade.

    This works only because models.py defines a naming convention: without
    deterministic names, a downgrade cannot drop constraints the server named.
    """
    assert f"DROP TABLE {table};" in downgrade_sql


def test_table_count_matches_the_models(upgrade_sql: str) -> None:
    # alembic_version is Alembic's own bookkeeping table, not one of ours.
    created = upgrade_sql.count("CREATE TABLE ") - upgrade_sql.count("CREATE TABLE alembic_version")
    assert created == len(MODEL_TABLES)


def test_indexes_are_created_and_dropped(upgrade_sql: str, downgrade_sql: str) -> None:
    created = upgrade_sql.count("CREATE INDEX ")
    dropped = downgrade_sql.count("DROP INDEX ")
    assert created > 0
    assert created == dropped, f"{created} indexes created but {dropped} dropped"


# --------------------------------------------------------------------------- #
# The columns the security design depends on
# --------------------------------------------------------------------------- #


def test_audit_log_columns_are_bytea_and_bigserial(upgrade_sql: str) -> None:
    """The hash chain covers exact bytes, and relies on a gapless sequence."""
    assert "seq BIGSERIAL NOT NULL" in upgrade_sql
    assert "detail_json BYTEA NOT NULL" in upgrade_sql
    assert "prev_hash BYTEA NOT NULL" in upgrade_sql
    assert "entry_hash BYTEA NOT NULL" in upgrade_sql


def test_policy_payload_is_bytea(upgrade_sql: str) -> None:
    """JSONB would re-encode the signed bytes and break every signature."""
    assert "payload BYTEA NOT NULL" in upgrade_sql


def test_timestamps_all_carry_a_timezone(upgrade_sql: str) -> None:
    assert "TIMESTAMP WITHOUT TIME ZONE" not in upgrade_sql
    assert "TIMESTAMP WITH TIME ZONE" in upgrade_sql


def test_check_constraints_are_emitted(upgrade_sql: str) -> None:
    for constraint in (
        "ck_users_role_valid",
        "ck_users_email_lowercase",
        "ck_devices_status_valid",
        "ck_policies_version_positive",
        "ck_usb_exceptions_reason_substantive",
    ):
        assert constraint in upgrade_sql, f"{constraint} missing from the migration"


def test_unique_constraints_that_enforce_requirements_are_emitted(upgrade_sql: str) -> None:
    assert "UNIQUE (policy_type, scope_kind, scope_id, version)" in upgrade_sql
    assert "UNIQUE (token_hash, csr_public_key_fingerprint)" in upgrade_sql
    assert "UNIQUE (cert_fingerprint)" in upgrade_sql


def test_no_credentials_appear_in_the_rendered_sql(upgrade_sql: str) -> None:
    """The URL is only there for the dialect; it must not be echoed into output
    that might be redirected to a file and committed.
    """
    assert "offline:offline" not in upgrade_sql
    assert OFFLINE_URL not in upgrade_sql


def test_migration_file_contains_no_connection_strings() -> None:
    """Checks for a URL, not for the word "password".

    `password_hash` is a legitimate column name, and matching on it made this
    test fail on correct code - a test that cries wolf gets deleted rather than
    heeded.
    """
    content = next((SERVER_DIR / "migrations" / "versions").glob("*.py")).read_text()
    for leak in ("postgresql://", "postgresql+psycopg://", "@localhost", "PASSWORD "):
        assert leak not in content, f"{leak!r} should not appear in a migration"
