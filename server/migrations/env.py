"""Alembic environment.

The URL comes from settings, never from alembic.ini, so no credential is ever
written into a tracked file. Migrations use the OWNER role; see alembic.ini for
why that is not the application role.

Offline mode (`alembic upgrade head --sql`) renders the DDL without connecting,
which is how the migration scripts are checked on a machine with no PostgreSQL.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from ubuntuguard.config import Settings
from ubuntuguard.models import Base

config = context.config

target_metadata = Base.metadata


def _database_url() -> str:
    # An explicitly supplied URL wins. Tests use this to render SQL offline
    # without touching the environment, which previously leaked a URL into
    # unrelated tests and made them attempt a real connection.
    explicit = config.get_main_option("sqlalchemy.url", None)
    if explicit:
        return explicit

    settings = Settings()
    url = settings.migration_database_url or settings.database_url
    if url is None:
        raise RuntimeError(
            "No database URL for migrations. Set UBUNTUGUARD_MIGRATION_DATABASE_URL "
            "to the owner role, for example:\n"
            "  export UBUNTUGUARD_MIGRATION_DATABASE_URL="
            "postgresql+psycopg://ubuntuguard_owner:devpassword@localhost:5432/ubuntuguard"
        )
    return url.get_secret_value()


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Needed for a downgrade to find the constraints it has to drop; the
        # metadata's naming convention supplies the names.
        render_as_batch=False,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            # One transaction for the whole migration, so a failure half way
            # through leaves the schema as it was rather than partly upgraded.
            transaction_per_migration=False,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
