"""Database engine and session plumbing.

Nothing here connects at import time. That is deliberate: importing the
application must not require a database, so the test suite, `--help`, and
OpenAPI generation all work on a machine with no PostgreSQL. The connection is
made on first use, and `/readyz` is where its absence becomes visible.

Sync SQLAlchemy, with FastAPI running endpoints in its threadpool. Async
sessions bring greenlet and context-leak failure modes that a 10-50 device
prototype gains nothing from, and Alembic is synchronous regardless.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from ubuntuguard.config import Settings


def create_db_engine(settings: Settings, **kwargs: object) -> Engine:
    """Build an engine from settings.

    `pool_pre_ping` is on because a laptop fleet's traffic is bursty and idle
    PostgreSQL connections get dropped by the server or a firewall; without it
    the first request after a quiet period fails with a stale connection.
    """
    return create_engine(
        settings.require_database_url(),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        # Echo only ever under an explicit dev override. SQL logging on the
        # auth path would put token hashes in the log.
        echo=False,
        future=True,
        **kwargs,
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
        class_=Session,
    )


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """A transaction that commits on success and rolls back on any exception."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def check_connectivity(engine: Engine) -> None:
    """Raise if the database is unreachable. Used by `/readyz`."""
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))


def audit_role_is_append_only(engine: Engine, role: str | None = None) -> bool:
    """Whether the connected role lacks UPDATE and DELETE on `audit_logs`.

    Checked at startup and asserted by a test, because the append-only
    guarantee is a property of the GRANTs, not of the application code. If
    someone deploys with the owner role by mistake, the audit log silently
    stops being append-only, and this is how that gets noticed.
    """
    query = text(
        """
        SELECT privilege_type
          FROM information_schema.role_table_grants
         WHERE table_name = 'audit_logs'
           AND grantee = COALESCE(:role, current_user)
        """
    )
    with engine.connect() as connection:
        granted = {row[0] for row in connection.execute(query, {"role": role})}
    return not ({"UPDATE", "DELETE"} & granted)
