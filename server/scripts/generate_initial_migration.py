#!/usr/bin/env python3
"""Generate the initial Alembic migration from the model metadata, offline.

Why not `alembic revision --autogenerate`? That diffs the models against a live
database and asserts a connection exists, so it cannot run before PostgreSQL is
installed. For the FIRST migration there is nothing to diff against: the target
is simply "create everything in Base.metadata". Building the ops directly gives
the same result with no connection.

Once a database exists, every SUBSEQUENT migration should come from the normal
`alembic revision --autogenerate -m "..."`, which can see what is already
deployed. This script is for the initial revision only, and re-running it on a
schema that already has migrations would produce a duplicate create.

Usage:  .venv/bin/python scripts/generate_initial_migration.py
"""

from __future__ import annotations

import datetime as dt
import subprocess
import sys
from pathlib import Path

from alembic.autogenerate import render_python_code
from alembic.migration import MigrationContext
from alembic.operations import ops

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ubuntuguard.models import Base  # noqa: E402

SERVER_DIR = Path(__file__).resolve().parents[1]
VERSIONS_DIR = SERVER_DIR / "migrations" / "versions"

REVISION = "0001_initial"
SLUG = "initial_schema"

TEMPLATE = '''"""Initial schema.

Revision ID: {revision}
Revises: None
Created: {created}

Generated from ubuntuguard.models by scripts/generate_initial_migration.py.
Do not hand-edit to add a new table: add it to the models and create a fresh
revision with `alembic revision --autogenerate`, so the models stay the single
source of truth.

The downgrade drops everything, which is what makes `alembic downgrade base`
testable. It relies on the naming convention in models.py: without deterministic
constraint names, a downgrade cannot drop what the server named for it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql  # noqa: F401 - used by rendered JSONB columns

revision: str = {revision!r}
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
{upgrade}


def downgrade() -> None:
{downgrade}
'''


def indent(code: str, spaces: int = 4) -> str:
    pad = " " * spaces
    lines = [f"{pad}{line}" if line.strip() else "" for line in code.splitlines()]
    return "\n".join(lines) or f"{pad}pass"


def main() -> int:
    # Rendering needs a dialect for type names, but no connection.
    context = MigrationContext.configure(dialect_name="postgresql")

    tables = list(Base.metadata.sorted_tables)

    create_ops: list[ops.MigrateOperation] = []
    for table in tables:
        create_ops.append(ops.CreateTableOp.from_table(table))
        # from_table does not carry indexes, so they are emitted separately.
        for index in sorted(table.indexes, key=lambda i: i.name or ""):
            create_ops.append(ops.CreateIndexOp.from_index(index))

    drop_ops: list[ops.MigrateOperation] = []
    for table in reversed(tables):
        for index in sorted(table.indexes, key=lambda i: i.name or ""):
            drop_ops.append(ops.DropIndexOp.from_index(index))
        drop_ops.append(ops.DropTableOp.from_table(table))

    upgrade_code = render_python_code(ops.UpgradeOps(ops=create_ops), migration_context=context)
    downgrade_code = render_python_code(ops.DowngradeOps(ops=drop_ops), migration_context=context)

    VERSIONS_DIR.mkdir(parents=True, exist_ok=True)
    target = VERSIONS_DIR / f"{REVISION}_{SLUG}.py"
    target.write_text(
        TEMPLATE.format(
            revision=REVISION,
            created=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            upgrade=indent(upgrade_code),
            downgrade=indent(downgrade_code),
        ),
        encoding="utf-8",
    )

    print(f"wrote {target.relative_to(SERVER_DIR)}")
    print(f"  tables:      {len(tables)}")
    print(f"  create ops:  {len(create_ops)}")
    print(f"  drop ops:    {len(drop_ops)}")

    # Formatting the generated file keeps it reviewable rather than a wall.
    ruff = SERVER_DIR / ".venv" / "bin" / "ruff"
    if ruff.exists():
        subprocess.run([str(ruff), "format", str(target)], check=False, cwd=SERVER_DIR)  # noqa: S603
        subprocess.run(  # noqa: S603
            [str(ruff), "check", "--fix", str(target)], check=False, cwd=SERVER_DIR
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
