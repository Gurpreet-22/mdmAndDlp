"""Forced password change after an administrator reset.

Revision ID: 0003_must_change_password
Revises: 0002_device_registration
Created: 2026-11-12T10:00:00+00:00

Adds one Boolean to `users`. It is set by `POST /users/{id}:reset-password` and
cleared by `POST /auth/password`, and while it is true `require_capability`
refuses every capability-guarded route - so the account can read `/auth/me`,
change its password, and sign out, and nothing else.

`server_default false` is the load-bearing part of this migration, not a
stylistic choice. A NOT NULL column added to a populated table needs a default
for PostgreSQL to backfill existing rows; without it the ALTER fails. With
`false` specifically, every administrator who exists today keeps working and
none of them is forced into a password change by the act of migrating. The
column is also given a Python-side `default=False` in the model, so a row
inserted through the ORM without mentioning it behaves the same way.

Unlike 0002, the downgrade here is lossless. Dropping the column discards only
the knowledge of which accounts owed a password change; it cannot leave a row
unrepresentable, because nothing else depends on the value. An account that was
mid-reset when a downgrade happened simply keeps the temporary password its
administrator set, which is recoverable through the same route on the way back
up.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_must_change_password"
down_revision: str | None = "0002_device_registration"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "must_change_password")
