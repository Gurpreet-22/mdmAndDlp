"""Record that a laptop's agent was removed, as distinct from merely quiet.

Asset coverage needs three answers, and the schema could only give two. A
device row with `enrolled_at IS NULL` is a company laptop that never had the
agent. A row with `enrolled_at` set is one that did. But a laptop whose agent
was uninstalled looked exactly like a laptop that was switched off: both stop
heartbeating and both read as offline.

`agent_removed_at` is set when a device tells the server it is being
uninstalled, which the package's `prerm` does before it stops the services. It
is cleared by the next heartbeat, so a reinstall needs no administrator action
to look correct again.

The weakness is worth stating rather than discovering: this is a courtesy
message from a machine that is being dismantled. Anyone who stops the service
first, pulls the network, or deletes the identity by hand will not send it, and
`docs/04-feature-list.md` section 4 says plainly that a local root user can do
exactly that. The reliable signal remains the absence of heartbeats. This field
exists so the ordinary case - somebody running `apt remove` - is reported as
what it is rather than as a laptop that might be in a drawer.

Revision ID: 0008_agent_removed
Revises: 0007_reported_hardware
Created: 2026-11-25T12:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_agent_removed"
down_revision: str | None = "0007_reported_hardware"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column("agent_removed_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "devices",
        sa.Column("agent_removed_reason", sa.String(length=200), nullable=True),
    )
    # The fleet-coverage query filters on this, and it is highly selective: a
    # handful of removals against the whole estate.
    op.create_index(
        "ix_devices_agent_removed_at",
        "devices",
        ["agent_removed_at"],
        postgresql_where=sa.text("agent_removed_at IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_devices_agent_removed_at", table_name="devices")
    op.drop_column("devices", "agent_removed_reason")
    op.drop_column("devices", "agent_removed_at")
