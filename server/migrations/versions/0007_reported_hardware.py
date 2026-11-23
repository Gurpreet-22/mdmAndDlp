"""Record the make and model the device reports, separately from the admin's.

The Assignment card had Manufacturer and Model as dashes on a laptop that knew
perfectly well what it was: `/sys/class/dmi/id/sys_vendor` and
`product_version` are world-readable, so the unprivileged agent can read them.

They land in NEW columns rather than in `devices.manufacturer` and
`devices.model`, and that is the whole point of this migration. Those two
belong to the administrator, and enrollment is guaranteed not to overwrite
administrator-supplied fields - a laptop does not get to rename itself or
restate its own make. Writing reported values into the same columns would
quietly retire that guarantee. Keeping them apart also means an operator can
see when the firmware and the asset record disagree, which is exactly the
interesting case.

Revision ID: 0007_reported_hardware
Revises: 0006_token_employee
Created: 2026-11-23T12:30:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_reported_hardware"
down_revision: str | None = "0006_token_employee"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Lengths match the administrator-facing siblings exactly - manufacturer is
    # String(64), model String(120) - so the two can be compared and displayed
    # interchangeably. The agent truncates to the same bounds, so an absurd DMI
    # string becomes a trimmed value rather than a rejected enrollment.
    op.add_column(
        "devices",
        sa.Column("reported_manufacturer", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "devices",
        sa.Column("reported_model", sa.String(length=120), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("devices", "reported_model")
    op.drop_column("devices", "reported_manufacturer")
