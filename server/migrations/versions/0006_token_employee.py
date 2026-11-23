"""Bind an enrollment token to the employee it was issued for.

An administrator minting a token already knows who they are handing it to, so
the token can carry that and the device can assign itself at enrollment. Before
this, every laptop arrived unassigned and somebody had to remember to go back
and fill in a second form -- which is why the Assignment card on a real,
working device read as nothing but dashes.

ON DELETE SET NULL rather than CASCADE: removing an employee record must not
delete the audit-relevant history of which tokens were issued. The token
survives with no employee, which is the truth of the situation.

Revision ID: 0006_token_employee
Revises: 0005_device_hardware_info
Created: 2026-11-23T06:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_token_employee"
down_revision: str | None = "0005_device_hardware_info"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "enrollment_tokens",
        sa.Column("employee_id", sa.UUID(), nullable=True),
    )
    op.create_foreign_key(
        "fk_enrollment_tokens_employee_id_employees",
        "enrollment_tokens",
        "employees",
        ["employee_id"],
        ["id"],
        ondelete="SET NULL",
    )
    # Tokens are listed newest-first and joined to the employee for display.
    op.create_index(
        "ix_enrollment_tokens_employee_id",
        "enrollment_tokens",
        ["employee_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_enrollment_tokens_employee_id", table_name="enrollment_tokens")
    op.drop_constraint(
        "fk_enrollment_tokens_employee_id_employees",
        "enrollment_tokens",
        type_="foreignkey",
    )
    op.drop_column("enrollment_tokens", "employee_id")
