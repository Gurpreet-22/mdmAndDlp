"""Device registration: a device row can exist before the device is enrolled.

Revision ID: 0002_device_registration
Revises: 0001_initial
Created: 2026-10-30T11:07:18+00:00

Adds the administrator-supplied half of a device record, so an IT admin can add
an employee laptop in the dashboard before the agent has ever run on it. That is
what makes "unenrolled" a tracked state rather than an absence of data.

Two columns become nullable, and the reason matters:

  `hostname`     only the device can know it, so a registered-but-unseen device
                 must be allowed not to have one. The server never guesses.
  `enrolled_at`  NULL is now the precise definition of unenrolled. Previously
                 every row had one because rows were only ever created BY
                 enrollment.

Autogenerate does not detect CHECK constraints, so `platform_valid` and
`enrolled_at_matches_status` are written by hand below. The second one is the
important one: it makes "active but never enrolled" and "pending with an
enrollment timestamp" unrepresentable, rather than merely unlikely.

THE DOWNGRADE DELETES PENDING DEVICES. It has to: going back to 0001 restores
`hostname` and `enrolled_at` as NOT NULL, and a registered-but-unenrolled row
has neither. There is no value to invent for them, and a downgrade that fails
halfway is worse than one that states its cost. Enrolled devices are untouched.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_device_registration"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- Administrator-supplied identity ---------------------------------- #
    op.add_column("devices", sa.Column("display_name", sa.String(length=120), nullable=True))
    op.add_column("devices", sa.Column("manufacturer", sa.String(length=64), nullable=True))
    op.add_column("devices", sa.Column("model", sa.String(length=120), nullable=True))
    op.add_column("devices", sa.Column("assigned_to_name", sa.String(length=120), nullable=True))
    op.add_column("devices", sa.Column("assigned_to_email", sa.String(length=320), nullable=True))
    op.add_column("devices", sa.Column("platform", sa.String(length=16), nullable=True))
    op.add_column("devices", sa.Column("asset_tag", sa.String(length=64), nullable=True))
    op.add_column(
        "devices",
        sa.Column(
            "registered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.add_column("devices", sa.Column("registered_by", sa.UUID(), nullable=True))

    # --- Agent-reported, informational only -------------------------------- #
    op.add_column("devices", sa.Column("primary_adapter_ip", sa.String(length=45), nullable=True))

    # --- The two columns that only exist after enrollment ------------------ #
    op.alter_column("devices", "hostname", existing_type=sa.VARCHAR(length=253), nullable=True)
    op.alter_column(
        "devices",
        "enrolled_at",
        existing_type=postgresql.TIMESTAMP(timezone=True),
        server_default=None,
        nullable=True,
    )

    op.create_index("ix_devices_status", "devices", ["status"], unique=False)
    op.create_index("ix_devices_assigned_to_email", "devices", ["assigned_to_email"], unique=False)
    op.create_foreign_key(
        op.f("fk_devices_registered_by_users"),
        "devices",
        "users",
        ["registered_by"],
        ["id"],
        ondelete="SET NULL",
    )

    # --- Hand-written: autogenerate does not emit CHECK constraints -------- #
    op.create_check_constraint(
        "platform_valid",
        "devices",
        "platform IN ('linux', 'macos', 'windows') OR platform IS NULL",
    )
    op.create_check_constraint(
        "enrolled_at_matches_status",
        "devices",
        "(status = 'pending' AND enrolled_at IS NULL) "
        "OR (status <> 'pending' AND enrolled_at IS NOT NULL)",
    )

    # --- The token -> pre-registered device link --------------------------- #
    # ON DELETE CASCADE: deleting a registered device that never enrolled should
    # take its unused enrollment token with it, not leave a live credential
    # pointing at nothing.
    op.add_column(
        "enrollment_tokens", sa.Column("pre_registered_device_id", sa.UUID(), nullable=True)
    )
    op.create_foreign_key(
        op.f("fk_enrollment_tokens_pre_registered_device_id_devices"),
        "enrollment_tokens",
        "devices",
        ["pre_registered_device_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("fk_enrollment_tokens_pre_registered_device_id_devices"),
        "enrollment_tokens",
        type_="foreignkey",
    )
    op.drop_column("enrollment_tokens", "pre_registered_device_id")

    # Short names on purpose. The `ck` naming convention in models.py expands
    # these to ck_devices_<name>, exactly as it did on the way up. Passing the
    # already-expanded name gets it expanded a SECOND time, which fails looking
    # for ck_devices_ck_devices_platform_valid.
    op.drop_constraint("enrolled_at_matches_status", "devices", type_="check")
    op.drop_constraint("platform_valid", "devices", type_="check")

    # Stated in the module docstring: a registered-but-unenrolled device cannot
    # be represented under 0001, because both columns it lacks are NOT NULL
    # there. Removing the rows is the only honest downgrade. Enrolled devices,
    # which by definition have both values, survive untouched.
    op.execute("DELETE FROM devices WHERE status = 'pending' OR enrolled_at IS NULL")

    op.drop_constraint(op.f("fk_devices_registered_by_users"), "devices", type_="foreignkey")
    op.drop_index("ix_devices_assigned_to_email", table_name="devices")
    op.drop_index("ix_devices_status", table_name="devices")

    op.alter_column(
        "devices",
        "enrolled_at",
        existing_type=postgresql.TIMESTAMP(timezone=True),
        server_default=sa.text("now()"),
        nullable=False,
    )
    op.alter_column("devices", "hostname", existing_type=sa.VARCHAR(length=253), nullable=False)

    op.drop_column("devices", "primary_adapter_ip")
    op.drop_column("devices", "registered_by")
    op.drop_column("devices", "registered_at")
    op.drop_column("devices", "asset_tag")
    op.drop_column("devices", "platform")
    op.drop_column("devices", "assigned_to_email")
    op.drop_column("devices", "assigned_to_name")
    op.drop_column("devices", "model")
    op.drop_column("devices", "manufacturer")
    op.drop_column("devices", "display_name")
