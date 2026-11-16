"""Employee management, device assignment history, and offline device incident kind.

Revision ID: 0004_assignment_and_offline_alerts
Revises: 0003_must_change_password
Created: 2026-11-16T12:30:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_employee_assignment"
down_revision: str | None = "0003_must_change_password"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Employees master table
    op.create_table(
        "employees",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("full_name", sa.String(length=120), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("department", sa.String(length=120), nullable=True),
        sa.Column("job_title", sa.String(length=120), nullable=True),
        sa.Column("phone", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=20), server_default="active", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'offboarded')",
            name="ck_employees_status_valid",
        ),
    )
    op.create_unique_constraint("uq_employees_email", "employees", ["email"])
    op.create_index("ix_employees_email", "employees", ["email"])
    op.create_index("ix_employees_department", "employees", ["department"])
    op.create_index("ix_employees_status", "employees", ["status"])

    # 2. Add department and assigned_to_id to devices
    op.add_column("devices", sa.Column("department", sa.String(length=120), nullable=True))
    op.add_column("devices", sa.Column("assigned_to_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_devices_assigned_to_id_employees",
        "devices",
        "employees",
        ["assigned_to_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # 3. Device assignment history table
    op.create_table(
        "device_assignments",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("employee_id", sa.UUID(), nullable=True),
        sa.Column("assigned_to_name", sa.String(length=120), nullable=False),
        sa.Column("assigned_to_email", sa.String(length=320), nullable=True),
        sa.Column("department", sa.String(length=120), nullable=True),
        sa.Column("notes", sa.String(length=500), nullable=True),
        sa.Column(
            "assigned_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("unassigned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assigned_by", sa.UUID(), nullable=True),
        sa.Column("unassigned_by", sa.UUID(), nullable=True),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name="fk_device_assignments_device_id_devices",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["employee_id"],
            ["employees.id"],
            name="fk_device_assignments_employee_id_employees",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_by"],
            ["users.id"],
            name="fk_device_assignments_assigned_by_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["unassigned_by"],
            ["users.id"],
            name="fk_device_assignments_unassigned_by_users",
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "ix_device_assignments_device_id_assigned_at",
        "device_assignments",
        ["device_id", "assigned_at"],
    )
    op.create_index(
        "ix_device_assignments_employee_id",
        "device_assignments",
        ["employee_id"],
    )

    # 4. Update incidents kind_valid check constraint to include 'device_offline'
    op.drop_constraint("kind_valid", "incidents", type_="check")
    op.create_check_constraint(
        "kind_valid",
        "incidents",
        "kind IN ('usb_blocked', 'clone_suspected', 'policy_rollback_failed', 'enforcer_unavailable', 'capability_lost', 'audit_chain_broken', 'device_offline')",
    )


def downgrade() -> None:
    # 4. Revert incidents kind_valid check constraint
    op.drop_constraint("kind_valid", "incidents", type_="check")
    op.create_check_constraint(
        "kind_valid",
        "incidents",
        "kind IN ('usb_blocked', 'clone_suspected', 'policy_rollback_failed', 'enforcer_unavailable', 'capability_lost', 'audit_chain_broken')",
    )

    # 3. Drop device_assignments
    op.drop_index("ix_device_assignments_employee_id", table_name="device_assignments")
    op.drop_index(
        "ix_device_assignments_device_id_assigned_at", table_name="device_assignments"
    )
    op.drop_table("device_assignments")

    # 2. Revert devices columns
    op.drop_constraint("fk_devices_assigned_to_id_employees", "devices", type_="foreignkey")
    op.drop_column("devices", "assigned_to_id")
    op.drop_column("devices", "department")

    # 1. Drop employees
    op.drop_index("ix_employees_status", table_name="employees")
    op.drop_index("ix_employees_department", table_name="employees")
    op.drop_index("ix_employees_email", table_name="employees")
    op.drop_constraint("uq_employees_email", "employees", type_="unique")
    op.drop_table("employees")
