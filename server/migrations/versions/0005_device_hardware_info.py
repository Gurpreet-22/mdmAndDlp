"""Hardware information (CPU model, CPU cores, RAM, and disk capacity).

Revision ID: 0005_device_hardware_info
Revises: 0004_employee_assignment
Created: 2026-11-16T13:10:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_device_hardware_info"
down_revision: str | None = "0004_employee_assignment"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("cpu_model", sa.String(length=128), nullable=True))
    op.add_column("devices", sa.Column("cpu_cores", sa.Integer(), nullable=True))
    op.add_column("devices", sa.Column("total_ram_bytes", sa.BigInteger(), nullable=True))
    op.add_column("devices", sa.Column("disk_total_bytes", sa.BigInteger(), nullable=True))
    op.add_column("devices", sa.Column("disk_free_bytes", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("devices", "disk_free_bytes")
    op.drop_column("devices", "disk_total_bytes")
    op.drop_column("devices", "total_ram_bytes")
    op.drop_column("devices", "cpu_cores")
    op.drop_column("devices", "cpu_model")

