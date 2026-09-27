"""Structured security experience provenance for Hindsight.

Revision ID: cc67b9f2a001
Revises: 3f1186d33919
"""

import sqlalchemy as sa

from alembic import op

revision = "cc67b9f2a001"
down_revision = "3f1186d33919"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "memory_experiences",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("document_id", sa.String(100), nullable=False, unique=True),
        sa.Column("experience", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_memory_experiences_incident_id", "memory_experiences", ["incident_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_memory_experiences_incident_id", table_name="memory_experiences")
    op.drop_table("memory_experiences")
