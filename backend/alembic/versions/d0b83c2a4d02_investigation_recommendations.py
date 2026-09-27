"""Persist reviewable recommendations. Revision ID: d0b83c2a4d02"""

import sqlalchemy as sa

from alembic import op

revision = "d0b83c2a4d02"
down_revision = "cc67b9f2a001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigation_recommendations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_investigation_recommendations_incident_id",
                    "investigation_recommendations", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_investigation_recommendations_incident_id", table_name="investigation_recommendations")
    op.drop_table("investigation_recommendations")
