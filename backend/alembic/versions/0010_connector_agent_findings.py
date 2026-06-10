"""Allow privilege findings for connector-agent jobs.

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "privilege_findings",
        "job_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
    )
    op.add_column(
        "privilege_findings",
        sa.Column("connector_agent_job_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_privilege_findings_connector_agent_job_id",
        "privilege_findings",
        "connector_agent_jobs",
        ["connector_agent_job_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_privilege_findings_connector_agent_job_id",
        "privilege_findings",
        ["connector_agent_job_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_privilege_findings_connector_agent_job_id", table_name="privilege_findings")
    op.drop_constraint(
        "fk_privilege_findings_connector_agent_job_id",
        "privilege_findings",
        type_="foreignkey",
    )
    op.drop_column("privilege_findings", "connector_agent_job_id")
    op.alter_column(
        "privilege_findings",
        "job_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False,
    )
