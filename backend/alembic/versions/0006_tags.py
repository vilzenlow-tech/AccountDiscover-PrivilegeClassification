"""Add managed tag catalog and asset-tag assignments.

Creates:
  tag_category_enum  — application, environment, business_unit, criticality,
                       compliance, ownership, technology, custom
  tag_status_enum    — active, inactive
  tags               — managed tag catalog
  asset_tags         — many-to-many asset ↔ tag with assignment metadata

Seeds six sample tags (SAP, CoreBanking, HRMS, PCI, Production, Critical).

Revision ID: 0006
Revises: 0005
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── 1. Create enum types ──────────────────────────────────────────────────
    tag_category_enum = postgresql.ENUM(
        "application", "environment", "business_unit", "criticality",
        "compliance", "ownership", "technology", "custom",
        name="tag_category_enum",
    )
    tag_category_enum.create(op.get_bind(), checkfirst=True)

    tag_status_enum = postgresql.ENUM(
        "active", "inactive",
        name="tag_status_enum",
    )
    tag_status_enum.create(op.get_bind(), checkfirst=True)

    # ── 2. tags table ─────────────────────────────────────────────────────────
    op.create_table(
        "tags",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tag_name", sa.String(100), nullable=False),
        sa.Column("tag_code", sa.String(50), nullable=True),
        sa.Column("description", sa.String(512), nullable=True),
        sa.Column("category",
                  postgresql.ENUM("application", "environment", "business_unit", "criticality",
                                  "compliance", "ownership", "technology", "custom",
                                  name="tag_category_enum", create_type=False),
                  nullable=False, server_default="custom"),
        sa.Column("color", sa.String(7), nullable=False, server_default="#6366f1"),
        sa.Column("status",
                  postgresql.ENUM("active", "inactive",
                                  name="tag_status_enum", create_type=False),
                  nullable=False, server_default="active"),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("updated_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("tag_name", name="uq_tag_name"),
        sa.UniqueConstraint("tag_code", name="uq_tag_code"),
    )
    op.create_index("ix_tags_tag_name", "tags", ["tag_name"])
    op.create_index("ix_tags_tag_code", "tags", ["tag_code"])
    op.create_index("ix_tags_status", "tags", ["status"])
    op.create_index("ix_tags_category", "tags", ["category"])

    # ── 3. asset_tags table ───────────────────────────────────────────────────
    op.create_table(
        "asset_tags",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tag_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tags.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("assigned_by", sa.String(255), nullable=True),
        sa.Column("assigned_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("asset_id", "tag_id", name="uq_asset_tag"),
    )
    op.create_index("ix_asset_tags_asset_id", "asset_tags", ["asset_id"])
    op.create_index("ix_asset_tags_tag_id", "asset_tags", ["tag_id"])

    # ── 4. Seed sample tags ───────────────────────────────────────────────────
    op.execute("""
        INSERT INTO tags (tag_name, tag_code, description, category, color, status) VALUES
        ('SAP',         'sap',          'SAP ERP application assets',              'application',  '#f59e0b', 'active'),
        ('CoreBanking', 'core-banking', 'Core Banking System assets',              'application',  '#3b82f6', 'active'),
        ('HRMS',        'hrms',         'Human Resource Management System',        'application',  '#8b5cf6', 'active'),
        ('PCI',         'pci',          'PCI DSS in-scope assets',                 'compliance',   '#ef4444', 'active'),
        ('Production',  'prod',         'Production environment assets',           'environment',  '#10b981', 'active'),
        ('Critical',    'critical',     'Business-critical assets requiring 24/7', 'criticality',  '#f97316', 'active')
        ON CONFLICT DO NOTHING;
    """)


def downgrade() -> None:
    op.drop_table("asset_tags")
    op.drop_table("tags")
    op.execute("DROP TYPE IF EXISTS tag_status_enum")
    op.execute("DROP TYPE IF EXISTS tag_category_enum")
