"""Appliance: organisation roles, remote-access grants, desired state, releases.

Adds what docs/appliance.md needs:

- ``users.org_role``: what an owner's user may do inside the organisation.
  Existing owner users become ``org_admin`` (they could do everything before).
- ``machines.management``: whether HappyMining staff manage the machine.
  Existing machines are ``company``: nothing changes for them.
- ``machine_appliances``: the desired-state document per machine, sealed
  secrets, and what the machine reports.
- ``remote_access_grants``: the owner's permission for staff to see or manage
  a customer-managed machine.
- ``releases``: signed firmware releases.

Revision ID: 0003
Revises: 0002
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("org_role", sa.String(length=20), nullable=True))
    op.execute("UPDATE users SET org_role = 'org_admin' WHERE role = 'owner'")
    op.create_check_constraint("user_org_role_link", "users", "(role = 'owner') = (org_role IS NOT NULL)")
    op.create_check_constraint(
        "user_org_role",
        "users",
        "org_role IS NULL OR org_role IN ('org_admin', 'org_operator', 'org_viewer')",
    )

    op.add_column(
        "machines",
        sa.Column("management", sa.String(length=20), nullable=False, server_default="company"),
    )
    op.create_check_constraint("machine_management", "machines", "management IN ('company', 'customer')")

    op.create_table(
        "machine_appliances",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("machine_id", sa.UUID(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("secrets", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reported", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("applied_revision", sa.Integer(), nullable=False),
        sa.Column("seal_public_key", sa.String(length=120), nullable=True),
        sa.CheckConstraint("revision >= 0", name="appliance_revision"),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_machine_appliances_machine_id"), "machine_appliances", ["machine_id"], unique=True
    )

    op.create_table(
        "remote_access_grants",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("machine_id", sa.UUID(), nullable=False),
        sa.Column("owner_id", sa.UUID(), nullable=False),
        sa.Column("level", sa.String(length=10), nullable=False),
        sa.Column("reason", sa.String(length=300), nullable=False),
        sa.Column("granted_by", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.UUID(), nullable=True),
        sa.CheckConstraint("level IN ('view', 'manage')", name="grant_level"),
        sa.ForeignKeyConstraint(["granted_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["owner_id"], ["owners.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["revoked_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_remote_access_grants_machine_id"), "remote_access_grants", ["machine_id"], unique=False
    )
    op.create_index(
        op.f("ix_remote_access_grants_owner_id"), "remote_access_grants", ["owner_id"], unique=False
    )

    op.create_table(
        "releases",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("version", sa.String(length=24), nullable=False),
        sa.Column("v_major", sa.Integer(), nullable=False),
        sa.Column("v_minor", sa.Integer(), nullable=False),
        sa.Column("v_patch", sa.Integer(), nullable=False),
        sa.Column("manifest", sa.LargeBinary(), nullable=False),
        sa.Column("signature", sa.String(length=128), nullable=False),
        sa.Column("key_id", sa.String(length=16), nullable=False),
        sa.Column("filename", sa.String(length=128), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("min_upgrade_from", sa.String(length=24), nullable=False),
        sa.Column("notes", sa.String(length=4000), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("channels", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("artifact", sa.LargeBinary(), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('awaiting_artifact', 'ready', 'withdrawn')", name="release_status"
        ),
        sa.CheckConstraint(
            "(status = 'awaiting_artifact') = (artifact IS NULL)", name="release_artifact_present"
        ),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("version"),
    )


def downgrade() -> None:
    op.drop_table("releases")
    op.drop_index(op.f("ix_remote_access_grants_owner_id"), table_name="remote_access_grants")
    op.drop_index(op.f("ix_remote_access_grants_machine_id"), table_name="remote_access_grants")
    op.drop_table("remote_access_grants")
    op.drop_index(op.f("ix_machine_appliances_machine_id"), table_name="machine_appliances")
    op.drop_table("machine_appliances")
    op.drop_constraint("machine_management", "machines", type_="check")
    op.drop_column("machines", "management")
    op.drop_constraint("user_org_role", "users", type_="check")
    op.drop_constraint("user_org_role_link", "users", type_="check")
    op.drop_column("users", "org_role")
