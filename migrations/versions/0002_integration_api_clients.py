"""Integration API clients (other software, such as Mole Hash).

Adds the ``api_clients`` table, records which client requested an operation
and under which idempotency key, and lets the audit trail name a client as the
actor.

Revision ID: 0002
Revises: 0001
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

ACTORS_BEFORE = "actor_type IN ('user', 'device', 'system')"
ACTORS_AFTER = "actor_type IN ('user', 'device', 'system', 'client')"


def upgrade() -> None:
    op.create_table(
        "api_clients",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False),
        sa.Column("scopes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("owner_id", sa.UUID(), nullable=True),
        sa.Column("secret_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_ip", sa.String(length=64), nullable=False),
        sa.CheckConstraint("status IN ('active', 'revoked')", name="api_client_status"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["owner_id"], ["owners.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(op.f("ix_api_clients_owner_id"), "api_clients", ["owner_id"], unique=False)

    op.add_column("operations", sa.Column("requested_by_client", sa.UUID(), nullable=True))
    op.add_column("operations", sa.Column("request_key", sa.String(length=128), nullable=True))
    op.create_foreign_key(
        "operations_requested_by_client_fkey",
        "operations",
        "api_clients",
        ["requested_by_client"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "uq_operation_client_request",
        "operations",
        ["requested_by_client", "request_key"],
        unique=True,
        postgresql_where=sa.text("request_key IS NOT NULL"),
    )

    # The audit trail is append-only for rows; widening who may be named as
    # the actor changes no row.
    op.drop_constraint("audit_actor", "audit_log", type_="check")
    op.create_check_constraint("audit_actor", "audit_log", ACTORS_AFTER)


def downgrade() -> None:
    op.drop_constraint("audit_actor", "audit_log", type_="check")
    # NOT VALID: audit rows cannot be deleted, so rows already written with a
    # client as the actor stay. New rows are held to the old list again.
    op.execute(f"ALTER TABLE audit_log ADD CONSTRAINT audit_actor CHECK ({ACTORS_BEFORE}) NOT VALID")
    op.drop_index("uq_operation_client_request", table_name="operations")
    op.drop_constraint("operations_requested_by_client_fkey", "operations", type_="foreignkey")
    op.drop_column("operations", "request_key")
    op.drop_column("operations", "requested_by_client")
    op.drop_index(op.f("ix_api_clients_owner_id"), table_name="api_clients")
    op.drop_table("api_clients")
