"""SQLAlchemy models.

Money columns are NUMERIC, never floating point. Internal amounts keep eight
decimal places (``Money8``); payout amounts are rounded to cents (``Money2``).
The ledger tables (journal entries and lines) and the audit log are
append-only: database triggers created in the migration reject UPDATE and
DELETE on them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

Money8 = Numeric(24, 8)
Money2 = Numeric(20, 2)
Rate = Numeric(9, 8)


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> uuid.UUID:
    return uuid.uuid4()


def in_list(column: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONB}


def pk() -> Mapped[uuid.UUID]:
    return mapped_column(PGUUID(as_uuid=True), primary_key=True, default=new_id)


def fk(target: str, *, nullable: bool = False, index: bool = True, **kw: Any) -> Mapped[Any]:
    return mapped_column(
        PGUUID(as_uuid=True), ForeignKey(target, ondelete="RESTRICT"), nullable=nullable, index=index, **kw
    )


def ts(*, nullable: bool = False, default: bool = True) -> Mapped[Any]:
    if default:
        return mapped_column(DateTime(timezone=True), nullable=nullable, default=utcnow)
    return mapped_column(DateTime(timezone=True), nullable=nullable)


# --------------------------------------------------------------------------
# People and access
# --------------------------------------------------------------------------

ROLES = ("admin", "owner", "auditor")
# What a user of role "owner" may do inside the owner's organisation
# (docs/appliance.md, section 3). Staff roles have no organisation role.
ORG_ROLES = ("org_admin", "org_operator", "org_viewer")


class Owner(Base):
    """A customer who owns GPU machines operated by HappyMining."""

    __tablename__ = "owners"

    id: Mapped[uuid.UUID] = pk()
    display_name: Mapped[str] = mapped_column(String(200))
    legal_name: Mapped[str] = mapped_column(String(200), default="")
    contact_email: Mapped[str] = mapped_column(String(320), default="")
    status: Mapped[str] = mapped_column(String(20), default="active")
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = ts()

    __table_args__ = (CheckConstraint(in_list("status", ("active", "suspended")), name="owner_status"),)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = pk()
    email: Mapped[str] = mapped_column(String(320), unique=True)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    role: Mapped[str] = mapped_column(String(20))
    owner_id: Mapped[uuid.UUID | None] = fk("owners.id", nullable=True)
    org_role: Mapped[str | None] = mapped_column(String(20), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(500), nullable=True)
    totp_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Last accepted TOTP time-step, so a code cannot be used twice (RFC 6238, 5.2).
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = ts()
    last_login_at: Mapped[datetime | None] = ts(nullable=True, default=False)

    owner: Mapped[Owner | None] = relationship()

    __table_args__ = (
        CheckConstraint(in_list("role", ROLES), name="user_role"),
        CheckConstraint("(role = 'owner') = (owner_id IS NOT NULL)", name="user_owner_link"),
        CheckConstraint("(role = 'owner') = (org_role IS NOT NULL)", name="user_org_role_link"),
        CheckConstraint("org_role IS NULL OR " + in_list("org_role", ORG_ROLES), name="user_org_role"),
        CheckConstraint("email = lower(email)", name="user_email_lower"),
    )


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = pk()
    user_id: Mapped[uuid.UUID] = fk("users.id")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = ts()
    expires_at: Mapped[datetime] = ts(default=False)
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(300), default="")

    user: Mapped[User] = relationship()


# --------------------------------------------------------------------------
# Machines, enrollment and devices
# --------------------------------------------------------------------------


MANAGEMENT_KINDS = ("company", "customer")


class Machine(Base):
    """A physical GPU server belonging to exactly one owner at a time."""

    __tablename__ = "machines"

    id: Mapped[uuid.UUID] = pk()
    owner_id: Mapped[uuid.UUID] = fk("owners.id")
    label: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20), default="pending_pairing")
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    hardware: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # Who runs the machine day to day. "company": HappyMining staff manage it.
    # "customer": staff need a remote-access grant from the owner's
    # organisation to read its appliance configuration, change it or request
    # operations (docs/appliance.md, section 3).
    management: Mapped[str] = mapped_column(String(20), default="company", server_default="company")
    created_at: Mapped[datetime] = ts()

    owner: Mapped[Owner] = relationship()
    device: Mapped[Device | None] = relationship(back_populates="machine", uselist=False)
    provider_machine: Mapped[ProviderMachine | None] = relationship(back_populates="machine", uselist=False)

    __table_args__ = (
        CheckConstraint(in_list("status", ("pending_pairing", "active", "retired")), name="machine_status"),
        CheckConstraint(in_list("management", MANAGEMENT_KINDS), name="machine_management"),
    )


class MachineOwnership(Base):
    """Ownership history in whole UTC days: [valid_from, valid_to).

    Day granularity matches the earnings buckets, so every bucket has exactly
    one owner. An exclusion constraint (migration) forbids overlaps.
    """

    __tablename__ = "machine_ownership"

    id: Mapped[uuid.UUID] = pk()
    machine_id: Mapped[uuid.UUID] = fk("machines.id")
    owner_id: Mapped[uuid.UUID] = fk("owners.id")
    valid_from: Mapped[date] = mapped_column(Date)
    valid_to: Mapped[date | None] = mapped_column(Date, nullable=True)
    changed_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    reason: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = ts()

    __table_args__ = (
        CheckConstraint("valid_to IS NULL OR valid_to > valid_from", name="ownership_range"),
        Index(
            "uq_machine_current_owner", "machine_id", unique=True, postgresql_where=text("valid_to IS NULL")
        ),
    )


class EnrollmentRequest(Base):
    """A pairing code issued for one owner and one machine record."""

    __tablename__ = "enrollment_requests"

    id: Mapped[uuid.UUID] = pk()
    owner_id: Mapped[uuid.UUID] = fk("owners.id")
    machine_id: Mapped[uuid.UUID] = fk("machines.id")
    locator: Mapped[str] = mapped_column(String(6), unique=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5)
    expires_at: Mapped[datetime] = ts(default=False)
    created_by: Mapped[uuid.UUID] = fk("users.id", index=False)
    created_at: Mapped[datetime] = ts()
    consumed_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    device_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)

    machine: Mapped[Machine] = relationship()
    owner: Mapped[Owner] = relationship()

    __table_args__ = (
        CheckConstraint(
            in_list("status", ("pending", "consumed", "expired", "locked", "cancelled")),
            name="enrollment_status",
        ),
    )


class Device(Base):
    """The HappyMining agent installation on a machine."""

    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = pk()
    machine_id: Mapped[uuid.UUID] = fk("machines.id", unique=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    hostname: Mapped[str] = mapped_column(String(128), default="")
    fingerprint: Mapped[str] = mapped_column(String(80), default="")
    agent_version: Mapped[str] = mapped_column(String(40), default="")
    os_info: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    boot_id: Mapped[str] = mapped_column(String(64), default="")
    last_seq: Mapped[int] = mapped_column(BigInteger, default=0)
    last_seen_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    created_at: Mapped[datetime] = ts()
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)

    machine: Mapped[Machine] = relationship(back_populates="device")

    __table_args__ = (CheckConstraint(in_list("status", ("active", "revoked")), name="device_status"),)


class DeviceCredential(Base):
    __tablename__ = "device_credentials"

    id: Mapped[uuid.UUID] = pk()
    device_id: Mapped[uuid.UUID] = fk("devices.id")
    secret_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = ts()
    first_used_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    last_used_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    superseded_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)

    device: Mapped[Device] = relationship()

    __table_args__ = (
        CheckConstraint(in_list("status", ("active", "superseded", "revoked")), name="credential_status"),
    )


class TelemetrySample(Base):
    __tablename__ = "telemetry_samples"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    device_id: Mapped[uuid.UUID] = fk("devices.id", index=False)
    machine_id: Mapped[uuid.UUID] = fk("machines.id", index=False)
    seq: Mapped[int] = mapped_column(BigInteger)
    boot_id: Mapped[str] = mapped_column(String(64), default="")
    collected_at: Mapped[datetime] = ts(default=False)
    received_at: Mapped[datetime] = ts()
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    gpu_count: Mapped[int] = mapped_column(Integer, default=0)
    gpu_util_avg: Mapped[Decimal | None] = mapped_column(Numeric(6, 2), nullable=True)
    gpu_power_w: Mapped[Decimal | None] = mapped_column(Numeric(10, 2), nullable=True)
    gpu_temp_max: Mapped[Decimal | None] = mapped_column(Numeric(6, 2), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint("device_id", "seq", name="uq_telemetry_device_seq"),
        Index("ix_telemetry_machine_time", "machine_id", "collected_at"),
    )


OPERATION_STATUSES = (
    "pending",
    "delivered",
    "accepted",
    "succeeded",
    "failed",
    "rejected",
    "expired",
    "cancelled",
    "blocked",
)
OPERATION_FINAL = ("succeeded", "failed", "rejected", "expired", "cancelled", "blocked")


class Operation(Base):
    """A typed, allowlisted operation requested from a device."""

    __tablename__ = "operations"

    id: Mapped[uuid.UUID] = pk()
    machine_id: Mapped[uuid.UUID] = fk("machines.id")
    device_id: Mapped[uuid.UUID] = fk("devices.id")
    type: Mapped[str] = mapped_column(String(40))
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    nonce: Mapped[str] = mapped_column(String(64))
    requested_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    # Set when the request came through the integration API (an API client,
    # not a person), with the idempotency key that client supplied.
    requested_by_client: Mapped[uuid.UUID | None] = fk("api_clients.id", nullable=True, index=False)
    request_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    issued_at: Mapped[datetime] = ts()
    expires_at: Mapped[datetime] = ts(default=False)
    delivered_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    completed_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    detail: Mapped[str] = mapped_column(String(2000), default="")
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    safety: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    machine: Mapped[Machine] = relationship()

    __table_args__ = (
        CheckConstraint(in_list("status", OPERATION_STATUSES), name="operation_status"),
        # One operation per (client, idempotency key): a retried request finds the first one.
        Index(
            "uq_operation_client_request",
            "requested_by_client",
            "request_key",
            unique=True,
            postgresql_where=text("request_key IS NOT NULL"),
        ),
    )


# --------------------------------------------------------------------------
# Integration API clients (other software, e.g. Mole Hash)
# --------------------------------------------------------------------------

API_CLIENT_SCOPES = (
    "fleet:read",
    "telemetry:read",
    "operations:read",
    "operations:write",
    "operations:disruptive",
    "earnings:read",
    "appliance:read",
)


class ApiClient(Base):
    """Another system allowed to call the integration API with a scoped token.

    Not a person and not a device. It can never reach the routes people or
    agents use, and those credentials can never reach its routes. Only a keyed
    hash of its secret is stored.
    """

    __tablename__ = "api_clients"

    id: Mapped[uuid.UUID] = pk()
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    scopes: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # NULL: the whole fleet. Set: only this owner's machines and earnings.
    owner_id: Mapped[uuid.UUID | None] = fk("owners.id", nullable=True)
    secret_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    created_at: Mapped[datetime] = ts()
    expires_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    rotated_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    last_used_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    last_used_ip: Mapped[str] = mapped_column(String(64), default="")

    __table_args__ = (CheckConstraint(in_list("status", ("active", "revoked")), name="api_client_status"),)


# --------------------------------------------------------------------------
# Appliance: what a machine should run, who may manage it, firmware releases
# (docs/appliance.md)
# --------------------------------------------------------------------------

APPLIANCE_MODES = ("vast", "private_ai", "vectorize")
GRANT_LEVELS = ("view", "manage")
RELEASE_CHANNELS = ("beta", "stable")
RELEASE_STATUSES = ("awaiting_artifact", "ready", "withdrawn")


class MachineAppliance(Base):
    """The desired-state document of one machine and what the machine last reported.

    ``document`` never contains secrets. ``secrets`` holds values sealed for
    the machine's own key: this process stores and forwards them and has no
    key to open them. ``reported`` comes from the device; it is displayed and
    never used to decide what anyone may do.
    """

    __tablename__ = "machine_appliances"

    id: Mapped[uuid.UUID] = pk()
    machine_id: Mapped[uuid.UUID] = fk("machines.id", unique=True)
    # 0: nothing was ever configured in the cloud; nothing is sent to the machine.
    revision: Mapped[int] = mapped_column(Integer, default=0)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    secrets: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    updated_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    updated_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    # From the device.
    reported: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    reported_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    applied_revision: Mapped[int] = mapped_column(Integer, default=0)
    seal_public_key: Mapped[str | None] = mapped_column(String(120), nullable=True)

    machine: Mapped[Machine] = relationship()

    __table_args__ = (CheckConstraint("revision >= 0", name="appliance_revision"),)


class RemoteAccessGrant(Base):
    """Permission, given by the owner's organisation, for HappyMining staff to
    see or manage one customer-managed machine. Rows are never deleted: a grant
    ends by expiring or by being revoked."""

    __tablename__ = "remote_access_grants"

    id: Mapped[uuid.UUID] = pk()
    machine_id: Mapped[uuid.UUID] = fk("machines.id")
    # The owner on whose behalf it was granted. A grant stops counting when
    # the machine changes owner.
    owner_id: Mapped[uuid.UUID] = fk("owners.id")
    level: Mapped[str] = mapped_column(String(10))
    reason: Mapped[str] = mapped_column(String(300), default="")
    granted_by: Mapped[uuid.UUID] = fk("users.id", index=False)
    created_at: Mapped[datetime] = ts()
    expires_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    revoked_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)

    __table_args__ = (CheckConstraint(in_list("level", GRANT_LEVELS), name="grant_level"),)


class Release(Base):
    """A signed firmware release. The manifest is stored byte for byte: the
    signature covers exactly those bytes."""

    __tablename__ = "releases"

    id: Mapped[uuid.UUID] = pk()
    version: Mapped[str] = mapped_column(String(24), unique=True)
    # The version again, as numbers, to order releases correctly.
    v_major: Mapped[int] = mapped_column(Integer)
    v_minor: Mapped[int] = mapped_column(Integer)
    v_patch: Mapped[int] = mapped_column(Integer)
    manifest: Mapped[bytes] = mapped_column(LargeBinary)
    signature: Mapped[str] = mapped_column(String(128))
    key_id: Mapped[str] = mapped_column(String(16))
    filename: Mapped[str] = mapped_column(String(128))
    size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    min_upgrade_from: Mapped[str] = mapped_column(String(24), default="0.0.0")
    notes: Mapped[str] = mapped_column(String(4000), default="")
    status: Mapped[str] = mapped_column(String(20), default="awaiting_artifact")
    channels: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # The package itself. Loaded only when a device downloads it.
    artifact: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, deferred=True)
    created_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    created_at: Mapped[datetime] = ts()
    published_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    withdrawn_at: Mapped[datetime | None] = ts(nullable=True, default=False)

    __table_args__ = (
        CheckConstraint(in_list("status", RELEASE_STATUSES), name="release_status"),
        CheckConstraint(
            "(status = 'awaiting_artifact') = (artifact IS NULL)", name="release_artifact_present"
        ),
    )


# --------------------------------------------------------------------------
# Provider (Vast) mapping
# --------------------------------------------------------------------------

RENTAL_STATES = ("unknown", "idle", "active_contracts", "stopped_instances", "stored_data")


class ProviderAccount(Base):
    __tablename__ = "provider_accounts"

    id: Mapped[uuid.UUID] = pk()
    provider: Mapped[str] = mapped_column(String(20))
    label: Mapped[str] = mapped_column(String(120))
    external_account_id: Mapped[str] = mapped_column(String(120), default="")
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = ts()
    last_sync_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    last_sync_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_sync_error: Mapped[str] = mapped_column(String(500), default="")

    __table_args__ = (
        CheckConstraint(in_list("provider", ("vast", "fake")), name="provider_kind"),
        UniqueConstraint("provider", "label", name="uq_provider_label"),
    )


class ProviderMachine(Base):
    """A machine as the provider reports it. Bound to at most one of ours."""

    __tablename__ = "provider_machines"

    id: Mapped[uuid.UUID] = pk()
    provider_account_id: Mapped[uuid.UUID] = fk("provider_accounts.id")
    external_id: Mapped[str] = mapped_column(String(64))
    machine_id: Mapped[uuid.UUID | None] = fk("machines.id", nullable=True, unique=True)
    bound_from: Mapped[date | None] = mapped_column(Date, nullable=True)
    bound_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    bound_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    hostname: Mapped[str] = mapped_column(String(200), default="")
    gpu_name: Mapped[str] = mapped_column(String(200), default="")
    num_gpus: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    rental_state: Mapped[str] = mapped_column(String(24), default="unknown")
    listed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    state_detail: Mapped[str] = mapped_column(String(500), default="")
    state_observed_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    first_seen_at: Mapped[datetime] = ts()
    last_seen_at: Mapped[datetime] = ts()
    missing_since: Mapped[datetime | None] = ts(nullable=True, default=False)

    account: Mapped[ProviderAccount] = relationship()
    machine: Mapped[Machine | None] = relationship(back_populates="provider_machine")

    __table_args__ = (
        UniqueConstraint("provider_account_id", "external_id", name="uq_provider_machine"),
        CheckConstraint(in_list("rental_state", RENTAL_STATES), name="provider_rental_state"),
        CheckConstraint("(machine_id IS NULL) = (bound_from IS NULL)", name="provider_binding_complete"),
    )


class ProviderBindingEvent(Base):
    __tablename__ = "provider_binding_events"

    id: Mapped[uuid.UUID] = pk()
    provider_machine_id: Mapped[uuid.UUID] = fk("provider_machines.id")
    machine_id: Mapped[uuid.UUID] = fk("machines.id")
    action: Mapped[str] = mapped_column(String(10))
    effective_day: Mapped[date] = mapped_column(Date)
    by_user: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    at: Mapped[datetime] = ts()
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    __table_args__ = (CheckConstraint(in_list("action", ("bind", "unbind")), name="binding_action"),)


class SourceSnapshot(Base):
    """Raw provider responses and reconciliation evidence, kept for provenance.

    Bodies are redacted before storage (no API keys, no personal address
    fields). Reading them is restricted to admin and auditor roles.
    """

    __tablename__ = "source_snapshots"

    id: Mapped[uuid.UUID] = pk()
    provider_account_id: Mapped[uuid.UUID | None] = fk("provider_accounts.id", nullable=True)
    kind: Mapped[str] = mapped_column(String(40))
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    body: Mapped[bytes] = mapped_column(LargeBinary)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    fetched_at: Mapped[datetime] = ts()
    created_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)


class SyncRun(Base):
    __tablename__ = "sync_runs"

    id: Mapped[uuid.UUID] = pk()
    provider_account_id: Mapped[uuid.UUID] = fk("provider_accounts.id")
    kind: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20))
    started_at: Mapped[datetime] = ts()
    finished_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    error_code: Mapped[str] = mapped_column(String(60), default="")
    error: Mapped[str] = mapped_column(String(500), default="")
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    __table_args__ = (
        CheckConstraint(in_list("kind", ("health", "machines", "earnings")), name="sync_kind"),
        CheckConstraint(in_list("status", ("ok", "error", "blocked")), name="sync_status"),
        Index("ix_sync_runs_recent", "provider_account_id", "kind", "started_at"),
    )


# --------------------------------------------------------------------------
# Fees
# --------------------------------------------------------------------------


class FeeSchedule(Base):
    """A versioned management fee. ``owner_id`` NULL is the default schedule.

    Versions are never edited. A bucket snapshots the version that applied on
    its day when it is first posted, so later versions cannot rewrite history.
    """

    __tablename__ = "fee_schedules"

    id: Mapped[uuid.UUID] = pk()
    owner_id: Mapped[uuid.UUID | None] = fk("owners.id", nullable=True)
    rate: Mapped[Decimal] = mapped_column(Rate)
    effective_from: Mapped[date] = mapped_column(Date)
    note: Mapped[str] = mapped_column(String(500), default="")
    is_demo_assumption: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    created_at: Mapped[datetime] = ts()

    __table_args__ = (
        CheckConstraint("rate >= 0 AND rate < 1", name="fee_rate_range"),
        Index(
            "uq_fee_owner_effective",
            "owner_id",
            "effective_from",
            unique=True,
            postgresql_nulls_not_distinct=True,
        ),
    )


# --------------------------------------------------------------------------
# Ledger
# --------------------------------------------------------------------------

ACCOUNT_KINDS = (
    "provider_receivable",
    "cash_clearing",
    "receipts_unallocated",
    "unmapped_earnings",
    "owner_accrued",
    "owner_available",
    "owner_reserved",
    "owner_in_transit",
    "fee_accrued",
    "fee_earned",
)


class LedgerAccount(Base):
    __tablename__ = "ledger_accounts"

    id: Mapped[uuid.UUID] = pk()
    code: Mapped[str] = mapped_column(String(120), unique=True)
    kind: Mapped[str] = mapped_column(String(30))
    owner_id: Mapped[uuid.UUID | None] = fk("owners.id", nullable=True)
    provider_account_id: Mapped[uuid.UUID | None] = fk("provider_accounts.id", nullable=True)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    normal_side: Mapped[str] = mapped_column(String(6))
    allow_overdraft: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = ts()

    __table_args__ = (
        CheckConstraint(in_list("kind", ACCOUNT_KINDS), name="account_kind"),
        CheckConstraint(in_list("normal_side", ("debit", "credit")), name="account_side"),
    )


class LedgerBalance(Base):
    """Running balance per account (debit positive), maintained by a trigger.

    The journal is the source of truth; this table is a derived cache that
    also lets the database refuse overdrafts under concurrency. ``ledger
    verify`` recomputes it from the journal.
    """

    __tablename__ = "ledger_balances"

    account_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("ledger_accounts.id", ondelete="RESTRICT"), primary_key=True
    )
    balance: Mapped[Decimal] = mapped_column(Money8, default=Decimal("0"))
    updated_at: Mapped[datetime] = ts()


class JournalEntry(Base):
    __tablename__ = "journal_entries"

    id: Mapped[uuid.UUID] = pk()
    entry_type: Mapped[str] = mapped_column(String(40))
    idempotency_key: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    occurred_on: Mapped[date] = mapped_column(Date)
    posted_at: Mapped[datetime] = ts()
    created_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    reverses_entry_id: Mapped[uuid.UUID | None] = fk("journal_entries.id", nullable=True, unique=True)
    ref_type: Mapped[str] = mapped_column(String(40), default="")
    ref_id: Mapped[str] = mapped_column(String(64), default="")
    # Transaction that created the entry. A trigger refuses lines added to an
    # entry by any later transaction, so a committed entry can never grow.
    created_txid: Mapped[int] = mapped_column(BigInteger, server_default=text("txid_current()"))

    lines: Mapped[list[JournalLine]] = relationship(back_populates="entry")

    __table_args__ = (Index("ix_journal_ref", "ref_type", "ref_id"),)


class JournalLine(Base):
    __tablename__ = "journal_lines"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    entry_id: Mapped[uuid.UUID] = fk("journal_entries.id")
    account_id: Mapped[uuid.UUID] = fk("ledger_accounts.id")
    # Signed amount: positive is a debit, negative is a credit.
    amount: Mapped[Decimal] = mapped_column(Money8)
    currency: Mapped[str] = mapped_column(String(3), default="USD")

    entry: Mapped[JournalEntry] = relationship(back_populates="lines")
    account: Mapped[LedgerAccount] = relationship()

    __table_args__ = (CheckConstraint("amount <> 0", name="journal_line_nonzero"),)


# --------------------------------------------------------------------------
# Earnings
# --------------------------------------------------------------------------


class EarningsImport(Base):
    __tablename__ = "earnings_imports"

    id: Mapped[uuid.UUID] = pk()
    provider_account_id: Mapped[uuid.UUID] = fk("provider_accounts.id")
    period_start: Mapped[date] = mapped_column(Date)
    period_end: Mapped[date] = mapped_column(Date)
    content_sha256: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(20))
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    created_at: Mapped[datetime] = ts()

    __table_args__ = (
        CheckConstraint(
            in_list("status", ("posted", "duplicate", "exception", "held_unverified")),
            name="earnings_import_status",
        ),
    )


class EarningBucket(Base):
    """One provider machine, one UTC day. The canonical accounting unit."""

    __tablename__ = "earning_buckets"

    id: Mapped[uuid.UUID] = pk()
    provider_account_id: Mapped[uuid.UUID] = fk("provider_accounts.id")
    external_machine_id: Mapped[str] = mapped_column(String(64))
    day: Mapped[date] = mapped_column(Date)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    status: Mapped[str] = mapped_column(String(12))
    machine_id: Mapped[uuid.UUID | None] = fk("machines.id", nullable=True)
    owner_id: Mapped[uuid.UUID | None] = fk("owners.id", nullable=True)
    fee_schedule_id: Mapped[uuid.UUID | None] = fk("fee_schedules.id", nullable=True, index=False)
    fee_rate: Mapped[Decimal | None] = mapped_column(Rate, nullable=True)
    reported_amount: Mapped[Decimal] = mapped_column(Money8, default=Decimal("0"))
    received_amount: Mapped[Decimal] = mapped_column(Money8, default=Decimal("0"))
    owner_accrued: Mapped[Decimal] = mapped_column(Money8, default=Decimal("0"))
    fee_accrued: Mapped[Decimal] = mapped_column(Money8, default=Decimal("0"))
    owner_released: Mapped[Decimal] = mapped_column(Money8, default=Decimal("0"))
    fee_released: Mapped[Decimal] = mapped_column(Money8, default=Decimal("0"))
    revision_count: Mapped[int] = mapped_column(Integer, default=0)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts()

    __table_args__ = (
        UniqueConstraint("provider_account_id", "external_machine_id", "day", name="uq_earning_bucket"),
        CheckConstraint(in_list("status", ("mapped", "unmapped")), name="bucket_status"),
        CheckConstraint(
            "(status = 'mapped') = (owner_id IS NOT NULL AND machine_id IS NOT NULL "
            "AND fee_schedule_id IS NOT NULL AND fee_rate IS NOT NULL)",
            name="bucket_mapping_complete",
        ),
        Index("ix_bucket_owner_day", "owner_id", "day"),
    )


class EarningRevision(Base):
    """What the provider reported for a bucket at one import."""

    __tablename__ = "earning_revisions"

    id: Mapped[uuid.UUID] = pk()
    bucket_id: Mapped[uuid.UUID] = fk("earning_buckets.id")
    import_id: Mapped[uuid.UUID] = fk("earnings_imports.id")
    revision_no: Mapped[int] = mapped_column(Integer)
    reported_amount: Mapped[Decimal] = mapped_column(Money8)
    delta: Mapped[Decimal] = mapped_column(Money8)
    components: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    journal_entry_id: Mapped[uuid.UUID | None] = fk("journal_entries.id", nullable=True, index=False)
    created_at: Mapped[datetime] = ts()

    __table_args__ = (UniqueConstraint("bucket_id", "revision_no", name="uq_bucket_revision"),)


EVIDENCE_SOURCES = ("bank_statement", "payout_provider_statement")


class ProviderReceipt(Base):
    """Cash actually received from the provider, entered with evidence.

    ``evidence_source`` records where the operator saw the money arrive. Only
    HappyMining's own bank or payout-provider statement counts. The provider's
    invoice page saying "Paid" is not an accepted source: it means the payout
    was submitted, not that it arrived.
    """

    __tablename__ = "provider_receipts"

    id: Mapped[uuid.UUID] = pk()
    provider_account_id: Mapped[uuid.UUID] = fk("provider_accounts.id")
    reference: Mapped[str] = mapped_column(String(120))
    received_on: Mapped[date] = mapped_column(Date)
    amount: Mapped[Decimal] = mapped_column(Money8)
    allocated_amount: Mapped[Decimal] = mapped_column(Money8, default=Decimal("0"))
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    evidence_source: Mapped[str] = mapped_column(String(30))
    evidence_note: Mapped[str] = mapped_column(String(1000), default="")
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    journal_entry_id: Mapped[uuid.UUID | None] = fk("journal_entries.id", nullable=True, index=False)
    created_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    created_at: Mapped[datetime] = ts()
    voided_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    voided_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    void_reason: Mapped[str] = mapped_column(String(500), default="")

    __table_args__ = (
        # One live receipt per bank reference; a voided one frees the reference.
        Index(
            "uq_receipt_reference",
            "provider_account_id",
            "reference",
            unique=True,
            postgresql_where=text("voided_at IS NULL"),
        ),
        CheckConstraint("amount > 0", name="receipt_positive"),
        CheckConstraint(
            "allocated_amount >= 0 AND allocated_amount <= amount", name="receipt_allocation_bound"
        ),
        CheckConstraint(in_list("evidence_source", EVIDENCE_SOURCES), name="receipt_evidence_source"),
        CheckConstraint("voided_at IS NULL OR allocated_amount = 0", name="receipt_void_unallocated"),
    )


class ReceiptAllocation(Base):
    __tablename__ = "receipt_allocations"

    id: Mapped[uuid.UUID] = pk()
    receipt_id: Mapped[uuid.UUID] = fk("provider_receipts.id")
    bucket_id: Mapped[uuid.UUID] = fk("earning_buckets.id")
    amount: Mapped[Decimal] = mapped_column(Money8)
    owner_released: Mapped[Decimal] = mapped_column(Money8)
    fee_released: Mapped[Decimal] = mapped_column(Money8)
    journal_entry_id: Mapped[uuid.UUID] = fk("journal_entries.id", index=False)
    # Client-supplied idempotency key of the request that created this row.
    request_key: Mapped[str] = mapped_column(String(120), default="")
    created_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    created_at: Mapped[datetime] = ts()

    __table_args__ = (
        CheckConstraint("amount <> 0", name="allocation_nonzero"),
        Index(
            "uq_allocation_request",
            "receipt_id",
            "bucket_id",
            "request_key",
            unique=True,
            postgresql_where=text("request_key <> ''"),
        ),
    )


# --------------------------------------------------------------------------
# Payouts
# --------------------------------------------------------------------------


class OwnerBeneficiary(Base):
    """Encrypted payout details for an owner (Fernet, key outside the DB)."""

    __tablename__ = "owner_beneficiaries"

    owner_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("owners.id", ondelete="RESTRICT"), primary_key=True
    )
    details_enc: Mapped[str] = mapped_column(Text)
    masked_hint: Mapped[str] = mapped_column(String(80), default="")
    updated_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    updated_at: Mapped[datetime] = ts()


BATCH_STATUSES = ("draft", "approved", "submitted", "closed", "cancelled")
ITEM_STATUSES = (
    "draft",
    "reserved",
    "submitted",
    "uncertain",
    "confirmed_paid",
    "failed",
    "reversed",
    "cancelled",
)


class PayoutBatch(Base):
    __tablename__ = "payout_batches"

    id: Mapped[uuid.UUID] = pk()
    status: Mapped[str] = mapped_column(String(12), default="draft")
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    idempotency_key: Mapped[str] = mapped_column(String(120), unique=True)
    note: Mapped[str] = mapped_column(String(500), default="")
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    created_at: Mapped[datetime] = ts()
    approved_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    approved_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    submitted_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    export_sha256: Mapped[str] = mapped_column(String(64), default="")
    export_count: Mapped[int] = mapped_column(Integer, default=0)

    items: Mapped[list[PayoutItem]] = relationship(back_populates="batch", order_by="PayoutItem.created_at")

    __table_args__ = (CheckConstraint(in_list("status", BATCH_STATUSES), name="batch_status"),)


class PayoutItem(Base):
    __tablename__ = "payout_items"

    id: Mapped[uuid.UUID] = pk()
    batch_id: Mapped[uuid.UUID] = fk("payout_batches.id")
    owner_id: Mapped[uuid.UUID] = fk("owners.id")
    amount: Mapped[Decimal] = mapped_column(Money2)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    status: Mapped[str] = mapped_column(String(16), default="draft")
    beneficiary_snapshot_enc: Mapped[str] = mapped_column(Text, default="")
    external_reference: Mapped[str] = mapped_column(String(120), default="")
    failure_reason: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts()

    batch: Mapped[PayoutBatch] = relationship(back_populates="items")
    owner: Mapped[Owner] = relationship()

    __table_args__ = (
        UniqueConstraint("batch_id", "owner_id", name="uq_payout_item_owner"),
        CheckConstraint("amount > 0", name="payout_item_positive"),
        CheckConstraint(in_list("status", ITEM_STATUSES), name="payout_item_status"),
    )


class PayoutEvidence(Base):
    __tablename__ = "payout_evidence"

    id: Mapped[uuid.UUID] = pk()
    item_id: Mapped[uuid.UUID] = fk("payout_items.id")
    kind: Mapped[str] = mapped_column(String(24))
    reference: Mapped[str] = mapped_column(String(200))
    note: Mapped[str] = mapped_column(String(1000), default="")
    recorded_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    recorded_at: Mapped[datetime] = ts()

    __table_args__ = (
        CheckConstraint(
            in_list(
                "kind",
                ("submission", "bank_confirmation", "bank_rejection", "bank_return", "uncertain_outcome"),
            ),
            name="payout_evidence_kind",
        ),
        # One bank transaction confirms one payout item.
        Index(
            "uq_bank_confirmation_reference",
            "reference",
            unique=True,
            postgresql_where=text("kind = 'bank_confirmation'"),
        ),
    )


# --------------------------------------------------------------------------
# Exceptions, audit, rate limits
# --------------------------------------------------------------------------

EXCEPTION_KINDS = (
    "unmapped_machine",
    "total_mismatch",
    "unknown_currency",
    "unexplained_adjustment",
    "no_fee_schedule",
    "unverified_semantics",
    "receipt_remainder",
    "over_received",
    "malformed_report",
    "missing_from_report",
)


class ExceptionItem(Base):
    """Something a human must look at before money can move."""

    __tablename__ = "exception_items"

    id: Mapped[uuid.UUID] = pk()
    kind: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(10), default="open")
    dedupe_key: Mapped[str | None] = mapped_column(String(200), unique=True, nullable=True)
    summary: Mapped[str] = mapped_column(String(500))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    provider_account_id: Mapped[uuid.UUID | None] = fk("provider_accounts.id", nullable=True)
    owner_id: Mapped[uuid.UUID | None] = fk("owners.id", nullable=True)
    created_at: Mapped[datetime] = ts()
    resolved_by: Mapped[uuid.UUID | None] = fk("users.id", nullable=True, index=False)
    resolved_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    resolution: Mapped[str] = mapped_column(String(1000), default="")

    __table_args__ = (
        CheckConstraint(in_list("kind", EXCEPTION_KINDS), name="exception_kind"),
        CheckConstraint(in_list("status", ("open", "resolved")), name="exception_status"),
    )


class AuditLog(Base):
    """Append-only, hash-chained application audit trail.

    Tamper-evident, not tamper-proof: a database administrator can still
    rewrite the whole chain. See docs/operations.md.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = ts()
    actor_type: Mapped[str] = mapped_column(String(10))
    actor_id: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(80), index=True)
    object_type: Mapped[str] = mapped_column(String(40), default="")
    object_id: Mapped[str] = mapped_column(String(64), default="")
    owner_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True, index=True)
    ip: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64))

    __table_args__ = (
        CheckConstraint(in_list("actor_type", ("user", "device", "system", "client")), name="audit_actor"),
    )


class RateLimitCounter(Base):
    __tablename__ = "rate_limit_counters"

    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)


class SystemInfo(Base):
    """Facts about this database itself, such as which mode it belongs to."""

    __tablename__ = "system_info"

    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    value: Mapped[str] = mapped_column(String(200))
    updated_at: Mapped[datetime] = ts()
