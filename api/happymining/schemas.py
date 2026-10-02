"""Request bodies. Unknown fields are rejected everywhere."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

Str128 = Annotated[str, StringConstraints(max_length=128)]
ShortStr = Annotated[str, StringConstraints(max_length=200)]
NoteStr = Annotated[str, StringConstraints(max_length=1000)]
# Money travels as a decimal string. JSON numbers are refused so that no
# binary floating point value can reach the ledger.
MoneyStr = Annotated[str, StringConstraints(pattern=r"^-?\d{1,12}(\.\d{1,8})?$")]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# --- auth ------------------------------------------------------------------


class LoginIn(Strict):
    email: ShortStr
    password: Annotated[str, StringConstraints(max_length=1024)]
    totp_code: Annotated[str, StringConstraints(max_length=12)] | None = None


class DemoLoginIn(Strict):
    email: ShortStr


class MfaActivateIn(Strict):
    code: Annotated[str, StringConstraints(max_length=12)]


# --- admin -----------------------------------------------------------------


class OwnerIn(Strict):
    display_name: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    legal_name: ShortStr = ""
    contact_email: ShortStr = ""


class UserIn(Strict):
    email: ShortStr
    role: Literal["admin", "owner", "auditor"]
    display_name: ShortStr = ""
    password: Annotated[str, StringConstraints(min_length=12, max_length=1024)]
    owner_id: uuid.UUID | None = None


class EnrollmentIn(Strict):
    owner_id: uuid.UUID
    machine_label: ShortStr = ""
    machine_id: uuid.UUID | None = None
    owned_since: date | None = None


class RevokeIn(Strict):
    reason: Annotated[str, StringConstraints(min_length=1, max_length=200)]


class TransferIn(Strict):
    new_owner_id: uuid.UUID
    reason: Annotated[str, StringConstraints(min_length=1, max_length=500)]


class OperationIn(Strict):
    type: Annotated[str, StringConstraints(max_length=40)]
    params: dict[str, Any] = Field(default_factory=dict)


class BindIn(Strict):
    machine_id: uuid.UUID
    bound_from: date


class ImportEarningsIn(Strict):
    start: date
    end: date


class FeeScheduleIn(Strict):
    owner_id: uuid.UUID | None = None
    rate: Annotated[str, StringConstraints(pattern=r"^0(\.\d{1,8})?$")]
    effective_from: date
    note: Annotated[str, StringConstraints(max_length=500)] = ""


class ReceiptIn(Strict):
    provider_account_id: uuid.UUID
    reference: Annotated[str, StringConstraints(min_length=1, max_length=120)]
    received_on: date
    amount: MoneyStr
    currency: Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]
    # Where the money was seen arriving. A provider invoice marked "Paid" is
    # not an accepted source.
    evidence_source: Literal["bank_statement", "payout_provider_statement"]
    evidence_note: Annotated[str, StringConstraints(min_length=1, max_length=1000)]


class AllocationIn(Strict):
    bucket_id: uuid.UUID
    amount: MoneyStr


class AllocateIn(Strict):
    allocations: Annotated[list[AllocationIn], Field(min_length=1, max_length=500)]


class AllocatePeriodIn(Strict):
    start: date
    end: date


class BeneficiaryIn(Strict):
    account_holder: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    iban: Annotated[str, StringConstraints(min_length=15, max_length=42)]
    bic: ShortStr = ""
    bank_name: ShortStr = ""
    country: ShortStr = ""


class BatchIn(Strict):
    owner_ids: Annotated[list[uuid.UUID], Field(max_length=500)] | None = None
    note: Annotated[str, StringConstraints(max_length=500)] = ""


class EvidenceIn(Strict):
    reference: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    note: NoteStr = ""


class UncertainIn(Strict):
    note: Annotated[str, StringConstraints(min_length=1, max_length=1000)]


class ConfirmationRow(Strict):
    item_id: uuid.UUID
    outcome: Literal["paid", "failed"]
    reference: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    note: NoteStr = ""


class ConfirmationsIn(Strict):
    rows: Annotated[list[ConfirmationRow], Field(min_length=1, max_length=1000)]


class VoidIn(Strict):
    reason: Annotated[str, StringConstraints(min_length=1, max_length=500)]


class ResolveIn(Strict):
    resolution: Annotated[str, StringConstraints(min_length=1, max_length=1000)]


# --- device protocol (docs/agent-protocol.md) ------------------------------

Pct = Annotated[float, Field(ge=0, le=1000)]


class Lenient(BaseModel):
    """Device payload sections: bounded, but tolerant of fields added by newer agents."""

    model_config = ConfigDict(extra="ignore")


class OsInfo(Lenient):
    id: Str128 = ""
    version_id: Str128 = ""
    kernel: Str128 = ""
    arch: Str128 = ""


class EnrollIn(Strict):
    pairing_code: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    hostname: Str128 = ""
    machine_fingerprint: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    agent_version: Annotated[str, StringConstraints(max_length=40)] = ""
    os: OsInfo = Field(default_factory=OsInfo)


class CpuInfo(Lenient):
    model: Str128 | None = None
    cores: Annotated[int, Field(ge=0, le=4096)] | None = None
    load1: Annotated[float, Field(ge=0, le=100000)] | None = None
    util_pct: Pct | None = None


class MemoryInfo(Lenient):
    total_bytes: Annotated[int, Field(ge=0, le=2**60)] | None = None
    available_bytes: Annotated[int, Field(ge=0, le=2**60)] | None = None


class DiskInfo(Lenient):
    mount: Str128 = ""
    fs: Str128 = ""
    total_bytes: Annotated[int, Field(ge=0, le=2**62)] | None = None
    avail_bytes: Annotated[int, Field(ge=0, le=2**62)] | None = None


class GpuInfo(Lenient):
    index: Annotated[int, Field(ge=0, le=255)] | None = None
    uuid: Str128 | None = None
    name: Str128 | None = None
    driver_version: Str128 | None = None
    vram_total_mib: Annotated[int, Field(ge=0, le=10_000_000)] | None = None
    vram_used_mib: Annotated[int, Field(ge=0, le=10_000_000)] | None = None
    util_pct: Pct | None = None
    power_w: Annotated[float, Field(ge=0, le=100000)] | None = None
    temp_c: Annotated[float, Field(ge=-100, le=1000)] | None = None
    fan_pct: Pct | None = None


class VastInfo(Lenient):
    daemon_installed: bool | None = None
    machine_id_hint: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")] | None = None


ServiceState = Literal["active", "inactive", "failed", "activating", "not-installed", "unknown"]


class Sample(Lenient):
    seq: Annotated[int, Field(ge=0, le=2**64 - 1)]
    collected_at: datetime
    uptime_s: Annotated[int, Field(ge=0, le=2**40)] | None = None
    synthetic: bool = False
    cpu: CpuInfo = Field(default_factory=CpuInfo)
    memory: MemoryInfo = Field(default_factory=MemoryInfo)
    disks: Annotated[list[DiskInfo], Field(max_length=16)] = Field(default_factory=list)
    gpus: Annotated[list[GpuInfo], Field(max_length=32)] = Field(default_factory=list)
    services: dict[Str128, ServiceState] = Field(default_factory=dict)
    vast: VastInfo = Field(default_factory=VastInfo)

    @field_validator("collected_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("collected_at must carry a UTC offset")
        return value

    @field_validator("services")
    @classmethod
    def _bounded(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 16:
            raise ValueError("at most 16 services")
        return value


class HeartbeatIn(Lenient):
    sent_at: datetime
    boot_id: Annotated[str, StringConstraints(max_length=64)] = ""
    agent_version: Annotated[str, StringConstraints(max_length=40)] = ""
    samples: Annotated[list[Sample], Field(min_length=1, max_length=100)]


class AckIn(Strict):
    status: Literal["accepted", "rejected", "succeeded", "failed"]
    nonce: Annotated[str, StringConstraints(max_length=64)]
    detail: Annotated[str, StringConstraints(max_length=2000)] = ""
    result: dict[str, Any] = Field(default_factory=dict)
    completed_at: datetime | None = None
