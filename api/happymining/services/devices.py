"""Device credentials and telemetry ingestion."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..config import Settings
from ..db import lock_row
from ..errors import DeviceUnauthorized, InvalidRequest, NotFound
from ..models import Device, DeviceCredential, Machine, Operation, TelemetrySample, utcnow
from ..security import constant_time_equal, device_secret_hash, parse_device_token
from .pairing import issue_credential

MAX_SEQ = 2**63 - 1
FUTURE_TOLERANCE = timedelta(minutes=10)
MAX_AGE = timedelta(days=7)


@dataclass(frozen=True)
class DevicePrincipal:
    device: Device
    credential: DeviceCredential
    machine: Machine


def authenticate_device(db: Session, settings: Settings, token: str) -> DevicePrincipal:
    """Resolve a bearer token to a device. Every failure is the same error."""
    parsed = parse_device_token(token)
    if parsed is None:
        raise DeviceUnauthorized()
    credential_id, secret = parsed
    credential = db.get(DeviceCredential, credential_id)
    presented = device_secret_hash(settings, secret)
    # Compare even when the credential is unknown, to keep timing flat.
    if (
        not constant_time_equal(credential.secret_hash if credential else "0" * 64, presented)
        or credential is None
    ):
        raise DeviceUnauthorized()
    now = utcnow()
    if credential.status == "revoked":
        raise DeviceUnauthorized()
    if credential.status == "superseded":
        grace = timedelta(hours=settings.credential_rotation_grace_hours)
        if credential.superseded_at is None or now - credential.superseded_at > grace:
            raise DeviceUnauthorized()
    device = db.get(Device, credential.device_id)
    if device is None or device.status != "active":
        raise DeviceUnauthorized()
    machine = db.get(Machine, device.machine_id)
    if machine is None or machine.status == "retired":
        raise DeviceUnauthorized()

    if credential.first_used_at is None:
        credential.first_used_at = now
        if credential.status == "active":
            # First use of a rotated credential ends the grace period of older ones.
            db.execute(
                update(DeviceCredential)
                .where(
                    DeviceCredential.device_id == device.id,
                    DeviceCredential.status == "superseded",
                    DeviceCredential.id != credential.id,
                )
                .values(status="revoked", revoked_at=now)
            )
    credential.last_used_at = now
    return DevicePrincipal(device=device, credential=credential, machine=machine)


def rotate_credential(
    db: Session, settings: Settings, principal: DevicePrincipal, ip: str
) -> tuple[DeviceCredential, str]:
    """Issue a new credential. The presented one stays valid for a grace period."""
    if principal.credential.status != "active":
        raise DeviceUnauthorized()
    now = utcnow()
    db.execute(
        update(DeviceCredential)
        .where(DeviceCredential.device_id == principal.device.id, DeviceCredential.status == "active")
        .values(status="superseded", superseded_at=now)
    )
    credential, token = issue_credential(db, settings, principal.device)
    audit(
        db,
        Actor("device", str(principal.device.id), ip),
        "device.credential_rotate",
        object_type="device",
        object_id=principal.device.id,
        owner_id=principal.machine.owner_id,
        details={"new_credential_id": str(credential.id)},
    )
    return credential, token


def revoke_device(db: Session, actor: Actor, device_id: uuid.UUID, reason: str) -> Device:
    device = lock_row(db, Device, device_id)
    if not device:
        raise NotFound()
    now = utcnow()
    device.status = "revoked"
    device.revoked_at = now
    db.execute(
        update(DeviceCredential)
        .where(DeviceCredential.device_id == device.id, DeviceCredential.status != "revoked")
        .values(status="revoked", revoked_at=now)
    )
    # Whatever was queued for the revoked device must not reach whoever pairs next.
    cancelled = (
        db.execute(
            update(Operation)
            .where(
                Operation.device_id == device.id, Operation.status.in_(("pending", "delivered", "accepted"))
            )
            .values(status="cancelled", completed_at=now, detail="device revoked before completion")
        ).rowcount
        or 0
    )
    machine = db.get(Machine, device.machine_id)
    assert machine is not None
    audit(
        db,
        actor,
        "device.revoke",
        object_type="device",
        object_id=device.id,
        owner_id=machine.owner_id,
        details={"reason": reason[:200], "operations_cancelled": cancelled},
    )
    db.flush()
    return device


# --- telemetry -------------------------------------------------------------


def _num(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return Decimal(str(value))
    except Exception:
        return None


def summarise_gpus(gpus: list[dict[str, Any]]) -> dict[str, Any]:
    utils = [u for u in (_num(g.get("util_pct")) for g in gpus) if u is not None]
    powers = [p for p in (_num(g.get("power_w")) for g in gpus) if p is not None]
    temps = [t for t in (_num(g.get("temp_c")) for g in gpus) if t is not None]
    return {
        "gpu_count": len(gpus),
        "gpu_util_avg": (sum(utils) / len(utils)).quantize(Decimal("0.01")) if utils else None,
        "gpu_power_w": sum(powers).quantize(Decimal("0.01")) if powers else None,
        "gpu_temp_max": max(temps).quantize(Decimal("0.01")) if temps else None,
    }


@dataclass
class IngestResult:
    accepted: int = 0
    duplicates: int = 0
    rejected: int = 0
    highest_seq: int = 0


def ingest_samples(
    db: Session,
    settings: Settings,
    principal: DevicePrincipal,
    *,
    samples: list[dict[str, Any]],
    boot_id: str,
    agent_version: str,
    now: datetime | None = None,
) -> IngestResult:
    """Store a batch of samples. Idempotent on (device, seq).

    A device can only write telemetry for the machine it is paired to; the
    machine comes from the credential, never from the payload.
    """
    now = now or utcnow()
    device, machine = principal.device, principal.machine
    result = IngestResult(highest_seq=device.last_seq)
    rows = []
    for sample in samples:
        seq = sample["seq"]
        collected_at: datetime = sample["collected_at"]
        if seq > MAX_SEQ or collected_at - now > FUTURE_TOLERANCE or now - collected_at > MAX_AGE:
            result.rejected += 1
            continue
        synthetic = bool(sample.get("synthetic", False))
        if synthetic and settings.is_live:
            # Synthetic data never enters a LIVE system.
            raise InvalidRequest("synthetic telemetry is refused in LIVE mode")
        if not synthetic and machine.is_synthetic:
            raise InvalidRequest("this machine record is synthetic; it only accepts simulator telemetry")
        payload = {k: v for k, v in sample.items() if k not in ("seq", "collected_at")}
        payload = _jsonable(payload)
        rows.append(
            {
                "device_id": device.id,
                "machine_id": machine.id,
                "seq": seq,
                "boot_id": boot_id[:64],
                "collected_at": collected_at,
                "received_at": now,
                "synthetic": synthetic,
                "payload": payload,
                **summarise_gpus(sample.get("gpus") or []),
            }
        )
    if rows:
        inserted = (
            db.execute(
                pg_insert(TelemetrySample)
                .values(rows)
                .on_conflict_do_nothing(constraint="uq_telemetry_device_seq")
                .returning(TelemetrySample.seq)
            )
            .scalars()
            .all()
        )
        result.accepted = len(inserted)
        result.duplicates = len(rows) - len(inserted)
        result.highest_seq = max([device.last_seq, *[r["seq"] for r in rows]])

    device.last_seen_at = now
    device.last_seq = result.highest_seq
    device.boot_id = boot_id[:64]
    device.agent_version = agent_version[:40]
    if rows:
        latest = max(rows, key=lambda r: r["seq"])
        hardware = _hardware_summary(latest["payload"])
        if hardware != machine.hardware:
            machine.hardware = hardware
    db.flush()
    return result


def _hardware_summary(payload: dict[str, Any]) -> dict[str, Any]:
    gpus = payload.get("gpus") or []
    cpu = payload.get("cpu") or {}
    memory = payload.get("memory") or {}
    return {
        "gpus": [
            {
                "index": g.get("index"),
                "name": g.get("name"),
                "vram_total_mib": g.get("vram_total_mib"),
                "driver_version": g.get("driver_version"),
            }
            for g in gpus
        ],
        "cpu_model": cpu.get("model"),
        "cpu_cores": cpu.get("cores"),
        "memory_total_bytes": memory.get("total_bytes"),
        "vast_daemon_installed": (payload.get("vast") or {}).get("daemon_installed"),
        "vast_machine_id_hint": (payload.get("vast") or {}).get("machine_id_hint"),
    }


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if isinstance(value, Decimal):
        return float(value)  # telemetry only; money never passes through here
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def device_state(settings: Settings, device: Device | None, now: datetime | None = None) -> str:
    """Human-facing connection state: unpaired, revoked, online, stale."""
    if device is None:
        return "unpaired"
    if device.status != "active":
        return "revoked"
    if device.last_seen_at is None:
        return "paired_never_seen"
    now = now or utcnow()
    age = (now - device.last_seen_at).total_seconds()
    return "online" if age <= settings.device_stale_after_s else "stale"


def purge_old_telemetry(db: Session, settings: Settings, batch: int = 20000) -> int:
    """Delete telemetry older than the retention period, a bounded batch at a time."""
    cutoff = utcnow() - timedelta(days=settings.telemetry_retention_days)
    victims = (
        select(TelemetrySample.id).where(TelemetrySample.collected_at < cutoff).limit(batch).scalar_subquery()
    )
    return db.execute(delete(TelemetrySample).where(TelemetrySample.id.in_(victims))).rowcount or 0
