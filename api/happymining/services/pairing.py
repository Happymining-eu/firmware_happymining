"""Pairing codes and device enrollment.

- A code is created by an admin for one owner and one machine record. The
  device never chooses either.
- Only an HMAC of the code's secret part is stored.
- Single use, short lived, locked after a few wrong attempts.
- Every failure looks the same to the caller.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..config import Settings
from ..db import lock_row
from ..errors import Conflict, InvalidRequest, NotFound, PairingFailed
from ..models import (
    Device,
    DeviceCredential,
    EnrollmentRequest,
    Machine,
    MachineOwnership,
    Owner,
    utcnow,
)
from ..security import (
    constant_time_equal,
    device_secret_hash,
    format_device_token,
    new_device_secret,
    new_pairing_code,
    pairing_secret_hash,
    parse_pairing_code,
)


@dataclass(frozen=True)
class IssuedPairing:
    request: EnrollmentRequest
    machine: Machine
    code: str  # shown once, never stored


def create_enrollment(
    db: Session,
    settings: Settings,
    actor: Actor,
    *,
    owner_id: uuid.UUID,
    machine_label: str,
    created_by: uuid.UUID,
    machine_id: uuid.UUID | None = None,
    owned_since: date | None = None,
    is_synthetic: bool = False,
) -> IssuedPairing:
    """Issue a pairing code, registering the machine record if it is new.

    ``owned_since`` is the first UTC day this owner is on record for the
    machine (default: today). An admin sets an earlier day when onboarding a
    machine that was already earning for the same owner; earnings for days
    before it are never attributed to them.
    """
    today = datetime.now(UTC).date()
    if owned_since is not None and owned_since > today:
        raise InvalidRequest("owned_since cannot be in the future")
    owner = db.get(Owner, owner_id)
    if not owner or owner.status != "active":
        raise NotFound("owner not found")
    if machine_id:
        machine = lock_row(db, Machine, machine_id)
        if not machine or machine.owner_id != owner_id:
            raise NotFound("machine not found for this owner")
        if machine.device and machine.device.status == "active":
            raise Conflict("this machine already has an active device; revoke it first")
    else:
        label = machine_label.strip()
        if not label:
            raise InvalidRequest("machine_label is required")
        machine = Machine(
            owner_id=owner_id, label=label[:120], is_synthetic=is_synthetic or owner.is_synthetic
        )
        db.add(machine)
        db.flush()
        db.add(
            MachineOwnership(
                machine_id=machine.id,
                owner_id=owner_id,
                valid_from=owned_since or today,
                changed_by=created_by,
                reason="machine registered",
            )
        )

    # One live code per machine: issuing a new one cancels the old one.
    for old in db.execute(
        select(EnrollmentRequest).where(
            EnrollmentRequest.machine_id == machine.id, EnrollmentRequest.status == "pending"
        )
    ).scalars():
        old.status = "cancelled"

    for _ in range(5):
        code = new_pairing_code()
        request = EnrollmentRequest(
            owner_id=owner_id,
            machine_id=machine.id,
            locator=code.locator,
            code_hash=pairing_secret_hash(settings, code.locator, code.secret),
            max_attempts=settings.pairing_max_attempts,
            expires_at=utcnow() + timedelta(minutes=settings.pairing_code_ttl_minutes),
            created_by=created_by,
        )
        try:
            with db.begin_nested():
                db.add(request)
                db.flush()
            break
        except IntegrityError:
            continue  # locator collision; draw again
    else:  # pragma: no cover - five collisions in a row
        raise Conflict("could not allocate a pairing code; try again")

    audit(
        db,
        actor,
        "enrollment.create",
        object_type="enrollment_request",
        object_id=request.id,
        owner_id=owner_id,
        details={"machine_id": str(machine.id), "expires_at": request.expires_at.isoformat()},
    )
    return IssuedPairing(request=request, machine=machine, code=code.display)


def cancel_enrollment(db: Session, actor: Actor, request_id: uuid.UUID) -> EnrollmentRequest:
    request = lock_row(db, EnrollmentRequest, request_id)
    if not request:
        raise NotFound()
    if request.status != "pending":
        raise Conflict(f"enrollment request is {request.status}")
    request.status = "cancelled"
    audit(
        db,
        actor,
        "enrollment.cancel",
        object_type="enrollment_request",
        object_id=request.id,
        owner_id=request.owner_id,
    )
    db.flush()
    return request


@dataclass(frozen=True)
class EnrollResult:
    device: Device
    credential: DeviceCredential
    token: str


def issue_credential(db: Session, settings: Settings, device: Device) -> tuple[DeviceCredential, str]:
    secret = new_device_secret()
    credential = DeviceCredential(
        id=uuid.uuid4(), device_id=device.id, secret_hash=device_secret_hash(settings, secret)
    )
    db.add(credential)
    db.flush()
    return credential, format_device_token(credential.id, secret)


def enroll_device(
    db: Session,
    settings: Settings,
    *,
    pairing_code: str,
    hostname: str,
    fingerprint: str,
    agent_version: str,
    os_info: dict[str, Any],
    ip: str,
) -> EnrollResult:
    """Consume a pairing code. Raises the same ``PairingFailed`` for every failure.

    A failed attempt has to be recorded even though the request fails, so the
    caller commits after catching ``PairingFailed``; see the router.
    """
    parsed = parse_pairing_code(pairing_code)
    if parsed is None:
        raise PairingFailed()
    request = db.execute(
        select(EnrollmentRequest)
        .where(EnrollmentRequest.locator == parsed.locator)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if request is None:
        raise PairingFailed()

    actor = Actor("device", "", ip)
    now = utcnow()
    if request.status == "pending" and request.expires_at <= now:
        request.status = "expired"
    if request.status != "pending":
        audit(
            db,
            actor,
            "enrollment.rejected",
            object_type="enrollment_request",
            object_id=request.id,
            owner_id=request.owner_id,
            details={"reason": request.status},
        )
        raise PairingFailed()

    expected = request.code_hash
    presented = pairing_secret_hash(settings, parsed.locator, parsed.secret)
    if not constant_time_equal(expected, presented):
        request.failed_attempts += 1
        if request.failed_attempts >= request.max_attempts:
            request.status = "locked"
        audit(
            db,
            actor,
            "enrollment.rejected",
            object_type="enrollment_request",
            object_id=request.id,
            owner_id=request.owner_id,
            details={
                "reason": "wrong_code",
                "failed_attempts": request.failed_attempts,
                "status": request.status,
            },
        )
        raise PairingFailed()

    machine = lock_row(db, Machine, request.machine_id)
    assert machine is not None
    existing = db.execute(
        select(Device)
        .where(Device.machine_id == machine.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if existing and existing.status == "active":
        # The machine was paired through another path in the meantime.
        request.status = "cancelled"
        raise PairingFailed()

    if existing:
        # Re-pairing a machine whose device was revoked: reuse the row, new identity.
        device = existing
        device.status = "active"
        device.revoked_at = None
        device.last_seq = 0
    else:
        device = Device(machine_id=machine.id)
        db.add(device)
    device.hostname = hostname[:128]
    device.fingerprint = fingerprint[:80]
    device.agent_version = agent_version[:40]
    device.os_info = os_info
    db.flush()

    credential, token = issue_credential(db, settings, device)
    request.status = "consumed"
    request.consumed_at = now
    request.device_id = device.id
    machine.status = "active"
    db.flush()
    audit(
        db,
        Actor("device", str(device.id), ip),
        "enrollment.consumed",
        object_type="device",
        object_id=device.id,
        owner_id=request.owner_id,
        details={
            "machine_id": str(machine.id),
            "hostname": hostname[:128],
            "agent_version": agent_version[:40],
        },
    )
    return EnrollResult(device=device, credential=credential, token=token)


def expire_stale(db: Session) -> int:
    """Mark overdue pending requests expired. Called by the worker."""
    rows = (
        db.execute(
            select(EnrollmentRequest)
            .where(EnrollmentRequest.status == "pending", EnrollmentRequest.expires_at <= utcnow())
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
        .scalars()
        .all()
    )
    for request in rows:
        request.status = "expired"
    db.flush()
    return len(rows)
