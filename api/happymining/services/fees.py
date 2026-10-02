"""Versioned management fee schedules.

A schedule version is never edited or deleted. Each earnings bucket stores the
version and rate that applied on its day when it was first posted; corrections
to that bucket reuse the stored rate. A later version therefore cannot change
what was already accrued.

The 10% used by the demo is a DEMO assumption, flagged as such in the data. It
is not an approved commercial rate.
"""

from __future__ import annotations

import uuid
from datetime import date
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..errors import Conflict, InvalidRequest
from ..models import EarningBucket, FeeSchedule
from .ledger import ZERO


def fee_for(db: Session, owner_id: uuid.UUID, day: date) -> FeeSchedule | None:
    """The schedule in force for ``owner_id`` on ``day``: owner-specific first, else default."""
    for scope in (FeeSchedule.owner_id == owner_id, FeeSchedule.owner_id.is_(None)):
        found = db.execute(
            select(FeeSchedule)
            .where(scope, FeeSchedule.effective_from <= day)
            .order_by(FeeSchedule.effective_from.desc())
            .limit(1)
        ).scalar_one_or_none()
        if found:
            return found
    return None


def create_fee_schedule(
    db: Session,
    actor: Actor,
    *,
    owner_id: uuid.UUID | None,
    rate: Decimal,
    effective_from: date,
    note: str,
    created_by: uuid.UUID | None,
    is_demo_assumption: bool = False,
) -> FeeSchedule:
    if not (ZERO <= rate < Decimal("1")):
        raise InvalidRequest("rate must be at least 0 and below 1 (for example 0.10 for 10%)")
    if rate != rate.quantize(Decimal("0.00000001")):
        raise InvalidRequest("rate has more than 8 decimal places")

    # A new version must not reach back over days that already have posted
    # earnings in its scope: those buckets carry their own snapshot, but late
    # imports for the same days would otherwise mix two rates for one period.
    scope = EarningBucket.owner_id == owner_id if owner_id else EarningBucket.owner_id.is_not(None)
    latest_posted = db.execute(
        select(func.max(EarningBucket.day)).where(scope, EarningBucket.status == "mapped")
    ).scalar_one_or_none()
    if latest_posted and effective_from <= latest_posted:
        raise Conflict(
            f"effective_from must be after {latest_posted.isoformat()}, the last day with posted earnings "
            "in this scope; fee history is not rewritten"
        )

    duplicate = db.execute(
        select(FeeSchedule.id).where(
            FeeSchedule.owner_id.is_(None) if owner_id is None else FeeSchedule.owner_id == owner_id,
            FeeSchedule.effective_from == effective_from,
        )
    ).scalar_one_or_none()
    if duplicate:
        raise Conflict("a fee version with this scope and effective date already exists")

    schedule = FeeSchedule(
        owner_id=owner_id,
        rate=rate,
        effective_from=effective_from,
        note=note[:500],
        created_by=created_by,
        is_demo_assumption=is_demo_assumption,
    )
    db.add(schedule)
    db.flush()
    audit(
        db,
        actor,
        "fee_schedule.create",
        object_type="fee_schedule",
        object_id=schedule.id,
        owner_id=owner_id,
        details={"rate": str(rate), "effective_from": effective_from.isoformat(), "demo": is_demo_assumption},
    )
    return schedule
