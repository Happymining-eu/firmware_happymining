"""Machine ownership changes, with history preserved."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, time, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..db import lock_row
from ..errors import Conflict, InvalidRequest, NotFound
from ..models import ApiClient, Machine, MachineOwnership, Operation, Owner, ProviderMachine, utcnow
from .provider_sync import _attribution_blockers


def owned_since(db: Session, machine: Machine) -> datetime | None:
    """Start of the current owner's period, as a UTC instant.

    What an owner, or an API client limited to an owner, may see of a
    machine's history starts here. Telemetry and operations from before belong
    to the previous owner's time with the machine.
    """
    start = db.execute(
        select(MachineOwnership.valid_from).where(
            MachineOwnership.machine_id == machine.id, MachineOwnership.valid_to.is_(None)
        )
    ).scalar_one_or_none()
    return datetime.combine(start, time.min, tzinfo=UTC) if start else None


def transfer_ownership(
    db: Session,
    actor: Actor,
    *,
    machine_id: uuid.UUID,
    new_owner_id: uuid.UUID,
    reason: str,
    user_id: uuid.UUID,
) -> Machine:
    """Move a machine to another owner from tomorrow (UTC) onwards.

    Past days keep their owner: earnings buckets are per closed UTC day and
    each already carries the owner it was attributed to. The change is refused
    while rentals, unreconciled earnings or payouts in progress would make it
    unclear who is owed what.
    """
    if not reason.strip():
        raise InvalidRequest("a reason is required")
    machine = lock_row(db, Machine, machine_id)
    new_owner = db.get(Owner, new_owner_id)
    if machine is None or new_owner is None or new_owner.status != "active":
        raise NotFound()
    if machine.owner_id == new_owner_id:
        raise Conflict("the machine already belongs to this owner")
    if machine.is_synthetic != new_owner.is_synthetic:
        raise Conflict("synthetic and real records cannot be mixed")

    # Queried explicitly: a relationship cached on the object could be stale.
    pm = db.execute(
        select(ProviderMachine).where(ProviderMachine.machine_id == machine.id)
    ).scalar_one_or_none()
    if pm is not None:
        blockers = _attribution_blockers(db, pm, machine)
        if blockers:
            raise Conflict(
                "ownership cannot change while attribution would be ambiguous: " + "; ".join(blockers)
            )

    # Effective from tomorrow (UTC): today's earnings were made under the
    # current owner and stay with them.
    effective = datetime.now(UTC).date() + timedelta(days=1)
    current = db.execute(
        select(MachineOwnership)
        .where(MachineOwnership.machine_id == machine.id, MachineOwnership.valid_to.is_(None))
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    previous_owner = machine.owner_id
    if current.valid_from >= effective:
        # The current period has not started yet (a transfer made earlier
        # today): there is no closed day under it, so it is simply replaced.
        current.owner_id = new_owner_id
        current.reason = f"{current.reason}; replaced before taking effect: {reason}"[:500]
        current.changed_by = user_id
    else:
        current.valid_to = effective
        db.flush()
        db.add(
            MachineOwnership(
                machine_id=machine.id,
                owner_id=new_owner_id,
                valid_from=effective,
                changed_by=user_id,
                reason=reason[:500],
            )
        )
    machine.owner_id = new_owner_id
    # Whatever an API client limited to the previous owner had queued and the
    # machine has not received yet was asked for under an authority that ends here.
    db.execute(
        update(Operation)
        .where(
            Operation.machine_id == machine.id,
            Operation.status == "pending",
            Operation.requested_by_client.in_(
                select(ApiClient.id).where(ApiClient.owner_id == previous_owner)
            ),
        )
        .values(status="cancelled", completed_at=utcnow(), detail="the machine changed owner")
    )
    db.flush()
    audit(
        db,
        actor,
        "machine.transfer_ownership",
        object_type="machine",
        object_id=machine.id,
        owner_id=new_owner_id,
        details={
            "from_owner": str(previous_owner),
            "to_owner": str(new_owner_id),
            "effective": effective.isoformat(),
            "reason": reason[:200],
        },
    )
    return machine
