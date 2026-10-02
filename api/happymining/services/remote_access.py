"""Who manages a machine, and remote-access grants (docs/appliance.md, section 3).

``Machine.management`` is ``company`` (HappyMining operates the machine) or
``customer``. On a customer-managed machine HappyMining staff, and a fleet-wide
integration API client, may request operations only while a grant of level
``manage`` issued by the owner's organisation is in force.

The permission itself is decided in ``services/access.py``. This module holds
what changes it (management, grants) and what has to follow when HappyMining's
access ends: operations that staff or a fleet-wide API client had requested and
that the machine has not received yet are cancelled, because the authority they
were requested under is gone.

Callers change management or grants while holding the machine's row lock
(``load_machine(..., lock=True)``). The routes that request operations take the
same lock before they check access, so a request and a revocation cannot pass
each other: either the revocation cancels the operation, or the request sees
the revocation and is refused.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..config import Settings
from ..db import lock_row
from ..errors import Forbidden, InvalidRequest, NotFound
from ..models import (
    GRANT_LEVELS,
    MANAGEMENT_KINDS,
    ApiClient,
    Machine,
    Operation,
    RemoteAccessGrant,
    User,
    utcnow,
)
from . import access
from .accounts import Principal
from .api_clients import ClientPrincipal

ACCESS_ENDED_DETAIL = "cancelled before delivery: the requester may no longer manage this machine"
PAST_GRANTS_SHOWN = 50
# The expiry choices the panel offers (hours, label). The API accepts any whole
# number of hours up to the configured maximum.
GRANT_DURATIONS = (
    (1, "1 hour"),
    (8, "8 hours"),
    (24, "1 day"),
    (7 * 24, "7 days"),
    (30 * 24, "30 days"),
    (90 * 24, "90 days"),
)


def grant_durations(settings: Settings) -> list[tuple[int, str]]:
    """The panel's expiry choices that fit within ``remote_access_max_hours``."""
    return [(hours, label) for hours, label in GRANT_DURATIONS if hours <= settings.remote_access_max_hours]


# --- what an operation was requested under ---------------------------------


def operation_still_authorised(
    db: Session, operation: Operation, machine: Machine, now: datetime | None = None
) -> bool:
    """True while whoever requested ``operation`` may still have it carried out on ``machine``.

    Meant for the moment an operation is about to be handed to the device
    (``services/operations.pending_for_device``), which is where an expired
    grant takes effect: nothing runs when a grant expires, so a pending
    operation is checked when the device asks for it.

    - Requested by HappyMining staff, or by nobody in particular (the system):
      the staff rule, ``access.staff_access(...) == "manage"``.
    - Requested by a fleet-wide API client: the staff rule as well. By a client
      limited to one owner: that owner must still own the machine.
    - Requested by a user of the owner's organisation: that organisation must
      still own the machine, and the user must still be able to change
      something in it (an operator at least).
    - A person whose account was deactivated since has no request left.

    Whether an API client's token is still valid is not checked here:
    ``pending_for_device`` already does that.

    ``machine`` must be the operation's machine. Only its ``management``,
    ``owner_id`` and grants are read; nothing the device reports is consulted.
    """
    if operation.requested_by_client is not None:
        client = db.get(ApiClient, operation.requested_by_client)
        if client is None:
            return False
        if client.owner_id is not None:
            return access.client_access(db, client.owner_id, machine) == "manage"
        return access.staff_access(db, machine, now) == "manage"
    if operation.requested_by is not None:
        user = db.get(User, operation.requested_by)
        if user is None or not user.is_active:
            return False
        if user.role == "owner":
            still_changes_things = (
                access.ORG_RANK.get(user.org_role or "", 0) >= access.ORG_RANK["org_operator"]
            )
            return user.owner_id == machine.owner_id and still_changes_things
    return access.staff_access(db, machine, now) == "manage"


def cancel_if_unauthorised(db: Session, operation: Operation, machine: Machine) -> bool:
    """Cancel a still-pending operation whose requester lost the right to it. True when cancelled.

    The one call ``pending_for_device`` needs for each pending operation::

        if remote_access.cancel_if_unauthorised(db, operation, machine):
            continue

    An operation that was already delivered is left alone: the device may have
    started it.
    """
    if operation.status != "pending" or operation_still_authorised(db, operation, machine):
        return False
    operation.status = "cancelled"
    operation.completed_at = utcnow()
    operation.detail = ACCESS_ENDED_DETAIL
    audit(
        db,
        Actor.system("remote-access"),
        "operation.cancel",
        object_type="operation",
        object_id=operation.id,
        owner_id=machine.owner_id,
        details={"type": operation.type, "reason": "requester_lost_access", "machine_id": str(machine.id)},
    )
    return True


def cancel_unauthorised_pending(db: Session, machine: Machine) -> int:
    """Cancel every pending operation on ``machine`` whose requester may no longer manage it.

    Called, with the machine row locked, right after HappyMining's access may
    have ended: a grant was revoked, management became ``customer``, the
    machine changed owner. Returns how many were cancelled.
    """
    pending = (
        db.execute(
            select(Operation)
            .where(Operation.machine_id == machine.id, Operation.status == "pending")
            .order_by(Operation.issued_at)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        .scalars()
        .all()
    )
    cancelled = sum(1 for operation in pending if cancel_if_unauthorised(db, operation, machine))
    db.flush()
    return cancelled


def require_client_manage(db: Session, principal: ClientPrincipal, machine: Machine) -> None:
    """An API client about to request or cancel an operation: fleet-wide clients follow the staff rule."""
    if access.client_access(db, principal.owner_id, machine) != "manage":
        raise Forbidden(
            "this machine is managed by its owner; a remote-access grant with the manage level is needed",
            code=access.REMOTE_ACCESS_REQUIRED,
        )


# --- representations -------------------------------------------------------


def _iso(value: datetime | None) -> str | None:
    """Always in UTC, whatever time zone the database session reports values in."""
    return value.astimezone(UTC).isoformat() if value else None


def grant_state(grant: RemoteAccessGrant, machine: Machine, now: datetime | None = None) -> str:
    """``active``, or why it no longer counts: ``revoked``, ``expired``, ``previous_owner``."""
    now = now or utcnow()
    if grant.revoked_at is not None:
        return "revoked"
    if grant.owner_id != machine.owner_id:
        return "previous_owner"
    if grant.expires_at is not None and grant.expires_at <= now:
        return "expired"
    return "active"


def grant_view(grant: RemoteAccessGrant, machine: Machine, now: datetime | None = None) -> dict[str, Any]:
    return {
        "id": str(grant.id),
        "machine_id": str(grant.machine_id),
        "level": grant.level,
        "state": grant_state(grant, machine, now),
        "reason": grant.reason,
        "granted_by": str(grant.granted_by),
        "created_at": _iso(grant.created_at),
        "expires_at": _iso(grant.expires_at),
        "revoked_at": _iso(grant.revoked_at),
        "revoked_by": str(grant.revoked_by) if grant.revoked_by else None,
    }


def describe(db: Session, machine: Machine, *, include_previous_owners: bool) -> dict[str, Any]:
    """Who manages the machine, what HappyMining may do on it now, and its grants.

    ``include_previous_owners`` is for staff. An organisation sees the grants
    issued on its own behalf only: who another organisation let in, and why, is
    that organisation's business.
    """
    now = utcnow()
    query = select(RemoteAccessGrant).where(RemoteAccessGrant.machine_id == machine.id)
    if not include_previous_owners:
        query = query.where(RemoteAccessGrant.owner_id == machine.owner_id)
    rows = db.execute(query.order_by(RemoteAccessGrant.created_at.desc(), RemoteAccessGrant.id)).scalars()
    active: list[dict[str, Any]] = []
    past: list[dict[str, Any]] = []
    for grant in rows:
        view = grant_view(grant, machine, now)
        if view["state"] == "active":
            active.append(view)
        elif len(past) < PAST_GRANTS_SHOWN:
            past.append(view)
    return {
        "machine_id": str(machine.id),
        "management": machine.management,
        "staff_access": access.staff_access(db, machine, now),
        "grants": active,
        "past_grants": past,
    }


# --- changes ---------------------------------------------------------------


def set_management(
    db: Session, principal: Principal, actor: Actor, machine: Machine, management: str
) -> tuple[Machine, bool]:
    """Say who manages the machine. Returns (machine, changed).

    ``company`` to ``customer``: a HappyMining admin or an ``org_admin`` of the
    owner. ``customer`` to ``company``: an ``org_admin`` of the owner only:
    staff cannot give themselves access. Asking for the value the machine
    already has changes nothing and is not an error.

    ``machine`` must be loaded with its row locked, through the caller's
    tenant scoping.
    """
    if management not in MANAGEMENT_KINDS:
        raise InvalidRequest("management must be one of: " + ", ".join(MANAGEMENT_KINDS))
    is_org_admin = principal.owner_id == machine.owner_id and access.has_org_role(principal, "org_admin")
    if not (is_org_admin or principal.role == "admin"):
        raise Forbidden()
    if machine.management == management:
        return machine, False
    if management == "company" and not is_org_admin:
        raise Forbidden(
            "only an administrator of the owner's organisation can hand the machine to HappyMining"
        )
    previous = machine.management
    machine.management = management
    db.flush()
    cancelled = cancel_unauthorised_pending(db, machine) if management == "customer" else 0
    audit(
        db,
        actor,
        "machine.management.change",
        object_type="machine",
        object_id=machine.id,
        owner_id=machine.owner_id,
        details={
            "from": previous,
            "to": management,
            "staff_access": access.staff_access(db, machine),
            "operations_cancelled": cancelled,
        },
    )
    return machine, True


def issue_grant(
    db: Session,
    settings: Settings,
    principal: Principal,
    actor: Actor,
    machine: Machine,
    *,
    level: str,
    expires_in_hours: int | None,
    reason: str = "",
) -> RemoteAccessGrant:
    """Let HappyMining see (``view``) or manage (``manage``) one machine. ``org_admin`` of the owner only.

    ``expires_in_hours`` is ``None`` for a grant that lasts until it is
    revoked, or 1 to ``settings.remote_access_max_hours``.
    """
    if not (principal.owner_id == machine.owner_id and access.has_org_role(principal, "org_admin")):
        raise Forbidden("remote access is granted by an administrator of the owner's organisation")
    if level not in GRANT_LEVELS:
        raise InvalidRequest("level must be one of: " + ", ".join(GRANT_LEVELS))
    if expires_in_hours is not None and (
        isinstance(expires_in_hours, bool)
        or not isinstance(expires_in_hours, int)
        or not 1 <= expires_in_hours <= settings.remote_access_max_hours
    ):
        raise InvalidRequest(
            f"expires_in_hours must be null or between 1 and {settings.remote_access_max_hours}"
        )
    now = utcnow()
    grant = RemoteAccessGrant(
        machine_id=machine.id,
        owner_id=machine.owner_id,
        level=level,
        reason=(reason or "").strip()[:300],
        granted_by=principal.user.id,
        created_at=now,
        expires_at=now + timedelta(hours=expires_in_hours) if expires_in_hours is not None else None,
    )
    db.add(grant)
    db.flush()
    audit(
        db,
        actor,
        "remote_access.grant",
        object_type="remote_access_grant",
        object_id=grant.id,
        owner_id=machine.owner_id,
        details={
            "machine_id": str(machine.id),
            "level": level,
            "expires_at": _iso(grant.expires_at),
            "reason": grant.reason,
            "management": machine.management,
        },
    )
    return grant


def _close(
    db: Session,
    actor: Actor,
    machine: Machine,
    grant: RemoteAccessGrant,
    *,
    revoked_by: uuid.UUID | None,
    why: str,
) -> None:
    grant.revoked_at = utcnow()
    grant.revoked_by = revoked_by
    db.flush()
    cancelled = cancel_unauthorised_pending(db, machine)
    audit(
        db,
        actor,
        "remote_access.revoke",
        object_type="remote_access_grant",
        object_id=grant.id,
        owner_id=grant.owner_id,
        details={
            "machine_id": str(machine.id),
            "level": grant.level,
            "expires_at": _iso(grant.expires_at),
            "reason": grant.reason,
            "why": why,
            "operations_cancelled": cancelled,
        },
    )


def revoke_grant(
    db: Session, principal: Principal, actor: Actor, machine: Machine, grant_id: uuid.UUID
) -> tuple[RemoteAccessGrant, bool]:
    """End a grant now. Returns (grant, changed); revoking twice changes nothing the second time.

    An ``org_admin`` of the owner revokes; a HappyMining admin may give a
    grant up. Either way the pending operations it carried are cancelled.
    An organisation cannot touch a grant issued on behalf of a previous owner:
    for it, that grant does not exist.
    """
    is_org_admin = principal.owner_id == machine.owner_id and access.has_org_role(principal, "org_admin")
    if not (is_org_admin or principal.role == "admin"):
        raise Forbidden()
    grant = lock_row(db, RemoteAccessGrant, grant_id)
    if grant is None or grant.machine_id != machine.id:
        raise NotFound()
    if principal.role == "owner" and grant.owner_id != machine.owner_id:
        raise NotFound()
    if grant.revoked_at is not None:
        return grant, False
    _close(
        db,
        actor,
        machine,
        grant,
        revoked_by=principal.user.id,
        why="revoked by the owner's organisation" if is_org_admin else "given up by HappyMining",
    )
    return grant, True


def close_grants_after_transfer(
    db: Session, actor: Actor, machine: Machine, *, user_id: uuid.UUID | None = None
) -> int:
    """After ``machine`` changed owner: end every grant still open on it. Returns how many.

    ``access.py`` already ignores a grant issued for another owner. Closing
    them as well means such a grant cannot come back to life if the machine
    later returns to the organisation that issued it, and it cancels whatever
    HappyMining had queued under it. Call with the machine row locked, in the
    transaction of the transfer.
    """
    grants = (
        db.execute(
            select(RemoteAccessGrant)
            .where(RemoteAccessGrant.machine_id == machine.id, RemoteAccessGrant.revoked_at.is_(None))
            .order_by(RemoteAccessGrant.created_at)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        .scalars()
        .all()
    )
    for grant in grants:
        _close(db, actor, machine, grant, revoked_by=user_id, why="the machine changed owner")
    if not grants:
        cancel_unauthorised_pending(db, machine)
    return len(grants)
