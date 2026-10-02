"""Who may see or change a machine beyond monitoring it (docs/appliance.md, section 3).

Three kinds of callers:

- a user of the owner's organisation: allowed by organisation role;
- HappyMining staff: allowed on a ``company``-managed machine; on a
  ``customer``-managed machine only through a remote-access grant issued by
  the owner's organisation;
- an integration API client: a fleet-wide one follows the staff rule, an
  owner-scoped one acts for that owner.

Every route that reads or changes the appliance configuration, or requests an
operation, goes through the functions below. Nothing a device reports is ever
consulted here.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..errors import Forbidden, NotFound
from ..models import Machine, RemoteAccessGrant, utcnow
from .accounts import Principal

ORG_RANK = {"org_viewer": 1, "org_operator": 2, "org_admin": 3}
# What a level of staff access allows, as a rank.
ACCESS_RANK = {"none": 0, "view": 1, "manage": 2}
REMOTE_ACCESS_REQUIRED = "remote_access_required"


def has_org_role(principal: Principal, minimum: str) -> bool:
    """True when an owner's user holds at least ``minimum`` in the organisation."""
    return principal.role == "owner" and ORG_RANK.get(principal.org_role or "", 0) >= ORG_RANK[minimum]


def require_org_role(principal: Principal, minimum: str) -> None:
    if not has_org_role(principal, minimum):
        raise Forbidden(f"this needs the {minimum} role in your organisation")


def require_money_access(principal: Principal) -> None:
    """Earnings, settlements and beneficiary details: staff as before; in an
    organisation only its administrators."""
    if principal.role == "owner" and not has_org_role(principal, "org_admin"):
        raise Forbidden("earnings and settlements are visible to your organisation's administrators only")


def grant_is_active(grant: RemoteAccessGrant, machine: Machine, now: datetime | None = None) -> bool:
    now = now or utcnow()
    return (
        grant.revoked_at is None
        and (grant.expires_at is None or grant.expires_at > now)
        # Given on behalf of a previous owner: it does not bind the new one.
        and grant.owner_id == machine.owner_id
    )


def active_grants(db: Session, machine: Machine, now: datetime | None = None) -> list[RemoteAccessGrant]:
    now = now or utcnow()
    rows = db.execute(
        select(RemoteAccessGrant)
        .where(
            RemoteAccessGrant.machine_id == machine.id,
            RemoteAccessGrant.owner_id == machine.owner_id,
            RemoteAccessGrant.revoked_at.is_(None),
        )
        .order_by(RemoteAccessGrant.created_at)
    ).scalars()
    return [g for g in rows if grant_is_active(g, machine, now)]


def staff_access(db: Session, machine: Machine, now: datetime | None = None) -> str:
    """What HappyMining may do on this machine: ``manage``, ``view`` or ``none``."""
    if machine.management == "company":
        return "manage"
    level = "none"
    for grant in active_grants(db, machine, now):
        if ACCESS_RANK[grant.level] > ACCESS_RANK[level]:
            level = grant.level
    return level


def _owns(principal: Principal, machine: Machine) -> bool:
    return principal.role == "owner" and principal.owner_id == machine.owner_id


def can_view_appliance(db: Session, principal: Principal, machine: Machine) -> bool:
    if principal.role == "owner":
        return _owns(principal, machine)
    return ACCESS_RANK[staff_access(db, machine)] >= ACCESS_RANK["view"]


def can_manage_appliance(
    db: Session, principal: Principal, machine: Machine, minimum_org_role: str = "org_admin"
) -> bool:
    if principal.role == "owner":
        return _owns(principal, machine) and has_org_role(principal, minimum_org_role)
    # An auditor reads; only an admin changes.
    return principal.role == "admin" and staff_access(db, machine) == "manage"


def require_view(db: Session, principal: Principal, machine: Machine) -> None:
    if principal.role == "owner":
        if not _owns(principal, machine):
            raise NotFound()
        return
    if not can_view_appliance(db, principal, machine):
        raise Forbidden(
            "this machine is managed by its owner; the owner's organisation has to grant remote access first",
            code=REMOTE_ACCESS_REQUIRED,
        )


def require_manage(
    db: Session, principal: Principal, machine: Machine, minimum_org_role: str = "org_admin"
) -> None:
    """Raise unless the caller may change this machine (or request operations on it)."""
    if principal.role == "owner":
        if not _owns(principal, machine):
            raise NotFound()
        require_org_role(principal, minimum_org_role)
        return
    if principal.role != "admin":
        raise Forbidden()
    if staff_access(db, machine) != "manage":
        raise Forbidden(
            "this machine is managed by its owner; a remote-access grant with the manage level is needed",
            code=REMOTE_ACCESS_REQUIRED,
        )


def client_access(db: Session, client_owner_id, machine: Machine) -> str:
    """What an integration API client may do on this machine: ``manage``, ``view`` or ``none``.

    A client limited to one owner acts for that owner. A fleet-wide client is
    HappyMining's own software and follows the staff rule.
    """
    if client_owner_id is not None:
        return "manage" if client_owner_id == machine.owner_id else "none"
    return staff_access(db, machine)
