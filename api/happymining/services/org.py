"""The users of an owner's organisation and their roles (docs/appliance.md, section 3).

An organisation is the set of users with the role ``owner`` that belong to one
owner. Its administrators (``org_admin``) manage it; HappyMining admins can do
the same for any organisation, which is how the first administrator of a new
organisation comes to exist.

Three rules hold whatever the caller and however requests overlap:

- an organisation always keeps at least one active ``org_admin``;
- a user never moves to another organisation and never changes ``role``;
- HappyMining's own accounts (admin, auditor) are neither listed nor changed
  here.

Every change to the roles or the active flag of an organisation's users is
made while holding that organisation's advisory lock, so two requests cannot
each see the other's administrator as "the one who remains".
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..db import lock_row
from ..errors import Conflict, Forbidden, InvalidRequest, NotFound
from ..models import ORG_ROLES, User
from . import accounts
from .accounts import Principal

# Two-key advisory lock: a namespace and the organisation. Held until commit.
_ORG_LOCK = text("SELECT pg_advisory_xact_lock(hashtext('hm:org-users'), hashtext(:owner))")


def lock_organisation(db: Session, owner_id: uuid.UUID) -> None:
    """Serialise changes to one organisation's users for the rest of the transaction."""
    db.execute(_ORG_LOCK, {"owner": str(owner_id)})


def org_user_view(user: User) -> dict[str, Any]:
    """What may be shown about a user of an organisation. Never the password hash or the TOTP secret."""
    return {
        "id": str(user.id),
        "owner_id": str(user.owner_id),
        "email": user.email,
        "display_name": user.display_name,
        "org_role": user.org_role,
        "is_active": user.is_active,
        "mfa_enabled": user.mfa_enabled,
        "created_at": user.created_at.isoformat(),
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


def users_query(owner_id: uuid.UUID | None):
    """Users of one organisation, or of every organisation (staff, no filter). Never staff accounts."""
    query = select(User).where(User.role == "owner").order_by(User.created_at, User.id)
    if owner_id is not None:
        query = query.where(User.owner_id == owner_id)
    return query


def _organisation_of(principal: Principal, requested: uuid.UUID | None) -> uuid.UUID:
    """The organisation a caller is about to change. An owner's user is pinned to their own."""
    if principal.role == "owner":
        if requested is not None and requested != principal.owner_id:
            raise NotFound()
        assert principal.owner_id is not None
        return principal.owner_id
    if principal.role != "admin":
        raise Forbidden()
    if requested is None:
        raise InvalidRequest("owner_id is required")
    return requested


def _confirm_caller(db: Session, principal: Principal, owner_id: uuid.UUID) -> None:
    """Check the caller's authority again, now that the organisation is locked.

    The session was resolved before the lock, possibly a moment before another
    administrator demoted or deactivated this caller. Reading the row again
    under the lock sees that change: a request that lost the race is refused
    instead of acting with an authority that no longer exists.
    """
    current = db.get(User, principal.user.id, populate_existing=True)
    if current is None or not current.is_active:
        raise Forbidden()
    if current.role == "admin":
        return
    if not (current.role == "owner" and current.owner_id == owner_id and current.org_role == "org_admin"):
        raise Forbidden("this needs the org_admin role in your organisation")


def _another_active_admin(db: Session, owner_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    return (
        db.execute(
            select(User.id)
            .where(
                User.owner_id == owner_id,
                User.role == "owner",
                User.org_role == "org_admin",
                User.is_active.is_(True),
                User.id != user_id,
            )
            .limit(1)
        ).first()
        is not None
    )


LAST_ADMIN_MESSAGE = (
    "this is the organisation's last active administrator; give another user the org_admin role first"
)


def create_org_user(
    db: Session,
    principal: Principal,
    actor: Actor,
    *,
    email: str,
    org_role: str,
    password: str,
    display_name: str = "",
    owner_id: uuid.UUID | None = None,
) -> User:
    """Add a user to an organisation. The role is always ``owner``: staff are not created here."""
    organisation = _organisation_of(principal, owner_id)
    if org_role not in ORG_ROLES:
        raise InvalidRequest("org_role must be one of: " + ", ".join(ORG_ROLES))
    if not password:
        raise InvalidRequest(f"password must be at least {accounts.MIN_PASSWORD_LENGTH} characters")
    lock_organisation(db, organisation)
    _confirm_caller(db, principal, organisation)
    try:
        with db.begin_nested():
            user = accounts.create_user(
                db,
                actor,
                email=email,
                role="owner",
                display_name=display_name,
                password=password,
                owner_id=organisation,
                org_role=org_role,
            )
    except IntegrityError as exc:
        # Lost a race with a request creating the same address.
        raise Conflict("a user with this email already exists") from exc
    audit(
        db,
        actor,
        "org.user.create",
        object_type="user",
        object_id=user.id,
        owner_id=organisation,
        details={"email": user.email, "org_role": user.org_role, "is_active": user.is_active},
    )
    return user


def update_org_user(
    db: Session,
    principal: Principal,
    actor: Actor,
    user_id: uuid.UUID,
    *,
    org_role: str | None = None,
    is_active: bool | None = None,
    display_name: str | None = None,
) -> User:
    """Change a user's organisation role, active flag or display name.

    Demoting or deactivating the organisation's last active administrator is
    refused (409). Deactivating ends the user's sessions.
    """
    if org_role is None and is_active is None and display_name is None:
        raise InvalidRequest("nothing to change: give org_role, is_active or display_name")
    if org_role is not None and org_role not in ORG_ROLES:
        raise InvalidRequest("org_role must be one of: " + ", ".join(ORG_ROLES))
    if principal.role not in ("owner", "admin"):
        raise Forbidden()
    # Read without a lock first, only to learn which organisation to lock. A
    # staff account, or a user of another organisation, does not exist here.
    found = db.get(User, user_id)
    if (
        found is None
        or found.role != "owner"
        or (principal.role == "owner" and found.owner_id != principal.owner_id)
    ):
        raise NotFound()
    organisation = found.owner_id
    lock_organisation(db, organisation)
    _confirm_caller(db, principal, organisation)
    user = lock_row(db, User, user_id)
    if user is None or user.role != "owner" or user.owner_id != organisation:
        raise NotFound()

    before = {"org_role": user.org_role, "is_active": user.is_active}
    new_role = org_role if org_role is not None else user.org_role
    new_active = is_active if is_active is not None else user.is_active
    new_name = display_name.strip()[:200] if display_name is not None else user.display_name
    was_running_it = user.is_active and user.org_role == "org_admin"
    if (
        was_running_it
        and not (new_active and new_role == "org_admin")
        and not _another_active_admin(db, organisation, user.id)
    ):
        raise Conflict(LAST_ADMIN_MESSAGE)

    after = {"org_role": new_role, "is_active": new_active}
    renamed = new_name != user.display_name
    if after == before and not renamed:
        return user  # nothing changed: nothing to record
    user.org_role = new_role
    user.is_active = new_active
    user.display_name = new_name
    sessions = accounts.revoke_sessions(db, user) if before["is_active"] and not new_active else 0
    db.flush()
    audit(
        db,
        actor,
        "org.user.update",
        object_type="user",
        object_id=user.id,
        owner_id=organisation,
        details={
            "before": before,
            "after": after,
            "display_name_changed": renamed,
            "sessions_revoked": sessions,
        },
    )
    return user


def guard_last_admin(db: Session, user_id: uuid.UUID) -> None:
    """For the staff route that deactivates any account: keep the organisation rule.

    Takes the organisation's lock (held until the caller commits) and refuses
    when the account is its organisation's last active administrator. Does
    nothing for a staff account or an unknown id; the caller handles those.
    """
    found = db.get(User, user_id)
    if found is None or found.role != "owner" or found.owner_id is None:
        return
    lock_organisation(db, found.owner_id)
    current = db.get(User, user_id, populate_existing=True)
    if (
        current is not None
        and current.is_active
        and current.org_role == "org_admin"
        and not _another_active_admin(db, current.owner_id, current.id)
    ):
        raise Conflict(LAST_ADMIN_MESSAGE)
