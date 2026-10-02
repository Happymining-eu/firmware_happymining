"""An owner's organisation: its users and their roles, machine management and
remote-access grants (docs/appliance.md, section 3)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from ..config import Settings
from ..db import get_db
from ..deps import client_ip, get_principal, load_machine, scoped_owner_id, settings_dep
from ..errors import Forbidden
from ..schemas import ManagementIn, OrgUserIn, OrgUserPatchIn, RemoteAccessGrantIn
from ..services import access, remote_access
from ..services import org as org_service
from ..services.accounts import Principal
from . import views

router = APIRouter(prefix="/api/v1", tags=["organisation"])

Limit = Query(50, ge=1, le=200)
Offset = Query(0, ge=0)


# --- who may call ----------------------------------------------------------
#
# Decided in dependencies, so that a caller without the role is told so (403)
# before the request body is even looked at.


def org_admin_or_staff(principal: Principal = Depends(get_principal)) -> Principal:
    """Reading: an organisation's administrator, or HappyMining staff (admin, auditor)."""
    if not (principal.is_staff or access.has_org_role(principal, "org_admin")):
        raise Forbidden("this needs the org_admin role in your organisation")
    return principal


def org_admin_or_admin(principal: Principal = Depends(get_principal)) -> Principal:
    """Changing: an organisation's administrator, or a HappyMining admin. An auditor reads."""
    if not (principal.is_admin or access.has_org_role(principal, "org_admin")):
        raise Forbidden("this needs the org_admin role in your organisation")
    return principal


def org_admin_only(principal: Principal = Depends(get_principal)) -> Principal:
    """Granting remote access is the organisation's decision alone: staff cannot do it."""
    if not access.has_org_role(principal, "org_admin"):
        raise Forbidden("remote access is granted by an administrator of the owner's organisation")
    return principal


# --- organisation users ----------------------------------------------------


@router.get("/org/users")
def list_org_users(
    owner_id: uuid.UUID | None = None,
    limit: int = Limit,
    offset: int = Offset,
    principal: Principal = Depends(org_admin_or_staff),
    db: Session = Depends(get_db),
):
    """The users of the caller's organisation. Staff pass ``owner_id``, or nothing for every organisation.

    HappyMining's own accounts are never in this list.
    """
    scope = scoped_owner_id(principal, owner_id)
    return views.page(db, org_service.users_query(scope), limit, offset, org_service.org_user_view)


@router.post("/org/users", status_code=201)
def create_org_user(
    body: OrgUserIn,
    request: Request,
    principal: Principal = Depends(org_admin_or_admin),
    db: Session = Depends(get_db),
):
    user = org_service.create_org_user(
        db,
        principal,
        principal.actor(client_ip(request)),
        email=body.email,
        display_name=body.display_name,
        org_role=body.org_role,
        password=body.password,
        owner_id=body.owner_id,
    )
    db.commit()
    return org_service.org_user_view(user)


@router.patch("/org/users/{user_id}")
def update_org_user(
    user_id: uuid.UUID,
    body: OrgUserPatchIn,
    request: Request,
    principal: Principal = Depends(org_admin_or_admin),
    db: Session = Depends(get_db),
):
    """Change the organisation role, the active flag or the display name. Nothing else can be changed."""
    user = org_service.update_org_user(
        db,
        principal,
        principal.actor(client_ip(request)),
        user_id,
        org_role=body.org_role,
        is_active=body.is_active,
        display_name=body.display_name,
    )
    db.commit()
    return org_service.org_user_view(user)


# --- machine management and remote access ----------------------------------


@router.get("/machines/{machine_id}/remote-access")
def get_remote_access(
    machine_id: uuid.UUID,
    principal: Principal = Depends(org_admin_or_staff),
    db: Session = Depends(get_db),
):
    """Who manages the machine, what HappyMining may do on it now, and the grants."""
    machine = load_machine(db, principal, machine_id)
    return remote_access.describe(db, machine, include_previous_owners=principal.is_staff)


@router.put("/machines/{machine_id}/management")
def put_management(
    machine_id: uuid.UUID,
    body: ManagementIn,
    request: Request,
    principal: Principal = Depends(org_admin_or_admin),
    db: Session = Depends(get_db),
):
    machine = load_machine(db, principal, machine_id, lock=True)
    _, changed = remote_access.set_management(
        db, principal, principal.actor(client_ip(request)), machine, body.management
    )
    db.commit()
    return {
        **remote_access.describe(db, machine, include_previous_owners=principal.is_staff),
        "changed": changed,
    }


@router.post("/machines/{machine_id}/remote-access/grants", status_code=201)
def create_grant(
    machine_id: uuid.UUID,
    body: RemoteAccessGrantIn,
    request: Request,
    principal: Principal = Depends(org_admin_only),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = load_machine(db, principal, machine_id, lock=True)
    grant = remote_access.issue_grant(
        db,
        settings,
        principal,
        principal.actor(client_ip(request)),
        machine,
        level=body.level,
        expires_in_hours=body.expires_in_hours,
        reason=body.reason,
    )
    db.commit()
    return remote_access.grant_view(grant, machine)


@router.post("/machines/{machine_id}/remote-access/grants/{grant_id}/revoke")
def revoke_grant(
    machine_id: uuid.UUID,
    grant_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(org_admin_or_admin),
    db: Session = Depends(get_db),
):
    """Revoke a grant (the organisation), or give it up (a HappyMining admin). Safe to repeat."""
    machine = load_machine(db, principal, machine_id, lock=True)
    grant, changed = remote_access.revoke_grant(
        db, principal, principal.actor(client_ip(request)), machine, grant_id
    )
    db.commit()
    return {**remote_access.grant_view(grant, machine), "changed": changed}
