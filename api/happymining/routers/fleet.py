"""Owners, users, enrollment, machines, telemetry and operations."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db import get_db
from ..deps import (
    client_ip,
    load_machine,
    load_owner,
    require_admin,
    require_admin_or_auditor,
    require_any,
    scoped_owner_id,
    settings_dep,
)
from ..errors import Conflict, NotFound
from ..models import Device, EnrollmentRequest, Machine, Operation, Owner, TelemetrySample, User
from ..providers.registry import get_provider
from ..schemas import EnrollmentIn, OperationIn, OwnerIn, RevokeIn, TransferIn, UserIn
from ..services import access, accounts, pairing, remote_access
from ..services import devices as device_service
from ..services import machines as machine_service
from ..services import operations as operation_service
from ..services import org as org_service
from ..services.accounts import Principal
from . import views
from .auth import user_view

router = APIRouter(prefix="/api/v1", tags=["fleet"])

Limit = Query(50, ge=1, le=200)
Offset = Query(0, ge=0)


# --- owners and users ------------------------------------------------------


@router.get("/owners")
def list_owners(
    limit: int = Limit,
    offset: int = Offset,
    principal: Principal = Depends(require_any),
    db: Session = Depends(get_db),
):
    query = select(Owner).order_by(Owner.created_at)
    if principal.role == "owner":
        query = query.where(Owner.id == principal.owner_id)
    return views.page(db, query, limit, offset, views.owner_view)


@router.post("/owners", status_code=201)
def create_owner(
    body: OwnerIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    owner = accounts.create_owner(
        db,
        principal.actor(client_ip(request)),
        display_name=body.display_name,
        legal_name=body.legal_name,
        contact_email=body.contact_email,
        is_synthetic=settings.is_demo,
    )
    db.commit()
    return views.owner_view(owner)


@router.get("/owners/{owner_id}")
def get_owner(
    owner_id: uuid.UUID, principal: Principal = Depends(require_any), db: Session = Depends(get_db)
):
    return views.owner_view(load_owner(db, principal, owner_id))


@router.get("/users")
def list_users(
    limit: int = Limit,
    offset: int = Offset,
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
):
    return views.page(db, select(User).order_by(User.created_at), limit, offset, user_view)


@router.post("/users", status_code=201)
def create_user(
    body: UserIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = accounts.create_user(
        db,
        principal.actor(client_ip(request)),
        email=body.email,
        role=body.role,
        display_name=body.display_name,
        password=body.password,
        owner_id=body.owner_id,
    )
    db.commit()
    return user_view(user)


@router.post("/users/{user_id}/deactivate")
def deactivate_user(
    user_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Disable an account and end all of its sessions.

    An organisation keeps at least one active administrator, whoever asks.
    """
    org_service.guard_last_admin(db, user_id)
    user = accounts.deactivate_user(db, principal.actor(client_ip(request)), user_id)
    db.commit()
    return {"id": str(user.id), "is_active": user.is_active}


@router.post("/users/{user_id}/revoke-sessions")
def revoke_user_sessions(
    user_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    count = accounts.revoke_user_sessions(db, principal.actor(client_ip(request)), user_id)
    db.commit()
    return {"id": str(user_id), "sessions_revoked": count}


# --- enrollment ------------------------------------------------------------


def enrollment_view(request_row: EnrollmentRequest, *, show_locator: bool = True) -> dict:
    return {
        "id": str(request_row.id),
        "owner_id": str(request_row.owner_id),
        "machine_id": str(request_row.machine_id),
        "status": request_row.status,
        # The locator is half of what is needed to burn a code's attempts, so
        # read-only roles do not get it.
        "locator": request_row.locator if show_locator else None,
        "failed_attempts": request_row.failed_attempts,
        "max_attempts": request_row.max_attempts,
        "expires_at": views.iso(request_row.expires_at),
        "consumed_at": views.iso(request_row.consumed_at),
        "created_at": views.iso(request_row.created_at),
    }


@router.post("/enrollment-requests", status_code=201)
def create_enrollment(
    body: EnrollmentIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    if body.machine_id is not None:
        # A new code for a machine that was paired before lets whoever holds it
        # connect a device as that machine, and that device is then sent the
        # machine's configuration. On a customer-managed machine that needs the
        # organisation's consent, like any other change (a machine that never
        # paired has nothing to protect yet).
        existing = db.get(Machine, body.machine_id)
        if existing is not None and existing.status != "pending_pairing":
            access.require_manage(db, principal, existing)
    issued = pairing.create_enrollment(
        db,
        settings,
        principal.actor(client_ip(request)),
        owner_id=body.owner_id,
        machine_label=body.machine_label,
        machine_id=body.machine_id,
        owned_since=body.owned_since,
        created_by=principal.user.id,
        is_synthetic=settings.is_demo,
        management=body.management,
    )
    db.commit()
    return {
        **enrollment_view(issued.request),
        # Shown exactly once. Only a keyed hash is stored.
        "pairing_code": issued.code,
        "note": "Enter this code on the machine with: sudo happyminingctl pair",
    }


@router.get("/enrollment-requests")
def list_enrollments(
    limit: int = Limit,
    offset: int = Offset,
    principal: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
):
    query = select(EnrollmentRequest).order_by(EnrollmentRequest.created_at.desc())
    return views.page(
        db, query, limit, offset, lambda row: enrollment_view(row, show_locator=principal.is_admin)
    )


@router.post("/enrollment-requests/{request_id}/cancel")
def cancel_enrollment(
    request_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    row = pairing.cancel_enrollment(db, principal.actor(client_ip(request)), request_id)
    db.commit()
    return enrollment_view(row)


# --- machines and devices --------------------------------------------------


@router.get("/machines")
def list_machines(
    owner_id: uuid.UUID | None = None,
    limit: int = Limit,
    offset: int = Offset,
    principal: Principal = Depends(require_any),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    scope = scoped_owner_id(principal, owner_id)
    query = select(Machine).order_by(Machine.created_at)
    if scope is not None:
        query = query.where(Machine.owner_id == scope)
    staff = principal.role != "owner"
    return views.page(db, query, limit, offset, lambda m: views.machine_view(settings, m, staff=staff))


@router.get("/machines/{machine_id}")
def get_machine(
    machine_id: uuid.UUID,
    principal: Principal = Depends(require_any),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = load_machine(db, principal, machine_id)
    return views.machine_view(settings, machine, staff=principal.role != "owner")


@router.get("/machines/{machine_id}/telemetry")
def machine_telemetry(
    machine_id: uuid.UUID,
    since: datetime | None = None,
    limit: int = Limit,
    principal: Principal = Depends(require_any),
    db: Session = Depends(get_db),
):
    machine = load_machine(db, principal, machine_id)
    staff = principal.role != "owner"
    query = select(TelemetrySample).where(TelemetrySample.machine_id == machine.id)
    if since is not None:
        query = query.where(TelemetrySample.collected_at >= since)
    if not staff:
        period_start = machine_service.owned_since(db, machine)
        if period_start is not None:
            query = query.where(TelemetrySample.collected_at >= period_start)
    rows = db.execute(query.order_by(TelemetrySample.collected_at.desc()).limit(limit)).scalars().all()
    return {"items": [views.telemetry_view(r, staff=staff) for r in rows], "limit": limit}


@router.post("/machines/{machine_id}/transfer-ownership")
def transfer_ownership(
    machine_id: uuid.UUID,
    body: TransferIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    # Handing a customer-managed machine to another organisation gives that
    # organisation its configuration: staff need the current owner's consent.
    access.require_manage(db, principal, load_machine(db, principal, machine_id, lock=True))
    actor = principal.actor(client_ip(request))
    machine = machine_service.transfer_ownership(
        db,
        actor,
        machine_id=machine_id,
        new_owner_id=body.new_owner_id,
        reason=body.reason,
        user_id=principal.user.id,
    )
    # The previous owner's grants end here, and with them what was queued under them.
    remote_access.close_grants_after_transfer(db, actor, machine, user_id=principal.user.id)
    db.commit()
    return views.machine_view(settings, machine, staff=True)


@router.post("/devices/{device_id}/revoke")
def revoke_device(
    device_id: uuid.UUID,
    body: RevokeIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    device = device_service.revoke_device(db, principal.actor(client_ip(request)), device_id, body.reason)
    db.commit()
    return {"device_id": str(device.id), "status": device.status}


# --- operations ------------------------------------------------------------


@router.get("/operation-types")
def operation_types(
    _: Principal = Depends(require_admin_or_auditor), settings: Settings = Depends(settings_dep)
):
    return {
        "types": sorted(operation_service.OPERATION_TYPES),
        "disruptive": sorted(operation_service.DISRUPTIVE_TYPES),
        "not_implemented": sorted(operation_service.NOT_IMPLEMENTED_TYPES),
        "disruptive_operations_enabled": settings.disruptive_operations_enabled,
    }


@router.post("/machines/{machine_id}/operations", status_code=201)
def request_operation(
    machine_id: uuid.UUID,
    body: OperationIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = load_machine(db, principal, machine_id, lock=True)
    # On a customer-managed machine staff need a remote-access grant (manage).
    access.require_manage(db, principal, machine)
    try:
        provider = get_provider(settings)
    except Exception:
        provider = None
    operation = operation_service.request_operation(
        db,
        settings,
        principal.actor(client_ip(request)),
        provider,
        machine=machine,
        op_type=body.type,
        params=body.params,
        requested_by=principal.user.id,
    )
    db.commit()
    if operation.status == "blocked":
        # The refusal is recorded (operation row and audit trail) and then
        # reported as an error. A blocked action never looks like a success.
        raise Conflict(operation.detail, code="maintenance_blocked")
    return views.operation_view(operation)


@router.get("/machines/{machine_id}/operations")
def list_operations(
    machine_id: uuid.UUID,
    limit: int = Limit,
    offset: int = Offset,
    principal: Principal = Depends(require_any),
    db: Session = Depends(get_db),
):
    machine = load_machine(db, principal, machine_id)
    query = select(Operation).where(Operation.machine_id == machine.id).order_by(Operation.issued_at.desc())
    if principal.role == "owner":
        period_start = machine_service.owned_since(db, machine)
        if period_start is not None:
            query = query.where(Operation.issued_at >= period_start)
    return views.page(db, query, limit, offset, views.operation_view)


@router.get("/operations")
def all_operations(
    status: str | None = None,
    limit: int = Limit,
    offset: int = Offset,
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
):
    query = select(Operation).order_by(Operation.issued_at.desc())
    if status:
        query = query.where(Operation.status == status)
    return views.page(db, query, limit, offset, views.operation_view)


@router.post("/operations/{operation_id}/cancel")
def cancel_operation(
    operation_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    found = db.get(Operation, operation_id)
    if found is None:
        raise NotFound()
    # Withdrawing a request is managing the machine too: same rule as requesting.
    access.require_manage(db, principal, load_machine(db, principal, found.machine_id, lock=True))
    operation = operation_service.cancel(db, principal.actor(client_ip(request)), operation_id)
    db.commit()
    return views.operation_view(operation)


@router.get("/devices/{device_id}")
def get_device_admin(
    device_id: uuid.UUID, _: Principal = Depends(require_admin_or_auditor), db: Session = Depends(get_db)
):
    device = db.get(Device, device_id)
    if device is None:
        raise NotFound()
    return {
        "id": str(device.id),
        "machine_id": str(device.machine_id),
        "status": device.status,
        "hostname": device.hostname,
        "agent_version": device.agent_version,
        "os": device.os_info,
        "last_seen_at": views.iso(device.last_seen_at),
        "last_seq": device.last_seq,
    }
