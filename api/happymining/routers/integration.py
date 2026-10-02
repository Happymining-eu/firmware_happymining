"""The integration API: how other software manages the AI servers.

Written for Mole Hash, the fleet manager HappyMining already runs for ASIC
miners, so that GPU servers show up and can be managed in the same place. It
is a server-to-server API: the caller holds an API client token created by an
admin, with the scopes that admin chose (``services/api_clients.py``).

Two routers:

``router``        ``/api/v1/integration/...``  what an API client may call.
``admin_router``  ``/api/v1/api-clients``      how admins create and revoke clients.

Everything a client can change goes through the same service functions as the
admin routes, so the rental-protection gate, the typed operation list and the
audit trail apply unchanged. There is no route here that touches money.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from sqlalchemy import Date, and_, cast, func, select
from sqlalchemy.orm import Session, selectinload

from .. import __version__
from ..config import Settings
from ..db import get_db
from ..deps import (
    client_ip,
    get_api_client,
    load_client_machine,
    require_admin,
    require_admin_or_auditor,
    require_scope,
    settings_dep,
)
from ..errors import Conflict, Forbidden, InvalidRequest, NotFound
from ..models import (
    API_CLIENT_SCOPES,
    EarningBucket,
    Machine,
    MachineOwnership,
    Operation,
    TelemetrySample,
    utcnow,
)
from ..providers.registry import get_provider
from ..schemas import ApiClientIn, OperationIn, RevokeIn
from ..services import access, api_clients, remote_access
from ..services import appliance as appliance_service
from ..services import machines as machine_service
from ..services import operations as operation_service
from ..services.accounts import Principal
from ..services.api_clients import ClientPrincipal
from ..services.devices import device_state
from ..services.ledger import ZERO, money_str
from . import views

API_VERSION = 1

router = APIRouter(prefix="/api/v1/integration", tags=["integration"])
admin_router = APIRouter(prefix="/api/v1/api-clients", tags=["api-clients"])

Limit = Query(50, ge=1, le=200)
Offset = Query(0, ge=0)


# --- representations -------------------------------------------------------


def _utc_day(column):
    return cast(func.timezone("UTC", column), Date)


def _within_current_ownership(query, machine_column, time_column):
    """Keep only rows from the current owner's period of each machine.

    A client limited to one owner sees a machine's history from the day the
    machine became that owner's. What happened before belongs to someone else.
    """
    return query.join(
        MachineOwnership,
        and_(MachineOwnership.machine_id == machine_column, MachineOwnership.valid_to.is_(None)),
    ).where(_utc_day(time_column) >= MachineOwnership.valid_from)


def latest_samples(
    db: Session, principal: ClientPrincipal, machine_ids: list[uuid.UUID]
) -> dict[uuid.UUID, TelemetrySample]:
    """The most recent telemetry sample of each machine, in one query."""
    if not machine_ids:
        return {}
    query = select(TelemetrySample).where(TelemetrySample.machine_id.in_(machine_ids))
    if principal.owner_id is not None:
        query = _within_current_ownership(query, TelemetrySample.machine_id, TelemetrySample.collected_at)
    rows = db.execute(
        query.distinct(TelemetrySample.machine_id).order_by(
            TelemetrySample.machine_id, TelemetrySample.collected_at.desc()
        )
    ).scalars()
    return {row.machine_id: row for row in rows}


def _number(value: Any) -> float | None:
    return float(value) if value is not None else None


def sample_summary(sample: TelemetrySample | None) -> dict[str, Any] | None:
    if sample is None:
        return None
    return {
        "collected_at": views.iso(sample.collected_at),
        "synthetic": sample.synthetic,
        "gpu_count": sample.gpu_count,
        "gpu_util_avg": _number(sample.gpu_util_avg),
        "gpu_power_w": _number(sample.gpu_power_w),
        "gpu_temp_max": _number(sample.gpu_temp_max),
    }


def machine_out(
    settings: Settings,
    principal: ClientPrincipal,
    machine: Machine,
    latest: TelemetrySample | None,
    mode: str | None = None,
) -> dict[str, Any]:
    """One AI server, in a shape a fleet manager can put next to its other devices."""
    device = machine.device
    out: dict[str, Any] = {
        "kind": "gpu_server",
        **views.machine_view(settings, machine, staff=False),
        "hostname": device.hostname if device else None,
        "created_at": views.iso(machine.created_at),
        # vast, private_ai or vectorize (docs/appliance.md, section 2); null when
        # this client may not see the machine's appliance configuration.
        "mode": mode,
    }
    if "telemetry:read" in principal.scopes:
        out["latest_telemetry"] = sample_summary(latest)
    return out


def machine_modes(
    db: Session, principal: ClientPrincipal, machines: list[Machine]
) -> dict[uuid.UUID, str | None]:
    """The mode each machine should be in.

    The mode is part of the appliance configuration: on a customer-managed
    machine a fleet-wide client sees it only under a remote-access grant, as
    staff do.
    """
    visible = [m.id for m in machines if access.client_access(db, principal.owner_id, m) != "none"]
    modes = appliance_service.desired_modes(db, visible)
    return {m.id: modes.get(m.id) for m in machines}


def _machine_query(principal: ClientPrincipal):
    query = (
        select(Machine)
        .options(selectinload(Machine.device), selectinload(Machine.provider_machine))
        .order_by(Machine.created_at, Machine.id)
    )
    if principal.owner_id is not None:
        query = query.where(Machine.owner_id == principal.owner_id)
    return query


def _operation_query(principal: ClientPrincipal):
    query = select(Operation).order_by(Operation.issued_at.desc(), Operation.id)
    if principal.owner_id is not None:
        query = query.join(Machine, Machine.id == Operation.machine_id).where(
            Machine.owner_id == principal.owner_id
        )
        query = _within_current_ownership(query, Operation.machine_id, Operation.issued_at)
    return query


def operation_out(principal: ClientPrincipal, operation: Operation) -> dict[str, Any]:
    """An operation as a client sees it.

    Who asked is reduced to a kind: other people's and other clients' ids are
    not this client's business. The gate's verdict and its reasons are kept;
    the raw provider counters behind them are not.
    """
    view = views.operation_view(operation)
    if operation.requested_by_client == principal.client.id:
        requester = "self"
    elif operation.requested_by_client is not None:
        requester = "client"
    elif operation.requested_by is not None:
        requester = "user"
    else:
        requester = "system"
    view.pop("requested_by_client", None)
    view["requested_by"] = requester
    safety = view.get("safety") or {}
    view["safety"] = {"allowed": safety.get("allowed"), "reasons": safety.get("reasons", [])}
    return view


def _load_operation(db: Session, principal: ClientPrincipal, operation_id: uuid.UUID) -> Operation:
    operation = db.get(Operation, operation_id)
    if operation is None:
        raise NotFound()
    machine = load_client_machine(db, principal, operation.machine_id)  # 404 outside the client's scope
    if principal.owner_id is not None:
        period_start = machine_service.owned_since(db, machine)
        if period_start is not None and operation.issued_at < period_start:
            raise NotFound()
    return operation


# --- who am I --------------------------------------------------------------


@router.get("")
def describe(
    principal: ClientPrincipal = Depends(get_api_client),
    settings: Settings = Depends(settings_dep),
):
    """Connection test: who the token belongs to and what it may do. Needs no particular scope."""
    view = api_clients.client_view(principal.client)
    return {
        "api": "happymining-integration",
        "api_version": API_VERSION,
        "server_version": __version__,
        "mode": settings.mode,
        "synthetic_data": settings.is_demo,
        "server_time": views.iso(utcnow()),
        "client": {k: view[k] for k in ("id", "name", "scopes", "owner_id", "expires_at")},
        "limits": {"requests_per_minute": settings.integration_rate_limit_per_minute},
    }


# --- fleet -----------------------------------------------------------------


@router.get("/fleet/summary")
def fleet_summary(
    principal: ClientPrincipal = Depends(require_scope("fleet:read")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machines = db.execute(_machine_query(principal).where(Machine.status != "retired")).scalars().all()
    now = utcnow()
    connection: dict[str, int] = {}
    for machine in machines:
        state = device_state(settings, machine.device, now)
        connection[state] = connection.get(state, 0) + 1
    out: dict[str, Any] = {
        "machines": len(machines),
        "by_connection": dict(sorted(connection.items())),
        "synthetic_data": settings.is_demo,
        "as_of": views.iso(now),
    }
    if "telemetry:read" in principal.scopes:
        latest = latest_samples(db, principal, [m.id for m in machines])
        # Only machines that are reporting now count towards the live totals.
        live = [
            latest[m.id]
            for m in machines
            if m.id in latest and device_state(settings, m.device, now) == "online"
        ]
        utils = [float(s.gpu_util_avg) for s in live if s.gpu_util_avg is not None]
        out["online_now"] = {
            "machines_reporting": len(live),
            "gpus": sum(s.gpu_count for s in live),
            "gpu_power_w": round(sum(float(s.gpu_power_w) for s in live if s.gpu_power_w is not None), 2),
            "gpu_util_avg": round(sum(utils) / len(utils), 2) if utils else None,
            "gpu_temp_max": max(
                (float(s.gpu_temp_max) for s in live if s.gpu_temp_max is not None), default=None
            ),
        }
    return out


@router.get("/machines")
def list_machines(
    limit: int = Limit,
    offset: int = Offset,
    principal: ClientPrincipal = Depends(require_scope("fleet:read")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    query = _machine_query(principal)
    total = db.execute(select(func.count()).select_from(query.order_by(None).subquery())).scalar_one()
    machines = db.execute(query.limit(limit).offset(offset)).scalars().all()
    latest = (
        latest_samples(db, principal, [m.id for m in machines])
        if "telemetry:read" in principal.scopes
        else {}
    )
    modes = machine_modes(db, principal, list(machines))
    return {
        "items": [machine_out(settings, principal, m, latest.get(m.id), modes[m.id]) for m in machines],
        "limit": limit,
        "offset": offset,
        "total": total,
    }


@router.get("/machines/{machine_id}")
def get_machine(
    machine_id: uuid.UUID,
    principal: ClientPrincipal = Depends(require_scope("fleet:read")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = load_client_machine(db, principal, machine_id)
    latest = latest_samples(db, principal, [machine.id]) if "telemetry:read" in principal.scopes else {}
    mode = machine_modes(db, principal, [machine])[machine.id]
    return machine_out(settings, principal, machine, latest.get(machine.id), mode)


@router.get("/machines/{machine_id}/appliance")
def machine_appliance(
    machine_id: uuid.UUID,
    principal: ClientPrincipal = Depends(require_scope("appliance:read")),
    db: Session = Depends(get_db),
):
    """Mode, plugin states and the indexing, backup and update summaries. Read only.

    State, not configuration: no NAS host or user name and no secret name.
    A fleet-wide client follows the staff rule: on a customer-managed machine
    it needs a remote-access grant (``403 remote_access_required``).
    """
    machine = load_client_machine(db, principal, machine_id)
    if access.client_access(db, principal.owner_id, machine) == "none":
        raise Forbidden(
            "this machine is managed by its owner; the owner's organisation has to grant remote access first",
            code=access.REMOTE_ACCESS_REQUIRED,
        )
    return appliance_service.integration_view(db, machine)


@router.get("/machines/{machine_id}/telemetry")
def machine_telemetry(
    machine_id: uuid.UUID,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(100, ge=1, le=1000),
    principal: ClientPrincipal = Depends(require_scope("telemetry:read")),
    db: Session = Depends(get_db),
):
    """Samples, newest first. ``payload`` holds the per-GPU, CPU, memory, disk and service detail."""
    machine = load_client_machine(db, principal, machine_id)
    query = select(TelemetrySample).where(TelemetrySample.machine_id == machine.id)
    if since is not None:
        query = query.where(TelemetrySample.collected_at >= since)
    if until is not None:
        query = query.where(TelemetrySample.collected_at < until)
    if principal.owner_id is not None:
        period_start = machine_service.owned_since(db, machine)
        if period_start is not None:
            query = query.where(TelemetrySample.collected_at >= period_start)
    rows = db.execute(query.order_by(TelemetrySample.collected_at.desc()).limit(limit)).scalars().all()
    return {"items": [views.telemetry_view(r) for r in rows], "limit": limit}


# --- operations ------------------------------------------------------------


@router.get("/operation-types")
def operation_types(
    principal: ClientPrincipal = Depends(require_scope("operations:read")),
    settings: Settings = Depends(settings_dep),
):
    """What can be requested, and what this client and this server allow right now."""
    return {
        # Without the operations only the appliance routes for people can request
        # (running an appliance job, installing an update): a client cannot queue them.
        "types": list(operation_service.GENERAL_TYPES),
        "disruptive": sorted(operation_service.DISRUPTIVE_TYPES),
        "not_implemented": sorted(operation_service.NOT_IMPLEMENTED_TYPES),
        "disruptive_operations_enabled": settings.disruptive_operations_enabled,
        "client_may_request": "operations:write" in principal.scopes,
        "client_may_request_disruptive": "operations:disruptive" in principal.scopes,
    }


@router.get("/operations")
def list_operations(
    status: str | None = Query(None, max_length=20),
    machine_id: uuid.UUID | None = None,
    limit: int = Limit,
    offset: int = Offset,
    principal: ClientPrincipal = Depends(require_scope("operations:read")),
    db: Session = Depends(get_db),
):
    query = _operation_query(principal)
    if status:
        query = query.where(Operation.status == status)
    if machine_id is not None:
        load_client_machine(db, principal, machine_id)  # 404 for a machine outside the client's scope
        query = query.where(Operation.machine_id == machine_id)
    return views.page(db, query, limit, offset, lambda op: operation_out(principal, op))


@router.get("/operations/{operation_id}")
def get_operation(
    operation_id: uuid.UUID,
    principal: ClientPrincipal = Depends(require_scope("operations:read")),
    db: Session = Depends(get_db),
):
    return operation_out(principal, _load_operation(db, principal, operation_id))


@router.post("/machines/{machine_id}/operations", status_code=201)
def request_operation(
    machine_id: uuid.UUID,
    body: OperationIn,
    request: Request,
    response: Response,
    idempotency_key: str | None = Header(default=None, max_length=128),
    principal: ClientPrincipal = Depends(require_scope("operations:write")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Request one typed operation. The ``Idempotency-Key`` header is required.

    201 for a new operation, 200 when the same key was already used for the
    same request (the first operation is returned and nothing new is queued).
    A disruptive operation the rental-protection gate refuses is recorded and
    answered with 409 ``maintenance_blocked``; it never looks like a success.
    """
    if not idempotency_key:
        raise InvalidRequest("the Idempotency-Key header is required")
    if body.type in operation_service.DISRUPTIVE_TYPES and "operations:disruptive" not in principal.scopes:
        raise Forbidden("this API client does not have the operations:disruptive scope")
    machine = load_client_machine(db, principal, machine_id, lock=True)
    # A fleet-wide client is HappyMining's own software: on a customer-managed
    # machine it needs the same remote-access grant as staff (403 remote_access_required).
    remote_access.require_client_manage(db, principal, machine)
    try:
        provider = get_provider(settings)
    except Exception:
        provider = None
    operation, created = operation_service.request_operation_for_client(
        db,
        settings,
        principal.actor(client_ip(request)),
        provider,
        machine=machine,
        op_type=body.type,
        params=body.params,
        client_id=principal.client.id,
        request_key=idempotency_key,
    )
    db.commit()
    if operation.status == "blocked":
        raise Conflict(operation.detail, code="maintenance_blocked")
    if not created:
        response.status_code = 200
    return operation_out(principal, operation)


@router.post("/operations/{operation_id}/cancel")
def cancel_operation(
    operation_id: uuid.UUID,
    request: Request,
    principal: ClientPrincipal = Depends(require_scope("operations:write")),
    db: Session = Depends(get_db),
):
    """Cancel an operation this client requested and the machine has not received yet."""
    found = _load_operation(db, principal, operation_id)
    if found.requested_by_client != principal.client.id:
        # Someone else's request (an admin's, another client's) is not this client's to withdraw.
        raise Forbidden("only operations this API client requested can be cancelled by it")
    # Same rule as requesting: without access to manage the machine, nothing on it is changed.
    remote_access.require_client_manage(
        db, principal, load_client_machine(db, principal, found.machine_id, lock=True)
    )
    operation = operation_service.cancel(db, principal.actor(client_ip(request)), operation_id)
    api_clients.ensure_still_active(db, principal.client.id)
    db.commit()
    return operation_out(principal, operation)


# --- earnings (read only) --------------------------------------------------


def _period(start: date | None, end: date | None) -> tuple[date, date]:
    today = utcnow().date()
    end = end or today - timedelta(days=1)
    start = start or end - timedelta(days=29)
    if end < start:
        raise InvalidRequest("end is before start")
    if end >= today:
        raise InvalidRequest("end must be a closed UTC day (yesterday at the latest)")
    if (end - start).days > 366:
        raise InvalidRequest("at most 367 days per request")
    return start, end


def _bucket_scope(principal: ClientPrincipal, start: date, end: date, machine_id: uuid.UUID | None):
    conditions = [EarningBucket.day >= start, EarningBucket.day <= end]
    if principal.owner_id is not None:
        conditions.append(EarningBucket.owner_id == principal.owner_id)
    if machine_id is not None:
        conditions.append(EarningBucket.machine_id == machine_id)
    return conditions


def earning_row(bucket: EarningBucket) -> dict[str, Any]:
    """One provider machine on one closed UTC day. Amounts are decimal strings, never floats."""
    return {
        "day": bucket.day.isoformat(),
        "machine_id": str(bucket.machine_id) if bucket.machine_id else None,
        "owner_id": str(bucket.owner_id) if bucket.owner_id else None,
        "provider_machine_id": bucket.external_machine_id,
        "attributed": bucket.status == "mapped",
        "currency": bucket.currency,
        "reported": money_str(bucket.reported_amount),
        "received": money_str(bucket.received_amount),
        "fee_reported": money_str(bucket.fee_accrued),
        "owner_share_reported": money_str(bucket.owner_accrued),
        "fee_reconciled": money_str(bucket.fee_released),
        "owner_share_reconciled": money_str(bucket.owner_released),
        "revisions": bucket.revision_count,
        "synthetic": bucket.is_synthetic,
    }


@router.get("/earnings/daily")
def earnings_daily(
    start: date | None = None,
    end: date | None = None,
    machine_id: uuid.UUID | None = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Offset,
    principal: ClientPrincipal = Depends(require_scope("earnings:read")),
    db: Session = Depends(get_db),
):
    """Earnings per machine and day, as reported by the provider. Default: the last 30 closed days.

    ``reported`` is what the provider says the machine earned. It is not cash:
    ``received`` is the part HappyMining has seen on its own statement and
    reconciled. Nothing here can be changed through this API.
    """
    start, end = _period(start, end)
    if machine_id is not None:
        load_client_machine(db, principal, machine_id)
    query = (
        select(EarningBucket)
        .where(*_bucket_scope(principal, start, end, machine_id))
        .order_by(EarningBucket.day.desc(), EarningBucket.external_machine_id)
    )
    out = views.page(db, query, limit, offset, earning_row)
    out["period"] = {"start": start.isoformat(), "end": end.isoformat()}
    return out


@router.get("/earnings/summary")
def earnings_summary(
    start: date | None = None,
    end: date | None = None,
    principal: ClientPrincipal = Depends(require_scope("earnings:read")),
    db: Session = Depends(get_db),
):
    """Totals per machine over a period. Same amounts and the same caveat as ``/earnings/daily``."""
    start, end = _period(start, end)
    rows = db.execute(
        select(
            EarningBucket.machine_id,
            EarningBucket.currency,
            func.count(),
            func.sum(EarningBucket.reported_amount),
            func.sum(EarningBucket.received_amount),
            func.sum(EarningBucket.fee_accrued),
            func.sum(EarningBucket.owner_accrued),
            func.sum(EarningBucket.owner_released),
        )
        .where(*_bucket_scope(principal, start, end, None))
        .group_by(EarningBucket.machine_id, EarningBucket.currency)
        .order_by(EarningBucket.machine_id, EarningBucket.currency)
    ).all()
    items = [
        {
            "machine_id": str(machine_id) if machine_id else None,
            "attributed": machine_id is not None,
            "currency": currency,
            "days": days,
            "reported": money_str(reported or ZERO),
            "received": money_str(received or ZERO),
            "fee_reported": money_str(fee or ZERO),
            "owner_share_reported": money_str(owner_share or ZERO),
            "owner_share_reconciled": money_str(reconciled or ZERO),
        }
        for machine_id, currency, days, reported, received, fee, owner_share, reconciled in rows
    ]
    return {"items": items, "period": {"start": start.isoformat(), "end": end.isoformat()}}


# --- admin: managing API clients -------------------------------------------


@admin_router.get("")
def list_clients(_: Principal = Depends(require_admin_or_auditor), db: Session = Depends(get_db)):
    return {
        "items": [api_clients.client_view(c) for c in api_clients.list_clients(db)],
        "available_scopes": {scope: api_clients.SCOPE_HELP[scope] for scope in API_CLIENT_SCOPES},
    }


@admin_router.post("", status_code=201)
def create_client(
    body: ApiClientIn,
    request: Request,
    response: Response,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Create a client. The token is in this response only; it is not stored and cannot be shown again."""
    issued = api_clients.create_client(
        db,
        settings,
        principal.actor(client_ip(request)),
        name=body.name,
        description=body.description,
        scopes=body.scopes,
        owner_id=body.owner_id,
        expires_in_days=body.expires_in_days,
        created_by=principal.user.id,
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return {**api_clients.client_view(issued.client), "token": issued.token}


@admin_router.post("/{client_id}/rotate")
def rotate_client(
    client_id: uuid.UUID,
    request: Request,
    response: Response,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    issued = api_clients.rotate_client(db, settings, principal.actor(client_ip(request)), client_id)
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return {**api_clients.client_view(issued.client), "token": issued.token}


@admin_router.post("/{client_id}/revoke")
def revoke_client(
    client_id: uuid.UUID,
    body: RevokeIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    client = api_clients.revoke_client(db, principal.actor(client_ip(request)), client_id, body.reason)
    db.commit()
    return api_clients.client_view(client)
