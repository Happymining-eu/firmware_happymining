"""Typed, allowlisted remote operations.

There is no arbitrary command endpoint. An operation is one of a fixed set of
types with a validated parameter schema, an id, an expiry and a nonce. The
agent enforces its own allowlist as well; the server cannot widen it.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..config import Settings
from ..db import lock_row
from ..errors import Conflict, Forbidden, Gone, InvalidRequest, NotFound, NotImplementedFeature
from ..models import OPERATION_FINAL, ApiClient, Device, Machine, Operation, utcnow
from ..providers.base import Provider
from ..sealing import VERSION_RE
from ..security import constant_time_equal, new_nonce, redact, redact_text
from . import remote_access
from .api_clients import ensure_still_active, is_usable
from .catalog import ID_RE as PLUGIN_ID_RE
from .maintenance import DISRUPTIVE_TYPES, describe_blocked, evaluate

DIAGNOSTIC_SECTIONS = ("services", "gpu", "disk", "network", "agent")
APPLIANCE_JOBS = ("vectorize_sync", "backup_run", "update_check", "plugin_restart")
MAX_RESULT_BYTES = 64 * 1024


def _no_params(params: dict[str, Any]) -> dict[str, Any]:
    if params:
        raise InvalidRequest("this operation takes no parameters")
    return {}


def _diagnostics(params: dict[str, Any]) -> dict[str, Any]:
    if set(params) != {"sections"} or not isinstance(params["sections"], list) or not params["sections"]:
        raise InvalidRequest('params must be {"sections": [...]}')
    sections = params["sections"]
    if len(set(sections)) != len(sections) or not set(sections) <= set(DIAGNOSTIC_SECTIONS):
        raise InvalidRequest("sections must be distinct values from: " + ", ".join(DIAGNOSTIC_SECTIONS))
    return {"sections": sections}


def _int_range(name: str, low: int, high: int):
    def validate(params: dict[str, Any]) -> dict[str, Any]:
        value = params.get(name)
        if (
            set(params) != {name}
            or isinstance(value, bool)
            or not isinstance(value, int)
            or not low <= value <= high
        ):
            raise InvalidRequest(f'params must be {{"{name}": <integer {low}..{high}>}}')
        return {name: value}

    return validate


def _profile(params: dict[str, Any]) -> dict[str, Any]:
    value = params.get("profile_id")
    if set(params) != {"profile_id"} or not isinstance(value, str) or not (1 <= len(value) <= 64):
        raise InvalidRequest('params must be {"profile_id": "<id>"}')
    return {"profile_id": value}


def _appliance_job(params: dict[str, Any]) -> dict[str, Any]:
    """``{"job": ...}``, plus ``"plugin"`` for ``plugin_restart`` and for nothing else."""
    job = params.get("job")
    if not isinstance(job, str) or job not in APPLIANCE_JOBS:
        raise InvalidRequest('params must be {"job": <one of ' + ", ".join(APPLIANCE_JOBS) + ">}")
    if job != "plugin_restart":
        if set(params) != {"job"}:
            raise InvalidRequest(f'params must be {{"job": "{job}"}}; only plugin_restart takes a plugin')
        return {"job": job}
    plugin = params.get("plugin")
    if set(params) != {"job", "plugin"} or not isinstance(plugin, str) or not PLUGIN_ID_RE.fullmatch(plugin):
        raise InvalidRequest('params must be {"job": "plugin_restart", "plugin": "<plugin id>"}')
    return {"job": job, "plugin": plugin}


def _install_update(params: dict[str, Any]) -> dict[str, Any]:
    version = params.get("version")
    if set(params) != {"version"} or not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise InvalidRequest('params must be {"version": "<MAJOR.MINOR.PATCH>"}')
    return {"version": version}


# type -> parameter validator. This table is the whole remote surface.
OPERATION_TYPES = {
    "refresh_inventory": _no_params,
    "collect_diagnostics": _diagnostics,
    "run_preflight": _no_params,
    "rotate_credential": _no_params,
    "restart_vast_daemon": _no_params,
    # The protocol allows up to an hour; the server asks for at most five
    # minutes, so a reboot cannot fire long after the gate was last checked.
    "reboot": _int_range("delay_s", 60, 300),
    "run_benchmark": _int_range("duration_s", 30, 600),
    "apply_hardware_profile": _profile,
    # docs/appliance.md, section 6.5. Neither is disruptive for renters: they
    # touch only HappyMining's own containers and package.
    "appliance_run_job": _appliance_job,
    "install_update": _install_update,
}
# Typed in the protocol but with no implementation in agent 0.1.0. Refused
# here explicitly instead of being queued to fail on the device.
NOT_IMPLEMENTED_TYPES = frozenset({"run_benchmark", "apply_hardware_profile"})
# Requested only through the appliance routes (services/appliance.py and
# services/releases.py), which check what the general operation routes do not:
# that the caller may manage the appliance, that the plugin is configured,
# that the release exists and may be installed. The general routes, the
# dashboard form and the integration API cannot queue them.
APPLIANCE_ONLY_TYPES = frozenset({"appliance_run_job", "install_update"})
# What the general operation routes accept.
GENERAL_TYPES = tuple(sorted(set(OPERATION_TYPES) - APPLIANCE_ONLY_TYPES))


def request_operation(
    db: Session,
    settings: Settings,
    actor: Actor,
    provider: Provider | None,
    *,
    machine: Machine,
    op_type: str,
    params: dict[str, Any],
    requested_by: uuid.UUID | None,
    client_id: uuid.UUID | None = None,
    request_key: str | None = None,
    via_appliance: bool = False,
) -> Operation:
    validator = OPERATION_TYPES.get(op_type)
    if validator is None:
        raise InvalidRequest("unknown operation type; allowed: " + ", ".join(GENERAL_TYPES))
    clean = validator(params or {})
    if op_type in APPLIANCE_ONLY_TYPES and not via_appliance:
        raise InvalidRequest(
            f"{op_type} is requested through the machine's appliance routes, not as a plain operation"
        )
    device = db.execute(select(Device).where(Device.machine_id == machine.id)).scalar_one_or_none()
    if device is None or device.status != "active":
        raise Conflict("this machine has no active paired device")
    if op_type in NOT_IMPLEMENTED_TYPES:
        raise NotImplementedFeature(
            f"{op_type} is not implemented in this release; nothing was sent to the machine"
        )

    decision = evaluate(db, settings, provider, machine, op_type)
    now = utcnow()
    operation = Operation(
        machine_id=machine.id,
        device_id=device.id,
        type=op_type,
        params=clean,
        nonce=new_nonce(),
        requested_by=requested_by,
        requested_by_client=client_id,
        request_key=request_key,
        issued_at=now,
        expires_at=now + timedelta(seconds=settings.operation_ttl_s),
        safety=decision.as_dict(),
    )
    if not decision.allowed:
        operation.status = "blocked"
        operation.detail = describe_blocked(decision)[:2000]
        operation.completed_at = now
    db.add(operation)
    db.flush()
    audit(
        db,
        actor,
        "operation.request" if decision.allowed else "operation.blocked",
        object_type="operation",
        object_id=operation.id,
        owner_id=machine.owner_id,
        details={
            "type": op_type,
            "params": clean,
            "machine_id": str(machine.id),
            "reasons": decision.reasons,
        },
    )
    return operation


def request_operation_for_client(
    db: Session,
    settings: Settings,
    actor: Actor,
    provider: Provider | None,
    *,
    machine: Machine,
    op_type: str,
    params: dict[str, Any],
    client_id: uuid.UUID,
    request_key: str,
) -> tuple[Operation, bool]:
    """Request an operation on behalf of an API client. Returns (operation, created).

    The client's idempotency key makes a retried request find the first
    operation instead of queueing a second one: a fleet manager that times out
    and tries again must not reboot a machine twice. The same key with a
    different machine, type or parameters is refused.
    """
    key = (request_key or "").strip()
    if not (8 <= len(key) <= 128):
        raise InvalidRequest("the Idempotency-Key header must be 8 to 128 characters")

    def earlier() -> Operation | None:
        return db.execute(
            select(Operation).where(Operation.requested_by_client == client_id, Operation.request_key == key)
        ).scalar_one_or_none()

    def same_request(found: Operation) -> Operation:
        validator = OPERATION_TYPES.get(op_type)
        clean = validator(params or {}) if validator else None
        if found.machine_id != machine.id or found.type != op_type or found.params != clean:
            raise Conflict("this idempotency key was already used for a different operation")
        return found

    found = earlier()
    if found is not None:
        return same_request(found), False
    # One client cannot fill a machine's queue: operations are handed to the
    # agent oldest first, a few at a time, and other requesters share it.
    open_now = db.execute(
        select(func.count())
        .select_from(Operation)
        .where(
            Operation.requested_by_client == client_id,
            Operation.machine_id == machine.id,
            Operation.status.in_(("pending", "delivered", "accepted")),
        )
    ).scalar_one()
    if open_now >= settings.integration_max_open_operations_per_machine:
        raise Conflict(
            f"this API client already has {open_now} operations open on this machine; "
            "wait for them to finish or cancel them",
            code="too_many_open_operations",
        )
    try:
        with db.begin_nested():
            operation = request_operation(
                db,
                settings,
                actor,
                provider,
                machine=machine,
                op_type=op_type,
                params=params,
                requested_by=None,
                client_id=client_id,
                request_key=key,
            )
            # The token was checked a moment ago, without a lock. Check again
            # now that the operation exists, so that a revocation happening in
            # between either cancels it or is seen here.
            ensure_still_active(db, client_id)
    except IntegrityError:
        # The same request arrived twice at the same moment; the other one won.
        found = earlier()
        if found is None:
            raise
        return same_request(found), False
    return operation, True


def _expire_if_due(operation: Operation) -> None:
    if operation.status in ("pending", "delivered", "accepted") and operation.expires_at <= utcnow():
        operation.status = "expired"
        operation.completed_at = utcnow()
        operation.detail = operation.detail or "expired before a final acknowledgement"


def pending_for_device(
    db: Session, settings: Settings, provider: Provider | None, device: Device, machine: Machine
) -> list[Operation]:
    """Operations to hand to the device now. Disruptive ones are re-checked first."""
    operations = (
        db.execute(
            select(Operation)
            .where(Operation.device_id == device.id, Operation.status.in_(("pending", "delivered")))
            .order_by(Operation.issued_at)
            .limit(32)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        .scalars()
        .all()
    )
    out: list[Operation] = []
    for operation in operations:
        _expire_if_due(operation)
        if operation.status == "expired":
            continue
        if operation.status == "pending" and operation.requested_by_client is not None:
            # Requested by an API client that has since been revoked or has
            # expired: its authority is gone, so the request does not leave.
            client = db.get(ApiClient, operation.requested_by_client)
            if not is_usable(client):
                operation.status = "cancelled"
                operation.completed_at = utcnow()
                operation.detail = "the requesting API client is no longer valid"
                continue
        # Requested under an authority that has ended since: a remote-access
        # grant that expired or was revoked, a machine that changed owner or
        # went back to being managed by its owner. Nothing runs when a grant
        # expires, so this is where it takes effect. Only an operation that has
        # not been handed over yet is cancelled.
        if remote_access.cancel_if_unauthorised(db, operation, machine):
            continue
        if operation.type in DISRUPTIVE_TYPES:
            # Second check, immediately before the operation leaves the server.
            decision = evaluate(db, settings, provider, machine, operation.type)
            if operation.status == "delivered":
                # Already handed over once: the device may have started it, so
                # nothing in its record is rewritten, including the check that
                # let it out. If the gate has closed it is simply not sent again.
                if not decision.allowed:
                    continue
            else:
                operation.safety = {**operation.safety, "recheck": decision.as_dict()}
            if not decision.allowed:
                operation.status = "blocked"
                operation.completed_at = utcnow()
                operation.detail = describe_blocked(decision)[:2000]
                audit(
                    db,
                    Actor.system("maintenance-gate"),
                    "operation.blocked",
                    object_type="operation",
                    object_id=operation.id,
                    owner_id=machine.owner_id,
                    details={"type": operation.type, "stage": "delivery", "reasons": decision.reasons},
                )
                continue
        if operation.status == "pending":
            operation.status = "delivered"
            operation.delivered_at = utcnow()
        out.append(operation)
    db.flush()
    return out


def serialize_for_device(operation: Operation) -> dict[str, Any]:
    return {
        "id": str(operation.id),
        "type": operation.type,
        "params": operation.params,
        "issued_at": operation.issued_at,
        "expires_at": operation.expires_at,
        "nonce": operation.nonce,
    }


def acknowledge(
    db: Session,
    actor: Actor,
    device: Device,
    operation_id: uuid.UUID,
    *,
    status: str,
    nonce: str,
    detail: str,
    result: dict[str, Any],
) -> Operation:
    """Record a device acknowledgement. Final states are write-once."""
    operation = lock_row(db, Operation, operation_id)
    # Not found and "not yours" are indistinguishable to the device.
    if operation is None or operation.device_id != device.id:
        raise NotFound()
    if not constant_time_equal(operation.nonce, nonce):
        raise Forbidden("nonce does not match this operation")
    if operation.status in OPERATION_FINAL:
        if operation.status == "expired":
            raise Gone()
        raise Conflict("this operation already has a final acknowledgement")
    _expire_if_due(operation)
    if operation.status == "expired":
        db.flush()
        raise Gone()
    if operation.status == "pending":
        # The device can only know operations that were delivered to it.
        raise Conflict("this operation has not been delivered")

    if len(json.dumps(result or {}, default=str)) > MAX_RESULT_BYTES:
        raise InvalidRequest("result is larger than 64 KiB")
    operation.status = status
    # Both fields come from the device and are shown to people: scrub them.
    operation.detail = redact_text(detail)[:2000]
    operation.result = redact(result or {})
    if status in ("succeeded", "failed", "rejected"):
        operation.completed_at = utcnow()
    db.flush()
    machine = db.get(Machine, operation.machine_id)
    audit(
        db,
        actor,
        "operation.ack",
        object_type="operation",
        object_id=operation.id,
        owner_id=machine.owner_id if machine else None,
        details={"type": operation.type, "status": status},
    )
    return operation


def cancel(db: Session, actor: Actor, operation_id: uuid.UUID) -> Operation:
    operation = lock_row(db, Operation, operation_id)
    if operation is None:
        raise NotFound()
    if operation.status != "pending":
        raise Conflict("only an operation that has not been delivered can be cancelled")
    operation.status = "cancelled"
    operation.completed_at = utcnow()
    audit(db, actor, "operation.cancel", object_type="operation", object_id=operation.id)
    db.flush()
    return operation


def expire_stale(db: Session) -> int:
    rows = (
        db.execute(
            select(Operation)
            .where(
                Operation.status.in_(("pending", "delivered", "accepted")), Operation.expires_at <= utcnow()
            )
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
        .scalars()
        .all()
    )
    for operation in rows:
        _expire_if_due(operation)
    db.flush()
    return len(rows)
