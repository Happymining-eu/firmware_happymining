"""Device-facing endpoints (docs/agent-protocol.md). HappyMining's own API, not Vast's.

A device can read and write only its own operational records. It has no access
to any financial data and cannot choose its owner or its machine.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request, Response
from sqlalchemy.orm import Session

from .. import ratelimit
from ..audit import Actor
from ..config import Settings
from ..db import get_db
from ..deps import client_ip, get_device, get_heartbeat_device, settings_dep
from ..errors import PairingFailed
from ..models import utcnow
from ..providers.registry import get_provider
from ..schemas import AckIn, EnrollIn, HeartbeatIn
from ..services import appliance as appliance_service
from ..services import devices as device_service
from ..services import operations as operation_service
from ..services import releases as release_service
from ..services.devices import DevicePrincipal
from ..services.pairing import enroll_device

router = APIRouter(prefix="/api/v1", tags=["device"])

# A package is large. An agent downloads one per update; this leaves room for retries.
ARTIFACT_DOWNLOADS_PER_HOUR = 12


def _provider_or_none(settings: Settings):
    try:
        return get_provider(settings)
    except Exception:
        # Without a provider the maintenance gate blocks disruptive operations.
        return None


@router.post("/devices/enroll", status_code=201)
def enroll(
    body: EnrollIn,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    ip = client_ip(request)
    ratelimit.hit(f"enroll:ip:{ip}", settings.pairing_rate_limit_per_minute)
    try:
        result = enroll_device(
            db,
            settings,
            pairing_code=body.pairing_code,
            hostname=body.hostname,
            fingerprint=body.machine_fingerprint,
            agent_version=body.agent_version,
            os_info=body.os.model_dump(),
            ip=ip,
        )
    except PairingFailed:
        db.commit()  # keep the failed-attempt counter and the audit row
        raise
    db.commit()
    return {
        "device_id": str(result.device.id),
        "machine_id": str(result.device.machine_id),
        "credential": {"id": str(result.credential.id), "token": result.token, "expires_at": None},
        "heartbeat_interval_s": settings.heartbeat_interval_s,
        "server_time": utcnow(),
    }


@router.post("/device/heartbeat")
def heartbeat(
    body: HeartbeatIn,
    principal: DevicePrincipal = Depends(get_heartbeat_device),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    result = device_service.ingest_samples(
        db,
        settings,
        principal,
        samples=[s.model_dump() for s in body.samples],
        boot_id=body.boot_id,
        agent_version=body.agent_version,
    )
    # An agent that sends no appliance object gets nothing about it back
    # (docs/appliance.md, section 6): nothing changes for agent 0.1.0.
    # Before the operations: the appliance row is locked first, then operation
    # rows, the same order in which a change made by a person takes them.
    appliance = None
    if body.appliance is not None:
        appliance = appliance_service.heartbeat_exchange(
            db, principal.machine, body.appliance, actor=Actor("device", str(principal.device.id))
        )
    operations = operation_service.pending_for_device(
        db, settings, _provider_or_none(settings), principal.device, principal.machine
    )
    db.commit()
    out = {
        "accepted": result.accepted,
        "duplicates": result.duplicates,
        "rejected": result.rejected,
        "highest_seq": result.highest_seq,
        "server_time": utcnow(),
        "next_interval_s": settings.heartbeat_interval_s,
        "operations": [operation_service.serialize_for_device(op) for op in operations],
    }
    if appliance is not None:
        out["appliance"] = appliance
    return out


@router.get("/device/operations")
def device_operations(
    principal: DevicePrincipal = Depends(get_device),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    operations = operation_service.pending_for_device(
        db, settings, _provider_or_none(settings), principal.device, principal.machine
    )
    db.commit()
    return {"operations": [operation_service.serialize_for_device(op) for op in operations]}


@router.post("/device/operations/{operation_id}/ack")
def acknowledge(
    operation_id: uuid.UUID,
    body: AckIn,
    request: Request,
    principal: DevicePrincipal = Depends(get_device),
    db: Session = Depends(get_db),
):
    operation = operation_service.acknowledge(
        db,
        Actor("device", str(principal.device.id), client_ip(request)),
        principal.device,
        operation_id,
        status=body.status,
        nonce=body.nonce,
        detail=body.detail,
        result=body.result,
    )
    db.commit()
    return {"status": operation.status}


@router.post("/device/credential/rotate")
def rotate(
    request: Request,
    principal: DevicePrincipal = Depends(get_device),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    ratelimit.hit(f"rotate:{principal.device.id}", settings.device_rotation_limit_per_hour, window_s=3600)
    credential, token = device_service.rotate_credential(db, settings, principal, client_ip(request))
    db.commit()
    return {"credential": {"id": str(credential.id), "token": token, "expires_at": None}}


@router.get("/device/self")
def device_self(principal: DevicePrincipal = Depends(get_device), db: Session = Depends(get_db)):
    db.commit()  # persists last_used_at
    return {
        "device_id": str(principal.device.id),
        "machine_id": str(principal.machine.id),
        "status": principal.device.status,
        "server_time": utcnow(),
    }


# --- firmware updates (docs/appliance.md, section 6.6) -----------------------


@router.get("/device/update")
def device_update(
    principal: DevicePrincipal = Depends(get_device),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """The machine's update channel and policy, and the release it may install now, if any."""
    return release_service.offer_for_device(db, settings, principal.machine, principal.device)


@router.get("/device/update/artifact/{version}")
def device_update_artifact(
    version: Annotated[str, Path(max_length=24)],
    principal: DevicePrincipal = Depends(get_device),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """The package of a release offered on this machine's channel. Anything else is not found."""
    # Counted before the session is used: one connection at a time (see deps.get_device).
    ratelimit.hit(f"update-artifact:{principal.device.id}", ARTIFACT_DOWNLOADS_PER_HOUR, window_s=3600)
    data = release_service.artifact_for_device(db, settings, principal.machine, version)
    return Response(content=data, media_type="application/octet-stream")
