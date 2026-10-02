"""Signed firmware releases and their channels (docs/appliance.md, section 9).

Staff only: admins publish, auditors read. A machine fetches releases through
the device routes (``routers/device.py``), never through these.
"""

from __future__ import annotations

import hashlib
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from starlette.requests import ClientDisconnect

from ..config import Settings
from ..db import get_db
from ..deps import client_ip, require_admin, require_admin_or_auditor, settings_dep
from ..errors import InvalidRequest, PayloadTooLarge
from ..schemas_appliance import ChannelsIn, ReleaseIn, WithdrawIn
from ..services import releases as release_service
from ..services.accounts import Principal

router = APIRouter(prefix="/api/v1", tags=["releases"])

Version = Annotated[str, Path(max_length=24)]
ARTIFACT_CONTENT_TYPE = "application/octet-stream"


@router.get("/releases")
def list_releases(_: Principal = Depends(require_admin_or_auditor), db: Session = Depends(get_db)):
    return {"items": [release_service.release_view(r) for r in release_service.list_releases(db)]}


@router.post("/releases", status_code=201)
def create_release(
    body: ReleaseIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """First step of publishing: the signed manifest. Refused unless the signature
    verifies against a key in ``HM_RELEASE_PUBLIC_KEYS``."""
    release = release_service.create_release(
        db,
        settings,
        principal.actor(client_ip(request)),
        manifest_b64=body.manifest_b64,
        signature_b64=body.signature_b64,
        user_id=principal.user.id,
    )
    db.commit()
    return release_service.release_view(release)


@router.put("/releases/{version}/artifact")
async def upload_artifact(
    version: Version,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Second step: the package itself, as the raw request body.

    Who is asking and whether a package is expected at all are settled before
    the first byte of the body is read. The body is then read as a stream and
    reading stops at the first byte beyond the size the signed manifest states.
    Nothing is stored unless size and SHA-256 match the manifest.
    """
    actor = principal.actor(client_ip(request))

    def expectation() -> tuple[int, str]:
        try:
            return release_service.expect_artifact(db, settings, version)
        finally:
            db.rollback()  # nothing is held while the upload is in progress

    size, _sha256 = await run_in_threadpool(expectation)
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != ARTIFACT_CONTENT_TYPE:
        raise InvalidRequest(
            f"the package is sent as the raw request body, Content-Type: {ARTIFACT_CONTENT_TYPE}"
        )
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) != size):
        raise InvalidRequest("the package does not have the size stated in the manifest")

    limit = min(size, settings.release_max_bytes)
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    received = 0
    try:
        async for chunk in request.stream():
            received += len(chunk)
            if received > limit:
                raise InvalidRequest("the package is larger than the size stated in the manifest")
            digest.update(chunk)
            chunks.append(chunk)
    except ClientDisconnect as exc:
        # The connection went away, or the body limit of the application cut it off.
        raise PayloadTooLarge("the upload was interrupted or is too large") from exc
    data = b"".join(chunks)

    def store():
        release = release_service.store_artifact(db, settings, actor, version, data)
        db.commit()
        return release_service.release_view(release)

    return await run_in_threadpool(store)


@router.post("/releases/{version}/channels")
def set_channels(
    version: Version,
    body: ChannelsIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Offer a ready release on exactly these channels (``beta``, ``stable``; an empty list: none)."""
    release = release_service.set_channels(
        db, settings, principal.actor(client_ip(request)), version, body.channels
    )
    db.commit()
    return release_service.release_view(release)


@router.post("/releases/{version}/withdraw")
def withdraw(
    version: Version,
    body: WithdrawIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    release = release_service.withdraw(db, principal.actor(client_ip(request)), version, body.reason)
    db.commit()
    return release_service.release_view(release)
