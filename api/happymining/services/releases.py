"""Signed firmware releases (docs/appliance.md, sections 6.6 and 9).

A release is the agent package and a manifest signed with a key that is not
on this server. The API checks the signature before it accepts a manifest,
and the package against the manifest before it stores it, so that a staff
session alone cannot publish firmware: without the signing key there is
nothing to upload that a machine would install. The machine checks all of it
again with the keys installed on it.

Steps: manifest and signature (``awaiting_artifact``) -> package (``ready``)
-> channels. A release can be withdrawn; it is then offered to nobody.

Only a release whose signing key is *still* configured is offered or
installed. Taking a key out of ``HM_RELEASE_PUBLIC_KEYS`` therefore stops the
distribution of everything signed with it, which is what an operator needs
when a signing key is lost.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import uuid
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..config import Settings
from ..errors import Conflict, InvalidRequest, NotFound
from ..models import RELEASE_CHANNELS, Device, Machine, Operation, Release, utcnow
from ..providers.base import Provider
from ..sealing import MAX_MANIFEST_BYTES, load_release_public_keys, parse_version, verify_manifest
from . import appliance as appliance_service
from . import operations as operation_service

NO_KEYS = "release_keys_not_configured"


def trusted_keys(settings: Settings) -> dict[str, Ed25519PublicKey]:
    """The keys a release must be signed with. Empty: nothing can be published or offered."""
    try:
        return load_release_public_keys(settings.release_public_keys)
    except InvalidRequest as exc:
        # A mistake in this server's configuration, not in the request.
        raise Conflict("HM_RELEASE_PUBLIC_KEYS is not valid: " + exc.message, code=NO_KEYS) from exc


def _signature_holds(release: Release, keys: dict[str, Ed25519PublicKey]) -> bool:
    key = keys.get(release.key_id)
    if key is None:
        return False
    try:
        key.verify(base64.b64decode(release.signature, validate=True), bytes(release.manifest))
    except (InvalidSignature, ValueError):
        return False
    return True


def _get(db: Session, version: str, *, lock: bool = False) -> Release:
    try:
        parse_version(version)
    except InvalidRequest as exc:
        raise NotFound("no such release") from exc
    query = select(Release).where(Release.version == version)
    if lock:
        query = query.with_for_update().execution_options(populate_existing=True)
    release = db.execute(query).scalar_one_or_none()
    if release is None:
        raise NotFound("no such release")
    return release


def release_view(release: Release) -> dict[str, Any]:
    """What staff see of a release. Never the package itself."""
    return {
        "version": release.version,
        "status": release.status,
        "channels": list(release.channels or ()),
        "filename": release.filename,
        "size": release.size,
        "sha256": release.sha256,
        "key_id": release.key_id,
        "min_upgrade_from": release.min_upgrade_from,
        "notes": release.notes,
        "created_at": release.created_at.isoformat(),
        "created_by": str(release.created_by) if release.created_by else None,
        "published_at": release.published_at.isoformat() if release.published_at else None,
        "withdrawn_at": release.withdrawn_at.isoformat() if release.withdrawn_at else None,
    }


def list_releases(db: Session) -> list[Release]:
    return list(
        db.execute(
            select(Release).order_by(Release.v_major.desc(), Release.v_minor.desc(), Release.v_patch.desc())
        ).scalars()
    )


# --- publishing ------------------------------------------------------------


def create_release(
    db: Session,
    settings: Settings,
    actor: Actor,
    *,
    manifest_b64: str,
    signature_b64: str,
    user_id: uuid.UUID | None,
) -> Release:
    """Accept a signed manifest. The package follows in a second step."""
    keys = trusted_keys(settings)
    if not keys:
        raise Conflict(
            "no release public key is configured (HM_RELEASE_PUBLIC_KEYS); nothing can be published",
            code=NO_KEYS,
        )
    try:
        raw = base64.b64decode(manifest_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidRequest("manifest_b64 is not base64") from exc
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise InvalidRequest("the manifest is empty or larger than 16 KiB")
    manifest = verify_manifest(raw, signature_b64, keys)
    if manifest.size > settings.release_max_bytes:
        raise InvalidRequest(
            f"the package is {manifest.size} bytes; this server accepts at most "
            f"{settings.release_max_bytes} (HM_RELEASE_MAX_BYTES)"
        )
    major, minor, patch = parse_version(manifest.version)
    if db.execute(select(Release.id).where(Release.version == manifest.version)).first() is not None:
        raise Conflict("a release with this version already exists; a version is published once")
    release = Release(
        version=manifest.version,
        v_major=major,
        v_minor=minor,
        v_patch=patch,
        manifest=raw,  # byte for byte: the signature covers exactly these bytes
        signature=signature_b64,
        key_id=manifest.key_id,
        filename=manifest.filename,
        size=manifest.size,
        sha256=manifest.sha256,
        min_upgrade_from=manifest.min_upgrade_from,
        notes=manifest.notes,
        status="awaiting_artifact",
        channels=[],
        created_by=user_id,
    )
    try:
        with db.begin_nested():
            db.add(release)
            db.flush()
    except IntegrityError as exc:
        # The same version arrived twice at the same moment; the other one won.
        raise Conflict("a release with this version already exists; a version is published once") from exc
    audit(
        db,
        actor,
        "release.create",
        object_type="release",
        object_id=release.id,
        details={
            "version": release.version,
            "key_id": release.key_id,
            "filename": release.filename,
            "size": release.size,
            "sha256": release.sha256,
            "min_upgrade_from": release.min_upgrade_from,
        },
    )
    return release


def expect_artifact(db: Session, settings: Settings, version: str) -> tuple[int, str]:
    """What the package of this release must be: (size, SHA-256). Called before any of it is read."""
    release = _get(db, version)
    if release.status != "awaiting_artifact":
        raise Conflict(f"this release is {release.status}; its package cannot be replaced")
    if not _signature_holds(release, trusted_keys(settings)):
        raise Conflict("the manifest of this release is not signed with a key this server trusts any more")
    if release.size > settings.release_max_bytes:
        raise InvalidRequest("the package is larger than this server accepts (HM_RELEASE_MAX_BYTES)")
    return release.size, release.sha256


def store_artifact(db: Session, settings: Settings, actor: Actor, version: str, data: bytes) -> Release:
    """Store the package once it is exactly what the signed manifest describes."""
    release = _get(db, version, lock=True)
    if release.status != "awaiting_artifact":
        raise Conflict(f"this release is {release.status}; its package cannot be replaced")
    if not _signature_holds(release, trusted_keys(settings)):
        raise Conflict("the manifest of this release is not signed with a key this server trusts any more")
    if len(data) != release.size:
        raise InvalidRequest("the package does not have the size stated in the manifest")
    if hashlib.sha256(data).hexdigest() != release.sha256:
        raise InvalidRequest("the package does not have the SHA-256 stated in the manifest")
    release.artifact = data
    release.status = "ready"
    db.flush()
    audit(
        db,
        actor,
        "release.artifact",
        object_type="release",
        object_id=release.id,
        details={"version": release.version, "size": release.size, "sha256": release.sha256},
    )
    return release


def set_channels(db: Session, settings: Settings, actor: Actor, version: str, channels: list[str]) -> Release:
    """Offer a ready release on exactly these channels (an empty list: on none)."""
    unknown = sorted(set(channels) - set(RELEASE_CHANNELS))
    if unknown or len(set(channels)) != len(channels):
        raise InvalidRequest("channels must be distinct values from: " + ", ".join(RELEASE_CHANNELS))
    release = _get(db, version, lock=True)
    if release.status != "ready":
        raise Conflict(f"this release is {release.status}; only a ready release can be put on a channel")
    wanted = [channel for channel in RELEASE_CHANNELS if channel in channels]
    if wanted and not _signature_holds(release, trusted_keys(settings)):
        raise Conflict("the manifest of this release is not signed with a key this server trusts any more")
    before = list(release.channels or ())
    release.channels = wanted
    if wanted and release.published_at is None:
        release.published_at = utcnow()
    db.flush()
    audit(
        db,
        actor,
        "release.channels",
        object_type="release",
        object_id=release.id,
        details={"version": release.version, "from": before, "to": wanted},
    )
    return release


def withdraw(db: Session, actor: Actor, version: str, reason: str) -> Release:
    """Stop offering a release. Updates not yet handed to a machine are cancelled."""
    if not reason.strip():
        raise InvalidRequest("a reason is required")
    release = _get(db, version, lock=True)
    if release.status == "withdrawn":
        raise Conflict("this release is already withdrawn")
    if release.status != "ready":
        raise Conflict("this release has no package yet; it is not offered to any machine")
    now = utcnow()
    release.status = "withdrawn"
    release.withdrawn_at = now
    cancelled = (
        db.execute(
            update(Operation)
            .where(
                Operation.type == "install_update",
                Operation.status == "pending",
                Operation.params["version"].astext == release.version,
            )
            .values(status="cancelled", completed_at=now, detail="the release was withdrawn")
        ).rowcount
        or 0
    )
    db.flush()
    audit(
        db,
        actor,
        "release.withdraw",
        object_type="release",
        object_id=release.id,
        details={
            "version": release.version,
            "reason": reason[:300],
            "channels": list(release.channels or ()),
            "operations_cancelled": cancelled,
        },
    )
    return release


# --- what a machine is offered ---------------------------------------------


def _version_of(text: str) -> tuple[int, int, int] | None:
    try:
        return parse_version(text)
    except InvalidRequest:
        return None


def _offered(release: Release, channel: str, keys: dict[str, Ed25519PublicKey]) -> bool:
    return (
        release.status == "ready" and channel in (release.channels or ()) and _signature_holds(release, keys)
    )


def _installable_from(release: Release, installed: tuple[int, int, int]) -> bool:
    """Newer than what the machine runs, and reachable from it in one step."""
    minimum = _version_of(release.min_upgrade_from)
    return (release.v_major, release.v_minor, release.v_patch) > installed and (
        minimum is not None and minimum <= installed
    )


def offer_for_device(db: Session, settings: Settings, machine: Machine, device: Device) -> dict[str, Any]:
    """The answer to ``GET /api/v1/device/update`` (section 6.6).

    ``release`` is the newest release on the machine's channel that is newer
    than the agent version the device last reported and that may be installed
    over it; null when there is none, when the machine has no channel, or when
    the device's version cannot be compared.
    """
    wanted = appliance_service.update_settings(db, machine)
    out: dict[str, Any] = {**wanted, "release": None}
    installed = _version_of(device.agent_version or "")
    if wanted["channel"] not in RELEASE_CHANNELS or installed is None:
        return out
    keys = trusted_keys(settings)
    for release in list_releases(db):  # newest first
        if _offered(release, wanted["channel"], keys) and _installable_from(release, installed):
            out["release"] = {
                "version": release.version,
                "manifest_b64": base64.b64encode(bytes(release.manifest)).decode(),
                "signature_b64": release.signature,
                "size": release.size,
                "sha256": release.sha256,
                "artifact_path": f"/api/v1/device/update/artifact/{release.version}",
            }
            break
    return out


def artifact_for_device(db: Session, settings: Settings, machine: Machine, version: str) -> bytes:
    """The package bytes, for a machine whose channel carries this release. Otherwise: not found."""
    release = _get(db, version)
    channel = appliance_service.update_settings(db, machine)["channel"]
    if channel not in RELEASE_CHANNELS or not _offered(release, channel, trusted_keys(settings)):
        raise NotFound("no such release")
    data = release.artifact  # loaded only now
    if data is None:
        raise NotFound("no such release")
    return bytes(data)


def request_install(
    db: Session,
    settings: Settings,
    actor: Actor,
    provider: Provider | None,
    machine: Machine,
    *,
    version: str,
    user_id: uuid.UUID | None,
) -> Operation:
    """Queue ``install_update`` for a release this machine can actually fetch and install."""
    release = _get(db, version)
    if release.status != "ready":
        raise Conflict(
            f"release {release.version} is {release.status.replace('_', ' ')}; it cannot be installed"
        )
    device = db.execute(select(Device).where(Device.machine_id == machine.id)).scalar_one_or_none()
    if device is None or device.status != "active":
        raise Conflict("this machine has no active paired device")
    installed = _version_of(device.agent_version or "")
    if installed is None:
        raise Conflict("the machine has not reported an agent version this release can be compared with")
    if (release.v_major, release.v_minor, release.v_patch) <= installed:
        raise Conflict(
            f"the machine runs {device.agent_version}; "
            "only a newer release can be installed, never an older one"
        )
    if not _installable_from(release, installed):
        raise Conflict(
            f"release {release.version} can only be installed over {release.min_upgrade_from} or newer; "
            f"the machine runs {device.agent_version}"
        )
    # The machine downloads the package itself, from its own channel only.
    channel = appliance_service.update_settings(db, machine)["channel"]
    if channel not in RELEASE_CHANNELS or not _offered(release, channel, trusted_keys(settings)):
        raise Conflict(
            f"release {release.version} is not offered on this machine's update channel ({channel}); "
            "the machine could not download it"
        )
    # The machine receives only the newest release it is offered, with that
    # release's manifest and signature (offer_for_device): asked for another
    # one, it could only fail. Refused here instead of failing on the machine.
    offered = offer_for_device(db, settings, machine, device)["release"]
    if offered is None or offered["version"] != release.version:
        newest = offered["version"] if offered else "none"
        raise Conflict(
            f"release {release.version} is not the one this machine is offered ({newest}); "
            "a machine installs only the newest release its channel offers it"
        )
    return operation_service.request_operation(
        db,
        settings,
        actor,
        provider,
        machine=machine,
        op_type="install_update",
        params={"version": release.version},
        requested_by=user_id,
        via_appliance=True,
    )
