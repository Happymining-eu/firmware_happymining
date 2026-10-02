"""Appliance configuration of a machine: mode, plugins, NAS, vectorization, backup,
schedules, updates and sealed secrets (docs/appliance.md, section 12).

Every route loads the machine through the tenant scope first (another owner's
machine does not exist for an owner's user), then asks ``services/access.py``
whether this caller may see or change it: an organisation role for the owner's
people; for HappyMining staff, a company-managed machine or a remote-access
grant. Nothing a device reports is consulted for that.

Every change may carry the revision it was based on in ``If-Match``; a
concurrent change then answers ``409 conflict`` instead of being overwritten.
The answer to a change is the same representation as ``GET``, with the new
revision in ``ETag``. Secrets appear in it as names, never as values.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Path, Request, Response
from sqlalchemy.orm import Session

from ..config import Settings
from ..db import get_db
from ..deps import client_ip, get_principal, load_machine, require_any, settings_dep
from ..errors import Conflict, Forbidden, InvalidRequest
from ..models import Machine
from ..providers.registry import get_provider
from ..schemas_appliance import (
    BackupIn,
    InstallUpdateIn,
    JobIn,
    ModeIn,
    NasIn,
    PluginIn,
    ScheduleIn,
    UpdateIn,
    VectorizerIn,
)
from ..services import access
from ..services import appliance as appliance_service
from ..services import releases as release_service
from ..services.accounts import Principal
from ..services.catalog import get_catalog
from ..services.maintenance import describe_blocked
from . import views

router = APIRouter(prefix="/api/v1", tags=["appliance"])


def may_change(minimum_org_role: str):
    """A change is for the owner's organisation, from this role up, and for HappyMining admins.

    Decided here, before the body is looked at: a viewer or an auditor is told
    "forbidden", not what is wrong with a request they may not make anyway.
    Whether this caller may change *this machine* (the owner's own machine;
    for staff, a company-managed machine or a remote-access grant) is checked
    in the route, once the machine is loaded.
    """

    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if principal.role == "owner":
            access.require_org_role(principal, minimum_org_role)
        elif principal.role != "admin":
            raise Forbidden()
        return principal

    return dependency


operator = may_change("org_operator")
administrator = may_change("org_admin")

# Ids travel in the path and have the shape the document gives them.
EntryId = Annotated[str, Path(pattern=r"^[a-z][a-z0-9-]{0,30}$")]
IfMatch = Annotated[str | None, Header(max_length=40)]


def _expected_revision(if_match: str | None) -> int | None:
    """``If-Match: 12`` or ``If-Match: "12"``: the revision the caller's change is based on."""
    if if_match is None:
        return None
    text = if_match.strip().removeprefix("W/").strip('"')
    if not text.isdigit() or len(text) > 10:
        raise InvalidRequest("If-Match must be the revision the change is based on, as a number")
    return int(text)


def _provider_or_none(settings: Settings):
    try:
        return get_provider(settings)
    except Exception:
        # Without a provider the rental-protection gate blocks.
        return None


def _machine(db: Session, principal: Principal, machine_id: uuid.UUID, minimum_org_role: str) -> Machine:
    """The machine, locked, for a caller who may change it."""
    machine = load_machine(db, principal, machine_id, lock=True)
    access.require_manage(db, principal, machine, minimum_org_role)
    return machine


def _answer(
    db: Session, settings: Settings, principal: Principal, machine: Machine, response: Response
) -> dict[str, Any]:
    out = appliance_service.view(db, settings, principal, machine)
    response.headers["ETag"] = f'"{out["revision"]}"'
    return out


def _commit(
    db: Session, settings: Settings, principal: Principal, machine: Machine, response: Response
) -> dict[str, Any]:
    """Commit a change and answer with what it produced.

    The answer is built inside the transaction that made the change, while the
    row is still locked: its revision and ETag are those of this change, not
    of one that another request committed a moment later.
    """
    out = _answer(db, settings, principal, machine, response)
    db.commit()
    return out


def _given(model: Any, *, without: tuple[str, ...] = ()) -> dict[str, Any]:
    """The fields the caller actually sent, as they go into the document."""
    return model.model_dump(exclude_none=True, exclude=set(without))


# --- reading ---------------------------------------------------------------


@router.get("/appliance/catalog")
def catalog(_: Principal = Depends(require_any), settings: Settings = Depends(settings_dep)):
    """The plugins this control plane knows, with their settings and the secrets they take."""
    return {"items": get_catalog(settings).public()}


@router.get("/machines/{machine_id}/appliance")
def get_appliance(
    machine_id: uuid.UUID,
    response: Response,
    principal: Principal = Depends(require_any),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = load_machine(db, principal, machine_id)
    access.require_view(db, principal, machine)
    return _answer(db, settings, principal, machine, response)


# --- mode ------------------------------------------------------------------


@router.put("/machines/{machine_id}/appliance/mode")
def put_mode(
    machine_id: uuid.UUID,
    body: ModeIn,
    request: Request,
    response: Response,
    if_match: IfMatch = None,
    principal: Principal = Depends(administrator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Change the mode. Leaving ``vast`` on a machine bound to a provider machine passes the
    rental-protection gate; a refusal is recorded and answered ``409 maintenance_blocked``."""
    machine = _machine(db, principal, machine_id, "org_admin")
    change = appliance_service.set_mode(
        db,
        settings,
        principal.actor(client_ip(request)),
        _provider_or_none(settings),
        machine,
        mode=body.mode,
        user_id=principal.user.id,
        expected_revision=_expected_revision(if_match),
    )
    if change.blocked is not None:
        # Recorded (audit trail), then reported as an error. A blocked change never looks like a success.
        db.commit()
        raise Conflict(describe_blocked(change.blocked), code="maintenance_blocked")
    return _commit(db, settings, principal, machine, response)


# --- plugins ---------------------------------------------------------------


@router.put("/machines/{machine_id}/appliance/plugins/{plugin_id}")
def put_plugin(
    machine_id: uuid.UUID,
    plugin_id: EntryId,
    body: PluginIn,
    request: Request,
    response: Response,
    if_match: IfMatch = None,
    principal: Principal = Depends(operator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    # Enabling and configuring a plugin is an operator's work. Secrets are an administrator's.
    machine = _machine(db, principal, machine_id, "org_admin" if body.sealed_secrets else "org_operator")
    appliance_service.set_plugin(
        db,
        settings,
        principal.actor(client_ip(request)),
        machine,
        plugin_id,
        enabled=body.enabled,
        values=body.settings,
        sealed_secrets=body.sealed_secrets,
        user_id=principal.user.id,
        expected_revision=_expected_revision(if_match),
    )
    return _commit(db, settings, principal, machine, response)


@router.delete("/machines/{machine_id}/appliance/plugins/{plugin_id}")
def delete_plugin(
    machine_id: uuid.UUID,
    plugin_id: EntryId,
    request: Request,
    response: Response,
    if_match: IfMatch = None,
    principal: Principal = Depends(operator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = _machine(db, principal, machine_id, "org_operator")
    appliance_service.remove_plugin(
        db,
        settings,
        principal.actor(client_ip(request)),
        machine,
        plugin_id,
        user_id=principal.user.id,
        expected_revision=_expected_revision(if_match),
    )
    return _commit(db, settings, principal, machine, response)


# --- NAS -------------------------------------------------------------------


@router.put("/machines/{machine_id}/appliance/nas/{nas_id}")
def put_nas(
    machine_id: uuid.UUID,
    nas_id: EntryId,
    body: NasIn,
    request: Request,
    response: Response,
    if_match: IfMatch = None,
    principal: Principal = Depends(administrator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = _machine(db, principal, machine_id, "org_admin")
    appliance_service.set_nas(
        db,
        settings,
        principal.actor(client_ip(request)),
        machine,
        nas_id,
        entry=_given(body, without=("sealed_secret",)),
        sealed_secret=body.sealed_secret,
        user_id=principal.user.id,
        expected_revision=_expected_revision(if_match),
    )
    return _commit(db, settings, principal, machine, response)


@router.delete("/machines/{machine_id}/appliance/nas/{nas_id}")
def delete_nas(
    machine_id: uuid.UUID,
    nas_id: EntryId,
    request: Request,
    response: Response,
    if_match: IfMatch = None,
    principal: Principal = Depends(administrator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = _machine(db, principal, machine_id, "org_admin")
    appliance_service.remove_nas(
        db,
        settings,
        principal.actor(client_ip(request)),
        machine,
        nas_id,
        user_id=principal.user.id,
        expected_revision=_expected_revision(if_match),
    )
    return _commit(db, settings, principal, machine, response)


# --- vectorization ---------------------------------------------------------


@router.put("/machines/{machine_id}/appliance/vectorizer")
def put_vectorizer(
    machine_id: uuid.UUID,
    body: VectorizerIn,
    request: Request,
    response: Response,
    if_match: IfMatch = None,
    principal: Principal = Depends(administrator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = _machine(db, principal, machine_id, "org_admin")
    section = _given(body)
    section["answer"].pop("sealed_secret", None)
    appliance_service.set_vectorizer(
        db,
        settings,
        principal.actor(client_ip(request)),
        machine,
        section=section,
        sealed_secret=body.answer.sealed_secret,
        user_id=principal.user.id,
        expected_revision=_expected_revision(if_match),
    )
    return _commit(db, settings, principal, machine, response)


@router.delete("/machines/{machine_id}/appliance/vectorizer")
def delete_vectorizer(
    machine_id: uuid.UUID,
    request: Request,
    response: Response,
    if_match: IfMatch = None,
    principal: Principal = Depends(administrator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = _machine(db, principal, machine_id, "org_admin")
    appliance_service.remove_vectorizer(
        db,
        settings,
        principal.actor(client_ip(request)),
        machine,
        user_id=principal.user.id,
        expected_revision=_expected_revision(if_match),
    )
    return _commit(db, settings, principal, machine, response)


# --- backup ----------------------------------------------------------------


@router.put("/machines/{machine_id}/appliance/backup")
def put_backup(
    machine_id: uuid.UUID,
    body: BackupIn,
    request: Request,
    response: Response,
    if_match: IfMatch = None,
    principal: Principal = Depends(administrator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = _machine(db, principal, machine_id, "org_admin")
    section = _given(body)
    section["destination"].pop("sealed_secret", None)
    appliance_service.set_backup(
        db,
        settings,
        principal.actor(client_ip(request)),
        machine,
        section=section,
        sealed_secret=body.destination.sealed_secret,
        user_id=principal.user.id,
        expected_revision=_expected_revision(if_match),
    )
    return _commit(db, settings, principal, machine, response)


@router.delete("/machines/{machine_id}/appliance/backup")
def delete_backup(
    machine_id: uuid.UUID,
    request: Request,
    response: Response,
    if_match: IfMatch = None,
    principal: Principal = Depends(administrator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = _machine(db, principal, machine_id, "org_admin")
    appliance_service.remove_backup(
        db,
        settings,
        principal.actor(client_ip(request)),
        machine,
        user_id=principal.user.id,
        expected_revision=_expected_revision(if_match),
    )
    return _commit(db, settings, principal, machine, response)


# --- schedules -------------------------------------------------------------


@router.put("/machines/{machine_id}/appliance/schedules/{schedule_id}")
def put_schedule(
    machine_id: uuid.UUID,
    schedule_id: EntryId,
    body: ScheduleIn,
    request: Request,
    response: Response,
    if_match: IfMatch = None,
    principal: Principal = Depends(operator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = _machine(db, principal, machine_id, "org_operator")
    appliance_service.set_schedule(
        db,
        settings,
        principal.actor(client_ip(request)),
        machine,
        schedule_id,
        entry=_given(body),
        user_id=principal.user.id,
        expected_revision=_expected_revision(if_match),
    )
    return _commit(db, settings, principal, machine, response)


@router.delete("/machines/{machine_id}/appliance/schedules/{schedule_id}")
def delete_schedule(
    machine_id: uuid.UUID,
    schedule_id: EntryId,
    request: Request,
    response: Response,
    if_match: IfMatch = None,
    principal: Principal = Depends(operator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = _machine(db, principal, machine_id, "org_operator")
    appliance_service.remove_schedule(
        db,
        settings,
        principal.actor(client_ip(request)),
        machine,
        schedule_id,
        user_id=principal.user.id,
        expected_revision=_expected_revision(if_match),
    )
    return _commit(db, settings, principal, machine, response)


# --- update policy ---------------------------------------------------------


@router.put("/machines/{machine_id}/appliance/update")
def put_update(
    machine_id: uuid.UUID,
    body: UpdateIn,
    request: Request,
    response: Response,
    if_match: IfMatch = None,
    principal: Principal = Depends(administrator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = _machine(db, principal, machine_id, "org_admin")
    appliance_service.set_update(
        db,
        settings,
        principal.actor(client_ip(request)),
        machine,
        section=_given(body),
        user_id=principal.user.id,
        expected_revision=_expected_revision(if_match),
    )
    return _commit(db, settings, principal, machine, response)


# --- jobs and updates: typed operations ------------------------------------


@router.post("/machines/{machine_id}/appliance/jobs", status_code=201)
def run_job(
    machine_id: uuid.UUID,
    body: JobIn,
    request: Request,
    principal: Principal = Depends(operator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Run one appliance job now. It reaches the machine as the typed operation ``appliance_run_job``."""
    machine = _machine(db, principal, machine_id, "org_operator")
    operation = appliance_service.request_job(
        db,
        settings,
        principal.actor(client_ip(request)),
        _provider_or_none(settings),
        machine,
        job=body.job,
        plugin=body.plugin,
        user_id=principal.user.id,
    )
    db.commit()
    return views.operation_view(operation)


@router.post("/machines/{machine_id}/appliance/install-update", status_code=201)
def install_update(
    machine_id: uuid.UUID,
    body: InstallUpdateIn,
    request: Request,
    principal: Principal = Depends(administrator),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Install one published release. It reaches the machine as the typed operation ``install_update``."""
    machine = _machine(db, principal, machine_id, "org_admin")
    operation = release_service.request_install(
        db,
        settings,
        principal.actor(client_ip(request)),
        _provider_or_none(settings),
        machine,
        version=body.version,
        user_id=principal.user.id,
    )
    db.commit()
    return views.operation_view(operation)
