"""Provider synchronisation, binding and integration health (admin and auditor)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db import get_db
from ..deps import client_ip, require_admin, require_admin_or_auditor, settings_dep
from ..errors import FeatureDisabled, NotFound, UpstreamUnavailable
from ..models import ProviderAccount, ProviderMachine, SyncRun
from ..providers.registry import get_provider
from ..schemas import BindIn, ImportEarningsIn, ListingIn, MinBidIn
from ..services import provider_control, provider_sync
from ..services.accounts import Principal
from . import views

router = APIRouter(prefix="/api/v1/provider", tags=["provider"])

Limit = Query(50, ge=1, le=200)
Offset = Query(0, ge=0)


def run_view(run: SyncRun) -> dict:
    return {
        "id": str(run.id),
        "kind": run.kind,
        "status": run.status,
        "started_at": views.iso(run.started_at),
        "finished_at": views.iso(run.finished_at),
        "error_code": run.error_code,
        "error": run.error,
        "stats": run.stats,
    }


def _raise_if_failed(run: SyncRun) -> None:
    """A failed or blocked provider call is an error response, never a quiet 200."""
    if run.status == "ok":
        return
    if run.status == "blocked":
        raise FeatureDisabled(run.error, code=run.error_code or "provider_blocked")
    raise UpstreamUnavailable(run.error, code=run.error_code or "provider_unavailable")


@router.get("/health")
def health(
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    return provider_sync.integration_health(db, settings)


@router.post("/check")
def check(
    _: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    provider = get_provider(settings)
    account = provider_sync.ensure_account(db, settings, provider)
    run = provider_sync.check_health(db, provider, account)
    db.commit()
    _raise_if_failed(run)
    return run_view(run)


@router.get("/accounts")
def accounts(_: Principal = Depends(require_admin_or_auditor), db: Session = Depends(get_db)):
    rows = db.execute(select(ProviderAccount).order_by(ProviderAccount.created_at)).scalars().all()
    keys = (
        "id",
        "provider",
        "label",
        "synthetic",
        "last_sync_at",
        "last_sync_ok",
        "failing",
        "last_sync_error",
    )
    items = []
    for account in rows:
        status = provider_sync.account_status(db, account)
        items.append({key: status[key] for key in keys})
    return {"items": items}


@router.post("/sync-machines")
def sync_machines(
    _: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    provider = get_provider(settings)
    account = provider_sync.ensure_account(db, settings, provider)
    run = provider_sync.sync_machines(db, provider, account)
    db.commit()
    _raise_if_failed(run)
    return run_view(run)


@router.get("/machines")
def provider_machines(
    limit: int = Limit,
    offset: int = Offset,
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
):
    query = select(ProviderMachine).order_by(ProviderMachine.external_id)
    return views.page(db, query, limit, offset, views.provider_machine_view)


@router.post("/machines/{provider_machine_id}/bind")
def bind(
    provider_machine_id: uuid.UUID,
    body: BindIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    pm = provider_sync.bind_machine(
        db,
        principal.actor(client_ip(request)),
        provider_machine_id=provider_machine_id,
        machine_id=body.machine_id,
        bound_from=body.bound_from,
        user_id=principal.user.id,
    )
    db.commit()
    return views.provider_machine_view(pm)


@router.post("/machines/{provider_machine_id}/unbind")
def unbind(
    provider_machine_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    pm = provider_sync.unbind_machine(
        db,
        principal.actor(client_ip(request)),
        provider_machine_id=provider_machine_id,
        user_id=principal.user.id,
    )
    db.commit()
    return views.provider_machine_view(pm)


@router.post("/machines/{provider_machine_id}/unlist")
def unlist(
    provider_machine_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Stop new rentals through the provider's own control. Existing rentals are untouched."""
    pm, detail = provider_control.unlist_machine(
        db, principal.actor(client_ip(request)), get_provider(settings), provider_machine_id
    )
    db.commit()
    return {
        **views.provider_machine_view(pm),
        "provider_result": detail,
        "verified_unlisted": pm.listed is False,
        "note": "Unlisting stops new rentals only. It is not permission to interrupt existing rentals.",
    }


@router.get("/machines/{provider_machine_id}")
def provider_machine(
    provider_machine_id: uuid.UUID,
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
):
    pm = db.get(ProviderMachine, provider_machine_id)
    if pm is None:
        raise NotFound()
    return views.provider_machine_view(pm)


@router.get("/machines/{provider_machine_id}/reports")
def provider_machine_reports(
    provider_machine_id: uuid.UUID,
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """What renters reported about the machine, straight from the provider (read-only)."""
    reports = provider_control.reports(db, get_provider(settings), provider_machine_id)
    return {
        "items": [{"problem": r.problem, "message": r.message, "created_at": r.created_at} for r in reports],
        "count": len(reports),
    }


@router.post("/machines/{provider_machine_id}/list")
def list_machine(
    provider_machine_id: uuid.UUID,
    body: ListingIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Create or replace the machine's offer (prices and end date). Running
    contracts keep their terms; a later end date may extend them."""
    pm, detail = provider_control.list_machine(
        db, principal.actor(client_ip(request)), get_provider(settings), provider_machine_id, body
    )
    db.commit()
    return {
        **views.provider_machine_view(pm),
        "provider_result": detail,
        "note": "The provider exposes no listed flag; the next machine sync refreshes the prices shown.",
    }


@router.post("/machines/{provider_machine_id}/min-bid")
def set_min_bid(
    provider_machine_id: uuid.UUID,
    body: MinBidIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Floor price for interruptible rentals, $/GPU/hour. New rentals only."""
    pm, detail = provider_control.set_min_bid(
        db, principal.actor(client_ip(request)), get_provider(settings), provider_machine_id, body.price
    )
    db.commit()
    return {**views.provider_machine_view(pm), "provider_result": detail}


@router.post("/machines/{provider_machine_id}/cancel-maintenance")
def cancel_maintenance(
    provider_machine_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Cancel an upcoming or ongoing maintenance window this account scheduled."""
    pm, detail = provider_control.cancel_maintenance(
        db, principal.actor(client_ip(request)), get_provider(settings), provider_machine_id
    )
    db.commit()
    return {**views.provider_machine_view(pm), "provider_result": detail}


@router.post("/import-earnings")
def import_earnings(
    body: ImportEarningsIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Pull provider earnings for closed UTC days. Owners cannot submit earnings."""
    provider = get_provider(settings)
    account = provider_sync.ensure_account(db, settings, provider)
    run, imp = provider_sync.run_earnings_import(
        db,
        principal.actor(client_ip(request)),
        provider,
        account,
        start=body.start,
        end=body.end,
        user_id=principal.user.id,
    )
    db.commit()
    _raise_if_failed(run)
    return {
        "run": run_view(run),
        "import": None
        if imp is None
        else {
            "id": str(imp.id),
            "status": imp.status,
            "posted": imp.status == "posted",
            "stats": imp.stats,
            "synthetic": imp.is_synthetic,
        },
    }


@router.get("/runs")
def runs(
    limit: int = Limit,
    offset: int = Offset,
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
):
    return views.page(db, select(SyncRun).order_by(SyncRun.started_at.desc()), limit, offset, run_view)
