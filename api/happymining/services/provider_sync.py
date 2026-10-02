"""Provider synchronisation, machine binding and integration health."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..config import Settings
from ..db import lock_row
from ..errors import Conflict, InvalidRequest, NotFound
from ..models import (
    EarningBucket,
    EarningsImport,
    Machine,
    PayoutItem,
    ProviderAccount,
    ProviderBindingEvent,
    ProviderMachine,
    SourceSnapshot,
    SyncRun,
    utcnow,
)
from ..providers.base import Provider, ProviderError
from .earnings import import_earnings
from .ledger import ZERO, owner_balances


def ensure_account(db: Session, settings: Settings, provider: Provider) -> ProviderAccount:
    """The provider account row for the configured adapter (created on first use)."""
    label = "Synthetic demo account" if provider.is_synthetic else "Vast.ai host account"
    account = db.execute(
        select(ProviderAccount).where(
            ProviderAccount.provider == provider.name, ProviderAccount.label == label
        )
    ).scalar_one_or_none()
    if account is None:
        account = ProviderAccount(provider=provider.name, label=label, is_synthetic=provider.is_synthetic)
        db.add(account)
        db.flush()
    return account


def _run(db: Session, account: ProviderAccount, kind: str) -> SyncRun:
    run = SyncRun(provider_account_id=account.id, kind=kind, status="ok", started_at=utcnow())
    db.add(run)
    db.flush()
    return run


def _fail(db: Session, account: ProviderAccount, run: SyncRun, exc: ProviderError) -> SyncRun:
    blocked = exc.code in (
        "provider_not_configured",
        "commercial_authorization_unverified",
        "provider_feature_disabled",
    )
    run.status = "blocked" if blocked else "error"
    run.error_code = exc.code
    run.error = exc.message[:500]
    run.finished_at = utcnow()
    account.last_sync_at = run.finished_at
    account.last_sync_ok = False
    account.last_sync_error = f"{exc.code}: {exc.message}"[:500]
    db.flush()
    return run


def _ok(db: Session, account: ProviderAccount, run: SyncRun, stats: dict[str, Any]) -> SyncRun:
    run.stats = stats
    run.finished_at = utcnow()
    account.last_sync_at = run.finished_at
    account.last_sync_ok = True
    account.last_sync_error = ""
    db.flush()
    return run


def check_health(db: Session, provider: Provider, account: ProviderAccount) -> SyncRun:
    run = _run(db, account, "health")
    try:
        health = provider.check_health()
    except ProviderError as exc:
        return _fail(db, account, run, exc)
    if health.account_id and not account.external_account_id:
        account.external_account_id = health.account_id[:120]
    return _ok(db, account, run, {"detail": health.detail, "account_id": health.account_id})


def sync_machines(db: Session, provider: Provider, account: ProviderAccount) -> SyncRun:
    """Refresh the provider's machine inventory. Never binds anything by itself."""
    run = _run(db, account, "machines")
    try:
        listing = provider.list_machines()
    except ProviderError as exc:
        return _fail(db, account, run, exc)

    db.add(
        SourceSnapshot(
            provider_account_id=account.id,
            kind="machines",
            sha256=hashlib.sha256(listing.raw_body).hexdigest(),
            body=listing.raw_body,
            is_synthetic=provider.is_synthetic,
            fetched_at=listing.fetched_at,
        )
    )
    known = {
        pm.external_id: pm
        for pm in db.execute(
            select(ProviderMachine)
            .where(ProviderMachine.provider_account_id == account.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalars()
    }
    seen: set[str] = set()
    created = 0
    for info in listing.machines:
        seen.add(info.external_id)
        pm = known.get(info.external_id)
        if pm is None:
            pm = ProviderMachine(provider_account_id=account.id, external_id=info.external_id)
            db.add(pm)
            created += 1
        pm.hostname = info.hostname
        pm.gpu_name = info.gpu_name
        pm.num_gpus = info.num_gpus
        pm.snapshot = info.raw
        pm.last_seen_at = listing.fetched_at
        pm.missing_since = None
        if info.rental is not None:
            pm.rental_state = info.rental.state
            pm.listed = info.rental.listed
            pm.state_detail = info.rental.detail[:500]
            pm.state_observed_at = info.rental.observed_at
    missing = 0
    for external_id, pm in known.items():
        if external_id not in seen and pm.missing_since is None:
            pm.missing_since = listing.fetched_at
            # A machine that vanished from the provider has an unknown state.
            pm.rental_state = "unknown"
            pm.listed = None
            pm.state_detail = "machine no longer appears in the provider inventory"
            missing += 1
    db.flush()
    return _ok(db, account, run, {"machines": len(listing.machines), "new": created, "missing": missing})


def bind_machine(
    db: Session,
    actor: Actor,
    *,
    provider_machine_id: uuid.UUID,
    machine_id: uuid.UUID,
    bound_from: date,
    user_id: uuid.UUID,
    today: date | None = None,
) -> ProviderMachine:
    """Bind a provider machine to one HappyMining machine.

    Only an admin can do this, only for a machine the provider itself listed
    under our account (the row exists because ``sync_machines`` saw it), and
    never on the word of a device. The agent's ``machine_id_hint`` is shown
    to the admin as untrusted evidence.

    ``bound_from`` is the first UTC day attributed through this binding. It
    cannot reach back into a period covered by an earlier binding of the same
    provider machine, so one day never has two answers.
    """
    today = today or datetime.now(UTC).date()
    pm = lock_row(db, ProviderMachine, provider_machine_id)
    machine = lock_row(db, Machine, machine_id)
    if pm is None or machine is None:
        raise NotFound()
    if pm.missing_since is not None:
        raise Conflict("the provider no longer lists this machine; sync and check before binding")
    if pm.machine_id is not None:
        raise Conflict("this provider machine is already bound")
    already = db.execute(select(ProviderMachine.id).where(ProviderMachine.machine_id == machine.id)).first()
    if already is not None:
        raise Conflict("this machine is already bound to a provider machine")
    if bound_from > today + timedelta(days=1):
        raise InvalidRequest("bound_from cannot be later than tomorrow (UTC)")
    last_unbind = db.execute(
        select(func.max(ProviderBindingEvent.effective_day)).where(
            ProviderBindingEvent.provider_machine_id == pm.id, ProviderBindingEvent.action == "unbind"
        )
    ).scalar_one_or_none()
    if last_unbind is not None and bound_from < last_unbind:
        raise Conflict(
            f"bound_from must be {last_unbind.isoformat()} or later: earlier days belong to the previous "
            "binding of this provider machine"
        )
    attributed_elsewhere = db.execute(
        select(func.count())
        .select_from(EarningBucket)
        .where(
            EarningBucket.provider_account_id == pm.provider_account_id,
            EarningBucket.external_machine_id == pm.external_id,
            EarningBucket.status == "mapped",
            EarningBucket.day >= bound_from,
            EarningBucket.machine_id != machine.id,
        )
    ).scalar_one()
    if attributed_elsewhere:
        raise Conflict(
            "earnings on or after that day are already attributed through another machine; "
            "choose a later bound_from"
        )
    hint = (machine.hardware or {}).get("vast_machine_id_hint")
    expected_hint = "sha256:" + hashlib.sha256(pm.external_id.encode()).hexdigest()
    pm.machine_id = machine.id
    pm.bound_from = bound_from
    pm.bound_by = user_id
    pm.bound_at = utcnow()
    evidence = {
        "provider_listed_machine": True,
        "agent_hint_present": bool(hint),
        "agent_hint_matches": bool(hint) and hint == expected_hint,
        "provider_gpu": f"{pm.num_gpus} x {pm.gpu_name}",
        "agent_gpus": [g.get("name") for g in (machine.hardware or {}).get("gpus", [])],
    }
    db.add(
        ProviderBindingEvent(
            provider_machine_id=pm.id,
            machine_id=machine.id,
            action="bind",
            effective_day=bound_from,
            by_user=user_id,
            evidence=evidence,
        )
    )
    db.flush()
    audit(
        db,
        actor,
        "provider_machine.bind",
        object_type="provider_machine",
        object_id=pm.id,
        owner_id=machine.owner_id,
        details={
            "machine_id": str(machine.id),
            "external_id": pm.external_id,
            "bound_from": bound_from.isoformat(),
            **evidence,
        },
    )
    return pm


def _attribution_blockers(db: Session, pm: ProviderMachine, machine: Machine) -> list[str]:
    """Reasons a binding or ownership change would make attribution ambiguous."""
    reasons = []
    if pm.rental_state != "idle":
        reasons.append(f"rental state is '{pm.rental_state}', not confirmed idle")
    open_buckets = db.execute(
        select(func.count())
        .select_from(EarningBucket)
        .where(
            EarningBucket.provider_account_id == pm.provider_account_id,
            EarningBucket.external_machine_id == pm.external_id,
            EarningBucket.reported_amount != EarningBucket.received_amount,
        )
    ).scalar_one()
    if open_buckets:
        reasons.append(f"{open_buckets} earnings day(s) are reported but not yet reconciled")
    balances = owner_balances(db, machine.owner_id)
    if balances.reserved != ZERO or balances.in_transit != ZERO:
        reasons.append("the owner has a payout in progress")
    pending = db.execute(
        select(func.count())
        .select_from(PayoutItem)
        .where(
            PayoutItem.owner_id == machine.owner_id,
            PayoutItem.status.in_(("draft", "reserved", "submitted", "uncertain")),
        )
    ).scalar_one()
    if pending:
        reasons.append("the owner has unsettled payout items")
    return reasons


def unbind_machine(
    db: Session, actor: Actor, *, provider_machine_id: uuid.UUID, user_id: uuid.UUID
) -> ProviderMachine:
    """End a binding from tomorrow (UTC).

    Today and every earlier day stay attributable through this binding, even
    if they are imported later: the binding history keeps the interval.
    """
    pm = lock_row(db, ProviderMachine, provider_machine_id)
    if pm is None:
        raise NotFound()
    if pm.machine_id is None:
        raise Conflict("this provider machine is not bound")
    machine = lock_row(db, Machine, pm.machine_id)
    assert machine is not None
    blockers = _attribution_blockers(db, pm, machine)
    if blockers:
        raise Conflict("cannot unbind while attribution would be ambiguous: " + "; ".join(blockers))
    last_day = datetime.now(UTC).date()
    db.add(
        ProviderBindingEvent(
            provider_machine_id=pm.id,
            machine_id=machine.id,
            action="unbind",
            effective_day=last_day + timedelta(days=1),
            by_user=user_id,
            evidence={"bound_from": pm.bound_from.isoformat() if pm.bound_from else None},
        )
    )
    audit(
        db,
        actor,
        "provider_machine.unbind",
        object_type="provider_machine",
        object_id=pm.id,
        owner_id=machine.owner_id,
        details={
            "machine_id": str(machine.id),
            "external_id": pm.external_id,
            "last_attributed_day": last_day.isoformat(),
        },
    )
    pm.machine_id = None
    pm.bound_from = None
    pm.bound_by = None
    pm.bound_at = None
    db.flush()
    return pm


def run_earnings_import(
    db: Session,
    actor: Actor,
    provider: Provider,
    account: ProviderAccount,
    *,
    start: date,
    end: date,
    user_id: uuid.UUID | None,
) -> tuple[SyncRun, EarningsImport | None]:
    """Fetch and import earnings for every provider machine we have ever seen.

    Machines that have since disappeared from the provider's inventory are
    still asked about: their last days may not have been imported yet.
    """
    run = _run(db, account, "earnings")
    machine_ids = list(
        db.execute(
            select(ProviderMachine.external_id).where(ProviderMachine.provider_account_id == account.id)
        ).scalars()
    )
    try:
        if not machine_ids:
            # Nothing to ask about yet. Still prove the provider is usable, so a
            # misconfigured integration is never reported as a successful run.
            provider.check_health()
            return (
                _ok(
                    db,
                    account,
                    run,
                    {"machines": 0, "note": "no provider machines known; sync machines first"},
                ),
                None,
            )
        report = provider.fetch_earnings(machine_ids, start, end)
    except ProviderError as exc:
        return _fail(db, account, run, exc), None
    imp = import_earnings(db, actor, account, report, created_by=user_id)
    return _ok(db, account, run, {"import_id": str(imp.id), "status": imp.status, **imp.stats}), imp


def account_status(db: Session, account: ProviderAccount) -> dict[str, Any]:
    """One account's sync state, from the latest run of each kind.

    The ``last_sync_ok`` column only records the most recent run of any kind,
    so a successful connection check would hide a failing machine sync. Nothing
    shown to an operator is taken from that column.
    """
    last_runs = {}
    for kind in ("health", "machines", "earnings"):
        run = db.execute(
            select(SyncRun)
            .where(SyncRun.provider_account_id == account.id, SyncRun.kind == kind)
            .order_by(SyncRun.started_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if run:
            last_runs[kind] = {
                "status": run.status,
                "at": run.started_at.isoformat(),
                "error_code": run.error_code,
                "error": run.error,
                "stats": run.stats,
            }
    stale = account.last_sync_at is None or utcnow() - account.last_sync_at > timedelta(hours=24)
    failing = sorted(kind for kind, last in last_runs.items() if last["status"] != "ok")
    return {
        "id": str(account.id),
        "provider": account.provider,
        "label": account.label,
        "synthetic": account.is_synthetic,
        "last_sync_at": account.last_sync_at.isoformat() if account.last_sync_at else None,
        # True only when the most recent run of every kind succeeded.
        "last_sync_ok": (not failing) if last_runs else None,
        "failing": failing,
        "last_sync_error": "; ".join(
            f"{kind}: {last_runs[kind]['error_code']} {last_runs[kind]['error']}".strip() for kind in failing
        ),
        "stale": stale,
        "last_runs": last_runs,
    }


def integration_health(db: Session, settings: Settings) -> dict[str, Any]:
    """What an admin needs to know about the provider integration, honestly."""
    accounts = db.execute(select(ProviderAccount).order_by(ProviderAccount.created_at)).scalars().all()
    out_accounts = [account_status(db, account) for account in accounts]
    live = settings.is_live
    return {
        "mode": settings.mode,
        "provider": settings.provider,
        "synthetic_data": settings.is_demo,
        "accounts": out_accounts,
        "prerequisites": {
            "api_key_configured": bool(settings.vast_api_key) if live else None,
            "commercial_authorization_recorded": bool(settings.vast_commercial_authorization_ref.strip())
            if live
            else None,
            "earnings_basis": settings.vast_earnings_basis
            if live
            else "net_of_provider_fee (defined, synthetic)",
            "earnings_buckets_verified": settings.vast_earnings_buckets_verified if live else True,
            "rental_state_available": not live,
        },
        "features": {
            "provider_mutations_enabled": settings.provider_mutations_enabled,
            "disruptive_operations_enabled": settings.disruptive_operations_enabled,
            "payouts_enabled": settings.payouts_enabled,
            "payout_provider": settings.payout_provider,
        },
        "notes": [
            "LIVE: rental state is not exposed by the documented Vast API, so disruptive maintenance "
            "is always blocked.",
            "LIVE: earnings are fetched but held, not posted, until HM_VAST_EARNINGS_BASIS and "
            "HM_VAST_EARNINGS_BUCKETS_VERIFIED are set after verification.",
        ]
        if live
        else [
            "DEMO: every machine, earning, receipt and payout shown is synthetic. No real money or hardware."
        ],
    }
