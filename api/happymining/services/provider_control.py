"""Operator controls on the provider's listing of a machine: offer terms
(prices, end date), minimum bid, cancelling a maintenance window, and reading
renter reports.

None of these touches money or a renter's workload: a listing change never
alters a running contract (docs/integration-evidence.md, D14), the minimum
bid applies to new interruptible rentals only, and cancelling a window is a
notification change. They therefore need no rental-state gate, only an
administrator, provider mutations switched on, and an audit row.

What is deliberately not here: scheduling a maintenance window (the start
time format is unresolved, D13), cleanup (deletes renter storage) and
force_delete (removes the machine). Those stay manual in the Vast console.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..db import lock_row
from ..errors import AppError, FeatureDisabled, InvalidRequest, NotFound, UpstreamUnavailable
from ..models import ProviderMachine
from ..providers import vast_wire
from ..providers.base import (
    ListingTerms,
    MachineReport,
    Provider,
    ProviderError,
    ProviderFeatureDisabled,
    ProviderOutcomeUncertain,
)
from ..schemas import ListingIn

MAX_LISTING_DAYS = 365


def _locked(db: Session, provider_machine_id: uuid.UUID) -> ProviderMachine:
    pm = lock_row(db, ProviderMachine, provider_machine_id)
    if pm is None:
        raise NotFound()
    return pm


def _call(db: Session, actor: Actor, pm: ProviderMachine, action: str, details: dict[str, Any], fn):
    """Run one provider write; translate its outcome; audit success and uncertainty."""
    try:
        result = fn()
    except ProviderFeatureDisabled as exc:
        raise FeatureDisabled(exc.message, code=exc.code) from exc
    except ProviderOutcomeUncertain as exc:
        audit(
            db,
            actor,
            f"provider_machine.{action}_uncertain",
            object_type="provider_machine",
            object_id=pm.id,
            details={"external_id": pm.external_id, **details},
        )
        pm.listed = None
        pm.state_detail = f"{action} was requested and its outcome is unknown; check the provider console"[
            :500
        ]
        db.commit()
        raise AppError(exc.message, code=exc.code) from exc
    except ProviderError as exc:
        raise UpstreamUnavailable(exc.message, code=exc.code) from exc
    audit(
        db,
        actor,
        f"provider_machine.{action}",
        object_type="provider_machine",
        object_id=pm.id,
        details={"external_id": pm.external_id, "provider_result": result.detail, **details},
    )
    return result


def terms_from(body: ListingIn) -> ListingTerms:
    end = body.end_date if body.end_date.tzinfo else body.end_date.replace(tzinfo=UTC)
    now = datetime.now(UTC)
    if end <= now:
        raise InvalidRequest("end_date must be in the future")
    if (end - now).days > MAX_LISTING_DAYS:
        raise InvalidRequest(f"end_date must be within {MAX_LISTING_DAYS} days")
    price_gpu = Decimal(body.price_gpu)
    if price_gpu <= 0:
        raise InvalidRequest("price_gpu must be positive")
    optional = {
        name: (Decimal(value) if value is not None else None)
        for name, value in (
            ("price_disk", body.price_disk),
            ("price_inet_up", body.price_inet_up),
            ("price_inet_down", body.price_inet_down),
            ("price_min_bid", body.price_min_bid),
        )
    }
    if optional["price_min_bid"] is not None and optional["price_min_bid"] > price_gpu:
        raise InvalidRequest("price_min_bid (the interruptible floor) cannot exceed price_gpu")
    return ListingTerms(price_gpu=price_gpu, end_date=end, min_chunk=body.min_chunk, **optional)


def terms_view(terms: ListingTerms) -> dict[str, Any]:
    return {
        "price_gpu": str(terms.price_gpu),
        "end_date": terms.end_date.astimezone(UTC).isoformat(),
        "price_disk": None if terms.price_disk is None else str(terms.price_disk),
        "price_inet_up": None if terms.price_inet_up is None else str(terms.price_inet_up),
        "price_inet_down": None if terms.price_inet_down is None else str(terms.price_inet_down),
        "price_min_bid": None if terms.price_min_bid is None else str(terms.price_min_bid),
        "min_chunk": terms.min_chunk,
    }


def list_machine(
    db: Session, actor: Actor, provider: Provider, provider_machine_id: uuid.UUID, body: ListingIn
) -> tuple[ProviderMachine, str]:
    pm = _locked(db, provider_machine_id)
    terms = terms_from(body)
    result = _call(
        db,
        actor,
        pm,
        "list",
        {"terms": terms_view(terms)},
        lambda: provider.list_machine(pm.external_id, terms),
    )
    # The provider exposes no "listed" flag (evidence B5): record the request,
    # not a verified state. The next machine sync refreshes the snapshot.
    pm.listed = None
    pm.state_detail = (
        f"listing requested at {datetime.now(UTC).isoformat(timespec='seconds')} "
        f"({terms.price_gpu} $/GPU/h until {terms.end_date.date().isoformat()}); "
        "not verifiable through the API"
    )[:500]
    return pm, result.detail


def set_min_bid(
    db: Session, actor: Actor, provider: Provider, provider_machine_id: uuid.UUID, price: str
) -> tuple[ProviderMachine, str]:
    pm = _locked(db, provider_machine_id)
    amount = Decimal(price)
    if amount < 0:
        raise InvalidRequest("price must not be negative")
    result = _call(
        db, actor, pm, "min_bid", {"price": str(amount)}, lambda: provider.set_min_bid(pm.external_id, amount)
    )
    return pm, result.detail


def unlist_machine(
    db: Session, actor: Actor, provider: Provider, provider_machine_id: uuid.UUID
) -> tuple[ProviderMachine, str]:
    """Stop new rentals through the provider's own control. Existing rentals are untouched."""
    pm = _locked(db, provider_machine_id)
    result = _call(db, actor, pm, "unlist", {}, lambda: provider.unlist_machine(pm.external_id))
    # Do not assume: read the state back and record what the provider says now.
    try:
        state = provider.get_rental_state(pm.external_id)
        pm.rental_state, pm.listed = state.state, state.listed
        pm.state_detail, pm.state_observed_at = state.detail[:500], state.observed_at
    except ProviderError:
        pm.listed = None
    return pm, result.detail


def cancel_maintenance(
    db: Session, actor: Actor, provider: Provider, provider_machine_id: uuid.UUID
) -> tuple[ProviderMachine, str]:
    pm = _locked(db, provider_machine_id)
    result = _call(
        db, actor, pm, "cancel_maintenance", {}, lambda: provider.cancel_maintenance(pm.external_id)
    )
    return pm, result.detail


def reports(db: Session, provider: Provider, provider_machine_id: uuid.UUID) -> list[MachineReport]:
    pm = db.get(ProviderMachine, provider_machine_id)
    if pm is None:
        raise NotFound()
    try:
        return provider.get_reports(pm.external_id)
    except ProviderError as exc:
        raise UpstreamUnavailable(exc.message, code=exc.code) from exc


def listing_view(pm: ProviderMachine) -> dict[str, Any] | None:
    """Offer fields from the last synced snapshot, or None when the snapshot
    has none of them (older sync, synthetic fixture without prices)."""
    try:
        snap = vast_wire.listing_snapshot(pm.snapshot or {})
    except ProviderError:
        return None
    view = vast_wire.snapshot_view(snap)
    return view if any(v not in (None, "") for v in view.values()) else None
