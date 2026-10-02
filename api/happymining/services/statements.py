"""Owner statements: base, fee, adjustments, reserve and payable shown separately."""

from __future__ import annotations

import uuid
from datetime import date
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import EarningBucket, EarningRevision, PayoutBatch, PayoutItem
from .ledger import Q2, ZERO, floor_cents, money_str, owner_balances, q8


def _sum(db: Session, column: Any, *where: Any) -> Decimal:
    return q8(db.execute(select(func.coalesce(func.sum(column), 0)).where(*where)).scalar_one())


def owner_statement(db: Session, owner_id: uuid.UUID, start: date, end: date) -> dict[str, Any]:
    """Statement for earnings days in [start, end], plus current balances.

    "Reported" figures are what the provider says was earned. "Reconciled"
    figures are backed by cash HappyMining actually received. Only reconciled
    money is ever payable.
    """
    scope = (EarningBucket.owner_id == owner_id, EarningBucket.day >= start, EarningBucket.day <= end)
    reported = _sum(db, EarningBucket.reported_amount, *scope)
    reconciled_base = _sum(db, EarningBucket.received_amount, *scope)
    fee_on_reconciled = _sum(db, EarningBucket.fee_released, *scope)
    owner_reconciled = _sum(db, EarningBucket.owner_released, *scope)
    fee_on_reported = _sum(db, EarningBucket.fee_accrued, *scope)
    owner_reported = _sum(db, EarningBucket.owner_accrued, *scope)

    adjustments = db.execute(
        select(func.count(), func.coalesce(func.sum(EarningRevision.delta), 0))
        .join(EarningBucket, EarningBucket.id == EarningRevision.bucket_id)
        .where(*scope, EarningRevision.revision_no > 1)
    ).one()

    rates = db.execute(
        select(EarningBucket.fee_rate, func.min(EarningBucket.day), func.max(EarningBucket.day))
        .where(*scope)
        .group_by(EarningBucket.fee_rate)
        .order_by(func.min(EarningBucket.day))
    ).all()

    balances = owner_balances(db, owner_id)
    paid_total = q8(
        db.execute(
            select(func.coalesce(func.sum(PayoutItem.amount), 0)).where(
                PayoutItem.owner_id == owner_id, PayoutItem.status == "confirmed_paid"
            )
        ).scalar_one()
    )
    payable = floor_cents(balances.available) if balances.available > ZERO else ZERO.quantize(Q2)

    return {
        "owner_id": str(owner_id),
        "currency": "USD",
        "period": {"start": start.isoformat(), "end": end.isoformat(), "basis": "earnings days (UTC)"},
        "reported": {
            "provider_reported_earnings": money_str(reported),
            "management_fee_on_reported": money_str(fee_on_reported),
            "owner_share_of_reported": money_str(owner_reported),
            "note": "Reported by the provider. Not cash. Not payable until received and reconciled.",
        },
        "reconciled": {
            "eligible_base": money_str(reconciled_base),
            "management_fee": money_str(fee_on_reconciled),
            "owner_share": money_str(owner_reconciled),
            "note": "Backed by provider payments HappyMining received and matched to these days.",
        },
        "outstanding_not_received": {
            "base": money_str(q8(reported - reconciled_base)),
            "owner_share": money_str(q8(owner_reported - owner_reconciled)),
        },
        "adjustments": {
            "count": int(adjustments[0]),
            "net_amount": money_str(q8(adjustments[1])),
            "note": "Provider corrections to days already imported. Included in the reported figures above.",
        },
        "fee_versions": [
            {"rate": str(rate), "first_day": first.isoformat(), "last_day": last.isoformat()}
            for rate, first, last in rates
            if rate is not None
        ],
        "balances_now": {
            **balances.as_dict(),
            "confirmed_paid_to_date": money_str(paid_total),
            "reserve": money_str(q8(balances.reserved + balances.in_transit)),
            "payable": money_str(payable),
        },
        "disclaimer": (
            "Operational settlement statement pending accounting review. Not a tax or statutory document. "
            "VAT treatment is not determined here. Past earnings do not predict future earnings."
        ),
    }


def owner_payout_history(db: Session, owner_id: uuid.UUID, limit: int = 100) -> list[dict[str, Any]]:
    rows = db.execute(
        select(PayoutItem, PayoutBatch)
        .join(PayoutBatch, PayoutBatch.id == PayoutItem.batch_id)
        .where(PayoutItem.owner_id == owner_id)
        .order_by(PayoutItem.created_at.desc())
        .limit(limit)
    ).all()
    return [
        {
            "item_id": str(item.id),
            "batch_id": str(batch.id),
            "amount": f"{item.amount:.2f}",
            "currency": item.currency,
            "status": item.status,
            "created_at": item.created_at.isoformat(),
            "updated_at": item.updated_at.isoformat(),
            "reference": item.external_reference if item.status == "confirmed_paid" else "",
            "synthetic": batch.is_synthetic,
        }
        for item, batch in rows
    ]
