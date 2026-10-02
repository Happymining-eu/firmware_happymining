"""Reconciliation of cash actually received from the provider.

A provider earnings report is not cash. A provider invoice marked "Paid" is
not cash either: Vast documents that "Paid" means the payout was *submitted*
to the payout provider (docs/integration-evidence.md, F19). Owner funds only
become available here, when an operator records a receipt seen on HappyMining's
own bank or payout-provider statement and allocates it to the earnings it pays
for.

Allocation is explicit. The system never guesses which days a payment covers.
Whatever part of a receipt is not allocated stays in a suspense account and
shows up as an open exception until someone explains it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..db import lock_row
from ..errors import Conflict, InvalidRequest, NotFound
from ..models import (
    EVIDENCE_SOURCES,
    EarningBucket,
    JournalEntry,
    ProviderAccount,
    ProviderReceipt,
    ReceiptAllocation,
    utcnow,
)
from .earnings import has_open_adjustment
from .exceptions_queue import raise_exception, resolve_by_key
from .ledger import CURRENCY, ZERO, Line, get_account, money_str, post_entry, q8, reverse_entry


def _live_receipt(db: Session, account: ProviderAccount, reference: str) -> ProviderReceipt | None:
    return db.execute(
        select(ProviderReceipt).where(
            ProviderReceipt.provider_account_id == account.id,
            ProviderReceipt.reference == reference,
            ProviderReceipt.voided_at.is_(None),
        )
    ).scalar_one_or_none()


def record_receipt(
    db: Session,
    actor: Actor,
    account: ProviderAccount,
    *,
    reference: str,
    received_on: date,
    amount: Decimal,
    currency: str,
    evidence_source: str,
    evidence_note: str,
    created_by: uuid.UUID | None,
    is_synthetic: bool = False,
) -> tuple[ProviderReceipt, bool]:
    """Record cash received. Idempotent on (provider account, reference)."""
    reference = reference.strip()
    if not reference:
        raise InvalidRequest("a bank or payout-provider reference is required")
    if evidence_source not in EVIDENCE_SOURCES:
        raise InvalidRequest(
            "evidence_source must be one of: "
            + ", ".join(EVIDENCE_SOURCES)
            + ". A provider invoice shown as 'Paid' is not evidence that money arrived."
        )
    if not evidence_note.strip():
        raise InvalidRequest("evidence is required: say which statement shows this receipt")
    if currency != CURRENCY:
        raise InvalidRequest(
            f"only {CURRENCY} receipts can be recorded; currencies are never converted silently"
        )
    amount = q8(amount)
    if amount <= ZERO:
        raise InvalidRequest("amount must be positive")
    if received_on > datetime.now(UTC).date():
        raise InvalidRequest("received_on cannot be in the future")

    def replay(existing: ProviderReceipt) -> tuple[ProviderReceipt, bool]:
        if existing.amount != amount or existing.received_on != received_on:
            raise Conflict("a receipt with this reference already exists with a different amount or date")
        return existing, False

    existing = _live_receipt(db, account, reference)
    if existing:
        return replay(existing)

    receipt = ProviderReceipt(
        id=uuid.uuid4(),
        provider_account_id=account.id,
        reference=reference[:120],
        received_on=received_on,
        amount=amount,
        currency=currency,
        evidence_source=evidence_source,
        evidence_note=evidence_note[:1000],
        created_by=created_by,
        is_synthetic=is_synthetic,
    )
    try:
        with db.begin_nested():
            db.add(receipt)
            db.flush()
    except IntegrityError:
        # The same receipt was recorded by a concurrent request: return that one.
        winner = _live_receipt(db, account, reference)
        if winner is None:
            raise
        return replay(winner)

    entry, _ = post_entry(
        db,
        entry_type="provider_receipt",
        idempotency_key=f"receipt:{receipt.id}",
        lines=[
            Line(get_account(db, "cash_clearing"), amount),
            Line(get_account(db, "receipts_unallocated", provider_account_id=account.id), -amount),
        ],
        occurred_on=received_on,
        description=f"Cash received from provider, reference {reference}",
        created_by=created_by,
        ref_type="provider_receipt",
        ref_id=receipt.id,
    )
    receipt.journal_entry_id = entry.id
    _sync_remainder_exception(db, receipt, created_by)
    audit(
        db,
        actor,
        "receipt.record",
        object_type="provider_receipt",
        object_id=receipt.id,
        details={
            "amount": money_str(amount),
            "reference": reference,
            "received_on": received_on.isoformat(),
            "evidence_source": evidence_source,
        },
    )
    db.flush()
    return receipt, True


def void_receipt(
    db: Session, actor: Actor, receipt_id: uuid.UUID, *, reason: str, user_id: uuid.UUID | None
) -> ProviderReceipt:
    """Undo a receipt entered by mistake, with a reversing entry.

    Only a receipt with nothing allocated can be voided; de-allocate first.
    The original entry stays in the journal and the reference becomes free.
    """
    if not reason.strip():
        raise InvalidRequest("a reason is required")
    receipt = lock_row(db, ProviderReceipt, receipt_id)
    if receipt is None:
        raise NotFound()
    if receipt.voided_at is not None:
        return receipt
    if receipt.allocated_amount != ZERO:
        raise Conflict("this receipt has allocations; de-allocate them before voiding it")
    entry = db.get(JournalEntry, receipt.journal_entry_id)
    assert entry is not None
    reverse_entry(
        db,
        entry,
        reason=f"receipt voided: {reason}"[:300],
        created_by=user_id,
        occurred_on=datetime.now(UTC).date(),
    )
    receipt.voided_at = utcnow()
    receipt.voided_by = user_id
    receipt.void_reason = reason[:500]
    resolve_by_key(db, f"receipt_remainder:{receipt.id}", "receipt voided", user_id)
    db.flush()
    audit(
        db,
        actor,
        "receipt.void",
        object_type="provider_receipt",
        object_id=receipt.id,
        details={
            "amount": money_str(receipt.amount),
            "reference": receipt.reference,
            "reason": reason[:200],
        },
    )
    return receipt


def _sync_remainder_exception(db: Session, receipt: ProviderReceipt, user_id: uuid.UUID | None) -> None:
    key = f"receipt_remainder:{receipt.id}"
    remainder = receipt.amount - receipt.allocated_amount
    if remainder == ZERO:
        resolve_by_key(db, key, "receipt fully allocated to earnings", user_id)
        return
    resolve_by_key(db, key, "remainder changed", user_id)
    raise_exception(
        db,
        "receipt_remainder",
        f"Receipt {receipt.reference}: {money_str(remainder)} {receipt.currency} is not matched to any "
        "earnings and is held in suspense.",
        dedupe_key=key,
        details={"receipt_id": str(receipt.id), "unallocated": money_str(remainder)},
        provider_account_id=receipt.provider_account_id,
    )


@dataclass(frozen=True)
class AllocationRequest:
    bucket_id: uuid.UUID
    amount: Decimal


def _within(value: Decimal, low: Decimal, high: Decimal) -> bool:
    return low <= value <= high


def _previous_request(db: Session, receipt: ProviderReceipt, request_key: str) -> list[ReceiptAllocation]:
    if not request_key:
        return []
    return list(
        db.execute(
            select(ReceiptAllocation).where(
                ReceiptAllocation.receipt_id == receipt.id, ReceiptAllocation.request_key == request_key
            )
        ).scalars()
    )


def allocate(
    db: Session,
    actor: Actor,
    receipt_id: uuid.UUID,
    requests: list[AllocationRequest],
    *,
    created_by: uuid.UUID | None,
    request_key: str = "",
) -> list[ReceiptAllocation]:
    """Match part of a receipt to specific earnings buckets.

    This is the step that turns accrued (reported) earnings into funds
    available to settle, split into owner share and management fee using the
    rate stored on the bucket.

    A negative amount de-allocates: it is how an over-received day is brought
    back to what the provider now reports, typically netted against new
    earnings on the receipt in which the provider recovered the difference.
    The request is validated as a whole, on its net effect.

    ``request_key`` makes the call replay-safe: the same key for the same
    receipt returns the allocations already made and changes nothing.
    """
    if not requests:
        raise InvalidRequest("no allocations given")
    if len({r.bucket_id for r in requests}) != len(requests):
        raise InvalidRequest("each bucket may appear once per allocation request")
    request_key = request_key.strip()
    if len(request_key) > 120:
        raise InvalidRequest("the idempotency key is too long")

    # Lock order: the receipt, then buckets by id. Every allocation path does
    # the same, so concurrent requests queue instead of deadlocking.
    receipt = lock_row(db, ProviderReceipt, receipt_id)
    if not receipt:
        raise NotFound()
    if receipt.voided_at is not None:
        raise Conflict("this receipt was voided")

    previous = _previous_request(db, receipt, request_key)
    if previous:
        if {(a.bucket_id, a.amount) for a in previous} != {(r.bucket_id, q8(r.amount)) for r in requests}:
            raise Conflict("this idempotency key was already used for a different allocation")
        return previous

    plan: list[tuple[EarningBucket, Decimal]] = []
    for req in sorted(requests, key=lambda r: str(r.bucket_id)):
        amount = q8(req.amount)
        if amount == ZERO:
            raise InvalidRequest("allocation amount must not be zero")
        # lock_row re-reads the row under the lock, so the checks below see
        # what a concurrent allocation may just have committed.
        bucket = lock_row(db, EarningBucket, req.bucket_id)
        if not bucket or bucket.provider_account_id != receipt.provider_account_id:
            raise NotFound("earnings bucket not found for this provider account")
        if bucket.status != "mapped":
            raise Conflict(
                f"bucket {bucket.external_machine_id} {bucket.day} is not attributed to an owner; "
                "resolve the unmapped machine first"
            )
        if bucket.currency != receipt.currency:
            raise Conflict("bucket and receipt currencies differ")

        low, high = min(ZERO, bucket.reported_amount), max(ZERO, bucket.reported_amount)
        before, after = bucket.received_amount, bucket.received_amount + amount
        if _within(before, low, high):
            # A normal bucket must stay inside what the provider reports.
            if not _within(after, low, high):
                raise Conflict(
                    f"bucket {bucket.external_machine_id} {bucket.day}: allocating {money_str(amount)} "
                    f"would make received {money_str(after)}, outside reported "
                    f"{money_str(bucket.reported_amount)}"
                )
            if has_open_adjustment(db, bucket.id):
                raise Conflict(
                    f"bucket {bucket.external_machine_id} {bucket.day} has an unexplained provider "
                    "adjustment; resolve that exception before reconciling it"
                )
        else:
            # An over-received bucket may only move back towards its range,
            # fully or in part, and never past the other side of it.
            target = high if before > high else low
            moves_back = abs(after - target) < abs(before - target) and (
                (before > high and after >= low) or (before < low and after <= high)
            )
            if not moves_back:
                raise Conflict(
                    f"bucket {bucket.external_machine_id} {bucket.day} has received "
                    f"{money_str(before)} against reported {money_str(bucket.reported_amount)}; "
                    "it can only be corrected towards the reported amount"
                )
        plan.append((bucket, amount))

    net = sum((amount for _, amount in plan), ZERO)
    allocated_after = receipt.allocated_amount + net
    if not _within(allocated_after, ZERO, receipt.amount):
        raise Conflict(
            f"the allocations net to {money_str(net)}; "
            f"{money_str(receipt.amount - receipt.allocated_amount)} of the receipt is unallocated and "
            f"{money_str(receipt.allocated_amount)} is allocated"
        )

    created: list[ReceiptAllocation] = []
    unallocated = get_account(db, "receipts_unallocated", provider_account_id=receipt.provider_account_id)
    receivable = get_account(db, "provider_receivable", provider_account_id=receipt.provider_account_id)
    # De-allocations first: they put money back into suspense, so the positive
    # ones that follow can never overdraw it part-way through the request.
    for bucket, amount in sorted(plan, key=lambda item: item[1] > ZERO):
        assert bucket.fee_rate is not None and bucket.owner_id is not None
        received_after = bucket.received_amount + amount
        # Release exactly what was accrued once the bucket is fully received,
        # otherwise the pro-rata share. Sub-cent precision is kept.
        if received_after == bucket.reported_amount:
            fee_released_total = bucket.fee_accrued
        else:
            fee_released_total = q8(received_after * bucket.fee_rate)
        fee_part = fee_released_total - bucket.fee_released
        owner_part = amount - fee_part

        allocation_id = uuid.uuid4()
        entry, _ = post_entry(
            db,
            entry_type="receipt_allocation" if amount > ZERO else "receipt_deallocation",
            idempotency_key=f"allocation:{allocation_id}",
            lines=[
                Line(unallocated, amount),
                Line(receivable, -amount),
                Line(get_account(db, "owner_accrued", owner_id=bucket.owner_id), owner_part),
                Line(get_account(db, "owner_available", owner_id=bucket.owner_id), -owner_part),
                Line(get_account(db, "fee_accrued"), fee_part),
                Line(get_account(db, "fee_earned"), -fee_part),
            ],
            occurred_on=receipt.received_on,
            description=(
                f"Receipt {receipt.reference} allocated to machine {bucket.external_machine_id} "
                f"{bucket.day.isoformat()}: base {money_str(amount)}, fee {money_str(fee_part)}, "
                f"owner {money_str(owner_part)}"
            ),
            created_by=created_by,
            ref_type="provider_receipt",
            ref_id=receipt.id,
        )
        allocation = ReceiptAllocation(
            id=allocation_id,
            receipt_id=receipt.id,
            bucket_id=bucket.id,
            amount=amount,
            owner_released=owner_part,
            fee_released=fee_part,
            journal_entry_id=entry.id,
            request_key=request_key,
            created_by=created_by,
        )
        db.add(allocation)
        bucket.received_amount = received_after
        bucket.owner_released = bucket.owner_released + owner_part
        bucket.fee_released = fee_released_total
        bucket.updated_at = utcnow()
        db.flush()
        low, high = min(ZERO, bucket.reported_amount), max(ZERO, bucket.reported_amount)
        if _within(bucket.received_amount, low, high):
            resolve_by_key(
                db, f"over_received:{bucket.id}", "received no longer exceeds reported", created_by
            )
        created.append(allocation)

    receipt.allocated_amount = allocated_after
    db.flush()
    _sync_remainder_exception(db, receipt, created_by)
    audit(
        db,
        actor,
        "receipt.allocate",
        object_type="provider_receipt",
        object_id=receipt.id,
        details={
            "allocations": [{"bucket": str(a.bucket_id), "amount": money_str(a.amount)} for a in created],
            "unallocated_after": money_str(receipt.amount - receipt.allocated_amount),
        },
    )
    return created


def allocate_period(
    db: Session,
    actor: Actor,
    receipt_id: uuid.UUID,
    start: date,
    end: date,
    *,
    created_by: uuid.UUID | None,
    request_key: str = "",
) -> list[ReceiptAllocation]:
    """Allocate a receipt in full to every open attributed bucket in [start, end].

    The operator states which days the payment covers. If the open earnings in
    that period come to more than the unallocated receipt, nothing is
    allocated: the difference has to be explained, not spread by a rule.
    """
    if end < start:
        raise InvalidRequest("end is before start")
    request_key = request_key.strip()
    receipt = lock_row(db, ProviderReceipt, receipt_id)
    if not receipt:
        raise NotFound()
    previous = _previous_request(db, receipt, request_key)
    if previous:
        return previous
    # Locked in the same order ``allocate`` uses, and re-read under the lock:
    # two receipts allocated to the same days at once must not both succeed.
    buckets = (
        db.execute(
            select(EarningBucket)
            .where(
                EarningBucket.provider_account_id == receipt.provider_account_id,
                EarningBucket.status == "mapped",
                EarningBucket.day >= start,
                EarningBucket.day <= end,
            )
            .order_by(EarningBucket.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        .scalars()
        .all()
    )
    open_buckets = [
        b
        for b in buckets
        if ZERO <= b.received_amount < b.reported_amount or b.reported_amount < b.received_amount <= ZERO
    ]
    if not open_buckets:
        raise Conflict("no open attributed earnings in that period")
    total_open = sum((b.reported_amount - b.received_amount for b in open_buckets), ZERO)
    unallocated = receipt.amount - receipt.allocated_amount
    if total_open > unallocated:
        raise Conflict(
            f"open earnings in the period total {money_str(total_open)} but only "
            f"{money_str(unallocated)} of the receipt is unallocated; nothing was allocated. "
            "Allocate specific buckets or record the missing receipt."
        )
    return allocate(
        db,
        actor,
        receipt_id,
        [AllocationRequest(b.id, b.reported_amount - b.received_amount) for b in open_buckets],
        created_by=created_by,
        request_key=request_key,
    )
