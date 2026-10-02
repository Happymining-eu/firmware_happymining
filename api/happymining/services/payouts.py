"""Owner settlements: prepare, approve, export, submit, confirm with evidence.

Money states for an owner, each a separate ledger account:

    accrued (reported)  ->  available  ->  reserved  ->  in transit  ->  paid
                         receipt        approval      submission      bank evidence
                         reconciled

Double payment is prevented in four independent ways:

1. A batch is created under an idempotency key; repeating the request returns
   the same batch.
2. Approval moves funds from "available" to "reserved" inside one transaction.
   The database refuses to overdraw "available", so two concurrent approvals
   cannot both reserve the same money.
3. Only items in "reserved" can be submitted, and each ledger step has its own
   idempotency key per item.
4. An unknown outcome (for example a timeout) leaves the funds in transit. They
   cannot be paid again until evidence shows the first attempt failed.

Amounts are rounded down to cents here and nowhere earlier. The sub-cent
remainder stays in the owner's available balance for the next settlement.
"""

from __future__ import annotations

import csv
import hashlib
import io
import logging
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..config import Settings
from ..db import lock_row
from ..errors import Conflict, FeatureDisabled, Forbidden, InsufficientFunds, InvalidRequest, NotFound
from ..models import (
    EarningBucket,
    ExceptionItem,
    Owner,
    OwnerBeneficiary,
    PayoutBatch,
    PayoutEvidence,
    PayoutItem,
    utcnow,
)
from ..payout_providers.base import PayoutInstruction, PayoutProvider, SubmitOutcome, SubmitResult
from ..payout_providers.manual_export import ManualExportProvider
from ..payout_providers.mock import MockPayoutProvider
from ..security import decrypt_json, encrypt_json
from .ledger import ZERO, Line, balance_of, floor_cents, get_account, lock_owner, owner_balances, post_entry

log = logging.getLogger(__name__)

FINAL_ITEM_STATES = ("confirmed_paid", "failed", "reversed", "cancelled")
BENEFICIARY_FIELDS = ("account_holder", "iban", "bic", "bank_name", "country", "payment_reference")


def get_payout_provider(settings: Settings) -> PayoutProvider:
    if settings.payout_provider == "mock":
        if settings.is_live:
            raise FeatureDisabled("the mock payout provider is not allowed in LIVE mode")
        return MockPayoutProvider()
    return ManualExportProvider()


def _require_enabled(settings: Settings) -> None:
    if not settings.payouts_enabled:
        raise FeatureDisabled("payouts are disabled (HM_PAYOUTS_ENABLED=false)")


def _today() -> Any:
    return datetime.now(UTC).date()


# --- beneficiaries ---------------------------------------------------------


def set_beneficiary(
    db: Session,
    settings: Settings,
    actor: Actor,
    owner_id: uuid.UUID,
    details: dict[str, str],
    user_id: uuid.UUID,
) -> OwnerBeneficiary:
    unknown = set(details) - set(BENEFICIARY_FIELDS)
    if unknown:
        raise InvalidRequest(f"unknown beneficiary fields: {', '.join(sorted(unknown))}")
    clean = {k: str(v).strip()[:200] for k, v in details.items() if str(v).strip()}
    if not clean.get("account_holder") or not clean.get("iban"):
        raise InvalidRequest("account_holder and iban are required")
    iban = clean["iban"].replace(" ", "").upper()
    if not (15 <= len(iban) <= 34 and iban.isalnum()):
        raise InvalidRequest("iban is not plausible")
    clean["iban"] = iban
    if not db.get(Owner, owner_id):
        raise NotFound()
    row = lock_row(db, OwnerBeneficiary, owner_id)
    if row is None:
        row = OwnerBeneficiary(owner_id=owner_id, details_enc="")
        db.add(row)
    row.details_enc = encrypt_json(settings, clean)
    row.masked_hint = f"{iban[:2]}** **** {iban[-4:]}"
    row.updated_by = user_id
    row.updated_at = utcnow()
    db.flush()
    audit(
        db,
        actor,
        "beneficiary.set",
        object_type="owner",
        object_id=owner_id,
        owner_id=owner_id,
        details={"masked": row.masked_hint},
    )
    return row


# --- prepare ---------------------------------------------------------------


def prepare_batch(
    db: Session,
    settings: Settings,
    actor: Actor,
    *,
    idempotency_key: str,
    created_by: uuid.UUID | None,
    owner_ids: list[uuid.UUID] | None = None,
    note: str = "",
    is_synthetic: bool = False,
) -> tuple[PayoutBatch, bool]:
    """Draft a batch from reconciled balances. Reserves nothing yet."""
    _require_enabled(settings)
    idempotency_key = idempotency_key.strip()
    if not (8 <= len(idempotency_key) <= 120):
        raise InvalidRequest("an Idempotency-Key of 8 to 120 characters is required")
    existing = db.execute(
        select(PayoutBatch).where(PayoutBatch.idempotency_key == idempotency_key)
    ).scalar_one_or_none()
    if existing:
        return existing, False

    minimum = Decimal(settings.payout_minimum)
    query = select(Owner).where(Owner.status == "active").order_by(Owner.id)
    if owner_ids is not None:
        query = query.where(Owner.id.in_(owner_ids))
    items: list[tuple[Owner, Decimal]] = []
    held: list[str] = []
    for owner in db.execute(query).scalars():
        if owner.is_synthetic != settings.is_demo:
            # Synthetic balances are never paid by a LIVE system, and a DEMO
            # system never touches real ones.
            continue
        amount = floor_cents(owner_balances(db, owner.id).available)
        if amount < minimum or amount <= ZERO:
            continue
        if payout_blockers(db, owner.id):
            held.append(owner.display_name)
            continue
        items.append((owner, amount))
    if not items:
        if held:
            raise Conflict(
                "nothing can be settled: unresolved provider adjustments for " + ", ".join(sorted(held))
            )
        raise InsufficientFunds(
            "no owner has a received-and-reconciled balance of at least "
            f"{minimum} {settings.settlement_currency}"
        )

    batch = PayoutBatch(
        idempotency_key=idempotency_key,
        currency=settings.settlement_currency,
        note=note[:500],
        created_by=created_by,
        is_synthetic=is_synthetic,
    )
    try:
        with db.begin_nested():
            db.add(batch)
            db.flush()
    except IntegrityError:
        # Lost a race on the idempotency key: return the winner.
        winner = db.execute(
            select(PayoutBatch).where(PayoutBatch.idempotency_key == idempotency_key)
        ).scalar_one_or_none()
        if winner:
            return winner, False
        raise
    for owner, amount in items:
        db.add(PayoutItem(batch_id=batch.id, owner_id=owner.id, amount=amount, currency=batch.currency))
    db.flush()
    audit(
        db,
        actor,
        "payout_batch.prepare",
        object_type="payout_batch",
        object_id=batch.id,
        details={"items": len(items), "total": str(sum((a for _, a in items), ZERO))},
    )
    return batch, True


# Open exceptions of these kinds mean an owner's available balance may include
# money the provider has since taken back. Nothing is paid until they are
# resolved (see docs/ledger.md, "When the provider revises a paid day").
BLOCKING_EXCEPTIONS = ("over_received", "unexplained_adjustment")


def payout_blockers(db: Session, owner_id: uuid.UUID) -> list[str]:
    """Reasons this owner must not be paid now.

    Two sources: open exceptions of the blocking kinds, and the buckets
    themselves. The second does not depend on anyone keeping an exception
    open: while a day has more cash allocated to it than the provider now
    reports, the owner is held, whatever the queue says.
    """
    out = list(
        db.execute(
            select(ExceptionItem.summary).where(
                ExceptionItem.owner_id == owner_id,
                ExceptionItem.status == "open",
                ExceptionItem.kind.in_(BLOCKING_EXCEPTIONS),
            )
        ).scalars()
    )
    # Buckets already described by an open exception are not listed twice.
    flagged = set(
        db.execute(
            select(ExceptionItem.dedupe_key).where(
                ExceptionItem.owner_id == owner_id,
                ExceptionItem.status == "open",
                ExceptionItem.kind == "over_received",
                ExceptionItem.dedupe_key.is_not(None),
            )
        ).scalars()
    )
    over = db.execute(
        select(
            EarningBucket.id,
            EarningBucket.external_machine_id,
            EarningBucket.day,
            EarningBucket.received_amount,
            EarningBucket.reported_amount,
        )
        .where(
            EarningBucket.owner_id == owner_id,
            EarningBucket.received_amount > func.greatest(EarningBucket.reported_amount, 0),
        )
        .order_by(EarningBucket.day)
        .limit(50)
    ).all()
    out.extend(
        f"machine {machine} on {day.isoformat()}: received {received} exceeds reported {reported}"
        for bucket_id, machine, day, received, reported in over
        if f"over_received:{bucket_id}" not in flagged
    )
    return out


def _require_unblocked(db: Session, batch: PayoutBatch, action: str) -> None:
    for item in _items(db, batch):
        if item.status not in ("draft", "reserved"):
            continue
        blockers = payout_blockers(db, item.owner_id)
        if blockers:
            raise Conflict(
                f"this batch cannot be {action}: owner {item.owner_id} has an unresolved provider "
                f"adjustment ({blockers[0]}). Cancel the batch, correct the allocation, then prepare "
                "a new one."
            )


def _lock_cash(db: Session) -> None:
    """Serialise checks against the cash clearing balance for this transaction."""
    db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended('cash_clearing', 0))"))


def _lock_batch(db: Session, batch_id: uuid.UUID) -> PayoutBatch:
    batch = lock_row(db, PayoutBatch, batch_id)
    if not batch:
        raise NotFound()
    return batch


def _items(db: Session, batch: PayoutBatch) -> list[PayoutItem]:
    return list(
        db.execute(
            select(PayoutItem)
            .where(PayoutItem.batch_id == batch.id)
            .order_by(PayoutItem.owner_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalars()
    )


# --- approve ---------------------------------------------------------------


def approve_batch(
    db: Session, settings: Settings, actor: Actor, batch_id: uuid.UUID, *, approver_id: uuid.UUID
) -> tuple[PayoutBatch, bool]:
    """Reserve funds for every item, or for none. Repeating the call is a no-op."""
    _require_enabled(settings)
    batch = _lock_batch(db, batch_id)
    if batch.status in ("approved", "submitted", "closed"):
        return batch, False
    if batch.status != "draft":
        raise Conflict(f"a {batch.status} batch cannot be approved")
    if settings.payout_require_distinct_approver and batch.created_by == approver_id:
        raise Forbidden("the batch must be approved by someone other than the person who prepared it")

    items = _items(db, batch)
    # Validate everything before the first posting: approve all items or none.
    beneficiaries = {item.owner_id: db.get(OwnerBeneficiary, item.owner_id) for item in items}
    missing = [str(owner_id) for owner_id, row in beneficiaries.items() if row is None]
    if missing:
        raise Conflict("no beneficiary on file for owner(s): " + ", ".join(sorted(missing)))
    owners = {o.id: o for o in db.execute(select(Owner).where(Owner.id.in_(beneficiaries))).scalars()}
    if any(owner.is_synthetic != settings.is_demo for owner in owners.values()):
        raise Conflict(
            "this batch mixes synthetic and real owners with the current mode; it cannot be approved"
        )
    total = ZERO
    for item in items:
        # The owner lock serialises this check with any other settlement for
        # the same owner; the overdraft trigger is the backstop.
        lock_owner(db, item.owner_id)
        blockers = payout_blockers(db, item.owner_id)
        if blockers:
            raise Conflict(
                f"owner {owners[item.owner_id].display_name} has an unresolved provider adjustment; "
                "resolve it before paying: " + blockers[0]
            )
        beneficiary = beneficiaries[item.owner_id]
        assert beneficiary is not None
        available = balance_of(db, get_account(db, "owner_available", owner_id=item.owner_id))
        if available < item.amount:
            raise InsufficientFunds(
                f"owner {item.owner_id}: {available} reconciled and available, {item.amount} requested"
            )
        post_entry(
            db,
            entry_type="payout_reserve",
            idempotency_key=f"payout:{item.id}:reserve",
            lines=[
                Line(get_account(db, "owner_available", owner_id=item.owner_id), item.amount),
                Line(get_account(db, "owner_reserved", owner_id=item.owner_id), -item.amount),
            ],
            occurred_on=_today(),
            description=f"Reserve for approved payout batch {batch.id}",
            created_by=approver_id,
            ref_type="payout_item",
            ref_id=item.id,
        )
        item.status = "reserved"
        item.beneficiary_snapshot_enc = beneficiary.details_enc
        item.updated_at = utcnow()
        total += item.amount

    _lock_cash(db)
    cash = balance_of(db, get_account(db, "cash_clearing"))
    if cash < total:
        raise InsufficientFunds(f"reconciled cash {cash} does not cover the batch total {total}")

    batch.status = "approved"
    batch.approved_by = approver_id
    batch.approved_at = utcnow()
    db.flush()
    audit(
        db,
        actor,
        "payout_batch.approve",
        object_type="payout_batch",
        object_id=batch.id,
        details={"items": len(items), "total": str(total)},
    )
    return batch, True


# --- export ----------------------------------------------------------------


def csv_cell(value: object) -> str:
    """Text for a CSV cell that a spreadsheet will not run as a formula.

    The export is opened by the person who pays. A name such as ``=HYPERLINK(...)``
    must arrive as text, so cells that start with a formula character are
    prefixed with an apostrophe, and control characters are dropped.
    """
    text_value = "".join(ch for ch in str(value) if ch == " " or ch.isprintable())
    if text_value[:1] in ("=", "+", "-", "@"):
        return "'" + text_value
    return text_value


def export_batch(db: Session, settings: Settings, actor: Actor, batch_id: uuid.UUID) -> tuple[bytes, str]:
    """Deterministic CSV of an approved batch. Changes no balance; safe to repeat."""
    _require_enabled(settings)
    batch = _lock_batch(db, batch_id)
    if batch.status not in ("approved", "submitted", "closed"):
        raise Conflict("only an approved batch can be exported")
    if batch.status == "approved" and not batch.export_count:
        # A revision can arrive between approval and export. The file must not
        # leave for the bank while an owner in it is being held. (A repeat of
        # an earlier export is the same file and is always allowed.)
        _require_unblocked(db, batch, "exported")
    owners = {o.id: o for o in db.execute(select(Owner)).scalars()}
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(
        [
            "payment_reference",
            "item_id",
            "owner_id",
            "owner_name",
            "amount",
            "currency",
            *BENEFICIARY_FIELDS[:-1],
        ]
    )
    for item in sorted(_items(db, batch), key=lambda i: str(i.id)):
        if not item.beneficiary_snapshot_enc:
            continue
        details = decrypt_json(settings, item.beneficiary_snapshot_enc)
        writer.writerow(
            [
                f"HM-{str(item.id)[:13].upper()}",
                item.id,
                item.owner_id,
                csv_cell(owners[item.owner_id].display_name),
                f"{item.amount:.2f}",
                item.currency,
                *[csv_cell(details.get(f, "")) for f in BENEFICIARY_FIELDS[:-1]],
            ]
        )
    body = out.getvalue().encode()
    digest = hashlib.sha256(body).hexdigest()
    if batch.export_sha256 and batch.export_sha256 != digest:
        raise Conflict(
            "the export no longer matches the first export of this batch; investigate before paying"
        )
    batch.export_sha256 = digest
    batch.export_count += 1
    db.flush()
    audit(
        db,
        actor,
        "payout_batch.export",
        object_type="payout_batch",
        object_id=batch.id,
        details={"sha256": digest, "export_count": batch.export_count},
    )
    return body, digest


# --- submit ----------------------------------------------------------------


def submit_batch(
    db: Session,
    settings: Settings,
    actor: Actor,
    batch_id: uuid.UUID,
    *,
    user_id: uuid.UUID | None,
    provider: PayoutProvider | None = None,
) -> tuple[PayoutBatch, bool]:
    """Record that the approved batch was handed over for payment.

    With the manual provider this is the operator's attestation that the
    exported file was given to the bank. Only items still "reserved" are
    processed, so repeating the call cannot submit an item twice.
    """
    _require_enabled(settings)
    batch = _lock_batch(db, batch_id)
    if batch.status in ("submitted", "closed"):
        return batch, False
    if batch.status != "approved":
        raise Conflict(f"a {batch.status} batch cannot be submitted")
    provider = provider or get_payout_provider(settings)
    if provider.is_mock and settings.is_live:
        raise FeatureDisabled("the mock payout provider is not allowed in LIVE mode")
    if provider.executes_transfer or not batch.export_count:
        # Held owners are not paid. The one case let through is a manual batch
        # whose file was already exported: it may be at the bank, so recording
        # the submission is recording a fact, and cancelling is not possible.
        _require_unblocked(db, batch, "submitted")
    owners = {o.id: o for o in db.execute(select(Owner)).scalars()}

    for item in _items(db, batch):
        if item.status != "reserved":
            continue
        try:
            result = provider.submit(
                PayoutInstruction(
                    item_id=str(item.id),
                    idempotency_key=f"payout:{item.id}",
                    owner_name=owners[item.owner_id].display_name,
                    amount=item.amount,
                    currency=item.currency,
                    beneficiary={},  # the manual and mock providers do not need the details
                )
            )
        except Exception as exc:
            # A timeout, a dropped connection or a crash in the provider says
            # nothing about whether the instruction was accepted. Unknown, not
            # failed: the funds stay locked in transit until evidence arrives.
            log.warning("payout provider raised; outcome recorded as uncertain", extra={"item": str(item.id)})
            result = SubmitResult(
                SubmitOutcome.UNCERTAIN, detail=f"provider error ({type(exc).__name__}); outcome unknown"
            )
        reserved = get_account(db, "owner_reserved", owner_id=item.owner_id)
        if result.outcome is SubmitOutcome.FAILED:
            post_entry(
                db,
                entry_type="payout_release",
                idempotency_key=f"payout:{item.id}:release",
                lines=[
                    Line(reserved, item.amount),
                    Line(get_account(db, "owner_available", owner_id=item.owner_id), -item.amount),
                ],
                occurred_on=_today(),
                description=f"Payout not sent ({result.detail}); funds released",
                created_by=user_id,
                ref_type="payout_item",
                ref_id=item.id,
            )
            item.status = "failed"
            item.failure_reason = result.detail[:500]
        else:
            # SUBMITTED and UNCERTAIN both lock the funds in transit.
            post_entry(
                db,
                entry_type="payout_submit",
                idempotency_key=f"payout:{item.id}:submit",
                lines=[
                    Line(reserved, item.amount),
                    Line(get_account(db, "owner_in_transit", owner_id=item.owner_id), -item.amount),
                ],
                occurred_on=_today(),
                description=f"Payout submitted via {provider.name}",
                created_by=user_id,
                ref_type="payout_item",
                ref_id=item.id,
            )
            uncertain = result.outcome is SubmitOutcome.UNCERTAIN
            item.status = "uncertain" if uncertain else "submitted"
            item.external_reference = result.reference[:120]
            db.add(
                PayoutEvidence(
                    item_id=item.id,
                    kind="uncertain_outcome" if uncertain else "submission",
                    reference=result.reference or f"{provider.name}:{item.id}",
                    note=result.detail[:1000],
                    recorded_by=user_id,
                )
            )
        item.updated_at = utcnow()

    batch.status = "submitted"
    batch.submitted_at = utcnow()
    db.flush()
    _maybe_close(db, batch)
    audit(
        db,
        actor,
        "payout_batch.submit",
        object_type="payout_batch",
        object_id=batch.id,
        details={"provider": provider.name},
    )
    return batch, True


# --- outcomes, with evidence ----------------------------------------------


def _lock_item(db: Session, item_id: uuid.UUID) -> PayoutItem:
    """Lock the item's batch, then the item: the same order every other path uses."""
    batch_id = db.execute(select(PayoutItem.batch_id).where(PayoutItem.id == item_id)).scalar_one_or_none()
    if batch_id is None:
        raise NotFound()
    _lock_batch(db, batch_id)
    item = lock_row(db, PayoutItem, item_id)
    if not item:
        raise NotFound()
    return item


def _evidence(
    db: Session, item: PayoutItem, kind: str, reference: str, note: str, user_id: uuid.UUID | None
) -> None:
    reference = reference.strip()
    if not reference:
        raise InvalidRequest("evidence is required: give the bank statement or transaction reference")
    evidence = PayoutEvidence(
        item_id=item.id, kind=kind, reference=reference[:200], note=note[:1000], recorded_by=user_id
    )
    try:
        with db.begin_nested():
            db.add(evidence)
            db.flush()
    except IntegrityError as exc:
        raise Conflict(
            "this bank reference already confirms another payout; one bank transaction pays one item"
        ) from exc


def _maybe_close(db: Session, batch: PayoutBatch) -> None:
    statuses = set(db.execute(select(PayoutItem.status).where(PayoutItem.batch_id == batch.id)).scalars())
    if batch.status == "submitted" and statuses and statuses <= set(FINAL_ITEM_STATES):
        batch.status = "closed"
        db.flush()


def confirm_item(
    db: Session,
    actor: Actor,
    item_id: uuid.UUID,
    *,
    reference: str,
    note: str = "",
    user_id: uuid.UUID | None,
) -> tuple[PayoutItem, bool]:
    """Mark an item paid on bank evidence. Cash leaves the clearing account here."""
    item = _lock_item(db, item_id)
    if item.status == "confirmed_paid":
        if item.external_reference and item.external_reference != reference.strip():
            raise Conflict("this payout is already confirmed with a different reference")
        return item, False
    if item.status not in ("submitted", "uncertain"):
        raise Conflict(f"a payout in state {item.status} cannot be confirmed as paid")
    _evidence(db, item, "bank_confirmation", reference, note, user_id)
    post_entry(
        db,
        entry_type="payout_confirm",
        idempotency_key=f"payout:{item.id}:confirm",
        lines=[
            Line(get_account(db, "owner_in_transit", owner_id=item.owner_id), item.amount),
            Line(get_account(db, "cash_clearing"), -item.amount),
        ],
        occurred_on=_today(),
        description=f"Payout confirmed paid, reference {reference.strip()}",
        created_by=user_id,
        ref_type="payout_item",
        ref_id=item.id,
    )
    item.status = "confirmed_paid"
    item.external_reference = reference.strip()[:120]
    item.updated_at = utcnow()
    db.flush()
    _maybe_close(db, _lock_batch(db, item.batch_id))
    audit(
        db,
        actor,
        "payout_item.confirm",
        object_type="payout_item",
        object_id=item.id,
        owner_id=item.owner_id,
        details={"amount": str(item.amount), "reference": reference.strip()},
    )
    return item, True


def fail_item(
    db: Session,
    actor: Actor,
    item_id: uuid.UUID,
    *,
    reference: str,
    note: str = "",
    user_id: uuid.UUID | None,
) -> tuple[PayoutItem, bool]:
    """Record, on evidence, that a submitted payout did not go through.

    Only evidence releases the funds. A timeout or a missing answer is not
    evidence of failure: use ``mark_uncertain`` for that.
    """
    item = _lock_item(db, item_id)
    if item.status == "failed":
        return item, False
    if item.status not in ("submitted", "uncertain"):
        raise Conflict(f"a payout in state {item.status} cannot be marked failed")
    _evidence(db, item, "bank_rejection", reference, note, user_id)
    post_entry(
        db,
        entry_type="payout_fail",
        idempotency_key=f"payout:{item.id}:fail",
        lines=[
            Line(get_account(db, "owner_in_transit", owner_id=item.owner_id), item.amount),
            Line(get_account(db, "owner_available", owner_id=item.owner_id), -item.amount),
        ],
        occurred_on=_today(),
        description=f"Payout failed per evidence {reference.strip()}; funds available again",
        created_by=user_id,
        ref_type="payout_item",
        ref_id=item.id,
    )
    item.status = "failed"
    item.failure_reason = (note or reference)[:500]
    item.updated_at = utcnow()
    db.flush()
    _maybe_close(db, _lock_batch(db, item.batch_id))
    audit(
        db,
        actor,
        "payout_item.fail",
        object_type="payout_item",
        object_id=item.id,
        owner_id=item.owner_id,
        details={"amount": str(item.amount), "reference": reference.strip()},
    )
    return item, True


def mark_uncertain(
    db: Session, actor: Actor, item_id: uuid.UUID, *, note: str, user_id: uuid.UUID | None
) -> PayoutItem:
    """Flag a submitted payout whose outcome is unknown. Funds stay locked in transit."""
    item = _lock_item(db, item_id)
    if item.status == "uncertain":
        return item
    if item.status != "submitted":
        raise Conflict(f"a payout in state {item.status} cannot be marked uncertain")
    db.add(
        PayoutEvidence(
            item_id=item.id,
            kind="uncertain_outcome",
            reference=f"uncertain:{item.id}",
            note=note[:1000],
            recorded_by=user_id,
        )
    )
    item.status = "uncertain"
    item.updated_at = utcnow()
    db.flush()
    audit(
        db,
        actor,
        "payout_item.uncertain",
        object_type="payout_item",
        object_id=item.id,
        owner_id=item.owner_id,
    )
    return item


def reverse_item(
    db: Session,
    actor: Actor,
    item_id: uuid.UUID,
    *,
    reference: str,
    note: str = "",
    user_id: uuid.UUID | None,
) -> tuple[PayoutItem, bool]:
    """A confirmed payout came back (bank return). The money is owed to the owner again."""
    item = _lock_item(db, item_id)
    if item.status == "reversed":
        return item, False
    if item.status != "confirmed_paid":
        raise Conflict("only a confirmed payout can be reversed")
    _evidence(db, item, "bank_return", reference, note, user_id)
    post_entry(
        db,
        entry_type="payout_return",
        idempotency_key=f"payout:{item.id}:return",
        lines=[
            Line(get_account(db, "cash_clearing"), item.amount),
            Line(get_account(db, "owner_available", owner_id=item.owner_id), -item.amount),
        ],
        occurred_on=_today(),
        description=f"Payout returned by bank, reference {reference.strip()}",
        created_by=user_id,
        ref_type="payout_item",
        ref_id=item.id,
    )
    item.status = "reversed"
    item.updated_at = utcnow()
    db.flush()
    audit(
        db,
        actor,
        "payout_item.reverse",
        object_type="payout_item",
        object_id=item.id,
        owner_id=item.owner_id,
        details={"amount": str(item.amount), "reference": reference.strip()},
    )
    return item, True


def cancel_batch(db: Session, actor: Actor, batch_id: uuid.UUID, *, user_id: uuid.UUID | None) -> PayoutBatch:
    """Cancel a draft, or an approved batch that was never submitted (releases reserves)."""
    batch = _lock_batch(db, batch_id)
    if batch.status == "cancelled":
        return batch
    if batch.status not in ("draft", "approved"):
        raise Conflict("a submitted batch cannot be cancelled; settle each item with evidence instead")
    if batch.export_count:
        # The payment file may already be at the bank. Releasing the reserve
        # now would let the same money be exported, and paid, a second time.
        raise Conflict(
            "this batch has been exported, so it may already have been paid; mark it as submitted and "
            "settle each item with bank evidence (paid, or failed) instead of cancelling"
        )
    for item in _items(db, batch):
        if item.status == "reserved":
            post_entry(
                db,
                entry_type="payout_release",
                idempotency_key=f"payout:{item.id}:release",
                lines=[
                    Line(get_account(db, "owner_reserved", owner_id=item.owner_id), item.amount),
                    Line(get_account(db, "owner_available", owner_id=item.owner_id), -item.amount),
                ],
                occurred_on=_today(),
                description=f"Payout batch {batch.id} cancelled before submission",
                created_by=user_id,
                ref_type="payout_item",
                ref_id=item.id,
            )
        item.status = "cancelled"
        item.updated_at = utcnow()
    batch.status = "cancelled"
    db.flush()
    audit(db, actor, "payout_batch.cancel", object_type="payout_batch", object_id=batch.id)
    return batch


def import_confirmations(
    db: Session, actor: Actor, batch_id: uuid.UUID, rows: list[dict[str, str]], *, user_id: uuid.UUID | None
) -> dict[str, int]:
    """Apply a bank result file: all rows or none.

    Each row: item_id, outcome (paid | failed), reference, note.
    """
    batch = _lock_batch(db, batch_id)
    item_ids = {i.id for i in _items(db, batch)}
    counts = {"paid": 0, "failed": 0, "unchanged": 0}
    for n, row in enumerate(rows, start=1):
        try:
            item_id = uuid.UUID(str(row.get("item_id", "")).strip())
        except ValueError as exc:
            raise InvalidRequest(f"row {n}: item_id is not a UUID") from exc
        if item_id not in item_ids:
            raise InvalidRequest(f"row {n}: item {item_id} is not part of this batch")
        outcome = str(row.get("outcome", "")).strip().lower()
        reference, note = str(row.get("reference", "")), str(row.get("note", ""))
        if outcome == "paid":
            _, changed = confirm_item(db, actor, item_id, reference=reference, note=note, user_id=user_id)
            counts["paid" if changed else "unchanged"] += 1
        elif outcome == "failed":
            _, changed = fail_item(db, actor, item_id, reference=reference, note=note, user_id=user_id)
            counts["failed" if changed else "unchanged"] += 1
        else:
            raise InvalidRequest(f"row {n}: outcome must be 'paid' or 'failed'")
    return counts
