"""Fees, earnings, reconciliation, settlements, statements, exceptions, audit.

Owners can read their own figures and nothing else. They cannot submit
earnings, change fees, record receipts or approve payouts: every mutating
route here requires the admin role. Devices have no access to any of it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..audit import verify_chain
from ..config import Settings
from ..db import get_db
from ..deps import (
    client_ip,
    load_owner,
    require_admin,
    require_admin_or_auditor,
    require_any,
    scoped_owner_id,
    settings_dep,
)
from ..errors import InvalidRequest, NotFound
from ..models import (
    AuditLog,
    EarningBucket,
    EarningRevision,
    EarningsImport,
    ExceptionItem,
    FeeSchedule,
    JournalEntry,
    JournalLine,
    LedgerAccount,
    OwnerBeneficiary,
    PayoutBatch,
    PayoutItem,
    ProviderAccount,
    ProviderReceipt,
    ReceiptAllocation,
)
from ..schemas import (
    AllocateIn,
    AllocatePeriodIn,
    BatchIn,
    BeneficiaryIn,
    ConfirmationsIn,
    EvidenceIn,
    FeeScheduleIn,
    ReceiptIn,
    ResolveIn,
    UncertainIn,
    VoidIn,
)
from ..services import earnings as earnings_service
from ..services import exceptions_queue, fees, payouts, receipts, statements
from ..services.accounts import Principal
from ..services.ledger import money_str, owner_balances, to_decimal, verify_ledger
from . import views

router = APIRouter(prefix="/api/v1", tags=["money"])

Limit = Query(50, ge=1, le=200)
Offset = Query(0, ge=0)


# --- fees ------------------------------------------------------------------


def fee_view(schedule: FeeSchedule) -> dict:
    return {
        "id": str(schedule.id),
        "owner_id": str(schedule.owner_id) if schedule.owner_id else None,
        "scope": "owner" if schedule.owner_id else "default",
        "rate": money_str(schedule.rate),
        "percent": f"{(schedule.rate * 100).normalize():f}",
        "effective_from": schedule.effective_from.isoformat(),
        "note": schedule.note,
        "demo_assumption": schedule.is_demo_assumption,
        "created_at": views.iso(schedule.created_at),
    }


@router.get("/fee-schedules")
def list_fees(principal: Principal = Depends(require_any), db: Session = Depends(get_db)):
    query = select(FeeSchedule).order_by(FeeSchedule.effective_from.desc())
    if principal.role == "owner":
        query = query.where(or_(FeeSchedule.owner_id.is_(None), FeeSchedule.owner_id == principal.owner_id))
    return {"items": [fee_view(s) for s in db.execute(query).scalars()]}


@router.post("/fee-schedules", status_code=201)
def create_fee(
    body: FeeScheduleIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    schedule = fees.create_fee_schedule(
        db,
        principal.actor(client_ip(request)),
        owner_id=body.owner_id,
        rate=Decimal(body.rate),
        effective_from=body.effective_from,
        note=body.note,
        created_by=principal.user.id,
        is_demo_assumption=settings.is_demo,
    )
    db.commit()
    return fee_view(schedule)


# --- earnings --------------------------------------------------------------


@router.get("/earnings/buckets")
def list_buckets(
    owner_id: uuid.UUID | None = None,
    start: date | None = None,
    end: date | None = None,
    status: str | None = Query(None, pattern="^(mapped|unmapped)$"),
    open_only: bool = False,
    limit: int = Limit,
    offset: int = Offset,
    principal: Principal = Depends(require_any),
    db: Session = Depends(get_db),
):
    scope = scoped_owner_id(principal, owner_id)
    query = select(EarningBucket).order_by(EarningBucket.day.desc(), EarningBucket.external_machine_id)
    if scope is not None:
        query = query.where(EarningBucket.owner_id == scope)
    if start:
        query = query.where(EarningBucket.day >= start)
    if end:
        query = query.where(EarningBucket.day <= end)
    if status:
        query = query.where(EarningBucket.status == status)
    if open_only:
        query = query.where(EarningBucket.reported_amount != EarningBucket.received_amount)
    return views.page(db, query, limit, offset, views.bucket_view)


@router.get("/earnings/buckets/{bucket_id}")
def get_bucket(
    bucket_id: uuid.UUID, principal: Principal = Depends(require_any), db: Session = Depends(get_db)
):
    bucket = db.get(EarningBucket, bucket_id)
    if bucket is None or (principal.role == "owner" and bucket.owner_id != principal.owner_id):
        raise NotFound()
    revisions = (
        db.execute(
            select(EarningRevision)
            .where(EarningRevision.bucket_id == bucket.id)
            .order_by(EarningRevision.revision_no)
        )
        .scalars()
        .all()
    )
    allocations = (
        db.execute(
            select(ReceiptAllocation)
            .where(ReceiptAllocation.bucket_id == bucket.id)
            .order_by(ReceiptAllocation.created_at)
        )
        .scalars()
        .all()
    )
    return {
        **views.bucket_view(bucket),
        "revisions": [
            {
                "revision": r.revision_no,
                "reported": money_str(r.reported_amount),
                "delta": money_str(r.delta),
                "components": r.components,
                "journal_entry_id": str(r.journal_entry_id) if r.journal_entry_id else None,
                "at": views.iso(r.created_at),
            }
            for r in revisions
        ],
        "allocations": [
            {
                "receipt_id": str(a.receipt_id),
                "amount": money_str(a.amount),
                "owner_share": money_str(a.owner_released),
                "fee": money_str(a.fee_released),
                "journal_entry_id": str(a.journal_entry_id),
                "at": views.iso(a.created_at),
            }
            for a in allocations
        ],
    }


@router.post("/earnings/buckets/{bucket_id}/attribute")
def attribute_bucket(
    bucket_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    bucket = earnings_service.remap_bucket(
        db, principal.actor(client_ip(request)), bucket_id, created_by=principal.user.id
    )
    db.commit()
    return views.bucket_view(bucket)


@router.get("/earnings/imports")
def list_imports(
    limit: int = Limit,
    offset: int = Offset,
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
):
    def render(imp: EarningsImport) -> dict:
        return {
            "id": str(imp.id),
            "status": imp.status,
            "period_start": imp.period_start.isoformat(),
            "period_end": imp.period_end.isoformat(),
            "stats": imp.stats,
            "synthetic": imp.is_synthetic,
            "content_sha256": imp.content_sha256,
            "created_at": views.iso(imp.created_at),
        }

    return views.page(
        db, select(EarningsImport).order_by(EarningsImport.created_at.desc()), limit, offset, render
    )


# --- balances and statements ----------------------------------------------


@router.get("/owners/{owner_id}/balance")
def owner_balance(
    owner_id: uuid.UUID, principal: Principal = Depends(require_any), db: Session = Depends(get_db)
):
    owner = load_owner(db, principal, owner_id)
    return {
        "owner_id": str(owner.id),
        "currency": "USD",
        "synthetic": owner.is_synthetic,
        **owner_balances(db, owner.id).as_dict(),
    }


@router.get("/owners/{owner_id}/statement")
def owner_statement(
    owner_id: uuid.UUID,
    start: date | None = None,
    end: date | None = None,
    principal: Principal = Depends(require_any),
    db: Session = Depends(get_db),
):
    owner = load_owner(db, principal, owner_id)
    today = datetime.now(UTC).date()
    end = end or today - timedelta(days=1)
    start = start or end - timedelta(days=29)
    if end < start or (end - start).days > 366:
        raise InvalidRequest("statement period must be between 1 and 366 days")
    return {"synthetic": owner.is_synthetic, **statements.owner_statement(db, owner.id, start, end)}


@router.get("/owners/{owner_id}/payouts")
def owner_payouts(
    owner_id: uuid.UUID, principal: Principal = Depends(require_any), db: Session = Depends(get_db)
):
    owner = load_owner(db, principal, owner_id)
    return {"items": statements.owner_payout_history(db, owner.id)}


# --- receipts and reconciliation ------------------------------------------


@router.post("/receipts", status_code=201)
def record_receipt(
    body: ReceiptIn,
    request: Request,
    response: Response,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    account = db.get(ProviderAccount, body.provider_account_id)
    if account is None:
        raise NotFound("provider account not found")
    receipt, created = receipts.record_receipt(
        db,
        principal.actor(client_ip(request)),
        account,
        reference=body.reference,
        received_on=body.received_on,
        amount=to_decimal(body.amount),
        currency=body.currency,
        evidence_source=body.evidence_source,
        evidence_note=body.evidence_note,
        created_by=principal.user.id,
        is_synthetic=settings.is_demo,
    )
    db.commit()
    if not created:
        response.status_code = 200
    return {**views.receipt_view(receipt), "created": created}


@router.post("/receipts/{receipt_id}/void")
def void_receipt(
    receipt_id: uuid.UUID,
    body: VoidIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Undo a receipt recorded by mistake. Posts a reversing entry; nothing is deleted."""
    receipt = receipts.void_receipt(
        db, principal.actor(client_ip(request)), receipt_id, reason=body.reason, user_id=principal.user.id
    )
    db.commit()
    return views.receipt_view(receipt)


@router.get("/receipts")
def list_receipts(
    limit: int = Limit,
    offset: int = Offset,
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
):
    query = select(ProviderReceipt).order_by(
        ProviderReceipt.received_on.desc(), ProviderReceipt.created_at.desc()
    )
    return views.page(db, query, limit, offset, views.receipt_view)


def _allocations_view(rows: list[ReceiptAllocation], receipt: ProviderReceipt) -> dict:
    return {
        "receipt": views.receipt_view(receipt),
        "allocations": [
            {
                "bucket_id": str(a.bucket_id),
                "amount": money_str(a.amount),
                "owner_share": money_str(a.owner_released),
                "fee": money_str(a.fee_released),
                "journal_entry_id": str(a.journal_entry_id),
            }
            for a in rows
        ],
    }


IdempotencyKey = Header(..., alias="Idempotency-Key", min_length=8, max_length=120)


@router.post("/receipts/{receipt_id}/allocate")
def allocate_receipt(
    receipt_id: uuid.UUID,
    body: AllocateIn,
    request: Request,
    idempotency_key: str = IdempotencyKey,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Allocate (or, with negative amounts, de-allocate). Replaying the same key changes nothing."""
    rows = receipts.allocate(
        db,
        principal.actor(client_ip(request)),
        receipt_id,
        [receipts.AllocationRequest(a.bucket_id, to_decimal(a.amount)) for a in body.allocations],
        created_by=principal.user.id,
        request_key=idempotency_key,
    )
    db.commit()
    return _allocations_view(rows, db.get(ProviderReceipt, receipt_id))


@router.post("/receipts/{receipt_id}/allocate-period")
def allocate_receipt_period(
    receipt_id: uuid.UUID,
    body: AllocatePeriodIn,
    request: Request,
    idempotency_key: str = IdempotencyKey,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    rows = receipts.allocate_period(
        db,
        principal.actor(client_ip(request)),
        receipt_id,
        body.start,
        body.end,
        created_by=principal.user.id,
        request_key=idempotency_key,
    )
    db.commit()
    return _allocations_view(rows, db.get(ProviderReceipt, receipt_id))


# --- beneficiaries ---------------------------------------------------------


@router.put("/owners/{owner_id}/beneficiary")
def put_beneficiary(
    owner_id: uuid.UUID,
    body: BeneficiaryIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    row = payouts.set_beneficiary(
        db, settings, principal.actor(client_ip(request)), owner_id, body.model_dump(), principal.user.id
    )
    db.commit()
    return {"owner_id": str(owner_id), "masked": row.masked_hint, "updated_at": views.iso(row.updated_at)}


@router.get("/owners/{owner_id}/beneficiary")
def get_beneficiary(
    owner_id: uuid.UUID, principal: Principal = Depends(require_any), db: Session = Depends(get_db)
):
    """Only a masked hint is ever returned. Full details leave the system only in a payout export."""
    owner = load_owner(db, principal, owner_id)
    row = db.get(OwnerBeneficiary, owner.id)
    return {"owner_id": str(owner.id), "on_file": row is not None, "masked": row.masked_hint if row else None}


# --- payout batches --------------------------------------------------------


@router.post("/payout-batches", status_code=201)
def prepare_batch(
    body: BatchIn,
    request: Request,
    response: Response,
    idempotency_key: str = IdempotencyKey,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    batch, created = payouts.prepare_batch(
        db,
        settings,
        principal.actor(client_ip(request)),
        idempotency_key=idempotency_key,
        created_by=principal.user.id,
        owner_ids=body.owner_ids,
        note=body.note,
        is_synthetic=settings.is_demo,
    )
    db.commit()
    if not created:
        response.status_code = 200
    return {**views.batch_view(batch), "created": created}


@router.get("/payout-batches")
def list_batches(
    limit: int = Limit,
    offset: int = Offset,
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
):
    query = select(PayoutBatch).order_by(PayoutBatch.created_at.desc())
    return views.page(db, query, limit, offset, views.batch_view)


@router.get("/payout-batches/{batch_id}")
def get_batch(
    batch_id: uuid.UUID, _: Principal = Depends(require_admin_or_auditor), db: Session = Depends(get_db)
):
    batch = db.get(PayoutBatch, batch_id)
    if batch is None:
        raise NotFound()
    return views.batch_view(batch)


@router.post("/payout-batches/{batch_id}/approve")
def approve_batch(
    batch_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    batch, changed = payouts.approve_batch(
        db, settings, principal.actor(client_ip(request)), batch_id, approver_id=principal.user.id
    )
    db.commit()
    db.refresh(batch)
    return {**views.batch_view(batch), "changed": changed}


@router.post("/payout-batches/{batch_id}/export")
def export_batch(
    batch_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Admin only. Contains decrypted beneficiary details; every export is audited."""
    body, digest = payouts.export_batch(db, settings, principal.actor(client_ip(request)), batch_id)
    db.commit()
    return Response(
        content=body,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="happymining-payout-{batch_id}.csv"',
            "X-Content-SHA256": digest,
            "Cache-Control": "no-store",
        },
    )


@router.post("/payout-batches/{batch_id}/submit")
def submit_batch(
    batch_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    batch, changed = payouts.submit_batch(
        db, settings, principal.actor(client_ip(request)), batch_id, user_id=principal.user.id
    )
    db.commit()
    db.refresh(batch)
    return {**views.batch_view(batch), "changed": changed}


@router.post("/payout-batches/{batch_id}/cancel")
def cancel_batch(
    batch_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    batch = payouts.cancel_batch(db, principal.actor(client_ip(request)), batch_id, user_id=principal.user.id)
    db.commit()
    db.refresh(batch)
    return views.batch_view(batch)


@router.post("/payout-batches/{batch_id}/confirmations")
def import_confirmations(
    batch_id: uuid.UUID,
    body: ConfirmationsIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    counts = payouts.import_confirmations(
        db,
        principal.actor(client_ip(request)),
        batch_id,
        [
            {"item_id": str(r.item_id), "outcome": r.outcome, "reference": r.reference, "note": r.note}
            for r in body.rows
        ],
        user_id=principal.user.id,
    )
    db.commit()
    return counts


def _item_action(action, item_id, body, request, principal, db):
    item, changed = action(
        db,
        principal.actor(client_ip(request)),
        item_id,
        reference=body.reference,
        note=body.note,
        user_id=principal.user.id,
    )
    db.commit()
    return {**views.item_view(item, staff=True), "changed": changed}


@router.post("/payout-items/{item_id}/confirm")
def confirm_item(
    item_id: uuid.UUID,
    body: EvidenceIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return _item_action(payouts.confirm_item, item_id, body, request, principal, db)


@router.post("/payout-items/{item_id}/fail")
def fail_item(
    item_id: uuid.UUID,
    body: EvidenceIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return _item_action(payouts.fail_item, item_id, body, request, principal, db)


@router.post("/payout-items/{item_id}/reverse")
def reverse_item(
    item_id: uuid.UUID,
    body: EvidenceIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return _item_action(payouts.reverse_item, item_id, body, request, principal, db)


@router.post("/payout-items/{item_id}/uncertain")
def uncertain_item(
    item_id: uuid.UUID,
    body: UncertainIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    item = payouts.mark_uncertain(
        db, principal.actor(client_ip(request)), item_id, note=body.note, user_id=principal.user.id
    )
    db.commit()
    return views.item_view(item, staff=True)


@router.get("/payout-items")
def list_items(
    owner_id: uuid.UUID | None = None,
    limit: int = Limit,
    offset: int = Offset,
    principal: Principal = Depends(require_any),
    db: Session = Depends(get_db),
):
    scope = scoped_owner_id(principal, owner_id)
    query = select(PayoutItem).order_by(PayoutItem.created_at.desc())
    if scope is not None:
        query = query.where(PayoutItem.owner_id == scope)
    staff = principal.role != "owner"
    return views.page(db, query, limit, offset, lambda i: views.item_view(i, staff=staff))


# --- exceptions ------------------------------------------------------------


@router.get("/exceptions")
def list_exceptions(
    status: str = Query("open", pattern="^(open|resolved|all)$"),
    limit: int = Limit,
    offset: int = Offset,
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
):
    query = select(ExceptionItem).order_by(ExceptionItem.created_at.desc())
    if status != "all":
        query = query.where(ExceptionItem.status == status)
    return views.page(db, query, limit, offset, views.exception_view)


@router.post("/exceptions/{exception_id}/resolve")
def resolve_exception(
    exception_id: uuid.UUID,
    body: ResolveIn,
    request: Request,
    principal: Principal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    item = exceptions_queue.resolve(
        db, principal.actor(client_ip(request)), exception_id, body.resolution, principal.user.id
    )
    db.commit()
    return views.exception_view(item)


# --- ledger and audit (admin, auditor) ------------------------------------


@router.get("/ledger/verify")
def ledger_verify(_: Principal = Depends(require_admin_or_auditor), db: Session = Depends(get_db)):
    return verify_ledger(db)


@router.get("/ledger/entries")
def ledger_entries(
    ref_type: str | None = None,
    ref_id: str | None = None,
    limit: int = Limit,
    offset: int = Offset,
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
):
    query = select(JournalEntry).order_by(JournalEntry.posted_at.desc(), JournalEntry.id)
    if ref_type:
        query = query.where(JournalEntry.ref_type == ref_type)
    if ref_id:
        query = query.where(JournalEntry.ref_id == ref_id)
    codes = dict(db.execute(select(LedgerAccount.id, LedgerAccount.code)).all())

    def render(entry: JournalEntry) -> dict:
        lines = db.execute(
            select(JournalLine).where(JournalLine.entry_id == entry.id).order_by(JournalLine.id)
        ).scalars()
        return {
            "id": str(entry.id),
            "type": entry.entry_type,
            "description": entry.description,
            "occurred_on": entry.occurred_on.isoformat(),
            "posted_at": views.iso(entry.posted_at),
            "ref": {"type": entry.ref_type, "id": entry.ref_id},
            "reverses": str(entry.reverses_entry_id) if entry.reverses_entry_id else None,
            "lines": [
                {
                    "account": codes.get(line.account_id, str(line.account_id)),
                    "debit": money_str(line.amount) if line.amount > 0 else None,
                    "credit": money_str(-line.amount) if line.amount < 0 else None,
                    "currency": line.currency,
                }
                for line in lines
            ],
        }

    return views.page(db, query, limit, offset, render)


@router.get("/audit-log")
def audit_log(
    action: str | None = None,
    owner_id: uuid.UUID | None = None,
    limit: int = Limit,
    offset: int = Offset,
    _: Principal = Depends(require_admin_or_auditor),
    db: Session = Depends(get_db),
):
    query = select(AuditLog).order_by(AuditLog.id.desc())
    if action:
        query = query.where(AuditLog.action == action)
    if owner_id:
        query = query.where(AuditLog.owner_id == owner_id)

    def render(row: AuditLog) -> dict:
        return {
            "id": row.id,
            "at": views.iso(row.at),
            "actor_type": row.actor_type,
            "actor_id": row.actor_id,
            "action": row.action,
            "object_type": row.object_type,
            "object_id": row.object_id,
            "owner_id": str(row.owner_id) if row.owner_id else None,
            "ip": row.ip,
            "details": row.details,
            "hash": row.hash,
        }

    return views.page(db, query, limit, offset, render)


@router.get("/audit-log/verify")
def audit_verify(_: Principal = Depends(require_admin_or_auditor), db: Session = Depends(get_db)):
    return verify_chain(db)
