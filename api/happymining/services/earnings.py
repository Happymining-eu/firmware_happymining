"""Replay-safe, revision-aware earnings import.

Canonical accounting unit: one **bucket** = one provider machine on one closed
UTC day. Buckets never overlap, so provider reports that overlap or are
fetched twice cannot double-count: an import only posts the *difference*
between what the provider says now and what is already recorded for a bucket.

- Unchanged report -> no revision, no journal entry.
- Changed amount -> a new revision and one adjustment entry for the delta.
- Unmapped machine, unknown currency, mismatched totals, unverified provider
  semantics -> exception queue; nothing becomes payable.

Reported earnings are an accrual. They are not cash and are never available to
pay out until a receipt has been reconciled against them (see receipts.py).

Per-job detail is never invented: the provider reports per machine per day and
that is the finest grain stored.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..db import lock_row
from ..errors import Conflict, InvalidRequest, NotFound
from ..models import (
    EarningBucket,
    EarningRevision,
    EarningsImport,
    ExceptionItem,
    FeeSchedule,
    MachineOwnership,
    ProviderAccount,
    ProviderBindingEvent,
    ProviderMachine,
    SourceSnapshot,
    utcnow,
)
from ..providers.base import EarningsReport, EarningsRow
from .exceptions_queue import raise_exception, resolve_by_key
from .fees import fee_for
from .ledger import CURRENCY, ZERO, Line, get_account, money_str, post_entry, q8

TOTAL_TOLERANCE = Decimal("0.000001")


@dataclass(frozen=True)
class Mapping:
    machine_id: uuid.UUID | None = None
    owner_id: uuid.UUID | None = None
    fee: FeeSchedule | None = None
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.fee is not None


def bound_machine_on(db: Session, pm: ProviderMachine, day: date) -> uuid.UUID | None:
    """Which HappyMining machine this provider machine was bound to on ``day``.

    The current binding covers ``[bound_from, ...)``. Earlier bindings are
    read from the binding history, each covering ``[bind day, unbind day)``,
    so days that were earned under a previous binding stay attributable after
    an unbind, whenever they are imported.
    """
    if pm.machine_id is not None and pm.bound_from is not None and day >= pm.bound_from:
        return pm.machine_id
    events = db.execute(
        select(ProviderBindingEvent)
        .where(ProviderBindingEvent.provider_machine_id == pm.id)
        .order_by(ProviderBindingEvent.at, ProviderBindingEvent.id)
    ).scalars()
    open_bind: ProviderBindingEvent | None = None
    for event in events:
        if event.action == "bind":
            open_bind = event
        elif open_bind is not None:
            if open_bind.effective_day <= day < event.effective_day:
                return open_bind.machine_id
            open_bind = None
    return None


def resolve_mapping(db: Session, account: ProviderAccount, external_machine_id: str, day: date) -> Mapping:
    """Who owned this provider machine on ``day`` and at which fee. No guessing."""
    pm = db.execute(
        select(ProviderMachine).where(
            ProviderMachine.provider_account_id == account.id,
            ProviderMachine.external_id == external_machine_id,
        )
    ).scalar_one_or_none()
    if pm is None:
        return Mapping(reason="provider machine is not known")
    machine_id = bound_machine_on(db, pm, day)
    if machine_id is None:
        return Mapping(reason="provider machine was not bound to a HappyMining machine on that day")
    ownership = db.execute(
        select(MachineOwnership).where(
            MachineOwnership.machine_id == machine_id,
            MachineOwnership.valid_from <= day,
            (MachineOwnership.valid_to.is_(None)) | (MachineOwnership.valid_to > day),
        )
    ).scalar_one_or_none()
    if ownership is None:
        return Mapping(reason="no owner on record for this machine on that day")
    fee = fee_for(db, ownership.owner_id, day)
    if fee is None:
        return Mapping(
            machine_id=machine_id, owner_id=ownership.owner_id, reason="no fee schedule in force on that day"
        )
    return Mapping(machine_id=machine_id, owner_id=ownership.owner_id, fee=fee)


def content_hash(report: EarningsReport) -> str:
    rows = sorted(
        (r.external_machine_id, r.day.isoformat(), str(q8(r.amount)), r.currency) for r in report.rows
    )
    material = json.dumps(
        {"rows": rows, "start": report.period_start.isoformat(), "end": report.period_end.isoformat()},
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode()).hexdigest()


def _lock_bucket(db: Session, account: ProviderAccount, row: EarningsRow, synthetic: bool) -> EarningBucket:
    key = (
        EarningBucket.provider_account_id == account.id,
        EarningBucket.external_machine_id == row.external_machine_id,
        EarningBucket.day == row.day,
    )
    bucket = db.execute(
        select(EarningBucket).where(*key).with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if bucket:
        return bucket
    db.execute(
        pg_insert(EarningBucket)
        .values(
            id=uuid.uuid4(),
            provider_account_id=account.id,
            external_machine_id=row.external_machine_id,
            day=row.day,
            currency=row.currency,
            status="unmapped",
            is_synthetic=synthetic,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        .on_conflict_do_nothing(constraint="uq_earning_bucket")
    )
    return db.execute(
        select(EarningBucket).where(*key).with_for_update().execution_options(populate_existing=True)
    ).scalar_one()


def _post_revision(
    db: Session,
    account: ProviderAccount,
    bucket: EarningBucket,
    imp: EarningsImport,
    row: EarningsRow,
    created_by: uuid.UUID | None,
) -> str:
    """Post the delta for one bucket. Returns 'new', 'revised' or 'unchanged'."""
    new_reported = q8(row.amount)
    is_new = bucket.revision_count == 0

    if is_new:
        mapping = resolve_mapping(db, account, row.external_machine_id, row.day)
        if mapping.ok:
            assert mapping.fee is not None
            bucket.status = "mapped"
            bucket.machine_id = mapping.machine_id
            bucket.owner_id = mapping.owner_id
            bucket.fee_schedule_id = mapping.fee.id
            bucket.fee_rate = mapping.fee.rate
        else:
            kind = "no_fee_schedule" if "fee schedule" in mapping.reason else "unmapped_machine"
            raise_exception(
                db,
                kind,
                f"Earnings for provider machine {row.external_machine_id} cannot be attributed: "
                f"{mapping.reason}",
                dedupe_key=f"unmapped:{account.id}:{row.external_machine_id}",
                details={"external_machine_id": row.external_machine_id, "first_day": row.day.isoformat()},
                provider_account_id=account.id,
            )

    delta = new_reported - bucket.reported_amount
    if delta == ZERO and not is_new:
        return "unchanged"
    if delta == ZERO and is_new:
        # A zero-earning day: record the bucket and its revision, nothing to post.
        bucket.revision_count = 1
        db.add(
            EarningRevision(
                bucket_id=bucket.id,
                import_id=imp.id,
                revision_no=1,
                reported_amount=new_reported,
                delta=ZERO,
                components=row.components,
            )
        )
        db.flush()
        return "new"

    revision_no = bucket.revision_count + 1
    receivable = get_account(db, "provider_receivable", provider_account_id=account.id)
    if bucket.status == "mapped":
        assert bucket.fee_rate is not None and bucket.owner_id is not None
        fee_total = q8(new_reported * bucket.fee_rate)
        fee_delta = fee_total - bucket.fee_accrued
        owner_delta = delta - fee_delta
        lines = [
            Line(receivable, delta),
            Line(get_account(db, "owner_accrued", owner_id=bucket.owner_id), -owner_delta),
            Line(get_account(db, "fee_accrued"), -fee_delta),
        ]
        bucket.fee_accrued = fee_total
        bucket.owner_accrued = bucket.owner_accrued + owner_delta
    else:
        lines = [
            Line(receivable, delta),
            Line(get_account(db, "unmapped_earnings", provider_account_id=account.id), -delta),
        ]

    entry, _ = post_entry(
        db,
        entry_type="earning_accrual" if is_new else "earning_adjustment",
        idempotency_key=f"earning:{bucket.id}:rev:{revision_no}",
        lines=lines,
        occurred_on=row.day,
        description=(
            f"Provider-reported earnings, machine {row.external_machine_id}, {row.day.isoformat()}"
            + ("" if is_new else f" (revision {revision_no}, delta {delta})")
        ),
        created_by=created_by,
        ref_type="earning_bucket",
        ref_id=bucket.id,
    )
    db.add(
        EarningRevision(
            bucket_id=bucket.id,
            import_id=imp.id,
            revision_no=revision_no,
            reported_amount=new_reported,
            delta=delta,
            components=row.components,
            journal_entry_id=entry.id,
        )
    )
    bucket.reported_amount = new_reported
    bucket.revision_count = revision_no
    bucket.updated_at = utcnow()
    db.flush()

    if not is_new:
        raise_exception(
            db,
            "unexplained_adjustment",
            f"Provider changed earnings for machine {row.external_machine_id} on {row.day.isoformat()} "
            f"by {delta} (revision {revision_no}). Review before reconciling this day.",
            dedupe_key=f"adjustment:{bucket.id}",
            details={"bucket_id": str(bucket.id), "delta": str(delta), "revision": revision_no},
            provider_account_id=account.id,
            owner_id=bucket.owner_id,
        )
    if new_reported < ZERO:
        raise_exception(
            db,
            "unexplained_adjustment",
            f"Negative reported earnings ({new_reported}) for machine {row.external_machine_id} "
            f"on {row.day.isoformat()}.",
            dedupe_key=f"negative:{bucket.id}",
            details={"bucket_id": str(bucket.id), "reported": str(new_reported)},
            provider_account_id=account.id,
            owner_id=bucket.owner_id,
        )
    if (new_reported >= ZERO and bucket.received_amount > new_reported) or (
        new_reported < ZERO and bucket.received_amount != ZERO
    ):
        raise_exception(
            db,
            "over_received",
            f"Machine {row.external_machine_id} on {row.day.isoformat()}: received {bucket.received_amount} "
            f"now exceeds reported {new_reported}. The difference must be recovered; see docs/ledger.md.",
            dedupe_key=f"over_received:{bucket.id}",
            details={"bucket_id": str(bucket.id)},
            provider_account_id=account.id,
            owner_id=bucket.owner_id,
        )
    return "new" if is_new else "revised"


def import_earnings(
    db: Session,
    actor: Actor,
    account: ProviderAccount,
    report: EarningsReport,
    *,
    created_by: uuid.UUID | None = None,
    today: date | None = None,
) -> EarningsImport:
    """Import one provider report. Safe to repeat with the same or overlapping data."""
    today = today or datetime.now(UTC).date()
    if report.period_end < report.period_start:
        raise InvalidRequest("period_end is before period_start")
    if report.period_end >= today:
        raise InvalidRequest("only closed UTC days can be imported; period_end must be before today (UTC)")

    snapshot = SourceSnapshot(
        provider_account_id=account.id,
        kind="earnings_report",
        params={"start": report.period_start.isoformat(), "end": report.period_end.isoformat()},
        sha256=hashlib.sha256(report.raw_body).hexdigest(),
        body=report.raw_body,
        is_synthetic=report.is_synthetic,
        fetched_at=report.fetched_at,
        created_by=created_by,
    )
    db.add(snapshot)

    digest = content_hash(report)
    imp = EarningsImport(
        provider_account_id=account.id,
        period_start=report.period_start,
        period_end=report.period_end,
        content_sha256=digest,
        status="posted",
        is_synthetic=report.is_synthetic,
        created_by=created_by,
        stats={},
    )
    db.add(imp)
    db.flush()
    stats: dict[str, Any] = {"rows": len(report.rows), "new": 0, "revised": 0, "unchanged": 0, "skipped": 0}
    stats["snapshot_id"] = str(snapshot.id)

    def finish(status: str) -> EarningsImport:
        imp.status = status
        imp.stats = stats
        db.flush()
        audit(
            db,
            actor,
            "earnings.import",
            object_type="earnings_import",
            object_id=imp.id,
            details={"status": status, "period": [str(report.period_start), str(report.period_end)], **stats},
        )
        return imp

    # 1. Structural anomalies found by the adapter: hold everything.
    out_of_range = [r for r in report.rows if not (report.period_start <= r.day <= report.period_end)]
    anomalies = list(report.anomalies)
    if out_of_range:
        anomalies.append(f"{len(out_of_range)} row(s) fall outside the requested period")
    seen: set[tuple[str, date]] = set()
    for r in report.rows:
        if (r.external_machine_id, r.day) in seen:
            anomalies.append(f"duplicate row for machine {r.external_machine_id} on {r.day}")
        seen.add((r.external_machine_id, r.day))
    if anomalies:
        stats["anomalies"] = anomalies[:20]
        raise_exception(
            db,
            "malformed_report",
            f"Earnings report {report.period_start}..{report.period_end} was not posted: {anomalies[0]}",
            dedupe_key=f"malformed:{account.id}:{digest}",
            details={"import_id": str(imp.id), "anomalies": anomalies[:20]},
            provider_account_id=account.id,
        )
        return finish("exception")

    # 2. Provider totals must match the rows they summarise.
    for machine_id, declared in report.declared_totals.items():
        actual = sum((r.amount for r in report.rows if r.external_machine_id == machine_id), ZERO)
        if abs(q8(actual) - q8(declared)) > TOTAL_TOLERANCE:
            stats["mismatch"] = {"machine": machine_id, "declared": str(declared), "rows": str(q8(actual))}
            raise_exception(
                db,
                "total_mismatch",
                f"Earnings report {report.period_start}..{report.period_end}: provider total {declared} for "
                f"machine {machine_id} does not match the sum of its daily rows {q8(actual)}. Not posted.",
                dedupe_key=f"mismatch:{account.id}:{digest}",
                details={"import_id": str(imp.id), **stats["mismatch"]},
                provider_account_id=account.id,
            )
            return finish("exception")

    # 3. Semantics that are not verified are never posted.
    if report.basis != "net_of_provider_fee" or not report.buckets_verified:
        stats["basis"] = report.basis
        stats["buckets_verified"] = report.buckets_verified
        raise_exception(
            db,
            "unverified_semantics",
            "Provider earnings are being fetched but not posted: whether amounts are net of the provider's "
            "fee and how day boundaries work has not been verified. "
            "See docs/integration-evidence.md (C8, C11).",
            dedupe_key=f"unverified:{account.id}",
            details={"basis": report.basis, "buckets_verified": report.buckets_verified},
            provider_account_id=account.id,
        )
        return finish("held_unverified")

    # 4. Post bucket by bucket, in a stable order.
    foreign = sorted({r.currency for r in report.rows if r.currency != CURRENCY})
    for currency in foreign:
        raise_exception(
            db,
            "unknown_currency",
            f"Earnings reported in {currency}; only {CURRENCY} is settled. These rows were not posted.",
            dedupe_key=f"currency:{account.id}:{currency}:{digest}",
            details={"import_id": str(imp.id), "currency": currency},
            provider_account_id=account.id,
        )
    for row in sorted(report.rows, key=lambda r: (r.external_machine_id, r.day)):
        if row.currency != CURRENCY:
            stats["skipped"] += 1
            continue
        bucket = _lock_bucket(db, account, row, report.is_synthetic)
        outcome = _post_revision(db, account, bucket, imp, row, created_by)
        stats[outcome] += 1

    # 5. A day we hold a non-zero amount for, in a period and for a machine this
    #    report covers, that the provider no longer mentions. What that means is
    #    not documented, so nothing is changed: it is flagged for a person.
    if report.covered_machines:
        present = {(r.external_machine_id, r.day) for r in report.rows}
        vanished = db.execute(
            select(EarningBucket).where(
                EarningBucket.provider_account_id == account.id,
                EarningBucket.external_machine_id.in_(sorted(report.covered_machines)),
                EarningBucket.day >= report.period_start,
                EarningBucket.day <= report.period_end,
                EarningBucket.reported_amount != ZERO,
            )
        ).scalars()
        missing = [b for b in vanished if (b.external_machine_id, b.day) not in present]
        for bucket in missing:
            raise_exception(
                db,
                "missing_from_report",
                f"Machine {bucket.external_machine_id} on {bucket.day.isoformat()} was reported as "
                f"{money_str(bucket.reported_amount)} and is absent from a later report covering that day. "
                "The recorded amount was left unchanged.",
                dedupe_key=f"missing:{bucket.id}",
                details={"bucket_id": str(bucket.id), "import_id": str(imp.id)},
                provider_account_id=account.id,
                owner_id=bucket.owner_id,
            )
        stats["missing_from_report"] = len(missing)

    return finish("posted" if (stats["new"] or stats["revised"] or stats["skipped"]) else "duplicate")


def remap_bucket(
    db: Session, actor: Actor, bucket_id: uuid.UUID, *, created_by: uuid.UUID | None
) -> EarningBucket:
    """Attribute a previously unmapped bucket once its machine has been bound."""
    bucket = lock_row(db, EarningBucket, bucket_id)
    if not bucket:
        raise NotFound()
    if bucket.status != "unmapped":
        raise Conflict("this bucket is already attributed to an owner")
    account = db.get(ProviderAccount, bucket.provider_account_id)
    assert account is not None
    mapping = resolve_mapping(db, account, bucket.external_machine_id, bucket.day)
    if not mapping.ok:
        raise Conflict(f"still not attributable: {mapping.reason}")
    assert mapping.fee is not None and mapping.owner_id is not None

    fee_total = q8(bucket.reported_amount * mapping.fee.rate)
    owner_total = bucket.reported_amount - fee_total
    if bucket.reported_amount != ZERO:
        post_entry(
            db,
            entry_type="earning_attribution",
            idempotency_key=f"earning:{bucket.id}:attribute",
            lines=[
                Line(
                    get_account(db, "unmapped_earnings", provider_account_id=account.id),
                    bucket.reported_amount,
                ),
                Line(get_account(db, "owner_accrued", owner_id=mapping.owner_id), -owner_total),
                Line(get_account(db, "fee_accrued"), -fee_total),
            ],
            occurred_on=bucket.day,
            description=(
                f"Attribute machine {bucket.external_machine_id} {bucket.day.isoformat()} to its owner"
            ),
            created_by=created_by,
            ref_type="earning_bucket",
            ref_id=bucket.id,
        )
    bucket.status = "mapped"
    bucket.machine_id = mapping.machine_id
    bucket.owner_id = mapping.owner_id
    bucket.fee_schedule_id = mapping.fee.id
    bucket.fee_rate = mapping.fee.rate
    bucket.fee_accrued = fee_total
    bucket.owner_accrued = owner_total
    bucket.updated_at = utcnow()
    db.flush()
    audit(
        db,
        actor,
        "earnings.attribute_bucket",
        object_type="earning_bucket",
        object_id=bucket.id,
        owner_id=mapping.owner_id,
        details={"machine": bucket.external_machine_id, "day": bucket.day.isoformat()},
    )
    remaining = db.execute(
        select(EarningBucket.id)
        .where(
            EarningBucket.provider_account_id == account.id,
            EarningBucket.external_machine_id == bucket.external_machine_id,
            EarningBucket.status == "unmapped",
        )
        .limit(1)
    ).scalar_one_or_none()
    if remaining is None:
        resolve_by_key(
            db, f"unmapped:{account.id}:{bucket.external_machine_id}", "all buckets attributed", created_by
        )
    return bucket


def has_open_adjustment(db: Session, bucket_id: uuid.UUID) -> bool:
    return (
        db.execute(
            select(ExceptionItem.id).where(
                ExceptionItem.dedupe_key.in_([f"adjustment:{bucket_id}", f"negative:{bucket_id}"]),
                ExceptionItem.status == "open",
            )
        ).first()
        is not None
    )
