"""Double-entry operational subledger.

Rules enforced here and again by database triggers (see the migration):

- Journal entries and lines are immutable. A mistake is corrected by a new
  reversing entry, never by an update.
- Every entry balances to zero per currency.
- Every entry has an idempotency key with a unique constraint, so posting the
  same business event twice creates one entry.
- Accounts that must never be overdrawn (owner available, reserved, in
  transit, unallocated receipts, cash clearing) are refused by the database
  when a line would overdraw them, even under concurrent transactions.

Amounts are ``Decimal`` with eight decimal places. A positive line is a debit
and a negative line is a credit.

This is an operational ledger for owner settlements. It is not a statutory
accounting system and has not been reviewed by an accountant.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import date
from decimal import ROUND_DOWN, ROUND_HALF_EVEN, Decimal
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..errors import InsufficientFunds, InvalidRequest
from ..models import JournalEntry, JournalLine, LedgerAccount, LedgerBalance

Q8 = Decimal("0.00000001")
Q2 = Decimal("0.01")
ZERO = Decimal("0")
CURRENCY = "USD"


def q8(value: Decimal | int | str) -> Decimal:
    return Decimal(value).quantize(Q8, rounding=ROUND_HALF_EVEN)


def money_str(value: Decimal | int | str) -> str:
    """Plain fixed-point text. ``str(Decimal("0E-8"))`` would print ``0E-8``."""
    return format(Decimal(value), "f")


def floor_cents(value: Decimal) -> Decimal:
    """Round down to cents. Used once, at settlement; the remainder carries forward."""
    return Decimal(value).quantize(Q2, rounding=ROUND_DOWN)


_MONEY_RE = re.compile(r"-?[0-9]{1,14}(\.[0-9]{1,8})?", re.ASCII)


def to_decimal(value: Any, field: str = "amount") -> Decimal:
    """Parse money from outside input: a plain decimal string and nothing else.

    Refused: binary floats, exponents ("1e3"), digit separators ("1_0"),
    non-ASCII digits, signs other than a leading minus, more than 8 decimals,
    more than 14 integer digits, surrounding whitespace.
    """
    if isinstance(value, float):
        raise InvalidRequest(f"{field} must be a decimal string, not a floating point number")
    if isinstance(value, Decimal):
        text_value = format(value, "f")
    elif isinstance(value, bool) or not isinstance(value, int | str):
        raise InvalidRequest(f"{field} is not a valid decimal amount")
    else:
        # Not stripped: " 1" is not a plain decimal. Callers that read a form
        # field or a file strip it themselves, where that is the intent.
        text_value = str(value)
    if not _MONEY_RE.fullmatch(text_value):
        raise InvalidRequest(
            f"{field} must be a plain decimal amount such as 1234.56 (at most 8 decimal places)"
        )
    return Decimal(text_value).quantize(Q8)


# kind -> (normal side, overdraft allowed)
ACCOUNT_RULES: dict[str, tuple[str, bool]] = {
    # What the provider reports it owes us and has not paid yet. May go
    # negative when a bucket is revised downwards after it was received.
    "provider_receivable": ("debit", True),
    # Cash confirmed received by reconciliation.
    "cash_clearing": ("debit", False),
    # Suspense: cash received and not yet matched to earnings.
    "receipts_unallocated": ("credit", False),
    # Reported earnings of machines not mapped to an owner.
    "unmapped_earnings": ("credit", True),
    # Owner share of reported earnings not yet received. Not payable.
    "owner_accrued": ("credit", True),
    # Owner share received and reconciled: available to settle.
    "owner_available": ("credit", False),
    # Reserved in an approved payout.
    "owner_reserved": ("credit", False),
    # Payout submitted, outcome not yet confirmed.
    "owner_in_transit": ("credit", False),
    # Management fee on reported, not yet received, earnings.
    "fee_accrued": ("credit", True),
    # Management fee on received and reconciled earnings.
    "fee_earned": ("credit", True),
}


def account_code(kind: str, scope: uuid.UUID | None) -> str:
    return f"{kind}:{scope}" if scope else kind


def get_account(
    db: Session,
    kind: str,
    *,
    owner_id: uuid.UUID | None = None,
    provider_account_id: uuid.UUID | None = None,
) -> LedgerAccount:
    """Return the account, creating it on first use (race-safe)."""
    side, overdraft = ACCOUNT_RULES[kind]
    code = account_code(kind, owner_id or provider_account_id)
    found = db.execute(select(LedgerAccount).where(LedgerAccount.code == code)).scalar_one_or_none()
    if found:
        return found
    db.execute(
        pg_insert(LedgerAccount)
        .values(
            id=uuid.uuid4(),
            code=code,
            kind=kind,
            owner_id=owner_id,
            provider_account_id=provider_account_id,
            currency=CURRENCY,
            normal_side=side,
            allow_overdraft=overdraft,
        )
        .on_conflict_do_nothing(index_elements=["code"])
    )
    return db.execute(select(LedgerAccount).where(LedgerAccount.code == code)).scalar_one()


def balance_of(db: Session, account: LedgerAccount) -> Decimal:
    """Balance in the account's natural direction (credit accounts read positive).

    Read without a row lock: callers that must not race take an advisory lock
    (``lock_owner``) first, and the overdraft trigger is the backstop.
    """
    raw = db.execute(
        select(LedgerBalance.balance).where(LedgerBalance.account_id == account.id)
    ).scalar_one_or_none()
    raw = raw or ZERO
    return raw if account.normal_side == "debit" else -raw


@dataclass(frozen=True)
class Line:
    account: LedgerAccount
    amount: Decimal  # positive debit, negative credit


def debit(account: LedgerAccount, amount: Decimal) -> Line:
    return Line(account, q8(amount))


def credit(account: LedgerAccount, amount: Decimal) -> Line:
    return Line(account, -q8(amount))


def post_entry(
    db: Session,
    *,
    entry_type: str,
    idempotency_key: str,
    lines: list[Line],
    occurred_on: date,
    description: str = "",
    created_by: uuid.UUID | None = None,
    ref_type: str = "",
    ref_id: Any = "",
    reverses: JournalEntry | None = None,
) -> tuple[JournalEntry, bool]:
    """Post one balanced entry. Returns (entry, created).

    If an entry with the same idempotency key already exists it is returned
    unchanged with ``created=False``.
    """
    existing = db.execute(
        select(JournalEntry).where(JournalEntry.idempotency_key == idempotency_key)
    ).scalar_one_or_none()
    if existing:
        return existing, False

    merged: dict[uuid.UUID, Decimal] = defaultdict(lambda: ZERO)
    accounts: dict[uuid.UUID, LedgerAccount] = {}
    for line in lines:
        merged[line.account.id] += line.amount
        accounts[line.account.id] = line.account
    merged = {k: q8(v) for k, v in merged.items() if q8(v) != ZERO}
    if len(merged) < 2:
        raise InvalidRequest("a journal entry needs at least two non-zero lines")
    if sum(merged.values(), ZERO) != ZERO:
        raise InvalidRequest("journal entry does not balance")
    if {accounts[k].currency for k in merged} != {CURRENCY}:
        raise InvalidRequest("only USD entries are supported")

    entry = JournalEntry(
        id=uuid.uuid4(),
        entry_type=entry_type,
        idempotency_key=idempotency_key,
        description=description[:500],
        occurred_on=occurred_on,
        created_by=created_by,
        reverses_entry_id=reverses.id if reverses else None,
        ref_type=ref_type,
        ref_id=str(ref_id or ""),
    )
    try:
        # Savepoint: on failure only this entry is undone and every object
        # added inside the block is expunged from the session.
        with db.begin_nested():
            db.add(entry)
            db.flush()
            # Stable order so concurrent postings lock balance rows consistently.
            for account_id in sorted(merged):
                db.add(
                    JournalLine(
                        entry_id=entry.id, account_id=account_id, amount=merged[account_id], currency=CURRENCY
                    )
                )
            db.flush()
    except IntegrityError as exc:
        message = str(exc.orig)
        if "ledger overdraft" in message:
            raise InsufficientFunds() from exc
        if "idempotency_key" in message:
            # A concurrent transaction posted the same event first.
            winner = db.execute(
                select(JournalEntry).where(JournalEntry.idempotency_key == idempotency_key)
            ).scalar_one()
            return winner, False
        raise
    return entry, True


def reverse_entry(
    db: Session, entry: JournalEntry, *, reason: str, created_by: uuid.UUID | None, occurred_on: date
) -> tuple[JournalEntry, bool]:
    """Post the mirror image of ``entry``. The original stays untouched."""
    lines = db.execute(select(JournalLine).where(JournalLine.entry_id == entry.id)).scalars().all()
    accounts = {
        a.id: a
        for a in db.execute(
            select(LedgerAccount).where(LedgerAccount.id.in_([line.account_id for line in lines]))
        ).scalars()
    }
    return post_entry(
        db,
        entry_type=f"reversal:{entry.entry_type}"[:40],
        idempotency_key=f"reversal:{entry.id}",
        lines=[Line(accounts[line.account_id], -line.amount) for line in lines],
        occurred_on=occurred_on,
        description=f"Reversal of {entry.id}: {reason}",
        created_by=created_by,
        ref_type=entry.ref_type,
        ref_id=entry.ref_id,
        reverses=entry,
    )


# --- owner balances --------------------------------------------------------


@dataclass(frozen=True)
class OwnerBalances:
    accrued: Decimal  # reported by the provider, cash not received: not payable
    available: Decimal  # received and reconciled: can be settled
    reserved: Decimal  # in an approved payout
    in_transit: Decimal  # submitted, outcome not confirmed

    def as_dict(self) -> dict[str, str]:
        return {
            "accrued_reported": money_str(self.accrued),
            "available_to_settle": money_str(self.available),
            "reserved_in_approved_payout": money_str(self.reserved),
            "submitted_in_transit": money_str(self.in_transit),
            "payable_now": money_str(
                floor_cents(self.available) if self.available > ZERO else ZERO.quantize(Q2)
            ),
        }


def owner_balances(db: Session, owner_id: uuid.UUID) -> OwnerBalances:
    rows = db.execute(
        select(LedgerAccount.kind, LedgerBalance.balance)
        .join(LedgerBalance, LedgerBalance.account_id == LedgerAccount.id)
        .where(LedgerAccount.owner_id == owner_id)
    ).all()
    by_kind = {kind: -balance for kind, balance in rows}  # all owner accounts are credit-normal
    return OwnerBalances(
        accrued=by_kind.get("owner_accrued", ZERO),
        available=by_kind.get("owner_available", ZERO),
        reserved=by_kind.get("owner_reserved", ZERO),
        in_transit=by_kind.get("owner_in_transit", ZERO),
    )


# --- verification ----------------------------------------------------------


def verify_ledger(db: Session) -> dict[str, Any]:
    """Recompute everything from the journal and compare with the cached state."""
    problems: list[str] = []

    unbalanced = db.execute(
        select(JournalLine.entry_id, JournalLine.currency, func.sum(JournalLine.amount))
        .group_by(JournalLine.entry_id, JournalLine.currency)
        .having(func.sum(JournalLine.amount) != 0)
    ).all()
    for entry_id, currency, total in unbalanced:
        problems.append(f"entry {entry_id} does not balance in {currency}: {total}")

    computed = dict(
        db.execute(
            select(JournalLine.account_id, func.sum(JournalLine.amount)).group_by(JournalLine.account_id)
        ).all()
    )
    cached = dict(db.execute(select(LedgerBalance.account_id, LedgerBalance.balance)).all())
    for account_id in set(computed) | set(cached):
        if q8(computed.get(account_id, ZERO)) != q8(cached.get(account_id, ZERO)):
            problems.append(
                f"balance cache mismatch for account {account_id}: "
                f"journal {computed.get(account_id, ZERO)} vs cache {cached.get(account_id, ZERO)}"
            )

    accounts = {a.id: a for a in db.execute(select(LedgerAccount)).scalars()}
    for account_id, raw in computed.items():
        account = accounts[account_id]
        natural = raw if account.normal_side == "debit" else -raw
        if not account.allow_overdraft and natural < ZERO:
            problems.append(f"account {account.code} is overdrawn: {natural}")

    # Cash on hand must cover everything owed out of reconciled funds.
    totals: dict[str, Decimal] = defaultdict(lambda: ZERO)
    for account_id, raw in computed.items():
        account = accounts[account_id]
        totals[account.kind] += raw if account.normal_side == "debit" else -raw
    owed = (
        totals["owner_available"]
        + totals["owner_reserved"]
        + totals["owner_in_transit"]
        + totals["receipts_unallocated"]
        + totals["fee_earned"]
    )
    if q8(totals["cash_clearing"]) != q8(owed):
        problems.append(
            f"cash clearing {totals['cash_clearing']} does not equal reconciled obligations {owed}"
        )

    # Account definitions must still be what the code says they are.
    # The code is fixed when the account is created and encodes its kind and
    # scope, so a relabelled or re-pointed account no longer agrees with it.
    for account in accounts.values():
        expected = ACCOUNT_RULES.get(account.kind)
        scope = account.owner_id or account.provider_account_id
        if (
            expected is None
            or (account.normal_side, account.allow_overdraft) != expected
            or account.code != account_code(account.kind, scope)
        ):
            problems.append(f"account {account.code} no longer matches its definition")

    problems.extend(_verify_reconciliation(db, accounts, computed))

    grand_total = db.execute(select(func.coalesce(func.sum(JournalLine.amount), 0))).scalar_one()
    if q8(grand_total) != ZERO:
        problems.append(f"journal does not sum to zero: {grand_total}")

    entries = db.execute(select(func.count()).select_from(JournalEntry)).scalar_one()
    return {
        "ok": not problems,
        "entries": entries,
        "problems": problems,
        "totals": {k: money_str(q8(v)) for k, v in sorted(totals.items())},
    }


def _verify_reconciliation(
    db: Session, accounts: dict[uuid.UUID, LedgerAccount], computed: dict[uuid.UUID, Decimal]
) -> list[str]:
    """Check the reconciliation tables against each other and against the journal.

    The bucket and receipt rows carry running totals. They are convenient, and
    they would hide an error if nothing compared them with the allocations
    they summarise.
    """
    from ..models import EarningBucket, ExceptionItem, ProviderReceipt, ReceiptAllocation

    problems: list[str] = []
    allocated = func.coalesce(func.sum(ReceiptAllocation.amount), 0)

    for bucket_id, received, total in db.execute(
        select(EarningBucket.id, EarningBucket.received_amount, allocated)
        .outerjoin(ReceiptAllocation, ReceiptAllocation.bucket_id == EarningBucket.id)
        .group_by(EarningBucket.id)
        .having(EarningBucket.received_amount != allocated)
    ):
        problems.append(f"bucket {bucket_id}: received {received} but its allocations sum to {total}")

    for receipt_id, recorded, total in db.execute(
        select(ProviderReceipt.id, ProviderReceipt.allocated_amount, allocated)
        .outerjoin(ReceiptAllocation, ReceiptAllocation.receipt_id == ProviderReceipt.id)
        .group_by(ProviderReceipt.id)
        .having(ProviderReceipt.allocated_amount != allocated)
    ):
        problems.append(f"receipt {receipt_id}: allocated {recorded} but its allocations sum to {total}")

    # More received than reported is only acceptable while an exception is open for it.
    flagged = {
        key.removeprefix("over_received:")
        for key in db.execute(
            select(ExceptionItem.dedupe_key).where(
                ExceptionItem.status == "open", ExceptionItem.kind == "over_received"
            )
        ).scalars()
        if key
    }
    for bucket_id, reported, received in db.execute(
        select(EarningBucket.id, EarningBucket.reported_amount, EarningBucket.received_amount).where(
            (
                (EarningBucket.reported_amount >= 0)
                & (EarningBucket.received_amount > EarningBucket.reported_amount)
            )
            | (
                (EarningBucket.reported_amount < 0)
                & (EarningBucket.received_amount < EarningBucket.reported_amount)
            )
            | ((EarningBucket.reported_amount >= 0) & (EarningBucket.received_amount < 0))
        )
    ):
        if str(bucket_id) not in flagged:
            problems.append(
                f"bucket {bucket_id}: received {received} exceeds reported {reported} with no open exception"
            )

    # A mapped bucket's reported amount is split between the owner and the fee, to the last digit.
    for bucket_id, reported, owner_part, fee_part in db.execute(
        select(
            EarningBucket.id,
            EarningBucket.reported_amount,
            EarningBucket.owner_accrued,
            EarningBucket.fee_accrued,
        ).where(
            EarningBucket.status == "mapped",
            EarningBucket.owner_accrued + EarningBucket.fee_accrued != EarningBucket.reported_amount,
        )
    ):
        problems.append(
            f"bucket {bucket_id}: reported {reported} but owner share {owner_part} plus fee {fee_part} "
            "do not add up to it"
        )

    # What the provider still owes, per provider account, is reported minus received.
    outstanding = dict(
        db.execute(
            select(
                EarningBucket.provider_account_id,
                func.sum(EarningBucket.reported_amount - EarningBucket.received_amount),
            ).group_by(EarningBucket.provider_account_id)
        ).all()
    )
    receivable = {
        account.provider_account_id: computed.get(account.id, ZERO)
        for account in accounts.values()
        if account.kind == "provider_receivable"
    }
    for provider_account_id in set(outstanding) | set(receivable):
        if q8(outstanding.get(provider_account_id, ZERO)) != q8(receivable.get(provider_account_id, ZERO)):
            problems.append(
                f"provider account {provider_account_id}: buckets show "
                f"{outstanding.get(provider_account_id, ZERO)} reported and not received, the journal shows "
                f"{receivable.get(provider_account_id, ZERO)} receivable"
            )

    # Owner accrued accounts must equal what the buckets say is accrued and not yet released.
    by_owner = dict(
        db.execute(
            select(
                EarningBucket.owner_id,
                func.sum(EarningBucket.owner_accrued - EarningBucket.owner_released),
            )
            .where(EarningBucket.owner_id.is_not(None))
            .group_by(EarningBucket.owner_id)
        ).all()
    )
    journal_by_owner = {
        account.owner_id: -computed.get(account.id, ZERO)
        for account in accounts.values()
        if account.kind == "owner_accrued"
    }
    for owner_id in set(by_owner) | set(journal_by_owner):
        if q8(by_owner.get(owner_id, ZERO)) != q8(journal_by_owner.get(owner_id, ZERO)):
            problems.append(
                f"owner {owner_id}: buckets show {by_owner.get(owner_id, ZERO)} accrued, "
                f"the journal shows {journal_by_owner.get(owner_id, ZERO)}"
            )
    return problems


def lock_owner(db: Session, owner_id: uuid.UUID) -> None:
    """Serialise settlement work for one owner for the rest of the transaction."""
    db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": f"owner:{owner_id}"})
