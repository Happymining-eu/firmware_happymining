"""Regression tests for the findings of the independent ledger review.

One section per finding, numbered as in the review. Everything runs against real PostgreSQL
through the shared fixtures. Concurrency tests give every thread its own session and release
the threads together with a barrier. Money is ``Decimal`` throughout.
"""

from __future__ import annotations

import csv
import io
import threading
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import psycopg
import pytest
from helpers import SYSTEM, World, dataset, live_settings
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.orm import sessionmaker
from test_earnings_ledger import count, open_exceptions, run_import, setup_fleet
from test_payouts import IBAN, funded, prepare

from happymining import cli
from happymining.audit import verify_chain
from happymining.db import get_engine, session_factory
from happymining.errors import AppError, Conflict, InsufficientFunds, InvalidRequest
from happymining.models import (
    EVIDENCE_SOURCES,
    AuditLog,
    EarningBucket,
    JournalEntry,
    JournalLine,
    LedgerAccount,
    LedgerBalance,
    PayoutBatch,
    PayoutEvidence,
    PayoutItem,
    ProviderAccount,
    ProviderMachine,
    ProviderReceipt,
    ReceiptAllocation,
)
from happymining.payout_providers.manual_export import ManualExportProvider
from happymining.payout_providers.mock import MockPayoutProvider
from happymining.providers import registry
from happymining.providers.base import EarningsReport, EarningsRow
from happymining.services import (
    earnings,
    exceptions_queue,
    fees,
    machines,
    payouts,
    provider_sync,
    receipts,
)
from happymining.services.ledger import balance_of, get_account, owner_balances, to_decimal, verify_ledger
from happymining.services.receipts import AllocationRequest

D = Decimal
ZERO = D("0")


# --- builders --------------------------------------------------------------


def build_fleet(world, plan, fee="0.10"):
    """Several owners, each with one machine bound to its own provider machine.

    ``plan`` maps owner name -> (provider machine id, {days_ago: amount}).
    Returns (owners by name, provider account, fake provider).
    """
    world.fee(fee)
    provider = world.provider(dataset({machine: {} for machine, _ in plan.values()}, dict(plan.values())))
    account = world.account(provider)
    owners = {}
    for name, (machine_id, _) in plan.items():
        owners[name] = world.owner(name)
        machine, _token = world.paired_machine(owners[name], f"m{machine_id}")
        world.bind(account, machine_id, machine)
    return owners, account, provider


def record(world, account, amount, reference="BANK-1"):
    """Record cash received, with statement evidence. Not allocated to anything yet."""
    receipt, created = receipts.record_receipt(
        world.session,
        SYSTEM,
        account,
        reference=reference,
        received_on=world.today,
        amount=D(amount),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="statement p.1",
        created_by=None,
    )
    world.commit()
    assert created
    return receipt


def reconcile(world, account, amount, reference, start_ago, end_ago):
    """Record a receipt and allocate it to every open day in the period."""
    receipt = record(world, account, amount, reference)
    receipts.allocate_period(
        world.session, SYSTEM, receipt.id, world.day(start_ago), world.day(end_ago), created_by=None
    )
    world.commit()
    return receipt


def allocate(world, receipt, *pairs, key=""):
    """Allocate ``(bucket, amount)`` pairs from ``receipt`` in one request and commit."""
    rows = receipts.allocate(
        world.session,
        SYSTEM,
        receipt.id,
        [AllocationRequest(bucket.id, D(amount)) for bucket, amount in pairs],
        created_by=None,
        request_key=key,
    )
    world.commit()
    return rows


def refused(world, receipt, *pairs, error=Conflict, match=None):
    """The allocation request is refused as a whole and leaves nothing behind."""
    with pytest.raises(error, match=match):
        receipts.allocate(
            world.session,
            SYSTEM,
            receipt.id,
            [AllocationRequest(bucket.id, D(amount)) for bucket, amount in pairs],
            created_by=None,
        )
    world.session.rollback()


def on_file(world, owner, admin, **details):
    payouts.set_beneficiary(
        world.session,
        world.settings,
        SYSTEM,
        owner.id,
        {"account_holder": owner.display_name, "iban": IBAN, **details},
        admin.id,
    )
    world.commit()


def revise(world, provider, account, machine, days_ago, amount):
    """The provider now reports a different amount for a day that was already imported."""
    provider.dataset["earnings"][machine][world.day(days_ago).isoformat()] = {"gpu_earn": amount}
    return run_import(world, provider, account, days_ago, days_ago)


def bucket_of(world, machine="101", days_ago=1):
    """The bucket row as it is in the database now, whatever this session loaded before."""
    return world.session.execute(
        select(EarningBucket)
        .where(EarningBucket.external_machine_id == machine, EarningBucket.day == world.day(days_ago))
        .execution_options(populate_existing=True)
    ).scalar_one()


def entry_types(world):
    return list(world.session.execute(select(JournalEntry.entry_type)).scalars())


def balances(world, owner):
    return owner_balances(world.session, owner.id)


def manual_report(rows, start, end, covered=()):
    """A provider report built by hand: ``rows`` is a list of (machine id, day, amount)."""
    return EarningsReport(
        rows=[EarningsRow(machine, day, D(amount), "USD") for machine, day, amount in rows],
        period_start=start,
        period_end=end,
        basis="net_of_provider_fee",
        buckets_verified=True,
        raw_body=b"{}",
        fetched_at=datetime.now(UTC),
        is_synthetic=True,
        covered_machines=frozenset(covered),
    )


def race(*jobs):
    """Run every ``job(session)`` at once, each in its own thread with its own session.

    A job's session is committed when the job returns and rolled back when it raises, as a
    request handler would do. Returns one outcome per job, in order: the job's return value
    or the ``AppError`` that refused it. Any other exception fails the test.
    """
    barrier = threading.Barrier(len(jobs))
    outcomes = [None] * len(jobs)

    def run(index, job):
        session = session_factory()()
        try:
            barrier.wait(timeout=15)
            result = job(session)
            session.commit()
            outcomes[index] = result
        except Exception as exc:
            session.rollback()
            outcomes[index] = exc
        finally:
            session.close()

    threads = [threading.Thread(target=run, args=(i, job)) for i, job in enumerate(jobs)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not any(thread.is_alive() for thread in threads), "a session is still blocked: deadlock?"
    for outcome in outcomes:
        if isinstance(outcome, Exception) and not isinstance(outcome, AppError):
            raise outcome
    return outcomes


def split(outcomes):
    """(results of the jobs that went through, errors of the jobs that were refused)."""
    return (
        [o for o in outcomes if not isinstance(o, AppError)],
        [o for o in outcomes if isinstance(o, AppError)],
    )


def assert_reconciliation_sound(world):
    """No receipt is allocated beyond its amount, no day is received beyond what was reported."""
    session = world.session
    allocated_by_receipt = dict(
        session.execute(
            select(ReceiptAllocation.receipt_id, func.sum(ReceiptAllocation.amount)).group_by(
                ReceiptAllocation.receipt_id
            )
        ).all()
    )
    for receipt_id, amount, recorded in session.execute(
        select(ProviderReceipt.id, ProviderReceipt.amount, ProviderReceipt.allocated_amount)
    ):
        allocated = allocated_by_receipt.get(receipt_id, ZERO)
        assert ZERO <= allocated <= amount, f"receipt {receipt_id}: {allocated} allocated of {amount}"
        assert recorded == allocated
    allocated_by_bucket = dict(
        session.execute(
            select(ReceiptAllocation.bucket_id, func.sum(ReceiptAllocation.amount)).group_by(
                ReceiptAllocation.bucket_id
            )
        ).all()
    )
    for bucket_id, reported, received in session.execute(
        select(EarningBucket.id, EarningBucket.reported_amount, EarningBucket.received_amount)
    ):
        assert received == allocated_by_bucket.get(bucket_id, ZERO)
        assert min(ZERO, reported) <= received <= max(ZERO, reported), (
            f"bucket {bucket_id}: received {received} of reported {reported}"
        )
    report = verify_ledger(session)
    assert report["ok"], report["problems"]


def ledger_state():
    """Everything the immutability rules protect, as plain tuples.

    Read on a connection of its own and released at once, so that the caller is not left
    holding table locks that a later TRUNCATE attempt would have to wait for.
    """
    queries = (
        select(JournalLine.id, JournalLine.entry_id, JournalLine.account_id, JournalLine.amount).order_by(
            JournalLine.id
        ),
        select(
            JournalEntry.id, JournalEntry.entry_type, JournalEntry.description, JournalEntry.occurred_on
        ).order_by(JournalEntry.id),
        select(LedgerBalance.account_id, LedgerBalance.balance).order_by(LedgerBalance.account_id),
        select(
            LedgerAccount.code,
            LedgerAccount.kind,
            LedgerAccount.owner_id,
            LedgerAccount.normal_side,
            LedgerAccount.allow_overdraft,
        ).order_by(LedgerAccount.code),
        select(AuditLog.id, AuditLog.action, AuditLog.hash).order_by(AuditLog.id),
    )
    with get_engine().connect() as conn:
        return [[tuple(row) for row in conn.execute(query)] for query in queries]


@pytest.fixture
def books(world):
    """A small set of books with every kind of balance in it.

    Alice (machine 101) and Bob (machine 202) each reported two days. Yesterday was received
    and reconciled for both; the day before is still only reported. Both were then settled:
    Alice's payout is confirmed paid, Bob's is submitted and still in transit.
    """
    owners, account, provider = build_fleet(
        world, {"Alice": ("101", {2: "40", 1: "100"}), "Bob": ("202", {2: "20", 1: "50"})}
    )
    run_import(world, provider, account, 2, 1)
    receipt = reconcile(world, account, "160", "BANK-1", 1, 1)  # 10 more than yesterday's earnings
    admin = world.user("admin")
    for owner in owners.values():
        on_file(world, owner, admin)
    batch, _ = prepare(world, admin, "books-batch-0001")
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id)
    paid = world.session.execute(
        select(PayoutItem).where(PayoutItem.owner_id == owners["Alice"].id)
    ).scalar_one()
    payouts.confirm_item(world.session, SYSTEM, paid.id, reference="BANK-OUT-1", user_id=admin.id)
    world.commit()
    report = verify_ledger(world.session)
    assert report["ok"], report["problems"]
    return SimpleNamespace(
        alice=owners["Alice"],
        bob=owners["Bob"],
        account=account,
        provider=provider,
        receipt=receipt,
        admin=admin,
        batch=batch,
    )


# --- 1. double allocation under concurrency --------------------------------


def test_concurrent_period_allocations_of_one_receipt_allocate_once(world):
    """Finding 1. Four sessions allocate the same receipt to the same day at the same instant.

    The receipt holds enough cash to pay the day twice over, so nothing but the re-read under
    the row lock stops the second allocation: the suspense account would not be overdrawn.
    """
    owner, account, provider = setup_fleet(world, {"101": {1: "100"}})
    run_import(world, provider, account, 1, 1)
    receipt_id, day = record(world, account, "250").id, world.day(1)

    def job(session):
        rows = receipts.allocate_period(session, SYSTEM, receipt_id, day, day, created_by=None)
        return [row.amount for row in rows]

    done, errors = split(race(job, job, job, job))
    assert done == [[D("100")]]
    assert len(errors) == 3 and all(isinstance(e, Conflict) for e in errors), errors

    assert bucket_of(world).received_amount == D("100")
    assert balances(world, owner).available == D("90")
    suspense = get_account(world.session, "receipts_unallocated", provider_account_id=account.id)
    assert balance_of(world.session, suspense) == D("150")
    assert entry_types(world).count("receipt_allocation") == 1
    assert_reconciliation_sound(world)


def test_two_receipts_racing_for_the_same_days_pay_them_once(world):
    """Finding 1. Two receipts, each large enough, are allocated to the same two days at once.

    Each session holds the lock on its own receipt, so only the buckets, re-read under their
    row locks, can tell the second session that the days are already paid.
    """
    owner, account, provider = setup_fleet(world, {"101": {2: "60", 1: "40"}})
    run_import(world, provider, account, 2, 1)
    first, second = record(world, account, "100", "BANK-1"), record(world, account, "100", "BANK-2")
    start, end = world.day(2), world.day(1)

    def period(receipt_id):
        def job(session):
            rows = receipts.allocate_period(session, SYSTEM, receipt_id, start, end, created_by=None)
            return sum((row.amount for row in rows), ZERO)

        return job

    done, errors = split(race(period(first.id), period(second.id)))
    assert done == [D("100")]
    assert len(errors) == 1 and isinstance(errors[0], Conflict), errors

    assert [bucket_of(world, "101", n).received_amount for n in (2, 1)] == [D("60"), D("40")]
    allocated = sorted(world.session.execute(select(ProviderReceipt.allocated_amount)).scalars())
    assert allocated == [ZERO, D("100")]
    assert balances(world, owner).available == D("90")  # not 180
    assert_reconciliation_sound(world)


def test_concurrent_explicit_allocations_respect_the_reported_amount(world):
    """Finding 1. ``allocate`` called directly: 60 four times over does not fit a day of 100."""
    owner, account, provider = setup_fleet(world, {"101": {1: "100"}})
    run_import(world, provider, account, 1, 1)
    first, second = record(world, account, "250", "BANK-1"), record(world, account, "250", "BANK-2")
    bucket_id = bucket_of(world).id

    def allocation(receipt_id):
        def job(session):
            (row,) = receipts.allocate(
                session, SYSTEM, receipt_id, [AllocationRequest(bucket_id, D("60"))], created_by=None
            )
            return row.amount

        return job

    outcomes = race(allocation(first.id), allocation(first.id), allocation(second.id), allocation(second.id))
    done, errors = split(outcomes)
    assert done == [D("60")]
    assert len(errors) == 3 and all(isinstance(e, Conflict) for e in errors), errors

    assert bucket_of(world).received_amount == D("60")
    assert balances(world, owner).available == D("54")
    assert_reconciliation_sound(world)


def test_concurrent_allocations_cannot_spend_one_receipt_twice(world):
    """Finding 1. One receipt of 100, two days of 80: both cannot be paid from it."""
    owner, account, provider = setup_fleet(world, {"101": {2: "80", 1: "80"}})
    run_import(world, provider, account, 2, 1)
    receipt_id = record(world, account, "100").id
    targets = [bucket_of(world, "101", 2).id, bucket_of(world, "101", 1).id]

    def allocation(bucket_id):
        def job(session):
            (row,) = receipts.allocate(
                session, SYSTEM, receipt_id, [AllocationRequest(bucket_id, D("80"))], created_by=None
            )
            return row.amount

        return job

    done, errors = split(race(*[allocation(bucket_id) for bucket_id in targets]))
    assert done == [D("80")]
    # Refused by the check made under the lock, not merely by the overdraft trigger behind it.
    assert len(errors) == 1 and isinstance(errors[0], Conflict), errors

    total = world.session.execute(select(func.sum(ReceiptAllocation.amount))).scalar_one()
    assert total == D("80")
    assert balances(world, owner).available == D("72")
    assert_reconciliation_sound(world)


def test_allocation_decides_on_rows_read_under_the_lock(world):
    """Finding 1, without timing: the original defect was a stale ORM instance.

    Three sessions load the receipts and buckets first. Another session then allocates and
    commits. When the three go on to allocate, the copies they loaded earlier are out of date:
    ``lock_row`` / ``populate_existing`` must replace them with what is in the database.
    """
    owner, account, provider = setup_fleet(world, {"101": {2: "100", 1: "100"}})
    run_import(world, provider, account, 2, 1)
    first, second = record(world, account, "100", "BANK-1"), record(world, account, "100", "BANK-2")
    paid_day, other_day = bucket_of(world, "101", 1), bucket_of(world, "101", 2)

    def session_with_everything_loaded():
        session = session_factory()()
        loaded_receipts = session.execute(select(ProviderReceipt)).scalars().all()
        loaded_buckets = session.execute(select(EarningBucket)).scalars().all()
        assert {r.allocated_amount for r in loaded_receipts} == {ZERO}
        assert {b.received_amount for b in loaded_buckets} == {ZERO}
        # A session only holds weak references to what it loaded: the instances are returned
        # and kept, as the local variables of a request handler would keep them.
        return session, [*loaded_receipts, *loaded_buckets]

    stale = [session_with_everything_loaded() for _ in range(3)]
    sessions = [session for session, _ in stale]
    try:
        allocate(world, first, (paid_day, "100"))  # commits

        # The day is already received in full: a second receipt cannot pay it again.
        with pytest.raises(Conflict, match="outside reported"):
            receipts.allocate(
                sessions[0], SYSTEM, second.id, [AllocationRequest(paid_day.id, D("100"))], created_by=None
            )
        sessions[0].rollback()  # releases its row locks before the next session needs them
        # The receipt is already allocated in full: it cannot pay another day.
        with pytest.raises(Conflict, match="of the receipt is unallocated"):
            receipts.allocate(
                sessions[1], SYSTEM, first.id, [AllocationRequest(other_day.id, D("100"))], created_by=None
            )
        sessions[1].rollback()
        # The period has no open day left for the second receipt.
        with pytest.raises(Conflict, match="no open attributed earnings"):
            receipts.allocate_period(
                sessions[2], SYSTEM, second.id, world.day(1), world.day(1), created_by=None
            )
    finally:
        for session in sessions:
            session.rollback()
            session.close()

    assert balances(world, owner).available == D("90")
    assert_reconciliation_sound(world)


# --- 2. over-received funds are not payable --------------------------------


def test_over_received_owner_is_held_until_corrected_and_resolved(world):
    """Finding 2. A day is revised down after its cash was allocated: the owner is not paid.

    ``payout_blockers`` reports it, ``prepare_batch`` leaves the owner out, ``approve_batch``
    refuses a draft made earlier. De-allocating back into range closes ``over_received``;
    the owner is payable again once the remaining exception is resolved too.
    """
    owners, account, provider = build_fleet(world, {"Alice": ("101", {1: "100"}), "Bob": ("202", {1: "50"})})
    alice, bob = owners["Alice"], owners["Bob"]
    run_import(world, provider, account, 1, 1)
    receipt = reconcile(world, account, "150", "BANK-1", 1, 1)
    admin = world.user("admin")
    on_file(world, alice, admin)
    on_file(world, bob, admin)
    assert payouts.payout_blockers(world.session, alice.id) == []
    earlier_draft, _ = prepare(world, admin, "draft-before-revision")
    assert {item.owner_id for item in earlier_draft.items} == {alice.id, bob.id}

    # The provider takes 30 back on a day already received in full.
    revise(world, provider, account, "101", 1, "70.00")
    assert sorted(e.kind for e in open_exceptions(world)) == ["over_received", "unexplained_adjustment"]
    assert len(payouts.payout_blockers(world.session, alice.id)) == 2
    assert payouts.payout_blockers(world.session, bob.id) == []
    assert balances(world, alice).available == D("90")  # still in the ledger, but held

    # A new batch leaves Alice out and still pays Bob.
    batch, _ = prepare(world, admin, "draft-after-revision")
    assert [(item.owner_id, item.amount) for item in batch.items] == [(bob.id, D("45.00"))]

    def prepare_for_alice(key):
        batch, _ = payouts.prepare_batch(
            world.session,
            world.settings,
            SYSTEM,
            idempotency_key=key,
            created_by=admin.id,
            owner_ids=[alice.id],
        )
        world.commit()
        return batch

    with pytest.raises(Conflict, match="Alice"):
        prepare_for_alice("alice-only-0001")
    world.session.rollback()
    # The draft made before the revision can no longer be approved, for anyone in it.
    with pytest.raises(Conflict, match="unresolved provider adjustment"):
        payouts.approve_batch(world.session, world.settings, SYSTEM, earlier_draft.id, approver_id=admin.id)
    world.session.rollback()
    assert (balances(world, alice).reserved, balances(world, bob).reserved) == (ZERO, ZERO)

    # Correction: 30 goes back from the day to the receipt's unallocated remainder.
    allocate(world, receipt, (bucket_of(world, "101"), "-30"))
    assert open_exceptions(world, "over_received") == []
    assert balances(world, alice).available == D("63")  # 70 less 10%
    # The provider's change itself is still unexplained, so she is still held.
    assert len(payouts.payout_blockers(world.session, alice.id)) == 1
    with pytest.raises(Conflict, match="Alice"):
        prepare_for_alice("alice-only-0002")
    world.session.rollback()

    (adjustment,) = open_exceptions(world, "unexplained_adjustment")
    exceptions_queue.resolve(world.session, SYSTEM, adjustment.id, "provider credit note 77", admin.id)
    world.commit()
    assert payouts.payout_blockers(world.session, alice.id) == []
    final = prepare_for_alice("alice-only-0003")
    assert [(item.owner_id, item.amount) for item in final.items] == [(alice.id, D("63.00"))]
    payouts.approve_batch(world.session, world.settings, SYSTEM, final.id, approver_id=admin.id)
    world.commit()
    b = balances(world, alice)
    assert (b.available, b.reserved) == (ZERO, D("63"))
    assert_reconciliation_sound(world)


def test_closing_the_over_received_exception_by_hand_does_not_make_the_funds_payable(world):
    """Finding 2. Still over-received, exception closed with a note: the owner stays unpaid.

    The provider took 30 back; nothing was de-allocated. An admin closes the open exceptions
    in the exception queue. Whether the application refuses that for ``over_received`` or
    keeps holding the owner some other way, the 90 that includes the provider's 30 must not
    be drafted or reserved, and the books must not be left in a state ``verify_ledger``
    itself reports as broken.
    """
    owners, account, provider = build_fleet(world, {"Alice": ("101", {1: "100"})})
    alice = owners["Alice"]
    run_import(world, provider, account, 1, 1)
    reconcile(world, account, "100", "BANK-1", 1, 1)
    admin = world.user("admin")
    on_file(world, alice, admin)
    revise(world, provider, account, "101", 1, "70.00")
    bucket = bucket_of(world)
    assert (bucket.reported_amount, bucket.received_amount) == (D("70"), D("100"))

    for exception in open_exceptions(world):
        try:
            exceptions_queue.resolve(world.session, SYSTEM, exception.id, "looked at it", admin.id)
            world.commit()
        except Conflict:
            world.session.rollback()

    assert payouts.payout_blockers(world.session, alice.id), "over-received and no longer held"
    with pytest.raises(Conflict):
        prepare(world, admin)
    world.session.rollback()
    assert balances(world, alice).reserved == ZERO
    report = verify_ledger(world.session)
    assert report["ok"], report["problems"]


def test_unexplained_adjustment_alone_holds_the_payout(world):
    """Finding 2. An open ``unexplained_adjustment`` blocks payout even with nothing over-received."""
    owners, account, provider = build_fleet(world, {"Alice": ("101", {1: "100"})})
    alice = owners["Alice"]
    run_import(world, provider, account, 1, 1)
    reconcile(world, account, "100", "BANK-1", 1, 1)
    admin = world.user("admin")
    on_file(world, alice, admin)
    earlier_draft, _ = prepare(world, admin, "draft-before-revision")

    revise(world, provider, account, "101", 1, "120.00")  # upwards: nothing is over-received
    assert [e.kind for e in open_exceptions(world)] == ["unexplained_adjustment"]
    (blocker,) = payouts.payout_blockers(world.session, alice.id)
    assert "revision 2" in blocker

    with pytest.raises(Conflict, match="unresolved provider adjustments for Alice"):
        prepare(world, admin, "draft-after-revision")
    world.session.rollback()
    with pytest.raises(Conflict, match="unresolved provider adjustment"):
        payouts.approve_batch(world.session, world.settings, SYSTEM, earlier_draft.id, approver_id=admin.id)
    world.session.rollback()
    b = balances(world, alice)
    assert (b.available, b.reserved) == (D("90"), ZERO)

    (adjustment,) = open_exceptions(world, "unexplained_adjustment")
    exceptions_queue.resolve(world.session, SYSTEM, adjustment.id, "confirmed with the provider", admin.id)
    world.commit()
    assert payouts.payout_blockers(world.session, alice.id) == []
    payouts.approve_batch(world.session, world.settings, SYSTEM, earlier_draft.id, approver_id=admin.id)
    world.commit()
    assert balances(world, alice).reserved == D("90")
    assert_reconciliation_sound(world)


# --- 3. cancel after export ------------------------------------------------


def test_exported_batch_cannot_be_cancelled(client, world):
    """Finding 3. Once exported, the bank file may be at the bank: the reserve is not released."""
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    payouts.export_batch(world.session, world.settings, SYSTEM, batch.id)
    world.commit()
    assert batch.export_count == 1

    with pytest.raises(Conflict, match="has been exported"):
        payouts.cancel_batch(world.session, SYSTEM, batch.id, user_id=admin.id)
    world.session.rollback()
    over_http = client.post(f"/api/v1/payout-batches/{batch.id}/cancel", headers=world.auth(admin))
    assert over_http.status_code == 409 and "exported" in over_http.json()["error"]["message"]

    world.session.refresh(batch)
    item = world.session.execute(select(PayoutItem).execution_options(populate_existing=True)).scalar_one()
    assert (batch.status, item.status) == ("approved", "reserved")
    b = balances(world, owner)
    assert (b.available, b.reserved) == (ZERO, D("90"))
    assert "payout_release" not in entry_types(world)
    # No second batch can be prepared from the same money.
    with pytest.raises(InsufficientFunds):
        prepare(world, admin, "second-batch-0001")
    world.session.rollback()

    # The way forward is submission and bank evidence.
    payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id)
    world.commit()
    assert balances(world, owner).in_transit == D("90")
    assert_reconciliation_sound(world)


def test_export_and_cancel_at_the_same_time_never_both_succeed(world):
    """Finding 3 under concurrency: there is never a payment file for a batch whose reserve was released."""
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    world.commit()
    batch_id, admin_id, settings = batch.id, admin.id, world.settings

    def export(session):
        payouts.export_batch(session, settings, SYSTEM, batch_id)
        return "exported"

    def cancel(session):
        payouts.cancel_batch(session, SYSTEM, batch_id, user_id=admin_id)
        return "cancelled"

    done, errors = split(race(export, cancel))
    assert len(done) == 1 and len(errors) == 1 and isinstance(errors[0], Conflict), (done, errors)
    world.session.refresh(batch)
    b = balances(world, owner)
    if done == ["exported"]:
        assert (batch.status, batch.export_count) == ("approved", 1)
        assert (b.available, b.reserved) == (ZERO, D("90"))
    else:
        assert (batch.status, batch.export_count) == ("cancelled", 0)
        assert (b.available, b.reserved) == (D("90"), ZERO)
    assert_reconciliation_sound(world)


# --- 4. allocation replay --------------------------------------------------


def test_allocation_request_key_makes_a_replay_a_no_op(world):
    """Finding 4. The same request key posts once, for ``allocate`` and ``allocate_period``."""
    owner, account, provider = setup_fleet(world, {"101": {2: "30", 1: "30"}})
    run_import(world, provider, account, 2, 1)
    receipt = record(world, account, "100")
    newer = bucket_of(world, "101", 1)

    first = allocate(world, receipt, (newer, "10"), key="alloc-key-1")
    entries = count(world, JournalEntry)
    for _ in range(3):
        again = allocate(world, receipt, (newer, "10"), key="alloc-key-1")
        assert [a.id for a in again] == [a.id for a in first]
    assert count(world, JournalEntry) == entries and count(world, ReceiptAllocation) == 1
    assert bucket_of(world, "101", 1).received_amount == D("10")
    assert balances(world, owner).available == D("9")

    # The key names one request. Using it for a different one is refused, not merged.
    with pytest.raises(Conflict, match="already used for a different allocation"):
        receipts.allocate(
            world.session,
            SYSTEM,
            receipt.id,
            [AllocationRequest(newer.id, D("5"))],
            created_by=None,
            request_key="alloc-key-1",
        )
    world.session.rollback()
    # Without a key the same call is a new allocation: this is what the key prevents.
    allocate(world, receipt, (newer, "10"))
    assert bucket_of(world, "101", 1).received_amount == D("20")

    def period(key):
        rows = receipts.allocate_period(
            world.session,
            SYSTEM,
            receipt.id,
            world.day(2),
            world.day(1),
            created_by=None,
            request_key=key,
        )
        world.commit()
        return sorted((row.id, row.amount) for row in rows)

    posted = period("period-key-1")
    assert sorted(amount for _, amount in posted) == [D("10"), D("30")]
    entries = count(world, JournalEntry)
    assert period("period-key-1") == posted
    assert count(world, JournalEntry) == entries and count(world, ReceiptAllocation) == 4
    world.session.refresh(receipt)
    assert receipt.allocated_amount == D("60")
    assert bucket_of(world, "101", 2).received_amount == D("30")
    assert balances(world, owner).available == D("54")
    assert_reconciliation_sound(world)


def test_concurrent_replays_of_one_allocation_request_post_once(world):
    """Finding 4 under concurrency: one request key, four sessions, one allocation.

    Without the key all four would be valid allocations (20 each of a day of 100).
    """
    owner, account, provider = setup_fleet(world, {"101": {1: "100"}})
    run_import(world, provider, account, 1, 1)
    receipt_id = record(world, account, "100").id
    bucket_id = bucket_of(world).id

    def job(session):
        (row,) = receipts.allocate(
            session,
            SYSTEM,
            receipt_id,
            [AllocationRequest(bucket_id, D("20"))],
            created_by=None,
            request_key="double-click-1",
        )
        return row.id

    done, errors = split(race(job, job, job, job))
    assert errors == [] and len(done) == 4 and len(set(done)) == 1
    assert count(world, ReceiptAllocation) == 1
    assert bucket_of(world).received_amount == D("20")
    assert balances(world, owner).available == D("18")
    assert_reconciliation_sound(world)


def test_allocation_endpoints_require_and_honour_the_idempotency_key(client, world):
    """Finding 4 over HTTP: no ``Idempotency-Key`` header, no allocation; same key, one posting."""
    owner, account, provider = setup_fleet(world, {"101": {2: "30", 1: "30"}})
    run_import(world, provider, account, 2, 1)
    receipt = record(world, account, "100")
    newer = bucket_of(world, "101", 1)
    h = world.auth(world.user("admin"))

    url = f"/api/v1/receipts/{receipt.id}/allocate"
    body = {"allocations": [{"bucket_id": str(newer.id), "amount": "10"}]}
    assert client.post(url, headers=h, json=body).status_code == 422
    assert client.post(url, headers={**h, "Idempotency-Key": "short"}, json=body).status_code == 422
    assert count(world, ReceiptAllocation) == 0

    keyed = {**h, "Idempotency-Key": "alloc-http-0001"}
    first, second = client.post(url, headers=keyed, json=body), client.post(url, headers=keyed, json=body)
    assert (first.status_code, second.status_code) == (200, 200)
    assert first.json() == second.json()
    assert second.json()["receipt"]["allocated"] == "10.00000000"
    assert count(world, ReceiptAllocation) == 1
    other = {"allocations": [{"bucket_id": str(newer.id), "amount": "11"}]}
    assert client.post(url, headers=keyed, json=other).status_code == 409

    url = f"/api/v1/receipts/{receipt.id}/allocate-period"
    body = {"start": world.day(2).isoformat(), "end": world.day(1).isoformat()}
    assert client.post(url, headers=h, json=body).status_code == 422
    assert count(world, ReceiptAllocation) == 1
    keyed = {**h, "Idempotency-Key": "period-http-0001"}
    first, second = client.post(url, headers=keyed, json=body), client.post(url, headers=keyed, json=body)
    assert (first.status_code, second.status_code) == (200, 200)
    assert first.json() == second.json()
    assert sorted(a["amount"] for a in first.json()["allocations"]) == ["20.00000000", "30.00000000"]
    assert count(world, ReceiptAllocation) == 3
    assert entry_types(world).count("receipt_allocation") == 3
    assert balances(world, owner).available == D("54")
    assert_reconciliation_sound(world)


# --- 5. clawback / de-allocation -------------------------------------------


def test_negative_allocation_returns_money_to_the_receipt(world):
    """Finding 5. A negative allocation moves cash from the day back into suspense."""
    owner, account, provider = setup_fleet(world, {"101": {1: "100"}})
    run_import(world, provider, account, 1, 1)
    receipt = reconcile(world, account, "100", "BANK-1", 1, 1)
    suspense = get_account(world.session, "receipts_unallocated", provider_account_id=account.id)
    cash = get_account(world.session, "cash_clearing")
    assert balance_of(world.session, suspense) == ZERO
    assert open_exceptions(world, "receipt_remainder") == []

    (back,) = allocate(world, receipt, (bucket_of(world), "-40"))
    assert (back.amount, back.owner_released, back.fee_released) == (D("-40"), D("-36"), D("-4"))
    assert world.session.get(JournalEntry, back.journal_entry_id).entry_type == "receipt_deallocation"
    types = entry_types(world)
    assert types.count("receipt_allocation") == 1 and types.count("receipt_deallocation") == 1

    bucket = bucket_of(world)
    assert (bucket.received_amount, bucket.owner_released, bucket.fee_released) == (D("60"), D("54"), D("6"))
    world.session.refresh(receipt)
    assert receipt.allocated_amount == D("60")
    b = balances(world, owner)
    assert (b.accrued, b.available) == (D("36"), D("54"))
    assert balance_of(world.session, suspense) == D("40")
    assert balance_of(world.session, cash) == D("100")  # the cash itself did not move
    (remainder,) = open_exceptions(world, "receipt_remainder")
    assert remainder.details["unallocated"] == "40.00000000"
    assert_reconciliation_sound(world)


def test_deallocation_stays_within_the_bucket_and_the_receipt(world):
    """Finding 5. No bucket below zero; a receipt's net allocation stays within [0, amount]."""
    owner, account, provider = setup_fleet(world, {"101": {2: "100", 1: "100"}})
    run_import(world, provider, account, 2, 1)
    older, newer = bucket_of(world, "101", 2), bucket_of(world, "101", 1)
    first, second = record(world, account, "100", "BANK-1"), record(world, account, "100", "BANK-2")
    allocate(world, first, (older, "60"))
    before = ledger_state()

    refused(world, first, (older, "-60.00000001"), match="outside reported")  # bucket below zero
    refused(world, first, (newer, "-1"), match="outside reported")  # nothing was received there
    refused(world, second, (older, "-10"), match="net to")  # this receipt allocated nothing
    refused(world, first, (older, "-10"), (newer, "60"), match="net to")  # 60 + 50 > 100
    refused(world, first, (newer, "40.00000001"), match="net to")
    refused(world, first, (older, "0"), error=InvalidRequest)
    assert ledger_state() == before

    # One request may net a de-allocation against an allocation: 60 moves to the other day
    # and the 40 that was left is used as well.
    rows = allocate(world, first, (older, "-60"), (newer, "100"))
    assert sorted(row.amount for row in rows) == [D("-60"), D("100")]
    assert (bucket_of(world, "101", 2).received_amount, bucket_of(world, "101", 1).received_amount) == (
        ZERO,
        D("100"),
    )
    world.session.refresh(first)
    assert first.allocated_amount == D("100")
    b = balances(world, owner)
    assert (b.accrued, b.available) == (D("90"), D("90"))
    assert_reconciliation_sound(world)


def test_over_received_bucket_only_moves_back_towards_its_range(world):
    """Finding 5. Received 100 against 70 now reported: only a correction towards 70 is accepted."""
    owner, account, provider = setup_fleet(world, {"101": {1: "100"}})
    run_import(world, provider, account, 1, 1)
    receipt = reconcile(world, account, "100", "BANK-1", 1, 1)
    extra = record(world, account, "50", "BANK-2")
    revise(world, provider, account, "101", 1, "70.00")
    bucket = bucket_of(world)
    assert (bucket.reported_amount, bucket.received_amount) == (D("70"), D("100"))

    refused(world, extra, (bucket, "10"), match="only be corrected towards")  # further out
    refused(world, receipt, (bucket, "-110"), match="only be corrected towards")  # past zero
    assert len(open_exceptions(world, "over_received")) == 1

    # Part of the way back: accepted, and still flagged.
    allocate(world, receipt, (bucket, "-20"))
    assert bucket_of(world).received_amount == D("80")
    assert len(open_exceptions(world, "over_received")) == 1
    assert balances(world, owner).available == D("72")

    # All the way back: the exception closes by itself.
    allocate(world, receipt, (bucket, "-10"))
    bucket = bucket_of(world)
    assert bucket.received_amount == bucket.reported_amount == D("70")
    assert (bucket.owner_released, bucket.fee_released) == (bucket.owner_accrued, bucket.fee_accrued)
    assert (bucket.owner_released, bucket.fee_released) == (D("63"), D("7"))
    assert open_exceptions(world, "over_received") == []
    b = balances(world, owner)
    assert (b.accrued, b.available) == (ZERO, D("63"))
    assert entry_types(world).count("receipt_deallocation") == 2
    assert_reconciliation_sound(world)


def test_clawback_of_money_already_paid_out_is_refused(world):
    """Finding 5. De-allocation cannot take back what the owner no longer has available."""
    owner, account, admin = funded(world)  # 100 reported, received, 90 available
    provider = registry.get_provider(world.settings)
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id)
    item = world.session.execute(select(PayoutItem)).scalar_one()
    payouts.confirm_item(world.session, SYSTEM, item.id, reference="BANK-OUT-1", user_id=admin.id)
    world.commit()

    revise(world, provider, account, "101", 1, "70.00")
    receipt = world.session.execute(select(ProviderReceipt)).scalar_one()
    before = ledger_state()
    refused(world, receipt, (bucket_of(world), "-30"), error=InsufficientFunds)
    assert ledger_state() == before
    assert bucket_of(world).received_amount == D("100")
    assert len(open_exceptions(world, "over_received")) == 1  # stays with a person
    assert payouts.payout_blockers(world.session, owner.id)
    report = verify_ledger(world.session)
    assert report["ok"], report["problems"]


# --- 6. database-level immutability ----------------------------------------

REFUSED_BY_TRIGGER = [
    # (e) the journal and the audit trail are append-only
    ("UPDATE journal_lines SET amount = amount * 2", "append-only"),
    ("DELETE FROM journal_lines", "append-only"),
    ("UPDATE journal_entries SET occurred_on = occurred_on - 30", "append-only"),
    ("DELETE FROM journal_entries", "append-only"),
    ("UPDATE audit_log SET details = '{}'::jsonb", "append-only"),
    ("DELETE FROM audit_log", "append-only"),
    # (b) so are the account definitions
    ("UPDATE ledger_accounts SET kind = 'owner_available' WHERE kind = 'owner_accrued'", "append-only"),
    ("UPDATE ledger_accounts SET owner_id = NULL WHERE owner_id IS NOT NULL", "append-only"),
    ("UPDATE ledger_accounts SET allow_overdraft = true", "append-only"),
    ("UPDATE ledger_accounts SET normal_side = 'debit'", "append-only"),
    ("DELETE FROM ledger_accounts", "append-only"),
    # (c) TRUNCATE fires no row trigger; a statement trigger refuses it
    ("TRUNCATE ledger_balances", "append-only"),
    ("TRUNCATE journal_entries CASCADE", "append-only"),
    ("TRUNCATE journal_lines", "append-only"),
    ("TRUNCATE ledger_accounts CASCADE", "append-only"),
    ("TRUNCATE audit_log", "append-only"),
    # (d) the balance cache is written by the journal trigger only
    ("UPDATE ledger_balances SET balance = 0", "journal trigger only"),
    ("UPDATE ledger_balances SET balance = balance - 1000000", "journal trigger only"),
    ("DELETE FROM ledger_balances", "journal trigger only"),
    (
        "INSERT INTO ledger_balances (account_id, balance, updated_at) "
        "SELECT id, -1000000, now() FROM ledger_accounts LIMIT 1",
        "journal trigger only",
    ),
]


@pytest.mark.parametrize(("statement", "message"), REFUSED_BY_TRIGGER, ids=[s for s, _ in REFUSED_BY_TRIGGER])
def test_ledger_tables_refuse_raw_sql_changes(world, books, statement, message):
    """Finding 6 (b)-(e). Raw SQL on the test's own connection, as the table owner."""
    before = ledger_state()
    assert all(before), "every protected table must have rows, or a row trigger proves nothing"
    world.session.rollback()  # hold no lock that a TRUNCATE attempt would wait for
    with get_engine().connect() as conn:
        with pytest.raises(DBAPIError, match=message):
            conn.execute(text(statement))
        conn.rollback()
    assert ledger_state() == before


def test_committed_entry_cannot_grow(world, books):
    """Finding 6 (a). Lines can only be added by the transaction that created the entry.

    The two extra lines cancel out, so the entry would still "balance" while 50 moved from
    Bob's reported-only account into his payable one.
    """
    entry_id = world.session.execute(
        select(JournalEntry.id).where(JournalEntry.entry_type == "earning_accrual").limit(1)
    ).scalar_one()
    accrued = get_account(world.session, "owner_accrued", owner_id=books.bob.id)
    available = get_account(world.session, "owner_available", owner_id=books.bob.id)
    before = ledger_state()
    with get_engine().connect() as conn:
        with pytest.raises(DBAPIError, match="is closed"):
            conn.execute(
                text(
                    "INSERT INTO journal_lines (entry_id, account_id, amount, currency) "
                    "VALUES (:entry, :accrued, 50, 'USD'), (:entry, :available, -50, 'USD')"
                ),
                {"entry": entry_id, "accrued": accrued.id, "available": available.id},
            )
        conn.rollback()
    assert ledger_state() == before
    assert balances(world, books.bob).available == ZERO


INSERT_ENTRY = text(
    "INSERT INTO journal_entries "
    "(id, entry_type, idempotency_key, description, occurred_on, posted_at, ref_type, ref_id) "
    "VALUES (:id, 'manual', :key, 'raw sql', current_date, now(), '', '')"
)
INSERT_LINE = text(
    "INSERT INTO journal_lines (entry_id, account_id, amount, currency) "
    "VALUES (:entry, :account, :amount, 'USD')"
)


@pytest.mark.parametrize(
    ("amounts", "message"),
    [
        (("5", "-4"), "does not balance"),
        (("5", "5"), "does not balance"),
        (("5",), "fewer than two lines"),
        ((), "has no lines"),
    ],
    ids=["unbalanced", "same-sign", "single-line", "no-lines"],
)
def test_malformed_entry_is_refused_at_commit(world, books, amounts, message):
    """Finding 6 (f). An entry that does not balance, or has no counterpart, never commits."""
    accounts = [get_account(world.session, "cash_clearing"), get_account(world.session, "fee_earned")]
    world.commit()
    before = ledger_state()
    entry_id = uuid.uuid4()
    with get_engine().connect() as conn:
        conn.execute(INSERT_ENTRY, {"id": entry_id, "key": f"raw:{entry_id}"})
        for account, amount in zip(accounts, amounts, strict=False):
            conn.execute(INSERT_LINE, {"entry": entry_id, "account": account.id, "amount": D(amount)})
        with pytest.raises(DBAPIError, match=message):
            conn.commit()
        conn.rollback()
    assert ledger_state() == before


@pytest.mark.parametrize(
    "kind", ["owner_available", "owner_reserved", "owner_in_transit", "receipts_unallocated", "cash_clearing"]
)
def test_protected_account_cannot_be_overdrawn_with_raw_sql(world, books, kind):
    """Finding 6 (g). One hundred-millionth beyond zero is refused, on the spot, by the database."""
    scope = {}
    if kind.startswith("owner_"):
        scope = {"owner_id": books.bob.id}
    elif kind == "receipts_unallocated":
        scope = {"provider_account_id": books.account.id}
    account = get_account(world.session, kind, **scope)
    counterpart = get_account(world.session, "fee_earned")  # may go either way
    world.commit()
    raw = (
        world.session.execute(
            select(LedgerBalance.balance).where(LedgerBalance.account_id == account.id)
        ).scalar_one_or_none()
        or ZERO
    )
    step = D("0.00000001")
    # Debit accounts hold raw >= 0, credit accounts raw <= 0: push just past zero.
    to_zero = -raw
    overdraw = to_zero - step if account.normal_side == "debit" else to_zero + step
    before = ledger_state()

    with get_engine().connect() as conn:
        if to_zero != ZERO:
            # Emptying the account exactly is fine as far as this rule goes.
            entry_id = uuid.uuid4()
            conn.execute(INSERT_ENTRY, {"id": entry_id, "key": f"raw:{entry_id}"})
            conn.execute(INSERT_LINE, {"entry": entry_id, "account": account.id, "amount": to_zero})
            conn.execute(INSERT_LINE, {"entry": entry_id, "account": counterpart.id, "amount": -to_zero})
            conn.rollback()
        entry_id = uuid.uuid4()
        conn.execute(INSERT_ENTRY, {"id": entry_id, "key": f"raw:{entry_id}"})
        with pytest.raises(DBAPIError, match="ledger overdraft"):
            conn.execute(INSERT_LINE, {"entry": entry_id, "account": account.id, "amount": overdraw})
        conn.rollback()
    assert ledger_state() == before


# --- 7. runtime database role ----------------------------------------------


@pytest.fixture
def runtime_role(world, monkeypatch):
    """``setup-runtime-role`` run twice, for a role that belongs to this test database only.

    Roles are cluster-wide. The command's default role is ``happymining_app`` (asserted in
    ``test_runtime_role_command_arguments``); here the role is named after the test database,
    so that test runs sharing one PostgreSQL server never alter or drop each other's role.
    It is dropped afterwards, and a role left behind by a crashed run is simply altered.
    """
    url = make_url(world.settings.database_url)
    role = f"hm_rt_{url.database}".lower()[:63]
    first_password, password = "first-" + uuid.uuid4().hex, "second-" + uuid.uuid4().hex
    monkeypatch.setenv(cli.RUNTIME_ROLE_ENV, first_password)
    assert cli.main(["setup-runtime-role", "--role", role]) == 0  # creates (or adopts) the role
    monkeypatch.setenv(cli.RUNTIME_ROLE_ENV, password)
    assert cli.main(["setup-runtime-role", "--role", role]) == 0  # running it again is safe

    role_url = url.set(username=role, password=password)
    engine = create_engine(role_url)
    try:
        yield SimpleNamespace(
            name=role,
            engine=engine,
            session=sessionmaker(bind=engine, expire_on_commit=False),
            stale_url=url.set(username=role, password=first_password),
        )
    finally:
        engine.dispose()
        owner_engine = create_engine(url, isolation_level="AUTOCOMMIT")
        with owner_engine.connect() as conn:
            conn.execute(text(f"DROP OWNED BY {role}"))
            conn.execute(text(f"DROP ROLE {role}"))
        owner_engine.dispose()


def test_runtime_role_command_arguments(monkeypatch):
    """Finding 7. Default role name, and the inputs the command refuses before touching anything."""
    monkeypatch.setenv(cli.RUNTIME_ROLE_ENV, "short")
    with pytest.raises(SystemExit, match="at least 12 characters"):
        cli.main(["setup-runtime-role"])
    monkeypatch.delenv(cli.RUNTIME_ROLE_ENV)
    with pytest.raises(SystemExit, match=cli.RUNTIME_ROLE_ENV):
        cli.main(["setup-runtime-role"])
    monkeypatch.setenv(cli.RUNTIME_ROLE_ENV, "long-enough-password")
    with pytest.raises(SystemExit, match="role name"):
        cli.main(["setup-runtime-role", "--role", "app; DROP ROLE postgres"])

    seen = []
    monkeypatch.setattr(cli, "cmd_setup_runtime_role", lambda args: seen.append(args.role) or 0)
    assert cli.main(["setup-runtime-role"]) == 0
    assert seen == ["happymining_app"]


def test_runtime_role_is_unprivileged(world, runtime_role):
    """Finding 7. Not a superuser, owns nothing, and the second run replaced the password."""
    with runtime_role.engine.connect() as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == runtime_role.name
        flags = conn.execute(
            text(
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolreplication, rolcanlogin "
                "FROM pg_roles WHERE rolname = current_user"
            )
        ).one()
        assert tuple(flags) == (False, False, False, False, False, True)
        me = "(SELECT oid FROM pg_roles WHERE rolname = current_user)"
        owned = conn.execute(text(f"SELECT count(*) FROM pg_class WHERE relowner = {me}")).scalar_one()
        assert owned == 0
        table_owners = set(
            conn.execute(text("SELECT tableowner FROM pg_tables WHERE schemaname = 'public'")).scalars()
        )
        assert table_owners and runtime_role.name not in table_owners
        memberships = conn.execute(
            text(f"SELECT count(*) FROM pg_auth_members WHERE member = {me}")
        ).scalar_one()
        assert memberships == 0
    stale = create_engine(runtime_role.stale_url)
    with pytest.raises(OperationalError):
        stale.connect()
    stale.dispose()


def test_runtime_role_can_do_the_normal_work(world, runtime_role):
    """Finding 7. Import, receipt, allocation and a full settlement, connected as the runtime role."""
    owners, account, provider = build_fleet(world, {"Alice": ("101", {1: "100"})})
    alice = owners["Alice"]
    admin = world.user("admin")
    with runtime_role.session() as db:
        assert db.execute(text("SELECT current_user")).scalar_one() == runtime_role.name
        own_account = db.get(ProviderAccount, account.id)
        report = provider.fetch_earnings(["101"], world.day(1), world.day(1))
        imported = earnings.import_earnings(db, SYSTEM, own_account, report)
        db.commit()
        assert imported.status == "posted" and imported.stats["new"] == 1

        receipt, created = receipts.record_receipt(
            db,
            SYSTEM,
            own_account,
            reference="BANK-1",
            received_on=world.today,
            amount=D("100"),
            currency="USD",
            evidence_source="bank_statement",
            evidence_note="statement p.1",
            created_by=admin.id,
        )
        receipts.allocate_period(db, SYSTEM, receipt.id, world.day(1), world.day(1), created_by=admin.id)
        db.commit()
        assert created and owner_balances(db, alice.id).available == D("90")

        payouts.set_beneficiary(
            db, world.settings, SYSTEM, alice.id, {"account_holder": "Alice", "iban": IBAN}, admin.id
        )
        batch, _ = payouts.prepare_batch(
            db, world.settings, SYSTEM, idempotency_key="runtime-role-batch", created_by=admin.id
        )
        payouts.approve_batch(db, world.settings, SYSTEM, batch.id, approver_id=admin.id)
        payouts.export_batch(db, world.settings, SYSTEM, batch.id)
        payouts.submit_batch(db, world.settings, SYSTEM, batch.id, user_id=admin.id)
        item = db.execute(select(PayoutItem)).scalar_one()
        payouts.confirm_item(db, SYSTEM, item.id, reference="BANK-OUT-1", user_id=admin.id)
        db.commit()
        b = owner_balances(db, alice.id)
        assert (b.accrued, b.available, b.reserved, b.in_transit) == (ZERO, ZERO, ZERO, ZERO)
        assert balance_of(db, get_account(db, "cash_clearing")) == D("10")
        ledger = verify_ledger(db)
        assert ledger["ok"], ledger["problems"]
        assert verify_chain(db)["ok"]
    assert_reconciliation_sound(world)


RUNTIME_ROLE_DENIED = [
    "UPDATE journal_lines SET amount = amount * 2",
    "DELETE FROM journal_lines",
    "UPDATE journal_entries SET description = 'x'",
    "DELETE FROM journal_entries",
    "UPDATE audit_log SET action = 'x'",
    "DELETE FROM audit_log",
    "UPDATE ledger_accounts SET allow_overdraft = true",
    "DELETE FROM ledger_accounts",
    "UPDATE ledger_balances SET balance = 0",
    "DELETE FROM ledger_balances",
    "INSERT INTO ledger_balances (account_id, balance, updated_at) SELECT id, -5, now() FROM ledger_accounts",
    "TRUNCATE journal_lines",
    "TRUNCATE journal_entries CASCADE",
    "TRUNCATE audit_log",
    "TRUNCATE ledger_accounts CASCADE",
    "TRUNCATE ledger_balances",
    "DROP TABLE journal_lines",
    "DROP TABLE journal_entries CASCADE",
    "DROP TABLE audit_log",
    "DROP TABLE ledger_accounts CASCADE",
    "DROP TABLE ledger_balances",
    "ALTER TABLE journal_lines DISABLE TRIGGER journal_lines_append_only",
    "ALTER TABLE journal_lines DISABLE TRIGGER ALL",
    "ALTER TABLE journal_entries DISABLE TRIGGER USER",
    "ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only",
    "ALTER TABLE ledger_balances DISABLE TRIGGER ledger_balances_guard",
    "DROP TRIGGER journal_lines_append_only ON journal_lines",
    "DROP FUNCTION hm_forbid_change() CASCADE",
    "ALTER TABLE journal_lines OWNER TO CURRENT_USER",
    "CREATE TRIGGER sneaky BEFORE INSERT ON journal_lines "
    "FOR EACH ROW EXECUTE FUNCTION hm_stamp_entry_txid()",
    "SET session_replication_role = replica",
    "SET LOCAL session_replication_role = replica",
    "ALTER ROLE CURRENT_USER SUPERUSER",
    "UPDATE alembic_version SET version_num = 'x'",
]


def test_runtime_role_cannot_rewrite_or_disarm_the_ledger(world, books, runtime_role):
    """Finding 7. Every way of changing history, or of switching the rules off, is denied."""
    before = ledger_state()
    owner_role = make_url(world.settings.database_url).username
    become_owner = [f'SET ROLE "{owner_role}"', f'SET SESSION AUTHORIZATION "{owner_role}"']
    world.session.rollback()  # hold no lock a DDL attempt could wait for
    for statement in [*RUNTIME_ROLE_DENIED, *become_owner]:
        with runtime_role.engine.connect() as conn:
            with pytest.raises(DBAPIError) as caught:
                conn.execute(text(statement))
            conn.rollback()
        assert isinstance(caught.value.orig, psycopg.errors.InsufficientPrivilege), (
            f"{statement}: {caught.value.orig}"
        )

    # What the role may do, inserting journal rows, is still held to the trigger rules.
    entry_id = world.session.execute(select(JournalEntry.id).limit(1)).scalar_one()
    accrued = get_account(world.session, "owner_accrued", owner_id=books.bob.id)
    available = get_account(world.session, "owner_available", owner_id=books.bob.id)
    with runtime_role.engine.connect() as conn:
        with pytest.raises(DBAPIError, match="is closed"):
            conn.execute(INSERT_LINE, {"entry": entry_id, "account": accrued.id, "amount": D("50")})
        conn.rollback()
        new_entry = uuid.uuid4()
        conn.execute(INSERT_ENTRY, {"id": new_entry, "key": f"raw:{new_entry}"})
        conn.execute(INSERT_LINE, {"entry": new_entry, "account": accrued.id, "amount": D("50")})
        conn.execute(INSERT_LINE, {"entry": new_entry, "account": available.id, "amount": D("-49")})
        with pytest.raises(DBAPIError, match="does not balance"):
            conn.commit()
        conn.rollback()

    assert ledger_state() == before
    report = verify_ledger(world.session)
    assert report["ok"], report["problems"]
    assert verify_chain(world.session)["ok"]


# --- 8. verify_ledger blind spots ------------------------------------------

ALICE = "(SELECT id FROM owners WHERE display_name = 'Alice')"
BOB = "(SELECT id FROM owners WHERE display_name = 'Bob')"

# name -> (statement run behind the triggers' back, words one of which the report must use)
CORRUPTIONS = {
    "journal line changed": (
        "UPDATE journal_lines SET amount = amount + 1 WHERE id = (SELECT min(id) FROM journal_lines)",
        ("does not balance",),
    ),
    "balance row changed": (
        "UPDATE ledger_balances SET balance = balance + 1 "
        "WHERE account_id IN (SELECT id FROM ledger_accounts WHERE kind = 'cash_clearing')",
        ("balance cache mismatch",),
    ),
    "balance row removed": (
        "DELETE FROM ledger_balances "
        "WHERE account_id IN (SELECT id FROM ledger_accounts WHERE kind = 'fee_earned')",
        ("balance cache mismatch",),
    ),
    "bucket received changed": (
        "UPDATE earning_buckets SET received_amount = received_amount - 10 WHERE received_amount > 0",
        ("allocations sum to",),
    ),
    "bucket reported changed": (
        "UPDATE earning_buckets SET reported_amount = reported_amount + 10 WHERE external_machine_id = '101'",
        ("reported", "receivable"),
    ),
    "bucket owner share changed": (
        "UPDATE earning_buckets SET owner_accrued = owner_accrued + 5 WHERE external_machine_id = '101'",
        ("accrued",),
    ),
    "receipt allocated changed": (
        "UPDATE provider_receipts SET allocated_amount = allocated_amount - 10",
        ("allocations sum to",),
    ),
    "account overdraft flag changed": (
        "UPDATE ledger_accounts SET allow_overdraft = true WHERE kind = 'owner_available'",
        ("no longer matches its definition",),
    ),
    "account side changed": (
        "UPDATE ledger_accounts SET normal_side = 'debit' WHERE kind = 'owner_reserved'",
        ("no longer matches its definition",),
    ),
    "account kind changed": (
        # Bob's payable account relabelled as his reserved one: same side, same overdraft rule.
        "UPDATE ledger_accounts SET kind = 'owner_reserved' "
        f"WHERE kind = 'owner_available' AND owner_id = {BOB}",
        ("definition", "kind", "code"),
    ),
    "account owner changed": (
        # Alice's payable account now points at Bob; its code still names Alice.
        f"UPDATE ledger_accounts SET owner_id = {BOB} WHERE kind = 'owner_available' AND owner_id = {ALICE}",
        ("definition", "owner", "code"),
    ),
}


def corrupt(statement):
    """Change data behind the triggers' back, as someone with superuser access could."""
    with get_engine().begin() as conn:
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        changed = conn.execute(text(statement)).rowcount
    assert changed >= 1, "the corruption did not touch any row"


def test_verify_ledger_is_clean_on_untouched_books(world, books):
    """Finding 8. No false alarm on books with every kind of balance in them."""
    report = verify_ledger(world.session)
    assert report["ok"] is True and report["problems"] == []
    assert report["entries"] == count(world, JournalEntry) > 0
    assert report["totals"]["cash_clearing"] == "70.00000000"  # 160 received, 90 paid out
    assert report["totals"]["owner_in_transit"] == "45.00000000"
    assert report["totals"]["receipts_unallocated"] == "10.00000000"


@pytest.mark.parametrize("name", list(CORRUPTIONS))
def test_verify_ledger_reports_corruption(world, books, name):
    """Finding 8. Data changed behind the triggers' back is reported, and the report says what.

    ``session_replication_role = replica`` switches the triggers off for the corrupting
    statement only, the way ``conftest._clean`` does to empty the tables.
    """
    statement, words = CORRUPTIONS[name]
    corrupt(statement)
    report = verify_ledger(world.session)
    assert not report["ok"], f"verify_ledger did not notice: {name}"
    assert any(word in problem for word in words for problem in report["problems"]), report["problems"]


# --- 9. machines missing from the provider list ----------------------------


def test_machine_missing_from_the_provider_list_still_has_its_earnings_imported(world):
    """Finding 9. A machine the provider no longer lists may still have days we never imported."""
    owners, account, provider = build_fleet(
        world, {"Alice": ("101", {2: "10", 1: "10"}), "Bob": ("202", {2: "7", 1: "7"})}
    )
    provider.dataset["machines"] = [m for m in provider.dataset["machines"] if str(m["id"]) != "202"]
    sync = provider_sync.sync_machines(world.session, provider, account)
    world.commit()
    assert sync.stats["missing"] == 1
    gone = world.session.execute(
        select(ProviderMachine)
        .where(ProviderMachine.external_id == "202")
        .execution_options(populate_existing=True)
    ).scalar_one()
    assert gone.missing_since is not None and gone.machine_id is not None

    run, imported = provider_sync.run_earnings_import(
        world.session, SYSTEM, provider, account, start=world.day(2), end=world.day(1), user_id=None
    )
    world.commit()
    assert run.status == "ok" and imported.status == "posted"
    assert imported.stats["new"] == 4 and imported.stats["rows"] == 4
    rows = world.session.execute(
        select(EarningBucket.status, EarningBucket.owner_id, EarningBucket.reported_amount).where(
            EarningBucket.external_machine_id == "202"
        )
    ).all()
    assert sorted(tuple(r) for r in rows) == [("mapped", owners["Bob"].id, D("7"))] * 2
    assert balances(world, owners["Bob"]).accrued == D("12.6")
    assert balances(world, owners["Alice"]).accrued == D("18")
    assert open_exceptions(world) == []
    assert_reconciliation_sound(world)


# --- 10. vanished days -----------------------------------------------------


def test_day_absent_from_a_later_report_is_flagged_and_left_alone(world):
    """Finding 10. A (machine, day) that a later report no longer mentions is never zeroed."""
    owner, account, provider = setup_fleet(world, {"101": {3: "10", 2: "20", 1: "30"}})
    run_import(world, provider, account, 3, 1)
    before = ledger_state()
    vanished = bucket_of(world, "101", 2)

    del provider.dataset["earnings"]["101"][world.day(2).isoformat()]
    imported = run_import(world, provider, account, 3, 1)
    assert imported.stats["missing_from_report"] == 1
    assert (imported.stats["new"], imported.stats["revised"], imported.stats["unchanged"]) == (0, 0, 2)
    (flag,) = open_exceptions(world, "missing_from_report")
    assert flag.details["bucket_id"] == str(vanished.id) and flag.owner_id == owner.id
    assert world.day(2).isoformat() in flag.summary

    bucket = bucket_of(world, "101", 2)
    assert (bucket.reported_amount, bucket.revision_count) == (D("20"), 1)
    assert ledger_state()[:3] == before[:3]  # no journal entry, no balance changed
    assert balances(world, owner).accrued == D("54")

    # Fetched again: still one open exception for that day.
    run_import(world, provider, account, 3, 1)
    assert len(open_exceptions(world, "missing_from_report")) == 1
    assert_reconciliation_sound(world)


def test_a_report_says_nothing_about_days_or_machines_it_does_not_cover(world):
    """Finding 10, the other side: only a report covering that machine and day counts as absence."""
    owner, account, provider = setup_fleet(world, {"101": {3: "10", 2: "20", 1: "30"}})
    run_import(world, provider, account, 3, 1)
    del provider.dataset["earnings"]["101"][world.day(2).isoformat()]

    run_import(world, provider, account, 1, 1)  # the period does not include the day
    other_machine = manual_report([], world.day(3), world.day(1), covered=["999"])
    earnings.import_earnings(world.session, SYSTEM, account, other_machine)
    unspecified = manual_report([], world.day(3), world.day(1))  # the adapter did not say what it covers
    earnings.import_earnings(world.session, SYSTEM, account, unspecified)
    world.commit()
    assert open_exceptions(world, "missing_from_report") == []
    assert bucket_of(world, "101", 2).reported_amount == D("20")


# --- 11. unbind and rebind by day ------------------------------------------


def test_unbind_and_rebind_take_effect_by_utc_day(world):
    """Finding 11. Days earned under a binding stay with it, whenever they are imported.

    The unbind takes effect tomorrow (UTC). Days up to and including today are attributed to
    the machine and owner bound at the time, even though they are imported after the unbind;
    days from the rebind on go to the new machine and its owner.
    """
    world.fee()
    alice, bob = world.owner("Alice"), world.owner("Bob")
    provider = world.provider(dataset({"101": {}}, {"101": {3: "10", 2: "10", 1: "10"}}))
    account = world.account(provider)
    machine_a, _ = world.paired_machine(alice, "a")
    machine_b, _ = world.paired_machine(bob, "b")
    pm = world.bind(account, "101", machine_a)
    admin = world.user("admin")
    today, tomorrow = world.today, world.today + timedelta(days=1)

    provider_sync.unbind_machine(world.session, SYSTEM, provider_machine_id=pm.id, user_id=admin.id)
    world.commit()
    assert pm.machine_id is None
    assert earnings.bound_machine_on(world.session, pm, today) == machine_a.id
    assert earnings.bound_machine_on(world.session, pm, tomorrow) is None

    # Imported after the unbind, earned before it: still Alice's machine.
    imported = run_import(world, provider, account, 3, 1)
    assert imported.stats["new"] == 3
    attributed = world.session.execute(
        select(EarningBucket.status, EarningBucket.machine_id, EarningBucket.owner_id)
    ).all()
    assert [tuple(r) for r in attributed] == [("mapped", machine_a.id, alice.id)] * 3
    assert open_exceptions(world, "unmapped_machine") == []
    assert balances(world, alice).accrued == D("27")

    # A new binding cannot reach back into the days of the previous one.
    with pytest.raises(Conflict, match="previous binding"):
        provider_sync.bind_machine(
            world.session,
            SYSTEM,
            provider_machine_id=pm.id,
            machine_id=machine_b.id,
            bound_from=today,
            user_id=admin.id,
        )
    world.session.rollback()
    world.bind(account, "101", machine_b, days_ago=-1)  # from tomorrow

    # Some days later the provider reports today and the two days after it.
    later = [today, tomorrow, tomorrow + timedelta(days=1)]
    report = manual_report([("101", day, "10") for day in later], later[0], later[-1])
    earnings.import_earnings(world.session, SYSTEM, account, report, today=later[-1] + timedelta(days=1))
    world.commit()
    by_day = {
        day: (machine_id, owner_id)
        for day, machine_id, owner_id in world.session.execute(
            select(EarningBucket.day, EarningBucket.machine_id, EarningBucket.owner_id).where(
                EarningBucket.day >= today
            )
        )
    }
    assert by_day == {
        today: (machine_a.id, alice.id),  # the day of the unbind was still earned under it
        tomorrow: (machine_b.id, bob.id),
        later[-1]: (machine_b.id, bob.id),
    }
    assert balances(world, alice).accrued == D("36")
    assert balances(world, bob).accrued == D("18")
    assert open_exceptions(world, "unmapped_machine") == []
    assert_reconciliation_sound(world)


# --- 12. ownership transfer by day -----------------------------------------


def test_ownership_transfer_takes_effect_by_utc_day(world):
    """Finding 12. Earnings up to and including the transfer day go to the previous owner."""
    world.fee()
    alice, bob = world.owner("Alice"), world.owner("Bob")
    provider = world.provider(dataset({"101": {}}, {}))
    account = world.account(provider)
    machine, _ = world.paired_machine(alice)
    world.bind(account, "101", machine)
    admin = world.user("admin")
    machines.transfer_ownership(
        world.session, SYSTEM, machine_id=machine.id, new_owner_id=bob.id, reason="sold", user_id=admin.id
    )
    world.commit()

    today = world.today
    days = [today + timedelta(days=offset) for offset in (-1, 0, 1, 2)]
    report = manual_report([("101", day, "10") for day in days], days[0], days[-1])
    imported = earnings.import_earnings(
        world.session, SYSTEM, account, report, today=days[-1] + timedelta(days=1)
    )
    world.commit()
    assert imported.stats["new"] == 4
    owner_by_day = dict(world.session.execute(select(EarningBucket.day, EarningBucket.owner_id)).all())
    assert owner_by_day == {days[0]: alice.id, days[1]: alice.id, days[2]: bob.id, days[3]: bob.id}
    assert set(world.session.execute(select(EarningBucket.machine_id)).scalars()) == {machine.id}
    assert (balances(world, alice).accrued, balances(world, bob).accrued) == (D("18"), D("18"))

    # The cash follows the same split when it arrives.
    receipt = record(world, account, "40")
    receipts.allocate_period(world.session, SYSTEM, receipt.id, days[0], days[-1], created_by=None)
    world.commit()
    assert (balances(world, alice).available, balances(world, bob).available) == (D("18"), D("18"))
    assert_reconciliation_sound(world)


# --- 13. strict money parsing ----------------------------------------------

NOT_MONEY = [
    pytest.param("1e5", id="exponent"),
    pytest.param("1E5", id="exponent-upper"),
    pytest.param("1,5", id="decimal-comma"),
    pytest.param("1,000.00", id="thousands-separator"),
    pytest.param(" 1", id="leading-space"),
    pytest.param("NaN", id="nan"),
    pytest.param("Infinity", id="infinity"),
    pytest.param("-Infinity", id="negative-infinity"),
    pytest.param("", id="empty"),
    pytest.param("0.123456789", id="nine-decimals"),
    pytest.param("123456789012345", id="fifteen-integer-digits"),
    pytest.param("123456789012345.5", id="fifteen-integer-digits-with-decimals"),
    pytest.param("+1", id="plus-sign"),
    pytest.param("1_000", id="underscore"),
    pytest.param(".5", id="no-integer-part"),
    pytest.param("5.", id="no-decimal-part"),
    pytest.param("0x10", id="hex"),
    pytest.param("\u0661\u0662\u0663", id="non-ascii-digits"),
    pytest.param(1.5, id="float"),
    pytest.param(0.1, id="float-fraction"),
    pytest.param(float("nan"), id="float-nan"),
    pytest.param(True, id="bool-true"),
    pytest.param(False, id="bool-false"),
    pytest.param(None, id="none"),
    pytest.param(b"1", id="bytes"),
    pytest.param(D("NaN"), id="decimal-nan"),
    pytest.param(D("Infinity"), id="decimal-infinity"),
    pytest.param(D("0.123456789"), id="decimal-nine-decimals"),
]


@pytest.mark.parametrize("value", NOT_MONEY)
def test_to_decimal_refuses_anything_but_a_plain_decimal(value):
    """Finding 13. ``to_decimal`` accepts a plain decimal string and nothing else."""
    with pytest.raises(InvalidRequest):
        to_decimal(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0", "0"),
        ("-12.5", "-12.5"),
        ("12345678901234.12345678", "12345678901234.12345678"),
        ("0.00000001", "0.00000001"),
        ("-0.5", "-0.5"),
        ("007", "7"),
        (12, "12"),
        (D("1.10"), "1.1"),
    ],
)
def test_to_decimal_accepts_plain_decimals_exactly(value, expected):
    """Finding 13. Accepted values come back exact, at eight decimal places."""
    parsed = to_decimal(value)
    assert isinstance(parsed, Decimal) and parsed == D(expected)
    assert parsed.as_tuple().exponent == -8


BAD_AMOUNTS_OVER_HTTP = [
    "1e5",
    "1,5",
    "NaN",
    "Infinity",
    "",
    "0.123456789",
    "123456789012345",
    "+5",
    "1_000",
    "\u0661\u0662\u0663",
]


def test_receipt_api_refuses_a_bad_amount_and_posts_nothing(client, world):
    """Finding 13 at the API edge: 4xx, no receipt, no journal entry."""
    owner, account, provider = setup_fleet(world, {})
    h = world.auth(world.user("admin"))
    base = {
        "provider_account_id": str(account.id),
        "reference": "BANK-API",
        "received_on": world.today.isoformat(),
        "currency": "USD",
        "evidence_source": "bank_statement",
        "evidence_note": "statement p.1",
    }
    for bad in [*BAD_AMOUNTS_OVER_HTTP, 1.5, 100, True, None]:
        r = client.post("/api/v1/receipts", headers=h, json={**base, "amount": bad})
        assert 400 <= r.status_code < 500, (bad, r.status_code)
        assert r.json()["error"]["code"] == "invalid_request"
    assert count(world, ProviderReceipt) == 0 and count(world, JournalEntry) == 0
    assert count(world, LedgerBalance) == 0

    ok = client.post("/api/v1/receipts", headers=h, json={**base, "amount": "12.50"})
    assert ok.status_code == 201 and ok.json()["amount"] == "12.50000000"
    assert balance_of(world.session, get_account(world.session, "cash_clearing")) == D("12.5")


def test_dashboard_receipt_form_refuses_a_bad_amount_and_posts_nothing(client, world):
    """Finding 13 on the dashboard form: the receipt is refused and nothing is posted.

    The form answers a refused action the way it answers every other one: a redirect back to
    the page carrying the error (``?err=``), never the success message. A plain 4xx is
    accepted here too.
    """
    owner, account, provider = setup_fleet(world, {})
    admin = world.user("admin")
    assert client.post("/demo-login", data={"email": admin.email}, follow_redirects=False).status_code == 303
    form = {
        "provider_account_id": str(account.id),
        "reference": "BANK-FORM",
        "received_on": world.today.isoformat(),
        "evidence_source": "bank_statement",
        "evidence_note": "statement p.1",
        "csrf_token": client.get("/api/v1/auth/me").json()["csrf_token"],
    }
    for bad in BAD_AMOUNTS_OVER_HTTP:
        r = client.post("/admin/receipts", data={**form, "amount": bad}, follow_redirects=False)
        location = r.headers.get("location", "")
        refused_by_redirect = r.status_code == 303 and "?err=" in location and "msg=" not in location
        assert refused_by_redirect or 400 <= r.status_code < 500, (bad, r.status_code, location)
    assert count(world, ProviderReceipt) == 0 and count(world, JournalEntry) == 0
    assert count(world, LedgerBalance) == 0

    ok = client.post("/admin/receipts", data={**form, "amount": "12.50"}, follow_redirects=False)
    assert ok.status_code == 303 and "?msg=" in ok.headers["location"]
    assert world.session.execute(select(ProviderReceipt.amount)).scalar_one() == D("12.5")


# --- 14. payout provider exception -> uncertain ----------------------------


def test_provider_exception_during_submit_is_uncertain_not_failed(world, monkeypatch):
    """Finding 14. A timeout is not proof that a payment failed.

    The provider raises for Alice. Her item becomes ``uncertain``, her money stays in transit
    and nothing is released; Bob's item in the same batch is submitted normally.
    """
    owners, account, provider = build_fleet(world, {"Alice": ("101", {1: "100"}), "Bob": ("202", {1: "50"})})
    alice, bob = owners["Alice"], owners["Bob"]
    run_import(world, provider, account, 1, 1)
    reconcile(world, account, "150", "BANK-1", 1, 1)
    admin = world.user("admin")
    on_file(world, alice, admin)
    on_file(world, bob, admin)
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    world.commit()

    calls = []
    real_submit = MockPayoutProvider.submit

    def flaky_submit(self, instruction):
        calls.append(instruction.owner_name)
        if instruction.owner_name == "Alice":
            raise TimeoutError("read timed out")
        return real_submit(self, instruction)

    monkeypatch.setattr(MockPayoutProvider, "submit", flaky_submit)
    _, changed = payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id)
    world.commit()
    assert changed and sorted(calls) == ["Alice", "Bob"]

    items = {i.owner_id: i for i in world.session.execute(select(PayoutItem)).scalars()}
    assert (items[alice.id].status, items[bob.id].status) == ("uncertain", "submitted")
    assert items[alice.id].failure_reason == ""
    assert batch.status == "submitted"
    a = balances(world, alice)
    assert (a.available, a.reserved, a.in_transit) == (ZERO, ZERO, D("90"))
    types = entry_types(world)
    assert types.count("payout_submit") == 2
    assert not {"payout_release", "payout_fail"} & set(types)
    evidence = world.session.execute(
        select(PayoutEvidence).where(PayoutEvidence.item_id == items[alice.id].id)
    ).scalar_one()
    assert evidence.kind == "uncertain_outcome" and "outcome unknown" in evidence.note

    # Submitting again does not ask the provider a second time, and nothing can be paid twice.
    _, changed = payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id)
    world.commit()
    assert not changed and len(calls) == 2
    with pytest.raises(InsufficientFunds):
        prepare(world, admin, "retry-after-timeout")
    world.session.rollback()
    assert balances(world, alice).in_transit == D("90")

    # Only evidence settles it; here the bank says it never arrived.
    payouts.fail_item(world.session, SYSTEM, items[alice.id].id, reference="BANK-REJ-1", user_id=admin.id)
    world.commit()
    a = balances(world, alice)
    assert (a.available, a.in_transit) == (D("90"), ZERO)
    assert_reconciliation_sound(world)


# --- 15. void receipt ------------------------------------------------------


def test_void_receipt_reverses_it_and_frees_the_reference(world):
    """Finding 15. Void only without net allocations; cash and suspense return to zero."""
    owner, account, provider = setup_fleet(world, {"101": {1: "100"}})
    run_import(world, provider, account, 1, 1)
    admin = world.user("admin")
    receipt = record(world, account, "100", "BANK-1")
    bucket = bucket_of(world)
    cash = get_account(world.session, "cash_clearing")
    suspense = get_account(world.session, "receipts_unallocated", provider_account_id=account.id)

    def void(reason="entered twice by mistake"):
        voided = receipts.void_receipt(world.session, SYSTEM, receipt.id, reason=reason, user_id=admin.id)
        world.commit()
        return voided

    # Allocated money has to be taken back first.
    allocate(world, receipt, (bucket, "100"))
    with pytest.raises(Conflict, match="de-allocate"):
        void()
    world.session.rollback()
    allocate(world, receipt, (bucket, "-40"))
    with pytest.raises(Conflict, match="de-allocate"):
        void()
    world.session.rollback()
    with pytest.raises(InvalidRequest):
        void(reason="  ")
    world.session.rollback()
    assert receipt.voided_at is None

    allocate(world, receipt, (bucket, "-60"))  # net allocation is now zero
    entries = count(world, JournalEntry)
    voided = void()
    assert voided.voided_at is not None and voided.voided_by == admin.id
    assert balance_of(world.session, cash) == ZERO and balance_of(world.session, suspense) == ZERO
    b = balances(world, owner)
    assert (b.accrued, b.available) == (D("90"), ZERO)
    assert open_exceptions(world, "receipt_remainder") == []

    # A reversing entry, not an edit: the original is still there.
    reversal = world.session.execute(
        select(JournalEntry).where(JournalEntry.reverses_entry_id == receipt.journal_entry_id)
    ).scalar_one()
    assert reversal.entry_type == "reversal:provider_receipt"
    lines = {
        entry_id: sorted(
            world.session.execute(
                select(JournalLine.amount).where(JournalLine.entry_id == entry_id)
            ).scalars()
        )
        for entry_id in (receipt.journal_entry_id, reversal.id)
    }
    assert lines[receipt.journal_entry_id] == lines[reversal.id] == [D("-100"), D("100")]
    assert count(world, JournalEntry) == entries + 1
    void()  # voiding twice changes nothing
    assert count(world, JournalEntry) == entries + 1

    # A voided receipt cannot be allocated.
    refused(world, receipt, (bucket, "100"), match="voided")
    with pytest.raises(Conflict, match="voided"):
        receipts.allocate_period(
            world.session, SYSTEM, receipt.id, world.day(1), world.day(1), created_by=None
        )
    world.session.rollback()

    # The same bank reference can be recorded again, as a new receipt.
    replacement = reconcile(world, account, "100", "BANK-1", 1, 1)
    assert replacement.id != receipt.id
    assert count(world, ProviderReceipt) == 2
    assert balance_of(world.session, cash) == D("100")
    assert balances(world, owner).available == D("90")
    assert_reconciliation_sound(world)


def test_void_receipt_over_http(client, world):
    """Finding 15 over the API: void, then record the same reference again."""
    owner, account, provider = setup_fleet(world, {})
    h = world.auth(world.user("admin"))
    body = {
        "provider_account_id": str(account.id),
        "reference": "BANK-1",
        "received_on": world.today.isoformat(),
        "amount": "75",
        "currency": "USD",
        "evidence_source": "payout_provider_statement",
        "evidence_note": "statement p.2",
    }
    first = client.post("/api/v1/receipts", headers=h, json=body)
    assert first.status_code == 201
    void_url = f"/api/v1/receipts/{first.json()['id']}/void"
    assert client.post(void_url, headers=h, json={"reason": ""}).status_code == 422
    voided = client.post(void_url, headers=h, json={"reason": "wrong account"})
    assert voided.status_code == 200 and voided.json()["voided"] is True
    assert balance_of(world.session, get_account(world.session, "cash_clearing")) == ZERO

    again = client.post("/api/v1/receipts", headers=h, json=body)
    assert again.status_code == 201 and again.json()["created"] is True
    assert again.json()["id"] != first.json()["id"]
    assert balance_of(world.session, get_account(world.session, "cash_clearing")) == D("75")
    report = verify_ledger(world.session)
    assert report["ok"], report["problems"]


# --- 16. receipt evidence --------------------------------------------------


def test_evidence_sources_are_statements_only():
    assert EVIDENCE_SOURCES == ("bank_statement", "payout_provider_statement")


@pytest.mark.parametrize(
    "source", ["provider_invoice", "vast_invoice_paid", "", "invoice", "BANK_STATEMENT", "bank_statement "]
)
def test_receipt_needs_statement_evidence(world, source):
    """Finding 16. A provider invoice marked "Paid" is not evidence that money arrived."""
    owner, account, provider = setup_fleet(world, {"101": {1: "100"}})
    run_import(world, provider, account, 1, 1)
    before = ledger_state()
    with pytest.raises(InvalidRequest, match="evidence_source"):
        receipts.record_receipt(
            world.session,
            SYSTEM,
            account,
            reference="INV-1",
            received_on=world.today,
            amount=D("100"),
            currency="USD",
            evidence_source=source,
            evidence_note="invoice page shows Paid",
            created_by=None,
        )
    world.session.rollback()
    assert count(world, ProviderReceipt) == 0 and ledger_state() == before
    # The database holds the same line, should the service ever be bypassed.
    with pytest.raises(IntegrityError, match="receipt_evidence_source"):
        world.session.execute(
            text(
                "INSERT INTO provider_receipts (id, provider_account_id, reference, received_on, amount, "
                "allocated_amount, currency, evidence_source, evidence_note, is_synthetic, created_at, "
                "void_reason) VALUES (:id, :account, 'INV-1', current_date, 100, 0, 'USD', :source, 'x', "
                "true, now(), '')"
            ),
            {"id": uuid.uuid4(), "account": account.id, "source": source},
        )
    world.session.rollback()
    assert balances(world, owner).available == ZERO


def test_receipt_api_needs_statement_evidence(client, world):
    """Finding 16 over the API: anything but a statement is a 4xx and posts nothing."""
    owner, account, provider = setup_fleet(world, {})
    h = world.auth(world.user("admin"))
    base = {
        "provider_account_id": str(account.id),
        "received_on": world.today.isoformat(),
        "amount": "100",
        "currency": "USD",
        "evidence_note": "seen on a page",
    }
    for source in ("provider_invoice", "vast_invoice_paid", "", None, "BANK_STATEMENT"):
        r = client.post(
            "/api/v1/receipts", headers=h, json={**base, "reference": "R", "evidence_source": source}
        )
        assert r.status_code == 422, source
    assert client.post("/api/v1/receipts", headers=h, json={**base, "reference": "R"}).status_code == 422
    assert count(world, ProviderReceipt) == 0 and count(world, JournalEntry) == 0

    for n, source in enumerate(EVIDENCE_SOURCES):
        r = client.post(
            "/api/v1/receipts", headers=h, json={**base, "reference": f"R-{n}", "evidence_source": source}
        )
        assert r.status_code == 201 and r.json()["evidence_source"] == source
    assert count(world, ProviderReceipt) == 2


def test_importing_earnings_never_touches_owner_available(world):
    """Finding 16. Reported earnings, and revisions of them, are accruals: never payable cash."""
    owner, account, provider = setup_fleet(world, {"101": {3: "10", 2: "20", 1: "30"}})
    run_import(world, provider, account, 3, 1)
    revise(world, provider, account, "101", 2, "25")
    revise(world, provider, account, "101", 1, "5")
    run_import(world, provider, account, 3, 1)

    b = balances(world, owner)
    assert (b.accrued, b.available) == (D("36"), ZERO)
    available_kinds = ("owner_available", "owner_reserved", "owner_in_transit", "cash_clearing", "fee_earned")
    touched = world.session.execute(
        select(func.count())
        .select_from(JournalLine)
        .join(LedgerAccount, LedgerAccount.id == JournalLine.account_id)
        .where(LedgerAccount.kind.in_(available_kinds))
    ).scalar_one()
    assert touched == 0
    assert set(entry_types(world)) == {"earning_accrual", "earning_adjustment"}
    admin = world.user("admin")
    on_file(world, owner, admin)
    for exception in open_exceptions(world, "unexplained_adjustment"):
        exceptions_queue.resolve(world.session, SYSTEM, exception.id, "checked", admin.id)
    world.commit()
    with pytest.raises(InsufficientFunds):
        prepare(world, admin)
    world.session.rollback()


# --- 17. concurrent record_receipt -----------------------------------------


def test_concurrent_identical_receipts_are_recorded_once(world):
    """Finding 17. Same reference from four sessions: one receipt, one entry, one answer."""
    owner, account, provider = setup_fleet(world, {})
    account_id, received_on = account.id, world.today

    def job(session):
        receipt, created = receipts.record_receipt(
            session,
            SYSTEM,
            session.get(ProviderAccount, account_id),
            reference="BANK-RACE",
            received_on=received_on,
            amount=D("50"),
            currency="USD",
            evidence_source="bank_statement",
            evidence_note="statement p.1",
            created_by=None,
        )
        return receipt.id, created

    done, errors = split(race(job, job, job, job))
    assert errors == [] and len(done) == 4
    assert len({receipt_id for receipt_id, _ in done}) == 1
    assert sorted(created for _, created in done) == [False, False, False, True]

    assert count(world, ProviderReceipt) == 1
    assert entry_types(world) == ["provider_receipt"]
    assert balance_of(world.session, get_account(world.session, "cash_clearing")) == D("50")
    suspense = get_account(world.session, "receipts_unallocated", provider_account_id=account.id)
    assert balance_of(world.session, suspense) == D("50")
    assert len(open_exceptions(world, "receipt_remainder")) == 1
    recorded = world.session.execute(
        select(func.count()).select_from(AuditLog).where(AuditLog.action == "receipt.record")
    ).scalar_one()
    assert recorded == 1
    assert_reconciliation_sound(world)


# --- 18. bank confirmation reference uniqueness ----------------------------


def test_one_bank_reference_cannot_confirm_two_payout_items(world, books):
    """Finding 18. One bank transaction pays one item."""
    paid = world.session.execute(select(PayoutItem).where(PayoutItem.owner_id == books.alice.id)).scalar_one()
    pending = world.session.execute(
        select(PayoutItem).where(PayoutItem.owner_id == books.bob.id)
    ).scalar_one()
    assert (paid.status, paid.external_reference, pending.status) == (
        "confirmed_paid",
        "BANK-OUT-1",
        "submitted",
    )
    cash = get_account(world.session, "cash_clearing")
    before = ledger_state()

    for reference in ("BANK-OUT-1", "  BANK-OUT-1  "):
        with pytest.raises(Conflict, match="already confirms another payout"):
            payouts.confirm_item(
                world.session, SYSTEM, pending.id, reference=reference, user_id=books.admin.id
            )
        world.session.rollback()
    # The bulk import of a bank result file is held to the same rule.
    row = {"item_id": str(pending.id), "outcome": "paid", "reference": "BANK-OUT-1", "note": ""}
    with pytest.raises(Conflict, match="already confirms another payout"):
        payouts.import_confirmations(world.session, SYSTEM, books.batch.id, [row], user_id=books.admin.id)
    world.session.rollback()

    world.session.refresh(pending)
    assert pending.status == "submitted"
    assert ledger_state() == before
    assert balances(world, books.bob).in_transit == D("45")
    assert balance_of(world.session, cash) == D("70")
    confirmations = world.session.execute(
        select(func.count()).select_from(PayoutEvidence).where(PayoutEvidence.kind == "bank_confirmation")
    ).scalar_one()
    assert confirmations == 1

    payouts.confirm_item(world.session, SYSTEM, pending.id, reference="BANK-OUT-2", user_id=books.admin.id)
    world.commit()
    world.session.refresh(books.batch)
    assert books.batch.status == "closed"
    assert balance_of(world.session, cash) == D("25")  # 15 of fees and the 10 still in suspense
    assert_reconciliation_sound(world)


# --- 19. synthetic owners are never paid in LIVE ---------------------------


def test_synthetic_owners_are_never_paid_in_live_nor_real_ones_in_demo(world):
    """Finding 19. ``prepare_batch`` only ever drafts owners that belong to the running mode."""
    live = live_settings(payouts_enabled=True)
    assert live.is_live and live.problems() == []
    live_world = World(live)
    try:
        world.fee()
        provider = world.provider(dataset({"101": {}, "202": {}}, {"101": {1: "100"}, "202": {1: "50"}}))
        account = world.account(provider)
        synthetic, real = world.owner("Synthetic Sam"), live_world.owner("Real Rita")
        assert synthetic.is_synthetic and not real.is_synthetic
        machine, _ = world.paired_machine(synthetic, "m101")
        world.bind(account, "101", machine)
        machine, _ = live_world.paired_machine(real, "m202")
        world.bind(account, "202", machine)
        run_import(world, provider, account, 1, 1)
        reconcile(world, account, "150", "BANK-1", 1, 1)
        admin = world.user("admin")
        on_file(world, synthetic, admin)
        on_file(world, real, admin)
        assert (balances(world, synthetic).available, balances(world, real).available) == (D("90"), D("45"))

        def drafted(settings, key, **kw):
            batch, _ = payouts.prepare_batch(
                world.session, settings, SYSTEM, idempotency_key=key, created_by=admin.id, **kw
            )
            world.commit()
            return batch, [(item.owner_id, item.amount) for item in batch.items]

        live_batch, live_items = drafted(live, "live-batch-0001")
        assert live_items == [(real.id, D("45.00"))]
        demo_batch, demo_items = drafted(world.settings, "demo-batch-0001")
        assert demo_items == [(synthetic.id, D("90.00"))]

        # Naming the owner explicitly does not get round it.
        with pytest.raises(InsufficientFunds):
            drafted(live, "live-synthetic-0001", owner_ids=[synthetic.id])
        world.session.rollback()
        with pytest.raises(InsufficientFunds):
            drafted(world.settings, "demo-real-0001", owner_ids=[real.id])
        world.session.rollback()
        assert count(world, PayoutBatch) == 2

        # Nor does a batch drafted in the other mode.
        for settings, batch in ((live, demo_batch), (world.settings, live_batch)):
            with pytest.raises(Conflict, match="synthetic and real"):
                payouts.approve_batch(world.session, settings, SYSTEM, batch.id, approver_id=admin.id)
            world.session.rollback()
        assert (balances(world, synthetic).reserved, balances(world, real).reserved) == (ZERO, ZERO)

        payouts.approve_batch(world.session, live, SYSTEM, live_batch.id, approver_id=admin.id)
        world.commit()
        assert (balances(world, synthetic).reserved, balances(world, real).reserved) == (ZERO, D("45"))
        assert balances(world, synthetic).available == D("90")
    finally:
        live_world.close()


# --- 20. CSV injection -----------------------------------------------------

FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")


@pytest.mark.parametrize(
    "value",
    [
        "=1+1",
        "+1+1",
        "-1+1",
        "@SUM(A1:A9)",
        "\t=1+1",
        "\r=1+1",
        "\r\n=1+1",
        "\t\t-2+3",
        '=HYPERLINK("http://x","click")',
        "=cmd|' /C calc'!A0",
    ],
)
def test_csv_cell_neutralises_formula_cells(value):
    """Finding 20. A cell beginning with = + - @ tab or CR arrives as text."""
    cell = payouts.csv_cell(value)
    assert not cell.startswith(FORMULA_STARTS), repr(cell)
    assert not any(ch in cell for ch in "\t\r\n")
    assert cell.endswith(value.strip("\t\r\n"))  # the text itself is kept


@pytest.mark.parametrize(
    "value", ["Alice", "O'Brien & Sons", IBAN, "90.00", "a=b", "x-y", "user@example.test", ""]
)
def test_csv_cell_leaves_ordinary_text_alone(value):
    assert payouts.csv_cell(value) == value


def test_export_contains_no_formula_cells(world):
    """Finding 20. An owner or beneficiary name that is a formula cannot run in the bank export."""
    name = '=HYPERLINK("http://x","pay")'
    owners, account, provider = build_fleet(world, {name: ("101", {1: "100"})})
    owner = owners[name]
    run_import(world, provider, account, 1, 1)
    reconcile(world, account, "100", "BANK-1", 1, 1)
    admin = world.user("admin")
    on_file(
        world,
        owner,
        admin,
        account_holder="@SUM(1+1)*cmd|' /C calc'!A0",
        bic="+BIC",
        bank_name="-2+3",
        country="\t=1+1",
    )
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    body, _ = payouts.export_batch(world.session, world.settings, SYSTEM, batch.id)
    world.commit()

    rows = list(csv.reader(io.StringIO(body.decode())))
    assert len(rows) == 2
    header, row = rows
    cells = dict(zip(header, row, strict=True))
    assert not any(cell.startswith(FORMULA_STARTS) for cell in row), row
    assert cells["owner_name"] == "'" + name
    assert cells["account_holder"] == "'@SUM(1+1)*cmd|' /C calc'!A0"
    assert (cells["bic"], cells["bank_name"], cells["country"]) == ("'+BIC", "'-2+3", "'=1+1")
    assert (cells["iban"], cells["amount"], cells["currency"]) == (IBAN, "90.00", "USD")


# --- 21. retroactive fee schedule ------------------------------------------


def test_fee_schedule_cannot_reach_back_over_posted_days(world):
    """Finding 21. The rule, as ``fees.create_fee_schedule`` implements it:

    a new version's ``effective_from`` must be strictly later than the latest day that already
    has attributed ("mapped") earnings in the version's scope. The scope of an owner-specific
    version is that owner's buckets; the scope of a default version (no owner) is every
    attributed bucket. Unattributed buckets do not count. Otherwise ``Conflict``.
    """
    owners, account, provider = build_fleet(
        world, {"Alice": ("101", {5: "100", 3: "100"}), "Bob": ("202", {})}
    )
    alice, bob = owners["Alice"], owners["Bob"]
    provider.dataset["machines"].append({"id": 999, "hostname": "h999", "gpu_name": "RTX", "num_gpus": 1})
    provider.dataset["earnings"]["999"] = {world.day(1).isoformat(): {"gpu_earn": "50"}}
    provider_sync.sync_machines(world.session, provider, account)
    world.commit()
    run_import(world, provider, account, 5, 1)  # Alice: days 5 and 3; machine 999: day 1, unattributed
    statuses = dict(world.session.execute(select(EarningBucket.day, EarningBucket.status)).all())
    assert statuses == {world.day(5): "mapped", world.day(3): "mapped", world.day(1): "unmapped"}
    before = ledger_state()

    def create(owner, days_ago, rate="0.20"):
        schedule = fees.create_fee_schedule(
            world.session,
            SYSTEM,
            owner_id=owner.id if owner else None,
            rate=D(rate),
            effective_from=world.day(days_ago),
            note="",
            created_by=None,
        )
        world.commit()
        return schedule

    for owner in (None, alice):
        for days_ago in (30, 5, 4, 3):  # on or before day 3, the last posted day
            with pytest.raises(Conflict, match="fee history is not rewritten"):
                create(owner, days_ago)
            world.session.rollback()
    assert create(None, 2).effective_from == world.day(2)  # the day after: allowed
    assert create(alice, 2, rate="0.05").owner_id == alice.id
    # Bob has no posted earnings: his own schedule may start anywhere.
    assert create(bob, 30, rate="0.15").effective_from == world.day(30)

    # Nothing that was posted has been re-priced.
    assert ledger_state()[:3] == before[:3]
    rates = set(
        world.session.execute(
            select(EarningBucket.fee_rate).where(EarningBucket.status == "mapped")
        ).scalars()
    )
    assert rates == {D("0.10")}
    assert balances(world, alice).accrued == D("180")
    assert_reconciliation_sound(world)


# =============================================================================
# Follow-ups found while writing the tests above
# =============================================================================


def approved_then_revised(world, *, export_first: bool):
    """Alice has 90 reserved in an approved batch; then the provider takes 30 of the day back."""
    owners, account, provider = build_fleet(world, {"Alice": ("101", {1: "100"})})
    alice = owners["Alice"]
    run_import(world, provider, account, 1, 1)
    reconcile(world, account, "100", "BANK-1", 1, 1)
    admin = world.user("admin")
    on_file(world, alice, admin)
    batch, _ = prepare(world, admin, "approved-then-revised")
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    world.commit()
    first_export = None
    if export_first:
        first_export = payouts.export_batch(world.session, world.settings, SYSTEM, batch.id)
        world.commit()
    revise(world, provider, account, "101", 1, "70.00")
    assert payouts.payout_blockers(world.session, alice.id)
    return alice, admin, batch, first_export


def test_revision_after_approval_stops_the_batch_before_it_reaches_the_bank(world):
    """Approved, not yet exported, then revised down: no file, no submission; cancelling releases it."""
    alice, admin, batch, _ = approved_then_revised(world, export_first=False)

    with pytest.raises(Conflict, match="cannot be exported"):
        payouts.export_batch(world.session, world.settings, SYSTEM, batch.id)
    world.session.rollback()
    for provider in (MockPayoutProvider(), ManualExportProvider()):
        with pytest.raises(Conflict, match="cannot be submitted"):
            payouts.submit_batch(
                world.session, world.settings, SYSTEM, batch.id, user_id=admin.id, provider=provider
            )
        world.session.rollback()
    b = owner_balances(world.session, alice.id)
    assert (b.available, b.reserved, b.in_transit) == (ZERO, D("90"), ZERO)
    assert world.session.get(PayoutBatch, batch.id).export_count == 0

    payouts.cancel_batch(world.session, SYSTEM, batch.id, user_id=admin.id)
    world.commit()
    b = owner_balances(world.session, alice.id)
    assert (b.available, b.reserved) == (D("90"), ZERO)
    # Still held, and still on the books as an open exception: nothing is hidden.
    assert payouts.payout_blockers(world.session, alice.id)
    assert verify_ledger(world.session)["ok"]


def test_exported_batch_can_still_be_recorded_as_submitted_but_never_auto_paid(world):
    """The file left before the revision: recording that fact is allowed, executing a transfer is not."""
    alice, admin, batch, (body, digest) = approved_then_revised(world, export_first=True)

    # The same file can be produced again; it is the one that may be at the bank.
    again, again_digest = payouts.export_batch(world.session, world.settings, SYSTEM, batch.id)
    world.commit()
    assert (again, again_digest) == (body, digest)
    # A provider that would itself move money is refused while the owner is held.
    with pytest.raises(Conflict, match="cannot be submitted"):
        payouts.submit_batch(
            world.session, world.settings, SYSTEM, batch.id, user_id=admin.id, provider=MockPayoutProvider()
        )
    world.session.rollback()
    # The operator's statement that the exported file was handed over is recorded.
    payouts.submit_batch(
        world.session, world.settings, SYSTEM, batch.id, user_id=admin.id, provider=ManualExportProvider()
    )
    world.commit()
    b = owner_balances(world.session, alice.id)
    assert (b.available, b.reserved, b.in_transit) == (ZERO, ZERO, D("90"))
    # The day is still over-received and the owner still held for anything further.
    assert open_exceptions(world, "over_received") and payouts.payout_blockers(world.session, alice.id)


def test_over_received_exception_cannot_be_closed_with_a_note(world):
    owners, account, provider = build_fleet(world, {"Alice": ("101", {1: "100"})})
    run_import(world, provider, account, 1, 1)
    receipt = reconcile(world, account, "100", "BANK-1", 1, 1)
    admin = world.user("admin")
    revise(world, provider, account, "101", 1, "70.00")
    (over,) = open_exceptions(world, "over_received")

    with pytest.raises(Conflict, match="de-allocate the difference"):
        exceptions_queue.resolve(world.session, SYSTEM, over.id, "it is fine", admin.id)
    world.session.rollback()
    assert [e.id for e in open_exceptions(world, "over_received")] == [over.id]

    # Corrected: it closes by itself, and there is nothing left to close by hand.
    allocate(world, receipt, (bucket_of(world, "101"), "-30"))
    assert open_exceptions(world, "over_received") == []
    with pytest.raises(Conflict, match="already resolved"):
        exceptions_queue.resolve(world.session, SYSTEM, over.id, "late", admin.id)
    world.session.rollback()
    assert_reconciliation_sound(world)
