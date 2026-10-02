"""Earnings import and ledger: replay safety, corrections, fees, reconciliation."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import pytest
from helpers import SYSTEM, dataset
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from happymining.errors import Conflict, InsufficientFunds, InvalidRequest
from happymining.models import (
    EarningBucket,
    EarningRevision,
    ExceptionItem,
    JournalEntry,
    JournalLine,
    LedgerBalance,
)
from happymining.providers.base import EarningsReport, EarningsRow
from happymining.services import earnings, fees, receipts
from happymining.services.ledger import (
    Line,
    balance_of,
    get_account,
    owner_balances,
    post_entry,
    to_decimal,
    verify_ledger,
)
from happymining.services.statements import owner_statement

D = Decimal


def setup_fleet(world, earnings_by_machine, *, fee="0.10", machines=("101",)):
    """Owner + bound machine(s) + fee schedule + fake provider. Returns (owner, account, provider)."""
    owner = world.owner("Alice")
    world.fee(fee)
    provider = world.provider(
        dataset({m: {} for m in set(machines) | set(earnings_by_machine)}, earnings_by_machine)
    )
    account = world.account(provider)
    for i, machine_id in enumerate(machines):
        machine, _ = world.paired_machine(owner, f"m{i}")
        world.bind(account, machine_id, machine)
    return owner, account, provider


def run_import(world, provider, account, start_ago, end_ago):
    report = provider.fetch_earnings(
        [str(m["id"]) for m in provider.dataset["machines"]], world.day(start_ago), world.day(end_ago)
    )
    imp = earnings.import_earnings(world.session, SYSTEM, account, report)
    world.commit()
    return imp


def count(world, model) -> int:
    return world.session.execute(select(func.count()).select_from(model)).scalar_one()


def open_exceptions(world, kind=None) -> list[ExceptionItem]:
    query = select(ExceptionItem).where(ExceptionItem.status == "open")
    if kind:
        query = query.where(ExceptionItem.kind == kind)
    return list(world.session.execute(query).scalars())


# --- import ----------------------------------------------------------------


def test_demo_example_100_fee_10_owner_90(world):
    """Spec example: eligible settled earnings 100.00, fee 10% = 10.00, owner payable 90.00."""
    owner, account, provider = setup_fleet(world, {"101": {2: "60.00", 1: "40.00"}})
    imp = run_import(world, provider, account, 3, 1)
    assert imp.status == "posted" and imp.stats["new"] == 2

    # Reported is not cash: nothing is available yet.
    b = owner_balances(world.session, owner.id)
    assert (b.accrued, b.available) == (D("90.00000000"), D("0"))

    receipt, _ = receipts.record_receipt(
        world.session,
        SYSTEM,
        account,
        reference="BANK-1",
        received_on=world.today,
        amount=D("100"),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="statement p.1",
        created_by=None,
    )
    receipts.allocate_period(world.session, SYSTEM, receipt.id, world.day(3), world.day(1), created_by=None)
    world.commit()

    b = owner_balances(world.session, owner.id)
    assert (b.accrued, b.available) == (D("0E-8"), D("90.00000000"))
    statement = owner_statement(world.session, owner.id, world.day(3), world.day(1))
    assert statement["reconciled"] == {
        "eligible_base": "100.00000000",
        "management_fee": "10.00000000",
        "owner_share": "90.00000000",
        "note": statement["reconciled"]["note"],
    }
    assert statement["balances_now"]["payable"] == "90.00"
    assert verify_ledger(world.session)["ok"]


def test_reimporting_an_unchanged_report_creates_nothing(world):
    owner, account, provider = setup_fleet(world, {"101": {3: "10.5", 2: "11.25", 1: "9.75"}})
    run_import(world, provider, account, 3, 1)
    entries, lines, revisions = (
        count(world, JournalEntry),
        count(world, JournalLine),
        count(world, EarningRevision),
    )
    before = owner_balances(world.session, owner.id)

    for _ in range(3):
        again = run_import(world, provider, account, 3, 1)
        assert again.status == "duplicate"
        assert again.stats["unchanged"] == 3 and again.stats["new"] == 0 and again.stats["revised"] == 0

    assert (count(world, JournalEntry), count(world, JournalLine), count(world, EarningRevision)) == (
        entries,
        lines,
        revisions,
    )
    assert owner_balances(world.session, owner.id) == before
    assert verify_ledger(world.session)["ok"]


def test_overlapping_imports_count_each_day_once(world):
    amounts = {7: "1", 6: "2", 5: "3", 4: "4", 3: "5", 2: "6", 1: "7"}
    owner, account, provider = setup_fleet(world, {"101": amounts})
    run_import(world, provider, account, 7, 3)  # days 7..3
    run_import(world, provider, account, 5, 1)  # days 5..1 overlap on 5, 4, 3
    run_import(world, provider, account, 7, 1)  # everything again

    assert count(world, EarningBucket) == 7
    reported = world.session.execute(select(func.sum(EarningBucket.reported_amount))).scalar_one()
    assert reported == D("28")
    assert owner_balances(world.session, owner.id).accrued == D("25.2")  # 28 less 10%
    assert verify_ledger(world.session)["ok"]


def test_correction_posts_only_the_delta_and_is_traceable(world):
    owner, account, provider = setup_fleet(world, {"101": {1: "10.00"}})
    run_import(world, provider, account, 1, 1)
    key = world.day(1).isoformat()

    provider.dataset["earnings"]["101"][key] = {"gpu_earn": "12.50"}
    imp = run_import(world, provider, account, 1, 1)
    assert imp.status == "posted" and imp.stats["revised"] == 1

    bucket = world.session.execute(select(EarningBucket)).scalar_one()
    assert bucket.reported_amount == D("12.5") and bucket.revision_count == 2
    revisions = (
        world.session.execute(select(EarningRevision).order_by(EarningRevision.revision_no)).scalars().all()
    )
    assert [(r.reported_amount, r.delta) for r in revisions] == [(D("10"), D("10")), (D("12.5"), D("2.5"))]
    # Each revision points at its own journal entry; the original is untouched.
    entries = world.session.execute(select(JournalEntry).order_by(JournalEntry.posted_at)).scalars().all()
    assert [e.entry_type for e in entries] == ["earning_accrual", "earning_adjustment"]
    assert {r.journal_entry_id for r in revisions} == {e.id for e in entries}
    assert owner_balances(world.session, owner.id).accrued == D("11.25")
    assert [e.kind for e in open_exceptions(world)] == ["unexplained_adjustment"]
    assert verify_ledger(world.session)["ok"]


def test_negative_adjustment_reduces_accrual(world):
    owner, account, provider = setup_fleet(world, {"101": {1: "10.00"}})
    run_import(world, provider, account, 1, 1)
    provider.dataset["earnings"]["101"][world.day(1).isoformat()] = {"gpu_earn": "4.00"}
    run_import(world, provider, account, 1, 1)

    assert owner_balances(world.session, owner.id).accrued == D("3.6")
    delta_entry = world.session.execute(
        select(JournalEntry).where(JournalEntry.entry_type == "earning_adjustment")
    ).scalar_one()
    lines = (
        world.session.execute(select(JournalLine).where(JournalLine.entry_id == delta_entry.id))
        .scalars()
        .all()
    )
    assert sorted(line.amount for line in lines) == [D("-6"), D("0.6"), D("5.4")]
    assert verify_ledger(world.session)["ok"]


def test_downward_revision_after_receipt_is_flagged_over_received(world):
    owner, account, provider = setup_fleet(world, {"101": {1: "10.00"}})
    run_import(world, provider, account, 1, 1)
    receipt, _ = receipts.record_receipt(
        world.session,
        SYSTEM,
        account,
        reference="R1",
        received_on=world.today,
        amount=D("10"),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="e",
        created_by=None,
    )
    receipts.allocate_period(world.session, SYSTEM, receipt.id, world.day(1), world.day(1), created_by=None)
    world.commit()

    provider.dataset["earnings"]["101"][world.day(1).isoformat()] = {"gpu_earn": "7.00"}
    run_import(world, provider, account, 1, 1)
    kinds = sorted(e.kind for e in open_exceptions(world))
    assert kinds == ["over_received", "unexplained_adjustment"]
    # The owner's accrued account now shows what must be recovered.
    b = owner_balances(world.session, owner.id)
    assert b.accrued == D("-2.7") and b.available == D("9")
    assert verify_ledger(world.session)["ok"]


def test_fractional_amounts_keep_sub_cent_precision(world):
    owner, account, provider = setup_fleet(world, {"101": {2: "0.12345678", 1: "0.00000001"}}, fee="0.125")
    run_import(world, provider, account, 2, 1)
    buckets = world.session.execute(select(EarningBucket).order_by(EarningBucket.day)).scalars().all()
    for bucket in buckets:
        assert bucket.owner_accrued + bucket.fee_accrued == bucket.reported_amount
    assert buckets[0].fee_accrued == D("0.01543210")  # 0.12345678 * 0.125 = 0.0154320975, half-even
    assert buckets[1].fee_accrued == D("0E-8") and buckets[1].owner_accrued == D("0.00000001")
    assert verify_ledger(world.session)["ok"]


def test_partial_receipts_release_exactly_what_was_accrued(world):
    owner, account, provider = setup_fleet(world, {"101": {1: "0.33333333"}}, fee="0.10")
    run_import(world, provider, account, 1, 1)
    bucket = world.session.execute(select(EarningBucket)).scalar_one()
    receipt, _ = receipts.record_receipt(
        world.session,
        SYSTEM,
        account,
        reference="R",
        received_on=world.today,
        amount=D("0.33333333"),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="e",
        created_by=None,
    )
    for part in ("0.11111111", "0.11111111", "0.11111111"):
        receipts.allocate(
            world.session,
            SYSTEM,
            receipt.id,
            [receipts.AllocationRequest(bucket.id, D(part))],
            created_by=None,
        )
    world.commit()
    world.session.refresh(bucket)
    assert bucket.received_amount == bucket.reported_amount
    assert bucket.fee_released == bucket.fee_accrued and bucket.owner_released == bucket.owner_accrued
    b = owner_balances(world.session, owner.id)
    assert b.accrued == D("0") and b.available == bucket.owner_accrued
    assert verify_ledger(world.session)["ok"]


def test_fee_version_boundary_and_history_is_not_rewritten(world):
    owner, account, provider = setup_fleet(world, {"101": {4: "100", 3: "100", 2: "100", 1: "100"}})
    run_import(world, provider, account, 4, 3)  # two days at 10%

    # A new version may not reach back over posted days...
    with pytest.raises(Conflict):
        fees.create_fee_schedule(
            world.session,
            SYSTEM,
            owner_id=None,
            rate=D("0.20"),
            effective_from=world.day(3),
            note="",
            created_by=None,
        )
    world.session.rollback()
    # ...but it can start the day after.
    fees.create_fee_schedule(
        world.session,
        SYSTEM,
        owner_id=None,
        rate=D("0.20"),
        effective_from=world.day(2),
        note="",
        created_by=None,
    )
    world.commit()
    run_import(world, provider, account, 4, 1)

    rates = dict(world.session.execute(select(EarningBucket.day, EarningBucket.fee_rate)).all())
    assert rates == {
        world.day(4): D("0.10"),
        world.day(3): D("0.10"),
        world.day(2): D("0.20"),
        world.day(1): D("0.20"),
    }
    # A later correction to an old day keeps that day's original rate.
    provider.dataset["earnings"]["101"][world.day(4).isoformat()] = {"gpu_earn": "150"}
    run_import(world, provider, account, 4, 1)
    old = world.session.execute(select(EarningBucket).where(EarningBucket.day == world.day(4))).scalar_one()
    assert old.fee_rate == D("0.10") and old.fee_accrued == D("15") and old.owner_accrued == D("135")
    assert verify_ledger(world.session)["ok"]


def test_owner_specific_fee_takes_precedence(world):
    owner, account, provider = setup_fleet(world, {"101": {1: "100"}})
    world.fee("0.05", days_ago=30, owner=owner)
    run_import(world, provider, account, 1, 1)
    assert owner_balances(world.session, owner.id).accrued == D("95")


def test_unmapped_machine_goes_to_exception_queue_and_is_not_payable(world):
    owner, account, provider = setup_fleet(world, {"101": {1: "10"}, "999": {1: "50"}})
    run_import(world, provider, account, 1, 1)

    unmapped = world.session.execute(
        select(EarningBucket).where(EarningBucket.status == "unmapped")
    ).scalar_one()
    assert unmapped.external_machine_id == "999" and unmapped.owner_id is None
    assert [e.kind for e in open_exceptions(world)] == ["unmapped_machine"]
    account_unmapped = get_account(world.session, "unmapped_earnings", provider_account_id=account.id)
    assert balance_of(world.session, account_unmapped) == D("50")

    # It cannot be reconciled into anyone's balance.
    receipt, _ = receipts.record_receipt(
        world.session,
        SYSTEM,
        account,
        reference="R",
        received_on=world.today,
        amount=D("60"),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="e",
        created_by=None,
    )
    with pytest.raises(Conflict):
        receipts.allocate(
            world.session,
            SYSTEM,
            receipt.id,
            [receipts.AllocationRequest(unmapped.id, D("50"))],
            created_by=None,
        )
    world.session.rollback()


def test_unmapped_bucket_is_attributed_after_binding(world):
    owner, account, provider = setup_fleet(world, {"999": {1: "50"}}, machines=())
    run_import(world, provider, account, 1, 1)
    bucket = world.session.execute(select(EarningBucket)).scalar_one()
    with pytest.raises(Conflict):
        earnings.remap_bucket(world.session, SYSTEM, bucket.id, created_by=None)
    world.session.rollback()

    machine, _ = world.paired_machine(owner, "late")
    world.bind(account, "999", machine)
    earnings.remap_bucket(world.session, SYSTEM, bucket.id, created_by=None)
    world.commit()
    world.session.refresh(bucket)
    assert bucket.status == "mapped" and bucket.owner_id == owner.id
    assert owner_balances(world.session, owner.id).accrued == D("45")
    assert open_exceptions(world, "unmapped_machine") == []
    assert verify_ledger(world.session)["ok"]


def test_days_before_the_binding_date_stay_unattributed(world):
    owner = world.owner()
    world.fee()
    provider = world.provider(dataset({"101": {}}, {"101": {5: "10", 1: "10"}}))
    account = world.account(provider)
    machine, _ = world.paired_machine(owner)
    world.bind(account, "101", machine, days_ago=2)  # attributable from two days ago
    run_import(world, provider, account, 5, 1)
    status = dict(world.session.execute(select(EarningBucket.day, EarningBucket.status)).all())
    assert status == {world.day(5): "unmapped", world.day(1): "mapped"}


def _report(world, rows, **kw):
    return EarningsReport(
        rows=rows,
        period_start=kw.pop("start", world.day(2)),
        period_end=kw.pop("end", world.day(1)),
        basis=kw.pop("basis", "net_of_provider_fee"),
        buckets_verified=kw.pop("buckets_verified", True),
        raw_body=b"{}",
        fetched_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        is_synthetic=True,
        **kw,
    )


def test_unknown_currency_is_not_posted(world):
    owner, account, provider = setup_fleet(world, {})
    report = _report(
        world,
        [
            EarningsRow("101", world.day(1), D("10"), "USD"),
            EarningsRow("101", world.day(2), D("10"), "EUR"),
        ],
    )
    imp = earnings.import_earnings(world.session, SYSTEM, account, report)
    world.commit()
    assert imp.stats["skipped"] == 1 and count(world, EarningBucket) == 1
    assert [e.kind for e in open_exceptions(world)] == ["unknown_currency"]
    assert owner_balances(world.session, owner.id).accrued == D("9")


def test_mismatched_totals_post_nothing(world):
    owner, account, provider = setup_fleet(world, {"101": {1: "10"}})
    provider.declared_total_override["101"] = D("12")
    imp = run_import(world, provider, account, 1, 1)
    assert imp.status == "exception"
    assert count(world, EarningBucket) == 0 and count(world, JournalEntry) == 0
    assert [e.kind for e in open_exceptions(world)] == ["total_mismatch"]


def test_unverified_provider_semantics_are_held_not_posted(world):
    owner, account, provider = setup_fleet(world, {})
    for kw in ({"basis": "unverified"}, {"buckets_verified": False}):
        report = _report(world, [EarningsRow("101", world.day(1), D("10"), "USD")], **kw)
        imp = earnings.import_earnings(world.session, SYSTEM, account, report)
        world.commit()
        assert imp.status == "held_unverified"
    assert count(world, EarningBucket) == 0 and count(world, JournalEntry) == 0
    assert [e.kind for e in open_exceptions(world)] == ["unverified_semantics"]


def test_rows_outside_the_period_or_duplicated_hold_the_report(world):
    owner, account, provider = setup_fleet(world, {})
    outside = _report(world, [EarningsRow("101", world.day(9), D("10"), "USD")])
    duplicated = _report(
        world,
        [EarningsRow("101", world.day(1), D("1"), "USD"), EarningsRow("101", world.day(1), D("2"), "USD")],
    )
    for report in (outside, duplicated):
        assert earnings.import_earnings(world.session, SYSTEM, account, report).status == "exception"
        world.commit()
    assert count(world, JournalEntry) == 0


def test_only_closed_utc_days_can_be_imported(world):
    owner, account, provider = setup_fleet(world, {})
    report = _report(world, [], start=world.day(1), end=world.day(0))
    with pytest.raises(InvalidRequest):
        earnings.import_earnings(world.session, SYSTEM, account, report)


# --- reconciliation --------------------------------------------------------


def test_report_is_not_cash_and_remainder_stays_in_suspense(world):
    owner, account, provider = setup_fleet(world, {"101": {2: "30", 1: "30"}})
    run_import(world, provider, account, 2, 1)
    receipt, created = receipts.record_receipt(
        world.session,
        SYSTEM,
        account,
        reference="BANK-7",
        received_on=world.today,
        amount=D("70"),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="statement",
        created_by=None,
    )
    world.commit()
    assert created
    # Recorded but unallocated: still nothing available.
    assert owner_balances(world.session, owner.id).available == D("0")
    assert [e.kind for e in open_exceptions(world)] == ["receipt_remainder"]

    receipts.allocate_period(world.session, SYSTEM, receipt.id, world.day(2), world.day(1), created_by=None)
    world.commit()
    assert owner_balances(world.session, owner.id).available == D("54")
    # 10 is unexplained: it stays in suspense with an open exception.
    suspense = get_account(world.session, "receipts_unallocated", provider_account_id=account.id)
    assert balance_of(world.session, suspense) == D("10")
    remainder = open_exceptions(world, "receipt_remainder")
    assert len(remainder) == 1 and remainder[0].details["unallocated"] == "10.00000000"
    assert verify_ledger(world.session)["ok"]


def test_recording_the_same_receipt_twice_is_idempotent(world):
    owner, account, provider = setup_fleet(world, {})
    args = dict(
        reference="BANK-1",
        received_on=world.today,
        amount=D("50"),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="e",
        created_by=None,
    )
    first, created1 = receipts.record_receipt(world.session, SYSTEM, account, **args)
    second, created2 = receipts.record_receipt(world.session, SYSTEM, account, **args)
    world.commit()
    assert created1 and not created2 and first.id == second.id
    assert balance_of(world.session, get_account(world.session, "cash_clearing")) == D("50")
    with pytest.raises(Conflict):
        receipts.record_receipt(world.session, SYSTEM, account, **{**args, "amount": D("51")})


def test_receipt_needs_evidence_and_usd(world):
    owner, account, provider = setup_fleet(world, {})
    base = dict(
        reference="R",
        received_on=world.today,
        amount=D("5"),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="e",
        created_by=None,
    )
    for bad in (
        {"evidence_source": "bank_statement", "evidence_note": " "},
        {"currency": "EUR"},
        {"amount": D("0")},
        {"reference": ""},
    ):
        with pytest.raises(InvalidRequest):
            receipts.record_receipt(world.session, SYSTEM, account, **{**base, **bad})


def test_allocation_cannot_exceed_reported_or_receipt(world):
    owner, account, provider = setup_fleet(world, {"101": {1: "30"}})
    run_import(world, provider, account, 1, 1)
    bucket = world.session.execute(select(EarningBucket)).scalar_one()
    receipt, _ = receipts.record_receipt(
        world.session,
        SYSTEM,
        account,
        reference="R",
        received_on=world.today,
        amount=D("20"),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="e",
        created_by=None,
    )
    world.commit()
    for amount in ("31", "25"):  # more than reported; more than the receipt
        with pytest.raises(Conflict):
            receipts.allocate(
                world.session,
                SYSTEM,
                receipt.id,
                [receipts.AllocationRequest(bucket.id, D(amount))],
                created_by=None,
            )
        world.session.rollback()
    # Period allocation refuses to spread a short receipt by a rule.
    with pytest.raises(Conflict):
        receipts.allocate_period(
            world.session, SYSTEM, receipt.id, world.day(1), world.day(1), created_by=None
        )
    world.session.rollback()
    assert owner_balances(world.session, owner.id).available == D("0")


def test_bucket_with_unexplained_adjustment_cannot_be_reconciled(world):
    owner, account, provider = setup_fleet(world, {"101": {1: "30"}})
    run_import(world, provider, account, 1, 1)
    provider.dataset["earnings"]["101"][world.day(1).isoformat()] = {"gpu_earn": "35"}
    run_import(world, provider, account, 1, 1)
    receipt, _ = receipts.record_receipt(
        world.session,
        SYSTEM,
        account,
        reference="R",
        received_on=world.today,
        amount=D("35"),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="e",
        created_by=None,
    )
    world.commit()
    with pytest.raises(Conflict, match="unexplained provider adjustment"):
        receipts.allocate_period(
            world.session, SYSTEM, receipt.id, world.day(1), world.day(1), created_by=None
        )
    world.session.rollback()


# --- ledger invariants enforced by the database ----------------------------


def test_journal_is_append_only(world):
    owner, account, provider = setup_fleet(world, {"101": {1: "10"}})
    run_import(world, provider, account, 1, 1)
    for statement in (
        "UPDATE journal_lines SET amount = amount * 2",
        "DELETE FROM journal_lines",
        "UPDATE journal_entries SET description = 'x'",
        "DELETE FROM journal_entries",
        "TRUNCATE journal_lines, journal_entries CASCADE",
        "UPDATE audit_log SET action = 'x'",
        "DELETE FROM audit_log",
    ):
        with pytest.raises(DBAPIError, match="append-only"):
            world.session.execute(text(statement))
        world.session.rollback()


def test_balance_cache_cannot_be_written_directly(world):
    owner, account, provider = setup_fleet(world, {"101": {1: "10"}})
    run_import(world, provider, account, 1, 1)
    with pytest.raises(DBAPIError, match="journal trigger only"):
        world.session.execute(text("UPDATE ledger_balances SET balance = 0"))
    world.session.rollback()


def test_unbalanced_entry_is_rejected_at_commit(world):
    a = get_account(world.session, "cash_clearing")
    b = get_account(world.session, "fee_earned")
    world.commit()
    # The service refuses first...
    with pytest.raises(InvalidRequest, match="does not balance"):
        post_entry(
            world.session,
            entry_type="x",
            idempotency_key="k1",
            lines=[Line(a, D("5")), Line(b, D("-4"))],
            occurred_on=world.today,
        )
    world.session.rollback()
    # ...and so does the database if the service is bypassed.
    entry = JournalEntry(entry_type="x", idempotency_key="k2", occurred_on=world.today)
    world.session.add(entry)
    world.session.flush()
    world.session.add_all(
        [
            JournalLine(entry_id=entry.id, account_id=a.id, amount=D("5")),
            JournalLine(entry_id=entry.id, account_id=b.id, amount=D("-4")),
        ]
    )
    with pytest.raises(DBAPIError, match="does not balance"):
        world.session.commit()
    world.session.rollback()
    assert count(world, JournalEntry) == 0


def test_protected_accounts_cannot_be_overdrawn(world):
    owner = world.owner()
    available = get_account(world.session, "owner_available", owner_id=owner.id)
    reserved = get_account(world.session, "owner_reserved", owner_id=owner.id)
    world.commit()
    with pytest.raises(InsufficientFunds):
        post_entry(
            world.session,
            entry_type="payout_reserve",
            idempotency_key="r1",
            lines=[Line(available, D("1")), Line(reserved, D("-1"))],
            occurred_on=world.today,
        )
    world.commit()
    assert count(world, JournalEntry) == 0 and count(world, LedgerBalance) == 0


def test_posting_is_idempotent_on_its_key(world):
    owner = world.owner()
    a = get_account(world.session, "provider_receivable", provider_account_id=None)
    b = get_account(world.session, "owner_accrued", owner_id=owner.id)
    first, created1 = post_entry(
        world.session,
        entry_type="t",
        idempotency_key="same",
        lines=[Line(a, D("3")), Line(b, D("-3"))],
        occurred_on=world.today,
    )
    second, created2 = post_entry(
        world.session,
        entry_type="t",
        idempotency_key="same",
        lines=[Line(a, D("3")), Line(b, D("-3"))],
        occurred_on=world.today,
    )
    world.commit()
    assert created1 and not created2 and first.id == second.id
    assert owner_balances(world.session, owner.id).accrued == D("3")


def test_money_never_passes_through_binary_floats(world):
    with pytest.raises(InvalidRequest, match="floating point"):
        to_decimal(0.1)
    with pytest.raises(InvalidRequest):
        to_decimal("0.123456789")  # more than 8 decimals
    with pytest.raises(InvalidRequest):
        to_decimal("NaN")
    assert to_decimal("0.1") + to_decimal("0.2") == D("0.3")


def test_statement_separates_reported_from_reconciled(world):
    owner, account, provider = setup_fleet(world, {"101": {2: "50", 1: "50"}})
    run_import(world, provider, account, 2, 1)
    receipt, _ = receipts.record_receipt(
        world.session,
        SYSTEM,
        account,
        reference="R",
        received_on=world.today,
        amount=D("50"),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="e",
        created_by=None,
    )
    receipts.allocate_period(world.session, SYSTEM, receipt.id, world.day(2), world.day(2), created_by=None)
    world.commit()
    s = owner_statement(world.session, owner.id, world.day(2) - timedelta(days=5), world.day(1))
    assert s["reported"]["provider_reported_earnings"] == "100.00000000"
    assert s["reconciled"]["eligible_base"] == "50.00000000"
    assert s["outstanding_not_received"]["owner_share"] == "45.00000000"
    assert s["balances_now"]["payable"] == "45.00"
