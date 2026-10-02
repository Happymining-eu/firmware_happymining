"""Owner settlements: idempotency, concurrency, evidence, unknown outcomes."""

from __future__ import annotations

import threading
from decimal import Decimal

import pytest
from helpers import SYSTEM, dataset, live_settings, make_settings
from sqlalchemy import func, select, text
from test_earnings_ledger import count, run_import, setup_fleet

from happymining.db import session_factory
from happymining.errors import Conflict, FeatureDisabled, Forbidden, InsufficientFunds, InvalidRequest
from happymining.models import JournalEntry, OwnerBeneficiary, PayoutBatch, PayoutItem
from happymining.payout_providers.mock import MockPayoutProvider
from happymining.services import payouts, receipts
from happymining.services.ledger import balance_of, get_account, owner_balances, verify_ledger

D = Decimal
IBAN = "FR7630006000011234567890189"


def funded(world, amount="100", owner_name="Alice", machine="101"):
    """An owner with ``amount`` reported, received and reconciled, and a beneficiary on file."""
    owner, account, provider = setup_fleet(world, {machine: {1: amount}})
    run_import(world, provider, account, 1, 1)
    receipt, _ = receipts.record_receipt(
        world.session,
        SYSTEM,
        account,
        reference=f"BANK-{machine}",
        received_on=world.today,
        amount=D(amount),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="statement",
        created_by=None,
    )
    receipts.allocate_period(world.session, SYSTEM, receipt.id, world.day(1), world.day(1), created_by=None)
    admin = world.user("admin")
    payouts.set_beneficiary(
        world.session,
        world.settings,
        SYSTEM,
        owner.id,
        {"account_holder": owner_name, "iban": IBAN},
        admin.id,
    )
    world.commit()
    return owner, account, admin


def prepare(world, admin, key="batch-key-0001"):
    batch, created = payouts.prepare_batch(
        world.session, world.settings, SYSTEM, idempotency_key=key, created_by=admin.id
    )
    world.commit()
    return batch, created


def test_full_settlement_cycle(world):
    owner, account, admin = funded(world)  # 100 reported -> 90 available
    batch, created = prepare(world, admin)
    assert created and [(i.amount, i.status) for i in batch.items] == [(D("90.00"), "draft")]
    # A draft reserves nothing.
    assert owner_balances(world.session, owner.id).available == D("90")

    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    world.commit()
    b = owner_balances(world.session, owner.id)
    assert (b.available, b.reserved, b.in_transit) == (D("0"), D("90"), D("0"))

    payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id)
    world.commit()
    b = owner_balances(world.session, owner.id)
    assert (b.available, b.reserved, b.in_transit) == (D("0"), D("0"), D("90"))

    item = world.session.execute(select(PayoutItem)).scalar_one()
    cash = get_account(world.session, "cash_clearing")
    assert balance_of(world.session, cash) == D("100")  # submitted is not paid
    payouts.confirm_item(world.session, SYSTEM, item.id, reference="BANK-TX-991", user_id=admin.id)
    world.commit()

    b = owner_balances(world.session, owner.id)
    assert (b.available, b.reserved, b.in_transit) == (D("0"), D("0"), D("0"))
    assert balance_of(world.session, cash) == D("10")  # the fee stays
    world.session.refresh(batch)
    assert batch.status == "closed" and item.status == "confirmed_paid"
    assert verify_ledger(world.session)["ok"]


def test_same_idempotency_key_returns_the_same_batch(world):
    owner, account, admin = funded(world)
    first, created1 = prepare(world, admin, "same-key-123")
    second, created2 = prepare(world, admin, "same-key-123")
    assert created1 and not created2 and first.id == second.id
    assert count(world, PayoutBatch) == 1 and count(world, PayoutItem) == 1


def test_repeating_approval_and_submission_changes_nothing(world):
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    results = [
        payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)[1]
        for _ in range(3)
    ]
    world.commit()
    assert results == [True, False, False]
    results = [
        payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id)[1]
        for _ in range(3)
    ]
    world.commit()
    assert results == [True, False, False]
    b = owner_balances(world.session, owner.id)
    assert (b.available, b.reserved, b.in_transit) == (D("0"), D("0"), D("90"))
    types = [e for (e,) in world.session.execute(select(JournalEntry.entry_type)).all()]
    assert types.count("payout_reserve") == 1 and types.count("payout_submit") == 1
    assert verify_ledger(world.session)["ok"]


def test_two_batches_cannot_reserve_the_same_money(world):
    owner, account, admin = funded(world)
    first, _ = prepare(world, admin, "batch-one-0001")
    second, _ = prepare(world, admin, "batch-two-0002")  # both drafts see the same 90
    payouts.approve_batch(world.session, world.settings, SYSTEM, first.id, approver_id=admin.id)
    world.commit()
    with pytest.raises(InsufficientFunds):
        payouts.approve_batch(world.session, world.settings, SYSTEM, second.id, approver_id=admin.id)
    world.session.rollback()
    assert owner_balances(world.session, owner.id).reserved == D("90")


def test_concurrent_approvals_reserve_once(world):
    """Two batches over the same funds, approved at the same instant from two connections."""
    owner, account, admin = funded(world)
    first, _ = prepare(world, admin, "race-one-0001")
    second, _ = prepare(world, admin, "race-two-0002")
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def approve(batch_id):
        session = session_factory()()
        try:
            barrier.wait(timeout=10)
            payouts.approve_batch(session, world.settings, SYSTEM, batch_id, approver_id=admin.id)
            session.commit()
            outcomes.append("approved")
        except InsufficientFunds:
            session.rollback()
            outcomes.append("refused")
        finally:
            session.close()

    threads = [threading.Thread(target=approve, args=(b.id,)) for b in (first, second)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert sorted(outcomes) == ["approved", "refused"]
    b = owner_balances(world.session, owner.id)
    assert (b.available, b.reserved) == (D("0"), D("90"))
    assert verify_ledger(world.session)["ok"]


def test_concurrent_approval_of_one_batch_reserves_once(world):
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    barrier = threading.Barrier(4)
    changed: list[bool] = []

    def approve():
        session = session_factory()()
        try:
            barrier.wait(timeout=10)
            _, did = payouts.approve_batch(session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
            session.commit()
            changed.append(did)
        finally:
            session.close()

    threads = [threading.Thread(target=approve) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert sorted(changed) == [False, False, False, True]
    assert owner_balances(world.session, owner.id).reserved == D("90")
    reserve_entries = world.session.execute(
        select(func.count()).select_from(JournalEntry).where(JournalEntry.entry_type == "payout_reserve")
    ).scalar_one()
    assert reserve_entries == 1


def test_concurrent_identical_prepare_requests_create_one_batch(world):
    owner, account, admin = funded(world)
    barrier = threading.Barrier(4)
    ids: list = []

    def go():
        session = session_factory()()
        try:
            barrier.wait(timeout=10)
            batch, _ = payouts.prepare_batch(
                session, world.settings, SYSTEM, idempotency_key="race-prepare-1", created_by=admin.id
            )
            session.commit()
            ids.append(batch.id)
        finally:
            session.close()

    threads = [threading.Thread(target=go) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(ids) == 4 and len(set(ids)) == 1
    assert count(world, PayoutBatch) == 1 and count(world, PayoutItem) == 1


def test_repeated_exports_are_identical_and_move_no_money(world):
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    with pytest.raises(Conflict):  # a draft cannot be exported
        payouts.export_batch(world.session, world.settings, SYSTEM, batch.id)
    world.session.rollback()
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    world.commit()
    entries = count(world, JournalEntry)
    exports = [payouts.export_batch(world.session, world.settings, SYSTEM, batch.id) for _ in range(3)]
    world.commit()
    assert len({digest for _, digest in exports}) == 1 and len({body for body, _ in exports}) == 1
    body = exports[0][0].decode()
    assert IBAN in body and "90.00" in body and "Alice" in body
    assert count(world, JournalEntry) == entries
    world.session.refresh(batch)
    assert batch.export_count == 3


def test_unknown_outcome_keeps_funds_locked_until_evidence(world):
    """A timeout is not a failure. The money must not become payable again."""
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    provider = MockPayoutProvider(script={"*": "timeout"})
    payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id, provider=provider)
    world.commit()

    item = world.session.execute(select(PayoutItem)).scalar_one()
    assert item.status == "uncertain"
    b = owner_balances(world.session, owner.id)
    assert (b.available, b.in_transit) == (D("0"), D("90"))

    # Submitting again does not call the provider a second time.
    payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id, provider=provider)
    world.commit()
    assert len(provider.calls) == 1

    # Nothing is available, so a second payout cannot be prepared.
    with pytest.raises(InsufficientFunds):
        prepare(world, admin, "retry-attempt-01")
    world.session.rollback()

    # Only evidence settles it. Here: the bank confirms it did go through.
    with pytest.raises(InvalidRequest):
        payouts.confirm_item(world.session, SYSTEM, item.id, reference="  ", user_id=admin.id)
    world.session.rollback()
    payouts.confirm_item(world.session, SYSTEM, item.id, reference="BANK-OK-1", user_id=admin.id)
    world.commit()
    assert owner_balances(world.session, owner.id).in_transit == D("0")
    assert balance_of(world.session, get_account(world.session, "cash_clearing")) == D("10")
    assert verify_ledger(world.session)["ok"]


def test_evidenced_failure_releases_funds_exactly_once(world):
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    payouts.submit_batch(
        world.session,
        world.settings,
        SYSTEM,
        batch.id,
        user_id=admin.id,
        provider=MockPayoutProvider(script={"*": "timeout"}),
    )
    world.commit()
    item = world.session.execute(select(PayoutItem)).scalar_one()
    results = [
        payouts.fail_item(world.session, SYSTEM, item.id, reference="BANK-REJ-5", user_id=admin.id)[1]
        for _ in range(2)
    ]
    world.commit()
    assert results == [True, False]
    b = owner_balances(world.session, owner.id)
    assert (b.available, b.in_transit) == (D("90"), D("0"))
    # A failed payout cannot be confirmed afterwards.
    with pytest.raises(Conflict):
        payouts.confirm_item(world.session, SYSTEM, item.id, reference="X", user_id=admin.id)
    world.session.rollback()
    # The money can go into a new batch now.
    again, created = prepare(world, admin, "second-attempt-1")
    assert created and again.items[0].amount == D("90.00")
    assert verify_ledger(world.session)["ok"]


def test_definitive_provider_rejection_releases_the_reserve(world):
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    payouts.submit_batch(
        world.session,
        world.settings,
        SYSTEM,
        batch.id,
        user_id=admin.id,
        provider=MockPayoutProvider(script={"*": "failed"}),
    )
    world.commit()
    b = owner_balances(world.session, owner.id)
    assert (b.available, b.reserved, b.in_transit) == (D("90"), D("0"), D("0"))


def test_confirming_twice_pays_once(world):
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id)
    world.commit()
    item = world.session.execute(select(PayoutItem)).scalar_one()
    results = [
        payouts.confirm_item(world.session, SYSTEM, item.id, reference="TX-1", user_id=admin.id)[1]
        for _ in range(3)
    ]
    world.commit()
    assert results == [True, False, False]
    assert balance_of(world.session, get_account(world.session, "cash_clearing")) == D("10")
    with pytest.raises(Conflict):  # a different reference for an already-confirmed payout is suspicious
        payouts.confirm_item(world.session, SYSTEM, item.id, reference="TX-OTHER", user_id=admin.id)
    world.session.rollback()


def test_bank_return_after_confirmation(world):
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id)
    item = world.session.execute(select(PayoutItem)).scalar_one()
    payouts.confirm_item(world.session, SYSTEM, item.id, reference="TX-1", user_id=admin.id)
    payouts.reverse_item(world.session, SYSTEM, item.id, reference="RETURN-1", user_id=admin.id)
    world.commit()
    assert owner_balances(world.session, owner.id).available == D("90")
    assert balance_of(world.session, get_account(world.session, "cash_clearing")) == D("100")
    assert verify_ledger(world.session)["ok"]


def test_cancelling_an_approved_batch_releases_the_reserve(world):
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    payouts.cancel_batch(world.session, SYSTEM, batch.id, user_id=admin.id)
    world.commit()
    b = owner_balances(world.session, owner.id)
    assert (b.available, b.reserved) == (D("90"), D("0"))
    # A cancelled batch can no longer be submitted.
    with pytest.raises(Conflict):
        payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id)
    world.session.rollback()


def test_reported_but_unreceived_earnings_cannot_be_paid(world):
    owner, account, provider = setup_fleet(world, {"101": {1: "500"}})
    run_import(world, provider, account, 1, 1)
    admin = world.user("admin")
    payouts.set_beneficiary(
        world.session, world.settings, SYSTEM, owner.id, {"account_holder": "A", "iban": IBAN}, admin.id
    )
    world.commit()
    assert owner_balances(world.session, owner.id).accrued == D("450")
    with pytest.raises(InsufficientFunds):
        prepare(world, admin)
    world.session.rollback()


def test_approval_fails_if_funds_went_away_after_the_draft(world):
    owner, account, admin = funded(world)
    stale, _ = prepare(world, admin, "stale-draft-001")
    fresh, _ = prepare(world, admin, "fresh-draft-001")
    payouts.approve_batch(world.session, world.settings, SYSTEM, fresh.id, approver_id=admin.id)
    payouts.submit_batch(world.session, world.settings, SYSTEM, fresh.id, user_id=admin.id)
    item = world.session.execute(select(PayoutItem).where(PayoutItem.batch_id == fresh.id)).scalar_one()
    payouts.confirm_item(world.session, SYSTEM, item.id, reference="TX", user_id=admin.id)
    world.commit()
    with pytest.raises(InsufficientFunds):
        payouts.approve_batch(world.session, world.settings, SYSTEM, stale.id, approver_id=admin.id)
    world.session.rollback()
    assert verify_ledger(world.session)["ok"]


def test_settlement_rounds_down_to_cents_and_carries_the_rest(world):
    # 33.37777777 reported: fee 3.33777778 (half-even at 8 dp), owner share 30.03999999.
    owner, account, admin = funded(world, amount="33.37777777")
    assert owner_balances(world.session, owner.id).available == D("30.03999999")
    batch, _ = prepare(world, admin)
    assert batch.items[0].amount == D("30.03")  # rounded down, never up
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    world.commit()
    # The sub-cent remainder is not lost; it waits for the next settlement.
    assert owner_balances(world.session, owner.id).available == D("0.00999999")
    assert verify_ledger(world.session)["ok"]


def test_missing_beneficiary_blocks_the_whole_approval(world):
    owner, account, admin = funded(world)
    world.session.execute(text("DELETE FROM owner_beneficiaries"))
    world.commit()
    batch, _ = prepare(world, admin)
    with pytest.raises(Conflict, match="beneficiary"):
        payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    world.session.rollback()
    assert owner_balances(world.session, owner.id).reserved == D("0")


def test_distinct_approver_rule(world):
    owner, account, admin = funded(world)
    strict = make_settings(payout_require_distinct_approver=True)
    batch, _ = prepare(world, admin)
    with pytest.raises(Forbidden):
        payouts.approve_batch(world.session, strict, SYSTEM, batch.id, approver_id=admin.id)
    world.session.rollback()
    other = world.user("admin")
    payouts.approve_batch(world.session, strict, SYSTEM, batch.id, approver_id=other.id)
    world.commit()
    assert owner_balances(world.session, owner.id).reserved == D("90")


def test_payouts_are_disabled_by_default_and_fail_explicitly(world):
    owner, account, admin = funded(world)
    off = make_settings(payouts_enabled=False)
    with pytest.raises(FeatureDisabled):
        payouts.prepare_batch(
            world.session, off, SYSTEM, idempotency_key="disabled-key-1", created_by=admin.id
        )
    assert Settings_default_payouts_enabled() is False


def Settings_default_payouts_enabled() -> bool:
    from happymining.config import Settings

    return Settings.model_fields["payouts_enabled"].default


def test_mock_payout_provider_is_refused_in_live(world):
    live = live_settings(payouts_enabled=True)
    assert live.payout_provider == "manual_export"
    assert payouts.get_payout_provider(live).name == "manual_export"
    bad = live.model_copy(update={"payout_provider": "mock"})
    assert any("mock payout" in p for p in bad.problems())
    with pytest.raises(FeatureDisabled):
        payouts.get_payout_provider(bad)


def test_beneficiary_details_are_encrypted_at_rest(world):
    owner, account, admin = funded(world)
    row = world.session.get(OwnerBeneficiary, owner.id)
    assert IBAN not in row.details_enc and "Alice" not in row.details_enc
    assert row.masked_hint == "FR** **** 0189"
    raw = world.session.execute(text("SELECT details_enc FROM owner_beneficiaries")).scalar_one()
    assert IBAN not in raw


def test_evidence_import_is_all_or_nothing(world):
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    payouts.submit_batch(world.session, world.settings, SYSTEM, batch.id, user_id=admin.id)
    world.commit()
    item = world.session.execute(select(PayoutItem)).scalar_one()
    rows = [
        {"item_id": str(item.id), "outcome": "paid", "reference": "TX-1", "note": ""},
        {
            "item_id": "00000000-0000-0000-0000-000000000000",
            "outcome": "paid",
            "reference": "TX-2",
            "note": "",
        },
    ]
    with pytest.raises(InvalidRequest):
        payouts.import_confirmations(world.session, SYSTEM, batch.id, rows, user_id=admin.id)
    world.session.rollback()
    world.session.refresh(item)
    assert item.status == "submitted"
    counts = payouts.import_confirmations(world.session, SYSTEM, batch.id, rows[:1], user_id=admin.id)
    world.commit()
    assert counts == {"paid": 1, "failed": 0, "unchanged": 0}


def test_dataset_helper_is_synthetic():
    assert dataset({"1": {}}, {})["account_id"] == "TEST-SYNTHETIC"
