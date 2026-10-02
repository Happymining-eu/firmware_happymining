"""Payout provider interface.

The pilot moves money by hand: an approved batch is exported, an operator pays
it through HappyMining's bank, and outcomes are confirmed with evidence. That
is ``ManualExportProvider`` and it never touches a network.

No live transfer integration (Stripe, Wise, bank API) exists in this codebase.
One can be added behind this interface later; it must stay disabled until
explicitly configured and separately authorised.

Outcome rule for any future network provider: a timeout or connection error
after a request was sent is ``UNCERTAIN``, never ``FAILED``. Funds stay in
transit until evidence settles the question.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import Protocol


class SubmitOutcome(StrEnum):
    SUBMITTED = "submitted"  # accepted for processing; not proof of payment
    FAILED = "failed"  # definitively not sent; safe to release funds
    UNCERTAIN = "uncertain"  # unknown; must be reconciled before any retry


@dataclass(frozen=True)
class SubmitResult:
    outcome: SubmitOutcome
    reference: str = ""
    detail: str = ""


@dataclass(frozen=True)
class PayoutInstruction:
    item_id: str
    idempotency_key: str
    owner_name: str
    amount: Decimal
    currency: str
    beneficiary: dict


class PayoutProvider(Protocol):
    name: str
    is_mock: bool
    # True when submit() itself moves (or simulates moving) money. False when
    # it only records an operator's statement that a file was taken to the bank.
    executes_transfer: bool
    moves_real_money: bool

    def submit(self, instruction: PayoutInstruction) -> SubmitResult: ...
