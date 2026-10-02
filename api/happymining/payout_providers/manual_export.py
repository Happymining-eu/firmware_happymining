"""Manual settlement: the operator pays the exported batch at the bank.

``submit`` performs no transfer. It records that the operator attests the
instruction was handed to the bank; the result is ``SUBMITTED`` and remains so
until bank evidence confirms or rejects it.
"""

from __future__ import annotations

from .base import PayoutInstruction, SubmitOutcome, SubmitResult


class ManualExportProvider:
    name = "manual_export"
    is_mock = False
    executes_transfer = False
    moves_real_money = False  # the software itself transfers nothing

    def submit(self, instruction: PayoutInstruction) -> SubmitResult:
        return SubmitResult(SubmitOutcome.SUBMITTED, detail="operator-attested manual submission")
