"""Mock payout provider for DEMO and tests. Rejected at startup in LIVE mode.

It simulates the outcomes a network provider can produce, including the one
that matters most: a timeout, which is reported as UNCERTAIN.
"""

from __future__ import annotations

from .base import PayoutInstruction, SubmitOutcome, SubmitResult


class MockPayoutProvider:
    name = "mock"
    is_mock = True
    executes_transfer = True
    moves_real_money = False

    def __init__(self, script: dict[str, str] | None = None, default: str = "submitted"):
        # script maps an owner name (or "*") to: submitted | failed | timeout
        self.script = script or {}
        self.default = default
        self.calls: list[PayoutInstruction] = []

    def submit(self, instruction: PayoutInstruction) -> SubmitResult:
        self.calls.append(instruction)
        behaviour = self.script.get(instruction.owner_name, self.script.get("*", self.default))
        if behaviour == "failed":
            return SubmitResult(SubmitOutcome.FAILED, detail="SIMULATED definitive rejection")
        if behaviour == "timeout":
            return SubmitResult(SubmitOutcome.UNCERTAIN, detail="SIMULATED timeout; outcome unknown")
        return SubmitResult(
            SubmitOutcome.SUBMITTED, reference=f"SIMULATED-{instruction.item_id[:8]}", detail="SIMULATED"
        )
