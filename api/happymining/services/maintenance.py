"""Rental protection: the gate every disruptive action has to pass.

A disruptive action is anything that can interrupt a renter: restarting the
host daemon, rebooting, benchmarking, changing a hardware profile.

The gate allows such an action only when all of this is established from the
provider, freshly, at request time and again at the moment of delivery:

1. the machine is bound to a provider machine;
2. new rentals cannot start: the machine is verified **unlisted**;
3. there are no active contracts;
4. there are no stopped instances (a stopped instance is still a rental: the
   customer keeps the disk and can restart it);
5. there is no stored customer data.

Anything unknown is treated as unsafe. In particular:

- Zero GPU utilisation is not evidence of anything and is never consulted.
- Unlisting does not end existing rentals, so "unlisted" alone is not enough.
- If the provider cannot be reached, or does not expose the state, the action
  is blocked and has to be handled by an operator.

With the real Vast adapter the rental state is currently always "unknown":
the documented API does not expose it (docs/integration-evidence.md, B6). So
in LIVE mode every disruptive action is blocked by this gate today. That is
the intended behaviour, not a bug.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Machine, ProviderMachine, utcnow
from ..providers.base import Provider, ProviderError, RentalState

DISRUPTIVE_TYPES = frozenset({"restart_vast_daemon", "reboot", "run_benchmark", "apply_hardware_profile"})
# Taking a machine out of Vast hosting so that its owner's plugins may run
# (docs/appliance.md, section 2). It is not an operation sent to a device, so
# it is not in DISRUPTIVE_TYPES, which also classifies operation types; but it
# can hurt a renter just the same and passes the same gate.
LEAVE_VAST_MODE = "leave_vast_mode"
# Everything the gate decides on. Anything else is not disruptive.
GATED_ACTIONS = DISRUPTIVE_TYPES | {LEAVE_VAST_MODE}


@dataclass(frozen=True)
class SafetyDecision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    checks: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "reasons": self.reasons, "checks": self.checks}


def record_rental_state(db: Session, pm: ProviderMachine, state: RentalState) -> None:
    pm.rental_state = state.state
    pm.listed = state.listed
    pm.state_detail = state.detail[:500]
    pm.state_observed_at = state.observed_at
    db.flush()


def evaluate(
    db: Session, settings: Settings, provider: Provider | None, machine: Machine, op_type: str
) -> SafetyDecision:
    """Decide whether ``op_type`` may be sent to ``machine`` right now.

    ``op_type`` is an operation type or one of the other gated actions
    (``LEAVE_VAST_MODE``).
    """
    if op_type not in GATED_ACTIONS:
        return SafetyDecision(True, checks={"disruptive": False})

    checks: dict[str, Any] = {"disruptive": True, "evaluated_at": utcnow().isoformat()}
    reasons: list[str] = []

    if not settings.disruptive_operations_enabled:
        reasons.append("disruptive operations are disabled (HM_DISRUPTIVE_OPERATIONS_ENABLED=false)")

    # Queried explicitly: a relationship cached on the object could be stale.
    pm = db.execute(
        select(ProviderMachine).where(ProviderMachine.machine_id == machine.id)
    ).scalar_one_or_none()
    if pm is None:
        reasons.append(
            "machine is not bound to a provider machine, so its rental state cannot be established"
        )
        return SafetyDecision(False, reasons, checks)
    if provider is None:
        reasons.append("no provider adapter is available")
        return SafetyDecision(False, reasons, checks)

    try:
        state = provider.get_rental_state(pm.external_id)
    except ProviderError as exc:
        checks["provider_error"] = exc.code
        reasons.append(
            f"provider state could not be read ({exc.code}); an unknown state is treated as unsafe"
        )
        return SafetyDecision(False, reasons, checks)

    record_rental_state(db, pm, state)
    age = utcnow() - state.observed_at
    checks.update(
        {
            "rental_state": state.state,
            "listed": state.listed,
            "active_contracts": state.active_contracts,
            "stopped_instances": state.stopped_instances,
            "stored_data": state.stored_data,
            "observed_age_s": int(age.total_seconds()),
        }
    )
    if age > timedelta(seconds=settings.provider_state_max_age_s):
        reasons.append("provider state is stale")
    if state.listed is None:
        reasons.append(
            "cannot verify that the machine is unlisted, so a new rental could start at any moment"
        )
    elif state.listed:
        reasons.append("machine is still listed; stop new rentals first and verify the result")
    if state.state == "unknown":
        reasons.append("rental state is unknown: " + (state.detail or "the provider does not expose it"))
    elif state.state == "active_contracts":
        reasons.append("there are active rental contracts")
    elif state.state == "stopped_instances":
        reasons.append("there are stopped instances; a stopped instance is still a rental")
    elif state.state == "stored_data":
        reasons.append("customer data is stored on the machine")
    elif state.state == "idle" and (
        # Be explicit: every counter must be known and zero, not merely absent.
        state.active_contracts != 0 or state.stopped_instances != 0 or state.stored_data is not False
    ):
        reasons.append("provider reports idle but contract or storage counters are not all confirmed zero")

    return SafetyDecision(not reasons, reasons, checks)


def describe_blocked(decision: SafetyDecision) -> str:
    return "Blocked; requires operator handling: " + "; ".join(decision.reasons)
