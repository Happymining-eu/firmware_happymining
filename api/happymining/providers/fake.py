"""Fake provider for DEMO mode and tests. Everything it returns is SYNTHETIC.

It produces bodies in the same wire shape as Vast's confirmed responses and
runs them through the same parser as the real adapter, so the import path is
exercised end to end. It performs no network access and can never run in
LIVE mode (the startup guard rejects ``HM_PROVIDER=fake`` there).

Because the data is made up, its semantics are defined rather than verified:
amounts are declared net of the provider's fee and days are UTC epoch days.
That says nothing about the real provider.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from . import vast_wire
from .base import (
    EarningsReport,
    EarningsRow,
    MachineList,
    MutationResult,
    ProviderError,
    ProviderFeatureDisabled,
    ProviderHealth,
    ProviderMachineInfo,
    ProviderUnavailable,
    RentalState,
)

DEFAULT_FIXTURE = Path(__file__).resolve().parent.parent / "demo" / "fixtures" / "synthetic_provider.json"
IDLE = {"state": "idle", "listed": False, "active_contracts": 0, "stopped_instances": 0, "stored_data": False}


class FakeProvider:
    """In-memory synthetic provider.

    ``dataset``::

        {
          "account_id": "SYNTHETIC-ACCOUNT",
          "currency": "USD",
          "machines": [{"id": 900001, "hostname": "...", "gpu_name": "...", "num_gpus": 2,
                        "rental": {"state": "idle", "listed": false, ...}}],
          "earnings": {"900001": {"2026-09-30": {"gpu_earn": "12.5", "sto_earn": "0.4", ...}}}
        }
    """

    name = "fake"
    is_synthetic = True

    def __init__(self, dataset: dict[str, Any], *, mutations_enabled: bool = False):
        self.dataset = dataset
        self.mutations_enabled = mutations_enabled
        self.outage = False  # tests flip this to simulate a provider outage
        self.declared_total_override: dict[str, Decimal] = {}
        self.calls: list[str] = []

    @classmethod
    def from_fixture(cls, path: Path | None = None, *, today: date | None = None, **kw: Any) -> FakeProvider:
        """Load a fixture whose earnings use ``day_offset`` relative to today (UTC)."""
        today = today or datetime.now(UTC).date()
        raw = json.loads((path or DEFAULT_FIXTURE).read_text())
        if raw.get("synthetic") is not True:
            raise ValueError('fake provider fixtures must be marked "synthetic": true')
        earnings: dict[str, dict[str, dict[str, str]]] = {}
        for machine_id, entries in raw.get("earnings_by_offset", {}).items():
            earnings[machine_id] = {
                (today + timedelta(days=int(offset))).isoformat(): parts for offset, parts in entries.items()
            }
        return cls(
            {
                "account_id": raw["account_id"],
                "currency": raw.get("currency", "USD"),
                "machines": raw["machines"],
                "earnings": earnings,
            },
            **kw,
        )

    def _check(self, call: str) -> None:
        self.calls.append(call)
        if self.outage:
            raise ProviderUnavailable("SIMULATED provider outage")

    def _machine(self, external_machine_id: str) -> dict[str, Any]:
        for machine in self.dataset["machines"]:
            if str(machine["id"]) == external_machine_id:
                return machine
        raise ProviderError(f"unknown synthetic machine {external_machine_id}")

    def check_health(self) -> ProviderHealth:
        self._check("health")
        return ProviderHealth(
            ok=True,
            detail="SYNTHETIC provider (demo fixture)",
            account_id=str(self.dataset["account_id"]),
            checked_at=datetime.now(UTC),
        )

    def _rental(self, machine: dict[str, Any]) -> RentalState:
        r = {**IDLE, "listed": True, **(machine.get("rental") or {})}
        return RentalState(
            state=r["state"],
            listed=r.get("listed"),
            observed_at=datetime.now(UTC),
            detail="SYNTHETIC rental state",
            active_contracts=r.get("active_contracts"),
            stopped_instances=r.get("stopped_instances"),
            stored_data=r.get("stored_data"),
        )

    def list_machines(self) -> MachineList:
        self._check("list_machines")
        body = vast_wire.dumps(
            {
                "synthetic": True,
                "machines": [{k: v for k, v in m.items() if k != "rental"} for m in self.dataset["machines"]],
            }
        )
        parsed = vast_wire.parse_machines(body)
        by_id = {str(m["id"]): m for m in self.dataset["machines"]}
        machines = [
            ProviderMachineInfo(
                m.external_id, m.hostname, m.gpu_name, m.num_gpus, m.raw, self._rental(by_id[m.external_id])
            )
            for m in parsed
        ]
        return MachineList(machines=machines, raw_body=body, fetched_at=datetime.now(UTC))

    def get_rental_state(self, external_machine_id: str) -> RentalState:
        self._check("get_rental_state")
        return self._rental(self._machine(external_machine_id))

    def earnings_body(self, machine_id: str, start: date, end: date) -> bytes:
        """Build a Vast-shaped earnings response for one machine."""
        days = self.dataset.get("earnings", {}).get(machine_id, {})
        per_day = []
        totals = {name: Decimal(0) for name in vast_wire.EARNING_COMPONENTS}
        for iso, parts in sorted(days.items()):
            day = date.fromisoformat(iso)
            if not (start <= day <= end):
                continue
            entry: dict[str, Any] = {"day": vast_wire.epoch_day(day)}
            for name in vast_wire.EARNING_COMPONENTS:
                value = Decimal(str(parts.get(name, "0")))
                entry[name] = value
                totals[name] += value
            per_day.append(entry)
        per_machine_entry: dict[str, Any] = {"machine_id": int(machine_id), **totals}
        if machine_id in self.declared_total_override:
            per_machine_entry["gpu_earn"] = self.declared_total_override[machine_id]
            for name in vast_wire.EARNING_COMPONENTS[1:]:
                per_machine_entry[name] = Decimal(0)
        return vast_wire.dumps(
            {
                "synthetic": True,
                "summary": {
                    "total_gpu": totals["gpu_earn"],
                    "total_stor": totals["sto_earn"],
                    "total_bwu": totals["bwu_earn"],
                    "total_bwd": totals["bwd_earn"],
                },
                "current": {"balance": 0, "service_fee": 0, "total": 0, "credit": 0},
                "per_machine": [per_machine_entry] if per_day else [],
                "per_day": per_day,
            }
        )

    def fetch_earnings(self, external_machine_ids: list[str], start: date, end: date) -> EarningsReport:
        self._check("fetch_earnings")
        currency = self.dataset.get("currency", "USD")
        rows: list[EarningsRow] = []
        totals: dict[str, Decimal] = {}
        anomalies: list[str] = []
        bodies: dict[str, Any] = {}
        for machine_id in sorted(set(external_machine_ids)):
            body = self.earnings_body(machine_id, start, end)
            machine_rows, declared, machine_anomalies = vast_wire.parse_earnings(
                body, machine_id, start, end, currency
            )
            rows.extend(machine_rows)
            anomalies.extend(machine_anomalies)
            if declared is not None:
                totals[machine_id] = declared
            bodies[machine_id] = vast_wire.loads(body)
        return EarningsReport(
            rows=rows,
            period_start=start,
            period_end=end,
            basis="net_of_provider_fee",  # defined for synthetic data, not verified for Vast
            buckets_verified=True,
            raw_body=vast_wire.dumps({"provider": "fake", "synthetic": True, "by_machine": bodies}),
            fetched_at=datetime.now(UTC),
            declared_totals=totals,
            anomalies=anomalies,
            covered_machines=frozenset(external_machine_ids),
            is_synthetic=True,
        )

    def unlist_machine(self, external_machine_id: str) -> MutationResult:
        self._check("unlist_machine")
        if not self.mutations_enabled:
            raise ProviderFeatureDisabled(
                "provider mutations are disabled (HM_PROVIDER_MUTATIONS_ENABLED=false)"
            )
        machine = self._machine(external_machine_id)
        machine.setdefault("rental", dict(IDLE))["listed"] = False
        return MutationResult(ok=True, detail="SYNTHETIC unlist; no real machine was touched")
