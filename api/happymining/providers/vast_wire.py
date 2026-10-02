"""Parsing and validation of Vast.ai response bodies.

Only fields confirmed in docs/integration-evidence.md are relied on. Money is
parsed straight from the JSON text into ``Decimal``; it never becomes a binary
float. Anything that does not match the confirmed shape raises
``ProviderMalformedResponse`` or is reported as an anomaly, which holds the
import instead of posting it.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from .base import EarningsRow, ProviderMachineInfo, ProviderMalformedResponse

EPOCH = date(1970, 1, 1)
# Confirmed field names (integration-evidence.md, C9).
EARNING_COMPONENTS = ("gpu_earn", "sto_earn", "bwu_earn", "bwd_earn")
# Personal data and secrets that must not be kept in stored snapshots.
PERSONAL_KEYS = frozenset(
    {
        "username",
        "email",
        "fullname",
        "address1",
        "address2",
        "city",
        "zip",
        "country",
        "taxinfo",
        "api_key",
        "ssh_key",
        "sid",
        "phone",
        "paypal_email",
        "wise_email",
    }
)
MAX_BODY_BYTES = 10 * 1024 * 1024


def epoch_day(day: date) -> int:
    return (day - EPOCH).days


def from_epoch_day(value: int) -> date:
    return EPOCH + timedelta(days=value)


def loads(body: bytes) -> Any:
    if len(body) > MAX_BODY_BYTES:
        raise ProviderMalformedResponse("response body exceeds the size limit")
    try:
        return json.loads(body, parse_float=Decimal, parse_int=int)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise ProviderMalformedResponse("response is not valid JSON") from exc


def scrub(value: Any) -> Any:
    """Remove personal data and secrets before a body is stored."""
    if isinstance(value, dict):
        return {k: ("[REMOVED]" if k in PERSONAL_KEYS else scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def dumps(value: Any) -> bytes:
    def default(obj: Any) -> Any:
        if isinstance(obj, Decimal):
            return str(obj)
        raise TypeError(type(obj).__name__)

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=default).encode()


MAX_AMOUNT = Decimal("1000000000000")  # far above anything real; guards the NUMERIC column
MAX_EPOCH_DAY = 200_000  # year 2517


def _money(value: Any, where: str) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise ProviderMalformedResponse(f"{where} is not a number")
    try:
        amount = Decimal(str(value)) if not isinstance(value, Decimal) else value
    except InvalidOperation as exc:
        raise ProviderMalformedResponse(f"{where} is not a number") from exc
    if not amount.is_finite():
        raise ProviderMalformedResponse(f"{where} is not finite")
    if abs(amount) >= MAX_AMOUNT:
        raise ProviderMalformedResponse(f"{where} is out of range")
    return amount


def parse_machines(body: bytes) -> list[ProviderMachineInfo]:
    """``GET /api/v0/machines`` -> ``{"machines": [...]}`` (docs and CLI)."""
    data = loads(body)
    if not isinstance(data, dict) or not isinstance(data.get("machines"), list):
        raise ProviderMalformedResponse("machines response has no 'machines' list")
    out: list[ProviderMachineInfo] = []
    seen: set[str] = set()
    for item in data["machines"]:
        if (
            not isinstance(item, dict)
            or isinstance(item.get("id"), bool)
            or not isinstance(item.get("id"), int)
        ):
            raise ProviderMalformedResponse("machine entry without an integer id")
        external_id = str(item["id"])
        if external_id in seen:
            raise ProviderMalformedResponse(f"machine id {external_id} listed twice")
        seen.add(external_id)
        num_gpus = item.get("num_gpus")
        out.append(
            ProviderMachineInfo(
                external_id=external_id,
                hostname=str(item.get("hostname") or "")[:200],
                gpu_name=str(item.get("gpu_name") or "")[:200],
                num_gpus=num_gpus if isinstance(num_gpus, int) and not isinstance(num_gpus, bool) else None,
                raw=json.loads(dumps(scrub(item))),
            )
        )
    return out


def parse_earnings(
    body: bytes, machine_id: str, start: date, end: date, currency: str
) -> tuple[list[EarningsRow], Decimal | None, list[str]]:
    """Parse one machine's earnings response.

    Returns (rows, provider total for the machine or None, anomalies). A row's
    amount is the sum of the four documented components for that day.
    """
    data = loads(body)
    if not isinstance(data, dict) or not isinstance(data.get("per_day"), list):
        raise ProviderMalformedResponse("earnings response has no 'per_day' list")
    anomalies: list[str] = []
    rows: list[EarningsRow] = []
    for entry in data["per_day"]:
        if not isinstance(entry, dict) or "day" not in entry:
            raise ProviderMalformedResponse("per_day entry without 'day'")
        raw_day = entry["day"]
        if isinstance(raw_day, bool) or not isinstance(raw_day, int | Decimal):
            raise ProviderMalformedResponse("per_day 'day' is not a number")
        if isinstance(raw_day, Decimal) and raw_day != raw_day.to_integral_value():
            anomalies.append(f"fractional day value {raw_day} for machine {machine_id}")
            continue
        if not (0 <= raw_day <= MAX_EPOCH_DAY):
            raise ProviderMalformedResponse("per_day 'day' is out of range")
        day = from_epoch_day(int(raw_day))
        if not (start <= day <= end):
            anomalies.append(f"day {raw_day} for machine {machine_id} is outside the requested range")
            continue
        absent = [name for name in EARNING_COMPONENTS if name not in entry]
        if absent:
            # A renamed or missing field must not be read as "earned nothing".
            anomalies.append(
                f"day {raw_day} for machine {machine_id} lacks the documented field(s) {', '.join(absent)}"
            )
            continue
        components = {name: _money(entry[name], f"per_day.{name}") for name in EARNING_COMPONENTS}
        rows.append(
            EarningsRow(
                external_machine_id=machine_id,
                day=day,
                amount=sum(components.values(), Decimal(0)),
                currency=currency,
                components={k: str(v) for k, v in components.items()},
            )
        )

    declared: Decimal | None = None
    per_machine = data.get("per_machine")
    if isinstance(per_machine, list):
        others = []
        for entry in per_machine:
            if not isinstance(entry, dict):
                raise ProviderMalformedResponse("per_machine entry is not an object")
            if str(entry.get("machine_id")) == machine_id:
                declared = sum(
                    (_money(entry.get(name, 0), f"per_machine.{name}") for name in EARNING_COMPONENTS),
                    Decimal(0),
                )
            else:
                others.append(str(entry.get("machine_id")))
        if others:
            # We asked for one machine; other machines in the answer mean the
            # filter did not apply and per_day may be an account-wide total.
            anomalies.append(
                f"response for machine {machine_id} also contains machines {', '.join(sorted(others)[:5])}; "
                "the machine filter may not have been applied"
            )
    elif per_machine is not None:
        raise ProviderMalformedResponse("'per_machine' is not a list")
    return rows, declared, anomalies
