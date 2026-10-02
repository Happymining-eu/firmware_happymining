"""Real Vast.ai host adapter. LIVE only, read-only by default.

Every endpoint used here is confirmed in docs/integration-evidence.md from
Vast's documentation and the official CLI source (vastai 1.8.2). Nothing is
invented. Where the documentation leaves a question open, the adapter says so
explicitly instead of guessing:

- Rental state (running, stopped, stored): not exposed by the documented API.
  ``get_rental_state`` always answers "unknown", which blocks disruptive
  maintenance.
- Earnings: whether amounts are net of Vast's fee, and the day unit and range
  boundaries, are not documented. Reports are returned with the basis from
  configuration (default "unverified"); unverified reports are held, not posted.
- Maintenance windows: docs and CLI disagree on the ``sdate`` format, so
  scheduling is not implemented.

Writes are never retried. A write whose outcome is unknown raises
``ProviderOutcomeUncertain`` and must be reconciled by an operator.
"""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

import httpx

from ..config import Settings
from . import vast_wire
from .base import (
    EarningsReport,
    EarningsRow,
    MachineList,
    MutationResult,
    ProviderAuthError,
    ProviderAuthorizationUnverified,
    ProviderError,
    ProviderFeatureDisabled,
    ProviderFeatureUnverified,
    ProviderHealth,
    ProviderMalformedResponse,
    ProviderNotConfigured,
    ProviderOutcomeUncertain,
    ProviderRateLimited,
    ProviderTimeout,
    ProviderUnavailable,
    RentalState,
)

log = logging.getLogger(__name__)

RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
MAX_READ_ATTEMPTS = 3
UNKNOWN_RENTAL_DETAIL = (
    "The documented Vast API does not expose running, stopped or stored instance counts "
    "(docs/integration-evidence.md, B6). Check the Vast console and `docker ps -a` on the host."
)


class VastProvider:
    name = "vast"
    is_synthetic = False

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._settings = settings
        self._sleep = sleep
        self._transport = transport
        self._client: httpx.Client | None = None

    # --- plumbing ----------------------------------------------------------

    def _ready(self) -> httpx.Client:
        settings = self._settings
        if not settings.vast_commercial_authorization_ref.strip():
            raise ProviderAuthorizationUnverified(
                "HM_VAST_COMMERCIAL_AUTHORIZATION_REF is empty: commercial authorization from Vast to "
                "operate third-party machines and use the API for it has not been recorded. "
                "Vast is not called."
            )
        if settings.vast_api_key is None or not settings.vast_api_key.get_secret_value().strip():
            raise ProviderNotConfigured("HM_VAST_API_KEY is not set")
        if self._client is None:
            self._client = httpx.Client(
                base_url=settings.vast_base_url.rstrip("/"),
                headers={
                    "Authorization": "Bearer " + settings.vast_api_key.get_secret_value().strip(),
                    "Accept": "application/json",
                    "User-Agent": "happymining-os/0.1",
                },
                timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0),
                follow_redirects=False,  # never forward the key to another host
                transport=self._transport,
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    @staticmethod
    def _raise_for(response: httpx.Response) -> None:
        status = response.status_code
        if status in (401, 403):
            raise ProviderAuthError(f"Vast rejected the API key or its permissions (HTTP {status})")
        if status == 404:
            # Vast answers 404 auth_error for an unknown key (evidence A4).
            raise ProviderAuthError("Vast answered 404; unknown key or resource")
        if status == 429:
            raise ProviderRateLimited("Vast rate limit reached (HTTP 429)")
        if status >= 500:
            raise ProviderUnavailable(f"Vast answered HTTP {status}")
        if status >= 400:
            raise ProviderError(f"Vast answered HTTP {status}")
        if 300 <= status < 400:
            raise ProviderMalformedResponse(f"unexpected redirect (HTTP {status})")

    def _get(self, path: str, params: dict[str, Any] | None = None) -> bytes:
        """Idempotent read with bounded retries and jittered backoff."""
        client = self._ready()
        last: ProviderError | None = None
        for attempt in range(MAX_READ_ATTEMPTS):
            if attempt:
                # Vast's 429 carries no Retry-After; its message hints at a
                # minimum interval of about 2 s (evidence A4). Back off above it.
                self._sleep(2.0 * (2 ** (attempt - 1)) + random.uniform(0, 1.0))  # noqa: S311 - jitter
            try:
                response = client.get(path, params=params)
            except httpx.TimeoutException:
                last = ProviderTimeout(f"timeout reading {path}")
                continue
            except httpx.HTTPError as exc:
                last = ProviderUnavailable(f"network error reading {path}: {type(exc).__name__}")
                continue
            if response.status_code in RETRYABLE_STATUS:
                last = (
                    ProviderRateLimited("Vast rate limit reached (HTTP 429)")
                    if response.status_code == 429
                    else ProviderUnavailable(f"Vast answered HTTP {response.status_code}")
                )
                continue
            self._raise_for(response)
            if len(response.content) > vast_wire.MAX_BODY_BYTES:
                raise ProviderMalformedResponse("response body exceeds the size limit")
            return response.content
        assert last is not None
        log.warning("vast read failed", extra={"path": path, "error": last.code})
        raise last

    # --- reads -------------------------------------------------------------

    def check_health(self) -> ProviderHealth:
        body = self._get("/api/v0/users/current")
        data = vast_wire.loads(body)
        if not isinstance(data, dict) or "id" not in data:
            raise ProviderMalformedResponse("users/current response has no 'id'")
        return ProviderHealth(
            ok=True,
            detail="Vast API reachable and key accepted",
            account_id=str(data["id"]),
            checked_at=datetime.now(UTC),
        )

    def list_machines(self) -> MachineList:
        body = self._get("/api/v0/machines", params={"owner": "me"})
        machines = vast_wire.parse_machines(body)
        now = datetime.now(UTC)
        unknown = RentalState("unknown", listed=None, observed_at=now, detail=UNKNOWN_RENTAL_DETAIL)
        machines = [replace(m, rental=unknown) for m in machines]
        return MachineList(
            machines=machines,
            raw_body=vast_wire.dumps(vast_wire.scrub(vast_wire.loads(body))),
            fetched_at=now,
        )

    def get_rental_state(self, external_machine_id: str) -> RentalState:
        # No network call: there is no documented field to read.
        return RentalState(
            "unknown", listed=None, observed_at=datetime.now(UTC), detail=UNKNOWN_RENTAL_DETAIL
        )

    def fetch_earnings(self, external_machine_ids: list[str], start: date, end: date) -> EarningsReport:
        """One request per machine: the API has no per-machine-per-day array (evidence C10)."""
        settings = self._settings
        rows: list[EarningsRow] = []
        totals: dict[str, Decimal] = {}
        anomalies: list[str] = []
        bodies: dict[str, Any] = {}
        for machine_id in sorted(set(external_machine_ids)):
            if not machine_id.isdigit():
                raise ProviderError(f"Vast machine ids are integers; got {machine_id!r}")
            body = self._get(
                "/api/v0/users/me/machine-earnings",
                params={
                    "owner": "me",
                    "sday": vast_wire.epoch_day(start),
                    "eday": vast_wire.epoch_day(end),
                    "machid": int(machine_id),
                },
            )
            machine_rows, declared, machine_anomalies = vast_wire.parse_earnings(
                body, machine_id, start, end, settings.settlement_currency
            )
            rows.extend(machine_rows)
            anomalies.extend(machine_anomalies)
            if declared is not None:
                totals[machine_id] = declared
            bodies[machine_id] = vast_wire.scrub(vast_wire.loads(body))
        return EarningsReport(
            rows=rows,
            period_start=start,
            period_end=end,
            basis=settings.vast_earnings_basis,
            buckets_verified=settings.vast_earnings_buckets_verified,
            raw_body=vast_wire.dumps({"provider": "vast", "by_machine": bodies}),
            fetched_at=datetime.now(UTC),
            declared_totals=totals,
            anomalies=anomalies,
            covered_machines=frozenset(external_machine_ids),
            is_synthetic=False,
        )

    # --- writes (disabled by default, never retried) ------------------------

    def unlist_machine(self, external_machine_id: str) -> MutationResult:
        """``DELETE /api/v0/machines/{id}/asks/``. Stops new rentals only.

        Vast documents that unlisting "does not affect existing" contracts. It
        is not permission to stop or reboot anything.
        """
        if not self._settings.provider_mutations_enabled:
            raise ProviderFeatureDisabled(
                "provider mutations are disabled (HM_PROVIDER_MUTATIONS_ENABLED=false)"
            )
        if not external_machine_id.isdigit():
            raise ProviderError(f"Vast machine ids are integers; got {external_machine_id!r}")
        client = self._ready()
        path = f"/api/v0/machines/{int(external_machine_id)}/asks/"
        try:
            response = client.request("DELETE", path, json={})
        except httpx.HTTPError as exc:
            raise ProviderOutcomeUncertain(
                f"unlist request for machine {external_machine_id} was sent and its outcome is unknown "
                f"({type(exc).__name__}); check the machine in the Vast console before doing anything else"
            ) from exc
        if response.status_code >= 500 or response.status_code == 429:
            raise ProviderOutcomeUncertain(
                f"unlist request for machine {external_machine_id} got HTTP {response.status_code}; "
                "outcome unknown, check the Vast console"
            )
        self._raise_for(response)
        data = vast_wire.loads(response.content)
        if not isinstance(data, dict) or data.get("success") is not True:
            raise ProviderError("Vast did not confirm the unlist request")
        return MutationResult(ok=True, detail="unlist accepted by Vast", raw=vast_wire.scrub(data))

    def schedule_maintenance(self, *_: Any, **__: Any) -> MutationResult:
        raise ProviderFeatureUnverified(
            "scheduling a Vast maintenance window is not implemented: the documentation and the official CLI "
            "disagree on the format of the start time (docs/integration-evidence.md, D13)"
        )
