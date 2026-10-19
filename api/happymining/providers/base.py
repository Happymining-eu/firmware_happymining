"""Provider interface.

Two implementations exist behind it: ``FakeProvider`` (DEMO, synthetic
fixtures, no network) and ``VastProvider`` (LIVE, read-only by default).
Selection is explicit configuration. Nothing in this package falls back from
one to the other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Protocol

# --- errors ----------------------------------------------------------------


class ProviderError(Exception):
    """Base class. ``code`` is stable and safe to store and show."""

    code = "provider_error"
    retryable = False

    def __init__(self, message: str = "", **extra: Any):
        super().__init__(message or self.code)
        self.message = message or self.code
        self.extra = extra


class ProviderNotConfigured(ProviderError):
    code = "provider_not_configured"


class ProviderAuthorizationUnverified(ProviderError):
    """The commercial authorization prerequisite has not been recorded."""

    code = "commercial_authorization_unverified"


class ProviderAuthError(ProviderError):
    code = "provider_auth_failed"


class ProviderRateLimited(ProviderError):
    code = "provider_rate_limited"
    retryable = True


class ProviderTimeout(ProviderError):
    code = "provider_timeout"
    retryable = True


class ProviderUnavailable(ProviderError):
    code = "provider_unavailable"
    retryable = True


class ProviderMalformedResponse(ProviderError):
    code = "provider_malformed_response"


class ProviderFeatureDisabled(ProviderError):
    """The feature exists but is switched off by configuration."""

    code = "provider_feature_disabled"


class ProviderFeatureUnverified(ProviderError):
    """Not documented well enough to implement. See docs/integration-evidence.md."""

    code = "provider_feature_unverified"


class ProviderOutcomeUncertain(ProviderError):
    """A write was sent and its outcome is unknown. Reconcile before retrying."""

    code = "provider_outcome_uncertain"


# --- data ------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderHealth:
    ok: bool
    detail: str
    account_id: str = ""
    checked_at: datetime | None = None


@dataclass(frozen=True)
class RentalState:
    """What is known about a machine's obligations to renters.

    ``state`` is one of: unknown, idle, active_contracts, stopped_instances,
    stored_data. Only ``idle`` together with ``listed is False`` allows
    disruptive maintenance. GPU utilisation is deliberately not part of this:
    an idle GPU can still be under contract.
    """

    state: str
    listed: bool | None
    observed_at: datetime
    detail: str = ""
    active_contracts: int | None = None
    stopped_instances: int | None = None
    stored_data: bool | None = None


@dataclass(frozen=True)
class ProviderMachineInfo:
    external_id: str
    hostname: str = ""
    gpu_name: str = ""
    num_gpus: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    rental: RentalState | None = None


@dataclass(frozen=True)
class MachineList:
    machines: list[ProviderMachineInfo]
    raw_body: bytes
    fetched_at: datetime


@dataclass(frozen=True)
class EarningsRow:
    external_machine_id: str
    day: date
    amount: Decimal
    currency: str
    components: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class EarningsReport:
    """Provider earnings normalised to one row per machine per UTC day.

    ``basis`` says whether amounts are net of the provider's own fee. Only
    ``net_of_provider_fee`` may be posted; ``unverified`` is held.
    ``buckets_verified`` says whether day units and range boundaries of the
    source are verified. Both come from the adapter, never from a guess.
    """

    rows: list[EarningsRow]
    period_start: date
    period_end: date  # inclusive
    basis: str
    buckets_verified: bool
    raw_body: bytes
    fetched_at: datetime
    declared_totals: dict[str, Decimal] = field(default_factory=dict)  # machine id -> provider total
    anomalies: list[str] = field(default_factory=list)
    is_synthetic: bool = False
    # Machines the provider was actually asked about for this period.
    covered_machines: frozenset[str] = frozenset()


@dataclass(frozen=True)
class MutationResult:
    ok: bool
    detail: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ListingTerms:
    """What an operator asks the provider to offer a machine at.

    Units follow the Vast CLI help (docs/integration-evidence.md, D13):
    ``price_gpu`` and ``price_min_bid`` in $/GPU/hour, ``price_disk`` in
    $/GB/month, ``price_inet_up`` and ``price_inet_down`` in $/GB, ``min_chunk``
    the smallest number of GPUs one rental may take, ``end_date`` when the offer
    expires (required: "set an offer end date before listing your machine, or
    the offer will remain open indefinitely"). Listing again with a later end
    date can extend existing contracts at their current price; a raised price
    never changes a running contract (D14).
    """

    price_gpu: Decimal
    end_date: datetime
    price_disk: Decimal | None = None
    price_inet_up: Decimal | None = None
    price_inet_down: Decimal | None = None
    price_min_bid: Decimal | None = None
    min_chunk: int | None = None


@dataclass(frozen=True)
class ListingSnapshot:
    """The offer-related fields the provider reports for a machine, as last
    synced. Every field is optional: the provider documents none of them, the
    official CLI merely prints them (docs/integration-evidence.md, B5)."""

    gpu_price: Decimal | None = None  # $/GPU/h, "listed_gpu_cost"
    min_bid_price: Decimal | None = None  # $/GPU/h, "min_bid_price"
    inet_up_price: Decimal | None = None  # $/GB, "listed_inet_up_cost"
    inet_down_price: Decimal | None = None  # $/GB, "listed_inet_down_cost"
    credit_discount_max: Decimal | None = None
    reliability: Decimal | None = None  # "reliability2", 0 to 1 presumed
    verification: str = ""
    num_reports: int | None = None
    gpu_occupancy: str = ""  # format undocumented; shown verbatim
    driver_version: str = ""
    disk_space: Decimal | None = None  # unit undocumented
    public_ip: str = ""
    geolocation: str = ""


@dataclass(frozen=True)
class MachineReport:
    """One renter report about a machine (``GET /machines/{id}/reports``)."""

    problem: str
    message: str
    created_at: str


class Provider(Protocol):
    name: str
    is_synthetic: bool

    def check_health(self) -> ProviderHealth: ...

    def list_machines(self) -> MachineList: ...

    def get_rental_state(self, external_machine_id: str) -> RentalState: ...

    def fetch_earnings(self, external_machine_ids: list[str], start: date, end: date) -> EarningsReport: ...

    def unlist_machine(self, external_machine_id: str) -> MutationResult: ...

    def list_machine(self, external_machine_id: str, terms: ListingTerms) -> MutationResult: ...

    def set_min_bid(self, external_machine_id: str, price: Decimal) -> MutationResult: ...

    def cancel_maintenance(self, external_machine_id: str) -> MutationResult: ...

    def get_reports(self, external_machine_id: str) -> list[MachineReport]: ...
