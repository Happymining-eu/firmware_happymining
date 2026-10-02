"""The real Vast adapter, exercised over HTTP against a fake server.

A passing run here proves the adapter's behaviour against the documented wire
shape. It does not prove anything about Vast's live service: no test in this
repository talks to Vast.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest
from fake_vast_server import API_KEY, FakeVast
from fastapi.testclient import TestClient
from helpers import SYSTEM, World, live_settings
from sqlalchemy import func, select

from happymining.config import ConfigError
from happymining.main import create_app
from happymining.models import (
    EarningBucket,
    ExceptionItem,
    JournalEntry,
    Machine,
    Owner,
    ProviderMachine,
    SourceSnapshot,
    SyncRun,
)
from happymining.providers import registry, vast_wire
from happymining.providers.base import (
    ProviderAuthError,
    ProviderAuthorizationUnverified,
    ProviderError,
    ProviderFeatureDisabled,
    ProviderFeatureUnverified,
    ProviderMalformedResponse,
    ProviderNotConfigured,
    ProviderOutcomeUncertain,
    ProviderRateLimited,
    ProviderTimeout,
    ProviderUnavailable,
)
from happymining.providers.vast import VastProvider
from happymining.services import operations, provider_sync
from happymining.services.maintenance import evaluate

D = Decimal
TODAY = datetime.now(UTC).date()


def day(n: int) -> date:
    return TODAY - timedelta(days=n)


def eday(n: int) -> int:
    return vast_wire.epoch_day(day(n))


@pytest.fixture
def vast():
    server = FakeVast().start()
    server.machines = [
        {
            "id": 5001,
            "hostname": "host-a",
            "gpu_name": "RTX 4090",
            "num_gpus": 2,
            "listed_gpu_cost": 0.4,
            "gpu_occupancy": "D D",
            "reliability2": 0.99,
            "verification": "verified",
        },
        {"id": 5002, "hostname": "host-b", "gpu_name": "RTX 3090", "num_gpus": 1},
    ]
    server.earnings = {
        5001: {eday(3): {"gpu_earn": 10.1, "sto_earn": 0.2}, eday(2): {"gpu_earn": 0.1, "bwu_earn": 0.2}},
        5002: {eday(2): {"gpu_earn": 3.3333}},
    }
    yield server
    server.stop()


def provider_for(vast, **overrides) -> tuple[VastProvider, list[float]]:
    sleeps: list[float] = []
    settings = live_settings(
        **{
            "vast_base_url": vast.base_url,
            "vast_api_key": API_KEY,
            "vast_commercial_authorization_ref": "TEST-ONLY-reference",
            **overrides,
        }
    )
    return VastProvider(settings, sleep=sleeps.append), sleeps


# --- reads -----------------------------------------------------------------


def test_machine_inventory_uses_the_documented_call(vast):
    provider, _ = provider_for(vast)
    listing = provider.list_machines()
    assert [(m.external_id, m.hostname, m.gpu_name, m.num_gpus) for m in listing.machines] == [
        ("5001", "host-a", "RTX 4090", 2),
        ("5002", "host-b", "RTX 3090", 1),
    ]
    call = vast.calls("GET", "/api/v0/machines")[0]
    assert call["query"] == {"owner": "me"}
    assert call["authorization"] == f"Bearer {API_KEY}"  # header, never a query parameter
    assert all("api_key" not in r["query"] for r in vast.requests)


def test_rental_state_is_reported_as_unknown_not_guessed(vast):
    provider, _ = provider_for(vast)
    listing = provider.list_machines()
    assert {m.rental.state for m in listing.machines} == {"unknown"}
    assert {m.rental.listed for m in listing.machines} == {None}
    before = len(vast.requests)
    state = provider.get_rental_state("5001")
    assert state.state == "unknown" and "does not expose" in state.detail
    assert len(vast.requests) == before  # nothing to read, so nothing is called


def test_health_check_and_account_id(vast):
    provider, _ = provider_for(vast)
    health = provider.check_health()
    assert health.ok and health.account_id == "424242"


def test_earnings_are_fetched_per_machine_with_integer_epoch_days(vast):
    provider, _ = provider_for(vast)
    report = provider.fetch_earnings(["5001", "5002"], day(3), day(1))
    calls = vast.calls("GET", "machine-earnings")
    assert [c["query"] for c in calls] == [
        {"owner": "me", "sday": str(eday(3)), "eday": str(eday(1)), "machid": "5001"},
        {"owner": "me", "sday": str(eday(3)), "eday": str(eday(1)), "machid": "5002"},
    ]
    rows = {(r.external_machine_id, r.day): r for r in report.rows}
    assert set(rows) == {("5001", day(3)), ("5001", day(2)), ("5002", day(2))}
    assert report.declared_totals == {"5001": D("10.6"), "5002": D("3.3333")}
    assert report.anomalies == [] and not report.is_synthetic


def test_money_is_parsed_without_binary_float_error(vast):
    provider, _ = provider_for(vast)
    report = provider.fetch_earnings(["5001"], day(2), day(2))
    row = report.rows[0]
    # 0.1 + 0.2 in binary floating point is 0.30000000000000004. Not here.
    assert row.amount == D("0.3") and str(row.amount) == "0.3"
    assert all(isinstance(v, str) for v in row.components.values())


def test_live_earnings_are_unverified_by_default_and_held(vast):
    provider, _ = provider_for(vast)
    report = provider.fetch_earnings(["5001"], day(3), day(1))
    assert report.basis == "unverified" and report.buckets_verified is False

    verified, _ = provider_for(
        vast, vast_earnings_basis="net_of_provider_fee", vast_earnings_buckets_verified=True
    )
    assert verified.fetch_earnings(["5001"], day(3), day(1)).basis == "net_of_provider_fee"


def test_stored_snapshots_are_scrubbed_of_personal_data_and_keys(vast):
    provider, _ = provider_for(vast)
    report = provider.fetch_earnings(["5001"], day(3), day(1))
    text = report.raw_body.decode()
    for leaked in (
        "synthetic@example.invalid",
        "Example Street",
        "SYNTHETIC-TAX-ID",
        "Synthetic Fixture",
        API_KEY,
    ):
        assert leaked not in text
    assert "[REMOVED]" in text and "per_day" in text


def test_machine_filter_not_applied_is_detected(vast):
    vast.ignore_machine_filter = True
    provider, _ = provider_for(vast)
    report = provider.fetch_earnings(["5001"], day(3), day(1))
    assert any("machine filter may not have been applied" in a for a in report.anomalies)


# --- faults ----------------------------------------------------------------


def test_429_is_retried_with_backoff_then_succeeds(vast):
    vast.fault("/api/v0/machines", 429, 429)
    provider, sleeps = provider_for(vast)
    assert len(provider.list_machines().machines) == 2
    assert len(vast.calls("GET", "/api/v0/machines")) == 3
    assert len(sleeps) == 2 and sleeps[0] >= 2.0 and sleeps[1] >= 4.0  # above Vast's ~2 s threshold


def test_persistent_429_gives_up_after_bounded_attempts(vast):
    vast.fault("/api/v0/machines", 429, 429, 429, 429, 429)
    provider, sleeps = provider_for(vast)
    with pytest.raises(ProviderRateLimited):
        provider.list_machines()
    assert len(vast.calls("GET", "/api/v0/machines")) == 3 and len(sleeps) == 2


def test_5xx_outage(vast):
    vast.fault("/api/v0/machines", 503, 502, 504)
    provider, _ = provider_for(vast)
    with pytest.raises(ProviderUnavailable):
        provider.list_machines()


def test_timeout_is_bounded(vast):
    import httpx

    vast.hang_s = 1.5
    vast.fault("/api/v0/machines", "timeout", "timeout", "timeout")
    provider, _ = provider_for(vast)
    provider._ready()
    provider._client.timeout = httpx.Timeout(0.2)
    started = datetime.now(UTC)
    with pytest.raises(ProviderTimeout):
        provider.list_machines()
    assert (datetime.now(UTC) - started).total_seconds() < 5
    assert len(vast.calls("GET", "/api/v0/machines")) == 3


def test_server_down(vast):
    provider, _ = provider_for(vast)
    vast.stop()
    with pytest.raises(ProviderUnavailable):
        provider.check_health()


@pytest.mark.parametrize("behaviour", ["garbage", "wrong_shape"])
def test_malformed_responses_are_rejected(vast, behaviour):
    vast.fault("/api/v0/machines", behaviour)
    provider, _ = provider_for(vast)
    with pytest.raises(ProviderMalformedResponse):
        provider.list_machines()
    vast.fault("/api/v0/users/me/machine-earnings", behaviour)
    with pytest.raises(ProviderMalformedResponse):
        provider.fetch_earnings(["5001"], day(3), day(1))


@pytest.mark.parametrize(
    "body",
    [
        b'{"per_day": [{"day": "tomorrow", "gpu_earn": 1}]}',
        b'{"per_day": [{"gpu_earn": 1}]}',
        b'{"per_day": [{"day": 20000, "gpu_earn": "lots", "sto_earn": 0, "bwu_earn": 0, "bwd_earn": 0}]}',
        b'{"per_day": [{"day": 20000, "gpu_earn": null, "sto_earn": 0, "bwu_earn": 0, "bwd_earn": 0}]}',
        b'{"per_day": [{"day": 20000, "gpu_earn": 1, "sto_earn": 0, "bwu_earn": true, "bwd_earn": 0}]}',
        b'{"per_day": "none"}',
        b'{"per_day": [], "per_machine": {"5001": 1}}',
        b"[]",
    ],
)
def test_malformed_earnings_bodies(body):
    with pytest.raises(ProviderMalformedResponse):
        vast_wire.parse_earnings(body, "5001", date(2024, 1, 1), date(2030, 1, 1), "USD")


def parts(gpu, sto=0, bwu=0, bwd=0):
    return {"gpu_earn": gpu, "sto_earn": sto, "bwu_earn": bwu, "bwd_earn": bwd}


def test_a_day_without_every_documented_component_is_an_anomaly_not_a_zero():
    """A renamed or dropped field must not silently become "earned nothing"."""
    body = json.dumps(
        {
            "per_day": [
                {"day": 20000, "gpu_earn": 4, "sto_earn": 1, "bwu_earn": 0},
                {"day": 20001, "gpu": 4, "sto_earn": 1, "bwu_earn": 0, "bwd_earn": 0},
                {"day": 20002, **parts(3, 0.5, 0.25, 0.25)},
            ]
        }
    ).encode()
    rows, _, anomalies = vast_wire.parse_earnings(
        body, "5001", vast_wire.from_epoch_day(19999), vast_wire.from_epoch_day(20003), "USD"
    )
    assert [(r.day, r.amount) for r in rows] == [(vast_wire.from_epoch_day(20002), D("4"))]
    assert len(anomalies) == 2
    assert "bwd_earn" in anomalies[0] and "gpu_earn" in anomalies[1]


def test_fractional_or_out_of_range_days_are_anomalies_not_rows():
    body = json.dumps(
        {
            "per_day": [
                {"day": 20000.5, **parts(1)},
                {"day": 1, **parts(1)},
                {"day": 20000, **parts(2.5)},
            ]
        }
    ).encode()
    start = vast_wire.from_epoch_day(19999)
    rows, declared, anomalies = vast_wire.parse_earnings(
        body, "5001", start, vast_wire.from_epoch_day(20001), "USD"
    )
    assert [(r.day, r.amount) for r in rows] == [(vast_wire.from_epoch_day(20000), D("2.5"))]
    assert declared is None and len(anomalies) == 2


def test_bad_key_is_an_auth_error_and_not_retried(vast):
    provider, sleeps = provider_for(vast, vast_api_key="wrong-key")
    with pytest.raises(ProviderAuthError):
        provider.list_machines()
    assert len(vast.calls("GET", "/api/v0/machines")) == 1 and sleeps == []


def test_redirects_are_not_followed(vast):
    vast.fault("/api/v0/machines", "redirect")
    provider, _ = provider_for(vast)
    with pytest.raises(ProviderMalformedResponse, match="redirect"):
        provider.list_machines()
    assert len(vast.requests) == 1  # the key was not carried anywhere else


def test_api_key_never_reaches_the_logs(vast, caplog):
    vast.fault("/api/v0/machines", 503, 503, 503)
    provider, _ = provider_for(vast)
    with caplog.at_level(logging.DEBUG), pytest.raises(ProviderUnavailable):
        provider.list_machines()
    assert caplog.records and API_KEY not in caplog.text
    try:
        provider.list_machines()
    except ProviderError as exc:
        assert API_KEY not in str(exc) and API_KEY not in repr(exc.extra)


# --- prerequisites: explicit failure, never a fallback ----------------------


def test_missing_key_fails_explicitly_without_calling_vast(vast):
    settings = live_settings(vast_base_url=vast.base_url, vast_commercial_authorization_ref="ref")
    with pytest.raises(ProviderNotConfigured):
        VastProvider(settings).list_machines()
    assert vast.requests == []


def test_unverified_commercial_authorization_blocks_every_call(vast):
    settings = live_settings(vast_base_url=vast.base_url, vast_api_key=API_KEY)
    provider = VastProvider(settings)
    for call in (
        provider.check_health,
        provider.list_machines,
        lambda: provider.fetch_earnings(["5001"], day(2), day(1)),
        lambda: provider.unlist_machine("5001"),
    ):
        with pytest.raises((ProviderAuthorizationUnverified, ProviderFeatureDisabled)):
            call()
    assert vast.requests == []


def test_registry_never_mixes_modes():
    live = live_settings()
    assert isinstance(registry.get_provider(live), VastProvider)
    with pytest.raises(ConfigError):
        registry.get_provider(live.model_copy(update={"provider": "fake"}))
    from happymining.config import get_settings

    with pytest.raises(ConfigError):
        registry.get_provider(get_settings().model_copy(update={"provider": "vast"}))


# --- writes ----------------------------------------------------------------


def test_writes_are_disabled_by_default(vast):
    provider, _ = provider_for(vast)
    with pytest.raises(ProviderFeatureDisabled):
        provider.unlist_machine("5001")
    assert vast.calls("DELETE") == []


def test_unlist_uses_the_documented_call(vast):
    provider, _ = provider_for(vast, provider_mutations_enabled=True)
    result = provider.unlist_machine("5001")
    assert result.ok
    call = vast.calls("DELETE")[0]
    assert call["path"] == "/api/v0/machines/5001/asks/" and json.loads(call["body"]) == {}


@pytest.mark.parametrize("behaviour", [503, 429, "timeout"])
def test_a_write_with_unknown_outcome_is_never_retried(vast, behaviour):
    import httpx

    vast.hang_s = 1.0
    vast.fault("/api/v0/machines/5001/asks/", behaviour, 503, 503)
    provider, sleeps = provider_for(vast, provider_mutations_enabled=True)
    provider._ready()
    provider._client.timeout = httpx.Timeout(0.3)
    with pytest.raises(ProviderOutcomeUncertain, match="outcome"):
        provider.unlist_machine("5001")
    assert len(vast.calls("DELETE")) == 1 and sleeps == []


def test_unconfirmed_write_is_an_error(vast):
    vast.fault("/api/v0/machines/5001/asks/", "success_false")
    provider, _ = provider_for(vast, provider_mutations_enabled=True)
    with pytest.raises(ProviderError):
        provider.unlist_machine("5001")


def test_maintenance_window_scheduling_is_not_implemented(vast):
    provider, _ = provider_for(vast, provider_mutations_enabled=True)
    with pytest.raises(ProviderFeatureUnverified, match="disagree"):
        provider.schedule_maintenance("5001")
    assert vast.requests == []


# --- LIVE application behaviour ----------------------------------------------


@pytest.fixture
def live(vast):
    """A LIVE app wired to the fake server, with an MFA-verified admin."""
    settings = live_settings(
        vast_base_url=vast.base_url,
        vast_api_key=API_KEY,
        vast_commercial_authorization_ref="TEST-ONLY-reference",
    )
    world = World(settings)
    admin = world.user("admin")
    registry.set_override(VastProvider(settings, sleep=lambda _: None))
    with TestClient(create_app(settings), base_url="https://api.example.test") as client:
        yield world, client, world.auth(admin), settings
    world.close()


def test_live_sync_and_import_holds_unverified_earnings(live, vast):
    world, client, h, settings = live
    assert client.post("/api/v1/provider/check", headers=h).status_code == 200
    sync = client.post("/api/v1/provider/sync-machines", headers=h)
    assert sync.status_code == 200 and sync.json()["stats"]["machines"] == 2
    machines = world.session.execute(select(ProviderMachine)).scalars().all()
    assert {m.rental_state for m in machines} == {"unknown"}

    r = client.post(
        "/api/v1/provider/import-earnings",
        headers=h,
        json={"start": day(3).isoformat(), "end": day(1).isoformat()},
    )
    assert r.status_code == 200
    assert r.json()["import"]["status"] == "held_unverified" and r.json()["import"]["synthetic"] is False
    # Fetched and kept as evidence, but nothing reached the ledger.
    assert world.session.execute(select(func.count()).select_from(EarningBucket)).scalar_one() == 0
    assert world.session.execute(select(func.count()).select_from(JournalEntry)).scalar_one() == 0
    kinds = [e.kind for e in world.session.execute(select(ExceptionItem)).scalars()]
    assert kinds == ["unverified_semantics"]
    snapshot = world.session.execute(
        select(SourceSnapshot).where(SourceSnapshot.kind == "earnings_report")
    ).scalar_one()
    assert not snapshot.is_synthetic and API_KEY.encode() not in snapshot.body


def test_live_provider_outage_is_an_explicit_error_and_creates_no_data(live, vast):
    world, client, h, settings = live
    vast.fault("/api/v0/machines", 503, 503, 503)
    r = client.post("/api/v1/provider/sync-machines", headers=h)
    assert r.status_code == 503 and r.json()["error"]["code"] == "provider_unavailable"
    assert world.session.execute(select(ProviderMachine)).first() is None
    run = world.session.execute(select(SyncRun).order_by(SyncRun.started_at.desc())).scalars().first()
    assert run.status == "error" and run.error_code == "provider_unavailable"
    health = client.get("/api/v1/provider/health", headers=h).json()
    assert health["accounts"][0]["last_sync_ok"] is False and health["synthetic_data"] is False


def test_live_without_prerequisites_never_falls_back_to_demo_data(vast):
    settings = live_settings(vast_base_url=vast.base_url)  # no key, no authorization reference
    world = World(settings)
    try:
        admin = world.user("admin")
        with TestClient(create_app(settings), base_url="https://api.example.test") as client:
            h = world.auth(admin)
            for path in ("/api/v1/provider/check", "/api/v1/provider/sync-machines"):
                r = client.post(path, headers=h)
                assert r.status_code == 409, r.text
                assert r.json()["error"]["code"] == "commercial_authorization_unverified"
            r = client.post(
                "/api/v1/provider/import-earnings",
                headers=h,
                json={"start": day(3).isoformat(), "end": day(1).isoformat()},
            )
            # Even with nothing to import, an unusable provider is an error, not a quiet success.
            assert r.status_code == 409
            assert r.json()["error"]["code"] == "commercial_authorization_unverified"
            health = client.get("/api/v1/provider/health", headers=h).json()
        assert health["prerequisites"]["commercial_authorization_recorded"] is False
        assert health["prerequisites"]["api_key_configured"] is False
        # No machine, owner, earning or snapshot appeared from anywhere.
        for model in (ProviderMachine, Machine, Owner, EarningBucket, SourceSnapshot):
            assert world.session.execute(select(model)).first() is None, model.__name__
        assert vast.requests == []
    finally:
        world.close()


def test_live_disruptive_maintenance_is_always_blocked(live, vast):
    world, client, h, settings = live
    enabled = settings.model_copy(update={"disruptive_operations_enabled": True})
    client.post("/api/v1/provider/sync-machines", headers=h)
    machine, _ = world.paired_machine(world.owner())
    world.bind(
        provider_sync.ensure_account(world.session, enabled, registry.get_provider(enabled)), "5001", machine
    )
    decision = evaluate(world.session, enabled, registry.get_provider(enabled), machine, "reboot")
    assert decision.allowed is False
    assert any("rental state is unknown" in r for r in decision.reasons)
    assert any("cannot verify that the machine is unlisted" in r for r in decision.reasons)
    op = operations.request_operation(
        world.session,
        enabled,
        SYSTEM,
        registry.get_provider(enabled),
        machine=machine,
        op_type="restart_vast_daemon",
        params={},
        requested_by=None,
    )
    assert op.status == "blocked"


def test_live_unlist_route_is_refused_while_writes_are_disabled(live, vast):
    world, client, h, settings = live
    client.post("/api/v1/provider/sync-machines", headers=h)
    pm = world.session.execute(
        select(ProviderMachine).where(ProviderMachine.external_id == "5001")
    ).scalar_one()
    r = client.post(f"/api/v1/provider/machines/{pm.id}/unlist", headers=h)
    assert r.status_code == 409 and r.json()["error"]["code"] == "provider_feature_disabled"
    assert vast.calls("DELETE") == []
