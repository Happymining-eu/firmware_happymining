"""DEMO / LIVE separation: the start-up guard, the worker and the CLI."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from fake_vast_server import API_KEY, FakeVast
from helpers import LIVE_OVERRIDES, World, live_settings, make_settings
from sqlalchemy import func, select

from happymining import worker
from happymining.config import (
    DEMO_FIELD_ENCRYPTION_KEY,
    ConfigError,
    Settings,
    get_settings,
    reset_settings_cache,
)
from happymining.main import create_app
from happymining.models import (
    EarningBucket,
    EarningsImport,
    JournalEntry,
    Machine,
    Owner,
    ProviderMachine,
    SyncRun,
    User,
)
from happymining.providers import registry

REPO = Path(__file__).resolve().parents[2]


def test_live_test_settings_are_accepted():
    assert live_settings().problems() == []
    create_app(live_settings())


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"secret_key": "change-me"}, "HM_SECRET_KEY"),
        ({"secret_key": "demo-secret-key-demo-secret-key-demo-secret-key"}, "default or placeholder"),
        ({"secret_key": "changeme-" + "x" * 40}, "default or placeholder"),
        ({"field_encryption_key": DEMO_FIELD_ENCRYPTION_KEY}, "published demo key"),
        ({"field_encryption_key": "not-a-fernet-key"}, "valid Fernet key"),
        ({"demo_login_enabled": True}, "HM_DEMO_LOGIN_ENABLED"),
        ({"provider": "fake"}, "fake provider is demo-only"),
        ({"payout_provider": "mock"}, "mock payout provider"),
        ({"cookie_secure": False}, "HM_COOKIE_SECURE"),
        ({"public_base_url": "http://api.example.test"}, "https://"),
        ({"allowed_hosts": ["*"]}, "HM_ALLOWED_HOSTS"),
        ({"allowed_hosts": []}, "HM_ALLOWED_HOSTS"),
        ({"cors_allowed_origins": ["*"]}, "HM_CORS_ALLOWED_ORIGINS"),
        (
            {"database_url": "postgresql+psycopg://happymining:happymining_dev@db/happymining"},
            "default development",
        ),
    ],
)
def test_live_refuses_to_start_with(override, expected):
    settings = live_settings(**override)
    problems = settings.problems()
    assert any(expected in p for p in problems), problems
    with pytest.raises(ConfigError, match="refusing to start in LIVE mode"):
        create_app(settings)


def test_demo_never_uses_a_real_provider_or_real_payouts():
    assert any("never calls a real provider" in p for p in make_settings(provider="vast").problems())
    assert any(
        "mock" in p for p in make_settings(payouts_enabled=True, payout_provider="manual_export").problems()
    )
    with pytest.raises(ConfigError):
        create_app(make_settings(provider="vast"))


def test_mode_has_no_default(monkeypatch):
    monkeypatch.delenv("HM_MODE")
    reset_settings_cache()
    try:
        with pytest.raises(ConfigError, match="mode"):
            get_settings()
    finally:
        monkeypatch.undo()
        reset_settings_cache()
    assert get_settings().mode == "demo"
    assert Settings.model_fields["mode"].is_required()
    assert Settings.model_fields["provider"].is_required()


def test_risky_features_default_to_off():
    for field in (
        "payouts_enabled",
        "provider_mutations_enabled",
        "disruptive_operations_enabled",
        "demo_login_enabled",
        "vast_earnings_buckets_verified",
    ):
        assert Settings.model_fields[field].default is False, field
    assert Settings.model_fields["vast_earnings_basis"].default == "unverified"
    assert Settings.model_fields["cookie_secure"].default is True
    assert Settings.model_fields["payout_provider"].default == "manual_export"
    assert Settings.model_fields["vast_commercial_authorization_ref"].default == ""


def test_cli_check_config_fails_for_a_bad_live_configuration():
    env = {
        **os.environ,
        "HM_MODE": "live",
        "HM_PROVIDER": "fake",
        "HM_SECRET_KEY": "change-me",
        "HM_DEMO_LOGIN_ENABLED": "true",
        "HM_PAYOUT_PROVIDER": "mock",
        "PYTHONPATH": str(REPO / "api"),
    }
    out = subprocess.run(
        [sys.executable, "-m", "happymining.cli", "check-config"], env=env, capture_output=True, text=True
    )
    assert out.returncode == 1
    for needle in ("HM_SECRET_KEY", "HM_DEMO_LOGIN_ENABLED", "fake provider", "mock payout"):
        assert needle in out.stdout
    assert "change-me" not in out.stdout  # the secret itself is not printed

    seed = subprocess.run(
        [sys.executable, "-m", "happymining.cli", "seed-demo"], env=env, capture_output=True, text=True
    )
    assert seed.returncode == 2 and "refusing to start in LIVE mode" in seed.stderr


# --- seed and worker ---------------------------------------------------------


def test_demo_seed_is_idempotent_and_everything_is_flagged_synthetic(world, settings):
    from happymining.demo.seed import seed_demo

    first = seed_demo(world.session, settings)
    world.commit()
    second = seed_demo(world.session, settings)
    world.commit()
    assert first == second
    assert world.session.execute(select(func.count()).select_from(Owner)).scalar_one() == 2
    assert all(o.is_synthetic for o in world.session.execute(select(Owner)).scalars())
    assert all(u.is_demo and u.password_hash is None for u in world.session.execute(select(User)).scalars())
    machines = world.session.execute(select(ProviderMachine)).scalars().all()
    assert len(machines) == 3 and all("synthetic" in m.hostname for m in machines)
    from happymining.models import FeeSchedule

    fee = world.session.execute(select(FeeSchedule)).scalar_one()
    assert fee.is_demo_assumption and "DEMO assumption" in fee.note


def test_demo_seed_refuses_live_mode(world):
    from happymining.demo.seed import seed_demo

    with pytest.raises(ConfigError):
        seed_demo(world.session, live_settings())


def test_worker_in_demo_syncs_and_imports_synthetic_data_once(world, settings):
    worker.run_once(settings)
    worker.run_once(settings)  # second tick: nothing is due yet
    runs = world.session.execute(select(SyncRun.kind, SyncRun.status)).all()
    assert sorted(runs) == [("earnings", "ok"), ("machines", "ok")]
    imports = world.session.execute(select(EarningsImport)).scalars().all()
    assert len(imports) == 1 and imports[0].is_synthetic and imports[0].status == "posted"
    # Nothing is bound yet, so everything sits in the exception queue, unattributed.
    statuses = set(world.session.execute(select(EarningBucket.status)).scalars())
    assert statuses == {"unmapped"}


def test_worker_in_live_without_prerequisites_records_a_blocked_run_and_invents_nothing():
    settings = live_settings()
    world = World(settings)
    try:
        registry.set_override(None)
        worker.run_once(settings)
        runs = world.session.execute(select(SyncRun.kind, SyncRun.status, SyncRun.error_code)).all()
        assert ("machines", "blocked", "commercial_authorization_unverified") in runs
        for model in (ProviderMachine, Machine, Owner, EarningBucket, EarningsImport, JournalEntry):
            assert world.session.execute(select(model)).first() is None, model.__name__
    finally:
        world.close()


def test_worker_survives_a_provider_outage():
    server = FakeVast().start()
    try:
        server.machines = [{"id": 1, "hostname": "h"}]
        server.fault("/api/v0/machines", 503, 503, 503)
        settings = live_settings(
            vast_base_url=server.base_url,
            vast_api_key=API_KEY,
            vast_commercial_authorization_ref="TEST-ONLY",
            worker_machine_sync_interval_s=60,
        )
        from happymining.providers.vast import VastProvider

        registry.set_override(VastProvider(settings, sleep=lambda _: None))
        world = World(settings)
        try:
            worker.run_once(settings)  # must not raise
            run = world.session.execute(select(SyncRun).where(SyncRun.kind == "machines")).scalar_one()
            assert (run.status, run.error_code) == ("error", "provider_unavailable")
            assert world.session.execute(select(ProviderMachine)).first() is None
        finally:
            world.close()
    finally:
        server.stop()
        registry.set_override(None)


def test_expired_pairing_codes_are_swept(world, settings):
    from sqlalchemy import text

    from happymining.models import EnrollmentRequest

    world.pairing(world.owner())
    world.session.execute(text("UPDATE enrollment_requests SET expires_at = now() - interval '1 minute'"))
    world.commit()
    worker.job_expire(settings)
    world.session.expire_all()
    assert world.session.execute(select(EnrollmentRequest.status)).scalar_one() == "expired"


def test_live_overrides_do_not_leak_into_demo_settings():
    assert get_settings().mode == "demo" and LIVE_OVERRIDES["mode"] == "live"
