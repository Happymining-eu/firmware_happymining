"""Regression tests for the findings of the independent security review.

One section per finding, in the review's numbering. Each test is written to
fail on the behaviour the review described. Findings that an older test file
already covers well are only referenced here, next to the section they belong
to, so that the whole list can be checked from this one file.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote

import pyotp
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from helpers import (
    BASE_URL,
    IDLE_UNLISTED,
    LIVE_OVERRIDES,
    SYSTEM,
    World,
    dataset,
    heartbeat,
    live_settings,
    make_settings,
    sample,
)
from sqlalchemy import func, select, text
from starlette.requests import Request

from happymining import cli, migrate, worker
from happymining import main as main_module
from happymining.config import DEMO_FIELD_ENCRYPTION_KEY, ConfigError, Settings
from happymining.db import session_factory
from happymining.deps import client_ip
from happymining.errors import Conflict, InvalidRequest, Unauthorized
from happymining.logging_setup import JsonFormatter
from happymining.main import DEFAULT_BODY_LIMIT, DEVICE_BODY_LIMIT, create_app
from happymining.models import (
    AuditLog,
    Device,
    DeviceCredential,
    Operation,
    Owner,
    SyncRun,
    SystemInfo,
    TelemetrySample,
    User,
    UserSession,
)
from happymining.providers.base import ProviderAuthorizationUnverified
from happymining.providers.fake import FakeProvider
from happymining.security import decrypt_text, redact, redact_text
from happymining.services import accounts, devices, operations, pairing, provider_sync
from happymining.services.system import MODE_KEY, claim_database_mode, ensure_database_mode

REPO = Path(__file__).resolve().parents[2]
LIVE_URL = "https://api.example.test"
UUID0 = "00000000-0000-0000-0000-000000000000"
PASSWORD = "correct horse battery staple"
STRONG_SECRET = str(LIVE_OVERRIDES["secret_key"])
PAIRING_CODE = "HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XA"  # the documentation example; never issued here
FINGERPRINT = "sha256:" + "ab" * 32
UNSAFE = ("POST", "PUT", "PATCH", "DELETE")
ACTIVE_CONTRACT = {
    "state": "active_contracts",
    "listed": False,
    "active_contracts": 1,
    "stopped_instances": 0,
    "stored_data": True,
}
STATE_UNKNOWN = {
    "state": "unknown",
    "listed": False,
    "active_contracts": None,
    "stopped_instances": None,
    "stored_data": None,
}
ENABLED = {"disruptive_operations_enabled": True}


# --- helpers -----------------------------------------------------------------


@contextmanager
def app_client(settings: Settings, *, base_url: str = BASE_URL, **kw) -> Iterator[TestClient]:
    """A running application (lifespan included) built from the given settings."""
    with TestClient(create_app(settings), base_url=base_url, **kw) as c:
        yield c


@contextmanager
def live_app() -> Iterator[tuple[World, TestClient, Settings]]:
    """A LIVE application with its own data builder. Nothing else may have claimed the database."""
    live = live_settings()
    world = World(live)
    try:
        with app_client(live, base_url=LIVE_URL) as c:
            yield world, c, live
    finally:
        world.close()


def browser_for(app, user=None) -> TestClient:
    """A separate cookie jar on the same application, optionally signed in through the demo form."""
    browser = TestClient(app, base_url=BASE_URL)
    if user is not None:
        r = browser.post("/demo-login", data={"email": user.email}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/dashboard", r.headers
    return browser


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def login(c: TestClient, email: str, password: str = PASSWORD, **kw):
    return c.post("/api/v1/auth/login", json={"email": email, "password": password}, **kw)


def envelope(response) -> dict[str, str]:
    """The documented error envelope, without the per-request id."""
    body = response.json()
    assert set(body) == {"error"} and set(body["error"]) == {"code", "message", "request_id"}, body
    assert response.headers["x-request-id"] == body["error"]["request_id"]
    return {k: v for k, v in body["error"].items() if k != "request_id"}


def count(world: World, model) -> int:
    return world.session.execute(select(func.count()).select_from(model)).scalar_one()


def audit_rows(world: World, action: str) -> list[AuditLog]:
    world.session.expire_all()
    query = select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)
    return list(world.session.execute(query).scalars())


def stay_inside_one_window(need_s: float = 8.0, window_s: int = 60) -> None:
    """Rate-limit windows are aligned to the clock; do not start counting just before one ends."""
    left = window_s - time.time() % window_s
    if left < need_s:
        time.sleep(left + 0.05)


def routes(app) -> list[tuple[str, str]]:
    """Every (method, path template) the application serves."""
    found: set[tuple[str, str]] = set()

    def walk(items) -> None:
        for route in items:
            if isinstance(route, APIRoute):
                found.update((method, route.path) for method in route.methods - {"HEAD", "OPTIONS"})
                continue
            # Included routers are wrapped differently from one FastAPI release to the next.
            for attribute in ("routes", "original_router", "router"):
                inner = getattr(route, attribute, None)
                inner = getattr(inner, "routes", inner)
                if isinstance(inner, list) and inner:
                    walk(inner)

    walk(app.routes)
    return sorted(found)


def concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", UUID0, path)


def fleet(world: World, rental: dict | None = None):
    """One paired machine bound to provider machine 101. Idle and unlisted unless told otherwise."""
    provider = world.provider(dataset({"101": {"rental": rental} if rental else dict(IDLE_UNLISTED)}, {}))
    account = world.account(provider)
    machine, token = world.paired_machine(world.owner())
    world.bind(account, "101", machine)
    world.session.refresh(machine)
    return machine, token, provider


def request_operation(world: World, settings: Settings, provider, machine, op_type: str, params=None):
    operation = operations.request_operation(
        world.session,
        settings,
        SYSTEM,
        provider,
        machine=machine,
        op_type=op_type,
        params=params or {},
        requested_by=None,
    )
    world.commit()
    return operation


def ack(c: TestClient, token: str, operation_id, **body):
    return c.post(f"/api/v1/device/operations/{operation_id}/ack", headers=bearer(token), json=body)


def stored_operation(world: World, operation_id) -> Operation:
    world.session.expire_all()
    return world.session.get(Operation, operation_id)


# =============================================================================
# 1. DEMO and LIVE can never share a database
# =============================================================================


def claimed_mode(world: World) -> str | None:
    world.session.expire_all()
    row = world.session.get(SystemInfo, MODE_KEY)
    return row.value if row else None


def test_first_start_records_the_mode_and_the_other_mode_is_refused_afterwards(db, settings):
    assert db.get(SystemInfo, MODE_KEY) is None  # a fresh database belongs to nobody yet
    assert claim_database_mode(db, settings) == "demo"
    db.commit()
    assert claim_database_mode(db, settings) == "demo"  # the same mode again is fine
    db.commit()

    live = live_settings()
    assert live.problems() == []  # the configuration is acceptable; the database is what refuses
    with pytest.raises(ConfigError, match="DEMO and LIVE never share a database"):
        claim_database_mode(db, live)
    db.rollback()
    with pytest.raises(ConfigError, match="belongs to a DEMO deployment"):
        ensure_database_mode(live)
    ensure_database_mode(settings)

    # The refused attempts changed nothing.
    rows = db.execute(select(SystemInfo.key, SystemInfo.value)).all()
    assert rows == [(MODE_KEY, "demo")]


def test_live_app_does_not_start_on_a_database_claimed_by_demo(client, world):
    assert client.get("/readyz").json()["mode"] == "demo"  # the running demo app claimed it
    assert claimed_mode(world) == "demo"
    with (
        pytest.raises(ConfigError, match=r"refusing to start in LIVE mode.*belongs to a DEMO deployment"),
        TestClient(create_app(live_settings()), base_url=LIVE_URL),
    ):
        pytest.fail("a LIVE application served requests from a DEMO database")
    assert claimed_mode(world) == "demo"


def test_demo_app_does_not_start_on_a_database_claimed_by_live(world):
    with app_client(live_settings(), base_url=LIVE_URL) as live_client:
        assert live_client.get("/readyz").json()["mode"] == "live"
    assert claimed_mode(world) == "live"
    with (
        pytest.raises(ConfigError, match=r"refusing to start in DEMO mode.*belongs to a LIVE deployment"),
        TestClient(create_app(world.settings), base_url=BASE_URL),
    ):
        pytest.fail("a DEMO application, with its passwordless login, opened a LIVE database")
    assert claimed_mode(world) == "live"


def test_same_mode_can_be_started_any_number_of_times(world, settings):
    for _ in range(3):
        with app_client(settings) as c:
            assert c.get("/readyz").status_code == 200
    assert claimed_mode(world) == "demo"
    assert count(world, SystemInfo) == 1


def test_worker_refuses_a_database_of_the_other_mode(monkeypatch, world):
    ensure_database_mode(world.settings)  # a DEMO deployment owns this database
    live = live_settings()
    monkeypatch.setattr(worker, "get_settings", lambda: live)
    monkeypatch.setattr(worker.signal, "signal", lambda *_: None)

    def ran(_settings):
        pytest.fail("the LIVE worker ran its jobs against a DEMO database")

    monkeypatch.setattr(worker, "run_once", ran)
    with pytest.raises(ConfigError, match="belongs to a DEMO deployment"):
        worker.main()
    assert count(world, SyncRun) == 0


def test_cli_refuses_a_database_of_the_other_mode(monkeypatch, capsys, world):
    ensure_database_mode(world.settings)
    live = live_settings()
    monkeypatch.setattr(cli, "get_settings", lambda: live)
    monkeypatch.setattr(cli, "_password", lambda: pytest.fail("create-admin went on to ask for a password"))
    assert cli.main(["create-admin", "ops@example.test"]) == 2
    assert "belongs to a DEMO deployment" in capsys.readouterr().err
    assert count(world, User) == 0


def test_demo_seed_never_writes_synthetic_data_into_a_live_database(capsys, world):
    ensure_database_mode(live_settings())
    assert cli.main(["seed-demo"]) == 2  # the command line is configured for DEMO, like the test process
    assert "belongs to a LIVE deployment" in capsys.readouterr().err
    assert count(world, Owner) == 0 and count(world, User) == 0


# =============================================================================
# 2. LIVE start-up guard
#
# Already covered by test_config_modes.py::test_live_refuses_to_start_with:
# "change-me", the published demo secret and demo field key, demo login, the
# fake provider, the mock payout provider, a non-https public URL, insecure
# cookies and the development database password. DEMO refusing the vast
# provider: test_config_modes.py::test_demo_never_uses_a_real_provider_or_real_payouts.
# =============================================================================


def refused_in_live(expected: str, **override) -> None:
    settings = live_settings(**override)
    problems = settings.problems()
    assert any(expected in p for p in problems), problems
    with pytest.raises(ConfigError, match="refusing to start in LIVE mode"):
        settings.validate_for_startup()
    with pytest.raises(ConfigError, match="refusing to start in LIVE mode"):
        create_app(settings)


@pytest.mark.parametrize(
    "prefix", ["change", "demo", "test", "dev-", "pytest", "example", "placeholder", "secret", "password"]
)
def test_live_refuses_a_placeholder_secret_however_long(prefix):
    refused_in_live("default or placeholder", secret_key=f"{prefix}-{STRONG_SECRET}")
    refused_in_live("default or placeholder", secret_key=f"{prefix.upper()}-{STRONG_SECRET}")


def test_live_refuses_every_secret_published_in_the_repository():
    """Whatever ships in .env.example, the Makefile or the demo script is public knowledge."""
    pattern = re.compile(r"\b(HM_SECRET_KEY|HM_FIELD_ENCRYPTION_KEY)\s*[=:]\s*\"?([^\s\"\\$]+)")
    published: dict[str, set[str]] = {"HM_SECRET_KEY": set(), "HM_FIELD_ENCRYPTION_KEY": set()}
    shipped = ("deploy/.env.example", "Makefile", "scripts/run-demo.sh", "docker-compose.yml")
    for path in (REPO / relative for relative in shipped):
        for line in path.read_text().splitlines() if path.exists() else []:
            if line.lstrip().startswith("#"):
                continue
            for name, value in pattern.findall(line):
                published[name].add(value)
    assert {"change-me", "demo-secret-key-demo-secret-key-demo-secret-key"} <= published["HM_SECRET_KEY"]
    assert {"change-me", DEMO_FIELD_ENCRYPTION_KEY} <= published["HM_FIELD_ENCRYPTION_KEY"]
    for value in sorted(published["HM_SECRET_KEY"]):
        refused_in_live("HM_SECRET_KEY", secret_key=value)
    for value in sorted(published["HM_FIELD_ENCRYPTION_KEY"]):
        refused_in_live("HM_FIELD_ENCRYPTION_KEY", field_encryption_key=value)
    # The secret the test suite itself runs DEMO with is refused as well.
    refused_in_live("default or placeholder", secret_key=make_settings().secret_key.get_secret_value())


@pytest.mark.parametrize(
    "secret", [f" {STRONG_SECRET}", f"{STRONG_SECRET} ", f"{STRONG_SECRET}\n", f"\t{STRONG_SECRET}"]
)
def test_live_refuses_a_secret_with_surrounding_whitespace(secret):
    refused_in_live("leading or trailing whitespace", secret_key=secret)


def test_live_refuses_a_secret_with_too_little_variety():
    refused_in_live("too little variety", secret_key="aB3" * 14)
    refused_in_live("too little variety", secret_key="0123456789abcde" * 3)  # 15 distinct characters
    assert live_settings(secret_key="0123456789abcdef" * 2).problems() == []  # 16: the documented floor
    refused_in_live("at least 32 characters", secret_key=STRONG_SECRET[:31])


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("postgresql+psycopg://happymining_app@db:5432/happymining", "has no password"),
        ("postgresql+psycopg://happymining_app:@db:5432/happymining", "has no password"),
        ("postgresql+psycopg://happymining_app:postgres@db:5432/happymining", "default development password"),
        ("postgresql+psycopg://happymining_app:PassWord@db:5432/happymining", "default development password"),
        (
            "postgresql+psycopg://happymining_app:change-me@db:5432/happymining",
            "default development password",
        ),
        ("postgresql+psycopg://happymining:happymining@db:5432/happymining", "default development password"),
        # The password is the role name: as guessable as a default.
        ("postgresql+psycopg://hm_runtime_role:hm_runtime_role@db:5432/hm", "default development password"),
        (
            "postgresql+psycopg://happymining_app:Xk9mQ2pLw7r@db:5432/happymining",
            "shorter than 12 characters",
        ),
        ("this is not a database url", "not a valid database URL"),
    ],
)
def test_live_refuses_a_weak_database_url(url, expected):
    refused_in_live(expected, database_url=url)


def test_live_accepts_a_database_password_of_twelve_random_characters():
    url = "postgresql+psycopg://happymining_app:Xk9mQ2pLw7rT@db:5432/happymining"
    assert live_settings(database_url=url).problems() == []


@pytest.mark.parametrize(
    "url",
    [
        "http://console.vast.ai",  # the account key would travel in clear text
        "https://vast.ai",
        "https://console.vast.ai.attacker.example",
        "https://console.vast.ai@attacker.example",
        "https://attacker.example/console.vast.ai",
        "http://127.0.0.1.attacker.example",
        "http://localhost.attacker.example:9",
        "ftp://console.vast.ai",
        "",
    ],
)
def test_live_refuses_a_vast_url_that_is_not_the_vast_console_over_tls(url):
    refused_in_live("HM_VAST_BASE_URL must be https://console.vast.ai", vast_base_url=url)


@pytest.mark.parametrize(
    "url",
    [
        "https://console.vast.ai",
        "https://console.vast.ai/",
        "http://127.0.0.1:9",
        "http://localhost:8080",
        "http://[::1]:8080",
    ],
)
def test_live_accepts_the_vast_console_and_loopback_stand_ins(url):
    assert live_settings(vast_base_url=url).problems() == []


# =============================================================================
# 3. Login rate limiting
#
# The plain per-address limit is covered by
# test_access_control.py::test_login_is_rate_limited.
# =============================================================================


def test_limited_login_does_not_reveal_whether_the_password_was_right(world):
    user = world.user("auditor", demo=False, password=PASSWORD)
    stay_inside_one_window()
    with app_client(make_settings(login_rate_limit_per_minute=3)) as c:
        assert [login(c, user.email, "a-wrong-password").status_code for _ in range(3)] == [401] * 3
        right = login(c, user.email)  # the correct password, over the limit
        wrong = login(c, user.email, "a-wrong-password")

    assert right.status_code == wrong.status_code == 429
    assert envelope(right) == envelope(wrong) == {"code": "rate_limited", "message": "Too many requests."}
    assert 1 <= int(right.headers["retry-after"]) <= 60
    assert "set-cookie" not in right.headers and "token" not in right.json()
    # The limited attempts were refused before any credential was looked at.
    assert count(world, UserSession) == 0
    assert len(audit_rows(world, "auth.login_failed")) == 3
    assert audit_rows(world, "auth.login") == []


def test_one_client_cannot_lock_an_account_out_for_everyone(world):
    victim = world.user("auditor", demo=False, password=PASSWORD)
    other = world.user("auditor", demo=False, password=PASSWORD)
    attacker, elsewhere = {"X-Forwarded-For": "198.51.100.7"}, {"X-Forwarded-For": "203.0.113.20"}
    stay_inside_one_window()
    with app_client(make_settings(login_rate_limit_per_minute=3, trusted_proxy_hops=1)) as c:
        codes = [
            login(c, victim.email, f"guess-number-{i:04d}", headers=attacker).status_code for i in range(5)
        ]
        assert codes == [401, 401, 401, 429, 429]
        # The address is throttled whichever account it turns to next...
        assert login(c, other.email, headers=attacker).status_code == 429
        # ...but the real user, coming from somewhere else, still gets in.
        assert login(c, victim.email, headers=elsewhere).status_code == 200


def test_account_wide_cap_bounds_guessing_spread_over_many_addresses(world):
    target = world.user("auditor", demo=False, password=PASSWORD)
    bystander = world.user("auditor", demo=False, password=PASSWORD)
    settings = make_settings(login_rate_limit_per_minute=1, trusted_proxy_hops=1)
    stay_inside_one_window()
    with app_client(settings) as c:
        # Nineteen attempts on one account, each from a different address (the
        # limiter is called exactly as the login route calls it)...
        for i in range(19):
            email = target.email.upper() if i % 2 else f"  {target.email} "
            accounts.login_rate_limit(settings, email, f"198.51.100.{i + 1}")
        # ...the twentieth is still looked at, the twenty-first is not: not from
        # a fresh address, not even with the right password.
        last = login(c, target.email, "a-wrong-password", headers={"X-Forwarded-For": "198.51.100.20"})
        assert last.status_code == 401
        limited = login(c, target.email, headers={"X-Forwarded-For": "203.0.113.77"})
        assert limited.status_code == 429 and envelope(limited)["code"] == "rate_limited"
        # Other accounts are unaffected.
        assert login(c, bystander.email, headers={"X-Forwarded-For": "203.0.113.78"}).status_code == 200
    assert [s.user_id for s in world.session.execute(select(UserSession)).scalars()] == [bystander.id]


def test_dashboard_login_form_is_behind_the_same_limiter(world):
    user = world.user("auditor", demo=False, password=PASSWORD)
    stay_inside_one_window()
    with app_client(make_settings(login_rate_limit_per_minute=2)) as c:
        for _ in range(2):
            r = c.post(
                "/login", data={"email": user.email, "password": "a-wrong-password"}, follow_redirects=False
            )
            assert r.status_code == 303
            assert unquote(r.headers["location"]) == "/login?err=Invalid email, password or code."
        r = c.post("/login", data={"email": user.email, "password": PASSWORD}, follow_redirects=False)
        assert r.status_code == 303 and unquote(r.headers["location"]) == "/login?err=Too many requests."
        assert "set-cookie" not in r.headers
        # The form and the API count against the same windows.
        assert login(c, user.email).status_code == 429
    assert count(world, UserSession) == 0


# =============================================================================
# 4. TOTP replay
#
# test_access_control.py::test_admin_needs_mfa_in_live_mode covers the
# activation code and one reuse of an accepted code. These add the second login
# inside the same 30-second step, an older code after a newer one, the browser
# form, and two logins racing for one code.
# =============================================================================


def stay_inside_one_totp_step(need_s: float = 8.0) -> None:
    left = 30 - time.time() % 30
    if left < need_s:
        time.sleep(left + 0.05)


def enroll_mfa(world: World, settings: Settings, user) -> pyotp.TOTP:
    """Enroll and activate with the previous step's code, so the current step is still unspent."""
    accounts.begin_mfa_enrollment(world.session, settings, user)
    totp = pyotp.TOTP(decrypt_text(settings, user.totp_secret_enc))
    accounts.activate_mfa(world.session, settings, SYSTEM, user, totp.at(int(time.time()), -1))
    world.commit()
    return totp


def failure_reasons(world: World) -> list[str]:
    return [row.details["reason"] for row in audit_rows(world, "auth.login_failed")]


def test_totp_code_cannot_be_used_for_a_second_login_in_the_same_step():
    stay_inside_one_totp_step()
    with live_app() as (world, c, live):
        admin = world.user("admin", password=PASSWORD)
        totp = enroll_mfa(world, live, admin)
        now = int(time.time())
        code = totp.at(now)
        never_valid = next(
            guess
            for guess in ("000000", "111111", "222222", "333333", "444444", "555555")
            if guess not in {totp.at(now, offset) for offset in range(-3, 4)}
        )

        def attempt(totp_code: str):
            body = {"email": admin.email, "password": PASSWORD, "totp_code": totp_code}
            return c.post("/api/v1/auth/login", json=body)

        first = attempt(code)
        assert first.status_code == 200 and first.json()["user"]["mfa_enabled"] is True
        replay = attempt(code)
        assert replay.status_code == 401 and "set-cookie" not in replay.headers
        # A replayed code is answered exactly like a wrong one.
        assert envelope(replay) == envelope(attempt(never_valid))
        assert envelope(replay) == {"code": "unauthorized", "message": "Invalid email, password or code."}
        # The browser form goes through the same check.
        form = c.post(
            "/login",
            data={"email": admin.email, "password": PASSWORD, "totp_code": code},
            follow_redirects=False,
        )
        assert form.status_code == 303 and form.headers["location"].startswith("/login?err=")
        assert "set-cookie" not in form.headers

        assert count(world, UserSession) == 1
        assert failure_reasons(world) == ["totp_replay", "bad_totp", "totp_replay"]
        world.session.refresh(admin)
        assert admin.totp_last_step == now // 30


def test_older_totp_code_is_refused_once_a_newer_one_was_accepted():
    stay_inside_one_totp_step()
    with live_app() as (world, c, live):
        auditor = world.user("auditor", password=PASSWORD)  # not only admins: any account with MFA
        totp = enroll_mfa(world, live, auditor)
        now = int(time.time())
        current, ahead = totp.at(now), totp.at(now, 1)

        def attempt(totp_code: str) -> int:
            body = {"email": auditor.email, "password": PASSWORD, "totp_code": totp_code}
            return c.post("/api/v1/auth/login", json=body).status_code

        assert attempt(ahead) == 200  # one step of clock drift is allowed
        # The current step's code is still inside the validity window, but it is
        # older than the last one accepted, so it is spent too.
        assert attempt(current) == 401
        assert attempt(ahead) == 401
        assert failure_reasons(world) == ["totp_replay", "totp_replay"]
        world.session.refresh(auditor)
        assert auditor.totp_last_step == now // 30 + 1
        assert count(world, UserSession) == 1


def test_two_simultaneous_logins_cannot_both_spend_one_totp_code():
    stay_inside_one_totp_step()
    live = live_settings()
    world = World(live)
    try:
        admin = world.user("admin", password=PASSWORD)
        code = enroll_mfa(world, live, admin).at(int(time.time()))
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def sign_in() -> None:
            session = session_factory()()
            try:
                barrier.wait(timeout=10)
                accounts.login(
                    session,
                    live,
                    email=admin.email,
                    password=PASSWORD,
                    totp_code=code,
                    ip="127.0.0.1",
                    user_agent="t",
                )
                session.commit()
                outcomes.append("signed in")
            except Unauthorized:
                session.commit()  # as the route does, to keep the audit row
                outcomes.append("refused")
            finally:
                session.close()

        threads = [threading.Thread(target=sign_in) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert sorted(outcomes) == ["refused", "signed in"]
        assert count(world, UserSession) == 1
        assert failure_reasons(world) == ["totp_replay"]
    finally:
        world.close()


# =============================================================================
# 5. Provider health is not falsely "ok"
# =============================================================================


def health_accounts(c: TestClient, headers: dict[str, str]) -> list[dict]:
    r = c.get("/api/v1/provider/health", headers=headers)
    assert r.status_code == 200
    return r.json()["accounts"]


def closed_days(world: World) -> dict[str, str]:
    return {"start": world.day(3).isoformat(), "end": world.day(1).isoformat()}


def test_provider_health_is_unknown_before_any_sync(client, world):
    h = world.auth(world.user("admin"))
    assert health_accounts(client, h) == []
    provider = world.provider(dataset({"101": {}}, {}))
    provider_sync.ensure_account(world.session, world.settings, provider)
    world.commit()
    (account,) = health_accounts(client, h)
    assert account["last_sync_ok"] is None  # neither ok nor failing: nothing has run
    assert account["failing"] == [] and account["last_runs"] == {} and account["last_sync_error"] == ""
    assert account["last_sync_at"] is None and account["stale"] is True


def test_failing_job_is_named_and_not_masked_by_another_jobs_success(app, client, world):
    admin = world.user("admin")
    h = world.auth(admin)
    browser = browser_for(app, admin)
    provider = world.provider(dataset({"101": {}}, {}))

    provider.outage = True
    failed = client.post("/api/v1/provider/sync-machines", headers=h)
    assert failed.status_code == 503 and envelope(failed)["code"] == "provider_unavailable"
    (account,) = health_accounts(client, h)
    assert account["last_sync_ok"] is False and account["failing"] == ["machines"]
    assert account["last_sync_error"].startswith("machines: provider_unavailable")

    # The provider answers again, but only the health check has run since.
    provider.outage = False
    assert client.post("/api/v1/provider/check", headers=h).status_code == 200
    (account,) = health_accounts(client, h)
    assert account["last_sync_ok"] is False and account["failing"] == ["machines"]
    assert account["last_runs"]["health"]["status"] == "ok"
    assert account["last_runs"]["machines"]["status"] == "error"
    assert account["last_sync_error"].startswith("machines: provider_unavailable")
    page = browser.get("/admin/provider")
    assert page.status_code == 200 and "failing: machines" in page.text and "all runs ok" not in page.text

    # A second job fails: both are named.
    provider.outage = True
    assert (
        client.post("/api/v1/provider/import-earnings", headers=h, json=closed_days(world)).status_code == 503
    )
    (account,) = health_accounts(client, h)
    assert account["last_sync_ok"] is False and account["failing"] == ["earnings", "machines"]

    # Only a success of the failing job itself clears it, one job at a time.
    provider.outage = False
    assert client.post("/api/v1/provider/sync-machines", headers=h).status_code == 200
    (account,) = health_accounts(client, h)
    assert account["last_sync_ok"] is False and account["failing"] == ["earnings"]
    assert (
        client.post("/api/v1/provider/import-earnings", headers=h, json=closed_days(world)).status_code == 200
    )
    (account,) = health_accounts(client, h)
    assert account["last_sync_ok"] is True and account["failing"] == [] and account["last_sync_error"] == ""
    assert "all runs ok" in browser.get("/admin/provider").text


def test_blocked_run_counts_as_failing(world, settings):
    class Unauthorised(FakeProvider):
        def list_machines(self):
            raise ProviderAuthorizationUnverified("no commercial authorization on record")

    provider = Unauthorised({"account_id": "T", "currency": "USD", "machines": [], "earnings": {}})
    account = provider_sync.ensure_account(world.session, settings, provider)
    assert provider_sync.check_health(world.session, provider, account).status == "ok"
    assert provider_sync.sync_machines(world.session, provider, account).status == "blocked"
    world.commit()
    (reported,) = provider_sync.integration_health(world.session, settings)["accounts"]
    assert reported["last_sync_ok"] is False and reported["failing"] == ["machines"]
    assert "commercial_authorization_unverified" in reported["last_sync_error"]


def test_account_listing_does_not_report_ok_while_a_job_is_failing(client, world):
    """GET /provider/accounts publishes the same account's sync state as /provider/health."""
    h = world.auth(world.user("admin"))
    provider = world.provider(dataset({"101": {}}, {}))
    provider.outage = True
    assert client.post("/api/v1/provider/sync-machines", headers=h).status_code == 503
    provider.outage = False
    assert client.post("/api/v1/provider/check", headers=h).status_code == 200

    (account,) = health_accounts(client, h)
    assert account["last_sync_ok"] is False and account["failing"] == ["machines"]
    (listed,) = client.get("/api/v1/provider/accounts", headers=h).json()["items"]
    assert listed["last_sync_ok"] is not True, (
        "the machine sync is still failing, but the account listing says the last sync was ok "
        f"and reports no error: {listed}"
    )


# =============================================================================
# 6. Account containment
#
# 403 for every non-admin on these routes is also enforced by the route walks in
# test_access_control.py (test_auditor_is_read_only and
# test_owner_role_cannot_use_any_mutating_or_staff_route).
# =============================================================================


def test_deactivating_a_user_ends_every_session_at_once_and_blocks_login(app, client, world):
    h = world.auth(world.user("admin"))
    victim = world.user("auditor", demo=False, password=PASSWORD)
    api_token = login(TestClient(app, base_url=BASE_URL), victim.email).json()["token"]
    browser = TestClient(app, base_url=BASE_URL)
    signed_in = browser.post(
        "/login", data={"email": victim.email, "password": PASSWORD}, follow_redirects=False
    )
    assert signed_in.status_code == 303 and signed_in.headers["location"] == "/dashboard"
    assert client.get("/api/v1/auth/me", headers=bearer(api_token)).status_code == 200
    assert browser.get("/dashboard").status_code == 200

    r = client.post(f"/api/v1/users/{victim.id}/deactivate", headers=h)
    assert r.status_code == 200 and r.json() == {"id": str(victim.id), "is_active": False}

    # Both sessions are dead on the very next request.
    assert client.get("/api/v1/auth/me", headers=bearer(api_token)).status_code == 401
    page = browser.get("/dashboard", follow_redirects=False)
    assert page.status_code == 303 and page.headers["location"] == "/login"
    assert browser.get("/api/v1/owners").status_code == 401
    # The right password no longer opens a session, and the answer does not say why.
    again, wrong = login(client, victim.email), login(client, victim.email, "a-wrong-password")
    assert again.status_code == 401 and envelope(again) == envelope(wrong)
    assert "set-cookie" not in again.headers
    assert failure_reasons(world) == ["inactive", "bad_credentials"]

    sessions = (
        world.session.execute(select(UserSession).where(UserSession.user_id == victim.id)).scalars().all()
    )
    assert len(sessions) == 2 and all(s.revoked_at is not None for s in sessions)
    (entry,) = audit_rows(world, "user.deactivate")
    assert entry.object_id == str(victim.id) and entry.details == {"sessions": 2}


def test_deactivated_demo_account_cannot_use_the_demo_login(client, world):
    h = world.auth(world.user("admin"))
    owner_user = world.user("owner", world.owner())
    token = world.token(owner_user)
    assert client.post(f"/api/v1/users/{owner_user.id}/deactivate", headers=h).status_code == 200
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401
    assert client.post("/api/v1/auth/demo-login", json={"email": owner_user.email}).status_code == 401
    form = TestClient(client.app, base_url=BASE_URL).post(
        "/demo-login", data={"email": owner_user.email}, follow_redirects=False
    )
    assert form.status_code == 303 and form.headers["location"].startswith("/login?err=")
    assert "set-cookie" not in form.headers


def test_revoking_sessions_signs_a_user_out_everywhere_but_keeps_the_account(app, client, world):
    admin = world.user("admin")
    h = world.auth(admin)
    target = world.user("auditor", demo=False, password=PASSWORD)
    bystander = world.user("auditor", demo=False, password=PASSWORD)
    first = login(TestClient(app, base_url=BASE_URL), target.email).json()["token"]
    second = login(TestClient(app, base_url=BASE_URL), target.email).json()["token"]
    other = login(TestClient(app, base_url=BASE_URL), bystander.email).json()["token"]

    r = client.post(f"/api/v1/users/{target.id}/revoke-sessions", headers=h)
    assert r.status_code == 200 and r.json() == {"id": str(target.id), "sessions_revoked": 2}
    for token in (first, second):
        assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401
    # Nobody else is signed out.
    assert client.get("/api/v1/auth/me", headers=bearer(other)).status_code == 200
    assert client.get("/api/v1/auth/me", headers=h).status_code == 200
    # The account itself is intact: the user signs in again and gets a working session.
    fresh = login(TestClient(app, base_url=BASE_URL), target.email)
    assert fresh.status_code == 200
    assert client.get("/api/v1/auth/me", headers=bearer(fresh.json()["token"])).status_code == 200
    again = client.post(f"/api/v1/users/{target.id}/revoke-sessions", headers=h)
    assert again.json()["sessions_revoked"] == 1
    assert [row.details for row in audit_rows(world, "user.revoke_sessions")] == [
        {"sessions": 2},
        {"sessions": 1},
    ]


def test_only_admins_can_deactivate_users_or_revoke_sessions(client, world):
    target = world.user("auditor")
    target_session = world.auth(target)
    owner_user = world.user("owner", world.owner())
    for caller in (world.user("auditor"), owner_user, target):
        h = world.auth(caller)
        for action in ("deactivate", "revoke-sessions"):
            r = client.post(f"/api/v1/users/{target.id}/{action}", headers=h)
            assert r.status_code == 403 and envelope(r)["code"] == "forbidden", (caller.role, action)
    assert client.get("/api/v1/auth/me", headers=target_session).status_code == 200
    world.session.expire_all()
    assert world.session.get(User, target.id).is_active is True
    assert audit_rows(world, "user.deactivate") == [] and audit_rows(world, "user.revoke_sessions") == []

    admin = world.auth(world.user("admin"))
    for action in ("deactivate", "revoke-sessions"):
        assert client.post(f"/api/v1/users/{UUID0}/{action}", headers=admin).status_code == 404


def test_last_active_admin_cannot_be_deactivated(client, world):
    first = world.user("admin")
    h = world.auth(first)
    refused = client.post(f"/api/v1/users/{first.id}/deactivate", headers=h)
    assert refused.status_code == 409 and envelope(refused)["code"] == "conflict"
    assert "last active admin" in refused.json()["error"]["message"]
    assert client.get("/api/v1/auth/me", headers=h).status_code == 200  # still signed in, still active

    # With a second admin the rule no longer applies. There is no separate
    # "not yourself" rule: an admin may switch their own account off.
    second = world.user("admin")
    h2 = world.auth(second)
    assert client.post(f"/api/v1/users/{first.id}/deactivate", headers=h).status_code == 200
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401

    # A deactivated admin does not count as "another admin".
    assert client.post(f"/api/v1/users/{second.id}/deactivate", headers=h2).status_code == 409
    world.session.expire_all()
    active = (
        world.session.execute(select(User.id).where(User.role == "admin", User.is_active)).scalars().all()
    )
    assert active == [second.id]


def wait_until_blocked_or_done(world: World, thread: threading.Thread, timeout_s: float = 10.0) -> None:
    """Return once the thread's database session is waiting for a lock, or the thread has finished."""
    waiting = text(
        "SELECT count(*) FROM pg_stat_activity "
        "WHERE datname = current_database() AND wait_event_type = 'Lock'"
    )
    deadline = time.monotonic() + timeout_s
    while thread.is_alive() and time.monotonic() < deadline:
        blocked = world.session.execute(waiting).scalar_one()
        world.session.rollback()
        if blocked:
            return
        time.sleep(0.02)


def test_two_admins_deactivating_each_other_cannot_leave_no_admin(world):
    """The last-admin rule has to hold for requests that overlap, not only one after the other."""
    first, second = world.user("admin"), world.user("admin")
    ahead, behind = session_factory()(), session_factory()()
    outcome: list[str] = []

    def deactivate_first() -> None:
        try:
            accounts.deactivate_user(behind, SYSTEM, first.id)
            behind.commit()
            outcome.append("deactivated")
        except Conflict:
            behind.rollback()
            outcome.append("refused")

    try:
        accounts.deactivate_user(ahead, SYSTEM, second.id)  # request one: checked, not yet committed
        thread = threading.Thread(target=deactivate_first)  # request two arrives in the meantime
        thread.start()
        wait_until_blocked_or_done(world, thread)
        ahead.commit()
        thread.join(timeout=30)
        assert not thread.is_alive() and len(outcome) == 1
    finally:
        ahead.close()
        behind.close()
    world.session.expire_all()
    active = (
        world.session.execute(select(User.email).where(User.role == "admin", User.is_active)).scalars().all()
    )
    assert active, (
        f"both admins were deactivated (second request: {outcome[0]}); nobody can administer the system"
    )


def test_set_password_ends_existing_sessions(app, client, world):
    user = world.user("auditor", demo=False, password=PASSWORD)
    token = login(TestClient(app, base_url=BASE_URL), user.email).json()["token"]
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 200

    replacement = "a brand new passphrase 2026"
    accounts.set_password(world.session, SYSTEM, user, replacement)
    world.commit()

    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401
    assert login(client, user.email).status_code == 401  # the old password is gone
    assert login(client, user.email, replacement).status_code == 200
    (entry,) = audit_rows(world, "user.set_password")
    assert entry.details == {"sessions": 1} and replacement not in json.dumps(entry.details)

    with pytest.raises(InvalidRequest, match="at least 12"):
        accounts.set_password(world.session, SYSTEM, user, "too-short")
    with pytest.raises(Conflict, match="demo accounts have no password"):
        accounts.set_password(world.session, SYSTEM, world.user("auditor"), replacement)


def test_operator_command_line_contains_an_account(monkeypatch, app, client, world, capsys):
    user = world.user("auditor", demo=False, password=PASSWORD)
    replacement = "typed at the operator console"
    monkeypatch.setattr(cli, "_password", lambda: replacement)

    token = login(TestClient(app, base_url=BASE_URL), user.email).json()["token"]
    assert cli.main(["set-password", user.email]) == 0
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401
    assert login(client, user.email).status_code == 401

    token = login(TestClient(app, base_url=BASE_URL), user.email, replacement).json()["token"]
    assert cli.main(["deactivate-user", user.email]) == 0
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401
    assert login(client, user.email, replacement).status_code == 401
    assert replacement not in capsys.readouterr().out


# =============================================================================
# 7. Telemetry flood and retention
#
# More than 100 samples per request (422) and an oversized heartbeat (413) are
# covered by test_pairing_devices.py::test_malformed_telemetry_is_refused and
# ::test_oversized_body_is_refused; the tests below add the exact boundaries.
# =============================================================================


def stored_seqs(world: World, machine=None) -> list[int]:
    query = select(TelemetrySample.seq).order_by(TelemetrySample.seq)
    if machine is not None:
        query = query.where(TelemetrySample.machine_id == machine.id)
    return list(world.session.execute(query).scalars())


def age_sample(world: World, seq: int, age: timedelta) -> None:
    world.session.execute(
        text("UPDATE telemetry_samples SET collected_at = :at WHERE seq = :seq"),
        {"at": datetime.now(UTC) - age, "seq": seq},
    )
    world.commit()


def test_heartbeats_are_rate_limited_per_device(world):
    owner = world.owner()
    machine_a, token_a = world.paired_machine(owner, "a")
    machine_b, token_b = world.paired_machine(owner, "b")
    settings = make_settings(device_heartbeat_rate_limit_per_minute=5)
    stay_inside_one_window()
    with app_client(settings) as c:
        assert [heartbeat(c, token_a, [sample(seq)]).status_code for seq in range(1, 6)] == [200] * 5
        queued = request_operation(world, settings, None, machine_a, "refresh_inventory")
        flood = heartbeat(c, token_a, [sample(6)])
        assert flood.status_code == 429
        assert envelope(flood) == {"code": "rate_limited", "message": "Too many requests."}
        assert 1 <= int(flood.headers["retry-after"]) <= 60
        # Another device, even of the same owner, is not slowed down.
        quiet = heartbeat(c, token_b, [sample(1)])
        assert quiet.status_code == 200 and quiet.json()["accepted"] == 1
    # The throttled request was dropped whole: no sample stored, no operation handed out.
    assert stored_seqs(world, machine_a) == [1, 2, 3, 4, 5]
    assert stored_operation(world, queued.id).status == "pending"


def test_purge_deletes_only_telemetry_older_than_the_retention_period(client, world):
    machine, token = world.paired_machine(world.owner())
    assert heartbeat(client, token, [sample(seq) for seq in range(1, 6)]).json()["accepted"] == 5
    ages = {
        1: timedelta(days=400),
        2: timedelta(days=30, hours=1),
        3: timedelta(days=29, hours=23),
        4: timedelta(days=8),
    }
    for seq, age in ages.items():
        age_sample(world, seq, age)

    assert world.settings.telemetry_retention_days == 30
    assert devices.purge_old_telemetry(world.session, world.settings) == 2
    world.commit()
    assert stored_seqs(world) == [3, 4, 5]
    assert devices.purge_old_telemetry(world.session, world.settings) == 0  # nothing newer is touched

    # The period is configuration: a week of retention removes two more.
    assert devices.purge_old_telemetry(world.session, make_settings(telemetry_retention_days=7)) == 2
    world.commit()
    assert stored_seqs(world) == [5]


def test_purge_removes_at_most_one_batch_per_call(client, world):
    machine, token = world.paired_machine(world.owner())
    heartbeat(client, token, [sample(seq) for seq in range(1, 5)])
    for seq in (1, 2, 3):
        age_sample(world, seq, timedelta(days=45))
    assert devices.purge_old_telemetry(world.session, world.settings, batch=2) == 2
    assert devices.purge_old_telemetry(world.session, world.settings, batch=2) == 1
    assert devices.purge_old_telemetry(world.session, world.settings, batch=2) == 0
    world.commit()
    assert stored_seqs(world) == [4]


def test_worker_applies_the_retention_period(client, world, settings):
    machine, token = world.paired_machine(world.owner())
    heartbeat(client, token, [sample(1), sample(2)])
    age_sample(world, 1, timedelta(days=31))
    worker.job_expire(settings)
    assert stored_seqs(world) == [2]


def test_heartbeat_batch_boundaries(client, world):
    machine, token = world.paired_machine(world.owner())
    full = heartbeat(client, token, [sample(seq) for seq in range(1, 101)])
    assert full.status_code == 200 and full.json()["accepted"] == 100
    over = heartbeat(client, token, [sample(seq) for seq in range(101, 202)])  # 101 samples
    assert over.status_code == 422 and envelope(over)["code"] == "invalid_request"

    # A well-formed heartbeat padded past 256 KiB is refused unread: its sample is not stored.
    body = {
        "sent_at": datetime.now(UTC).isoformat(),
        "samples": [sample(500)],
        "padding": "x" * DEVICE_BODY_LIMIT,
    }
    padded = client.post("/api/v1/device/heartbeat", headers=bearer(token), json=body)
    assert padded.status_code == 413 and envelope(padded)["code"] == "payload_too_large"
    assert stored_seqs(world) == list(range(1, 101))


# =============================================================================
# 8. Operation acknowledgements
#
# Another device's operation (404): test_access_control.py::
# test_device_cannot_touch_another_devices_operation. Wrong nonce (403):
# test_operations_maintenance.py::test_wrong_nonce_is_refused.
# =============================================================================


def delivered_operation(c: TestClient, world: World, op_type="collect_diagnostics", params=None):
    machine, token = world.paired_machine(world.owner())
    params = {"sections": ["agent"]} if params is None else params
    operation = request_operation(world, world.settings, None, machine, op_type, params)
    (delivered,) = heartbeat(c, token, [sample(1)]).json()["operations"]
    assert delivered["id"] == str(operation.id)
    return machine, token, operation, delivered["nonce"]


def test_secrets_in_an_acknowledgement_are_scrubbed_before_storage(client, world):
    machine, token, operation, nonce = delivered_operation(client, world)
    secrets = {
        "device token": token,
        "device secret": token.split(".")[1],
        "password": "hunter2-hunter2",
        "bearer token": "eyJhbGciOiJIUzI1NiJ9.payload.signature",
        "pairing code": PAIRING_CODE,
        "pairing code without hyphens": PAIRING_CODE.replace("-", ""),
        "database password": "S3cr3t-db-pass",
        "basic credentials": "dXNlcjpwYXNzd29yZA==",
        "provider key": "vast-key-0123456789",
    }
    s = secrets
    detail = (
        f"agent.log: login failed password={s['password']}; sent Authorization: Bearer {s['bearer token']}; "
        f"credential {token}; operator typed {PAIRING_CODE} then {s['pairing code without hyphens']}; "
        f"dsn postgresql://hm:{s['database password']}@db/hm"
    )
    result = {
        "agent": {
            "log_tail": [
                f"Authorization: Bearer {s['bearer token']}",
                f"token {token}",
                f"pairing with {PAIRING_CODE.lower()}",
            ],
            "config": {
                "api_key": s["provider key"],
                "db_password": s["database password"],
                "Authorization": f"Basic {s['basic credentials']}",
                "proxy": f"upstream auth Basic {s['basic credentials']}",
            },
        },
        "gpu": "fine",
        "count": 2,
    }
    r = ack(client, token, operation.id, status="succeeded", nonce=nonce, detail=detail, result=result)
    assert r.status_code == 200 and r.json() == {"status": "succeeded"}

    stored = stored_operation(world, operation.id)
    views = {
        "database": stored.detail + json.dumps(stored.result),
        "api": client.get(
            f"/api/v1/machines/{machine.id}/operations", headers=world.auth(world.user("admin"))
        ).text,
        "audit trail": json.dumps([row.details for row in world.session.execute(select(AuditLog)).scalars()]),
    }
    for place, dump in views.items():
        for label, secret in secrets.items():
            assert secret not in dump and secret.lower() not in dump.lower(), (
                f"{label} is readable in the {place}"
            )
    # The rest of what the device reported is kept.
    assert stored.detail.startswith("agent.log: login failed password=[REDACTED]")
    assert stored.result["gpu"] == "fine" and stored.result["count"] == 2
    assert stored.result["agent"]["config"]["api_key"] == "[REDACTED]"


def test_oversized_acknowledgement_result_is_refused_and_not_stored(client, world):
    machine, token, operation, nonce = delivered_operation(client, world)
    limit = operations.MAX_RESULT_BYTES
    assert limit == 64 * 1024
    overhead = len(json.dumps({"dump": ""}))

    too_big = {"dump": "x" * (limit - overhead + 1)}  # one byte over, far below the body limit
    r = ack(client, token, operation.id, status="succeeded", nonce=nonce, result=too_big)
    assert r.status_code == 400
    assert envelope(r) == {"code": "invalid_request", "message": "result is larger than 64 KiB"}
    stored = stored_operation(world, operation.id)
    assert (stored.status, stored.result, stored.completed_at) == ("delivered", {}, None)

    # Exactly at the limit it is accepted, so the refusal above was about size only.
    fits = {"dump": "x" * (limit - overhead)}
    assert ack(client, token, operation.id, status="succeeded", nonce=nonce, result=fits).status_code == 200
    assert stored_operation(world, operation.id).status == "succeeded"


# =============================================================================
# 9. Device revocation cancels its queued operations
#
# The token dying on the heartbeat route is also covered by
# test_pairing_devices.py::test_revoked_credential_is_refused.
# =============================================================================


def test_revoking_a_device_cancels_whatever_was_still_queued_for_it(client, world):
    machine, token = world.paired_machine(world.owner())
    h = world.auth(world.user("admin"))

    def queue() -> str:
        r = client.post(
            f"/api/v1/machines/{machine.id}/operations", headers=h, json={"type": "refresh_inventory"}
        )
        assert r.status_code == 201
        return r.json()["id"]

    finished, started, delivered = queue(), queue(), queue()
    nonces = {op["id"]: op["nonce"] for op in heartbeat(client, token, [sample(1)]).json()["operations"]}
    assert set(nonces) == {finished, started, delivered}
    assert ack(client, token, finished, status="succeeded", nonce=nonces[finished]).status_code == 200
    assert ack(client, token, started, status="accepted", nonce=nonces[started]).status_code == 200
    waiting = queue()  # never handed to the device

    r = client.post(f"/api/v1/devices/{machine.device.id}/revoke", headers=h, json={"reason": "stolen"})
    assert r.status_code == 200 and r.json()["status"] == "revoked"

    after = {op_id: stored_operation(world, op_id) for op_id in (finished, started, delivered, waiting)}
    assert {op_id: op.status for op_id, op in after.items()} == {
        finished: "succeeded",  # final states are left alone
        started: "cancelled",
        delivered: "cancelled",
        waiting: "cancelled",
    }
    for op_id in (started, delivered, waiting):
        assert after[op_id].completed_at is not None
        assert after[op_id].detail == "device revoked before completion"
    (entry,) = audit_rows(world, "device.revoke")
    assert entry.details == {"reason": "stolen", "operations_cancelled": 3}

    # The credential is dead on every device route, straight away.
    assert heartbeat(client, token, [sample(2)]).status_code == 401
    assert client.get("/api/v1/device/operations", headers=bearer(token)).status_code == 401
    assert client.get("/api/v1/device/self", headers=bearer(token)).status_code == 401
    assert client.post("/api/v1/device/credential/rotate", headers=bearer(token)).status_code == 401
    late = ack(client, token, delivered, status="succeeded", nonce=nonces[delivered])
    assert late.status_code == 401 and envelope(late)["code"] == "device_unauthorized"
    assert stored_operation(world, delivered).status == "cancelled"
    assert stored_seqs(world) == [1]
    # And nothing new can be queued for a device that no longer exists.
    r = client.post(
        f"/api/v1/machines/{machine.id}/operations", headers=h, json={"type": "refresh_inventory"}
    )
    assert r.status_code == 409 and "no active paired device" in r.json()["error"]["message"]


def test_revocation_also_kills_a_rotated_credential_in_its_grace_period(client, world):
    machine, old = world.paired_machine(world.owner())
    new = client.post("/api/v1/device/credential/rotate", headers=bearer(old)).json()["credential"]["token"]
    devices.revoke_device(world.session, SYSTEM, machine.device.id, "compromised")
    world.commit()
    for token in (old, new):
        assert client.get("/api/v1/device/self", headers=bearer(token)).status_code == 401
    assert set(world.session.execute(select(DeviceCredential.status)).scalars()) == {"revoked"}


def test_re_paired_machine_does_not_receive_the_revoked_devices_operations(client, world):
    owner = world.owner()
    machine, old_token = world.paired_machine(owner, "rack-9")
    handed_over = request_operation(world, world.settings, None, machine, "refresh_inventory")
    (seen,) = heartbeat(client, old_token, [sample(1)]).json()["operations"]
    waiting = request_operation(world, world.settings, None, machine, "run_preflight")
    device_id = machine.device.id
    devices.revoke_device(world.session, SYSTEM, device_id, "decommissioned")
    world.commit()

    # The same machine record is paired again: a new device behind the same row.
    issued = pairing.create_enrollment(
        world.session,
        world.settings,
        SYSTEM,
        owner_id=owner.id,
        machine_label="",
        machine_id=machine.id,
        created_by=world.user("admin").id,
    )
    enrolled = pairing.enroll_device(
        world.session,
        world.settings,
        pairing_code=issued.code,
        hostname="replacement",
        fingerprint="sha256:" + "1" * 64,
        agent_version="0.1.0",
        os_info={},
        ip="127.0.0.1",
    )
    world.commit()
    assert enrolled.device.id == device_id and count(world, Device) == 1

    first = heartbeat(client, enrolled.token, [sample(100)])
    assert first.status_code == 200 and first.json()["operations"] == []
    assert client.get("/api/v1/device/operations", headers=bearer(enrolled.token)).json() == {
        "operations": []
    }
    # Knowing an old operation's id and nonce does not revive it either.
    stale = ack(client, enrolled.token, handed_over.id, status="succeeded", nonce=seen["nonce"])
    assert stale.status_code == 409
    assert {stored_operation(world, op.id).status for op in (handed_over, waiting)} == {"cancelled"}
    assert heartbeat(client, old_token, [sample(2)]).status_code == 401


# =============================================================================
# 10. Delivered operations are not relabelled
#
# A not-yet-delivered operation being blocked at delivery is covered by
# test_operations_maintenance.py::
# test_allowed_only_when_unlisted_idle_and_enabled_then_rechecked_at_delivery.
# =============================================================================


def test_delivered_operation_keeps_its_record_when_the_gate_closes_afterwards(world):
    machine, token, provider = fleet(world)  # idle and unlisted: the gate is open
    settings = make_settings(**ENABLED)
    h = world.auth(world.user("admin"))
    with app_client(settings) as c:

        def queue(op_type: str, params: dict) -> str:
            r = c.post(
                f"/api/v1/machines/{machine.id}/operations",
                headers=h,
                json={"type": op_type, "params": params},
            )
            assert r.status_code == 201, r.text
            return r.json()["id"]

        handed_over = queue("restart_vast_daemon", {})
        (first,) = heartbeat(c, token, [sample(1)]).json()["operations"]
        assert first["id"] == handed_over
        before = stored_operation(world, handed_over)
        assert before.status == "delivered" and before.delivered_at is not None
        delivered_at = before.delivered_at
        waiting = queue("reboot", {"delay_s": 60})  # allowed when requested, not delivered yet

        # A rental starts.
        provider.dataset["machines"][0]["rental"] = dict(ACTIVE_CONTRACT)
        assert heartbeat(c, token, [sample(2)]).json()["operations"] == []
        assert c.get("/api/v1/device/operations", headers=bearer(token)).json() == {"operations": []}

        # The operation that never left is blocked, on record...
        blocked = stored_operation(world, waiting)
        assert blocked.status == "blocked" and blocked.delivered_at is None
        assert blocked.detail.startswith("Blocked; requires operator handling")
        # ...the one the device may already be executing is not rewritten.
        kept = stored_operation(world, handed_over)
        assert (kept.status, kept.detail, kept.completed_at) == ("delivered", "", None)
        assert kept.delivered_at == delivered_at and kept.safety["allowed"] is True
        assert [row.object_id for row in audit_rows(world, "operation.blocked")] == [waiting]
        listed = c.get(f"/api/v1/machines/{machine.id}/operations", headers=h).json()["items"]
        assert {op["id"]: op["status"] for op in listed} == {handed_over: "delivered", waiting: "blocked"}

        # So the device's report on it is still accepted, and the blocked one stays final.
        done = ack(c, token, handed_over, status="succeeded", nonce=first["nonce"], detail="restarted")
        assert done.status_code == 200 and done.json() == {"status": "succeeded"}
        refused = ack(c, token, waiting, status="succeeded", nonce=blocked.nonce)
        assert refused.status_code == 409
    assert stored_operation(world, handed_over).status == "succeeded"
    assert stored_operation(world, waiting).status == "blocked"


# =============================================================================
# 11. Reboot delay bounds, unimplemented and unknown operations, no shell
#
# Service-level coverage exists in test_operations_maintenance.py
# (test_there_is_no_shell_only_a_fixed_typed_allowlist,
# test_parameters_are_validated_strictly, test_unimplemented_types_fail_explicitly).
# These go through the HTTP route with the gate open, and add the upper bound.
# =============================================================================


def test_reboot_delay_must_be_between_one_and_five_minutes(world):
    machine, token, provider = fleet(world)
    h = world.auth(world.user("admin"))
    url = f"/api/v1/machines/{machine.id}/operations"
    with app_client(make_settings(**ENABLED)) as c:
        for delay in (0, 1, 59, 301, 600, 3600, -60, 60.5, "120", None, True, [60]):
            r = c.post(url, headers=h, json={"type": "reboot", "params": {"delay_s": delay}})
            assert r.status_code == 400, f"delay_s={delay!r} answered {r.status_code}"
            assert envelope(r)["code"] == "invalid_request"
        assert c.post(url, headers=h, json={"type": "reboot"}).status_code == 400
        assert count(world, Operation) == 0  # a refused request leaves nothing behind

        for delay in (60, 300):
            r = c.post(url, headers=h, json={"type": "reboot", "params": {"delay_s": delay}})
            assert r.status_code == 201, r.text
            assert r.json()["params"] == {"delay_s": delay} and r.json()["status"] == "pending"


def test_unimplemented_operations_are_refused_not_reported_as_done(world):
    machine, token, provider = fleet(world)
    h = world.auth(world.user("admin"))
    url = f"/api/v1/machines/{machine.id}/operations"
    with app_client(make_settings(**ENABLED)) as c:  # even with the gate open
        for op_type, params in (
            ("run_benchmark", {"duration_s": 60}),
            ("apply_hardware_profile", {"profile_id": "eco"}),
        ):
            r = c.post(url, headers=h, json={"type": op_type, "params": params})
            assert r.status_code == 501 and envelope(r)["code"] == "not_implemented"
            message = r.json()["error"]["message"]
            assert "not implemented" in message and "nothing was sent to the machine" in message
        assert heartbeat(c, token, [sample(1)]).json()["operations"] == []
        types = c.get("/api/v1/operation-types", headers=h).json()
        assert types["not_implemented"] == ["apply_hardware_profile", "run_benchmark"]
    assert count(world, Operation) == 0


def test_unknown_operation_types_and_free_form_commands_are_refused(client, world):
    machine, token = world.paired_machine(world.owner())
    h = world.auth(world.user("admin"))
    url = f"/api/v1/machines/{machine.id}/operations"
    for op_type in ("shell", "exec", "bash", "run_command", "REBOOT", "reboot; id", ""):
        r = client.post(url, headers=h, json={"type": op_type, "params": {"command": "id"}})
        assert r.status_code == 400 and envelope(r)["code"] == "invalid_request", op_type
        assert "unknown operation type" in r.json()["error"]["message"]
    # The request body has no field for a command...
    for extra in ("command", "shell", "script", "args"):
        r = client.post(url, headers=h, json={"type": "refresh_inventory", "params": {}, extra: "id"})
        assert r.status_code == 422, extra
    # ...and no operation type takes one as a parameter, alone or next to its own.
    own_params = {
        "refresh_inventory": {},
        "collect_diagnostics": {"sections": ["gpu"]},
        "run_preflight": {},
        "rotate_credential": {},
        "restart_vast_daemon": {},
        "reboot": {"delay_s": 60},
        "run_benchmark": {"duration_s": 60},
        "apply_hardware_profile": {"profile_id": "eco"},
    }
    assert set(own_params) == set(operations.OPERATION_TYPES)
    for op_type, params in own_params.items():
        validate = operations.OPERATION_TYPES[op_type]
        assert validate(dict(params)) == params
        for name in ("command", "cmd", "shell", "script", "args"):
            for smuggled in ({name: "id"}, {**params, name: "id"}):
                with pytest.raises(InvalidRequest):
                    validate(smuggled)
                r = client.post(url, headers=h, json={"type": op_type, "params": smuggled})
                assert r.status_code == 400, (op_type, smuggled)
    assert count(world, Operation) == 0
    assert heartbeat(client, token, [sample(1)]).json()["operations"] == []


# =============================================================================
# 12. Blocked disruptive operation
#
# test_operations_maintenance.py::
# test_blocked_request_is_an_error_over_http_not_a_quiet_success checks the 409
# with disruptive operations switched off. Here they are switched on, so the
# only thing blocking is the rental state.
# =============================================================================


@pytest.mark.parametrize("case", ["state unknown", "active contract", "provider unreachable"])
def test_blocked_disruptive_operation_is_a_409_and_nothing_is_queued(world, case):
    rental = {"state unknown": STATE_UNKNOWN, "active contract": ACTIVE_CONTRACT}.get(case)
    machine, token, provider = fleet(world, rental=rental)
    provider.outage = case == "provider unreachable"
    h = world.auth(world.user("admin"))
    with app_client(make_settings(**ENABLED)) as c:
        # Telemetry showing every GPU at zero utilisation is not evidence of anything.
        idle = sample(1)
        assert [gpu["util_pct"] for gpu in idle["gpus"]] == [0]
        assert heartbeat(c, token, [idle]).json()["accepted"] == 1

        for op_type, params in (("reboot", {"delay_s": 60}), ("restart_vast_daemon", {})):
            r = c.post(
                f"/api/v1/machines/{machine.id}/operations",
                headers=h,
                json={"type": op_type, "params": params},
            )
            assert r.status_code == 409, f"{op_type}: {r.status_code} {r.text}"
            assert envelope(r)["code"] == "maintenance_blocked"
            assert r.json()["error"]["message"].startswith("Blocked; requires operator handling")

        assert heartbeat(c, token, [sample(2)]).json()["operations"] == []
        assert c.get("/api/v1/device/operations", headers=bearer(token)).json() == {"operations": []}

    world.session.expire_all()
    recorded = world.session.execute(select(Operation)).scalars().all()
    assert sorted(op.type for op in recorded) == ["reboot", "restart_vast_daemon"]
    for op in recorded:
        assert op.status == "blocked" and op.delivered_at is None and op.completed_at is not None
        assert op.safety["allowed"] is False and "util" not in json.dumps(op.safety).lower()
    assert len(audit_rows(world, "operation.blocked")) == 2 and audit_rows(world, "operation.request") == []


def test_dashboard_reports_a_blocked_operation_as_an_error(world):
    machine, token, provider = fleet(world, rental=ACTIVE_CONTRACT)
    admin = world.user("admin")
    with app_client(make_settings(**ENABLED)) as c:
        browser = browser_for(c.app, admin)
        csrf = browser.get("/api/v1/auth/me").json()["csrf_token"]
        r = browser.post(
            f"/machines/{machine.id}/operations",
            data={"op_type": "reboot", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303
        location = unquote(r.headers["location"])
        assert location.startswith(f"/machines/{machine.id}?err=Blocked; requires operator handling")
        assert "queued" not in location
        assert heartbeat(c, token, [sample(1)]).json()["operations"] == []
    assert [op.status for op in world.session.execute(select(Operation)).scalars()] == ["blocked"]


# =============================================================================
# 13. Pairing locator hidden from non-admins
# =============================================================================

LOCATOR = "ZQ7XKZ"  # recognisable, and cannot occur in an id or a timestamp


def pending_enrollment(world: World, owner=None, locator: str = LOCATOR):
    issued = world.pairing(owner or world.owner(), "rack-7")
    world.session.execute(
        text("UPDATE enrollment_requests SET locator = :locator WHERE id = :id"),
        {"locator": locator, "id": issued.request.id},
    )
    world.commit()
    return issued


def test_enrollment_list_hides_the_locator_from_an_auditor(client, world):
    issued = pending_enrollment(world)
    admin_view = client.get("/api/v1/enrollment-requests", headers=world.auth(world.user("admin")))
    assert [item["locator"] for item in admin_view.json()["items"]] == [LOCATOR]

    h = world.auth(world.user("auditor"))
    listing = client.get("/api/v1/enrollment-requests", headers=h)
    assert listing.status_code == 200
    (item,) = listing.json()["items"]
    # The auditor still sees the request and its state, only not the locator.
    assert item["id"] == str(issued.request.id) and item["status"] == "pending"
    assert item["locator"] is None and LOCATOR not in listing.text
    # Nor does the audit trail of the same request give it away.
    trail = client.get("/api/v1/audit-log", headers=h)
    assert trail.status_code == 200 and "enrollment.create" in trail.text and LOCATOR not in trail.text


def test_pairing_page_hides_the_locator_from_an_auditor(app, world):
    issued = pending_enrollment(world)
    admin_page = browser_for(app, world.user("admin")).get("/admin/pairing")
    assert admin_page.status_code == 200 and LOCATOR in admin_page.text

    auditor = browser_for(app, world.user("auditor"))
    page = auditor.get("/admin/pairing")
    assert page.status_code == 200 and "pending" in page.text
    assert LOCATOR not in page.text and "hidden" in page.text
    assert LOCATOR not in auditor.get("/admin/audit").text
    # Read-only: no form to create a code, and posting one is refused.
    assert "New pairing code" not in page.text
    csrf = auditor.get("/api/v1/auth/me").json()["csrf_token"]
    form = {"owner_id": str(issued.request.owner_id), "machine_label": "x", "csrf_token": csrf}
    assert auditor.post("/admin/pairing", data=form).status_code == 403


def test_owners_cannot_list_enrollments_their_own_or_anyone_elses(app, client, world):
    mine, theirs = world.owner("Mine"), world.owner("Theirs")
    pending_enrollment(world, mine, "ZQ7XKA")
    other = pending_enrollment(world, theirs, "ZQ7XKB")
    owner_user = world.user("owner", mine)
    h = world.auth(owner_user)

    listing = client.get("/api/v1/enrollment-requests", headers=h)
    assert listing.status_code == 403 and envelope(listing)["code"] == "forbidden"
    cancel = client.post(f"/api/v1/enrollment-requests/{other.request.id}/cancel", headers=h)
    assert cancel.status_code == 403
    browser = browser_for(app, owner_user)
    pages = [browser.get("/admin/pairing"), browser.get("/admin/audit"), browser.get("/dashboard")]
    assert [page.status_code for page in pages] == [403, 403, 200]
    for response in (listing, cancel, client.get("/api/v1/machines", headers=h), *pages):
        assert "ZQ7XK" not in response.text


# =============================================================================
# 14. Redaction
# =============================================================================


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "Password",
        "db_password",
        "secret",
        "client_secret",
        "SECRET_KEY",
        "token",
        "access_token",
        "refresh-token",
        "api_key",
        "X-API_KEY",
        "vast_api_key",
        "authorization",
        "Authorization",
        "Proxy-Authorization",
    ],
)
def test_sensitive_keys_are_masked_whatever_their_case_or_depth(key):
    value = "s3cr3t-value-123"
    document = {
        key: value,
        "nested": {"list": [{key: value, "kept": "yes"}], key: {"inner": value}},
        "tuple": ({key: value},),
    }
    assert redact(document) == {
        key: "[REDACTED]",
        "nested": {"list": [{key: "[REDACTED]", "kept": "yes"}], key: "[REDACTED]"},
        "tuple": [{key: "[REDACTED]"}],
    }


def test_cookie_keys_are_masked():
    """A logged Cookie or Set-Cookie header is a session, whatever the cookie is called."""
    value = "opaque-session-value-1234"
    leaked = []
    for key in ("cookie", "Cookie", "Set-Cookie", "session_cookie"):
        out = redact({key: f"sid={value}", "headers": [{key: f"theme=dark; sid={value}"}]})
        if value in json.dumps(out):
            leaked.append(key)
    assert leaked == [], f"values under these keys are not masked: {leaked}"


SECRET_STRINGS = [
    # (text, the secret in it, what has to remain readable)
    ("postgresql://u:pw@h/db", ":pw@", ["postgresql://u:", "@h/db"]),
    (
        "postgresql+psycopg://hm_app:Sup3rS3cretPw@db:5432/happymining",
        "Sup3rS3cretPw",
        ["postgresql+psycopg://hm_app:", "@db:5432/happymining"],
    ),
    (
        "proxy auth was Basic dXNlcjpwYXNzd29yZA== (rejected)",
        "dXNlcjpwYXNzd29yZA==",
        ["proxy auth", "(rejected)"],
    ),
    ("upstream sent basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA==", ["upstream sent"]),
    ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA==", ["Authorization:"]),
    (
        "got Bearer abcdefghijklmnop.qrstuv from the agent",
        "abcdefghijklmnop.qrstuv",
        ["got", "from the agent"],
    ),
    ("got bearer abcdefghijklmnop", "abcdefghijklmnop", ["got"]),
    ("Authorization: Bearer abcdefghijklmnop.qrstuv", "abcdefghijklmnop.qrstuv", ["Authorization:"]),
    ('{"authorization": "Bearer abcdefghijklmnop"}', "abcdefghijklmnop", ['{"authorization": "']),
    (f"device presented hmd_{'0a' * 16}.{'S' * 43} twice", "S" * 43, ["device presented", "twice"]),
    (f"device presented hmd_{'0a' * 16}.{'S' * 43} twice", "0a" * 16, ["device presented", "twice"]),
    (f"cookie hm_session=hms_{'c' * 43}; path=/", "c" * 43, ["cookie hm_session=", "; path=/"]),
    (f"operator typed {PAIRING_CODE}.", "4F8T", ["operator typed"]),
    (f"operator typed {PAIRING_CODE.replace('-', '')}.", "4F8TZP3D", ["operator typed"]),
    (f"operator typed {PAIRING_CODE.lower()}.", "4f8t", ["operator typed"]),
    ("login failed: password=hunter2-hunter2 user=bob", "hunter2", ["login failed: password=", "user=bob"]),
    ('{"password": "hunter2-hunter2", "user": "bob"}', "hunter2", ['{"password": "', '"user": "bob"}']),
    ("api_key=sk_live_123456 trailing", "sk_live_123456", ["api_key=", "trailing"]),
    ("token: abcdef123456 and secret=s3cr3tvalue", "abcdef123456", ["token:", "and secret="]),
    ("token: abcdef123456 and secret=s3cr3tvalue", "s3cr3tvalue", ["token:", "and secret="]),
]


@pytest.mark.parametrize(("raw", "secret", "kept"), SECRET_STRINGS)
def test_secrets_inside_strings_are_masked(raw, secret, kept):
    assert secret in raw
    # On its own, and buried in a structure under an innocent key.
    nested = redact({"note": raw, "lines": [raw, ("x", raw)]})
    for out in (redact_text(raw), redact(raw), nested["note"], nested["lines"][0], nested["lines"][1][1]):
        assert secret not in out and "[REDACTED]" in out, out
        for fragment in kept:
            assert fragment in out, out


def test_values_that_are_not_secrets_survive_redaction():
    document = {
        "hostname": "gpu-01",
        "machine_id": "3f2b8c1e-5a4d-4e6f-9a7b-1c2d3e4f5a6b",
        "gpu_count": 2,
        "temp_c": 41.5,
        "healthy": True,
        "missing": None,
        "services": {"docker": "active", "vastai": "failed"},
        "note": "GPU 0 at 41 C, driver 550.120, token ring disabled, basic checks passed",
        "url": "https://console.vast.ai/api/v0/machines?page=2",
        "release": "HM-OS 0.1.0",
        "fingerprint": FINGERPRINT,
        "lines": ["first", "second"],
    }
    assert redact(document) == document
    assert redact(b"\x00\x01\x02") == "[3 bytes]"  # raw bytes are never copied into a log


# =============================================================================
# 15. Host guard and health
#
# Unknown Host -> 400 on ordinary GET routes and /healthz exempt is covered by
# test_access_control.py::test_unknown_host_header_is_refused.
# =============================================================================


@pytest.mark.parametrize(
    "host", ["api:8000", "10.0.0.5:8000", "attacker.example", "127.0.0.1.attacker.example"]
)
def test_only_the_liveness_probe_answers_a_host_outside_the_allowlist(app, host):
    with TestClient(app, base_url=f"http://{host}") as c:
        probe = c.get("/healthz")
        assert probe.status_code == 200 and probe.json()["status"] == "ok"
        for method, path in (
            ("GET", "/readyz"),
            ("GET", "/metrics"),
            ("GET", "/healthz/"),
            ("GET", "/dashboard"),
            ("POST", "/login"),
            ("POST", "/api/v1/auth/login"),
            ("POST", "/api/v1/devices/enroll"),
            ("POST", "/api/v1/device/heartbeat"),
        ):
            r = c.request(method, path, follow_redirects=False)
            assert r.status_code == 400, f"{method} {path} answered {r.status_code} for Host {host}"
            # The refusal still carries the request id and the security headers.
            assert re.fullmatch(r"[0-9a-f]{32}", r.headers["x-request-id"])
            assert r.headers["x-content-type-options"] == "nosniff"


def test_allowed_hosts_are_matched_without_the_port(app):
    for host in ("127.0.0.1", "127.0.0.1:8000", "localhost:9999"):
        with TestClient(app, base_url=f"http://{host}") as c:
            assert c.get("/readyz").status_code == 200, host


def test_readyz_is_ready_only_with_a_reachable_database_at_the_expected_revision(client, monkeypatch):
    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready", "mode": "demo", "schema": migrate.expected_revision()}

    monkeypatch.setattr(migrate, "expected_revision", lambda: "a-revision-not-applied-yet")
    pending = client.get("/readyz")
    assert pending.status_code == 503
    assert pending.json()["status"] == "not_ready" and pending.json()["schema"] == "migration pending"

    def unreachable():
        raise RuntimeError("could not connect to postgresql://hm:Sup3rS3cretPw@db/hm")

    monkeypatch.setattr(main_module, "get_engine", unreachable)
    down = client.get("/readyz")
    assert down.status_code == 503 and down.json() == {"status": "not_ready", "database": "unreachable"}
    assert client.get("/healthz").status_code == 200  # liveness does not depend on the database


def test_metrics_need_the_configured_bearer_token(client, world):
    # No token configured: closed to everybody, an admin session included.
    assert client.get("/metrics").status_code == 403
    assert client.get("/metrics", headers=world.auth(world.user("admin"))).status_code == 403

    token = "metrics-" + "m" * 32
    with app_client(make_settings(metrics_token=token)) as c:
        assert c.get("/metrics").status_code == 403
        assert c.get("/metrics", headers=bearer("metrics-" + "x" * 32)).status_code == 403
        assert c.get("/metrics", headers=world.auth(world.user("admin"))).status_code == 403
        assert c.get(f"/metrics?token={token}").status_code == 403
        scraped = c.get("/metrics", headers=bearer(token))
        assert scraped.status_code == 200 and "hm_http_requests_total" in scraped.text
        assert token not in scraped.text


# =============================================================================
# 16. 500 responses
# =============================================================================


class LogLines(logging.Handler):
    """Collects what the application's JSON formatter would write for each record."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(JsonFormatter().format(record))


def test_unhandled_error_is_a_generic_500_with_request_id_and_security_headers():
    app = create_app(make_settings(cookie_secure=True))  # so HSTS is part of the standard set
    leak = "could not connect to postgresql://hm:Sup3rS3cretPw@db/hm"

    @app.get("/__boom")
    def boom():
        raise RuntimeError(leak)

    @app.post("/api/v1/__boom")
    def api_boom():
        raise ZeroDivisionError(leak)

    log = LogLines()
    logging.getLogger("happymining.api").addHandler(log)
    try:
        with TestClient(app, base_url=BASE_URL, raise_server_exceptions=False) as c:
            page, api = c.get("/__boom"), c.post("/api/v1/__boom", json={})
            assert c.get("/healthz").status_code == 200  # the application keeps serving
    finally:
        logging.getLogger("happymining.api").removeHandler(log)

    for r in (page, api):
        assert r.status_code == 500
        assert envelope(r) == {"code": "internal_error", "message": "Internal error."}
        assert re.fullmatch(r"[0-9a-f]{32}", r.headers["x-request-id"])
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert r.headers["strict-transport-security"].startswith("max-age=")
        for fragment in (
            "Sup3rS3cretPw",
            "postgresql",
            "could not connect",
            "RuntimeError",
            "Division",
            "Traceback",
        ):
            assert fragment not in r.text
    assert api.headers["cache-control"] == "no-store"
    assert page.headers["x-request-id"] != api.headers["x-request-id"]

    # The operator gets the cause in the log, under the same request id, with the password scrubbed.
    errors = [json.loads(line) for line in log.lines if '"unhandled error"' in line]
    assert [e["request_id"] for e in errors] == [page.headers["x-request-id"], api.headers["x-request-id"]]
    assert [e["error_type"] for e in errors] == ["RuntimeError", "ZeroDivisionError"]
    for entry in errors:
        assert "could not connect" in entry["exc"] and "Sup3rS3cretPw" not in json.dumps(entry)


# =============================================================================
# 17. Body limit
#
# The device limit with a declared Content-Length is covered by
# test_pairing_devices.py::test_oversized_body_is_refused.
# =============================================================================


def padded_json(document: dict, size: int) -> bytes:
    """A valid JSON document followed by insignificant whitespace, ``size`` bytes in all."""
    body = json.dumps(document).encode()
    return body + b" " * (size - len(body))


def owner_names(world: World) -> set[str]:
    world.session.expire_all()
    return set(world.session.execute(select(Owner.display_name)).scalars())


def post_in_chunks(app, path: str, headers: dict[str, str], chunks: list[bytes]) -> tuple[int, bytes]:
    """POST straight to the ASGI application, the body arriving piece by piece as from a real server."""
    pending = list(chunks)
    sent: list[dict] = []

    async def receive() -> dict:
        if pending:
            chunk = pending.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(pending)}
        await asyncio.sleep(5)  # the connection stays open while the response is produced
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        sent.append(message)

    raw_headers = {"host": "127.0.0.1:8000", "transfer-encoding": "chunked", **headers}
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in raw_headers.items()],
        "client": ("203.0.113.5", 40000),
        "server": ("127.0.0.1", 8000),
    }
    asyncio.run(app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    return status, b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


def test_body_over_the_limit_is_refused_before_it_is_read(client, world):
    h = {**world.auth(world.user("admin")), "Content-Type": "application/json"}
    at_limit = client.post(
        "/api/v1/owners", headers=h, content=padded_json({"display_name": "At the limit"}, DEFAULT_BODY_LIMIT)
    )
    assert at_limit.status_code == 201
    over = client.post(
        "/api/v1/owners", headers=h, content=padded_json({"display_name": "Over"}, DEFAULT_BODY_LIMIT + 1)
    )
    assert over.status_code == 413
    assert envelope(over) == {"code": "payload_too_large", "message": "The request body is too large."}
    assert over.headers["x-content-type-options"] == "nosniff"
    assert owner_names(world) == {"At the limit"}


def test_body_limit_counts_a_body_sent_without_content_length(client, world):
    h = {**world.auth(world.user("admin")), "Content-Type": "application/json"}
    body = padded_json({"display_name": "Chunked"}, DEFAULT_BODY_LIMIT + 1)

    def stream() -> Iterator[bytes]:
        for start in range(0, len(body), 64 * 1024):
            yield body[start : start + 64 * 1024]

    r = client.post("/api/v1/owners", headers=h, content=stream())
    assert "content-length" not in r.request.headers
    assert r.request.headers["transfer-encoding"] == "chunked"
    assert r.status_code == 413 and envelope(r)["code"] == "payload_too_large"
    assert owner_names(world) == set()


def test_streamed_body_over_the_limit_is_not_processed(app, world):
    """A 413 has to mean "nothing happened", also when the body arrives in pieces."""
    h = {**world.auth(world.user("admin")), "content-type": "application/json"}
    piece = 64 * 1024

    def pieces(name: str, total: int) -> list[bytes]:
        body = padded_json({"display_name": name}, total)
        return [body[start : start + piece] for start in range(0, total, piece)]

    status, _ = post_in_chunks(
        app, "/api/v1/owners", h, pieces("Streamed within the limit", DEFAULT_BODY_LIMIT)
    )
    assert status == 201
    status, raw = post_in_chunks(app, "/api/v1/owners", h, pieces("Smuggled", DEFAULT_BODY_LIMIT + piece))
    assert status == 413 and json.loads(raw)["error"]["code"] == "payload_too_large"
    assert owner_names(world) == {"Streamed within the limit"}, (
        "the request was answered 413, but the part of its body received before the limit was executed"
    )


def test_device_routes_have_the_smaller_limit(client, world):
    enroll = {"pairing_code": "HM-ZZZZZZ-0000-0000-0000-0000", "machine_fingerprint": FINGERPRINT}
    json_headers = {"Content-Type": "application/json"}
    over = client.post(
        "/api/v1/devices/enroll", headers=json_headers, content=padded_json(enroll, DEVICE_BODY_LIMIT + 1)
    )
    assert over.status_code == 413 and envelope(over)["code"] == "payload_too_large"
    # At the limit the request is read and answered on its merits.
    at_limit = client.post(
        "/api/v1/devices/enroll", headers=json_headers, content=padded_json(enroll, DEVICE_BODY_LIMIT)
    )
    assert at_limit.status_code == 401 and envelope(at_limit)["code"] == "pairing_failed"
    # The same size is fine on a route for people, whose limit is 1 MiB.
    credentials = {"email": "nobody@test.invalid", "password": "a-wrong-password"}
    human = client.post(
        "/api/v1/auth/login", headers=json_headers, content=padded_json(credentials, DEVICE_BODY_LIMIT + 1)
    )
    assert human.status_code == 401


# =============================================================================
# 18. Dashboard robustness
# =============================================================================

SPARSE_PAYLOADS = [
    {},
    {"memory": {"total_bytes": 64 << 30}},  # no available_bytes, no gpus, no disks
    {"memory": {}, "gpus": [], "disks": []},
    {"memory": None, "gpus": None, "disks": None, "cpu": None, "services": None, "uptime_s": None},
    {"memory": {"available_bytes": None, "total_bytes": None}, "cpu": {"load1": None}},
    {"gpus": [{}], "disks": [{}], "cpu": {}},
    {
        "gpus": [{"index": 0, "name": None, "util_pct": None, "vram_used_mib": None}],
        "disks": [{"mount": "/", "fs": "ext4", "avail_bytes": None}],
    },
]


def test_machine_page_renders_when_the_agent_reports_partial_telemetry(app, client, world):
    owner = world.owner()
    machine, token = world.paired_machine(owner)
    partial = {
        "seq": 1,
        "collected_at": datetime.now(UTC).isoformat(),
        "synthetic": True,
        "memory": {"total_bytes": 64 << 30},
    }
    assert heartbeat(client, token, [partial]).json()["accepted"] == 1

    for user in (world.user("admin"), world.user("auditor"), world.user("owner", owner)):
        page = browser_for(app, user).get(f"/machines/{machine.id}")
        assert page.status_code == 200, f"{user.role}: {page.status_code}"
        assert "The agent reported no GPUs." in page.text and "n/a" in page.text
        assert "of 64.0 GiB" in page.text  # what was reported is still shown
    api = client.get(f"/api/v1/machines/{machine.id}/telemetry", headers=world.auth(world.user("admin")))
    assert api.status_code == 200 and api.json()["items"][0]["gpu_util_avg"] is None


@pytest.mark.parametrize("payload", SPARSE_PAYLOADS, ids=[json.dumps(p)[:60] for p in SPARSE_PAYLOADS])
def test_machine_page_renders_whatever_is_missing_from_the_stored_sample(app, client, world, payload):
    machine, token = world.paired_machine(world.owner())
    assert heartbeat(client, token, [sample(1)]).json()["accepted"] == 1
    stored = world.session.execute(select(TelemetrySample)).scalar_one()
    stored.payload = payload
    world.commit()
    page = browser_for(app, world.user("admin")).get(f"/machines/{machine.id}")
    assert page.status_code == 200, payload
    assert "Latest telemetry" in page.text and "n/a" in page.text


# =============================================================================
# 19. Trusted proxy hops
# =============================================================================


def failed_login_addresses(world: World) -> set[str]:
    return {row.ip for row in audit_rows(world, "auth.login_failed")}


def test_spoofed_forwarded_for_entry_does_not_dodge_the_login_limiter(world):
    stay_inside_one_window()
    with app_client(make_settings(login_rate_limit_per_minute=3, trusted_proxy_hops=1)) as c:
        codes = []
        for i in range(6):
            # What one proxy forwards: whatever the client claimed, then the address it really saw.
            forwarded = {"X-Forwarded-For": f"10.66.{i}.1, 203.0.113.9"}
            codes.append(
                login(c, f"nobody-{i}@test.invalid", "a-wrong-password", headers=forwarded).status_code
            )
    assert codes == [401, 401, 401, 429, 429, 429]
    assert failed_login_addresses(world) == {"203.0.113.9"}


def test_forwarded_for_is_ignored_when_no_proxy_is_trusted(world):
    stay_inside_one_window()
    with app_client(make_settings(login_rate_limit_per_minute=3, trusted_proxy_hops=0)) as c:
        codes = [
            login(
                c, f"nobody-{i}@test.invalid", "a-wrong-password", headers={"X-Forwarded-For": f"10.66.{i}.1"}
            ).status_code
            for i in range(6)
        ]
    assert codes == [401, 401, 401, 429, 429, 429]
    assert failed_login_addresses(world) == {"testclient"}  # the peer address, not the header


@pytest.mark.parametrize(
    ("hops", "forwarded", "expected"),
    [
        (0, "198.51.100.1", "192.0.2.10"),
        (0, None, "192.0.2.10"),
        (1, "198.51.100.1", "198.51.100.1"),
        (1, "10.66.0.1, 198.51.100.1", "198.51.100.1"),
        (1, "10.66.0.1,10.66.0.2 ,  198.51.100.1 ", "198.51.100.1"),
        (2, "10.66.0.1, 198.51.100.1, 172.16.0.2", "198.51.100.1"),
        (2, "198.51.100.1, 172.16.0.2", "198.51.100.1"),
        # Fewer entries than trusted hops: the request did not come through
        # them, so nothing in the header is believed.
        (2, "10.66.0.1", "192.0.2.10"),
        (1, "", "192.0.2.10"),
        (1, None, "192.0.2.10"),
        (1, " , ", "192.0.2.10"),
    ],
)
def test_client_address_comes_from_exactly_the_trusted_hops(hops, forwarded, expected):
    headers = [] if forwarded is None else [(b"x-forwarded-for", forwarded.encode())]
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": headers,
            "client": ("192.0.2.10", 40000),
            "app": SimpleNamespace(state=SimpleNamespace(settings=make_settings(trusted_proxy_hops=hops))),
        }
    )
    assert client_ip(request) == expected


# =============================================================================
# 20. CSRF and cookies
#
# One API route and one form are covered by test_access_control.py
# (test_cookie_session_needs_csrf_token_for_unsafe_requests,
# test_dashboard_forms_need_the_csrf_field, and
# test_secure_cookie_flag_follows_configuration for the Secure flag in LIVE).
# These walk every route instead.
# =============================================================================

PUBLIC_API = {
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/demo-login"),
    ("POST", "/api/v1/devices/enroll"),
}
SIGN_IN_FORMS = {"/login", "/demo-login"}


def every_form_field(today: str) -> dict[str, str]:
    """A valid value for every field any dashboard form declares, so each request reaches its handler."""
    return {
        "owner_id": UUID0,
        "machine_label": "rack-1",
        "machine_id": UUID0,
        "bound_from": today,
        "resolution": "looked into it",
        "rate_percent": "10",
        "effective_from": today,
        "note": "n",
        "provider_account_id": UUID0,
        "reference": "R-1",
        "received_on": today,
        "amount": "1.00",
        "evidence_source": "bank_statement",
        "evidence_note": "statement",
        "start": today,
        "end": today,
        "request_key": "k",
        "reason": "r",
        "account_holder": "A. Holder",
        "iban": "FR7630006000011234567890189",
        "bic": "",
        "idempotency_key": "csrf-walk-key-0001",
        "op_type": "refresh_inventory",
    }


def test_every_dashboard_form_post_is_refused_without_a_valid_csrf_token(app, world):
    admin = world.user("admin")
    browser = browser_for(app, admin)
    csrf = browser.get("/api/v1/auth/me").json()["csrf_token"]
    forms = [path for method, path in routes(app) if method == "POST" and not path.startswith("/api/")]
    expected = {
        "/logout",
        "/admin/pairing",
        "/admin/fees",
        "/machines/{machine_id}/operations",
        *SIGN_IN_FORMS,
    }
    assert set(forms) >= expected and len(forms) >= 15, forms

    fields = every_form_field(world.today.isoformat())
    audit_before = count(world, AuditLog)
    for path in forms:
        if path in SIGN_IN_FORMS:
            continue  # no session yet, so no token: see the cross-origin test below
        url = concrete(path)
        missing = browser.post(url, data=fields, follow_redirects=False)
        assert missing.status_code == 403, f"POST {path} without a token answered {missing.status_code}"
        assert "CSRF token" in missing.text
        wrong = browser.post(url, data={**fields, "csrf_token": "not-the-token"}, follow_redirects=False)
        assert wrong.status_code == 403 and "CSRF token" in wrong.text, path
        foreign = browser.post(
            url,
            data={**fields, "csrf_token": csrf},
            headers={"Origin": "https://attacker.example"},
            follow_redirects=False,
        )
        assert foreign.status_code == 403 and "cross-origin" in foreign.text, path

    # Nothing was done, and the session is still there (the logout form was refused too).
    assert count(world, AuditLog) == audit_before
    assert count(world, Owner) == 0 and count(world, Operation) == 0
    assert browser.get("/dashboard").status_code == 200
    # With the token the same kind of request goes through.
    out = browser.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert out.status_code == 303 and out.headers["location"] == "/login"


def test_every_unsafe_api_route_needs_the_csrf_header_when_the_session_is_a_cookie(app, world):
    admin = world.user("admin")
    browser = TestClient(app, base_url=BASE_URL)
    signed_in = browser.post("/api/v1/auth/demo-login", json={"email": admin.email})
    csrf = signed_in.json()["csrf_token"]
    unsafe = [
        (method, path)
        for method, path in routes(app)
        if path.startswith("/api/v1/")
        and method in UNSAFE
        and (method, path) not in PUBLIC_API
        and not path.startswith("/api/v1/device/")  # device credentials are bearer-only
        and not path.startswith("/api/v1/integration")  # so are API client tokens
    ]
    assert len(unsafe) > 30 and ("POST", "/api/v1/users/{user_id}/deactivate") in unsafe

    audit_before = count(world, AuditLog)
    for method, path in unsafe:
        url = concrete(path)
        for headers in (
            {},
            {"X-CSRF-Token": "not-the-token"},
            {"X-CSRF-Token": csrf, "Origin": "https://attacker.example"},
        ):
            r = browser.request(method, url, json={}, headers=headers)
            assert r.status_code == 403, f"{method} {path} answered {r.status_code} with {sorted(headers)}"
            assert envelope(r)["code"] == "csrf_failed", f"{method} {path}"
    assert count(world, AuditLog) == audit_before
    assert browser.get("/api/v1/auth/me").status_code == 200  # not logged out either

    # Reading needs no token; writing works with it, or with a bearer token and no cookie at all.
    assert browser.get("/api/v1/owners").status_code == 200
    with_token = browser.post("/api/v1/owners", json={"display_name": "A"}, headers={"X-CSRF-Token": csrf})
    assert with_token.status_code == 201
    by_bearer = TestClient(app, base_url=BASE_URL).post(
        "/api/v1/owners", json={"display_name": "B"}, headers=bearer(signed_in.json()["token"])
    )
    assert by_bearer.status_code == 201


def test_sign_in_forms_refuse_cross_origin_posts(app, world):
    user = world.user("auditor", demo=False, password=PASSWORD)
    demo_user = world.user("admin")
    foreign = {"Origin": "https://attacker.example"}
    browser = TestClient(app, base_url=BASE_URL)
    for path, form in (
        ("/login", {"email": user.email, "password": PASSWORD}),
        ("/demo-login", {"email": demo_user.email}),
    ):
        r = browser.post(path, data=form, headers=foreign, follow_redirects=False)
        assert r.status_code == 303 and unquote(r.headers["location"]).startswith("/login?err=cross-origin")
        assert "set-cookie" not in r.headers
    assert count(world, UserSession) == 0
    same_origin = browser.post(
        "/login",
        data={"email": user.email, "password": PASSWORD},
        headers={"Origin": BASE_URL},
        follow_redirects=False,
    )
    assert same_origin.status_code == 303 and same_origin.headers["location"] == "/dashboard"


@pytest.mark.parametrize("secure", [True, False])
def test_session_cookie_is_httponly_samesite_strict_and_secure_when_configured(world, secure):
    settings = make_settings(cookie_secure=secure)
    demo_user = world.user("admin")
    user = world.user("auditor", demo=False, password=PASSWORD)
    with app_client(settings) as c:
        responses = {
            "api demo login": c.post("/api/v1/auth/demo-login", json={"email": demo_user.email}),
            "api login": login(c, user.email),
            "demo form": c.post("/demo-login", data={"email": demo_user.email}, follow_redirects=False),
            "login form": c.post(
                "/login", data={"email": user.email, "password": PASSWORD}, follow_redirects=False
            ),
        }
    for name, r in responses.items():
        assert r.status_code in (200, 303), name
        headers = r.headers.get_list("set-cookie")
        assert len(headers) == 1, f"{name}: {headers}"  # the CSRF token is never put in a cookie
        (morsel,) = SimpleCookie(headers[0]).values()
        assert morsel.key == "hm_session" and morsel.value.startswith("hms_"), name
        assert morsel["httponly"] is True, name
        assert morsel["samesite"].lower() == "strict", name
        assert morsel["path"] == "/" and int(morsel["max-age"]) == settings.session_ttl_minutes * 60, name
        assert bool(morsel["secure"]) is secure, name
        assert ("strict-transport-security" in r.headers) is secure, name
    api = responses["api login"].json()
    assert api["csrf_token"] not in responses["api login"].headers["set-cookie"]
    assert api["csrf_token"] != api["token"]


# =============================================================================
# Follow-ups found while writing the tests above
# =============================================================================


def test_demo_refuses_to_hold_a_provider_credential():
    problems = make_settings(vast_api_key="vast-key-that-should-not-be-here").problems()
    assert any("HM_VAST_API_KEY is set in DEMO mode" in p for p in problems), problems
    assert make_settings(vast_api_key="").problems() == []
    assert make_settings(vast_api_key=None).problems() == []


def test_live_refuses_a_secret_with_whitespace_inside():
    phrase = STRONG_SECRET[:20] + " " + STRONG_SECRET[20:]
    refused_in_live("contains whitespace", secret_key=phrase)
    refused_in_live("contains whitespace", secret_key=STRONG_SECRET[:20] + "\t" + STRONG_SECRET[20:])


@pytest.mark.parametrize(
    "argv",
    [
        ["enroll-mfa", "ops@example.test"],
        ["set-password", "ops@example.test"],
        ["deactivate-user", "ops@example.test"],
        ["verify"],
    ],
)
def test_every_operator_command_refuses_a_database_of_the_other_mode(monkeypatch, capsys, world, argv):
    ensure_database_mode(world.settings)  # this database is a DEMO one
    monkeypatch.setattr(cli, "get_settings", lambda: live_settings())
    monkeypatch.setattr(cli, "_password", lambda: pytest.fail("went on to ask for a password"))
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("went on to ask for a code"))
    assert cli.main(argv) == 2
    assert "belongs to a DEMO deployment" in capsys.readouterr().err


def test_device_sending_invalid_requests_is_throttled_like_any_other(world):
    """The limit is counted when the device authenticates, before its body is looked at."""
    owner = world.owner()
    machine_a, token_a = world.paired_machine(owner, "a")
    _, token_b = world.paired_machine(owner, "b")
    settings = make_settings(device_request_rate_limit_per_minute=10)
    stay_inside_one_window()
    with app_client(settings) as c:
        rubbish = [
            c.post("/api/v1/device/heartbeat", headers=bearer(token_a), json={"samples": "no"}).status_code
            for _ in range(12)
        ]
        assert rubbish == [422] * 10 + [429] * 2
        # Every device route shares the budget...
        assert c.get("/api/v1/device/operations", headers=bearer(token_a)).status_code == 429
        assert c.get("/api/v1/device/self", headers=bearer(token_a)).status_code == 429
        # ...and it is per device.
        assert c.get("/api/v1/device/self", headers=bearer(token_b)).status_code == 200
    assert stored_seqs(world, machine_a) == []


def test_credential_rotation_is_limited_per_device(world):
    _, token = world.paired_machine(world.owner())
    settings = make_settings(device_rotation_limit_per_hour=2)
    with app_client(settings) as c:
        statuses = []
        for _ in range(3):
            r = c.post("/api/v1/device/credential/rotate", headers=bearer(token))
            statuses.append(r.status_code)
            if r.status_code == 200:
                token = r.json()["credential"]["token"]
        assert statuses == [200, 200, 429]
    world.session.expire_all()
    assert count(world, DeviceCredential) == 3  # the first one and two rotations, not a third


MORE_SECRET_STRINGS = [
    ("operator typed HM 7K2M9Q 4F8T ZP3D W6NH R5XA.", "4F8T", ["operator typed"]),
    ("operator typed 7K2M9Q-4F8T-ZP3D-W6NH-R5XA.", "4F8T", ["operator typed"]),
    ("operator typed 7k2m9q 4f8t zp3d w6nh r5xa.", "4f8t", ["operator typed"]),
    ("login failed: password=abc user=bob", "abc", ["login failed: password=", "user=bob"]),
    ('passphrase="correct horse battery staple" user=bob', "horse battery", ["passphrase=", "user=bob"]),
    ("x-api-key: k1 trailing", "k1", ["x-api-key:", "trailing"]),
    ("Authorization: Bearer short", "short", ["Authorization:"]),
    ("Cookie: theme=dark; sid=opaque-value-1", "opaque-value-1", ["Cookie:"]),
    ("Set-Cookie: sid=opaque-value-1; Path=/\nnext line", "opaque-value-1", ["Set-Cookie:", "next line"]),
]


@pytest.mark.parametrize(("raw", "secret", "kept"), MORE_SECRET_STRINGS)
def test_more_secrets_inside_strings_are_masked(raw, secret, kept):
    out = redact_text(raw)
    assert secret not in out and "[REDACTED]" in out, out
    for fragment in kept:
        assert fragment in out, out


def test_header_style_keys_are_masked():
    assert redact({"X-Api-Key": "k", "x-auth-token": "t", "Set-Cookie": "a=b", "db-passwd": "p", "n": 1}) == {
        "X-Api-Key": "[REDACTED]",
        "x-auth-token": "[REDACTED]",
        "Set-Cookie": "[REDACTED]",
        "db-passwd": "[REDACTED]",
        "n": 1,
    }


def test_delivered_operation_keeps_the_check_that_let_it_out(world):
    """Not even the stored gate decision of a delivered operation is rewritten by later polls."""
    machine, token, provider = fleet(world)
    settings = make_settings(**ENABLED)
    with app_client(settings) as c:
        operation = request_operation(world, settings, provider, machine, "restart_vast_daemon")
        (delivered,) = heartbeat(c, token, [sample(1)]).json()["operations"]
        assert delivered["id"] == str(operation.id)
        at_delivery = dict(stored_operation(world, operation.id).safety)
        assert at_delivery["recheck"]["allowed"] is True

        provider.dataset["machines"][0]["rental"] = dict(ACTIVE_CONTRACT)
        assert heartbeat(c, token, [sample(2)]).json()["operations"] == []
        assert c.get("/api/v1/device/operations", headers=bearer(token)).json() == {"operations": []}
    assert stored_operation(world, operation.id).safety == at_delivery


def test_forwarded_for_sent_as_several_header_lines_is_read_as_one_list(world):
    """A proxy may add its own X-Forwarded-For line instead of appending to the client's."""
    settings = make_settings(trusted_proxy_hops=1, login_rate_limit_per_minute=1000)
    with app_client(settings) as c:
        r = c.post(
            "/api/v1/auth/login",
            headers=[("X-Forwarded-For", "6.6.6.6"), ("X-Forwarded-For", "203.0.113.9")],
            json={"email": "nobody@example.test", "password": "wrong-password-123"},
        )
        assert r.status_code == 401
    assert failed_login_addresses(world) == {"203.0.113.9"}
