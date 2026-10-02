"""Shared fixtures. Every test runs against a real PostgreSQL database.

The database comes from HM_TEST_DATABASE_URL if set, otherwise from
``scripts/dev-postgres.sh start`` (Docker if available, else local binaries).
A dedicated ``happymining_test`` database is created, migrated once per session
with Alembic, and emptied between tests.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

REPO = Path(__file__).resolve().parents[2]
TEST_SECRET = "pytest-" + "k" * 40
TEST_FERNET = "cHl0ZXN0LWZpZWxkLWVuY3J5cHRpb24ta2V5LTAwMDA="  # 32 bytes, tests only
LIVE_DB_PASSWORD = "pytest-live-role-9f2c71d4"


def _base_database_url() -> str:
    url = os.environ.get("HM_TEST_DATABASE_URL")
    if url:
        return url
    env = dict(os.environ)
    if os.geteuid() == 0 and "HM_DEV_PG_DIR" not in env and Path("/var/lib/postgresql").is_dir():
        env["HM_DEV_PG_DIR"] = "/var/lib/postgresql/hm-dev"
    out = subprocess.run(
        [str(REPO / "scripts" / "dev-postgres.sh"), "start"],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return out.stdout.strip().splitlines()[-1]


def _prepare_database() -> str:
    """Create a fresh test database. HM_TEST_DB_NAME lets parallel runs use separate ones."""
    name = os.environ.get("HM_TEST_DB_NAME", "happymining_test")
    if not name.replace("_", "").isalnum():
        raise RuntimeError("HM_TEST_DB_NAME must be alphanumeric with underscores")
    base = make_url(_base_database_url())
    test_url = base.set(database=name)
    admin = create_engine(base, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        conn.execute(text(f'CREATE DATABASE "{name}"'))
        # A second role whose password is not a known development default, so
        # that LIVE-mode settings pass the start-up guard in tests.
        exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = 'hm_live_test'")).first()
        verb = "ALTER" if exists else "CREATE"
        conn.execute(text(f"{verb} ROLE hm_live_test LOGIN SUPERUSER PASSWORD '{LIVE_DB_PASSWORD}'"))
    admin.dispose()
    return test_url.render_as_string(hide_password=False)


# Configure the process before anything imports the application.
_TEST_DB = _prepare_database()
os.environ.update(
    {
        "HM_MODE": "demo",
        "HM_PROVIDER": "fake",
        "HM_DATABASE_URL": _TEST_DB,
        "HM_SECRET_KEY": TEST_SECRET,
        "HM_FIELD_ENCRYPTION_KEY": TEST_FERNET,
        "HM_DEMO_LOGIN_ENABLED": "true",
        "HM_COOKIE_SECURE": "false",
        "HM_PAYOUTS_ENABLED": "true",
        "HM_PAYOUT_PROVIDER": "mock",
        "HM_PAYOUT_REQUIRE_DISTINCT_APPROVER": "false",
        "HM_PUBLIC_BASE_URL": "http://127.0.0.1:8000",
        "HM_ALLOWED_HOSTS": "127.0.0.1,localhost",
        "HM_LOGIN_RATE_LIMIT_PER_MINUTE": "1000",
        "HM_PAIRING_RATE_LIMIT_PER_MINUTE": "1000",
        "HM_DEVICE_HEARTBEAT_RATE_LIMIT_PER_MINUTE": "100000",
        "HM_DEVICE_REQUEST_RATE_LIMIT_PER_MINUTE": "100000",
        "HM_DEVICE_ROTATION_LIMIT_PER_HOUR": "100000",
    }
)
for _stale in ("HM_VAST_API_KEY", "HM_VAST_COMMERCIAL_AUTHORIZATION_REF", "HM_DISRUPTIVE_OPERATIONS_ENABLED"):
    os.environ.pop(_stale, None)

os.environ["HM_TEST_LIVE_DATABASE_URL"] = (
    make_url(_TEST_DB)
    .set(username="hm_live_test", password=LIVE_DB_PASSWORD)
    .render_as_string(hide_password=False)
)

from fastapi.testclient import TestClient  # noqa: E402
from helpers import BASE_URL, World  # noqa: E402

from happymining import migrate  # noqa: E402
from happymining.config import Settings, get_settings  # noqa: E402
from happymining.db import get_engine, session_factory  # noqa: E402
from happymining.main import create_app  # noqa: E402
from happymining.models import Base  # noqa: E402
from happymining.providers import registry  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _migrated() -> Iterator[None]:
    migrate.upgrade(_TEST_DB)
    yield
    get_engine().dispose()


@pytest.fixture(autouse=True)
def _clean() -> Iterator[None]:
    """Empty every table before each test (append-only triggers are bypassed here only)."""
    registry.set_override(None)
    tables = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
    with get_engine().begin() as conn:
        conn.execute(text("SET session_replication_role = replica"))
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
        conn.execute(text("SET session_replication_role = DEFAULT"))
    yield
    registry.set_override(None)


@pytest.fixture
def settings() -> Settings:
    return get_settings()


@pytest.fixture
def db():
    session = session_factory()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app, base_url=BASE_URL) as c:
        yield c


@pytest.fixture
def world(settings) -> Iterator[World]:
    w = World(settings)
    try:
        yield w
    finally:
        w.close()
