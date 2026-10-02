"""Persistent background worker.

One process, a simple loop, and a PostgreSQL advisory lock per job so that two
workers never run the same job at once. Jobs:

- expire overdue pairing codes and operations;
- refresh the provider machine inventory;
- import provider earnings for recent closed UTC days (revision-aware);
- purge old rate-limit counters.

Provider failures are recorded as failed or blocked runs and surface in the
integration-health view. The worker never substitutes demo data for a provider
that is unavailable or not configured.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from . import ratelimit
from .audit import Actor
from .config import ConfigError, Settings, get_settings
from .db import session_scope
from .logging_setup import configure_logging
from .models import ProviderAccount, SyncRun
from .providers.registry import get_provider
from .services import devices, operations, pairing, provider_sync
from .services.system import ensure_database_mode

log = logging.getLogger("happymining.worker")


def _with_lock(db: Session, name: str, fn: Callable[[], object]) -> object | None:
    """Run ``fn`` only if no other worker holds the lock for ``name``."""
    got = db.execute(
        text("SELECT pg_try_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": f"job:{name}"}
    ).scalar_one()
    if not got:
        return None
    return fn()


def _due(db: Session, account_id, kind: str, interval_s: int) -> bool:
    last = db.execute(
        select(SyncRun.started_at)
        .where(SyncRun.provider_account_id == account_id, SyncRun.kind == kind)
        .order_by(SyncRun.started_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    return last is None or datetime.now(UTC) - last >= timedelta(seconds=interval_s)


def job_expire(settings: Settings) -> None:
    with session_scope() as db:
        n1 = _with_lock(db, "expire", lambda: (pairing.expire_stale(db), operations.expire_stale(db)))
        if n1 and any(n1):
            log.info("expired stale items", extra={"enrollments": n1[0], "operations": n1[1]})
    ratelimit.purge_old()
    with session_scope() as db:
        purged = _with_lock(db, "telemetry-retention", lambda: devices.purge_old_telemetry(db, settings))
        if purged:
            log.info("purged old telemetry", extra={"rows": purged})


def job_provider(settings: Settings) -> None:
    try:
        provider = get_provider(settings)
    except ConfigError as exc:
        log.error("provider configuration error", extra={"error": str(exc)})
        return
    with session_scope() as db:
        account = provider_sync.ensure_account(db, settings, provider)
        account_id = account.id

    with session_scope() as db:
        account = db.get(ProviderAccount, account_id)

        def machines():
            if _due(db, account_id, "machines", settings.worker_machine_sync_interval_s):
                run = provider_sync.sync_machines(db, provider, account)
                log.info(
                    "machine sync",
                    extra={"status": run.status, "error_code": run.error_code, "stats": run.stats},
                )

        _with_lock(db, "provider-machines", machines)

    with session_scope() as db:
        account = db.get(ProviderAccount, account_id)

        def earnings():
            if _due(db, account_id, "earnings", settings.worker_earnings_import_interval_s):
                today = datetime.now(UTC).date()
                run, imp = provider_sync.run_earnings_import(
                    db,
                    Actor.system("worker"),
                    provider,
                    account,
                    start=today - timedelta(days=settings.worker_earnings_lookback_days),
                    end=today - timedelta(days=1),
                    user_id=None,
                )
                log.info(
                    "earnings import",
                    extra={
                        "status": run.status,
                        "error_code": run.error_code,
                        "import_status": imp.status if imp else None,
                        "stats": run.stats,
                    },
                )

        _with_lock(db, "provider-earnings", earnings)


def run_once(settings: Settings) -> None:
    for job in (job_expire, job_provider):
        try:
            job(settings)
        except Exception:
            # One failing job must not stop the others or the loop.
            log.exception("worker job failed", extra={"job": job.__name__})


def main() -> None:
    settings = get_settings()
    settings.validate_for_startup()
    configure_logging(settings.log_level)
    ensure_database_mode(settings)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    log.info("worker started", extra={"mode": settings.mode, "provider": settings.provider})
    while not stop.is_set():
        started = time.monotonic()
        run_once(settings)
        stop.wait(max(1.0, settings.worker_tick_s - (time.monotonic() - started)))
    log.info("worker stopped")


if __name__ == "__main__":
    main()
