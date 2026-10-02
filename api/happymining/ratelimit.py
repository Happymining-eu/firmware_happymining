"""Fixed-window rate limiting backed by PostgreSQL.

Counters live in the database so the limit holds across API processes. Each
check runs in its own short transaction, so a failed request still counts.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from .db import get_engine
from .errors import RateLimited


def hit(key: str, limit: int, window_s: int = 60) -> None:
    """Count one attempt for ``key``; raise RateLimited once over ``limit``."""
    now = datetime.now(UTC)
    window = now.replace(microsecond=0) - timedelta(seconds=int(now.timestamp()) % window_s)
    with get_engine().begin() as conn:
        count = conn.execute(
            text(
                "INSERT INTO rate_limit_counters (key, window_start, count) VALUES (:k, :w, 1) "
                "ON CONFLICT (key, window_start) DO UPDATE SET count = rate_limit_counters.count + 1 "
                "RETURNING count"
            ),
            {"k": key[:200], "w": window},
        ).scalar_one()
    if count > limit:
        elapsed = int(now.timestamp()) % window_s
        raise RateLimited(retry_after_s=max(1, window_s - elapsed))


def purge_old(max_age_s: int = 3600) -> int:
    cutoff = datetime.now(UTC) - timedelta(seconds=max_age_s)
    with get_engine().begin() as conn:
        result = conn.execute(text("DELETE FROM rate_limit_counters WHERE window_start < :c"), {"c": cutoff})
    return result.rowcount or 0
