"""Which mode a database belongs to.

DEMO data is synthetic and must never be paid; LIVE data is real and must never
be opened with the passwordless demo login. The start-up guard checks the
configuration; this checks the *database*: the first process to use a database
records its mode, and any process configured for the other mode refuses to
start against it.
"""

from __future__ import annotations

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..config import ConfigError, Settings
from ..db import lock_row, session_scope
from ..models import SystemInfo, utcnow

MODE_KEY = "mode"


def claim_database_mode(db: Session, settings: Settings) -> str:
    """Record this database's mode on first use; refuse if it belongs to the other one."""
    db.execute(
        pg_insert(SystemInfo)
        .values(key=MODE_KEY, value=settings.mode, updated_at=utcnow())
        .on_conflict_do_nothing(index_elements=["key"])
    )
    row = lock_row(db, SystemInfo, MODE_KEY)
    assert row is not None
    if row.value != settings.mode:
        raise ConfigError(
            f"refusing to start in {settings.mode.upper()} mode: this database belongs to a "
            f"{row.value.upper()} deployment. DEMO and LIVE never share a database."
        )
    return row.value


def ensure_database_mode(settings: Settings) -> None:
    with session_scope() as db:
        claim_database_mode(db, settings)
