"""Database engine and session handling.

Request handlers get a session from ``get_db`` and call ``db.commit()``
themselves once the whole unit of work has succeeded. Nothing is committed
implicitly: an exception anywhere rolls the transaction back.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings

_engine: Engine | None = None
_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine, _factory
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=10,
            future=True,
        )
        _factory = sessionmaker(bind=_engine, expire_on_commit=False, autoflush=True)
    return _engine


def session_factory() -> sessionmaker[Session]:
    get_engine()
    assert _factory is not None
    return _factory


def dispose_engine() -> None:
    global _engine, _factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _factory = None


def get_db() -> Iterator[Session]:
    """FastAPI dependency. The caller commits; this only cleans up."""
    db = session_factory()()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Commit-on-success scope for the worker, the CLI and tests."""
    db = session_factory()()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def lock_row(db: Session, model: type, key: object):
    """``SELECT ... FOR UPDATE`` by primary key, always returning current values.

    ``Session.get(..., with_for_update=True)`` takes the row lock but does not
    refresh an instance that is already loaded in the session, so a check made
    after it could run on values read before the lock. ``populate_existing``
    closes that gap. Pending changes are flushed first so they are not lost.
    """
    db.flush()
    return db.get(model, key, with_for_update=True, populate_existing=True)
