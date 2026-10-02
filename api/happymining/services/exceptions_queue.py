"""The exception queue: things a human must resolve before money can move."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..db import lock_row
from ..errors import Conflict, InvalidRequest, NotFound
from ..models import ExceptionItem, utcnow


def raise_exception(
    db: Session,
    kind: str,
    summary: str,
    *,
    dedupe_key: str | None = None,
    details: dict[str, Any] | None = None,
    provider_account_id: uuid.UUID | None = None,
    owner_id: uuid.UUID | None = None,
) -> ExceptionItem | None:
    """Open an exception. With a ``dedupe_key`` the same problem is recorded once."""
    values = {
        "id": uuid.uuid4(),
        "kind": kind,
        "status": "open",
        "dedupe_key": dedupe_key,
        "summary": summary[:500],
        "details": details or {},
        "provider_account_id": provider_account_id,
        "owner_id": owner_id,
        "created_at": utcnow(),
        "resolution": "",
    }
    stmt = pg_insert(ExceptionItem).values(**values)
    if dedupe_key:
        stmt = stmt.on_conflict_do_nothing(index_elements=["dedupe_key"])
    db.execute(stmt)
    db.flush()
    return db.execute(select(ExceptionItem).where(ExceptionItem.id == values["id"])).scalar_one_or_none()


def resolve_by_key(db: Session, dedupe_key: str, resolution: str, user_id: uuid.UUID | None = None) -> None:
    item = db.execute(
        select(ExceptionItem).where(ExceptionItem.dedupe_key == dedupe_key, ExceptionItem.status == "open")
    ).scalar_one_or_none()
    if item:
        item.status = "resolved"
        item.resolution = resolution[:1000]
        item.resolved_by = user_id
        item.resolved_at = utcnow()
        # Free the key so the same problem can be reported again if it recurs.
        item.dedupe_key = None
        db.flush()


def resolve(
    db: Session, actor: Actor, exception_id: uuid.UUID, resolution: str, user_id: uuid.UUID
) -> ExceptionItem:
    if not resolution.strip():
        raise InvalidRequest("a resolution note is required")
    item = lock_row(db, ExceptionItem, exception_id)
    if not item:
        raise NotFound()
    if item.status != "open":
        raise Conflict("this exception is already resolved")
    if item.kind == "over_received":
        _require_recovered(db, item)
    item.status = "resolved"
    item.resolution = resolution[:1000]
    item.resolved_by = user_id
    item.resolved_at = utcnow()
    item.dedupe_key = None
    audit(
        db,
        actor,
        "exception.resolve",
        object_type="exception",
        object_id=item.id,
        details={"kind": item.kind},
    )
    db.flush()
    return item


def _require_recovered(db: Session, item: ExceptionItem) -> None:
    """An over-received day is not closed with a note.

    It closes by itself once the allocation is corrected. Until then the money
    is still out, so the exception stays open and the owner stays held.
    """
    from ..models import EarningBucket

    raw = (item.details or {}).get("bucket_id")
    try:
        bucket = db.get(EarningBucket, uuid.UUID(str(raw))) if raw else None
    except ValueError:
        bucket = None
    if bucket is not None and bucket.received_amount > max(bucket.reported_amount, 0):
        raise Conflict(
            f"this day still has {bucket.received_amount} received against {bucket.reported_amount} "
            "reported; de-allocate the difference from the receipt first. The exception closes itself "
            "when that is done."
        )
