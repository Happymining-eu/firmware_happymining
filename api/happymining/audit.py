"""Append-only, hash-chained application audit trail.

Each row stores the hash of the previous row, so removing or editing a row in
the middle breaks the chain and ``verify_chain`` reports it. This is
tamper-evident only. Someone with direct database write access and the ability
to disable the triggers can rewrite the entire chain; protecting against that
needs an external anchor (for example shipping the head hash to a separate
system), which is described in docs/operations.md.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import AuditLog, utcnow
from .security import redact

_AUDIT_LOCK_KEY = 0x484D4155  # "HMAU"


@dataclass(frozen=True)
class Actor:
    type: str  # user | device | system
    id: str = ""
    ip: str = ""

    @classmethod
    def system(cls, name: str = "system") -> Actor:
        return cls("system", name)


def _digest(prev_hash: str, at: datetime, row: dict[str, Any]) -> str:
    material = json.dumps(
        {"prev": prev_hash, "at": at.astimezone(UTC).isoformat(), **row},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(material.encode()).hexdigest()


def audit(
    db: Session,
    actor: Actor,
    action: str,
    *,
    object_type: str = "",
    object_id: Any = "",
    owner_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Write one audit row inside the caller's transaction."""
    # Serialise writers so the chain has a single head. Held until commit.
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_LOCK_KEY})
    prev = db.execute(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1)).scalar_one_or_none() or ""
    at = utcnow()
    row = {
        "actor_type": actor.type,
        "actor_id": actor.id,
        "action": action,
        "object_type": object_type,
        "object_id": str(object_id or ""),
        "owner_id": str(owner_id) if owner_id else None,
        "ip": actor.ip,
        # Normalise to plain JSON so the stored value and the hashed value are identical.
        "details": json.loads(json.dumps(redact(details or {}), default=str)),
    }
    entry = AuditLog(
        at=at,
        actor_type=actor.type,
        actor_id=actor.id,
        action=action,
        object_type=object_type,
        object_id=row["object_id"],
        owner_id=owner_id,
        ip=actor.ip,
        details=row["details"],
        prev_hash=prev,
        hash=_digest(prev, at, row),
    )
    db.add(entry)
    db.flush()
    return entry


def verify_chain(db: Session, limit: int | None = None) -> dict[str, Any]:
    """Recompute the chain. Returns the first broken row id, if any."""
    query = select(AuditLog).order_by(AuditLog.id.asc())
    if limit:
        query = query.limit(limit)
    prev = ""
    count = 0
    for entry in db.execute(query).scalars():
        row = {
            "actor_type": entry.actor_type,
            "actor_id": entry.actor_id,
            "action": entry.action,
            "object_type": entry.object_type,
            "object_id": entry.object_id,
            "owner_id": str(entry.owner_id) if entry.owner_id else None,
            "ip": entry.ip,
            "details": entry.details,
        }
        if entry.prev_hash != prev or entry.hash != _digest(prev, entry.at, row):
            return {"ok": False, "checked": count, "first_broken_id": entry.id}
        prev = entry.hash
        count += 1
    return {"ok": True, "checked": count, "head_hash": prev}
