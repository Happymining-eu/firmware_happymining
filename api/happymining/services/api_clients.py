"""Integration API clients: other software allowed to call the integration API.

An API client is a third kind of caller, next to people (sessions) and agents
(device credentials). The first one is Mole Hash, the fleet manager HappyMining
already uses for ASIC miners, so that AI servers can be watched and managed
from the same place.

What a client can do is fixed by the scopes an admin gave it, and by what the
integration API offers at all: reading the fleet, its telemetry, its
operations and its earnings, and requesting the same typed operations an admin
can request, through the same rental-protection gate. It cannot move money,
create users or pairing codes, bind provider machines, or read beneficiary
details. There is no scope for any of those.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..config import Settings
from ..db import get_engine, lock_row
from ..errors import ClientUnauthorized, Conflict, InvalidRequest, NotFound
from ..models import API_CLIENT_SCOPES, ApiClient, Operation, Owner, utcnow
from ..security import (
    client_secret_hash,
    constant_time_equal,
    format_client_token,
    new_client_secret,
    parse_client_token,
)

SCOPE_HELP: dict[str, str] = {
    "fleet:read": "List machines, their connection state, hardware and provider binding.",
    "telemetry:read": "Read GPU, CPU, memory, disk and service telemetry.",
    "operations:read": "List operations and their results.",
    "operations:write": "Request and cancel non-disruptive typed operations.",
    "operations:disruptive": (
        "Also request operations that can interrupt a renter (daemon restart, reboot). "
        "Still subject to the server switch, the rental-protection gate and the machine's own settings."
    ),
    "earnings:read": "Read reported and received earnings per machine and day.",
    "appliance:read": "Read a machine's mode, plugins, indexing, backup and update state. Changes nothing.",
}
MAX_TTL_DAYS = 730
# How often "last used" is written. Not on every request: it is a hint for
# operators, not an access log.
LAST_USED_RESOLUTION_S = 60


@dataclass(frozen=True)
class ClientPrincipal:
    client: ApiClient

    @property
    def scopes(self) -> frozenset[str]:
        return frozenset(self.client.scopes or ())

    @property
    def owner_id(self) -> uuid.UUID | None:
        return self.client.owner_id

    def actor(self, ip: str = "") -> Actor:
        return Actor("client", str(self.client.id), ip)


@dataclass(frozen=True)
class IssuedClient:
    client: ApiClient
    token: str  # shown once, never stored


def _clean_scopes(scopes: list[str] | tuple[str, ...]) -> list[str]:
    wanted = {str(s).strip() for s in scopes if str(s).strip()}
    unknown = sorted(wanted - set(API_CLIENT_SCOPES))
    if unknown:
        raise InvalidRequest(
            "unknown scope(s): " + ", ".join(unknown) + "; allowed: " + ", ".join(API_CLIENT_SCOPES)
        )
    if not wanted:
        raise InvalidRequest("at least one scope is required")
    if "operations:disruptive" in wanted and "operations:write" not in wanted:
        raise InvalidRequest("operations:disruptive needs operations:write as well")
    # Stored in the canonical order, so two clients with the same rights look the same.
    return [s for s in API_CLIENT_SCOPES if s in wanted]


def create_client(
    db: Session,
    settings: Settings,
    actor: Actor,
    *,
    name: str,
    scopes: list[str],
    description: str = "",
    owner_id: uuid.UUID | None = None,
    expires_in_days: int | None = None,
    created_by: uuid.UUID | None = None,
) -> IssuedClient:
    """Register a client and return its token. The token is not stored and cannot be shown again."""
    name = (name or "").strip()
    if not (1 <= len(name) <= 120):
        raise InvalidRequest("a name of 1 to 120 characters is required")
    clean = _clean_scopes(scopes)
    if owner_id is not None and db.get(Owner, owner_id) is None:
        raise NotFound("no such owner")
    if expires_in_days is not None and not (1 <= expires_in_days <= MAX_TTL_DAYS):
        raise InvalidRequest(f"expires_in_days must be between 1 and {MAX_TTL_DAYS}")
    if db.execute(select(ApiClient.id).where(ApiClient.name == name)).first() is not None:
        raise Conflict("an API client with this name already exists")
    secret = new_client_secret()
    now = utcnow()
    client = ApiClient(
        name=name,
        description=(description or "").strip()[:500],
        scopes=clean,
        owner_id=owner_id,
        secret_hash=client_secret_hash(settings, secret),
        status="active",
        created_by=created_by,
        created_at=now,
        expires_at=now + timedelta(days=expires_in_days) if expires_in_days else None,
    )
    try:
        with db.begin_nested():
            db.add(client)
            db.flush()
    except IntegrityError as exc:
        # Lost a race with a request creating the same name.
        raise Conflict("the API client could not be created; the name may already be in use") from exc
    audit(
        db,
        actor,
        "api_client.create",
        object_type="api_client",
        object_id=client.id,
        owner_id=owner_id,
        details={
            "name": name,
            "scopes": clean,
            "expires_at": client.expires_at.isoformat() if client.expires_at else None,
        },
    )
    return IssuedClient(client=client, token=format_client_token(client.id, secret))


def rotate_client(db: Session, settings: Settings, actor: Actor, client_id: uuid.UUID) -> IssuedClient:
    """Replace the secret. The old token stops working at once."""
    client = lock_row(db, ApiClient, client_id)
    if client is None:
        raise NotFound()
    if client.status != "active":
        raise Conflict("a revoked client cannot be rotated; create a new one")
    if client.expires_at is not None and client.expires_at <= utcnow():
        # A new secret would be issued for a client that still cannot sign in.
        raise Conflict("this client has expired; create a new one")
    secret = new_client_secret()
    client.secret_hash = client_secret_hash(settings, secret)
    client.rotated_at = utcnow()
    db.flush()
    audit(db, actor, "api_client.rotate", object_type="api_client", object_id=client.id)
    return IssuedClient(client=client, token=format_client_token(client.id, secret))


def revoke_client(db: Session, actor: Actor, client_id: uuid.UUID, reason: str = "") -> ApiClient:
    """Switch a client off for good and cancel whatever it had queued and not yet delivered."""
    client = lock_row(db, ApiClient, client_id)
    if client is None:
        raise NotFound()
    if client.status == "revoked":
        return client
    if not reason.strip():
        raise InvalidRequest("a reason is required")
    now = utcnow()
    client.status = "revoked"
    client.revoked_at = now
    cancelled = (
        db.execute(
            update(Operation)
            .where(Operation.requested_by_client == client.id, Operation.status == "pending")
            .values(status="cancelled", completed_at=now, detail="the requesting API client was revoked")
        ).rowcount
        or 0
    )
    db.flush()
    audit(
        db,
        actor,
        "api_client.revoke",
        object_type="api_client",
        object_id=client.id,
        details={"reason": reason[:300], "operations_cancelled": cancelled},
    )
    return client


def list_clients(db: Session) -> list[ApiClient]:
    return list(db.execute(select(ApiClient).order_by(ApiClient.created_at)).scalars())


def authenticate_client(db: Session, settings: Settings, token: str, ip: str = "") -> ClientPrincipal:
    """Resolve a bearer token to an API client. Every failure is the same error."""
    parsed = parse_client_token(token)
    if parsed is None:
        raise ClientUnauthorized()
    client_id, secret = parsed
    client = db.get(ApiClient, client_id)
    presented = client_secret_hash(settings, secret)
    # Compare even when the client is unknown, to keep timing flat.
    if not constant_time_equal(client.secret_hash if client else "0" * 64, presented) or client is None:
        raise ClientUnauthorized()
    now = utcnow()
    if not is_usable(client, now):
        raise ClientUnauthorized()
    # Give the session's connection back before anything below takes another
    # one from the pool. Holding one while waiting for a second is how a burst
    # of requests would otherwise exhaust the pool and stall the whole API.
    # Nothing is pending on the session at this point.
    db.commit()
    if client.last_used_at is None or (now - client.last_used_at).total_seconds() >= LAST_USED_RESOLUTION_S:
        # In its own short transaction: read-only routes never commit theirs.
        with get_engine().begin() as conn:
            conn.execute(
                update(ApiClient)
                .where(ApiClient.id == client.id)
                .values(last_used_at=now, last_used_ip=ip[:64])
            )
    return ClientPrincipal(client=client)


def is_usable(client: ApiClient | None, now=None) -> bool:
    now = now or utcnow()
    return (
        client is not None
        and client.status == "active"
        and (client.expires_at is None or client.expires_at > now)
    )


def ensure_still_active(db: Session, client_id: uuid.UUID) -> None:
    """Re-check a client inside the transaction that is about to act for it.

    Authentication read the client without a lock, possibly a moment before an
    admin revoked it. This takes a key-share lock on the row, which waits for a
    revocation in progress, and reads the committed state. Called after the
    work is flushed and before it is committed: either the revocation sees and
    cancels what was just queued, or this sees the revocation and refuses.
    """
    client = db.execute(
        select(ApiClient)
        .where(ApiClient.id == client_id)
        .with_for_update(key_share=True, read=True)
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if not is_usable(client):
        raise ClientUnauthorized()


def client_view(client: ApiClient) -> dict[str, object]:
    """What may be shown about a client. Never the secret or its hash."""
    now = utcnow()
    expired = client.expires_at is not None and client.expires_at <= now
    return {
        "id": str(client.id),
        "name": client.name,
        "description": client.description,
        "scopes": list(client.scopes or ()),
        "owner_id": str(client.owner_id) if client.owner_id else None,
        "status": "expired" if client.status == "active" and expired else client.status,
        "token_prefix": f"hmc_{client.id.hex[:8]}",
        "created_at": client.created_at.isoformat(),
        "expires_at": client.expires_at.isoformat() if client.expires_at else None,
        "rotated_at": client.rotated_at.isoformat() if client.rotated_at else None,
        "revoked_at": client.revoked_at.isoformat() if client.revoked_at else None,
        "last_used_at": client.last_used_at.isoformat() if client.last_used_at else None,
        "last_used_ip": client.last_used_ip,
    }
