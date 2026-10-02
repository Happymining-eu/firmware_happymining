"""Request dependencies: who is calling and what they may see.

Authorization is enforced here and in the scoped loaders below, for every
route. The rule for tenant data is simple: an owner-role user can only ever
load objects whose ``owner_id`` is their own; anything else is reported as
"not found", so object ids cannot be probed.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from urllib.parse import urlsplit

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from . import ratelimit
from .config import Settings
from .db import get_db, lock_row
from .errors import ClientUnauthorized, Forbidden, NotFound
from .models import Machine, Owner
from .security import SESSION_PREFIX, constant_time_equal
from .services.accounts import Principal, resolve_session
from .services.api_clients import ClientPrincipal, authenticate_client
from .services.devices import DevicePrincipal, authenticate_device

log = logging.getLogger("happymining.auth")

SESSION_COOKIE = "hm_session"
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def settings_dep(request: Request) -> Settings:
    """Settings of the running application instance."""
    return request.app.state.settings


def client_ip(request: Request) -> str:
    """Client address. X-Forwarded-For is honoured only for configured proxy hops."""
    settings: Settings = request.app.state.settings
    peer = request.client.host if request.client else ""
    hops = settings.trusted_proxy_hops
    if hops > 0:
        # Every X-Forwarded-For line counts: a proxy may add its entry as a
        # separate header line instead of appending to the client's.
        lines = ",".join(request.headers.getlist("x-forwarded-for"))
        forwarded = [p.strip() for p in lines.split(",") if p.strip()]
        if len(forwarded) >= hops:
            return forwarded[-hops][:64]
    return peer[:64]


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    return value.strip() if scheme.lower() == "bearer" else ""


def _same_origin(request: Request, settings: Settings) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True  # non-browser client, or same-origin form without the header
    allowed = {settings.public_base_url.rstrip("/"), *[o.rstrip("/") for o in settings.cors_allowed_origins]}
    parts = urlsplit(origin)
    return f"{parts.scheme}://{parts.netloc}" in allowed


def get_principal(
    request: Request, db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)
) -> Principal:
    """Authenticate a human by bearer session token or session cookie.

    Cookie-authenticated unsafe requests must also carry the session's CSRF
    token in ``X-CSRF-Token`` and come from an allowed origin. Bearer requests
    are not ambient, so they need no CSRF token.
    """
    bearer = _bearer(request)
    if bearer.startswith(SESSION_PREFIX):
        principal = resolve_session(db, settings, bearer, via_cookie=False)
    else:
        cookie = request.cookies.get(SESSION_COOKIE, "")
        principal = resolve_session(db, settings, cookie, via_cookie=True)
        if request.method in UNSAFE_METHODS:
            if not _same_origin(request, settings):
                raise Forbidden("cross-origin request refused", code="csrf_failed")
            supplied = request.headers.get("x-csrf-token", "")
            if not supplied or not constant_time_equal(supplied, principal.session.csrf_token):
                raise Forbidden("missing or invalid CSRF token", code="csrf_failed")
    request.state.principal = principal
    return principal


def require_roles(*roles: str) -> Callable[..., Principal]:
    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if principal.role not in roles:
            raise Forbidden()
        return principal

    return dependency


require_admin = require_roles("admin")
require_admin_or_auditor = require_roles("admin", "auditor")
require_any = require_roles("admin", "auditor", "owner")


def get_device(
    request: Request, db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)
) -> DevicePrincipal:
    principal = authenticate_device(db, settings, _bearer(request))
    request.state.device = principal
    # The credential bookkeeping is committed here, which also hands the
    # session's connection back: the rate limiter takes its own connection, and
    # a request must never hold one while waiting for another.
    db.commit()
    # Counted here, before the body is validated, so that a device sending
    # rubbish is throttled like one sending valid requests.
    ratelimit.hit(f"device:{principal.device.id}", settings.device_request_rate_limit_per_minute)
    return principal


def get_heartbeat_device(
    principal: DevicePrincipal = Depends(get_device), settings: Settings = Depends(settings_dep)
) -> DevicePrincipal:
    ratelimit.hit(f"heartbeat:{principal.device.id}", settings.device_heartbeat_rate_limit_per_minute)
    return principal


# --- integration API clients -----------------------------------------------


def get_api_client(
    request: Request, db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)
) -> ClientPrincipal:
    """Authenticate another system by its API client token. Bearer only: no cookie, no session."""
    ip = client_ip(request)
    try:
        principal = authenticate_client(db, settings, _bearer(request), ip)
    except ClientUnauthorized:
        # Guessing a 256-bit secret is hopeless, but a stream of refused tokens
        # is worth slowing down and worth a line in the log.
        db.rollback()
        log.warning("integration API: token refused", extra={"ip": ip})
        ratelimit.hit(f"client-auth-fail:{ip}", settings.integration_auth_failure_limit_per_minute)
        raise
    request.state.api_client = principal
    ratelimit.hit(f"client:{principal.client.id}", settings.integration_rate_limit_per_minute)
    return principal


def require_scope(scope: str) -> Callable[..., ClientPrincipal]:
    def dependency(principal: ClientPrincipal = Depends(get_api_client)) -> ClientPrincipal:
        if scope not in principal.scopes:
            raise Forbidden(f"this API client does not have the {scope} scope")
        return principal

    return dependency


def load_client_machine(
    db: Session, principal: ClientPrincipal, machine_id: uuid.UUID, *, lock: bool = False
) -> Machine:
    """A machine the client may see. Anything outside its owner scope does not exist for it."""
    machine = lock_row(db, Machine, machine_id) if lock else db.get(Machine, machine_id)
    if machine is None or (principal.owner_id is not None and machine.owner_id != principal.owner_id):
        raise NotFound()
    return machine


# --- tenant scoping --------------------------------------------------------


def scoped_owner_id(principal: Principal, requested: uuid.UUID | None) -> uuid.UUID | None:
    """The owner filter to apply. Owners are pinned to themselves; staff may pass any or none."""
    if principal.role == "owner":
        if requested is not None and requested != principal.owner_id:
            raise NotFound()
        return principal.owner_id
    return requested


def load_owner(db: Session, principal: Principal, owner_id: uuid.UUID) -> Owner:
    if principal.role == "owner" and principal.owner_id != owner_id:
        raise NotFound()
    owner = db.get(Owner, owner_id)
    if owner is None:
        raise NotFound()
    return owner


def load_machine(db: Session, principal: Principal, machine_id: uuid.UUID, *, lock: bool = False) -> Machine:
    machine = lock_row(db, Machine, machine_id) if lock else db.get(Machine, machine_id)
    if machine is None or (principal.role == "owner" and machine.owner_id != principal.owner_id):
        raise NotFound()
    return machine
