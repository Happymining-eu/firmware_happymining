"""Dashboard pages for an owner's organisation and for remote access.

- ``/organisation``: an organisation's administrator lists its users, adds
  one, changes a role, deactivates or reactivates.
- On the machine page: who manages the machine, the remote-access grants, and
  the forms to grant, revoke and change management.

Same conventions as ``dashboard.py``, whose router and helpers are used here:
every form carries the session's CSRF token, a POST answers with a redirect,
and each handler calls the same service function as the JSON API, so the rules
of docs/appliance.md (section 3) are enforced in one place.

A POST checks the CSRF token before anything else, the caller's role included:
a forged request learns nothing about what the session could have done.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from fastapi import Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from .config import Settings
from .dashboard import back, check_csrf, page_principal, render, router
from .db import get_db
from .deps import client_ip, load_machine, settings_dep
from .errors import AppError, Forbidden, InvalidRequest, NotFound
from .models import ORG_ROLES, Owner
from .services import access, remote_access
from .services import org as org_service
from .services.accounts import MIN_PASSWORD_LENGTH, Principal

ORG_ROLE_HELP = {
    "org_admin": "Everything: machines, users, remote access, earnings and settlements.",
    "org_operator": "Runs the machines day to day: plugins, jobs and schedules. No users, no money.",
    "org_viewer": "Sees machines and their state. Changes nothing. No money.",
}


def _run(db: Session, path: str, fn: Callable[[], Any], ok: str | Callable[[Any], str]) -> RedirectResponse:
    """One mutating service call for a form post.

    A refusal for lack of permission, or an object that does not exist for the
    caller, stays an error page with its status code. Anything else the service
    objects to (a last administrator, an invalid value) goes back to the form
    as a message.
    """
    try:
        result = fn()
        db.commit()
    except (Forbidden, NotFound):
        db.rollback()
        raise
    except AppError as exc:
        db.rollback()
        return back(path, err=exc.message)
    return back(path, msg=ok(result) if callable(ok) else ok)


def _need_org_admin(principal: Principal) -> None:
    access.require_org_role(principal, "org_admin")


def _need_org_admin_or_admin(principal: Principal) -> None:
    if not (principal.is_admin or access.has_org_role(principal, "org_admin")):
        raise Forbidden()


# --- organisation users ----------------------------------------------------


@router.get("/organisation", response_class=HTMLResponse)
def organisation_page(
    request: Request,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    _need_org_admin(principal)
    owner = db.get(Owner, principal.owner_id)
    assert owner is not None
    users = db.execute(org_service.users_query(owner.id)).scalars().all()
    return render(
        request,
        settings,
        principal,
        "organisation.html",
        owner=owner,
        users=users,
        org_roles=ORG_ROLES,
        org_role_help=ORG_ROLE_HELP,
        min_password_length=MIN_PASSWORD_LENGTH,
    )


@router.post("/organisation/users")
def organisation_user_create(
    request: Request,
    email: str = Form(""),
    display_name: str = Form(""),
    org_role: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    check_csrf(request, principal, settings, csrf_token)
    _need_org_admin(principal)
    return _run(
        db,
        "/organisation",
        lambda: org_service.create_org_user(
            db,
            principal,
            principal.actor(client_ip(request)),
            email=email,
            display_name=display_name,
            org_role=org_role,
            password=password,
        ),
        lambda user: f"{user.email} was added.",
    )


@router.post("/organisation/users/{user_id}")
def organisation_user_update(
    user_id: uuid.UUID,
    request: Request,
    org_role: str = Form(""),
    is_active: str = Form(""),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    check_csrf(request, principal, settings, csrf_token)
    _need_org_admin(principal)

    def update():
        if is_active not in ("", "true", "false"):
            raise InvalidRequest("is_active must be true or false")
        return org_service.update_org_user(
            db,
            principal,
            principal.actor(client_ip(request)),
            user_id,
            org_role=org_role or None,
            is_active={"true": True, "false": False}.get(is_active),
        )

    return _run(db, "/organisation", update, lambda user: f"{user.email} was updated.")


# --- machine management and remote access ----------------------------------


@router.post("/machines/{machine_id}/management")
def machine_management(
    machine_id: uuid.UUID,
    request: Request,
    management: str = Form(""),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    check_csrf(request, principal, settings, csrf_token)
    _need_org_admin_or_admin(principal)
    return _run(
        db,
        f"/machines/{machine_id}",
        lambda: remote_access.set_management(
            db,
            principal,
            principal.actor(client_ip(request)),
            load_machine(db, principal, machine_id, lock=True),
            management,
        ),
        lambda result: (
            f"This machine is now managed by the {result[0].management}."
            if result[1]
            else "Nothing changed: the machine was already managed that way."
        ),
    )


@router.post("/machines/{machine_id}/remote-access/grants")
def machine_grant_create(
    machine_id: uuid.UUID,
    request: Request,
    level: str = Form(""),
    expires_in_hours: str = Form(""),
    reason: str = Form(""),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    check_csrf(request, principal, settings, csrf_token)
    _need_org_admin(principal)

    def grant():
        hours = expires_in_hours.strip()
        # "never" has to be chosen: an empty field is not an open-ended grant.
        if hours != "never" and not (hours.isascii() and hours.isdecimal()):
            raise InvalidRequest("choose how long the access lasts")
        return remote_access.issue_grant(
            db,
            settings,
            principal,
            principal.actor(client_ip(request)),
            load_machine(db, principal, machine_id, lock=True),
            level=level,
            expires_in_hours=None if hours == "never" else int(hours),
            reason=reason,
        )

    def granted(g) -> str:
        until = f"until {g.expires_at:%Y-%m-%d %H:%M} UTC" if g.expires_at else "until you revoke the access"
        return f"HappyMining may now {g.level} this machine {until}."

    return _run(db, f"/machines/{machine_id}", grant, granted)


@router.post("/machines/{machine_id}/remote-access/grants/{grant_id}/revoke")
def machine_grant_revoke(
    machine_id: uuid.UUID,
    grant_id: uuid.UUID,
    request: Request,
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    check_csrf(request, principal, settings, csrf_token)
    _need_org_admin_or_admin(principal)
    return _run(
        db,
        f"/machines/{machine_id}",
        lambda: remote_access.revoke_grant(
            db,
            principal,
            principal.actor(client_ip(request)),
            load_machine(db, principal, machine_id, lock=True),
            grant_id,
        ),
        lambda result: "Remote access revoked." if result[1] else "This access had already ended.",
    )
