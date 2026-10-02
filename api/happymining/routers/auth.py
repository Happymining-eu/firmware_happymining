"""Human authentication."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from .. import ratelimit
from ..config import Settings
from ..db import get_db
from ..deps import SESSION_COOKIE, client_ip, get_principal, settings_dep
from ..errors import AppError
from ..schemas import DemoLoginIn, LoginIn, MfaActivateIn
from ..services import accounts
from ..services.accounts import Principal

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def set_session_cookie(response: Response, settings: Settings, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_ttl_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )


def user_view(user) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "owner_id": str(user.owner_id) if user.owner_id else None,
        "mfa_enabled": user.mfa_enabled,
        "demo": user.is_demo,
    }


@router.post("/login")
def login(
    body: LoginIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    ip = client_ip(request)
    accounts.login_rate_limit(settings, body.email, ip)
    try:
        session, token, user = accounts.login(
            db,
            settings,
            email=body.email,
            password=body.password,
            totp_code=body.totp_code,
            ip=ip,
            user_agent=request.headers.get("user-agent", ""),
        )
    except AppError:
        db.commit()  # keep the failed-login audit row
        raise
    db.commit()
    set_session_cookie(response, settings, token)
    # The token is also returned for API clients that use "Authorization: Bearer".
    return {
        "token": token,
        "csrf_token": session.csrf_token,
        "expires_at": session.expires_at,
        "user": user_view(user),
    }


@router.post("/demo-login")
def demo_login(
    body: DemoLoginIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    ip = client_ip(request)
    ratelimit.hit(f"login:ip:{ip}", settings.login_rate_limit_per_minute)
    session, token, user = accounts.demo_login(
        db, settings, email=body.email, ip=ip, user_agent=request.headers.get("user-agent", "")
    )
    db.commit()
    set_session_cookie(response, settings, token)
    return {
        "token": token,
        "csrf_token": session.csrf_token,
        "expires_at": session.expires_at,
        "user": user_view(user),
        "demo": True,
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    accounts.logout(db, principal, client_ip(request))
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(principal: Principal = Depends(get_principal), settings: Settings = Depends(settings_dep)):
    return {
        "user": user_view(principal.user),
        "csrf_token": principal.session.csrf_token,
        "mode": settings.mode,
        "synthetic_data": settings.is_demo,
    }


@router.post("/mfa/enroll")
def mfa_enroll(
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    uri = accounts.begin_mfa_enrollment(db, settings, principal.user)
    db.commit()
    return {"otpauth_uri": uri}


@router.post("/mfa/activate")
def mfa_activate(
    body: MfaActivateIn,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    accounts.activate_mfa(
        db,
        settings,
        principal.actor(client_ip(request)),
        principal.user,
        body.code,
        keep_session_id=principal.session.id,
    )
    db.commit()
    return {"mfa_enabled": True}
