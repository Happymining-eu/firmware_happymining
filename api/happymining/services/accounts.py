"""Human users, login and sessions.

Production admin access requires TOTP. The separate demo login exists only in
DEMO mode, only for accounts flagged ``is_demo``, and the startup guard refuses
to start LIVE with it enabled.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..config import Settings
from ..db import lock_row
from ..errors import Conflict, FeatureDisabled, Forbidden, InvalidRequest, NotFound, Unauthorized
from ..models import ORG_ROLES, ROLES, Owner, User, UserSession, utcnow
from ..security import (
    decrypt_text,
    encrypt_text,
    hash_password,
    match_totp_step,
    new_csrf_token,
    new_session_token,
    new_totp_secret,
    session_token_hash,
    totp_uri,
    verify_password,
)

MIN_PASSWORD_LENGTH = 12


@dataclass(frozen=True)
class Principal:
    user: User
    session: UserSession
    via_cookie: bool

    @property
    def role(self) -> str:
        return self.user.role

    @property
    def owner_id(self) -> uuid.UUID | None:
        return self.user.owner_id

    @property
    def is_admin(self) -> bool:
        return self.user.role == "admin"

    @property
    def is_staff(self) -> bool:
        """HappyMining's own people: admins and auditors. Not an owner's user."""
        return self.user.role in ("admin", "auditor")

    @property
    def org_role(self) -> str | None:
        """The role inside the owner's organisation; None for staff."""
        return self.user.org_role

    def actor(self, ip: str = "") -> Actor:
        return Actor("user", str(self.user.id), ip)


def normalise_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not (3 <= len(email) <= 320) or email.count("@") != 1 or " " in email:
        raise InvalidRequest("a valid email address is required")
    return email


def create_owner(
    db: Session,
    actor: Actor,
    *,
    display_name: str,
    legal_name: str = "",
    contact_email: str = "",
    is_synthetic: bool = False,
) -> Owner:
    if not display_name.strip():
        raise InvalidRequest("display_name is required")
    owner = Owner(
        display_name=display_name.strip()[:200],
        legal_name=legal_name.strip()[:200],
        contact_email=contact_email.strip()[:320],
        is_synthetic=is_synthetic,
    )
    db.add(owner)
    db.flush()
    audit(
        db,
        actor,
        "owner.create",
        object_type="owner",
        object_id=owner.id,
        owner_id=owner.id,
        details={"display_name": owner.display_name, "synthetic": is_synthetic},
    )
    return owner


def create_user(
    db: Session,
    actor: Actor,
    *,
    email: str,
    role: str,
    display_name: str = "",
    password: str | None = None,
    owner_id: uuid.UUID | None = None,
    is_demo: bool = False,
    org_role: str | None = None,
) -> User:
    email = normalise_email(email)
    if role not in ROLES:
        raise InvalidRequest("role must be one of: " + ", ".join(ROLES))
    if (role == "owner") != (owner_id is not None):
        raise InvalidRequest("owner_id is required for the owner role and not allowed for other roles")
    if role == "owner":
        # The first users of an organisation are created by staff and run it.
        org_role = org_role or "org_admin"
        if org_role not in ORG_ROLES:
            raise InvalidRequest("org_role must be one of: " + ", ".join(ORG_ROLES))
    elif org_role is not None:
        raise InvalidRequest("org_role only applies to the owner role")
    if owner_id and not db.get(Owner, owner_id):
        raise NotFound("owner not found")
    if password is not None and len(password) < MIN_PASSWORD_LENGTH:
        raise InvalidRequest(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if db.execute(select(User.id).where(User.email == email)).first():
        raise Conflict("a user with this email already exists")
    user = User(
        email=email,
        role=role,
        display_name=display_name.strip()[:200],
        owner_id=owner_id,
        org_role=org_role,
        password_hash=hash_password(password) if password else None,
        is_demo=is_demo,
    )
    db.add(user)
    db.flush()
    audit(
        db,
        actor,
        "user.create",
        object_type="user",
        object_id=user.id,
        owner_id=owner_id,
        details={"email": email, "role": role, "org_role": org_role, "demo": is_demo},
    )
    return user


def begin_mfa_enrollment(db: Session, settings: Settings, user: User) -> str:
    """Create (or replace a not-yet-activated) TOTP secret. Returns the otpauth URI."""
    if user.mfa_enabled:
        raise Conflict("MFA is already active for this user")
    secret = new_totp_secret()
    user.totp_secret_enc = encrypt_text(settings, secret)
    db.flush()
    return totp_uri(secret, user.email)


def activate_mfa(
    db: Session,
    settings: Settings,
    actor: Actor,
    user: User,
    code: str,
    *,
    keep_session_id: uuid.UUID | None = None,
) -> None:
    if user.mfa_enabled:
        raise Conflict("MFA is already active for this user")
    if not user.totp_secret_enc:
        raise Conflict("start MFA enrollment first")
    step = match_totp_step(decrypt_text(settings, user.totp_secret_enc), code)
    if step is None:
        raise InvalidRequest("the code is not valid")
    user.mfa_enabled = True
    user.totp_last_step = step  # the activation code cannot be reused to log in
    # Sessions opened before the second factor existed are ended.
    revoked = revoke_sessions(db, user, keep_session_id=keep_session_id)
    db.flush()
    audit(
        db,
        actor,
        "user.mfa_activate",
        object_type="user",
        object_id=user.id,
        details={"sessions_revoked": revoked},
    )


def _new_session(
    db: Session,
    settings: Settings,
    user: User,
    *,
    mfa_verified: bool,
    is_demo: bool,
    ip: str,
    user_agent: str,
) -> tuple[UserSession, str]:
    token = new_session_token()
    session = UserSession(
        user_id=user.id,
        token_hash=session_token_hash(settings, token),
        csrf_token=new_csrf_token(),
        mfa_verified=mfa_verified,
        is_demo=is_demo,
        expires_at=utcnow() + timedelta(minutes=settings.session_ttl_minutes),
        ip=ip[:64],
        user_agent=user_agent[:300],
    )
    db.add(session)
    user.last_login_at = utcnow()
    db.flush()
    return session, token


def login(
    db: Session,
    settings: Settings,
    *,
    email: str,
    password: str,
    totp_code: str | None,
    ip: str,
    user_agent: str,
) -> tuple[UserSession, str, User]:
    """Password login, plus TOTP when enrolled. Admins must have TOTP in LIVE mode.

    Every credential failure is the same ``Unauthorized``; the audit trail
    records the real reason.
    """
    actor = Actor("user", "", ip)
    try:
        email = normalise_email(email)
    except InvalidRequest:
        verify_password(None, password or "")
        raise Unauthorized("Invalid email, password or code.") from None
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    ok = verify_password(user.password_hash if user else None, password or "")

    def deny(reason: str) -> Unauthorized:
        audit(
            db,
            actor,
            "auth.login_failed",
            object_type="user",
            object_id=user.id if user else "",
            details={"email": email, "reason": reason},
        )
        return Unauthorized("Invalid email, password or code.")

    if user is None or not ok:
        raise deny("bad_credentials")
    if not user.is_active:
        raise deny("inactive")
    if user.is_demo:
        # Demo accounts have no password path at all.
        raise deny("demo_account")
    if user.mfa_enabled:
        step = (
            match_totp_step(decrypt_text(settings, user.totp_secret_enc), totp_code or "")
            if user.totp_secret_enc
            else None
        )
        if step is None:
            raise deny("bad_totp")
        # Serialise on the user row so two logins cannot both spend the same code.
        locked = lock_row(db, User, user.id)
        if locked.totp_last_step is not None and step <= locked.totp_last_step:
            raise deny("totp_replay")
        locked.totp_last_step = step
        mfa_verified = True
    else:
        if user.role == "admin" and settings.is_live:
            audit(
                db,
                actor,
                "auth.login_failed",
                object_type="user",
                object_id=user.id,
                details={"email": email, "reason": "admin_without_mfa"},
            )
            raise Forbidden(
                "Admin accounts need MFA in LIVE mode. "
                "Enroll with: python -m happymining.cli enroll-mfa <email>",
                code="mfa_enrollment_required",
            )
        mfa_verified = False
    session, token = _new_session(
        db, settings, user, mfa_verified=mfa_verified, is_demo=False, ip=ip, user_agent=user_agent
    )
    audit(
        db,
        Actor("user", str(user.id), ip),
        "auth.login",
        object_type="user",
        object_id=user.id,
        owner_id=user.owner_id,
        details={"mfa": mfa_verified},
    )
    return session, token, user


def demo_login(
    db: Session, settings: Settings, *, email: str, ip: str, user_agent: str
) -> tuple[UserSession, str, User]:
    """DEMO only: sign in as a synthetic demo account without a password."""
    if not (settings.is_demo and settings.demo_login_enabled):
        raise FeatureDisabled("demo login is not available")
    user = db.execute(select(User).where(User.email == normalise_email(email))).scalar_one_or_none()
    if user is None or not user.is_demo or not user.is_active:
        raise Unauthorized("Unknown demo account.")
    session, token = _new_session(
        db, settings, user, mfa_verified=False, is_demo=True, ip=ip, user_agent=user_agent
    )
    audit(
        db,
        Actor("user", str(user.id), ip),
        "auth.demo_login",
        object_type="user",
        object_id=user.id,
        owner_id=user.owner_id,
    )
    return session, token, user


def resolve_session(db: Session, settings: Settings, token: str, *, via_cookie: bool) -> Principal:
    if not token:
        raise Unauthorized()
    session = db.execute(
        select(UserSession).where(UserSession.token_hash == session_token_hash(settings, token))
    ).scalar_one_or_none()
    if session is None or session.revoked_at is not None or session.expires_at <= utcnow():
        raise Unauthorized()
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise Unauthorized()
    if session.is_demo and not (settings.is_demo and settings.demo_login_enabled):
        raise Unauthorized()
    if user.role == "admin" and settings.is_live and not session.mfa_verified:
        raise Unauthorized()
    return Principal(user=user, session=session, via_cookie=via_cookie)


def logout(db: Session, principal: Principal, ip: str) -> None:
    principal.session.revoked_at = utcnow()
    db.flush()
    audit(db, principal.actor(ip), "auth.logout", object_type="user", object_id=principal.user.id)


# --- containing a compromised account --------------------------------------


def revoke_sessions(db: Session, user: User, *, keep_session_id: uuid.UUID | None = None) -> int:
    """End every open session of a user, optionally keeping the caller's own."""
    query = (
        update(UserSession)
        .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    if keep_session_id is not None:
        query = query.where(UserSession.id != keep_session_id)
    return db.execute(query).rowcount or 0


def _load_user(db: Session, user_id: uuid.UUID) -> User:
    user = lock_row(db, User, user_id)
    if user is None:
        raise NotFound()
    return user


def revoke_user_sessions(db: Session, actor: Actor, user_id: uuid.UUID) -> int:
    user = _load_user(db, user_id)
    count = revoke_sessions(db, user)
    audit(
        db, actor, "user.revoke_sessions", object_type="user", object_id=user.id, details={"sessions": count}
    )
    return count


def deactivate_user(db: Session, actor: Actor, user_id: uuid.UUID) -> User:
    """Disable an account and end its sessions. The last active admin cannot be disabled."""
    # Serialised: two admins switching each other off at the same moment would
    # otherwise each see the other as "another active admin".
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('hm:admin-accounts'))"))
    user = _load_user(db, user_id)
    if user.role == "admin" and user.is_active:
        others = db.execute(
            select(User.id).where(User.role == "admin", User.is_active.is_(True), User.id != user.id).limit(1)
        ).first()
        if others is None:
            raise Conflict("this is the last active admin; create another admin first")
    user.is_active = False
    count = revoke_sessions(db, user)
    db.flush()
    audit(db, actor, "user.deactivate", object_type="user", object_id=user.id, details={"sessions": count})
    return user


def set_password(db: Session, actor: Actor, user: User, password: str) -> None:
    """Replace a password (operator command line) and end the user's sessions."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise InvalidRequest(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if user.is_demo:
        raise Conflict("demo accounts have no password")
    user.password_hash = hash_password(password)
    count = revoke_sessions(db, user)
    db.flush()
    audit(db, actor, "user.set_password", object_type="user", object_id=user.id, details={"sessions": count})


def login_rate_limit(settings: Settings, email: str, ip: str) -> None:
    """Throttle login attempts.

    Three windows: per client address; per (account, address), which stops one
    client guessing one account; and a much wider per-account cap, which bounds
    guessing spread over many addresses without letting a single client lock
    the account's owner out with ten requests.
    """
    from .. import ratelimit

    key = (email or "").strip().lower()[:150]
    limit = settings.login_rate_limit_per_minute
    ratelimit.hit(f"login:ip:{ip}", limit)
    ratelimit.hit(f"login:pair:{key}:{ip}", limit)
    ratelimit.hit(f"login:email:{key}", limit * 20)
