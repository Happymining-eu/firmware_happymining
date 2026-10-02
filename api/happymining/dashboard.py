"""Server-rendered owner and admin dashboard.

Every page goes through the same services and the same tenant scoping as the
JSON API. Browser actions are cookie-authenticated, so every POST carries the
session's CSRF token and is refused when it is missing or wrong.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import ratelimit
from .config import Settings
from .db import get_db
from .deps import SESSION_COOKIE, _same_origin, client_ip, load_machine, settings_dep
from .errors import AppError, Forbidden, InvalidRequest, NotFound, Unauthorized
from .models import (
    AuditLog,
    EarningBucket,
    EnrollmentRequest,
    ExceptionItem,
    FeeSchedule,
    Machine,
    Operation,
    Owner,
    OwnerBeneficiary,
    PayoutBatch,
    ProviderAccount,
    ProviderMachine,
    ProviderReceipt,
    TelemetrySample,
    User,
    utcnow,
)
from .providers.registry import get_provider
from .routers import views
from .routers.auth import set_session_cookie
from .security import constant_time_equal
from .services import accounts, exceptions_queue, fees, pairing, payouts, provider_sync, receipts, statements
from .services import earnings as earnings_service
from .services import operations as operation_service
from .services.accounts import Principal, resolve_session
from .services.ledger import owner_balances, to_decimal

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parents[2] / "dashboard" / "templates"))
router = APIRouter(include_in_schema=False)

SAFE_OPERATION_TYPES = ("refresh_inventory", "collect_diagnostics", "run_preflight", "rotate_credential")


def _money(value: Any) -> str:
    """Display money to cents; the ledger keeps eight decimals."""
    if value is None:
        return "-"
    return f"{Decimal(str(value)):,.2f}"


def _money8(value: Any) -> str:
    return "-" if value is None else f"{Decimal(str(value)):,.8f}".rstrip("0").rstrip(".")


def _age(seconds: int | None) -> str:
    if seconds is None:
        return "never"
    if seconds < 90:
        return f"{seconds}s ago"
    if seconds < 5400:
        return f"{seconds // 60} min ago"
    if seconds < 172800:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} d ago"


TEMPLATES.env.filters["money"] = _money
TEMPLATES.env.filters["money8"] = _money8
TEMPLATES.env.filters["age"] = _age


# --- session helpers -------------------------------------------------------


class LoginRequired(Exception):
    pass


def page_principal(
    request: Request, db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)
) -> Principal:
    try:
        return resolve_session(db, settings, request.cookies.get(SESSION_COOKIE, ""), via_cookie=True)
    except Unauthorized as exc:
        raise LoginRequired() from exc


def check_csrf(request: Request, principal: Principal, settings: Settings, token: str) -> None:
    if not _same_origin(request, settings):
        raise Forbidden("cross-origin request refused", code="csrf_failed")
    if not token or not constant_time_equal(token, principal.session.csrf_token):
        raise Forbidden("missing or invalid CSRF token", code="csrf_failed")


def need(principal: Principal, *roles: str) -> None:
    if principal.role not in roles:
        raise Forbidden()


def render(
    request: Request, settings: Settings, principal: Principal | None, template: str, **ctx: Any
) -> Response:
    return TEMPLATES.TemplateResponse(
        request,
        template,
        {
            "settings": settings,
            "demo": settings.is_demo,
            "user": principal.user if principal else None,
            "role": principal.role if principal else None,
            "csrf": principal.session.csrf_token if principal else "",
            "message": request.query_params.get("msg", ""),
            "error": request.query_params.get("err", ""),
            "now": utcnow(),
            **ctx,
        },
    )


def _form_uuid(value: str, what: str) -> uuid.UUID:
    try:
        return uuid.UUID(value.strip())
    except ValueError as exc:
        raise InvalidRequest(f"{what} is not a valid identifier") from exc


def back(path: str, *, msg: str = "", err: str = "") -> RedirectResponse:
    query = f"?msg={quote(msg[:300])}" if msg else (f"?err={quote(err[:300])}" if err else "")
    return RedirectResponse(path + query, status_code=303)


def action(db: Session, path: str, fn, ok: str) -> RedirectResponse:
    """Run one mutating service call for a form post; commit or report the error."""
    try:
        result = fn()
        db.commit()
    except AppError as exc:
        db.rollback()
        return back(path, err=exc.message)
    return back(path, msg=ok(result) if callable(ok) else ok)


# --- login -----------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
def root():
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)):
    demo_users = []
    if settings.is_demo and settings.demo_login_enabled:
        demo_users = (
            db.execute(select(User).where(User.is_demo.is_(True)).order_by(User.role, User.email))
            .scalars()
            .all()
        )
    return render(request, settings, None, "login.html", demo_users=demo_users)


@router.post("/login")
def login_submit(
    request: Request,
    email: str = Form(""),
    password: str = Form(""),
    totp_code: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    ip = client_ip(request)
    try:
        if not _same_origin(request, settings):
            raise Forbidden("cross-origin request refused")
        accounts.login_rate_limit(settings, email, ip)
        _, token, _ = accounts.login(
            db,
            settings,
            email=email,
            password=password,
            totp_code=totp_code or None,
            ip=ip,
            user_agent=request.headers.get("user-agent", ""),
        )
        db.commit()
    except AppError as exc:
        db.commit()
        return back("/login", err=exc.message)
    response = RedirectResponse("/dashboard", status_code=303)
    set_session_cookie(response, settings, token)
    return response


@router.post("/demo-login")
def demo_login_submit(
    request: Request,
    email: str = Form(""),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    try:
        if not _same_origin(request, settings):
            raise Forbidden("cross-origin request refused")
        ratelimit.hit(f"login:ip:{client_ip(request)}", settings.login_rate_limit_per_minute)
        _, token, _ = accounts.demo_login(
            db, settings, email=email, ip=client_ip(request), user_agent=request.headers.get("user-agent", "")
        )
        db.commit()
    except AppError as exc:
        db.rollback()
        return back("/login", err=exc.message)
    response = RedirectResponse("/dashboard", status_code=303)
    set_session_cookie(response, settings, token)
    return response


@router.post("/logout")
def logout_submit(
    request: Request,
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    check_csrf(request, principal, settings, csrf_token)
    accounts.logout(db, principal, client_ip(request))
    db.commit()
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# --- overview --------------------------------------------------------------


def _period() -> tuple[date, date]:
    end = datetime.now(UTC).date() - timedelta(days=1)
    return end - timedelta(days=29), end


def _owner_summary(db: Session, settings: Settings, owner: Owner) -> dict[str, Any]:
    start, end = _period()
    machines = (
        db.execute(select(Machine).where(Machine.owner_id == owner.id).order_by(Machine.label))
        .scalars()
        .all()
    )
    return {
        "owner": owner,
        "balances": owner_balances(db, owner.id).as_dict(),
        "statement": statements.owner_statement(db, owner.id, start, end),
        "machines": [views.machine_view(settings, m, staff=False) for m in machines],
        "payouts": statements.owner_payout_history(db, owner.id, limit=10),
        "beneficiary": db.get(OwnerBeneficiary, owner.id),
    }


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    if principal.role == "owner":
        owner = db.get(Owner, principal.owner_id)
        assert owner is not None
        fee = fees.fee_for(db, owner.id, datetime.now(UTC).date())
        return render(
            request, settings, principal, "owner.html", fee=fee, **_owner_summary(db, settings, owner)
        )

    owners = db.execute(select(Owner).order_by(Owner.display_name)).scalars().all()
    machines = db.execute(select(Machine).order_by(Machine.label)).scalars().all()
    open_exceptions = db.execute(
        select(func.count()).select_from(ExceptionItem).where(ExceptionItem.status == "open")
    ).scalar_one()
    return render(
        request,
        settings,
        principal,
        "admin_overview.html",
        owners=[{"owner": o, "balances": owner_balances(db, o.id).as_dict()} for o in owners],
        machines=[views.machine_view(settings, m, staff=True) for m in machines],
        owner_names={str(o.id): o.display_name for o in owners},
        open_exceptions=open_exceptions,
        health=provider_sync.integration_health(db, settings),
    )


@router.get("/owners/{owner_id}", response_class=HTMLResponse)
def owner_page(
    owner_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    if principal.role == "owner" and principal.owner_id != owner_id:
        raise NotFound()
    owner = db.get(Owner, owner_id)
    if owner is None:
        raise NotFound()
    fee = fees.fee_for(db, owner.id, datetime.now(UTC).date())
    return render(request, settings, principal, "owner.html", fee=fee, **_owner_summary(db, settings, owner))


@router.get("/machines/{machine_id}", response_class=HTMLResponse)
def machine_page(
    machine_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = load_machine(db, principal, machine_id)
    samples = (
        db.execute(
            select(TelemetrySample)
            .where(TelemetrySample.machine_id == machine.id)
            .order_by(TelemetrySample.collected_at.desc())
            .limit(20)
        )
        .scalars()
        .all()
    )
    operations = (
        db.execute(
            select(Operation)
            .where(Operation.machine_id == machine.id)
            .order_by(Operation.issued_at.desc())
            .limit(20)
        )
        .scalars()
        .all()
    )
    return render(
        request,
        settings,
        principal,
        "machine.html",
        machine=views.machine_view(settings, machine, staff=principal.role != "owner"),
        latest=views.telemetry_view(samples[0]) if samples else None,
        samples=[views.telemetry_view(s) for s in samples],
        operations=[views.operation_view(o) for o in operations],
        safe_types=SAFE_OPERATION_TYPES,
    )


@router.get("/earnings", response_class=HTMLResponse)
def earnings_page(
    request: Request,
    owner_id: uuid.UUID | None = None,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    scope = principal.owner_id if principal.role == "owner" else owner_id
    query = (
        select(EarningBucket).order_by(EarningBucket.day.desc(), EarningBucket.external_machine_id).limit(200)
    )
    if scope is not None:
        query = query.where(EarningBucket.owner_id == scope)
    buckets = db.execute(query).scalars().all()
    return render(
        request, settings, principal, "earnings.html", buckets=[views.bucket_view(b) for b in buckets]
    )


# --- admin: pairing --------------------------------------------------------


@router.get("/admin/pairing", response_class=HTMLResponse)
def pairing_page(
    request: Request,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin", "auditor")
    requests = (
        db.execute(select(EnrollmentRequest).order_by(EnrollmentRequest.created_at.desc()).limit(50))
        .scalars()
        .all()
    )
    owners = (
        db.execute(select(Owner).where(Owner.status == "active").order_by(Owner.display_name)).scalars().all()
    )
    return render(
        request, settings, principal, "admin_pairing.html", requests=requests, owners=owners, issued=None
    )


@router.post("/admin/pairing", response_class=HTMLResponse)
def pairing_create(
    request: Request,
    owner_id: uuid.UUID = Form(...),
    machine_label: str = Form(""),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)
    try:
        issued = pairing.create_enrollment(
            db,
            settings,
            principal.actor(client_ip(request)),
            owner_id=owner_id,
            machine_label=machine_label,
            created_by=principal.user.id,
            is_synthetic=settings.is_demo,
        )
        db.commit()
    except AppError as exc:
        db.rollback()
        return back("/admin/pairing", err=exc.message)
    # The code is rendered once in this response and never stored or put in a URL.
    requests = (
        db.execute(select(EnrollmentRequest).order_by(EnrollmentRequest.created_at.desc()).limit(50))
        .scalars()
        .all()
    )
    owners = (
        db.execute(select(Owner).where(Owner.status == "active").order_by(Owner.display_name)).scalars().all()
    )
    response = render(
        request, settings, principal, "admin_pairing.html", requests=requests, owners=owners, issued=issued
    )
    response.headers["Cache-Control"] = "no-store"
    return response


# --- admin: provider -------------------------------------------------------


@router.get("/admin/provider", response_class=HTMLResponse)
def provider_page(
    request: Request,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin", "auditor")
    provider_machines = (
        db.execute(select(ProviderMachine).order_by(ProviderMachine.external_id)).scalars().all()
    )
    unbound = (
        db.execute(
            select(Machine)
            .outerjoin(ProviderMachine, ProviderMachine.machine_id == Machine.id)
            .where(ProviderMachine.id.is_(None))
            .order_by(Machine.label)
        )
        .scalars()
        .all()
    )
    _, end = _period()
    return render(
        request,
        settings,
        principal,
        "admin_provider.html",
        health=provider_sync.integration_health(db, settings),
        provider_machines=[views.provider_machine_view(pm) for pm in provider_machines],
        machine_labels={str(m.id): m.label for m in db.execute(select(Machine)).scalars()},
        unbound=unbound,
        today=datetime.now(UTC).date(),
        start=end - timedelta(days=6),
        end=end,
    )


def _provider_action(
    db: Session, settings: Settings, kind: str, principal: Principal, request: Request, **kw: Any
):
    provider = get_provider(settings)
    account = provider_sync.ensure_account(db, settings, provider)
    if kind == "check":
        return provider_sync.check_health(db, provider, account)
    if kind == "machines":
        return provider_sync.sync_machines(db, provider, account)
    run, _ = provider_sync.run_earnings_import(
        db,
        principal.actor(client_ip(request)),
        provider,
        account,
        start=kw["start"],
        end=kw["end"],
        user_id=principal.user.id,
    )
    return run


def _run_message(run) -> str:
    if run.status == "ok":
        return f"{run.kind}: ok {run.stats}"
    return f"{run.kind}: {run.status.upper()} ({run.error_code}) {run.error}"


@router.post("/admin/provider/{kind}")
def provider_action(
    kind: str,
    request: Request,
    csrf_token: str = Form(""),
    start: date | None = Form(None),
    end: date | None = Form(None),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)
    if kind not in ("check", "machines", "earnings"):
        raise NotFound()
    try:
        run = _provider_action(db, settings, kind, principal, request, start=start, end=end)
        db.commit()
    except AppError as exc:
        db.rollback()
        return back("/admin/provider", err=exc.message)
    if run.status == "ok":
        return back("/admin/provider", msg=_run_message(run))
    return back("/admin/provider", err=_run_message(run))


@router.post("/admin/provider-machines/{provider_machine_id}/bind")
def provider_bind(
    provider_machine_id: uuid.UUID,
    request: Request,
    machine_id: uuid.UUID = Form(...),
    bound_from: date = Form(...),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)
    return action(
        db,
        "/admin/provider",
        lambda: provider_sync.bind_machine(
            db,
            principal.actor(client_ip(request)),
            provider_machine_id=provider_machine_id,
            machine_id=machine_id,
            bound_from=bound_from,
            user_id=principal.user.id,
        ),
        "Provider machine bound.",
    )


# --- admin: exceptions, fees ----------------------------------------------


@router.get("/admin/exceptions", response_class=HTMLResponse)
def exceptions_page(
    request: Request,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin", "auditor")
    items = (
        db.execute(
            select(ExceptionItem).order_by(ExceptionItem.status, ExceptionItem.created_at.desc()).limit(200)
        )
        .scalars()
        .all()
    )
    unmapped = (
        db.execute(
            select(EarningBucket)
            .where(EarningBucket.status == "unmapped")
            .order_by(EarningBucket.day)
            .limit(200)
        )
        .scalars()
        .all()
    )
    return render(
        request,
        settings,
        principal,
        "admin_exceptions.html",
        items=[views.exception_view(i) for i in items],
        unmapped=[views.bucket_view(b) for b in unmapped],
    )


@router.post("/admin/exceptions/{exception_id}/resolve")
def exception_resolve(
    exception_id: uuid.UUID,
    request: Request,
    resolution: str = Form(""),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)
    return action(
        db,
        "/admin/exceptions",
        lambda: exceptions_queue.resolve(
            db, principal.actor(client_ip(request)), exception_id, resolution, principal.user.id
        ),
        "Exception resolved.",
    )


@router.post("/admin/buckets/{bucket_id}/attribute")
def bucket_attribute(
    bucket_id: uuid.UUID,
    request: Request,
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)
    return action(
        db,
        "/admin/exceptions",
        lambda: earnings_service.remap_bucket(
            db, principal.actor(client_ip(request)), bucket_id, created_by=principal.user.id
        ),
        "Earnings day attributed to its owner.",
    )


@router.get("/admin/fees", response_class=HTMLResponse)
def fees_page(
    request: Request,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin", "auditor")
    schedules = (
        db.execute(
            select(FeeSchedule).order_by(FeeSchedule.owner_id.is_not(None), FeeSchedule.effective_from.desc())
        )
        .scalars()
        .all()
    )
    owners = db.execute(select(Owner).order_by(Owner.display_name)).scalars().all()
    return render(
        request,
        settings,
        principal,
        "admin_fees.html",
        schedules=schedules,
        owners=owners,
        owner_names={o.id: o.display_name for o in owners},
        tomorrow=datetime.now(UTC).date() + timedelta(days=1),
    )


@router.post("/admin/fees")
def fees_create(
    request: Request,
    rate_percent: str = Form(...),
    effective_from: date = Form(...),
    owner_id: str = Form(""),
    note: str = Form(""),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)

    def create():
        rate = to_decimal(rate_percent.strip(), "rate") / Decimal(100)
        return fees.create_fee_schedule(
            db,
            principal.actor(client_ip(request)),
            owner_id=_form_uuid(owner_id, "owner") if owner_id else None,
            rate=rate,
            effective_from=effective_from,
            note=note,
            created_by=principal.user.id,
            is_demo_assumption=settings.is_demo,
        )

    return action(db, "/admin/fees", create, "Fee version created.")


# --- admin: settlements ----------------------------------------------------


@router.get("/admin/settlements", response_class=HTMLResponse)
def settlements_page(
    request: Request,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin", "auditor")
    receipts_rows = (
        db.execute(select(ProviderReceipt).order_by(ProviderReceipt.created_at.desc()).limit(50))
        .scalars()
        .all()
    )
    batches = (
        db.execute(select(PayoutBatch).order_by(PayoutBatch.created_at.desc()).limit(20)).scalars().all()
    )
    accounts_rows = db.execute(select(ProviderAccount).order_by(ProviderAccount.created_at)).scalars().all()
    owners = db.execute(select(Owner).order_by(Owner.display_name)).scalars().all()
    _, end = _period()
    return render(
        request,
        settings,
        principal,
        "admin_settlements.html",
        receipts=[views.receipt_view(r) for r in receipts_rows],
        batches=[views.batch_view(b) for b in batches],
        accounts=accounts_rows,
        owners=[
            {
                "owner": o,
                "balances": owner_balances(db, o.id).as_dict(),
                "beneficiary": db.get(OwnerBeneficiary, o.id),
            }
            for o in owners
        ],
        owner_names={str(o.id): o.display_name for o in owners},
        today=datetime.now(UTC).date(),
        start=end - timedelta(days=6),
        end=end,
        new_key=uuid.uuid4().hex,
    )


@router.post("/admin/receipts")
def receipt_create(
    request: Request,
    provider_account_id: uuid.UUID = Form(...),
    reference: str = Form(...),
    received_on: date = Form(...),
    amount: str = Form(...),
    evidence_source: str = Form(""),
    evidence_note: str = Form(""),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)

    def create():
        account = db.get(ProviderAccount, provider_account_id)
        if account is None:
            raise NotFound("provider account not found")
        return receipts.record_receipt(
            db,
            principal.actor(client_ip(request)),
            account,
            reference=reference,
            received_on=received_on,
            amount=to_decimal(amount.strip()),
            currency="USD",
            evidence_source=evidence_source,
            evidence_note=evidence_note,
            created_by=principal.user.id,
            is_synthetic=settings.is_demo,
        )

    return action(db, "/admin/settlements", create, "Receipt recorded. It is in suspense until allocated.")


@router.post("/admin/receipts/{receipt_id}/allocate-period")
def receipt_allocate(
    receipt_id: uuid.UUID,
    request: Request,
    start: date = Form(...),
    end: date = Form(...),
    request_key: str = Form(""),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)
    return action(
        db,
        "/admin/settlements",
        lambda: receipts.allocate_period(
            db,
            principal.actor(client_ip(request)),
            receipt_id,
            start,
            end,
            created_by=principal.user.id,
            request_key=request_key,
        ),
        lambda rows: f"Allocated to {len(rows)} earnings day(s).",
    )


@router.post("/admin/receipts/{receipt_id}/void")
def receipt_void(
    receipt_id: uuid.UUID,
    request: Request,
    reason: str = Form(""),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)
    return action(
        db,
        "/admin/settlements",
        lambda: receipts.void_receipt(
            db, principal.actor(client_ip(request)), receipt_id, reason=reason, user_id=principal.user.id
        ),
        "Receipt voided with a reversing entry.",
    )


@router.post("/admin/owners/{owner_id}/beneficiary")
def beneficiary_set(
    owner_id: uuid.UUID,
    request: Request,
    account_holder: str = Form(...),
    iban: str = Form(...),
    bic: str = Form(""),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)
    return action(
        db,
        "/admin/settlements",
        lambda: payouts.set_beneficiary(
            db,
            settings,
            principal.actor(client_ip(request)),
            owner_id,
            {"account_holder": account_holder, "iban": iban, "bic": bic},
            principal.user.id,
        ),
        "Beneficiary saved (stored encrypted).",
    )


@router.post("/admin/batches")
def batch_prepare(
    request: Request,
    idempotency_key: str = Form(...),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)
    return action(
        db,
        "/admin/settlements",
        lambda: payouts.prepare_batch(
            db,
            settings,
            principal.actor(client_ip(request)),
            idempotency_key=idempotency_key,
            created_by=principal.user.id,
            is_synthetic=settings.is_demo,
        ),
        lambda result: (
            "Settlement batch prepared."
            if result[1]
            else "This batch already exists; nothing new was created."
        ),
    )


@router.post("/admin/batches/{batch_id}/{step}")
def batch_step(
    batch_id: uuid.UUID,
    step: str,
    request: Request,
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)
    actor = principal.actor(client_ip(request))
    if step == "approve":
        return action(
            db,
            "/admin/settlements",
            lambda: payouts.approve_batch(db, settings, actor, batch_id, approver_id=principal.user.id),
            lambda r: "Batch approved; funds reserved." if r[1] else "Batch was already approved.",
        )
    if step == "submit":
        return action(
            db,
            "/admin/settlements",
            lambda: payouts.submit_batch(db, settings, actor, batch_id, user_id=principal.user.id),
            lambda r: "Batch marked as submitted." if r[1] else "Batch was already submitted.",
        )
    if step == "cancel":
        return action(
            db,
            "/admin/settlements",
            lambda: payouts.cancel_batch(db, actor, batch_id, user_id=principal.user.id),
            "Batch cancelled.",
        )
    if step == "export":
        try:
            body, digest = payouts.export_batch(db, settings, actor, batch_id)
            db.commit()
        except AppError as exc:
            db.rollback()
            return back("/admin/settlements", err=exc.message)
        return Response(
            content=body,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="happymining-payout-{batch_id}.csv"',
                "X-Content-SHA256": digest,
                "Cache-Control": "no-store",
            },
        )
    raise NotFound()


@router.post("/admin/payout-items/{item_id}/{outcome}")
def item_outcome(
    item_id: uuid.UUID,
    outcome: str,
    request: Request,
    reference: str = Form(""),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)
    actor = principal.actor(client_ip(request))
    handlers = {"confirm": payouts.confirm_item, "fail": payouts.fail_item, "reverse": payouts.reverse_item}
    if outcome not in handlers:
        raise NotFound()
    return action(
        db,
        "/admin/settlements",
        lambda: handlers[outcome](db, actor, item_id, reference=reference, user_id=principal.user.id),
        f"Payout item updated: {outcome}.",
    )


# --- admin: operations and audit -------------------------------------------


@router.post("/machines/{machine_id}/operations")
def operation_create(
    machine_id: uuid.UUID,
    request: Request,
    op_type: str = Form(...),
    csrf_token: str = Form(""),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin")
    check_csrf(request, principal, settings, csrf_token)
    path = f"/machines/{machine_id}"
    params: dict[str, Any] = (
        {"sections": ["services", "gpu", "disk"]} if op_type == "collect_diagnostics" else {}
    )
    if op_type == "reboot":
        params = {"delay_s": 300}
    try:
        machine = load_machine(db, principal, machine_id, lock=True)
        try:
            provider = get_provider(settings)
        except Exception:
            provider = None
        operation = operation_service.request_operation(
            db,
            settings,
            principal.actor(client_ip(request)),
            provider,
            machine=machine,
            op_type=op_type,
            params=params,
            requested_by=principal.user.id,
        )
        db.commit()
    except AppError as exc:
        db.rollback()
        return back(path, err=exc.message)
    if operation.status == "blocked":
        return back(path, err=operation.detail)
    return back(path, msg=f"Operation {op_type} queued; it is delivered on the next heartbeat.")


@router.get("/admin/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    need(principal, "admin", "auditor")
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(200)).scalars().all()
    return render(request, settings, principal, "admin_audit.html", rows=rows)
