"""Authentication, roles, tenant isolation, CSRF, MFA."""

from __future__ import annotations

import re
import time
from decimal import Decimal

import pyotp
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from helpers import BASE_URL, SYSTEM, World, dataset, heartbeat, live_settings, make_settings, sample
from sqlalchemy import select
from test_earnings_ledger import run_import
from test_payouts import IBAN, funded

from happymining.main import create_app
from happymining.models import API_CLIENT_SCOPES, AuditLog, EarningBucket, Operation, PayoutItem, User
from happymining.security import decrypt_text
from happymining.services import accounts, api_clients, payouts, receipts

PUBLIC = {
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/demo-login"),
    ("POST", "/api/v1/devices/enroll"),
}
UUID0 = "00000000-0000-0000-0000-000000000000"


def api_routes(app) -> list[tuple[str, str]]:
    """Every (method, concrete path) under /api/v1, found by walking the app's routes."""
    found: list[tuple[str, str]] = []

    def walk(routes):
        for route in routes:
            if isinstance(route, APIRoute):
                if route.path.startswith("/api/v1"):
                    for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                        found.append((method, route.path))
            for attr in ("routes",):
                inner = getattr(route, attr, None)
                if inner and not isinstance(route, APIRoute):
                    walk(inner)
            original = getattr(route, "original_router", None) or getattr(route, "router", None)
            if original is not None and getattr(original, "routes", None):
                walk(original.routes)

    walk(app.routes)
    return sorted(set(found))


# Three kinds of caller, three kinds of credential, three disjoint sets of routes.
DEVICE_PREFIX = "/api/v1/device/"
INTEGRATION_PREFIX = "/api/v1/integration"


def route_kind(path: str) -> str:
    if path.startswith(DEVICE_PREFIX):
        return "device"
    if path.startswith(INTEGRATION_PREFIX):
        return "client"
    return "human"


def concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", UUID0, path)


def call(client, method: str, path: str, **kw):
    body = {"json": {}} if method in ("POST", "PUT", "PATCH") else {}
    return client.request(method, concrete(path), **body, **kw)


def test_route_discovery_finds_the_api(app):
    routes = api_routes(app)
    assert len(routes) > 60, routes
    assert ("POST", "/api/v1/payout-batches/{batch_id}/approve") in routes
    assert ("POST", "/api/v1/device/heartbeat") in routes


def test_every_route_requires_authentication(app, client):
    """No route except login and enrollment answers an anonymous caller."""
    for method, path in api_routes(app):
        if (method, path) in PUBLIC:
            continue
        r = call(client, method, path)
        assert r.status_code == 401, f"{method} {path} answered {r.status_code} without credentials"
        expected = {"human": "unauthorized", "device": "device_unauthorized", "client": "client_unauthorized"}
        assert r.json()["error"]["code"] == expected[route_kind(path)], f"{method} {path}"


def test_credentials_of_one_kind_open_no_route_of_another_kind(app, client, world):
    """A session, a device credential and an API client token are not interchangeable anywhere."""
    owner = world.owner()
    machine, device_token = world.paired_machine(owner)
    issued = api_clients.create_client(
        world.session, world.settings, SYSTEM, name="all scopes", scopes=list(API_CLIENT_SCOPES)
    )
    world.commit()
    credentials = {
        "human": world.token(world.user("admin")),
        "device": device_token,
        "client": issued.token,
    }
    checked = 0
    for method, path in api_routes(app):
        if (method, path) in PUBLIC:
            continue
        for kind, token in credentials.items():
            if kind == route_kind(path):
                continue
            r = call(client, method, path, headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 401, (
                f"{method} {path} accepted a {kind} credential ({r.status_code} {r.text[:120]})"
            )
            checked += 1
    assert checked > 150


# What a user of an owner's organisation may reach, and the lowest organisation
# role that may (docs/appliance.md, section 3). A human route that is not in this
# table is refused to every owner's user: a new route has to be entered here with
# its role, or it fails the tests below, which forces the decision of who may call it.
SELF_SERVICE = {"/api/v1/auth/logout", "/api/v1/auth/mfa/enroll", "/api/v1/auth/mfa/activate"}
ORG_RANK = {"org_viewer": 1, "org_operator": 2, "org_admin": 3}
OWNER_ROUTES: dict[tuple[str, str], str] = {
    # The organisation's own machines and their state: every role.
    ("GET", "/api/v1/owners"): "org_viewer",
    ("GET", "/api/v1/owners/{owner_id}"): "org_viewer",
    ("GET", "/api/v1/machines"): "org_viewer",
    ("GET", "/api/v1/machines/{machine_id}"): "org_viewer",
    ("GET", "/api/v1/machines/{machine_id}/telemetry"): "org_viewer",
    ("GET", "/api/v1/machines/{machine_id}/operations"): "org_viewer",
    ("GET", "/api/v1/auth/me"): "org_viewer",
    # Money: administrators only.
    ("GET", "/api/v1/fee-schedules"): "org_admin",
    ("GET", "/api/v1/earnings/buckets"): "org_admin",
    ("GET", "/api/v1/earnings/buckets/{bucket_id}"): "org_admin",
    ("GET", "/api/v1/owners/{owner_id}/balance"): "org_admin",
    ("GET", "/api/v1/owners/{owner_id}/statement"): "org_admin",
    ("GET", "/api/v1/owners/{owner_id}/payouts"): "org_admin",
    ("GET", "/api/v1/owners/{owner_id}/beneficiary"): "org_admin",
    ("GET", "/api/v1/payout-items"): "org_admin",
    # The organisation's users, who manages a machine, remote access: administrators only.
    ("GET", "/api/v1/org/users"): "org_admin",
    ("POST", "/api/v1/org/users"): "org_admin",
    ("PATCH", "/api/v1/org/users/{user_id}"): "org_admin",
    ("GET", "/api/v1/machines/{machine_id}/remote-access"): "org_admin",
    ("PUT", "/api/v1/machines/{machine_id}/management"): "org_admin",
    ("POST", "/api/v1/machines/{machine_id}/remote-access/grants"): "org_admin",
    ("POST", "/api/v1/machines/{machine_id}/remote-access/grants/{grant_id}/revoke"): "org_admin",
    # The appliance configuration, exactly as the table of docs/appliance.md, section 12.
    ("GET", "/api/v1/appliance/catalog"): "org_viewer",
    ("GET", "/api/v1/machines/{machine_id}/appliance"): "org_viewer",
    ("PUT", "/api/v1/machines/{machine_id}/appliance/plugins/{plugin_id}"): "org_operator",
    ("DELETE", "/api/v1/machines/{machine_id}/appliance/plugins/{plugin_id}"): "org_operator",
    ("PUT", "/api/v1/machines/{machine_id}/appliance/schedules/{schedule_id}"): "org_operator",
    ("DELETE", "/api/v1/machines/{machine_id}/appliance/schedules/{schedule_id}"): "org_operator",
    ("POST", "/api/v1/machines/{machine_id}/appliance/jobs"): "org_operator",
    ("PUT", "/api/v1/machines/{machine_id}/appliance/mode"): "org_admin",
    ("PUT", "/api/v1/machines/{machine_id}/appliance/nas/{nas_id}"): "org_admin",
    ("DELETE", "/api/v1/machines/{machine_id}/appliance/nas/{nas_id}"): "org_admin",
    ("PUT", "/api/v1/machines/{machine_id}/appliance/vectorizer"): "org_admin",
    ("DELETE", "/api/v1/machines/{machine_id}/appliance/vectorizer"): "org_admin",
    ("PUT", "/api/v1/machines/{machine_id}/appliance/backup"): "org_admin",
    ("DELETE", "/api/v1/machines/{machine_id}/appliance/backup"): "org_admin",
    ("PUT", "/api/v1/machines/{machine_id}/appliance/update"): "org_admin",
    ("POST", "/api/v1/machines/{machine_id}/appliance/install-update"): "org_admin",
}


def human_routes(app) -> list[tuple[str, str]]:
    return [
        (method, path)
        for method, path in api_routes(app)
        if (method, path) not in PUBLIC and route_kind(path) == "human" and path not in SELF_SERVICE
    ]


def check_owner_routes(app, client, headers, org_role: str) -> int:
    """Call every human route as a user with ``org_role``. Returns how many were refused."""
    assert set(OWNER_ROUTES) <= set(human_routes(app)), set(OWNER_ROUTES) - set(human_routes(app))
    refused = 0
    for method, path in human_routes(app):
        r = call(client, method, path, headers=headers)
        needed = OWNER_ROUTES.get((method, path))
        if needed is not None and ORG_RANK[org_role] >= ORG_RANK[needed]:
            # Let through by the role check. With the placeholder id and the
            # empty body used here, what answers is the route itself.
            assert r.status_code in (200, 201, 400, 404, 422), (
                f"{org_role}: {method} {path}: {r.status_code} {r.text[:200]}"
            )
        else:
            assert r.status_code == 403, f"{org_role} reached {method} {path}: {r.status_code} {r.text[:200]}"
            assert r.json()["error"]["code"] == "forbidden", f"{method} {path}"
            refused += 1
    return refused


def test_owner_role_cannot_use_any_mutating_or_staff_route(app, client, world):
    """Owners cannot submit earnings, alter fees, record receipts or approve payouts.

    The caller here is an organisation's administrator, the most an owner's
    user can be: what it reaches beyond reading is its own organisation.
    """
    owner = world.owner()
    headers = world.auth(world.user("owner", owner))
    assert check_owner_routes(app, client, headers, "org_admin") > 50


@pytest.mark.parametrize("org_role", ["org_operator", "org_viewer"])
def test_operators_and_viewers_reach_no_money_no_users_and_no_staff_route(app, client, world, org_role):
    owner = world.owner()
    headers = world.auth(world.user("owner", owner, org_role=org_role))
    refused = check_owner_routes(app, client, headers, org_role)
    assert refused > 60
    # Spelled out for the routes that matter most: money and the organisation itself.
    for path in ("/api/v1/earnings/buckets", f"/api/v1/owners/{owner.id}/balance", "/api/v1/org/users"):
        assert client.get(path, headers=headers).status_code == 403, path


def test_auditor_is_read_only(app, client, world):
    headers = world.auth(world.user("auditor"))
    self_service = {"/api/v1/auth/logout", "/api/v1/auth/mfa/enroll", "/api/v1/auth/mfa/activate"}
    for method, path in api_routes(app):
        if (method, path) in PUBLIC or route_kind(path) != "human" or path in self_service:
            continue
        r = call(client, method, path, headers=headers)
        if method == "GET":
            assert r.status_code in (200, 404), f"{method} {path}: {r.status_code}"
        else:
            assert r.status_code == 403, f"auditor reached {method} {path}: {r.status_code}"


def two_tenants(world):
    """Two owners, each with a machine, telemetry, earnings, a balance and a payout."""
    world.fee()
    a, b = world.owner("Tenant A"), world.owner("Tenant B")
    provider = world.provider(dataset({"101": {}, "202": {}}, {"101": {1: "100"}, "202": {1: "300"}}))
    account = world.account(provider)
    machine_a, token_a = world.paired_machine(a, "a")
    machine_b, token_b = world.paired_machine(b, "b")
    world.bind(account, "101", machine_a)
    world.bind(account, "202", machine_b)
    run_import(world, provider, account, 1, 1)
    receipt, _ = receipts.record_receipt(
        world.session,
        SYSTEM,
        account,
        reference="R",
        received_on=world.today,
        amount=Decimal("400"),
        currency="USD",
        evidence_source="bank_statement",
        evidence_note="e",
        created_by=None,
    )
    receipts.allocate_period(world.session, SYSTEM, receipt.id, world.day(1), world.day(1), created_by=None)
    admin = world.user("admin")
    for owner in (a, b):
        payouts.set_beneficiary(
            world.session,
            world.settings,
            SYSTEM,
            owner.id,
            {"account_holder": owner.display_name, "iban": IBAN},
            admin.id,
        )
    payouts.prepare_batch(
        world.session, world.settings, SYSTEM, idempotency_key="tenant-batch-1", created_by=admin.id
    )
    world.commit()
    return a, b, machine_a, machine_b, token_a, token_b, admin


def test_owner_cannot_read_another_owners_data(client, world):
    a, b, machine_a, machine_b, token_a, token_b, admin = two_tenants(world)
    heartbeat(client, token_b, [sample(1)])
    h = world.auth(world.user("owner", a))
    bucket_b = world.session.execute(select(EarningBucket).where(EarningBucket.owner_id == b.id)).scalar_one()

    # Direct object access: reported as not found, never as forbidden.
    for path in (
        f"/api/v1/owners/{b.id}",
        f"/api/v1/owners/{b.id}/balance",
        f"/api/v1/owners/{b.id}/statement",
        f"/api/v1/owners/{b.id}/payouts",
        f"/api/v1/owners/{b.id}/beneficiary",
        f"/api/v1/machines/{machine_b.id}",
        f"/api/v1/machines/{machine_b.id}/telemetry",
        f"/api/v1/machines/{machine_b.id}/operations",
        f"/api/v1/earnings/buckets/{bucket_b.id}",
    ):
        r = client.get(path, headers=h)
        assert r.status_code == 404, f"{path}: {r.status_code}"

    # Filters cannot be widened to another tenant.
    for path in ("/api/v1/machines", "/api/v1/earnings/buckets", "/api/v1/payout-items"):
        assert client.get(f"{path}?owner_id={b.id}", headers=h).status_code == 404

    # Lists contain only the caller's own records.
    machines = client.get("/api/v1/machines", headers=h).json()["items"]
    assert [m["id"] for m in machines] == [str(machine_a.id)]
    buckets = client.get("/api/v1/earnings/buckets", headers=h).json()["items"]
    assert {x["owner_id"] for x in buckets} == {str(a.id)}
    items = client.get("/api/v1/payout-items", headers=h).json()["items"]
    assert {x["owner_id"] for x in items} == {str(a.id)}
    owners = client.get("/api/v1/owners", headers=h).json()["items"]
    assert [o["id"] for o in owners] == [str(a.id)]

    # Own data is readable and correct.
    balance = client.get(f"/api/v1/owners/{a.id}/balance", headers=h).json()
    assert balance["available_to_settle"] == "90.00000000"
    assert str(b.id) not in client.get(f"/api/v1/owners/{a.id}/statement", headers=h).text


def test_owner_sees_no_staff_fields(client, world):
    a, b, machine_a, *_ = two_tenants(world)
    h = world.auth(world.user("owner", a))
    machine = client.get(f"/api/v1/machines/{machine_a.id}", headers=h).json()
    assert "device_id" not in machine and "vast_machine_id_hint" not in machine
    item = client.get("/api/v1/payout-items", headers=h).json()["items"][0]
    assert "failure_reason" not in item and "external_reference" not in item
    beneficiary = client.get(f"/api/v1/owners/{a.id}/beneficiary", headers=h).json()
    assert beneficiary == {"owner_id": str(a.id), "on_file": True, "masked": "FR** **** 0189"}


def test_dashboard_pages_are_tenant_scoped(client, world):
    a, b, machine_a, machine_b, *_ = two_tenants(world)
    owner_user = world.user("owner", a)
    r = client.post("/demo-login", data={"email": owner_user.email}, follow_redirects=False)
    assert r.status_code == 303
    page = client.get("/dashboard")
    assert page.status_code == 200 and "Tenant A" in page.text and "Tenant B" not in page.text
    assert "SYNTHETIC" in page.text  # demo data is labelled
    assert client.get(f"/machines/{machine_b.id}").status_code == 404
    assert client.get(f"/owners/{b.id}").status_code == 404
    for admin_page in (
        "/admin/pairing",
        "/admin/provider",
        "/admin/exceptions",
        "/admin/fees",
        "/admin/settlements",
        "/admin/audit",
    ):
        assert client.get(admin_page).status_code == 403
    earnings = client.get("/earnings").text
    assert "#101" in earnings and "#202" not in earnings


def test_device_cannot_touch_another_devices_operation(client, world):
    a, b, machine_a, machine_b, token_a, token_b, admin = two_tenants(world)
    h = world.auth(admin)
    op = client.post(
        f"/api/v1/machines/{machine_b.id}/operations", headers=h, json={"type": "refresh_inventory"}
    )
    assert op.status_code == 201
    op_id = op.json()["id"]
    delivered = heartbeat(client, token_b, [sample(1)]).json()["operations"]
    nonce = delivered[0]["nonce"]
    # Device A knows the id and even the nonce: still nothing.
    r = client.post(
        f"/api/v1/device/operations/{op_id}/ack",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"status": "succeeded", "nonce": nonce},
    )
    assert r.status_code == 404
    assert heartbeat(client, token_a, [sample(1)]).json()["operations"] == []
    world.session.expire_all()
    assert world.session.get(Operation, op_id).status == "delivered"


def test_device_has_no_access_to_financial_routes(app, client, world):
    a, b, machine_a, machine_b, token_a, *_ = two_tenants(world)
    h = {"Authorization": f"Bearer {token_a}"}
    for path in (
        f"/api/v1/owners/{a.id}/balance",
        "/api/v1/earnings/buckets",
        "/api/v1/receipts",
        "/api/v1/payout-batches",
        "/api/v1/ledger/entries",
        "/api/v1/fee-schedules",
    ):
        assert client.get(path, headers=h).status_code == 401
    assert (
        client.post(
            "/api/v1/provider/import-earnings", headers=h, json={"start": "2026-01-01", "end": "2026-01-02"}
        ).status_code
        == 401
    )


# --- browser sessions: CSRF and cookies ------------------------------------


def test_cookie_session_needs_csrf_token_for_unsafe_requests(client, world):
    admin = world.user("admin")
    login = client.post("/api/v1/auth/demo-login", json={"email": admin.email})
    csrf = login.json()["csrf_token"]
    cookie = login.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert client.get("/api/v1/owners").status_code == 200  # safe method: cookie is enough

    body = {"display_name": "X"}
    assert client.post("/api/v1/owners", json=body).status_code == 403
    assert client.post("/api/v1/owners", json=body, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    r = client.post(
        "/api/v1/owners", json=body, headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"}
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "csrf_failed"
    assert client.post("/api/v1/owners", json=body, headers={"X-CSRF-Token": csrf}).status_code == 201
    assert (
        client.post(
            "/api/v1/owners", json=body, headers={"X-CSRF-Token": csrf, "Origin": BASE_URL}
        ).status_code
        == 201
    )


def test_dashboard_forms_need_the_csrf_field(client, world):
    admin, owner = world.user("admin"), world.owner()
    client.post("/demo-login", data={"email": admin.email})
    form = {"owner_id": str(owner.id), "machine_label": "x"}
    assert client.post("/admin/pairing", data=form).status_code == 403
    csrf = client.get("/api/v1/auth/me").json()["csrf_token"]
    ok = client.post("/admin/pairing", data={**form, "csrf_token": csrf})
    assert ok.status_code == 200 and "HM-" in ok.text and ok.headers["cache-control"] == "no-store"


def test_secure_cookie_flag_follows_configuration(world):
    live = live_settings()
    w = World(live)
    try:
        user = w.user("auditor", password="correct horse battery staple")
        with TestClient(create_app(live), base_url="https://api.example.test") as c:
            r = c.post(
                "/api/v1/auth/login", json={"email": user.email, "password": "correct horse battery staple"}
            )
            assert r.status_code == 200
            assert "Secure" in r.headers["set-cookie"]
            assert r.headers["strict-transport-security"].startswith("max-age=")
    finally:
        w.close()


def test_logout_revokes_the_session(client, world):
    h = world.auth(world.user("admin"))
    assert client.get("/api/v1/auth/me", headers=h).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=h).status_code == 200
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401


def test_cross_site_cors_is_closed_by_default(client):
    r = client.options(
        "/api/v1/owners", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"}
    )
    assert "access-control-allow-origin" not in r.headers


def test_unknown_host_header_is_refused(app):
    with TestClient(app, base_url="http://attacker.example") as c:
        for path in ("/login", "/readyz", "/api/v1/auth/me", "/static/app.css", "/metrics"):
            assert c.get(path).status_code == 400, path
        # Liveness is exempt: probes inside the deployment use internal names,
        # and it returns nothing but a static "ok".
        health = c.get("/healthz")
        assert health.status_code == 200 and set(health.json()) == {"status", "version"}


def test_security_headers_are_set(client):
    r = client.get("/login")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "script-src 'self'" in r.headers["content-security-policy"]


# --- login, MFA, demo login -------------------------------------------------


def test_password_login_and_generic_failure(client, world):
    user = world.user("auditor", demo=False, password="a-long-enough-password")
    ok = client.post("/api/v1/auth/login", json={"email": user.email, "password": "a-long-enough-password"})
    assert ok.status_code == 200 and ok.json()["user"]["role"] == "auditor"
    wrong = client.post("/api/v1/auth/login", json={"email": user.email, "password": "nope-nope-nope"})
    unknown = client.post(
        "/api/v1/auth/login", json={"email": "ghost@test.invalid", "password": "nope-nope-nope"}
    )
    for r in (wrong, unknown):
        assert r.status_code == 401
    strip = lambda r: {k: v for k, v in r.json()["error"].items() if k != "request_id"}  # noqa: E731
    assert strip(wrong) == strip(unknown)
    # The failure is in the audit trail with the real reason, without the password.
    failures = (
        world.session.execute(select(AuditLog).where(AuditLog.action == "auth.login_failed")).scalars().all()
    )
    assert len(failures) == 2 and "nope-nope-nope" not in str([f.details for f in failures])
    stored = world.session.execute(select(User.password_hash).where(User.id == user.id)).scalar_one()
    assert stored.startswith("$argon2id$") and "a-long-enough-password" not in stored


def test_admin_needs_mfa_in_live_mode():
    live = live_settings()
    w = World(live)
    try:
        password = "an-admin-password-of-some-length"
        admin = w.user("admin", password=password)
        with TestClient(create_app(live), base_url="https://api.example.test") as c:
            r = c.post("/api/v1/auth/login", json={"email": admin.email, "password": password})
            assert r.status_code == 403 and r.json()["error"]["code"] == "mfa_enrollment_required"

            # Enroll (the CLI does this), then log in with a code.
            accounts.begin_mfa_enrollment(w.session, live, admin)
            secret = decrypt_text(live, admin.totp_secret_enc)
            totp = pyotp.TOTP(secret)
            activation_code = totp.now()
            accounts.activate_mfa(w.session, live, SYSTEM, admin, activation_code)
            w.commit()

            def attempt(code=None):
                body = {"email": admin.email, "password": password}
                if code is not None:
                    body["totp_code"] = code
                return c.post("/api/v1/auth/login", json=body)

            assert attempt().status_code == 401  # password alone is not enough
            assert attempt("000000").status_code == 401
            # The code used to activate MFA cannot be replayed as a login.
            assert attempt(activation_code).status_code == 401
            # The next time-step's code is accepted (one step of clock drift is allowed)...
            next_code = totp.at(int(time.time()), 1)
            good = attempt(next_code)
            assert good.status_code == 200
            # ...exactly once.
            assert attempt(next_code).status_code == 401
            h = {"Authorization": f"Bearer {good.json()['token']}"}
            assert c.get("/api/v1/provider/health", headers=h).status_code == 200
        # The TOTP secret is encrypted at rest.
        assert secret not in admin.totp_secret_enc
    finally:
        w.close()


def test_demo_login_does_not_exist_in_live_mode():
    live = live_settings()
    w = World(live)
    try:
        ghost = w.user("admin", demo=True)  # a leftover demo account must be useless in LIVE
        with TestClient(create_app(live), base_url="https://api.example.test") as c:
            r = c.post("/api/v1/auth/demo-login", json={"email": ghost.email})
            assert r.status_code == 409 and r.json()["error"]["code"] == "feature_disabled"
            assert c.get("/login").text.count("Enter demo") == 0
            assert "DEMO MODE" not in c.get("/login").text
            assert c.get("/api/docs").status_code == 404  # interactive docs are demo-only
    finally:
        w.close()


def test_demo_accounts_cannot_use_password_login(client, world):
    demo = world.user("admin", demo=True, password="some-long-password-123")
    r = client.post("/api/v1/auth/login", json={"email": demo.email, "password": "some-long-password-123"})
    assert r.status_code == 401


def test_demo_session_dies_when_demo_login_is_switched_off(world):
    token = world.token(world.user("admin"))
    off = create_app(make_settings(demo_login_enabled=False))
    with TestClient(off, base_url=BASE_URL) as c:
        assert c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_login_is_rate_limited(world):
    limited = create_app(make_settings(login_rate_limit_per_minute=3))
    with TestClient(limited, base_url=BASE_URL) as c:
        codes = [
            c.post("/api/v1/auth/login", json={"email": "x@test.invalid", "password": "p" * 12}).status_code
            for _ in range(6)
        ]
    assert codes[:3] == [401, 401, 401] and set(codes[3:]) == {429}


# --- money input validation at the API edge --------------------------------


def test_money_must_be_a_decimal_string(client, world):
    owner, account, admin = funded(world)
    h = world.auth(admin)
    base = {
        "provider_account_id": str(account.id),
        "reference": "R-API",
        "received_on": world.today.isoformat(),
        "currency": "USD",
        "evidence_source": "bank_statement",
        "evidence_note": "statement",
    }
    for bad in (12.5, 12, "12,50", "1e3", "abc", "0.123456789"):
        r = client.post("/api/v1/receipts", headers=h, json={**base, "amount": bad})
        assert r.status_code == 422, bad
    ok = client.post("/api/v1/receipts", headers=h, json={**base, "amount": "12.50"})
    assert ok.status_code == 201 and ok.json()["amount"] == "12.50000000"
    again = client.post("/api/v1/receipts", headers=h, json={**base, "amount": "12.50"})
    assert again.status_code == 200 and again.json()["created"] is False


def test_settlement_api_end_to_end_with_idempotency_header(client, world):
    owner, account, admin = funded(world)
    h = world.auth(admin)
    assert client.post("/api/v1/payout-batches", headers=h, json={}).status_code == 422  # header required
    first = client.post("/api/v1/payout-batches", headers={**h, "Idempotency-Key": "api-key-00001"}, json={})
    second = client.post("/api/v1/payout-batches", headers={**h, "Idempotency-Key": "api-key-00001"}, json={})
    assert (first.status_code, second.status_code) == (201, 200)
    assert first.json()["id"] == second.json()["id"] and second.json()["created"] is False
    batch_id = first.json()["id"]

    assert client.post(f"/api/v1/payout-batches/{batch_id}/approve", headers=h).json()["changed"] is True
    assert client.post(f"/api/v1/payout-batches/{batch_id}/approve", headers=h).json()["changed"] is False
    exports = [client.post(f"/api/v1/payout-batches/{batch_id}/export", headers=h) for _ in range(2)]
    assert exports[0].content == exports[1].content
    assert exports[0].headers["x-content-sha256"] == exports[1].headers["x-content-sha256"]
    assert client.post(f"/api/v1/payout-batches/{batch_id}/submit", headers=h).json()["status"] == "submitted"

    item = world.session.execute(select(PayoutItem)).scalar_one()
    assert (
        client.post(f"/api/v1/payout-items/{item.id}/confirm", headers=h, json={"reference": ""}).status_code
        == 422
    )
    paid = client.post(f"/api/v1/payout-items/{item.id}/confirm", headers=h, json={"reference": "BANK-1"})
    assert paid.status_code == 200 and paid.json()["status"] == "confirmed_paid"
    verify = client.get("/api/v1/ledger/verify", headers=h).json()
    assert verify["ok"], verify
    chain = client.get("/api/v1/audit-log/verify", headers=h).json()
    assert chain["ok"] and chain["checked"] > 5


def test_audit_chain_detects_tampering(client, world):
    from sqlalchemy import text

    owner, account, admin = funded(world)
    h = world.auth(admin)
    assert client.get("/api/v1/audit-log/verify", headers=h).json()["ok"]
    # Someone with direct database access disables the trigger and edits a row.
    world.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    world.session.execute(text("UPDATE audit_log SET action = 'nothing.to.see' WHERE id = 3"))
    world.session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    world.commit()
    result = client.get("/api/v1/audit-log/verify", headers=h).json()
    assert result["ok"] is False and result["first_broken_id"] == 3


@pytest.mark.parametrize("path", ["/api/v1/nope", "/api/v1/machines/not-a-uuid"])
def test_errors_use_the_envelope(client, world, path):
    r = client.get(path, headers=world.auth(world.user("admin")))
    assert r.status_code in (404, 422)
    assert set(r.json()["error"]) == {"code", "message", "request_id"}
    assert r.headers["x-request-id"] == r.json()["error"]["request_id"]
