"""An owner's organisation: its users, their roles, and what each role may reach.

docs/appliance.md, section 3. Covers the routes under ``/api/v1/org/users``,
the rule that an organisation always keeps one active administrator (also when
requests overlap), isolation between organisations, money being visible to
administrators only (API and dashboard), and the Organisation page.
"""

from __future__ import annotations

import threading
import uuid

import pytest
from fastapi.testclient import TestClient
from helpers import BASE_URL, SYSTEM, World
from sqlalchemy import func, select
from test_access_control import two_tenants
from test_security_regressions import wait_until_blocked_or_done

from happymining.db import session_factory
from happymining.errors import Conflict, Forbidden
from happymining.models import AuditLog, EarningBucket, Operation, RemoteAccessGrant, User, UserSession
from happymining.services import accounts
from happymining.services import org as org_service

PASSWORD = "a-long-enough-password"
UUID0 = "00000000-0000-0000-0000-000000000000"
ROLES = ("org_admin", "org_operator", "org_viewer")


# --- helpers ---------------------------------------------------------------


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def envelope(response) -> dict[str, str]:
    body = response.json()
    assert set(body) == {"error"}, body
    return {k: v for k, v in body["error"].items() if k != "request_id"}


def count(world: World, model) -> int:
    world.session.expire_all()
    return world.session.execute(select(func.count()).select_from(model)).scalar_one()


def audit_rows(world: World, action: str) -> list[AuditLog]:
    world.session.expire_all()
    return list(
        world.session.execute(
            select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)
        ).scalars()
    )


def fresh(world: World, user: User) -> User:
    world.session.expire_all()
    return world.session.get(User, user.id)


def browser_for(app, user) -> TestClient:
    """A cookie session on the same application, signed in through the demo form."""
    browser = TestClient(app, base_url=BASE_URL)
    r = browser.post("/demo-login", data={"email": user.email}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard", r.headers
    return browser


def csrf_of(browser: TestClient) -> str:
    return browser.get("/api/v1/auth/me").json()["csrf_token"]


def active_admins(world: World, owner) -> list[uuid.UUID]:
    world.session.expire_all()
    return list(
        world.session.execute(
            select(User.id).where(
                User.owner_id == owner.id, User.org_role == "org_admin", User.is_active.is_(True)
            )
        ).scalars()
    )


def new_user_body(**overrides) -> dict:
    return {
        "email": f"new-{uuid.uuid4().hex[:8]}@test.invalid",
        "display_name": "New Person",
        "org_role": "org_operator",
        "password": PASSWORD,
        **overrides,
    }


# --- an administrator runs the organisation --------------------------------


def test_org_admin_lists_adds_and_changes_the_users_of_the_organisation(client, world):
    owner, other = world.owner("Acme"), world.owner("Other")
    admin = world.user("owner", owner)
    world.user("owner", other)
    world.user("admin")  # staff: never in the list
    h = world.auth(admin)

    listing = client.get("/api/v1/org/users", headers=h)
    assert listing.status_code == 200 and listing.json()["total"] == 1
    (me,) = listing.json()["items"]
    assert me == {
        "id": str(admin.id),
        "owner_id": str(owner.id),
        "email": admin.email,
        "display_name": "",
        "org_role": "org_admin",
        "is_active": True,
        "mfa_enabled": False,
        "created_at": me["created_at"],
        "last_login_at": me["last_login_at"],
    }

    created = client.post("/api/v1/org/users", headers=h, json=new_user_body(email="  Op@Test.Invalid "))
    assert created.status_code == 201, created.text
    new = created.json()
    assert (new["email"], new["org_role"], new["owner_id"]) == (
        "op@test.invalid",
        "org_operator",
        str(owner.id),
    )
    assert new["is_active"] is True and "password" not in created.text
    stored = world.session.get(User, uuid.UUID(new["id"]))
    assert (
        stored.role == "owner" and stored.owner_id == owner.id and stored.password_hash.startswith("$argon2")
    )

    # The new user signs in with the password and holds exactly that role.
    signed_in = client.post("/api/v1/auth/login", json={"email": "op@test.invalid", "password": PASSWORD})
    assert signed_in.status_code == 200
    op = bearer(signed_in.json()["token"])
    assert client.get("/api/v1/machines", headers=op).status_code == 200
    assert client.get("/api/v1/org/users", headers=op).status_code == 403

    renamed = client.patch(
        f"/api/v1/org/users/{new['id']}", headers=h, json={"org_role": "org_viewer", "display_name": "Viewer"}
    )
    assert renamed.status_code == 200
    assert (renamed.json()["org_role"], renamed.json()["display_name"]) == ("org_viewer", "Viewer")
    ids = [u["id"] for u in client.get("/api/v1/org/users", headers=h).json()["items"]]
    assert ids == [str(admin.id), new["id"]]

    # Validation: the same rules as everywhere else.
    for body, status in (
        (new_user_body(password="short"), 422),
        (new_user_body(org_role="owner"), 422),
        (new_user_body(email="not-an-address"), 400),
        (new_user_body(email="op@test.invalid"), 409),
        ({k: v for k, v in new_user_body().items() if k != "password"}, 422),
    ):
        assert client.post("/api/v1/org/users", headers=h, json=body).status_code == status, body
    assert client.patch(f"/api/v1/org/users/{new['id']}", headers=h, json={}).status_code == 400
    assert count(world, User) == 4


def test_a_change_of_role_takes_effect_on_the_next_request(client, world):
    owner = world.owner()
    admin, second = world.user("owner", owner), world.user("owner", owner)
    h, h2 = world.auth(admin), world.auth(second)
    assert client.get("/api/v1/org/users", headers=h2).status_code == 200
    assert client.get(f"/api/v1/owners/{owner.id}/balance", headers=h2).status_code == 200

    demoted = client.patch(f"/api/v1/org/users/{second.id}", headers=h, json={"org_role": "org_viewer"})
    assert demoted.status_code == 200
    # Same session, no new login: the role is read on every request.
    assert client.get("/api/v1/org/users", headers=h2).status_code == 403
    assert client.get(f"/api/v1/owners/{owner.id}/balance", headers=h2).status_code == 403
    assert client.get("/api/v1/machines", headers=h2).status_code == 200


def test_deactivating_ends_the_users_sessions_and_reactivating_lets_them_back(app, client, world):
    owner = world.owner()
    admin = world.user("owner", owner)
    target = world.user("owner", owner, org_role="org_operator")
    h = world.auth(admin)
    api_token = world.token(target)
    browser = browser_for(app, target)
    assert client.get("/api/v1/auth/me", headers=bearer(api_token)).status_code == 200
    assert browser.get("/dashboard").status_code == 200

    off = client.patch(f"/api/v1/org/users/{target.id}", headers=h, json={"is_active": False})
    assert off.status_code == 200 and off.json()["is_active"] is False
    assert client.get("/api/v1/auth/me", headers=bearer(api_token)).status_code == 401
    page = browser.get("/dashboard", follow_redirects=False)
    assert page.status_code == 303 and page.headers["location"] == "/login"
    assert client.post("/api/v1/auth/demo-login", json={"email": target.email}).status_code == 401
    sessions = (
        world.session.execute(select(UserSession).where(UserSession.user_id == target.id)).scalars().all()
    )
    assert len(sessions) == 2 and all(s.revoked_at is not None for s in sessions)
    # The administrator who did it is still signed in.
    assert client.get("/api/v1/auth/me", headers=h).status_code == 200

    on = client.patch(f"/api/v1/org/users/{target.id}", headers=h, json={"is_active": True})
    assert on.status_code == 200 and on.json()["is_active"] is True
    assert (
        client.get("/api/v1/auth/me", headers=bearer(api_token)).status_code == 401
    )  # old session stays dead
    assert client.get("/api/v1/auth/me", headers=world.auth(target)).status_code == 200


def test_every_change_is_audited_without_the_password(client, world):
    owner = world.owner()
    admin = world.user("owner", owner)
    h = world.auth(admin)
    secret = "this-password-must-never-be-logged"
    new = client.post("/api/v1/org/users", headers=h, json=new_user_body(password=secret)).json()
    client.patch(f"/api/v1/org/users/{new['id']}", headers=h, json={"org_role": "org_admin"})
    client.patch(f"/api/v1/org/users/{new['id']}", headers=h, json={"is_active": False})
    # Saying again what is already so changes nothing and records nothing.
    again = client.patch(f"/api/v1/org/users/{new['id']}", headers=h, json={"is_active": False})
    assert again.status_code == 200

    (created,) = audit_rows(world, "org.user.create")
    assert (created.actor_type, created.actor_id) == ("user", str(admin.id))
    assert (created.object_id, created.owner_id) == (new["id"], owner.id)
    assert created.details == {"email": new["email"], "org_role": "org_operator", "is_active": True}
    promoted, deactivated = audit_rows(world, "org.user.update")
    assert promoted.details == {
        "before": {"org_role": "org_operator", "is_active": True},
        "after": {"org_role": "org_admin", "is_active": True},
        "display_name_changed": False,
        "sessions_revoked": 0,
    }
    assert deactivated.details["before"] == {"org_role": "org_admin", "is_active": True}
    assert deactivated.details["after"] == {"org_role": "org_admin", "is_active": False}
    assert (deactivated.actor_id, deactivated.object_id) == (str(admin.id), new["id"])
    trail = world.session.execute(select(AuditLog)).scalars().all()
    assert secret not in str([(row.action, row.details) for row in trail])


# --- the permission matrix of section 3 ------------------------------------

# kind of action -> (org_admin, org_operator, org_viewer). Everything goes through HTTP.
MATRIX = {
    "see the machines": (200, 200, 200),
    "see one machine": (200, 200, 200),
    "see telemetry": (200, 200, 200),
    "see the operation history": (200, 200, 200),
    "see the balance": (200, 403, 403),
    "see the statement": (200, 403, 403),
    "see earnings": (200, 403, 403),
    "see payouts": (200, 403, 403),
    "see the beneficiary": (200, 403, 403),
    "see the fees": (200, 403, 403),
    "list users": (200, 403, 403),
    "add a user": (201, 403, 403),
    "change a user": (200, 403, 403),
    "see remote access": (200, 403, 403),
    "change management": (200, 403, 403),
    "grant remote access": (201, 403, 403),
    "revoke remote access": (200, 403, 403),
    # Staff routes: no organisation role opens them.
    "request an operation": (403, 403, 403),
    "create a pairing code": (403, 403, 403),
    "read the audit trail": (403, 403, 403),
}


@pytest.mark.parametrize("position,org_role", list(enumerate(ROLES)))
def test_each_organisation_role_may_do_exactly_what_section_3_says(client, world, position, org_role):
    owner = world.owner()
    boss = world.user("owner", owner)  # keeps the organisation administered whatever the caller is
    colleague = world.user("owner", owner, org_role="org_viewer")
    machine, _ = world.paired_machine(owner)
    grant = RemoteAccessGrant(machine_id=machine.id, owner_id=owner.id, level="view", granted_by=boss.id)
    world.session.add(grant)
    world.commit()
    caller = boss if org_role == "org_admin" else world.user("owner", owner, org_role=org_role)
    h = world.auth(caller)
    m, o = f"/api/v1/machines/{machine.id}", f"/api/v1/owners/{owner.id}"
    before = {model: count(world, model) for model in (User, RemoteAccessGrant, Operation)}

    actions = {
        "see the machines": lambda: client.get("/api/v1/machines", headers=h),
        "see one machine": lambda: client.get(m, headers=h),
        "see telemetry": lambda: client.get(f"{m}/telemetry", headers=h),
        "see the operation history": lambda: client.get(f"{m}/operations", headers=h),
        "see the balance": lambda: client.get(f"{o}/balance", headers=h),
        "see the statement": lambda: client.get(f"{o}/statement", headers=h),
        "see earnings": lambda: client.get("/api/v1/earnings/buckets", headers=h),
        "see payouts": lambda: client.get(f"{o}/payouts", headers=h),
        "see the beneficiary": lambda: client.get(f"{o}/beneficiary", headers=h),
        "see the fees": lambda: client.get("/api/v1/fee-schedules", headers=h),
        "list users": lambda: client.get("/api/v1/org/users", headers=h),
        "add a user": lambda: client.post("/api/v1/org/users", headers=h, json=new_user_body()),
        "change a user": lambda: client.patch(
            f"/api/v1/org/users/{colleague.id}", headers=h, json={"display_name": "Renamed"}
        ),
        "see remote access": lambda: client.get(f"{m}/remote-access", headers=h),
        "change management": lambda: client.put(
            f"{m}/management", headers=h, json={"management": "customer"}
        ),
        "grant remote access": lambda: client.post(
            f"{m}/remote-access/grants",
            headers=h,
            json={"level": "manage", "expires_in_hours": 2, "reason": "matrix"},
        ),
        "revoke remote access": lambda: client.post(f"{m}/remote-access/grants/{grant.id}/revoke", headers=h),
        "request an operation": lambda: client.post(
            f"{m}/operations", headers=h, json={"type": "refresh_inventory"}
        ),
        "create a pairing code": lambda: client.post(
            "/api/v1/enrollment-requests", headers=h, json={"owner_id": str(owner.id), "machine_label": "x"}
        ),
        "read the audit trail": lambda: client.get("/api/v1/audit-log", headers=h),
    }
    assert set(actions) == set(MATRIX)
    for name, send in actions.items():
        response = send()
        assert response.status_code == MATRIX[name][position], f"{org_role}: {name}: {response.text[:200]}"
        if response.status_code == 403:
            assert envelope(response)["code"] == "forbidden", name

    after = {model: count(world, model) for model in (User, RemoteAccessGrant, Operation)}
    if org_role == "org_admin":
        assert (after[User], after[RemoteAccessGrant]) == (before[User] + 1, before[RemoteAccessGrant] + 1)
    else:
        # A refusal changes nothing.
        assert after == before
        assert fresh(world, colleague).display_name == ""
        world.session.refresh(machine)
        world.session.refresh(grant)
        assert machine.management == "company" and grant.revoked_at is None
        assert audit_rows(world, "org.user.create") == [] and audit_rows(world, "org.user.update") == []
    assert after[Operation] == 0


# --- HappyMining staff -----------------------------------------------------


def test_staff_admin_manages_any_organisation_by_naming_it(client, world):
    acme, other = world.owner("Acme"), world.owner("Other")
    acme_user, other_user = world.user("owner", acme), world.user("owner", other)
    staff = world.user("admin")
    h = world.auth(staff)

    everyone = client.get("/api/v1/org/users", headers=h).json()["items"]
    assert {u["id"] for u in everyone} == {str(acme_user.id), str(other_user.id)}  # no staff account
    only_acme = client.get("/api/v1/org/users", headers=h, params={"owner_id": str(acme.id)}).json()["items"]
    assert [u["id"] for u in only_acme] == [str(acme_user.id)]

    # Creating needs the organisation to be named, and it has to exist.
    assert client.post("/api/v1/org/users", headers=h, json=new_user_body()).status_code == 400
    assert client.post("/api/v1/org/users", headers=h, json=new_user_body(owner_id=UUID0)).status_code == 404
    created = client.post(
        "/api/v1/org/users", headers=h, json=new_user_body(owner_id=str(acme.id), org_role="org_admin")
    )
    assert created.status_code == 201 and created.json()["owner_id"] == str(acme.id)
    changed = client.patch(
        f"/api/v1/org/users/{created.json()['id']}", headers=h, json={"org_role": "org_viewer"}
    )
    assert changed.status_code == 200 and changed.json()["org_role"] == "org_viewer"
    (row,) = audit_rows(world, "org.user.update")
    assert (row.actor_id, row.owner_id) == (str(staff.id), acme.id)


def test_auditor_reads_organisations_and_changes_nothing(client, world):
    owner = world.owner()
    user = world.user("owner", owner)
    h = world.auth(world.user("auditor"))
    listing = client.get("/api/v1/org/users", headers=h, params={"owner_id": str(owner.id)})
    assert listing.status_code == 200 and [u["id"] for u in listing.json()["items"]] == [str(user.id)]
    refused = (
        client.post("/api/v1/org/users", headers=h, json=new_user_body(owner_id=str(owner.id))),
        client.patch(f"/api/v1/org/users/{user.id}", headers=h, json={"display_name": "x"}),
    )
    assert [r.status_code for r in refused] == [403, 403]
    assert count(world, User) == 2 and fresh(world, user).display_name == ""


def test_staff_accounts_do_not_exist_for_these_routes(client, world):
    owner = world.owner()
    org_admin = world.user("owner", owner)
    staff, auditor = world.user("admin"), world.user("auditor")
    for caller in (org_admin, staff):
        h = world.auth(caller)
        for target in (staff, auditor):
            for body in ({"is_active": False}, {"org_role": "org_admin"}, {"display_name": "pwned"}):
                r = client.patch(f"/api/v1/org/users/{target.id}", headers=h, json=body)
                assert r.status_code == 404, (caller.role, target.role, body)
        listed = {u["id"] for u in client.get("/api/v1/org/users", headers=h).json()["items"]}
        assert listed == {str(org_admin.id)}
    for account in (staff, auditor):
        row = fresh(world, account)
        assert row.is_active and row.org_role is None and row.display_name == ""
    assert audit_rows(world, "org.user.update") == []


def test_nobody_can_create_staff_change_a_role_or_move_a_user(client, world):
    acme, other = world.owner("Acme"), world.owner("Other")
    admin, member = world.user("owner", acme), world.user("owner", acme, org_role="org_viewer")
    for caller in (admin, world.user("admin")):
        h = world.auth(caller)
        for extra in (
            {"role": "admin"},
            {"owner_id": str(other.id)},
            {"password": "another-long-password"},
            {"email": "moved@test.invalid"},
            {"is_demo": True},
            {"mfa_enabled": False},
        ):
            r = client.patch(f"/api/v1/org/users/{member.id}", headers=h, json={"display_name": "x", **extra})
            assert r.status_code == 422, (caller.role, extra, r.text)
        for extra in ({"role": "admin"}, {"role": "auditor"}, {"is_demo": True}):
            body = new_user_body(owner_id=str(acme.id), **extra)
            assert client.post("/api/v1/org/users", headers=h, json=body).status_code == 422, extra
    row = fresh(world, member)
    assert (row.role, row.owner_id, row.org_role, row.display_name) == ("owner", acme.id, "org_viewer", "")
    assert count(world, User) == 3
    assert world.session.execute(select(func.count()).where(User.role != "owner")).scalar_one() == 1


# --- isolation between organisations ---------------------------------------


def test_another_organisations_users_do_not_exist_for_an_org_admin(client, world):
    acme, other = world.owner("Acme"), world.owner("Other")
    admin = world.user("owner", acme)
    theirs = world.user("owner", other)
    their_viewer = world.user("owner", other, org_role="org_viewer")
    h = world.auth(admin)

    assert client.get("/api/v1/org/users", headers=h, params={"owner_id": str(other.id)}).status_code == 404
    assert client.get("/api/v1/org/users", headers=h, params={"owner_id": str(acme.id)}).status_code == 200
    listed = client.get("/api/v1/org/users", headers=h).json()
    assert [u["id"] for u in listed["items"]] == [str(admin.id)] and listed["total"] == 1

    planted = client.post("/api/v1/org/users", headers=h, json=new_user_body(owner_id=str(other.id)))
    assert planted.status_code == 404
    for target in (theirs, their_viewer):
        for body in ({"org_role": "org_viewer"}, {"is_active": False}, {"display_name": "x"}):
            r = client.patch(f"/api/v1/org/users/{target.id}", headers=h, json=body)
            assert r.status_code == 404 and envelope(r)["code"] == "not_found", body
    # Indistinguishable from an id that does not exist at all.
    assert client.patch(f"/api/v1/org/users/{UUID0}", headers=h, json={"is_active": False}).status_code == 404
    assert fresh(world, theirs).org_role == "org_admin" and fresh(world, theirs).is_active
    assert fresh(world, their_viewer).display_name == ""
    assert count(world, User) == 3
    assert audit_rows(world, "org.user.create") == [] and audit_rows(world, "org.user.update") == []


# --- an organisation always keeps one active administrator -----------------


def test_the_last_active_administrator_cannot_be_demoted_or_deactivated(client, world):
    owner = world.owner()
    only = world.user("owner", owner)
    world.user("owner", owner, org_role="org_operator")  # other users do not count
    h = world.auth(only)
    staff = world.auth(world.user("admin"))

    for headers in (h, staff):
        for body in ({"org_role": "org_operator"}, {"org_role": "org_viewer"}, {"is_active": False}):
            r = client.patch(f"/api/v1/org/users/{only.id}", headers=headers, json=body)
            assert r.status_code == 409 and envelope(r)["code"] == "conflict", body
            assert "last active administrator" in r.json()["error"]["message"]
    # The older staff route that switches any account off keeps the rule too.
    assert client.post(f"/api/v1/users/{only.id}/deactivate", headers=staff).status_code == 409
    assert active_admins(world, owner) == [only.id]
    assert client.get("/api/v1/auth/me", headers=h).status_code == 200
    assert audit_rows(world, "org.user.update") == [] and audit_rows(world, "user.deactivate") == []

    # With a second administrator either of them may step down, themselves included.
    second = world.user("owner", owner)
    stepped_down = client.patch(f"/api/v1/org/users/{only.id}", headers=h, json={"org_role": "org_viewer"})
    assert stepped_down.status_code == 200
    assert active_admins(world, owner) == [second.id]
    # ... and now the second one is the last.
    h2 = world.auth(second)
    assert (
        client.patch(f"/api/v1/org/users/{second.id}", headers=h2, json={"is_active": False}).status_code
        == 409
    )

    # A deactivated administrator does not count as "another one".
    third = world.user("owner", owner)
    assert (
        client.patch(f"/api/v1/org/users/{third.id}", headers=h2, json={"is_active": False}).status_code
        == 200
    )
    refused = client.patch(f"/api/v1/org/users/{second.id}", headers=h2, json={"org_role": "org_operator"})
    assert refused.status_code == 409
    # Renaming the last administrator is not a demotion.
    assert (
        client.patch(f"/api/v1/org/users/{second.id}", headers=h2, json={"display_name": "S"}).status_code
        == 200
    )
    assert active_admins(world, owner) == [second.id]


def test_staff_deactivating_one_of_two_administrators_is_allowed(client, world):
    owner = world.owner()
    first, second = world.user("owner", owner), world.user("owner", owner)
    staff = world.auth(world.user("admin"))
    assert client.post(f"/api/v1/users/{first.id}/deactivate", headers=staff).status_code == 200
    assert client.post(f"/api/v1/users/{second.id}/deactivate", headers=staff).status_code == 409
    assert active_admins(world, owner) == [second.id]


def test_two_overlapping_demotions_cannot_leave_an_organisation_without_administrator(world):
    """Request two has to wait for request one, and then sees what it did."""
    owner = world.owner()
    first, second = world.user("owner", owner), world.user("owner", owner)
    staff = world.user("admin")
    token = world.token(staff)
    ahead, behind = session_factory()(), session_factory()()
    outcome: list[str] = []

    def demote_first() -> None:
        try:
            principal = accounts.resolve_session(behind, world.settings, token, via_cookie=False)
            org_service.update_org_user(behind, principal, SYSTEM, first.id, org_role="org_viewer")
            behind.commit()
            outcome.append("demoted")
        except Conflict:
            behind.rollback()
            outcome.append("refused")

    try:
        principal = accounts.resolve_session(ahead, world.settings, token, via_cookie=False)
        # Request one: checked and applied, not yet committed.
        org_service.update_org_user(ahead, principal, SYSTEM, second.id, org_role="org_viewer")
        thread = threading.Thread(target=demote_first)  # request two arrives in the meantime
        thread.start()
        wait_until_blocked_or_done(world, thread)
        assert thread.is_alive(), "the second demotion did not wait for the first"
        ahead.commit()
        thread.join(timeout=30)
        assert not thread.is_alive()
    finally:
        ahead.close()
        behind.close()
    assert outcome == ["refused"]
    assert active_admins(world, owner) == [first.id]


def simultaneously(app, requests) -> list:
    """Send each request at the same moment, each on its own connection. Returns the responses."""
    barrier = threading.Barrier(len(requests))
    responses: list = [None] * len(requests)

    def one(index: int, send) -> None:
        with TestClient(app, base_url=BASE_URL) as c:
            barrier.wait(timeout=30)
            responses[index] = send(c)

    threads = [threading.Thread(target=one, args=(i, send)) for i, send in enumerate(requests)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert all(r is not None for r in responses)
    return responses


@pytest.mark.parametrize("round_number", range(4))
def test_two_simultaneous_demotions_exactly_one_succeeds(app, world, round_number):
    owner = world.owner()
    first, second = world.user("owner", owner), world.user("owner", owner)
    h = world.auth(world.user("admin"))

    def demote(user, body):
        return lambda c: c.patch(f"/api/v1/org/users/{user.id}", headers=h, json=body)

    # Alternate what "stops being an administrator" means: another role, or switched off.
    body_a = {"org_role": "org_operator"} if round_number % 2 == 0 else {"is_active": False}
    responses = simultaneously(app, [demote(first, body_a), demote(second, {"org_role": "org_viewer"})])
    codes = sorted(r.status_code for r in responses)
    assert codes == [200, 409], [r.text for r in responses]
    assert len(active_admins(world, owner)) == 1
    assert len(audit_rows(world, "org.user.update")) == 1


def test_two_administrators_demoting_each_other_at_once_leave_one(app, world):
    owner = world.owner()
    first, second = world.user("owner", owner), world.user("owner", owner)
    h1, h2 = world.auth(first), world.auth(second)
    body = {"org_role": "org_viewer"}
    responses = simultaneously(
        app,
        [
            lambda c: c.patch(f"/api/v1/org/users/{second.id}", headers=h1, json=body),
            lambda c: c.patch(f"/api/v1/org/users/{first.id}", headers=h2, json=body),
        ],
    )
    codes = sorted(r.status_code for r in responses)
    # The loser is refused either as "no longer an administrator" or as "the last one".
    assert codes[0] == 200 and codes[1] in (403, 409), [r.text for r in responses]
    assert len(active_admins(world, owner)) == 1


def test_an_administrator_demoted_a_moment_ago_cannot_act_on_a_session_resolved_before(world):
    """Authority is checked again once the organisation is locked."""
    owner = world.owner()
    first, second = world.user("owner", owner), world.user("owner", owner)
    victim = world.user("owner", owner, org_role="org_operator")
    token = world.token(second)
    racing = session_factory()()
    try:
        principal = accounts.resolve_session(racing, world.settings, token, via_cookie=False)
        assert principal.org_role == "org_admin"  # true at this moment
        racing.commit()
        # Meanwhile the other administrator demotes this one.
        world.session.get(User, second.id).org_role = "org_viewer"
        world.commit()
        with pytest.raises(Forbidden):
            org_service.update_org_user(racing, principal, SYSTEM, victim.id, is_active=False)
        racing.rollback()
        with pytest.raises(Forbidden):
            org_service.create_org_user(
                racing, principal, SYSTEM, email="x@test.invalid", org_role="org_admin", password=PASSWORD
            )
        racing.rollback()
    finally:
        racing.close()
    assert fresh(world, victim).is_active and count(world, User) == 3
    assert active_admins(world, owner) == [first.id]


# --- money is for administrators -------------------------------------------

MONEY_READS = (
    "/api/v1/fee-schedules",
    "/api/v1/earnings/buckets",
    "/api/v1/earnings/buckets/{bucket}",
    "/api/v1/owners/{owner}/balance",
    "/api/v1/owners/{owner}/statement",
    "/api/v1/owners/{owner}/payouts",
    "/api/v1/owners/{owner}/beneficiary",
    "/api/v1/payout-items",
)


def test_money_routes_are_closed_to_operators_and_viewers(client, world):
    a, *_ = two_tenants(world)
    bucket = world.session.execute(select(EarningBucket).where(EarningBucket.owner_id == a.id)).scalar_one()
    paths = [p.format(owner=a.id, bucket=bucket.id) for p in MONEY_READS]

    admin = world.auth(world.user("owner", a))
    for path in paths:
        assert client.get(path, headers=admin).status_code == 200, path
    assert client.get(f"/api/v1/owners/{a.id}/balance", headers=admin).json()["available_to_settle"] == (
        "90.00000000"
    )

    for org_role in ("org_operator", "org_viewer"):
        h = world.auth(world.user("owner", a, org_role=org_role))
        for path in paths:
            r = client.get(path, headers=h)
            assert r.status_code == 403 and envelope(r)["code"] == "forbidden", (org_role, path)
            assert "90.0" not in r.text and "administrators only" in r.json()["error"]["message"]
        # The machines are still theirs to see.
        assert client.get("/api/v1/machines", headers=h).json()["total"] == 1

    # Staff are unaffected.
    for staff_role in ("admin", "auditor"):
        h = world.auth(world.user(staff_role))
        for path in paths:
            assert client.get(path, headers=h).status_code == 200, (staff_role, path)


@pytest.mark.parametrize("org_role", ["org_operator", "org_viewer"])
def test_dashboard_shows_no_money_to_operators_and_viewers(app, world, org_role):
    a, b, machine_a, *_ = two_tenants(world)
    browser = browser_for(app, world.user("owner", a, org_role=org_role))

    home = browser.get("/dashboard")
    assert home.status_code == 200 and "Tenant A" in home.text
    assert f'href="/machines/{machine_a.id}"' in home.text  # the machines are there
    for money in ("Payable now", "Statement", "Payout history", "Management fee", "90.00", "FR**"):
        assert money not in home.text, money
    assert "visible to your organisation's administrators" in home.text
    assert 'href="/earnings"' not in home.text and 'href="/organisation"' not in home.text
    own = browser.get(f"/owners/{a.id}")
    assert own.status_code == 200 and "Payable now" not in own.text and "90.00" not in own.text

    earnings = browser.get("/earnings")
    assert earnings.status_code == 403 and "#101" not in earnings.text
    assert browser.get(f"/machines/{machine_a.id}").status_code == 200
    for admin_page in ("/admin/settlements", "/admin/fees", "/admin/exceptions", "/organisation"):
        assert browser.get(admin_page).status_code == 403, admin_page


def test_dashboard_shows_money_to_the_organisations_administrators(app, world):
    a, b, machine_a, *_ = two_tenants(world)
    browser = browser_for(app, world.user("owner", a))
    home = browser.get("/dashboard")
    assert home.status_code == 200
    for money in ("Payable now", "Statement", "Payout history", "90.00", "FR**"):
        assert money in home.text, money
    assert 'href="/earnings"' in home.text and 'href="/organisation"' in home.text
    assert "#101" in browser.get("/earnings").text
    assert "Payable now" in browser.get(f"/owners/{a.id}").text
    # Staff see the owner's page with its figures, as before.
    staff = browser_for(app, world.user("auditor"))
    assert "Payable now" in staff.get(f"/owners/{a.id}").text
    assert 'href="/earnings"' in staff.get("/dashboard").text


# --- the Organisation page --------------------------------------------------


def test_organisation_page_lists_users_and_its_forms_work(app, world):
    owner, other = world.owner("Acme"), world.owner("Other")
    admin = world.user("owner", owner)
    member = world.user("owner", owner, org_role="org_viewer")
    stranger = world.user("owner", other)
    browser = browser_for(app, admin)
    csrf = csrf_of(browser)

    page = browser.get("/organisation")
    assert page.status_code == 200
    assert admin.email in page.text and member.email in page.text and stranger.email not in page.text
    assert page.text.count(f'name="csrf_token" value="{csrf}"') >= 5  # every form carries the token
    assert "<script" not in page.text

    added = browser.post(
        "/organisation/users",
        data={
            "email": "form@test.invalid",
            "display_name": "Form User",
            "org_role": "org_operator",
            "password": PASSWORD,
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert added.status_code == 303 and added.headers["location"].startswith("/organisation?msg=")
    created = world.session.execute(select(User).where(User.email == "form@test.invalid")).scalar_one()
    assert (created.owner_id, created.role, created.org_role) == (owner.id, "owner", "org_operator")
    assert "form@test.invalid" in browser.get("/organisation").text

    def post(user, **fields):
        return browser.post(
            f"/organisation/users/{user.id}", data={**fields, "csrf_token": csrf}, follow_redirects=False
        )

    assert post(member, org_role="org_operator").status_code == 303
    assert fresh(world, member).org_role == "org_operator"
    assert post(member, is_active="false").status_code == 303
    assert fresh(world, member).is_active is False
    assert "deactivated" in browser.get("/organisation").text
    assert post(member, is_active="true").status_code == 303
    assert fresh(world, member).is_active is True

    # What the service refuses comes back as a message on the page, and nothing changes.
    for fields in ({"is_active": "false"}, {"org_role": "org_viewer"}):
        last = post(admin, **fields)
        assert last.status_code == 303 and "/organisation?err=" in last.headers["location"]
        assert "last%20active%20administrator" in last.headers["location"]
    weak = browser.post(
        "/organisation/users",
        data={
            "email": "weak@test.invalid",
            "org_role": "org_viewer",
            "password": "short",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert weak.status_code == 303 and "/organisation?err=" in weak.headers["location"]
    assert fresh(world, admin).is_active and fresh(world, admin).org_role == "org_admin"
    # Another organisation's user is not found, whatever is asked.
    assert post(stranger, is_active="false").status_code == 404
    assert fresh(world, stranger).is_active is True
    assert len(audit_rows(world, "org.user.create")) == 1 and len(audit_rows(world, "org.user.update")) == 3


def test_organisation_forms_need_the_csrf_token_and_the_role(app, world):
    owner = world.owner()
    admin = world.user("owner", owner)
    member = world.user("owner", owner, org_role="org_operator")
    browser = browser_for(app, admin)
    csrf = csrf_of(browser)
    new = {"email": "csrf@test.invalid", "org_role": "org_viewer", "password": PASSWORD}

    for token in ({}, {"csrf_token": "not-the-token"}):
        r = browser.post("/organisation/users", data={**new, **token}, follow_redirects=False)
        assert r.status_code == 403 and "CSRF token" in r.text
        r = browser.post(
            f"/organisation/users/{member.id}", data={"is_active": "false", **token}, follow_redirects=False
        )
        assert r.status_code == 403 and "CSRF token" in r.text
    foreign = browser.post(
        "/organisation/users",
        data={**new, "csrf_token": csrf},
        headers={"Origin": "https://attacker.example"},
        follow_redirects=False,
    )
    assert foreign.status_code == 403 and "cross-origin" in foreign.text

    # A valid token is not enough: the forms are the administrators'.
    for caller in (member, world.user("owner", owner, org_role="org_viewer"), world.user("admin")):
        other = browser_for(app, caller)
        token = csrf_of(other)
        assert other.get("/organisation").status_code == 403
        r = other.post("/organisation/users", data={**new, "csrf_token": token}, follow_redirects=False)
        assert r.status_code == 403, caller.email
        r = other.post(
            f"/organisation/users/{admin.id}",
            data={"org_role": "org_viewer", "csrf_token": token},
            follow_redirects=False,
        )
        assert r.status_code == 403, caller.email
    assert count(world, User) == 4 and fresh(world, member).is_active
    assert fresh(world, admin).org_role == "org_admin"
    assert audit_rows(world, "org.user.create") == [] and audit_rows(world, "org.user.update") == []
