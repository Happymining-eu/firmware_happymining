"""Who manages a machine, and remote-access grants (docs/appliance.md, section 3).

HappyMining staff, and a fleet-wide integration API client, may request or
cancel operations on a customer-managed machine only while a ``manage`` grant
from the owner's organisation is in force. Covers the routes, the rule applied
to the operation routes that already existed (API, integration API, dashboard),
what happens to queued operations when the access ends, ownership transfers,
the audit trail and the dashboard card.
"""

from __future__ import annotations

import threading
import uuid
from datetime import timedelta

from fastapi.testclient import TestClient
from helpers import BASE_URL, SYSTEM, World, heartbeat, make_settings, sample
from sqlalchemy import func, select
from test_security_regressions import wait_until_blocked_or_done

from happymining.db import lock_row, session_factory
from happymining.main import create_app
from happymining.models import (
    AuditLog,
    EnrollmentRequest,
    Machine,
    Operation,
    RemoteAccessGrant,
    User,
    utcnow,
)
from happymining.services import access, accounts, api_clients, operations, remote_access
from happymining.services import machines as machine_service

UUID0 = "00000000-0000-0000-0000-000000000000"
INTEGRATION = "/api/v1/integration"
CLIENT_SCOPES = ("fleet:read", "telemetry:read", "operations:read", "operations:write")


# --- helpers ---------------------------------------------------------------


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def envelope(response) -> dict[str, str]:
    body = response.json()
    assert set(body) == {"error"}, body
    return {k: v for k, v in body["error"].items() if k != "request_id"}


def refused_for_lack_of_access(response) -> bool:
    return response.status_code == 403 and envelope(response)["code"] == "remote_access_required"


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


def machine_of(world: World, owner=None, *, management: str = "customer", label: str = "m1"):
    """Returns (owner, machine, device token): a paired machine, customer-managed unless told otherwise."""
    owner = owner or world.owner()
    machine, device_token = world.paired_machine(owner, label)
    machine.management = management
    world.commit()
    return owner, machine, device_token


def grant(client, headers, machine, level="manage", hours: int | None = 24, reason="support request"):
    r = client.post(
        f"/api/v1/machines/{machine.id}/remote-access/grants",
        headers=headers,
        json={"level": level, "expires_in_hours": hours, "reason": reason},
    )
    assert r.status_code == 201, r.text
    return r.json()


def revoke(client, headers, machine, grant_id):
    return client.post(
        f"/api/v1/machines/{machine.id}/remote-access/grants/{grant_id}/revoke", headers=headers
    )


def let_expire(world: World, grant_id: str) -> None:
    """Move time: the grant ended a minute ago."""
    world.session.expire_all()
    row = world.session.get(RemoteAccessGrant, uuid.UUID(grant_id))
    row.expires_at = utcnow() - timedelta(minutes=1)
    world.commit()


def request_op(client, headers, machine, op_type="refresh_inventory", params=None):
    return client.post(
        f"/api/v1/machines/{machine.id}/operations",
        headers=headers,
        json={"type": op_type, "params": params or {}},
    )


def client_token(world: World, owner=None) -> tuple[uuid.UUID, str]:
    issued = api_clients.create_client(
        world.session,
        world.settings,
        SYSTEM,
        name=f"client-{uuid.uuid4().hex[:8]}",
        scopes=list(CLIENT_SCOPES),
        owner_id=owner.id if owner else None,
    )
    world.commit()
    return issued.client.id, issued.token


def client_op(client, token, machine, op_type="refresh_inventory"):
    return client.post(
        f"{INTEGRATION}/machines/{machine.id}/operations",
        headers={**bearer(token), "Idempotency-Key": f"key-{uuid.uuid4().hex}"},
        json={"type": op_type, "params": {}},
    )


def status_of(world: World, operation_id: str) -> str:
    world.session.expire_all()
    return world.session.get(Operation, uuid.UUID(operation_id)).status


def browser_for(app, user) -> TestClient:
    browser = TestClient(app, base_url=BASE_URL)
    r = browser.post("/demo-login", data={"email": user.email}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard", r.headers
    return browser


def csrf_of(browser: TestClient) -> str:
    return browser.get("/api/v1/auth/me").json()["csrf_token"]


# --- management is chosen when the machine is created ----------------------


def test_management_is_chosen_at_creation_and_defaults_to_company(client, world):
    owner = world.owner()
    h = world.auth(world.user("admin"))
    base = {"owner_id": str(owner.id)}

    default = client.post("/api/v1/enrollment-requests", headers=h, json={**base, "machine_label": "a"})
    customer = client.post(
        "/api/v1/enrollment-requests",
        headers=h,
        json={**base, "machine_label": "b", "management": "customer"},
    )
    company = client.post(
        "/api/v1/enrollment-requests", headers=h, json={**base, "machine_label": "c", "management": "company"}
    )
    assert [r.status_code for r in (default, customer, company)] == [201, 201, 201]
    kinds = [
        world.session.get(Machine, uuid.UUID(r.json()["machine_id"])).management
        for r in (default, customer, company)
    ]
    assert kinds == ["company", "customer", "company"]
    assert [row.details["management"] for row in audit_rows(world, "enrollment.create")] == kinds

    bad = client.post(
        "/api/v1/enrollment-requests", headers=h, json={**base, "machine_label": "d", "management": "nobody"}
    )
    assert bad.status_code == 422

    # A new code for an existing machine does not change who manages it.
    again = {**base, "machine_id": customer.json()["machine_id"]}
    assert client.post("/api/v1/enrollment-requests", headers=h, json=again).status_code == 201
    same = client.post("/api/v1/enrollment-requests", headers=h, json={**again, "management": "customer"})
    assert same.status_code == 201
    flipped = client.post("/api/v1/enrollment-requests", headers=h, json={**again, "management": "company"})
    assert flipped.status_code == 400 and "pairing does not change that" in flipped.json()["error"]["message"]
    world.session.expire_all()
    assert world.session.get(Machine, uuid.UUID(customer.json()["machine_id"])).management == "customer"
    assert count(world, Machine) == 3


def test_pairing_form_offers_the_management_choice(app, world):
    owner = world.owner()
    browser = browser_for(app, world.user("admin"))
    csrf = csrf_of(browser)
    page = browser.get("/admin/pairing")
    assert 'name="management"' in page.text and 'value="customer"' in page.text

    form = {"owner_id": str(owner.id), "csrf_token": csrf}
    made = browser.post("/admin/pairing", data={**form, "machine_label": "theirs", "management": "customer"})
    assert made.status_code == 200 and "HM-" in made.text
    default = browser.post("/admin/pairing", data={**form, "machine_label": "ours"})
    assert default.status_code == 200
    kinds = dict(world.session.execute(select(Machine.label, Machine.management)).all())
    assert kinds == {"theirs": "customer", "ours": "company"}
    bad = browser.post(
        "/admin/pairing", data={**form, "machine_label": "x", "management": "nobody"}, follow_redirects=False
    )
    assert bad.status_code == 303 and "/admin/pairing?err=" in bad.headers["location"]
    assert count(world, Machine) == 2


# --- reading ---------------------------------------------------------------


def test_remote_access_is_readable_by_the_organisations_administrators_and_by_staff(client, world):
    owner, machine, _ = machine_of(world)
    boss = world.user("owner", owner)
    hb = world.auth(boss)
    url = f"/api/v1/machines/{machine.id}/remote-access"

    empty = client.get(url, headers=hb)
    assert empty.status_code == 200
    assert empty.json() == {
        "machine_id": str(machine.id),
        "management": "customer",
        "staff_access": "none",
        "grants": [],
        "past_grants": [],
    }

    issued = grant(client, hb, machine, "view", 2, "look at the NAS settings")
    assert issued == {
        "id": issued["id"],
        "machine_id": str(machine.id),
        "level": "view",
        "state": "active",
        "reason": "look at the NAS settings",
        "granted_by": str(boss.id),
        "created_at": issued["created_at"],
        "expires_at": issued["expires_at"],
        "revoked_at": None,
        "revoked_by": None,
    }
    old = grant(client, hb, machine, "manage", 1)
    let_expire(world, old["id"])
    gone = grant(client, hb, machine, "manage", None)
    assert gone["expires_at"] is None
    assert revoke(client, hb, machine, gone["id"]).status_code == 200

    for reader in (boss, world.user("admin"), world.user("auditor")):
        view = client.get(url, headers=world.auth(reader)).json()
        assert (view["management"], view["staff_access"]) == ("customer", "view"), reader.role
        assert [g["id"] for g in view["grants"]] == [issued["id"]]
        assert {g["id"]: g["state"] for g in view["past_grants"]} == {
            old["id"]: "expired",
            gone["id"]: "revoked",
        }

    for org_role in ("org_operator", "org_viewer"):
        r = client.get(url, headers=world.auth(world.user("owner", owner, org_role=org_role)))
        assert r.status_code == 403 and envelope(r)["code"] == "forbidden"
    stranger = world.auth(world.user("owner", world.owner("Other")))
    assert client.get(url, headers=stranger).status_code == 404
    assert client.get(f"/api/v1/machines/{UUID0}/remote-access", headers=hb).status_code == 404


# --- management ------------------------------------------------------------


def put_management(client, headers, machine, management):
    return client.put(
        f"/api/v1/machines/{machine.id}/management", headers=headers, json={"management": management}
    )


def test_staff_hand_a_machine_to_the_customer_and_cannot_take_it_back(client, world):
    owner, machine, _ = machine_of(world, management="company")
    staff = world.user("admin")
    hs = world.auth(staff)

    handed = put_management(client, hs, machine, "customer")
    assert handed.status_code == 200
    assert (handed.json()["management"], handed.json()["staff_access"], handed.json()["changed"]) == (
        "customer",
        "none",
        True,
    )
    # Saying it again is not an error and changes nothing.
    again = put_management(client, hs, machine, "customer")
    assert again.status_code == 200 and again.json()["changed"] is False

    taken = put_management(client, hs, machine, "company")
    assert taken.status_code == 403 and envelope(taken)["code"] == "forbidden"
    assert "owner's organisation" in taken.json()["error"]["message"]
    world.session.refresh(machine)
    assert machine.management == "customer"

    (row,) = audit_rows(world, "machine.management.change")
    assert (row.actor_type, row.actor_id, row.object_id, row.owner_id) == (
        "user",
        str(staff.id),
        str(machine.id),
        owner.id,
    )
    assert row.details == {
        "from": "company",
        "to": "customer",
        "staff_access": "none",
        "operations_cancelled": 0,
    }


def test_only_the_organisations_administrators_hand_a_machine_to_happymining(client, world):
    owner, machine, _ = machine_of(world)
    boss = world.user("owner", owner)
    hb = world.auth(boss)

    refused = {
        "auditor": world.user("auditor"),
        "operator": world.user("owner", owner, org_role="org_operator"),
        "viewer": world.user("owner", owner, org_role="org_viewer"),
    }
    for name, user in refused.items():
        for target in ("company", "customer"):
            r = put_management(client, world.auth(user), machine, target)
            assert r.status_code == 403, (name, target)
    stranger = world.auth(world.user("owner", world.owner("Other")))
    assert put_management(client, stranger, machine, "company").status_code == 404
    assert put_management(client, hb, machine, "nobody").status_code == 422
    world.session.refresh(machine)
    assert machine.management == "customer" and audit_rows(world, "machine.management.change") == []

    back = put_management(client, hb, machine, "company")
    assert (
        back.status_code == 200 and back.json()["staff_access"] == "manage" and back.json()["changed"] is True
    )
    # Once the company manages it, staff operate it without any grant.
    assert request_op(client, world.auth(world.user("admin")), machine).status_code == 201
    # And the organisation may take it back at any time.
    assert put_management(client, hb, machine, "customer").json()["management"] == "customer"
    changes = audit_rows(world, "machine.management.change")
    assert [(c.details["from"], c.details["to"], c.actor_id) for c in changes] == [
        ("customer", "company", str(boss.id)),
        ("company", "customer", str(boss.id)),
    ]
    assert changes[1].details["operations_cancelled"] == 1  # what staff had queued in between


# --- grants ----------------------------------------------------------------


def test_only_an_org_admin_grants_and_the_expiry_is_bounded(client, world):
    owner, machine, _ = machine_of(world)
    boss = world.user("owner", owner)
    hb = world.auth(boss)
    url = f"/api/v1/machines/{machine.id}/remote-access/grants"
    body = {"level": "manage", "expires_in_hours": 4, "reason": "r"}

    # Staff cannot give themselves access; nor can anyone else who is not an administrator.
    for user in (
        world.user("admin"),
        world.user("auditor"),
        world.user("owner", owner, org_role="org_operator"),
        world.user("owner", owner, org_role="org_viewer"),
    ):
        r = client.post(url, headers=world.auth(user), json=body)
        assert r.status_code == 403 and envelope(r)["code"] == "forbidden", user.email
    stranger = world.auth(world.user("owner", world.owner("Other")))
    assert client.post(url, headers=stranger, json=body).status_code == 404
    assert count(world, RemoteAccessGrant) == 0 and audit_rows(world, "remote_access.grant") == []

    for bad in (
        {**body, "expires_in_hours": 0},
        {**body, "expires_in_hours": -3},
        {**body, "expires_in_hours": 1.5},
        {**body, "expires_in_hours": "soon"},
        {**body, "level": "root"},
        {"level": "manage", "reason": "no expiry given at all"},
        {**body, "machine_id": UUID0},
    ):
        assert client.post(url, headers=hb, json=bad).status_code == 422, bad
    # 90 days is the default maximum; one hour more is refused.
    too_long = client.post(url, headers=hb, json={**body, "expires_in_hours": 90 * 24 + 1})
    assert too_long.status_code == 400 and "between 1 and 2160" in too_long.json()["error"]["message"]
    assert count(world, RemoteAccessGrant) == 0

    before = utcnow()
    shortest = grant(client, hb, machine, "view", 1)
    longest = grant(client, hb, machine, "manage", 90 * 24)
    open_ended = grant(client, hb, machine, "manage", None)
    rows = {str(g.id): g for g in world.session.execute(select(RemoteAccessGrant)).scalars()}
    assert timedelta(minutes=59) < rows[shortest["id"]].expires_at - before < timedelta(minutes=61)
    assert (
        timedelta(days=89, hours=23) < rows[longest["id"]].expires_at - before < timedelta(days=90, hours=1)
    )
    assert rows[open_ended["id"]].expires_at is None
    assert {(g.owner_id, g.granted_by, g.machine_id) for g in rows.values()} == {
        (owner.id, boss.id, machine.id)
    }


def test_the_maximum_expiry_follows_the_configuration(world):
    owner, machine, _ = machine_of(world)
    hb = world.auth(world.user("owner", owner))
    url = f"/api/v1/machines/{machine.id}/remote-access/grants"
    with TestClient(create_app(make_settings(remote_access_max_hours=48)), base_url=BASE_URL) as c:
        assert c.post(url, headers=hb, json={"level": "view", "expires_in_hours": 49}).status_code == 400
        assert c.post(url, headers=hb, json={"level": "view", "expires_in_hours": 48}).status_code == 201


def test_revoking_is_for_the_organisation_and_staff_may_give_a_grant_up(client, world):
    owner, machine, _ = machine_of(world)
    _, other_machine, _ = machine_of(world, owner, label="m2")
    boss, staff = world.user("owner", owner), world.user("admin")
    hb, hs = world.auth(boss), world.auth(staff)
    first, second = grant(client, hb, machine), grant(client, hb, machine, "view", None)

    for user in (
        world.user("auditor"),
        world.user("owner", owner, org_role="org_operator"),
        world.user("owner", owner, org_role="org_viewer"),
    ):
        assert revoke(client, world.auth(user), machine, first["id"]).status_code == 403
    stranger = world.auth(world.user("owner", world.owner("Other")))
    assert revoke(client, stranger, machine, first["id"]).status_code == 404
    assert revoke(client, hb, machine, UUID0).status_code == 404
    # A grant is addressed through its own machine only.
    assert revoke(client, hb, other_machine, first["id"]).status_code == 404
    assert count(world, RemoteAccessGrant) == 2 and audit_rows(world, "remote_access.revoke") == []
    assert (
        client.get(f"/api/v1/machines/{machine.id}/remote-access", headers=hb).json()["staff_access"]
        == "manage"
    )

    done = revoke(client, hb, machine, first["id"])
    assert done.status_code == 200
    assert (done.json()["state"], done.json()["revoked_by"], done.json()["changed"]) == (
        "revoked",
        str(boss.id),
        True,
    )
    twice = revoke(client, hb, machine, first["id"])
    assert twice.status_code == 200 and twice.json()["changed"] is False
    assert twice.json()["revoked_at"] == done.json()["revoked_at"]

    given_up = revoke(client, hs, machine, second["id"])
    assert given_up.status_code == 200 and given_up.json()["revoked_by"] == str(staff.id)
    assert revoke(client, hs, machine, second["id"]).json()["changed"] is False
    by_owner, by_staff = audit_rows(world, "remote_access.revoke")
    assert (by_owner.actor_id, by_owner.details["why"]) == (
        str(boss.id),
        "revoked by the owner's organisation",
    )
    assert (by_staff.actor_id, by_staff.details["why"]) == (str(staff.id), "given up by HappyMining")
    view = client.get(f"/api/v1/machines/{machine.id}/remote-access", headers=hb).json()
    assert view["staff_access"] == "none" and view["grants"] == []


def test_each_change_leaves_an_audit_row_with_who_level_expiry_and_reason(client, world):
    owner, machine, _ = machine_of(world, management="company")
    boss, staff = world.user("owner", owner), world.user("admin")
    hb = world.auth(boss)

    put_management(client, world.auth(staff), machine, "customer")
    issued = grant(client, hb, machine, "manage", 6, "ticket 4711: replace a disk")
    revoke(client, hb, machine, issued["id"])

    (changed,) = audit_rows(world, "machine.management.change")
    assert (changed.actor_id, changed.object_type, changed.object_id) == (
        str(staff.id),
        "machine",
        str(machine.id),
    )
    (granted,) = audit_rows(world, "remote_access.grant")
    assert (granted.actor_type, granted.actor_id, granted.owner_id) == ("user", str(boss.id), owner.id)
    assert (granted.object_type, granted.object_id) == ("remote_access_grant", issued["id"])
    assert granted.details == {
        "machine_id": str(machine.id),
        "level": "manage",
        "expires_at": issued["expires_at"],
        "reason": "ticket 4711: replace a disk",
        "management": "customer",
    }
    (revoked,) = audit_rows(world, "remote_access.revoke")
    assert (revoked.actor_id, revoked.object_id, revoked.owner_id) == (str(boss.id), issued["id"], owner.id)
    assert revoked.details == {
        "machine_id": str(machine.id),
        "level": "manage",
        "expires_at": issued["expires_at"],
        "reason": "ticket 4711: replace a disk",
        "why": "revoked by the owner's organisation",
        "operations_cancelled": 0,
    }


# --- the rule applied to operations: staff ---------------------------------


def test_staff_need_a_manage_grant_to_request_or_cancel_operations(client, world):
    owner, machine, _ = machine_of(world)
    boss, staff = world.user("owner", owner), world.user("admin")
    hb, hs = world.auth(boss), world.auth(staff)

    # No grant: nothing can be requested, and nothing is recorded as requested.
    refused = request_op(client, hs, machine)
    assert refused_for_lack_of_access(refused)
    assert "managed by its owner" in refused.json()["error"]["message"]
    assert count(world, Operation) == 0 and audit_rows(world, "operation.request") == []

    # Monitoring is untouched.
    for path in ("", "/telemetry", "/operations"):
        assert client.get(f"/api/v1/machines/{machine.id}{path}", headers=hs).status_code == 200, path
    listed = client.get("/api/v1/machines", headers=hs).json()["items"]
    assert [m["id"] for m in listed] == [str(machine.id)]
    assert client.get("/api/v1/operations", headers=hs).status_code == 200

    # A view grant lets staff look, not act.
    looking = grant(client, hb, machine, "view", 4)
    assert refused_for_lack_of_access(request_op(client, hs, machine))
    assert count(world, Operation) == 0

    # With a manage grant: request and cancel.
    acting = grant(client, hb, machine, "manage", 4)
    queued = request_op(client, hs, machine)
    assert queued.status_code == 201 and queued.json()["status"] == "pending"
    cancelled = client.post(f"/api/v1/operations/{queued.json()['id']}/cancel", headers=hs)
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"

    # Revoked: refused again, the view grant that remains changes nothing.
    assert revoke(client, hb, machine, acting["id"]).status_code == 200
    assert refused_for_lack_of_access(request_op(client, hs, machine))
    assert revoke(client, hb, machine, looking["id"]).status_code == 200
    assert refused_for_lack_of_access(request_op(client, hs, machine))
    assert count(world, Operation) == 1


def test_an_expired_grant_no_longer_allows_anything(client, world):
    owner, machine, _ = machine_of(world)
    hb, hs = world.auth(world.user("owner", owner)), world.auth(world.user("admin"))
    issued = grant(client, hb, machine, "manage", 1)
    queued = request_op(client, hs, machine)
    assert queued.status_code == 201

    let_expire(world, issued["id"])
    assert refused_for_lack_of_access(request_op(client, hs, machine))
    # Withdrawing a request is managing the machine too.
    assert refused_for_lack_of_access(
        client.post(f"/api/v1/operations/{queued.json()['id']}/cancel", headers=hs)
    )
    view = client.get(f"/api/v1/machines/{machine.id}/remote-access", headers=hs).json()
    assert (view["staff_access"], view["grants"]) == ("none", [])
    assert [(g["id"], g["state"]) for g in view["past_grants"]] == [(issued["id"], "expired")]
    assert count(world, Operation) == 1

    # A new grant restores the access.
    grant(client, hb, machine, "manage", 1)
    assert request_op(client, hs, machine, "run_preflight").status_code == 201


def test_a_cancel_of_an_unknown_operation_is_not_found(client, world):
    hs = world.auth(world.user("admin"))
    assert client.post(f"/api/v1/operations/{UUID0}/cancel", headers=hs).status_code == 404


def test_company_managed_machines_work_as_before_and_grants_do_not_matter_there(client, world):
    owner, machine, device_token = machine_of(world, management="company")
    hb, hs = world.auth(world.user("owner", owner)), world.auth(world.user("admin"))
    assert (
        client.get(f"/api/v1/machines/{machine.id}/remote-access", headers=hs).json()["staff_access"]
        == "manage"
    )
    assert request_op(client, hs, machine).status_code == 201
    issued = grant(client, hb, machine, "view", 1)  # allowed, and without effect while the company manages
    assert request_op(client, hs, machine, "run_preflight").status_code == 201
    revoke(client, hb, machine, issued["id"])
    delivered = heartbeat(client, device_token, [sample(1)]).json()["operations"]
    assert len(delivered) == 2  # nothing was cancelled by the revocation


# --- what was queued when the access ends ----------------------------------


def test_revoking_cancels_what_staff_and_fleet_wide_clients_had_queued(client, world):
    owner, machine, device_token = machine_of(world)
    boss, staff = world.user("owner", owner), world.user("admin")
    hb, hs = world.auth(boss), world.auth(staff)
    fleet_client, fleet_token = client_token(world)
    _, owner_token = client_token(world, owner)
    issued = grant(client, hb, machine, "manage", None)

    already_out = request_op(client, hs, machine).json()["id"]
    (delivered,) = heartbeat(client, device_token, [sample(1)]).json()["operations"]
    assert delivered["id"] == already_out
    by_staff = request_op(client, hs, machine, "run_preflight").json()["id"]
    by_fleet_client = client_op(client, fleet_token, machine).json()["id"]
    by_owner_client = client_op(client, owner_token, machine).json()["id"]

    done = revoke(client, hb, machine, issued["id"])
    assert done.status_code == 200
    assert status_of(world, by_staff) == "cancelled" and status_of(world, by_fleet_client) == "cancelled"
    row = world.session.get(Operation, uuid.UUID(by_staff))
    assert row.detail == remote_access.ACCESS_ENDED_DETAIL and row.completed_at is not None
    # The owner's own client keeps its request, and what the machine already has is not rewritten.
    assert status_of(world, by_owner_client) == "pending" and status_of(world, already_out) == "delivered"

    (revoked,) = audit_rows(world, "remote_access.revoke")
    assert revoked.details["operations_cancelled"] == 2
    cancels = audit_rows(world, "operation.cancel")
    assert {c.object_id for c in cancels} == {by_staff, by_fleet_client}
    assert {(c.actor_type, c.actor_id, c.details["reason"]) for c in cancels} == {
        ("system", "remote-access", "requester_lost_access")
    }
    # Only what is still authorised leaves the server.
    handed = heartbeat(client, device_token, [sample(2)]).json()["operations"]
    assert {op["id"] for op in handed} == {already_out, by_owner_client}
    assert fleet_client is not None


def test_handing_a_machine_to_the_customer_cancels_what_staff_had_queued(client, world):
    owner, machine, _ = machine_of(world, management="company")
    hs = world.auth(world.user("admin"))
    queued = request_op(client, hs, machine).json()["id"]
    assert put_management(client, hs, machine, "customer").status_code == 200
    assert status_of(world, queued) == "cancelled"
    (row,) = audit_rows(world, "machine.management.change")
    assert row.details["operations_cancelled"] == 1


def test_with_a_manage_grant_in_force_the_hand_over_cancels_nothing(client, world):
    owner, machine, _ = machine_of(world, management="company")
    hb, hs = world.auth(world.user("owner", owner)), world.auth(world.user("admin"))
    grant(client, hb, machine, "manage", 8)
    queued = request_op(client, hs, machine).json()["id"]
    handed = put_management(client, hs, machine, "customer")
    assert handed.status_code == 200 and handed.json()["staff_access"] == "manage"
    assert status_of(world, queued) == "pending"
    assert request_op(client, hs, machine, "run_preflight").status_code == 201


def test_a_request_that_overlaps_a_revocation_is_refused(app, world):
    """The request waits for the machine row the revocation holds, then sees the revocation."""
    owner, machine, _ = machine_of(world)
    boss, staff = world.user("owner", owner), world.user("admin")
    hs = world.auth(staff)
    with TestClient(app, base_url=BASE_URL) as c:
        issued = grant(c, world.auth(boss), machine)
    boss_token = world.token(boss)
    ahead = session_factory()()
    answers: list = []

    def send() -> None:
        with TestClient(app, base_url=BASE_URL) as c:
            answers.append(request_op(c, hs, machine))

    try:
        principal = accounts.resolve_session(ahead, world.settings, boss_token, via_cookie=False)
        locked = lock_row(ahead, Machine, machine.id)  # what the route does
        remote_access.revoke_grant(ahead, principal, SYSTEM, locked, uuid.UUID(issued["id"]))
        thread = threading.Thread(target=send)  # the staff request arrives before the commit
        thread.start()
        wait_until_blocked_or_done(world, thread)
        assert thread.is_alive(), "the request did not wait for the revocation"
        ahead.commit()
        thread.join(timeout=30)
        assert not thread.is_alive()
    finally:
        ahead.close()
    assert refused_for_lack_of_access(answers[0])
    assert count(world, Operation) == 0


# --- operation_still_authorised: where an expired grant takes effect --------


def queue(world: World, machine, *, user=None, client_id=None, op_type="refresh_inventory") -> Operation:
    """Queue an operation through the service, as a person, an API client or the system."""
    world.session.expire_all()
    operation = operations.request_operation(
        world.session,
        world.settings,
        SYSTEM,
        None,
        machine=world.session.get(Machine, machine.id),
        op_type=op_type,
        params={},
        requested_by=user.id if user else None,
        client_id=client_id,
        request_key=f"key-{uuid.uuid4().hex}" if client_id else None,
    )
    world.commit()
    return operation


def authorised(world: World, operation, **kw) -> bool:
    world.session.expire_all()
    machine = world.session.get(Machine, operation.machine_id)
    return remote_access.operation_still_authorised(world.session, operation, machine, **kw)


def test_operation_still_authorised_follows_the_requesters_current_right(client, world):
    owner, machine, _ = machine_of(world, management="company")
    boss, staff = world.user("owner", owner), world.user("admin")
    hb = world.auth(boss)
    fleet_client, _ = client_token(world)
    owner_client, _ = client_token(world, owner)
    other_client, _ = client_token(world, world.owner("Other"))

    by_staff = queue(world, machine, user=staff)
    by_system = queue(world, machine)
    by_fleet = queue(world, machine, client_id=fleet_client)
    by_owner_client = queue(world, machine, client_id=owner_client)
    by_org_user = queue(world, machine, user=boss)
    happymining = (by_staff, by_system, by_fleet)
    organisation = (by_owner_client, by_org_user)

    def verdicts(operations_, **kw):
        return [authorised(world, op, **kw) for op in operations_]

    # Company-managed: everyone who could ask still may.
    assert verdicts(happymining) == [True, True, True] and verdicts(organisation) == [True, True]

    # Customer-managed, no grant: HappyMining's requests lost their authority, the organisation's did not.
    put_management(client, hb, machine, "customer")
    assert verdicts(happymining) == [False, False, False] and verdicts(organisation) == [True, True]

    looking = grant(client, hb, machine, "view", 2)
    assert verdicts(happymining) == [False, False, False]
    acting = grant(client, hb, machine, "manage", 2)
    assert verdicts(happymining) == [True, True, True]
    # Time passes: asked "as of" three hours from now, and then for real.
    assert verdicts(happymining, now=utcnow() + timedelta(hours=3)) == [False, False, False]
    let_expire(world, acting["id"])
    assert verdicts(happymining) == [False, False, False] and verdicts(organisation) == [True, True]
    assert looking["state"] == "active"

    # A client limited to another owner, or a requester that no longer exists, has no say.
    stray = Operation(
        machine_id=machine.id,
        device_id=by_staff.device_id,
        type="refresh_inventory",
        nonce="n" * 32,
        requested_by_client=other_client,
        request_key="stray-key-0001",
        expires_at=utcnow() + timedelta(minutes=5),
    )
    world.session.add(stray)
    world.commit()
    assert authorised(world, stray) is False

    # People who can no longer change anything have no request left either.
    grant(client, hb, machine, "manage", 2)
    operator = world.user("owner", owner, org_role="org_operator")
    by_operator = queue(world, machine, user=operator)
    assert verdicts((by_staff, by_org_user, by_operator)) == [True, True, True]
    world.session.get(User, operator.id).org_role = "org_viewer"
    world.session.get(User, staff.id).is_active = False
    world.commit()
    assert verdicts((by_staff, by_org_user, by_operator)) == [False, True, False]
    second_boss = world.user("owner", owner)
    world.session.get(User, boss.id).is_active = False
    world.commit()
    assert verdicts((by_org_user,)) == [False] and second_boss.is_active


def test_cancel_if_unauthorised_cancels_pending_operations_only(client, world):
    owner, machine, device_token = machine_of(world)
    hb, hs = world.auth(world.user("owner", owner)), world.auth(world.user("admin"))
    issued = grant(client, hb, machine, "manage", 1)
    out = request_op(client, hs, machine).json()["id"]
    heartbeat(client, device_token, [sample(1)])
    waiting = request_op(client, hs, machine, "run_preflight").json()["id"]

    def run(operation_id: str) -> bool:
        world.session.expire_all()
        operation = world.session.get(Operation, uuid.UUID(operation_id))
        result = remote_access.cancel_if_unauthorised(
            world.session, operation, world.session.get(Machine, machine.id)
        )
        world.commit()
        return result

    # While the grant holds, nothing is cancelled.
    assert run(waiting) is False and status_of(world, waiting) == "pending"
    let_expire(world, issued["id"])
    # Expiry alone runs nothing: the operation waits until the device asks for it.
    assert status_of(world, waiting) == "pending"
    assert run(waiting) is True and status_of(world, waiting) == "cancelled"
    assert run(waiting) is False  # already final
    # Delivered: the device may have started it, so its record is not rewritten.
    assert run(out) is False and status_of(world, out) == "delivered"
    (row,) = audit_rows(world, "operation.cancel")
    assert row.object_id == waiting and row.details["reason"] == "requester_lost_access"


def test_an_operation_queued_under_a_grant_that_expired_is_not_handed_to_the_device(client, world):
    """End to end: depends on the call to ``cancel_if_unauthorised`` in ``operations.pending_for_device``."""
    owner, machine, device_token = machine_of(world)
    hb, hs = world.auth(world.user("owner", owner)), world.auth(world.user("admin"))
    fleet_client, fleet_token = client_token(world)
    issued = grant(client, hb, machine, "manage", 1)
    by_staff = request_op(client, hs, machine).json()["id"]
    by_client = client_op(client, fleet_token, machine, "run_preflight").json()["id"]
    let_expire(world, issued["id"])
    # Nothing ran at the moment of expiry: both are still waiting.
    assert status_of(world, by_staff) == "pending" and status_of(world, by_client) == "pending"

    assert heartbeat(client, device_token, [sample(1)]).json()["operations"] == []
    assert status_of(world, by_staff) == "cancelled" and status_of(world, by_client) == "cancelled"
    row = world.session.get(Operation, uuid.UUID(by_staff))
    assert row.detail == remote_access.ACCESS_ENDED_DETAIL and row.delivered_at is None
    assert len(audit_rows(world, "operation.cancel")) == 2 and fleet_client is not None
    # The device's other way of asking for work gives the same answer.
    polled = client.get("/api/v1/device/operations", headers=bearer(device_token))
    assert polled.status_code == 200 and polled.json()["operations"] == []


# --- the rule applied to operations: integration API clients ----------------


def test_a_fleet_wide_client_follows_the_staff_rule(client, world):
    owner, machine, _ = machine_of(world)
    hb = world.auth(world.user("owner", owner))
    client_id, token = client_token(world)
    h = bearer(token)

    refused = client_op(client, token, machine)
    assert refused_for_lack_of_access(refused)
    assert count(world, Operation) == 0 and audit_rows(world, "operation.request") == []
    # Reading the fleet is not restricted.
    for path in ("/machines", f"/machines/{machine.id}", f"/machines/{machine.id}/telemetry", "/operations"):
        assert client.get(INTEGRATION + path, headers=h).status_code == 200, path

    looking = grant(client, hb, machine, "view", 2)
    assert refused_for_lack_of_access(client_op(client, token, machine))

    acting = grant(client, hb, machine, "manage", 2)
    first = client_op(client, token, machine)
    assert first.status_code == 201
    withdrawn = client.post(f"{INTEGRATION}/operations/{first.json()['id']}/cancel", headers=h)
    assert withdrawn.status_code == 200 and withdrawn.json()["status"] == "cancelled"

    second = client_op(client, token, machine, "run_preflight")
    assert second.status_code == 201
    let_expire(world, acting["id"])
    assert refused_for_lack_of_access(client_op(client, token, machine))
    assert refused_for_lack_of_access(
        client.post(f"{INTEGRATION}/operations/{second.json()['id']}/cancel", headers=h)
    )
    assert status_of(world, second.json()["id"]) == "pending"

    third_grant = grant(client, hb, machine, "manage", 2)
    assert revoke(client, hb, machine, third_grant["id"]).status_code == 200
    assert (
        status_of(world, second.json()["id"]) == "cancelled"
    )  # queued by the client, cancelled by the revocation
    assert refused_for_lack_of_access(client_op(client, token, machine))
    assert looking["state"] == "active" and count(world, Operation) == 2
    assert client_id is not None


def test_an_owner_scoped_client_is_unaffected(client, world):
    owner, machine, device_token = machine_of(world)
    _, token = client_token(world, owner)
    queued = client_op(client, token, machine)
    assert queued.status_code == 201  # no grant anywhere: the client acts for the owner
    (delivered,) = heartbeat(client, device_token, [sample(1)]).json()["operations"]
    assert delivered["id"] == queued.json()["id"]
    again = client_op(client, token, machine, "run_preflight")
    cancelled = client.post(f"{INTEGRATION}/operations/{again.json()['id']}/cancel", headers=bearer(token))
    assert cancelled.status_code == 200
    # Another owner's client does not see the machine at all, as before.
    _, foreign = client_token(world, world.owner("Other"))
    assert client_op(client, foreign, machine).status_code == 404


# --- ownership transfers ---------------------------------------------------


def test_a_grant_from_a_previous_owner_does_not_count_after_a_transfer(client, world):
    old_owner, machine, _ = machine_of(world)
    new_owner = world.owner("New owner")
    old_boss, staff = world.user("owner", old_owner), world.user("admin")
    hs = world.auth(staff)
    issued = grant(client, world.auth(old_boss), machine, "manage", None, "open-ended, from the first owner")
    queued = request_op(client, hs, machine)
    assert queued.status_code == 201

    machine_service.transfer_ownership(
        world.session,
        SYSTEM,
        machine_id=machine.id,
        new_owner_id=new_owner.id,
        reason="sold",
        user_id=staff.id,
    )
    world.commit()

    # The grant was neither revoked nor expired, and still it opens nothing.
    world.session.expire_all()
    row = world.session.get(RemoteAccessGrant, uuid.UUID(issued["id"]))
    current = world.session.get(Machine, machine.id)
    assert row.revoked_at is None and row.expires_at is None and row.owner_id == old_owner.id
    assert access.staff_access(world.session, current) == "none"
    assert refused_for_lack_of_access(request_op(client, hs, machine))
    assert authorised(world, world.session.get(Operation, uuid.UUID(queued.json()["id"]))) is False

    as_staff = client.get(f"/api/v1/machines/{machine.id}/remote-access", headers=hs).json()
    assert (as_staff["staff_access"], as_staff["grants"]) == ("none", [])
    assert [(g["id"], g["state"]) for g in as_staff["past_grants"]] == [(issued["id"], "previous_owner")]

    # The new organisation does not see who the previous one let in, and cannot touch that grant.
    new_boss = world.auth(world.user("owner", new_owner))
    theirs = client.get(f"/api/v1/machines/{machine.id}/remote-access", headers=new_boss).json()
    assert theirs["grants"] == [] and theirs["past_grants"] == [] and "first owner" not in str(theirs)
    assert revoke(client, new_boss, machine, issued["id"]).status_code == 404
    # The previous organisation has no say over the machine any more.
    hb_old = world.auth(old_boss)
    assert client.get(f"/api/v1/machines/{machine.id}/remote-access", headers=hb_old).status_code == 404
    assert (
        client.post(
            f"/api/v1/machines/{machine.id}/remote-access/grants",
            headers=hb_old,
            json={"level": "manage", "expires_in_hours": 1},
        ).status_code
        == 404
    )
    # The new one decides from scratch.
    grant(client, new_boss, machine, "manage", 1)
    assert request_op(client, hs, machine, "run_preflight").status_code == 201


def transfer(client, headers, machine, new_owner, reason="sold"):
    return client.post(
        f"/api/v1/machines/{machine.id}/transfer-ownership",
        headers=headers,
        json={"new_owner_id": str(new_owner.id), "reason": reason},
    )


def test_transferring_a_customer_managed_machine_needs_the_owners_consent_and_ends_its_grants(client, world):
    first_owner, machine, _ = machine_of(world)
    second_owner = world.owner("Second")
    first_boss, second_boss = world.user("owner", first_owner), world.user("owner", second_owner)
    staff = world.user("admin")
    hs = world.auth(staff)

    assert refused_for_lack_of_access(transfer(client, hs, machine, second_owner))
    grant(client, world.auth(first_boss), machine, "view", None)
    assert refused_for_lack_of_access(transfer(client, hs, machine, second_owner))
    world.session.refresh(machine)
    assert machine.owner_id == first_owner.id and audit_rows(world, "machine.transfer_ownership") == []

    consent = grant(client, world.auth(first_boss), machine, "manage", None, "selling the machine")
    queued = request_op(client, hs, machine).json()["id"]
    moved = transfer(client, hs, machine, second_owner)
    assert moved.status_code == 200 and moved.json()["owner_id"] == str(second_owner.id)

    # Every grant of the previous owner is closed, and what was queued under them is cancelled.
    grants = world.session.execute(select(RemoteAccessGrant)).scalars().all()
    world.session.expire_all()
    assert len(grants) == 2 and all(g.revoked_at is not None and g.revoked_by == staff.id for g in grants)
    assert status_of(world, queued) == "cancelled"
    closed = audit_rows(world, "remote_access.revoke")
    assert {c.details["why"] for c in closed} == {"the machine changed owner"} and len(closed) == 2
    assert {c.owner_id for c in closed} == {first_owner.id}
    assert refused_for_lack_of_access(request_op(client, hs, machine))

    # Back to the first owner later: the old grant does not come back to life.
    grant(client, world.auth(second_boss), machine, "manage", 1)
    assert transfer(client, hs, machine, first_owner, "bought back").status_code == 200
    view = client.get(f"/api/v1/machines/{machine.id}/remote-access", headers=world.auth(first_boss)).json()
    assert (view["management"], view["staff_access"], view["grants"]) == ("customer", "none", [])
    assert {g["id"]: g["state"] for g in view["past_grants"]}[consent["id"]] == "revoked"
    assert refused_for_lack_of_access(request_op(client, hs, machine))


def test_transferring_a_company_managed_machine_is_unchanged(client, world):
    owner, machine, _ = machine_of(world, management="company")
    other = world.owner("Other")
    moved = transfer(client, world.auth(world.user("admin")), machine, other)
    assert moved.status_code == 200 and moved.json()["owner_id"] == str(other.id)
    assert audit_rows(world, "remote_access.revoke") == []


# --- pairing a machine again ------------------------------------------------


def test_a_new_pairing_code_for_a_customer_managed_machine_needs_a_manage_grant(client, world):
    owner, machine, _ = machine_of(world)
    hb, hs = world.auth(world.user("owner", owner)), world.auth(world.user("admin"))
    body = {"owner_id": str(owner.id), "machine_id": str(machine.id)}
    codes_before = count(world, EnrollmentRequest)

    # Cutting a device off stays possible without a grant: it protects the control plane.
    world.session.refresh(machine)
    cut = client.post(f"/api/v1/devices/{machine.device.id}/revoke", headers=hs, json={"reason": "leaked"})
    assert cut.status_code == 200
    # Connecting another device as this machine does not.
    assert refused_for_lack_of_access(client.post("/api/v1/enrollment-requests", headers=hs, json=body))
    assert count(world, EnrollmentRequest) == codes_before
    grant(client, hb, machine, "manage", 1)
    assert client.post("/api/v1/enrollment-requests", headers=hs, json=body).status_code == 201

    # A machine that never paired has nothing to protect yet: its code can be issued again.
    fresh = client.post(
        "/api/v1/enrollment-requests",
        headers=hs,
        json={"owner_id": str(owner.id), "machine_label": "new", "management": "customer"},
    )
    assert fresh.status_code == 201
    again = client.post(
        "/api/v1/enrollment-requests",
        headers=hs,
        json={"owner_id": str(owner.id), "machine_id": fresh.json()["machine_id"]},
    )
    assert again.status_code == 201


# --- dashboard --------------------------------------------------------------


def test_machine_page_shows_the_remote_access_card_to_those_who_may_use_it(app, world):
    owner, machine, _ = machine_of(world)
    boss = world.user("owner", owner)
    url = f"/machines/{machine.id}"

    as_boss = browser_for(app, boss)
    page = as_boss.get(url)
    assert page.status_code == 200 and "Remote access" in page.text and "<script" not in page.text
    assert f'action="{url}/remote-access/grants"' in page.text and f'action="{url}/management"' in page.text
    assert (
        "Let HappyMining manage this machine" in page.text
        and "No remote access has been granted." in page.text
    )
    assert f'action="{url}/operations"' not in page.text  # operations are requested by staff

    # Grant through the form, then see it and its revoke button.
    csrf = csrf_of(as_boss)
    posted = as_boss.post(
        f"{url}/remote-access/grants",
        data={"level": "manage", "expires_in_hours": "24", "reason": "form grant", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert posted.status_code == 303 and posted.headers["location"].startswith(f"{url}?msg=")
    issued = world.session.execute(select(RemoteAccessGrant)).scalar_one()
    assert (issued.level, issued.reason, issued.granted_by) == ("manage", "form grant", boss.id)
    assert timedelta(hours=23) < issued.expires_at - utcnow() < timedelta(hours=25)
    page = as_boss.get(url)
    assert "form grant" in page.text and boss.email in page.text
    assert f'action="{url}/remote-access/grants/{issued.id}/revoke"' in page.text and ">Revoke<" in page.text

    # Staff see the card, may give the grant up, and cannot grant or take the machine back.
    as_staff = browser_for(app, world.user("admin"))
    staff_page = as_staff.get(url)
    assert "Remote access" in staff_page.text and ">Give up<" in staff_page.text
    assert f'action="{url}/remote-access/grants"' not in staff_page.text
    assert f'action="{url}/management"' not in staff_page.text
    assert f'action="{url}/operations"' in staff_page.text  # the manage grant is in force
    auditor_page = browser_for(app, world.user("auditor")).get(url)
    assert (
        "Remote access" in auditor_page.text
        and '<form class="inline" method="post" action="/machines' not in auditor_page.text
    )

    # Operators and viewers see the machine without the card.
    for org_role in ("org_operator", "org_viewer"):
        other = browser_for(app, world.user("owner", owner, org_role=org_role)).get(url)
        assert (
            other.status_code == 200 and "Remote access" not in other.text and "form grant" not in other.text
        )

    revoked = as_boss.post(
        f"{url}/remote-access/grants/{issued.id}/revoke", data={"csrf_token": csrf}, follow_redirects=False
    )
    assert revoked.status_code == 303
    world.session.refresh(issued)
    assert issued.revoked_at is not None and issued.revoked_by == boss.id
    handed = as_boss.post(
        f"{url}/management", data={"management": "company", "csrf_token": csrf}, follow_redirects=False
    )
    assert handed.status_code == 303
    world.session.refresh(machine)
    assert machine.management == "company"
    assert "Hand management to the customer" in as_boss.get(url).text


def test_staff_see_a_notice_instead_of_the_operation_form_without_a_manage_grant(app, world):
    owner, machine, _ = machine_of(world)
    hb = world.auth(world.user("owner", owner))
    staff = browser_for(app, world.user("admin"))
    csrf = csrf_of(staff)
    url = f"/machines/{machine.id}"

    page = staff.get(url)
    assert page.status_code == 200
    assert "managed by its owner" in page.text and "without a remote-access grant" in page.text
    assert f'action="{url}/operations"' not in page.text
    # Posting the form anyway is refused and queues nothing.
    forced = staff.post(
        f"{url}/operations", data={"op_type": "refresh_inventory", "csrf_token": csrf}, follow_redirects=False
    )
    assert forced.status_code == 303 and f"{url}?err=" in forced.headers["location"]
    assert "remote-access%20grant" in forced.headers["location"]
    assert count(world, Operation) == 0

    with TestClient(app, base_url=BASE_URL) as api:
        looking = grant(api, hb, machine, "view", 1)
        page = staff.get(url)
        assert (
            "with the current grant (view only)" in page.text
            and f'action="{url}/operations"' not in page.text
        )
        grant(api, hb, machine, "manage", 1)
    page = staff.get(url)
    assert f'action="{url}/operations"' in page.text and "managed by its owner. Operations" not in page.text
    queued = staff.post(
        f"{url}/operations", data={"op_type": "refresh_inventory", "csrf_token": csrf}, follow_redirects=False
    )
    assert queued.status_code == 303 and f"{url}?msg=" in queued.headers["location"]
    assert count(world, Operation) == 1 and looking["state"] == "active"


def test_remote_access_forms_need_the_csrf_token_and_the_same_permissions(app, world):
    owner, machine, _ = machine_of(world)
    boss = world.user("owner", owner)
    url = f"/machines/{machine.id}"
    with TestClient(app, base_url=BASE_URL) as api:
        issued = grant(api, world.auth(boss), machine, "view", None)
    grant_form = {"level": "manage", "expires_in_hours": "24", "reason": "x"}
    forms = (
        (f"{url}/remote-access/grants", grant_form),
        (f"{url}/remote-access/grants/{issued['id']}/revoke", {}),
        (f"{url}/management", {"management": "company"}),
    )

    as_boss = browser_for(app, boss)
    csrf = csrf_of(as_boss)
    for path, fields in forms:
        for token in ({}, {"csrf_token": "not-the-token"}):
            r = as_boss.post(path, data={**fields, **token}, follow_redirects=False)
            assert r.status_code == 403 and "CSRF token" in r.text, path
        foreign = as_boss.post(
            path,
            data={**fields, "csrf_token": csrf},
            headers={"Origin": "https://attacker.example"},
            follow_redirects=False,
        )
        assert foreign.status_code == 403 and "cross-origin" in foreign.text, path

    # With a valid token of their own: staff cannot grant or take the machine back, others nothing at all.
    staff = browser_for(app, world.user("admin"))
    staff_csrf = csrf_of(staff)
    for path, fields in (forms[0], forms[2]):
        r = staff.post(path, data={**fields, "csrf_token": staff_csrf}, follow_redirects=False)
        assert r.status_code == 403, path
    for user in (
        world.user("auditor"),
        world.user("owner", owner, org_role="org_operator"),
        world.user("owner", owner, org_role="org_viewer"),
    ):
        other = browser_for(app, user)
        token = csrf_of(other)
        for path, fields in forms:
            r = other.post(path, data={**fields, "csrf_token": token}, follow_redirects=False)
            assert r.status_code == 403, (user.email, path)
    stranger = browser_for(app, world.user("owner", world.owner("Other")))
    stranger_csrf = csrf_of(stranger)
    for path, fields in forms:
        r = stranger.post(path, data={**fields, "csrf_token": stranger_csrf}, follow_redirects=False)
        assert r.status_code == 404, path

    # Nothing happened.
    world.session.expire_all()
    row = world.session.get(RemoteAccessGrant, uuid.UUID(issued["id"]))
    assert count(world, RemoteAccessGrant) == 1 and row.revoked_at is None
    assert world.session.get(Machine, machine.id).management == "customer"
    assert (
        audit_rows(world, "remote_access.revoke") == []
        and audit_rows(world, "machine.management.change") == []
    )
    assert len(audit_rows(world, "remote_access.grant")) == 1

    # An empty expiry is not an open-ended grant: it has to be chosen.
    vague = as_boss.post(
        f"{url}/remote-access/grants",
        data={"level": "manage", "expires_in_hours": "", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert vague.status_code == 303 and f"{url}?err=" in vague.headers["location"]
    assert count(world, RemoteAccessGrant) == 1
    chosen = as_boss.post(
        f"{url}/remote-access/grants",
        data={"level": "manage", "expires_in_hours": "never", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert chosen.status_code == 303 and f"{url}?msg=" in chosen.headers["location"]
    newest = world.session.execute(
        select(RemoteAccessGrant).order_by(RemoteAccessGrant.created_at.desc()).limit(1)
    ).scalar_one()
    assert newest.level == "manage" and newest.expires_at is None
    # And staff may give a grant up through the form.
    given_up = staff.post(
        f"{url}/remote-access/grants/{newest.id}/revoke",
        data={"csrf_token": staff_csrf},
        follow_redirects=False,
    )
    assert given_up.status_code == 303
    world.session.refresh(newest)
    assert newest.revoked_at is not None
