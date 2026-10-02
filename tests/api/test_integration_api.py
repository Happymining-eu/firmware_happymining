"""The integration API: how other software (Mole Hash) manages the AI servers.

Covers the API clients themselves (creation, the token shown once, rotation,
revocation, expiry), authentication and scopes, tenant scoping, the fleet,
telemetry and earnings views, operations through the same gate as an admin's,
idempotency, and the Python client shipped for Mole Hash.
"""

from __future__ import annotations

import importlib.util
import json
import re
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import BASE_URL, IDLE_UNLISTED, SYSTEM, World, dataset, heartbeat, make_settings, sample
from sqlalchemy import func, select, text
from test_access_control import api_routes
from test_earnings_ledger import run_import, setup_fleet

from happymining.db import get_engine, session_factory
from happymining.errors import ClientUnauthorized, Conflict, InvalidRequest
from happymining.main import create_app
from happymining.models import API_CLIENT_SCOPES, ApiClient, AuditLog, Machine, Operation
from happymining.security import redact, redact_text
from happymining.services import api_clients, operations
from happymining.services import machines as machine_service

REPO = Path(__file__).resolve().parents[2]
D = Decimal
BASE = "/api/v1/integration"
READ = ("fleet:read", "telemetry:read", "operations:read", "earnings:read")
WRITE = (*READ, "operations:write")
UUID0 = "00000000-0000-0000-0000-000000000000"
ACTIVE_CONTRACT = {
    "state": "active_contracts",
    "listed": True,
    "active_contracts": 1,
    "stopped_instances": 0,
    "stored_data": False,
}

# Every route a client can call, and the scope it needs. A new integration
# route has to be added here, which forces the decision of what it needs.
ROUTE_SCOPES = {
    ("GET", BASE): None,
    ("GET", BASE + "/fleet/summary"): "fleet:read",
    ("GET", BASE + "/machines"): "fleet:read",
    ("GET", BASE + "/machines/{machine_id}"): "fleet:read",
    ("GET", BASE + "/machines/{machine_id}/telemetry"): "telemetry:read",
    ("GET", BASE + "/machines/{machine_id}/appliance"): "appliance:read",
    ("GET", BASE + "/operation-types"): "operations:read",
    ("GET", BASE + "/operations"): "operations:read",
    ("GET", BASE + "/operations/{operation_id}"): "operations:read",
    ("POST", BASE + "/machines/{machine_id}/operations"): "operations:write",
    ("POST", BASE + "/operations/{operation_id}/cancel"): "operations:write",
    ("GET", BASE + "/earnings/daily"): "earnings:read",
    ("GET", BASE + "/earnings/summary"): "earnings:read",
}


# --- helpers ---------------------------------------------------------------


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def issue(world: World, scopes=READ, **kw):
    """Returns (client row, token)."""
    issued = api_clients.create_client(
        world.session,
        world.settings,
        SYSTEM,
        name=kw.pop("name", f"client-{uuid.uuid4().hex[:8]}"),
        scopes=list(scopes),
        **kw,
    )
    world.commit()
    return issued.client, issued.token


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


def envelope(response) -> dict[str, str]:
    body = response.json()
    assert set(body) == {"error"}, body
    return {k: v for k, v in body["error"].items() if k != "request_id"}


def integration_routes(app) -> set[tuple[str, str]]:
    return {(method, path) for method, path in api_routes(app) if path.startswith(BASE)}


def stay_inside_one_window(need_s: float = 6.0) -> None:
    """Rate limit windows are whole minutes; do not start a counting test at the end of one."""
    left = 60 - time.time() % 60
    if left < need_s:
        time.sleep(left + 0.2)


def request_op(c, token, machine, op_type="refresh_inventory", params=None, key=None):
    return c.post(
        f"{BASE}/machines/{machine.id}/operations",
        headers={**bearer(token), "Idempotency-Key": key or f"key-{uuid.uuid4().hex}"},
        json={"type": op_type, "params": params or {}},
    )


def gated_fleet(world: World, rental: dict | None = None):
    """One paired machine bound to provider machine 101, idle and unlisted unless told otherwise."""
    provider = world.provider(dataset({"101": {"rental": rental} if rental else dict(IDLE_UNLISTED)}, {}))
    account = world.account(provider)
    machine, token = world.paired_machine(world.owner())
    world.bind(account, "101", machine)
    world.session.refresh(machine)
    return machine, token, provider


# --- API clients: creation, the token, the admin routes ---------------------


def test_admin_creates_a_client_and_the_token_is_shown_once(client, world):
    admin = world.auth(world.user("admin"))
    r = client.post(
        "/api/v1/api-clients",
        headers=admin,
        json={
            "name": "Mole Hash",
            "description": "fleet manager",
            "scopes": ["telemetry:read", "fleet:read"],
        },
    )
    assert r.status_code == 201, r.text
    assert r.headers["cache-control"] == "no-store"
    created = r.json()
    token = created["token"]
    assert token.startswith("hmc_") and len(token) == 4 + 32 + 1 + 43
    assert created["scopes"] == ["fleet:read", "telemetry:read"]  # canonical order
    assert created["token_prefix"] == token[:12] and created["status"] == "active"

    # Only a keyed hash is stored, and nothing ever shows the token again.
    secret = token.split(".")[1]
    row = world.session.execute(select(ApiClient)).scalar_one()
    assert row.secret_hash != secret and len(row.secret_hash) == 64
    listing = client.get("/api/v1/api-clients", headers=admin)
    assert listing.status_code == 200
    assert set(listing.json()["available_scopes"]) == set(API_CLIENT_SCOPES)
    (item,) = listing.json()["items"]
    assert "token" not in item and "secret_hash" not in item
    dumped = json.dumps(listing.json()) + json.dumps(
        [a.details for a in audit_rows(world, "api_client.create")]
    )
    assert secret not in dumped and row.secret_hash not in dumped
    (created_audit,) = audit_rows(world, "api_client.create")
    assert created_audit.actor_type == "user" and created_audit.details["scopes"] == [
        "fleet:read",
        "telemetry:read",
    ]

    # The token works.
    me = client.get(BASE, headers=bearer(token))
    assert me.status_code == 200 and me.json()["client"]["name"] == "Mole Hash"


def test_only_admins_manage_clients(client, world):
    owner = world.owner()
    body = {"name": "x", "scopes": ["fleet:read"]}
    row, _ = issue(world)
    for user, may_list in ((world.user("auditor"), True), (world.user("owner", owner), False)):
        h = world.auth(user)
        assert client.get("/api/v1/api-clients", headers=h).status_code == (200 if may_list else 403)
        assert client.post("/api/v1/api-clients", headers=h, json=body).status_code == 403
        assert client.post(f"/api/v1/api-clients/{row.id}/rotate", headers=h).status_code == 403
        revoke = client.post(f"/api/v1/api-clients/{row.id}/revoke", headers=h, json={"reason": "r"})
        assert revoke.status_code == 403
    assert count(world, ApiClient) == 1
    world.session.refresh(row)
    assert row.status == "active" and row.rotated_at is None


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ({"name": "x", "scopes": ["fleet:read", "payouts:write"]}, "unknown scope"),
        ({"name": "x", "scopes": ["money:write"]}, "unknown scope"),
        ({"name": "x", "scopes": ["operations:disruptive", "fleet:read"]}, "needs operations:write"),
        ({"name": "x", "scopes": ["fleet:read"], "owner_id": UUID0}, "no such owner"),
    ],
)
def test_client_creation_is_validated(client, world, body, fragment):
    r = client.post("/api/v1/api-clients", headers=world.auth(world.user("admin")), json=body)
    assert r.status_code in (400, 404) and fragment in r.json()["error"]["message"], r.text
    assert count(world, ApiClient) == 0


def test_there_is_no_scope_for_money_users_pairing_or_binding():
    """What a client can never be given, however it is configured."""
    assert set(API_CLIENT_SCOPES) == {
        "fleet:read",
        "telemetry:read",
        "operations:read",
        "operations:write",
        "operations:disruptive",
        "earnings:read",
        # Read only (docs/appliance.md, section 3): mode, plugin states, indexing,
        # backup and update state. Nothing that changes the appliance.
        "appliance:read",
    }
    assert set(api_clients.SCOPE_HELP) == set(API_CLIENT_SCOPES)
    # Typed operations are the only thing any scope lets a client change. There is
    # no scope that writes money, users, pairing codes, provider bindings or the
    # appliance configuration.
    writing = {scope for scope in API_CLIENT_SCOPES if not scope.endswith(":read")}
    assert writing == {"operations:write", "operations:disruptive"}


def test_client_names_are_unique(world):
    issue(world, name="Mole Hash")
    with pytest.raises(Conflict, match="already exists"):
        api_clients.create_client(
            world.session, world.settings, SYSTEM, name="Mole Hash", scopes=["fleet:read"]
        )
    world.session.rollback()
    with pytest.raises(InvalidRequest, match="at least one scope"):
        api_clients.create_client(world.session, world.settings, SYSTEM, name="Other", scopes=[])


# --- authentication --------------------------------------------------------


def test_every_bad_token_gets_the_same_answer(client, world):
    row, token = issue(world)
    locator, secret = token.split(".")
    revoked_row, revoked = issue(world)
    api_clients.revoke_client(world.session, SYSTEM, revoked_row.id, "test")
    _, expired = issue(world, expires_in_days=1)
    world.commit()
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "UPDATE api_clients SET expires_at = now() - interval '1 second' WHERE expires_at IS NOT NULL"
            )
        )
    bad = {
        "no header": {},
        "not a token": bearer("hello"),
        "wrong secret": bearer(f"{locator}.{'A' * 43}"),
        "unknown client": bearer(f"hmc_{uuid.uuid4().hex}.{secret}"),
        "truncated": bearer(token[:-1]),
        "revoked": bearer(revoked),
        "expired": bearer(expired),
        "basic scheme": {"Authorization": f"Basic {token}"},
    }
    answers = {name: client.get(f"{BASE}/machines", headers=h) for name, h in bad.items()}
    for name, r in answers.items():
        assert r.status_code == 401, name
        assert envelope(r) == {
            "code": "client_unauthorized",
            "message": "The API client token is not valid.",
        }, name
    assert client.get(f"{BASE}/machines", headers=bearer(token)).status_code == 200


def test_browser_session_does_not_open_the_integration_api(app, world):
    """A signed-in admin's cookie is not a credential here: the API is bearer-token only."""
    admin = world.user("admin")
    browser = TestClient(app, base_url=BASE_URL)
    signed_in = browser.post("/api/v1/auth/demo-login", json={"email": admin.email})
    assert signed_in.status_code == 200
    assert browser.get("/api/v1/machines").status_code == 200
    r = browser.get(f"{BASE}/machines", headers={"X-CSRF-Token": signed_in.json()["csrf_token"]})
    assert r.status_code == 401 and envelope(r)["code"] == "client_unauthorized"


def test_last_use_is_recorded(client, world):
    row, token = issue(world)
    assert row.last_used_at is None
    assert client.get(BASE, headers=bearer(token)).status_code == 200
    world.session.refresh(row)
    assert row.last_used_at is not None and row.last_used_ip


# --- scopes ----------------------------------------------------------------


def test_every_integration_route_has_a_declared_scope(app):
    assert integration_routes(app) == set(ROUTE_SCOPES)


def test_each_route_needs_its_scope_and_nothing_less(client, world):
    owner = world.owner()
    machine, _ = world.paired_machine(owner)
    _, everything = issue(world, scopes=API_CLIENT_SCOPES)

    def call(method: str, path: str, token: str):
        url = path.replace("{machine_id}", str(machine.id)).replace("{operation_id}", UUID0)
        kw = {"json": {"type": "refresh_inventory", "params": {}}} if method == "POST" else {}
        return client.request(
            method, url, headers={**bearer(token), "Idempotency-Key": "scope-walk-0001"}, **kw
        )

    for (method, path), needed in ROUTE_SCOPES.items():
        if needed is None:
            continue
        # Every scope except the one this route needs (and what implies it).
        others = [s for s in API_CLIENT_SCOPES if s != needed]
        if needed == "operations:write":
            others.remove("operations:disruptive")
        _, without = issue(world, scopes=others)
        r = call(method, path, without)
        assert r.status_code == 403, f"{method} {path} answered {r.status_code} without {needed}"
        assert needed in r.json()["error"]["message"]
        allowed = call(method, path, everything)
        assert allowed.status_code in (200, 201, 404), (
            f"{method} {path}: {allowed.status_code} {allowed.text[:200]}"
        )
    assert count(world, Operation) == 1  # only the fully scoped request queued anything


def test_the_only_things_a_client_can_change_are_operations(app):
    unsafe = {(m, p) for m, p in integration_routes(app) if m != "GET"}
    assert unsafe == {
        ("POST", BASE + "/machines/{machine_id}/operations"),
        ("POST", BASE + "/operations/{operation_id}/cancel"),
    }


# --- fleet and telemetry ---------------------------------------------------


def test_fleet_machines_and_telemetry(client, world):
    alice, bob = world.owner("Alice"), world.owner("Bob")
    m1, t1 = world.paired_machine(alice, "gpu-a")
    m2, _ = world.paired_machine(bob, "gpu-b")
    older = datetime.now(UTC) - timedelta(minutes=5)
    assert heartbeat(client, t1, [sample(1, at=older), sample(2)]).json()["accepted"] == 2
    _, token = issue(world)
    h = bearer(token)

    me = client.get(BASE, headers=h).json()
    assert me["api"] == "happymining-integration" and me["api_version"] == 1
    assert me["mode"] == "demo" and me["synthetic_data"] is True
    assert me["client"]["scopes"] == list(READ) and me["client"]["owner_id"] is None

    listing = client.get(f"{BASE}/machines", headers=h).json()
    assert listing["total"] == 2 and [m["label"] for m in listing["items"]] == ["gpu-a", "gpu-b"]
    first, second = listing["items"]
    assert first["kind"] == "gpu_server" and first["id"] == str(m1.id) and first["owner_id"] == str(alice.id)
    assert first["connection"] == "online" and first["hostname"] == "gpu-a" and first["synthetic"] is True
    assert first["latest_telemetry"]["gpu_count"] == 1 and first["latest_telemetry"]["gpu_power_w"] == 30.5
    assert second["connection"] == "paired_never_seen" and second["latest_telemetry"] is None
    # Staff-only fields and anything that identifies the device credential stay out.
    for item in listing["items"]:
        assert not {"device_id", "vast_machine_id_hint", "device_status"} & set(item)

    one = client.get(f"{BASE}/machines/{m1.id}", headers=h)
    assert one.status_code == 200 and one.json() == first
    assert client.get(f"{BASE}/machines/{UUID0}", headers=h).status_code == 404

    history = client.get(f"{BASE}/machines/{m1.id}/telemetry", headers=h).json()["items"]
    assert [s["seq"] for s in history] == [2, 1]  # newest first
    assert history[0]["payload"]["gpus"][0]["name"] == "RTX 4090"
    since = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    recent = client.get(f"{BASE}/machines/{m1.id}/telemetry", headers=h, params={"since": since})
    assert [s["seq"] for s in recent.json()["items"]] == [2]

    summary = client.get(f"{BASE}/fleet/summary", headers=h).json()
    assert summary["machines"] == 2
    assert summary["by_connection"] == {"online": 1, "paired_never_seen": 1}
    assert summary["online_now"] == {
        "machines_reporting": 1,
        "gpus": 1,
        "gpu_power_w": 30.5,
        "gpu_util_avg": 0.0,
        "gpu_temp_max": 40.0,
    }

    # Paging.
    page = client.get(f"{BASE}/machines", headers=h, params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 2 and [m["id"] for m in page["items"]] == [str(m2.id)]


def test_telemetry_is_left_out_without_its_scope(client, world):
    machine, device_token = world.paired_machine(world.owner())
    heartbeat(client, device_token, [sample(1)])
    _, token = issue(world, scopes=("fleet:read",))
    h = bearer(token)
    item = client.get(f"{BASE}/machines/{machine.id}", headers=h).json()
    assert "latest_telemetry" not in item
    assert "online_now" not in client.get(f"{BASE}/fleet/summary", headers=h).json()
    assert client.get(f"{BASE}/machines/{machine.id}/telemetry", headers=h).status_code == 403


def test_owner_scoped_client_sees_one_owner_only(client, world):
    alice, account, provider = setup_fleet(
        world, {"101": {1: "100.00"}, "202": {1: "50.00"}}, machines=("101",)
    )
    bob = world.owner("Bob")
    theirs, their_device = world.paired_machine(bob, "bob-1")
    world.bind(account, "202", theirs)
    run_import(world, provider, account, 1, 1)
    own_machine = world.session.execute(select(Machine).where(Machine.owner_id == alice.id)).scalar_one()
    _, token = issue(world, scopes=WRITE, owner_id=alice.id)
    h = bearer(token)

    assert client.get(BASE, headers=h).json()["client"]["owner_id"] == str(alice.id)
    listing = client.get(f"{BASE}/machines", headers=h).json()
    assert listing["total"] == 1 and listing["items"][0]["id"] == str(own_machine.id)
    assert client.get(f"{BASE}/fleet/summary", headers=h).json()["machines"] == 1

    # Another owner's machine does not exist for this client, on any route.
    for path in (f"/machines/{theirs.id}", f"/machines/{theirs.id}/telemetry"):
        assert client.get(BASE + path, headers=h).status_code == 404, path
    assert request_op(client, token, theirs).status_code == 404
    assert count(world, Operation) == 0
    assert (
        client.get(f"{BASE}/earnings/daily", headers=h, params={"machine_id": str(theirs.id)}).status_code
        == 404
    )

    # An operation an admin queued on the other machine is invisible and cannot be cancelled.
    _, fleet_token = issue(world, scopes=WRITE)
    foreign = request_op(client, fleet_token, theirs).json()
    assert client.get(f"{BASE}/operations/{foreign['id']}", headers=h).status_code == 404
    assert client.post(f"{BASE}/operations/{foreign['id']}/cancel", headers=h).status_code == 404
    assert client.get(f"{BASE}/operations", headers=h).json()["total"] == 0

    # Earnings: only this owner's days.
    daily = client.get(f"{BASE}/earnings/daily", headers=h).json()
    assert [(row["owner_id"], row["reported"]) for row in daily["items"]] == [(str(alice.id), "100.00000000")]
    summary = client.get(f"{BASE}/earnings/summary", headers=h).json()
    assert [(row["machine_id"], row["reported"]) for row in summary["items"]] == [
        (str(own_machine.id), "100.00000000")
    ]


# --- earnings (read only) --------------------------------------------------


def test_earnings_are_reported_as_exact_decimal_strings(client, world):
    owner, account, provider = setup_fleet(
        world, {"101": {1: "100.00", 2: "49.4148"}, "303": {1: "13.15"}}, machines=("101",)
    )
    run_import(world, provider, account, 2, 1)
    _, token = issue(world)
    h = bearer(token)

    daily = client.get(f"{BASE}/earnings/daily", headers=h).json()
    assert daily["total"] == 3
    assert daily["period"] == {"start": world.day(30).isoformat(), "end": world.day(1).isoformat()}
    rows = {(row["provider_machine_id"], row["day"]): row for row in daily["items"]}
    top = rows[("101", world.day(1).isoformat())]
    assert top["attributed"] is True and top["owner_id"] == str(owner.id) and top["currency"] == "USD"
    assert (top["reported"], top["received"]) == ("100.00000000", "0.00000000")
    assert (top["fee_reported"], top["owner_share_reported"]) == ("10.00000000", "90.00000000")
    assert top["owner_share_reconciled"] == "0.00000000" and top["synthetic"] is True
    odd = rows[("101", world.day(2).isoformat())]
    assert D(odd["fee_reported"]) + D(odd["owner_share_reported"]) == D(odd["reported"]) == D("49.4148")
    # A machine nobody is bound to is visible to a fleet-wide client, as unattributed.
    stray = rows[("303", world.day(1).isoformat())]
    assert stray["attributed"] is False and stray["machine_id"] is None and stray["owner_id"] is None
    for row in daily["items"]:
        for field in ("reported", "received", "fee_reported", "owner_share_reported"):
            assert isinstance(row[field], str)

    summary = client.get(f"{BASE}/earnings/summary", headers=h).json()["items"]
    totals = {row["machine_id"]: row for row in summary}
    (machine_id,) = [k for k in totals if k]
    assert totals[machine_id]["reported"] == "149.41480000" and totals[machine_id]["days"] == 2
    assert totals[None]["reported"] == "13.15000000" and totals[None]["attributed"] is False

    one_day = client.get(
        f"{BASE}/earnings/daily",
        headers=h,
        params={"start": world.day(2).isoformat(), "end": world.day(2).isoformat()},
    ).json()
    assert [row["reported"] for row in one_day["items"]] == ["49.41480000"]
    bad = client.get(
        f"{BASE}/earnings/daily",
        headers=h,
        params={"start": world.day(1).isoformat(), "end": world.day(5).isoformat()},
    )
    assert bad.status_code == 400 and "before start" in bad.json()["error"]["message"]
    too_long = client.get(f"{BASE}/earnings/summary", headers=h, params={"start": "2020-01-01"})
    assert too_long.status_code == 400


# --- operations ------------------------------------------------------------


def test_operation_requested_by_a_client_reaches_the_agent(client, world):
    machine, device_token = world.paired_machine(world.owner())
    row, token = issue(world, scopes=WRITE)
    h = bearer(token)

    types = client.get(f"{BASE}/operation-types", headers=h).json()
    assert "refresh_inventory" in types["types"] and "reboot" in types["disruptive"]
    assert types["client_may_request"] is True and types["client_may_request_disruptive"] is False

    r = request_op(client, token, machine, "collect_diagnostics", {"sections": ["agent"]})
    assert r.status_code == 201, r.text
    queued = r.json()
    assert queued["status"] == "pending" and queued["requested_by"] == "self"
    assert "requested_by_client" not in queued and "nonce" not in queued

    # The agent gets it with its next heartbeat and reports the result.
    (delivered,) = heartbeat(client, device_token, [sample(1)]).json()["operations"]
    assert delivered["id"] == queued["id"] and delivered["type"] == "collect_diagnostics"
    ack = client.post(
        f"/api/v1/device/operations/{queued['id']}/ack",
        headers=bearer(device_token),
        json={
            "status": "succeeded",
            "nonce": delivered["nonce"],
            "detail": "done",
            "result": {"agent": "ok"},
        },
    )
    assert ack.status_code == 200

    seen = client.get(f"{BASE}/operations/{queued['id']}", headers=h).json()
    assert (seen["status"], seen["detail"], seen["result"]) == ("succeeded", "done", {"agent": "ok"})
    listing = client.get(f"{BASE}/operations", headers=h, params={"machine_id": str(machine.id)}).json()
    assert [op["id"] for op in listing["items"]] == [queued["id"]]
    assert client.get(f"{BASE}/operations", headers=h, params={"status": "pending"}).json()["total"] == 0

    # On the record as the client's doing, not a person's and not the system's.
    (request_audit,) = audit_rows(world, "operation.request")
    assert (request_audit.actor_type, request_audit.actor_id) == ("client", str(row.id))
    stored = world.session.get(Operation, uuid.UUID(queued["id"]))
    assert stored.requested_by_client == row.id and stored.requested_by is None


def test_idempotency_key_is_required_and_makes_a_retry_safe(client, world):
    machine, _ = world.paired_machine(world.owner())
    other, _ = world.paired_machine(world.owner(), "m2")
    _, token = issue(world, scopes=WRITE)
    url = f"{BASE}/machines/{machine.id}/operations"
    body = {"type": "refresh_inventory", "params": {}}

    missing = client.post(url, headers=bearer(token), json=body)
    assert missing.status_code == 400 and "Idempotency-Key" in missing.json()["error"]["message"]
    short = client.post(url, headers={**bearer(token), "Idempotency-Key": "k"}, json=body)
    assert short.status_code == 400
    assert count(world, Operation) == 0

    first = request_op(client, token, machine, key="molehash-action-0001")
    assert first.status_code == 201
    again = request_op(client, token, machine, key="molehash-action-0001")
    assert again.status_code == 200 and again.json()["id"] == first.json()["id"]
    assert count(world, Operation) == 1 and len(audit_rows(world, "operation.request")) == 1

    # The same key for something else is a mistake in the caller, not a new request.
    for response in (
        request_op(client, token, machine, "run_preflight", key="molehash-action-0001"),
        request_op(client, token, other, key="molehash-action-0001"),
        request_op(
            client, token, machine, "collect_diagnostics", {"sections": ["gpu"]}, key="molehash-action-0001"
        ),
    ):
        assert response.status_code == 409 and "different operation" in response.json()["error"]["message"]
    assert count(world, Operation) == 1

    # Keys belong to a client: another client may use the same string.
    _, second_token = issue(world, scopes=WRITE)
    theirs = request_op(client, second_token, machine, key="molehash-action-0001")
    assert theirs.status_code == 201 and theirs.json()["id"] != first.json()["id"]


def test_the_same_request_sent_twice_at_once_queues_one_operation(app, world):
    machine, _ = world.paired_machine(world.owner())
    _, token = issue(world, scopes=WRITE)
    barrier = threading.Barrier(4)
    results: list[tuple[int, str]] = []

    def send():
        with TestClient(app, base_url=BASE_URL) as c:
            barrier.wait(timeout=10)
            r = request_op(c, token, machine, key="simultaneous-0001")
            results.append((r.status_code, r.json().get("id", r.text)))

    threads = [threading.Thread(target=send) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert sorted(code for code, _ in results) == [200, 200, 200, 201], results
    assert len({op_id for _, op_id in results}) == 1
    assert count(world, Operation) == 1


def test_only_typed_operations_exist(client, world):
    machine, _ = world.paired_machine(world.owner())
    _, token = issue(world, scopes=(*WRITE, "operations:disruptive"))
    for op_type, params, status, code in (
        ("shell", {"command": "id"}, 400, "invalid_request"),
        ("refresh_inventory", {"command": "id"}, 400, "invalid_request"),
        ("run_benchmark", {"duration_s": 60}, 501, "not_implemented"),
        ("apply_hardware_profile", {"profile_id": "eco"}, 501, "not_implemented"),
    ):
        r = request_op(client, token, machine, op_type, params)
        assert (r.status_code, envelope(r)["code"]) == (status, code), f"{op_type}: {r.text}"
    extra = client.post(
        f"{BASE}/machines/{machine.id}/operations",
        headers={**bearer(token), "Idempotency-Key": "extra-field-0001"},
        json={"type": "refresh_inventory", "params": {}, "command": "id"},
    )
    assert extra.status_code == 422
    assert count(world, Operation) == 0


def test_disruptive_operations_need_the_scope_and_still_pass_the_gate(world):
    machine, device_token, provider = gated_fleet(world)
    _, plain = issue(world, scopes=WRITE)
    _, trusted = issue(world, scopes=(*WRITE, "operations:disruptive"))

    # Without the scope: refused outright, nothing recorded, whatever the server allows.
    with TestClient(create_app(make_settings(disruptive_operations_enabled=True)), base_url=BASE_URL) as c:
        for op_type, params in (("reboot", {"delay_s": 60}), ("restart_vast_daemon", {})):
            r = request_op(c, plain, machine, op_type, params)
            assert r.status_code == 403 and "operations:disruptive" in r.json()["error"]["message"]
        assert count(world, Operation) == 0

    # With the scope, but the server switch is off: blocked, on record, reported as an error.
    with TestClient(create_app(make_settings(disruptive_operations_enabled=False)), base_url=BASE_URL) as c:
        r = request_op(c, trusted, machine, "reboot", {"delay_s": 60}, key="reboot-attempt-0001")
        assert r.status_code == 409 and envelope(r)["code"] == "maintenance_blocked"
        # Repeating the same request does not turn the refusal into something else.
        again = request_op(c, trusted, machine, "reboot", {"delay_s": 60}, key="reboot-attempt-0001")
        assert again.status_code == 409 and envelope(again)["code"] == "maintenance_blocked"
        assert heartbeat(c, device_token, [sample(1)]).json()["operations"] == []
    assert [op.status for op in world.session.execute(select(Operation)).scalars()] == ["blocked"]
    assert len(audit_rows(world, "operation.blocked")) == 1

    with TestClient(create_app(make_settings(disruptive_operations_enabled=True)), base_url=BASE_URL) as c:
        # Switch on, machine rented: the gate refuses. Idle telemetry changes nothing.
        provider.dataset["machines"][0]["rental"] = dict(ACTIVE_CONTRACT)
        heartbeat(c, device_token, [sample(2)])  # 0% GPU utilisation
        rented = request_op(c, trusted, machine, "restart_vast_daemon")
        assert rented.status_code == 409 and envelope(rented)["code"] == "maintenance_blocked"
        assert "active" in rented.json()["error"]["message"].lower()

        # Switch on, provider confirms idle and unlisted: allowed, and delivered.
        provider.dataset["machines"][0]["rental"] = dict(IDLE_UNLISTED["rental"])
        ok = request_op(c, trusted, machine, "restart_vast_daemon")
        assert ok.status_code == 201 and ok.json()["safety"]["allowed"] is True
        (delivered,) = heartbeat(c, device_token, [sample(3)]).json()["operations"]
        assert delivered["id"] == ok.json()["id"]


def test_cancel_before_delivery_only(client, world):
    machine, device_token = world.paired_machine(world.owner())
    row, token = issue(world, scopes=WRITE)
    h = bearer(token)
    pending = request_op(client, token, machine).json()
    cancelled = client.post(f"{BASE}/operations/{pending['id']}/cancel", headers=h)
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
    assert heartbeat(client, device_token, [sample(1)]).json()["operations"] == []
    (cancel_audit,) = audit_rows(world, "operation.cancel")
    assert (cancel_audit.actor_type, cancel_audit.actor_id) == ("client", str(row.id))

    sent = request_op(client, token, machine).json()
    assert len(heartbeat(client, device_token, [sample(2)]).json()["operations"]) == 1
    late = client.post(f"{BASE}/operations/{sent['id']}/cancel", headers=h)
    assert late.status_code == 409
    assert client.post(f"{BASE}/operations/{UUID0}/cancel", headers=h).status_code == 404


# --- rate limit, rotation, revocation --------------------------------------


def test_each_client_has_its_own_rate_limit(world):
    _, busy = issue(world)
    _, quiet = issue(world)
    stay_inside_one_window()
    with TestClient(create_app(make_settings(integration_rate_limit_per_minute=10)), base_url=BASE_URL) as c:
        codes = [c.get(f"{BASE}/machines", headers=bearer(busy)).status_code for _ in range(12)]
        assert codes == [200] * 10 + [429] * 2
        limited = c.get(BASE, headers=bearer(busy))
        assert limited.status_code == 429 and envelope(limited)["code"] == "rate_limited"
        assert 1 <= int(limited.headers["retry-after"]) <= 60
        assert c.get(f"{BASE}/machines", headers=bearer(quiet)).status_code == 200


def test_rotation_replaces_the_token_at_once(client, world):
    row, old = issue(world)
    admin = world.auth(world.user("admin"))
    r = client.post(f"/api/v1/api-clients/{row.id}/rotate", headers=admin)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    new = r.json()["token"]
    assert new != old and new.split(".")[0] == old.split(".")[0]  # same client, new secret
    assert client.get(BASE, headers=bearer(old)).status_code == 401
    assert client.get(BASE, headers=bearer(new)).status_code == 200
    (rotated,) = audit_rows(world, "api_client.rotate")
    assert new.split(".")[1] not in json.dumps(rotated.details)


def test_revocation_is_immediate_and_cancels_what_was_queued(client, world):
    machine, device_token = world.paired_machine(world.owner())
    row, token = issue(world, scopes=WRITE)
    _, bystander = issue(world, scopes=WRITE)
    delivered = request_op(client, token, machine).json()
    assert len(heartbeat(client, device_token, [sample(1)]).json()["operations"]) == 1
    waiting = request_op(client, token, machine, "run_preflight").json()
    untouched = request_op(client, bystander, machine, "run_preflight").json()

    admin = world.auth(world.user("admin"))
    r = client.post(f"/api/v1/api-clients/{row.id}/revoke", headers=admin, json={"reason": "token leaked"})
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    assert client.get(BASE, headers=bearer(token)).status_code == 401
    assert request_op(client, token, machine).status_code == 401

    states = {str(op.id): op.status for op in world.session.execute(select(Operation)).scalars()}
    # Not yet delivered: cancelled. Already with the agent: left alone. Someone else's: left alone.
    assert states == {delivered["id"]: "delivered", waiting["id"]: "cancelled", untouched["id"]: "pending"}
    (revoked,) = audit_rows(world, "api_client.revoke")
    assert revoked.details == {"reason": "token leaked", "operations_cancelled": 1}

    # Revoking twice changes nothing; a revoked client cannot be rotated back to life.
    assert (
        client.post(
            f"/api/v1/api-clients/{row.id}/revoke", headers=admin, json={"reason": "again"}
        ).status_code
        == 200
    )
    assert len(audit_rows(world, "api_client.revoke")) == 1
    assert client.post(f"/api/v1/api-clients/{row.id}/rotate", headers=admin).status_code == 409


# --- redaction -------------------------------------------------------------


def test_client_tokens_are_redacted_like_other_credentials(world):
    _, token = issue(world)
    secret = token.split(".")[1]
    for text_value in (f"called with {token} twice", f"Authorization: Bearer {token}"):
        out = redact_text(text_value)
        assert secret not in out and "[REDACTED]" in out
    assert secret not in json.dumps(redact({"note": f"token was {token}", "api_token": token}))


# --- dashboard -------------------------------------------------------------


def signed_in_browser(app, user) -> tuple[TestClient, str]:
    browser = TestClient(app, base_url=BASE_URL)
    assert browser.post("/demo-login", data={"email": user.email}, follow_redirects=False).status_code == 303
    return browser, browser.get("/api/v1/auth/me").json()["csrf_token"]


def test_integrations_page_creates_shows_once_and_revokes(app, client, world):
    owner = world.owner("Alice")
    browser, csrf = signed_in_browser(app, world.user("admin"))
    page = browser.get("/admin/integrations")
    assert page.status_code == 200 and "No API client yet." in page.text

    created = browser.post(
        "/admin/integrations",
        data={
            "name": "Mole Hash",
            "description": "fleet manager",
            "scopes": ["fleet:read", "telemetry:read"],
            "owner_id": str(owner.id),
            "expires_in_days": "90",
            "csrf_token": csrf,
        },
    )
    assert created.status_code == 200 and created.headers["cache-control"] == "no-store"
    row = world.session.execute(select(ApiClient)).scalar_one()
    assert (row.name, row.scopes, row.owner_id) == ("Mole Hash", ["fleet:read", "telemetry:read"], owner.id)
    assert row.expires_at is not None
    (token,) = set(re.findall(r"hmc_[0-9a-f]{32}\.[A-Za-z0-9_-]{43}", created.text))
    assert client.get(BASE, headers=bearer(token)).status_code == 200

    # A reload shows the client, not the token.
    later = browser.get("/admin/integrations")
    assert "Mole Hash" in later.text and token not in later.text and token.split(".")[1] not in later.text
    assert token[:12] in later.text and "Alice" in later.text

    rotated = browser.post(f"/admin/integrations/{row.id}/rotate", data={"csrf_token": csrf})
    assert rotated.status_code == 200 and "hmc_" in rotated.text
    assert client.get(BASE, headers=bearer(token)).status_code == 401

    revoked = browser.post(
        f"/admin/integrations/{row.id}/revoke",
        data={"reason": "done", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert revoked.status_code == 303 and "msg=" in revoked.headers["location"]
    world.session.refresh(row)
    assert row.status == "revoked"

    # Bad input comes back as a message, and creates nothing.
    bad = browser.post(
        "/admin/integrations",
        data={"name": "No scopes", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert bad.status_code == 303 and "err=" in bad.headers["location"]
    assert count(world, ApiClient) == 1


def test_auditor_sees_clients_but_cannot_change_them(app, world):
    row, token = issue(world, name="Mole Hash")
    browser, csrf = signed_in_browser(app, world.user("auditor"))
    page = browser.get("/admin/integrations")
    assert page.status_code == 200 and "Mole Hash" in page.text
    assert "New API client" not in page.text and "Rotate token" not in page.text
    assert token.split(".")[1] not in page.text
    for path, data in (
        ("/admin/integrations", {"name": "x", "scopes": ["fleet:read"]}),
        (f"/admin/integrations/{row.id}/rotate", {}),
        (f"/admin/integrations/{row.id}/revoke", {"reason": "r"}),
    ):
        r = browser.post(path, data={**data, "csrf_token": csrf}, follow_redirects=False)
        assert r.status_code == 403, path
    assert count(world, ApiClient) == 1
    owner_browser, _ = signed_in_browser(app, world.user("owner", world.owner()))
    assert owner_browser.get("/admin/integrations").status_code == 403


# --- the client shipped for Mole Hash --------------------------------------


def load_molehash_client():
    path = REPO / "integrations" / "molehash" / "happymining_client.py"
    spec = importlib.util.spec_from_file_location("happymining_client", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def served(world):
    """The API on a real loopback port, so the urllib-based client talks real HTTP to it."""
    from test_end_to_end_binaries import Server

    server = Server({}).start()
    try:
        yield server
    finally:
        server.stop()


def test_molehash_client_reads_the_fleet_and_requests_an_operation(served, world):
    hm_module = load_molehash_client()
    owner, account, provider = setup_fleet(world, {"101": {1: "100.00"}}, machines=("101",))
    run_import(world, provider, account, 1, 1)
    row, token = issue(world, scopes=WRITE)
    hm = hm_module.HappyMiningClient(served.url, token, retries=0)
    assert token not in repr(hm)

    assert hm.describe()["client"]["name"] == row.name
    machines = list(hm.machines(page_size=1))
    assert len(machines) == 1 and machines[0]["kind"] == "gpu_server"
    machine_id = machines[0]["id"]
    assert hm.machine(machine_id)["id"] == machine_id
    assert hm.fleet_summary()["machines"] == 1
    assert hm.telemetry(machine_id) == []
    assert [row["reported"] for row in hm.earnings_daily()] == ["100.00000000"]
    assert hm.earnings_summary()["items"][0]["reported"] == "100.00000000"

    record = hm_module.to_device_record(machines[0])
    assert record["external_id"] == machine_id and record["source"] == "happymining-os"
    assert record["online"] is False and record["synthetic"] is True and "hashrate" not in record

    first = hm.request_operation(machine_id, "refresh_inventory", idempotency_key="molehash-job-0001")
    again = hm.request_operation(machine_id, "refresh_inventory", idempotency_key="molehash-job-0001")
    assert first["id"] == again["id"] and first["status"] == "pending"
    assert [op["id"] for op in hm.operations(status="pending")] == [first["id"]]
    assert hm.cancel_operation(first["id"])["status"] == "cancelled"
    assert hm.operation(first["id"])["status"] == "cancelled"

    # Errors come back typed, with the server's code.
    with pytest.raises(hm_module.HappyMiningError) as refused:
        hm.request_operation(machine_id, "reboot", {"delay_s": 60})
    assert (refused.value.status, refused.value.code) == (403, "forbidden")
    with pytest.raises(hm_module.HappyMiningError) as missing:
        hm.machine(UUID0)
    assert missing.value.status == 404 and missing.value.request_id

    bad = hm_module.HappyMiningClient(served.url, "hmc_" + "0" * 32 + "." + "A" * 43, retries=0)
    with pytest.raises(hm_module.HappyMiningError) as denied:
        bad.describe()
    assert (denied.value.status, denied.value.code) == (401, "client_unauthorized")


def test_molehash_client_refuses_to_send_the_token_in_clear_text():
    hm_module = load_molehash_client()
    token = "hmc_" + "0" * 32 + "." + "A" * 43
    with pytest.raises(ValueError, match="loopback"):
        hm_module.HappyMiningClient("http://api.happymining.fr", token)
    with pytest.raises(ValueError, match="hmc_"):
        hm_module.HappyMiningClient("https://api.happymining.fr", "hms_session-token")
    hm_module.HappyMiningClient("https://api.happymining.fr", token)  # fine
    unreachable = hm_module.HappyMiningClient("http://127.0.0.1:9", token, retries=0, timeout=2)
    with pytest.raises(hm_module.HappyMiningError) as failed:
        unreachable.describe()
    assert failed.value.status == 0 and failed.value.code == "unreachable"


def test_session_factory_is_untouched_by_client_auth(world):
    """Authenticating a client records its last use in a separate transaction; the caller's stays clean."""
    row, token = issue(world)
    session = session_factory()()
    try:
        principal = api_clients.authenticate_client(session, world.settings, token, "203.0.113.7")
        assert principal.client.id == row.id and not session.dirty and not session.new
    finally:
        session.rollback()
        session.close()
    world.session.refresh(row)
    assert row.last_used_ip == "203.0.113.7"


# --- LIVE ------------------------------------------------------------------


def test_integration_api_in_live_mode_says_so_and_serves_no_synthetic_flag():
    """The same API in LIVE: it identifies the mode, and a client is as bound by the gate as an admin."""
    from test_security_regressions import live_app

    with live_app() as (live_world, c, live):
        owner = live_world.owner()
        machine, _ = live_world.paired_machine(owner)
        issued = api_clients.create_client(
            live_world.session, live, SYSTEM, name="Mole Hash", scopes=[*WRITE, "operations:disruptive"]
        )
        live_world.commit()
        h = bearer(issued.token)
        me = c.get(BASE, headers=h)
        assert me.status_code == 200, me.text
        assert (me.json()["mode"], me.json()["synthetic_data"]) == ("live", False)
        (item,) = c.get(f"{BASE}/machines", headers=h).json()["items"]
        assert item["synthetic"] is False and item["provider"] is None

        # No rental state is available in LIVE, so a disruptive request is blocked, not queued.
        r = c.post(
            f"{BASE}/machines/{machine.id}/operations",
            headers={**h, "Idempotency-Key": "live-reboot-0001"},
            json={"type": "reboot", "params": {"delay_s": 60}},
        )
        assert r.status_code == 409 and envelope(r)["code"] == "maintenance_blocked"
        # A harmless one is accepted.
        ok = c.post(
            f"{BASE}/machines/{machine.id}/operations",
            headers={**h, "Idempotency-Key": "live-inventory-0001"},
            json={"type": "refresh_inventory", "params": {}},
        )
        assert ok.status_code == 201


# =============================================================================
# Findings of the independent review of this API, each with its test
# =============================================================================


def burst(app, n: int, send) -> tuple[list[int], float]:
    """``n`` requests at the same moment, each on its own connection. Returns (status codes, seconds)."""
    barrier = threading.Barrier(n)
    codes: list[int] = []

    def one():
        with TestClient(app, base_url=BASE_URL) as c:
            barrier.wait(timeout=30)
            codes.append(send(c).status_code)

    threads = [threading.Thread(target=one) for _ in range(n)]
    started = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=90)
    return codes, time.monotonic() - started


def test_a_burst_from_one_client_does_not_exhaust_the_connection_pool(app, world):
    """More simultaneous requests than the pool has connections: all answered, none after a pool timeout.

    Each request used to hold one connection while waiting for a second (rate
    limit, last-use bookkeeping). With the pool full of such requests, nothing
    moved for 30 seconds and the whole API stalled, for every caller.
    """
    world.paired_machine(world.owner())
    _, token = issue(world)
    codes, seconds = burst(app, 45, lambda c: c.get(f"{BASE}/machines", headers=bearer(token)))
    assert codes == [200] * 45, sorted(set(codes))
    assert seconds < 20, f"the burst took {seconds:.1f}s"


def test_a_burst_from_one_device_does_not_exhaust_the_connection_pool(app, world):
    _, device_token = world.paired_machine(world.owner())
    codes, seconds = burst(app, 45, lambda c: c.get("/api/v1/device/self", headers=bearer(device_token)))
    assert codes == [200] * 45, sorted(set(codes))
    assert seconds < 20, f"the burst took {seconds:.1f}s"


def test_provider_machine_hint_is_for_staff_only(client, world):
    """The agent's guess at the provider machine is evidence for the binding admin, nobody else."""
    owner = world.owner()
    machine, device_token = world.paired_machine(owner)
    hint = "sha256:" + "ab" * 32
    vast = {"daemon_installed": True, "machine_id_hint": hint}
    assert heartbeat(client, device_token, [sample(1, vast=vast)]).json()["accepted"] == 1

    _, token = issue(world)
    for path in (f"/machines/{machine.id}/telemetry", f"/machines/{machine.id}", "/machines"):
        r = client.get(BASE + path, headers=bearer(token))
        assert r.status_code == 200 and hint not in r.text, path
    kept = client.get(f"{BASE}/machines/{machine.id}/telemetry", headers=bearer(token)).json()["items"][0]
    assert kept["payload"]["vast"] == {"daemon_installed": True}  # the rest of the sample is intact

    owner_view = client.get(
        f"/api/v1/machines/{machine.id}/telemetry", headers=world.auth(world.user("owner", owner))
    )
    assert owner_view.status_code == 200 and hint not in owner_view.text
    admin_view = client.get(
        f"/api/v1/machines/{machine.id}/telemetry", headers=world.auth(world.user("admin"))
    )
    assert hint in admin_view.text


def test_request_authenticated_just_before_revocation_queues_nothing(world):
    """The token is re-checked inside the transaction that queues the operation."""
    machine, _ = world.paired_machine(world.owner())
    row, token = issue(world, scopes=WRITE)
    racing = session_factory()()
    try:
        principal = api_clients.authenticate_client(racing, world.settings, token)  # valid at this moment
        api_clients.revoke_client(world.session, SYSTEM, row.id, "leaked")
        world.commit()
        with pytest.raises(ClientUnauthorized):
            operations.request_operation_for_client(
                racing,
                world.settings,
                principal.actor(),
                None,
                machine=racing.get(Machine, machine.id),
                op_type="rotate_credential",
                params={},
                client_id=row.id,
                request_key="queued-during-revocation",
            )
        racing.rollback()
    finally:
        racing.close()
    assert count(world, Operation) == 0 and audit_rows(world, "operation.request") == []


def test_operations_of_a_client_that_expired_are_not_delivered(client, world):
    machine, device_token = world.paired_machine(world.owner())
    _, token = issue(world, scopes=WRITE, expires_in_days=1)
    _, lasting = issue(world, scopes=WRITE)
    doomed = request_op(client, token, machine).json()
    kept = request_op(client, lasting, machine, "run_preflight").json()
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "UPDATE api_clients SET expires_at = now() - interval '1 second' WHERE expires_at IS NOT NULL"
            )
        )

    delivered = heartbeat(client, device_token, [sample(1)]).json()["operations"]
    assert [op["id"] for op in delivered] == [kept["id"]]
    stored = world.session.get(Operation, uuid.UUID(doomed["id"]))
    world.session.refresh(stored)
    assert stored.status == "cancelled" and "no longer valid" in stored.detail


def test_a_client_cancels_only_what_it_requested(client, world):
    machine, _ = world.paired_machine(world.owner())
    _, token = issue(world, scopes=WRITE)
    _, other = issue(world, scopes=WRITE)
    by_admin = client.post(
        f"/api/v1/machines/{machine.id}/operations",
        headers=world.auth(world.user("admin")),
        json={"type": "rotate_credential", "params": {}},
    ).json()
    by_other = request_op(client, other, machine, "run_preflight").json()
    for foreign in (by_admin, by_other):
        r = client.post(f"{BASE}/operations/{foreign['id']}/cancel", headers=bearer(token))
        assert r.status_code == 403 and "this API client requested" in r.json()["error"]["message"]
    assert {op.status for op in world.session.execute(select(Operation)).scalars()} == {"pending"}
    assert audit_rows(world, "operation.cancel") == []


def test_one_client_cannot_fill_a_machines_queue(world):
    owner = world.owner()
    machine, device_token = world.paired_machine(owner, "m1")
    elsewhere, _ = world.paired_machine(owner, "m2")
    _, token = issue(world, scopes=WRITE)
    _, other = issue(world, scopes=WRITE)
    with TestClient(
        create_app(make_settings(integration_max_open_operations_per_machine=3)), base_url=BASE_URL
    ) as c:
        first = [request_op(c, token, machine) for _ in range(3)]
        assert [r.status_code for r in first] == [201] * 3
        full = request_op(c, token, machine)
        assert full.status_code == 409 and envelope(full)["code"] == "too_many_open_operations"
        # The limit is per client and per machine.
        assert request_op(c, other, machine).status_code == 201
        assert request_op(c, token, elsewhere).status_code == 201
        # Delivered operations still count: the agent has not finished them.
        assert len(heartbeat(c, device_token, [sample(1)]).json()["operations"]) == 4
        assert request_op(c, token, machine).status_code == 409
        # Room again once one of them is over.
        done = c.post(
            f"/api/v1/device/operations/{first[0].json()['id']}/ack",
            headers=bearer(device_token),
            json={
                "status": "succeeded",
                "nonce": world.session.get(Operation, uuid.UUID(first[0].json()["id"])).nonce,
            },
        )
        assert done.status_code == 200
        assert request_op(c, token, machine).status_code == 201


def test_owner_scoped_view_starts_when_the_machine_became_theirs(client, world):
    """After a transfer, the new owner's client does not read the previous owner's telemetry or operations."""
    bob, alice = world.owner("Bob"), world.owner("Alice")
    machine, device_token = world.paired_machine(bob, "handed-over")
    _, bob_token = issue(world, scopes=WRITE, owner_id=bob.id)
    _, alice_token = issue(world, scopes=WRITE, owner_id=alice.id)
    _, fleet_token = issue(world, scopes=WRITE)
    heartbeat(client, device_token, [sample(1)])
    done = request_op(client, bob_token, machine, "collect_diagnostics", {"sections": ["agent"]}).json()
    (delivered,) = heartbeat(client, device_token, [sample(2)]).json()["operations"]
    ack = client.post(
        f"/api/v1/device/operations/{done['id']}/ack",
        headers=bearer(device_token),
        json={"status": "succeeded", "nonce": delivered["nonce"], "result": {"note": "from Bob's time"}},
    )
    assert ack.status_code == 200
    waiting = request_op(client, bob_token, machine, "run_preflight").json()

    admin = world.user("admin")
    machine_service.transfer_ownership(
        world.session, SYSTEM, machine_id=machine.id, new_owner_id=alice.id, reason="sold", user_id=admin.id
    )
    world.commit()

    # Bob's client no longer has the machine, and what it had queued is withdrawn.
    assert client.get(f"{BASE}/machines/{machine.id}", headers=bearer(bob_token)).status_code == 404
    world.session.expire_all()
    assert world.session.get(Operation, uuid.UUID(waiting["id"])).status == "cancelled"
    assert heartbeat(client, device_token, [sample(3)]).json()["operations"] == []

    # Alice's client has the machine, without its history under Bob.
    h = bearer(alice_token)
    item = client.get(f"{BASE}/machines/{machine.id}", headers=h).json()
    assert item["owner_id"] == str(alice.id) and item["latest_telemetry"] is None
    assert client.get(f"{BASE}/machines/{machine.id}/telemetry", headers=h).json()["items"] == []
    assert (
        client.get(f"{BASE}/operations", headers=h, params={"machine_id": str(machine.id)}).json()["total"]
        == 0
    )
    assert client.get(f"{BASE}/operations/{done['id']}", headers=h).status_code == 404
    assert "from Bob's time" not in client.get(f"{BASE}/operations", headers=h).text
    # The same holds for Alice as a person, through the owner routes.
    as_alice = world.auth(world.user("owner", alice))
    assert client.get(f"/api/v1/machines/{machine.id}/telemetry", headers=as_alice).json()["items"] == []
    assert client.get(f"/api/v1/machines/{machine.id}/operations", headers=as_alice).json()["total"] == 0

    # Staff and a fleet-wide client keep the whole history.
    fleet = bearer(fleet_token)
    assert len(client.get(f"{BASE}/machines/{machine.id}/telemetry", headers=fleet).json()["items"]) == 3
    assert client.get(f"{BASE}/operations/{done['id']}", headers=fleet).status_code == 200


def test_operations_do_not_reveal_who_else_asked(client, world):
    machine, _, provider = gated_fleet(world)
    row, token = issue(world, scopes=WRITE)
    _, other = issue(world, scopes=WRITE)
    admin = world.user("admin")
    by_admin = client.post(
        f"/api/v1/machines/{machine.id}/operations",
        headers=world.auth(admin),
        json={"type": "refresh_inventory", "params": {}},
    ).json()
    by_other = request_op(client, other, machine).json()
    mine = request_op(client, token, machine).json()

    listing = client.get(f"{BASE}/operations", headers=bearer(token))
    who = {op["id"]: op["requested_by"] for op in listing.json()["items"]}
    assert who == {by_admin["id"]: "user", by_other["id"]: "client", mine["id"]: "self"}
    assert str(admin.id) not in listing.text and by_other["requested_by"] == "self"
    other_id = world.session.execute(select(ApiClient.id).where(ApiClient.id != row.id)).scalar_one()
    assert str(other_id) not in listing.text
    for op in listing.json()["items"]:
        assert "requested_by_client" not in op and set(op["safety"]) == {"allowed", "reasons"}


def test_filtering_operations_on_a_machine_outside_the_scope_is_not_found(client, world):
    alice, bob = world.owner("Alice"), world.owner("Bob")
    world.paired_machine(alice)
    theirs, _ = world.paired_machine(bob, "bobs")
    _, token = issue(world, owner_id=alice.id)
    r = client.get(f"{BASE}/operations", headers=bearer(token), params={"machine_id": str(theirs.id)})
    assert r.status_code == 404
    assert (
        client.get(f"{BASE}/operations", headers=bearer(token), params={"machine_id": UUID0}).status_code
        == 404
    )


def test_earnings_cover_closed_days_only(client, world):
    _, token = issue(world)
    today = world.today.isoformat()
    for path in ("/earnings/daily", "/earnings/summary"):
        r = client.get(
            BASE + path, headers=bearer(token), params={"start": world.day(3).isoformat(), "end": today}
        )
        assert r.status_code == 400 and "closed UTC day" in r.json()["error"]["message"], path


def test_expired_client_cannot_be_rotated_and_revoking_needs_a_reason(client, world):
    row, _ = issue(world, expires_in_days=1)
    with get_engine().begin() as conn:
        conn.execute(text("UPDATE api_clients SET expires_at = now() - interval '1 second'"))
    admin = world.auth(world.user("admin"))
    listed = client.get("/api/v1/api-clients", headers=admin).json()["items"][0]
    assert listed["status"] == "expired"
    rotate = client.post(f"/api/v1/api-clients/{row.id}/rotate", headers=admin)
    assert rotate.status_code == 409 and "expired" in rotate.json()["error"]["message"]
    assert audit_rows(world, "api_client.rotate") == []

    with pytest.raises(InvalidRequest, match="reason is required"):
        api_clients.revoke_client(world.session, SYSTEM, row.id, "   ")
    world.session.rollback()
    world.session.refresh(row)
    assert row.status == "active"


def test_integrations_form_rejects_bad_input_without_an_error_page(app, world):
    row, _ = issue(world, name="Mole Hash")
    browser, csrf = signed_in_browser(app, world.user("admin"))
    odd_number = browser.post(
        "/admin/integrations",
        data={"name": "Second", "scopes": ["fleet:read"], "expires_in_days": "²", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert odd_number.status_code == 303 and "err=" in odd_number.headers["location"]
    no_reason = browser.post(
        f"/admin/integrations/{row.id}/revoke",
        data={"reason": " ", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert no_reason.status_code == 303 and "err=" in no_reason.headers["location"]
    world.session.refresh(row)
    assert row.status == "active" and count(world, ApiClient) == 1


def test_integrations_forms_need_the_csrf_token(app, world):
    row, _ = issue(world, name="Mole Hash")
    browser, csrf = signed_in_browser(app, world.user("admin"))
    for path, data in (
        ("/admin/integrations", {"name": "x", "scopes": ["fleet:read"]}),
        (f"/admin/integrations/{row.id}/rotate", {}),
        (f"/admin/integrations/{row.id}/revoke", {"reason": "r"}),
    ):
        assert browser.post(path, data=data, follow_redirects=False).status_code == 403, path
        wrong = browser.post(path, data={**data, "csrf_token": "nope"}, follow_redirects=False)
        assert wrong.status_code == 403, path
        foreign = browser.post(
            path,
            data={**data, "csrf_token": csrf},
            headers={"Origin": "https://attacker.example"},
            follow_redirects=False,
        )
        assert foreign.status_code == 403, path
    world.session.refresh(row)
    assert row.status == "active" and row.rotated_at is None and count(world, ApiClient) == 1


def test_refused_tokens_are_throttled_per_address(world, capsys):
    _, token = issue(world)
    stay_inside_one_window()
    settings = make_settings(integration_auth_failure_limit_per_minute=5)
    with TestClient(create_app(settings), base_url=BASE_URL) as c:
        capsys.readouterr()
        wrong = bearer("hmc_" + "0" * 32 + "." + "A" * 43)
        codes = [c.get(BASE, headers=wrong).status_code for _ in range(7)]
        assert codes == [401] * 5 + [429] * 2
        # Each refusal leaves a line in the application log, with the address and without the token.
        logged = [line for line in capsys.readouterr().out.splitlines() if "token refused" in line]
        assert len(logged) == 7 and all("A" * 43 not in line for line in logged)
        # A valid token from the same address is not caught by it.
        assert c.get(BASE, headers=bearer(token)).status_code == 200


def test_molehash_client_never_puts_the_token_in_an_error(served, world):
    hm_module = load_molehash_client()
    _, token = issue(world)
    # A trailing newline (a secret read from a file) is accepted and stripped.
    hm = hm_module.HappyMiningClient(served.url, token + "\n", retries=0)
    assert hm.describe()["mode"] == "demo"
    for bad in (token + "\nX", token[:-1], "Bearer " + token, ""):
        with pytest.raises(ValueError) as refused:
            hm_module.HappyMiningClient(served.url, bad)
        assert token.split(".")[1] not in str(refused.value)
    with pytest.raises(ValueError, match="user name"):
        hm_module.HappyMiningClient("https://user:pw@api.happymining.fr", token)
    # An id cannot steer the request to another path.
    with pytest.raises(hm_module.HappyMiningError) as outside:
        hm.machine("../../../v1/api-clients?x=")
    assert outside.value.status in (404, 422)
