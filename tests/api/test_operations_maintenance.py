"""Typed operations and the rental-protection gate."""

from __future__ import annotations

from datetime import timedelta

import pytest
from helpers import IDLE_UNLISTED, SYSTEM, dataset, heartbeat, make_settings, sample
from sqlalchemy import select, text

from happymining.errors import Conflict, InvalidRequest, NotImplementedFeature
from happymining.models import AuditLog, Operation
from happymining.services import machines as machine_service
from happymining.services import operations, provider_sync
from happymining.services.maintenance import DISRUPTIVE_TYPES, evaluate

RENTAL_CASES = {
    "active contract": {
        "state": "active_contracts",
        "listed": False,
        "active_contracts": 1,
        "stopped_instances": 0,
        "stored_data": True,
    },
    "stopped instance": {
        "state": "stopped_instances",
        "listed": False,
        "active_contracts": 0,
        "stopped_instances": 1,
        "stored_data": True,
    },
    "stored customer data": {
        "state": "stored_data",
        "listed": False,
        "active_contracts": 0,
        "stopped_instances": 0,
        "stored_data": True,
    },
    "state unknown": {
        "state": "unknown",
        "listed": False,
        "active_contracts": None,
        "stopped_instances": None,
        "stored_data": None,
    },
    "still listed": {
        "state": "idle",
        "listed": True,
        "active_contracts": 0,
        "stopped_instances": 0,
        "stored_data": False,
    },
    "listing unknown": {
        "state": "idle",
        "listed": None,
        "active_contracts": 0,
        "stopped_instances": 0,
        "stored_data": False,
    },
    "idle but counters missing": {
        "state": "idle",
        "listed": False,
        "active_contracts": None,
        "stopped_instances": 0,
        "stored_data": False,
    },
}


def fleet(world, rental=None, bind=True):
    owner = world.owner()
    provider = world.provider(dataset({"101": {"rental": rental} if rental else dict(IDLE_UNLISTED)}, {}))
    account = world.account(provider)
    machine, token = world.paired_machine(owner)
    if bind:
        world.bind(account, "101", machine)
    world.session.refresh(machine)
    return machine, token, provider


ENABLED = dict(disruptive_operations_enabled=True)


def request(world, settings, provider, machine, op_type, params=None):
    op = operations.request_operation(
        world.session,
        settings,
        SYSTEM,
        provider,
        machine=machine,
        op_type=op_type,
        params=params or {},
        requested_by=None,
    )
    world.commit()
    return op


# --- the operation surface --------------------------------------------------


def test_there_is_no_shell_only_a_fixed_typed_allowlist(world):
    machine, token, provider = fleet(world)
    assert set(operations.OPERATION_TYPES) == {
        "refresh_inventory",
        "collect_diagnostics",
        "run_preflight",
        "rotate_credential",
        "restart_vast_daemon",
        "reboot",
        "run_benchmark",
        "apply_hardware_profile",
    }
    for bad_type in ("shell", "exec", "run_command", "bash", "", "reboot; rm -rf /"):
        with pytest.raises(InvalidRequest):
            request(world, world.settings, provider, machine, bad_type, {"command": "id"})
        world.session.rollback()


@pytest.mark.parametrize(
    ("op_type", "params"),
    [
        ("refresh_inventory", {"command": "id"}),
        ("collect_diagnostics", {}),
        ("collect_diagnostics", {"sections": ["services", "/etc/shadow"]}),
        ("collect_diagnostics", {"sections": ["gpu"], "extra": 1}),
        ("reboot", {}),
        ("reboot", {"delay_s": 5}),
        ("reboot", {"delay_s": "60"}),
        ("reboot", {"delay_s": True}),
        ("reboot", {"delay_s": 60, "force": True}),
    ],
)
def test_parameters_are_validated_strictly(world, op_type, params):
    machine, token, provider = fleet(world)
    settings = make_settings(**ENABLED)
    with pytest.raises(InvalidRequest):
        request(world, settings, provider, machine, op_type, params)


def test_unimplemented_types_fail_explicitly(world):
    machine, token, provider = fleet(world)
    settings = make_settings(**ENABLED)
    for op_type, params in (
        ("run_benchmark", {"duration_s": 60}),
        ("apply_hardware_profile", {"profile_id": "p"}),
    ):
        with pytest.raises(NotImplementedFeature, match="not implemented"):
            request(world, settings, provider, machine, op_type, params)
        world.session.rollback()
    assert world.session.execute(select(Operation)).first() is None


def test_monitoring_operation_lifecycle(client, world):
    machine, token, provider = fleet(world)
    op = request(
        world, world.settings, provider, machine, "collect_diagnostics", {"sections": ["gpu", "disk"]}
    )
    assert op.status == "pending"

    delivered = heartbeat(client, token, [sample(1)]).json()["operations"]
    assert [d["id"] for d in delivered] == [str(op.id)]
    assert set(delivered[0]) == {"id", "type", "params", "issued_at", "expires_at", "nonce"}
    h = {"Authorization": f"Bearer {token}"}
    ack = client.post(
        f"/api/v1/device/operations/{op.id}/ack",
        headers=h,
        json={
            "status": "succeeded",
            "nonce": delivered[0]["nonce"],
            "detail": "ok",
            "result": {"gpu": "fine", "token": "hmd_" + "a" * 32 + "." + "b" * 43},
        },
    )
    assert ack.status_code == 200 and ack.json() == {"status": "succeeded"}
    world.session.expire_all()
    stored = world.session.get(Operation, op.id)
    assert stored.status == "succeeded" and stored.result["token"] == "[REDACTED]"
    # A finished operation is not delivered again.
    assert heartbeat(client, token, [sample(2)]).json()["operations"] == []


# --- replay, nonce, expiry --------------------------------------------------


def test_acknowledgement_replay_is_refused(client, world):
    machine, token, provider = fleet(world)
    op = request(world, world.settings, provider, machine, "refresh_inventory")
    nonce = heartbeat(client, token, [sample(1)]).json()["operations"][0]["nonce"]
    h = {"Authorization": f"Bearer {token}"}
    url = f"/api/v1/device/operations/{op.id}/ack"
    assert client.post(url, headers=h, json={"status": "succeeded", "nonce": nonce}).status_code == 200
    for status in ("succeeded", "failed", "accepted"):
        r = client.post(url, headers=h, json={"status": status, "nonce": nonce})
        assert r.status_code == 409 and r.json()["error"]["code"] == "conflict"
    world.session.expire_all()
    assert world.session.get(Operation, op.id).status == "succeeded"


def test_wrong_nonce_is_refused(client, world):
    machine, token, provider = fleet(world)
    op = request(world, world.settings, provider, machine, "refresh_inventory")
    heartbeat(client, token, [sample(1)])
    r = client.post(
        f"/api/v1/device/operations/{op.id}/ack",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "succeeded", "nonce": "guessed-nonce"},
    )
    assert r.status_code == 403
    world.session.expire_all()
    assert world.session.get(Operation, op.id).status == "delivered"


def test_expired_operation_is_not_delivered_and_cannot_be_acknowledged(client, world):
    machine, token, provider = fleet(world)
    op = request(world, world.settings, provider, machine, "refresh_inventory")
    nonce = op.nonce
    world.session.execute(text("UPDATE operations SET expires_at = now() - interval '1 second'"))
    world.commit()
    assert heartbeat(client, token, [sample(1)]).json()["operations"] == []
    r = client.post(
        f"/api/v1/device/operations/{op.id}/ack",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "succeeded", "nonce": nonce},
    )
    assert r.status_code == 410 and r.json()["error"]["code"] == "expired"


def test_operation_that_was_never_delivered_cannot_be_acknowledged(client, world):
    machine, token, provider = fleet(world)
    op = request(world, world.settings, provider, machine, "refresh_inventory")
    r = client.post(
        f"/api/v1/device/operations/{op.id}/ack",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "succeeded", "nonce": op.nonce},
    )
    assert r.status_code == 409


def test_operations_need_a_paired_device(world):
    owner = world.owner()
    issued = world.pairing(owner)  # machine exists, no device yet
    with pytest.raises(Conflict):
        request(world, world.settings, None, issued.machine, "refresh_inventory")


# --- the rental-protection gate ----------------------------------------------


def test_disruptive_operations_are_disabled_by_default(world):
    machine, token, provider = fleet(world)  # idle and unlisted: as safe as it gets
    assert world.settings.disruptive_operations_enabled is False
    for op_type in ("restart_vast_daemon", "reboot"):
        op = request(
            world, world.settings, provider, machine, op_type, {"delay_s": 60} if op_type == "reboot" else {}
        )
        assert op.status == "blocked" and "disabled" in op.detail


@pytest.mark.parametrize("case", sorted(RENTAL_CASES))
def test_disruptive_operation_is_denied_unless_provably_idle(world, case):
    machine, token, provider = fleet(world, rental=RENTAL_CASES[case])
    settings = make_settings(**ENABLED)
    decision = evaluate(world.session, settings, provider, machine, "reboot")
    assert decision.allowed is False, case
    op = request(world, settings, provider, machine, "reboot", {"delay_s": 60})
    assert op.status == "blocked" and op.detail.startswith("Blocked; requires operator handling")
    audit = (
        world.session.execute(select(AuditLog).where(AuditLog.action == "operation.blocked")).scalars().all()
    )
    assert len(audit) == 1 and audit[0].details["reasons"]


def test_zero_gpu_utilisation_is_not_proof_of_idleness(client, world):
    """The gate never looks at telemetry: an idle GPU can still be under contract."""
    machine, token, provider = fleet(world, rental=RENTAL_CASES["active contract"])
    idle_sample = sample(1)
    assert idle_sample["gpus"][0]["util_pct"] == 0
    heartbeat(client, token, [idle_sample])
    settings = make_settings(**ENABLED)
    world.session.refresh(machine)
    decision = evaluate(world.session, settings, provider, machine, "restart_vast_daemon")
    assert decision.allowed is False
    assert "active rental contracts" in " ".join(decision.reasons)
    assert "util" not in str(decision.checks).lower()


def test_unbound_machine_and_provider_outage_block(world):
    settings = make_settings(**ENABLED)
    machine, token, provider = fleet(world, bind=False)
    assert evaluate(world.session, settings, provider, machine, "reboot").allowed is False

    machine2, token2, provider2 = fleet(world)
    provider2.outage = True
    decision = evaluate(world.session, settings, provider2, machine2, "reboot")
    assert decision.allowed is False and decision.checks["provider_error"] == "provider_unavailable"
    assert evaluate(world.session, settings, None, machine2, "reboot").allowed is False


def test_allowed_only_when_unlisted_idle_and_enabled_then_rechecked_at_delivery(client, world):
    machine, token, provider = fleet(world)  # idle, unlisted, counters zero
    settings = make_settings(**ENABLED)
    assert evaluate(world.session, settings, provider, machine, "reboot").allowed is True
    op = request(world, settings, provider, machine, "reboot", {"delay_s": 120})
    assert op.status == "pending"

    # A rental starts between the request and the next heartbeat.
    provider.dataset["machines"][0]["rental"] = RENTAL_CASES["active contract"]
    from fastapi.testclient import TestClient
    from helpers import BASE_URL

    from happymining.main import create_app

    with TestClient(create_app(settings), base_url=BASE_URL) as c:
        delivered = heartbeat(c, token, [sample(1)]).json()["operations"]
    assert delivered == []  # never left the server
    world.session.expire_all()
    stored = world.session.get(Operation, op.id)
    assert stored.status == "blocked" and "recheck" in stored.safety
    assert stored.safety["recheck"]["allowed"] is False


def test_safe_operation_is_delivered_when_gate_passes(world):
    machine, token, provider = fleet(world)
    settings = make_settings(**ENABLED)
    op = request(world, settings, provider, machine, "restart_vast_daemon")
    pending = operations.pending_for_device(world.session, settings, provider, machine.device, machine)
    world.commit()
    assert [p.id for p in pending] == [op.id] and pending[0].status == "delivered"
    assert pending[0].safety["recheck"]["allowed"] is True


def test_blocked_request_is_an_error_over_http_not_a_quiet_success(client, world):
    machine, token, provider = fleet(world, rental=RENTAL_CASES["active contract"])
    admin = world.user("admin")
    r = client.post(
        f"/api/v1/machines/{machine.id}/operations",
        headers=world.auth(admin),
        json={"type": "reboot", "params": {"delay_s": 60}},
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "maintenance_blocked"
    # The refusal is on record.
    stored = world.session.execute(select(Operation)).scalar_one()
    assert stored.status == "blocked"


def test_every_disruptive_type_goes_through_the_gate():
    assert {"restart_vast_daemon", "reboot", "run_benchmark", "apply_hardware_profile"} == DISRUPTIVE_TYPES
    assert not (
        DISRUPTIVE_TYPES & {"refresh_inventory", "collect_diagnostics", "run_preflight", "rotate_credential"}
    )


def test_unlisting_alone_does_not_make_maintenance_safe(world):
    """Unlisting stops new rentals. Existing ones keep every right they had."""
    rental = {**RENTAL_CASES["active contract"], "listed": True}
    machine, token, provider = fleet(world, rental=rental)
    provider.mutations_enabled = True
    settings = make_settings(**ENABLED)
    assert provider.unlist_machine("101").ok
    decision = evaluate(world.session, settings, provider, machine, "reboot")
    assert decision.checks["listed"] is False and decision.allowed is False
    assert "active rental contracts" in " ".join(decision.reasons)


# --- ownership and binding are protected too ---------------------------------


def test_binding_requires_a_provider_listed_machine_and_is_one_to_one(world):
    owner = world.owner()
    provider = world.provider(dataset({"101": {}, "102": {}}, {}))
    account = world.account(provider)
    m1, _ = world.paired_machine(owner, "one")
    m2, _ = world.paired_machine(owner, "two")
    pm = world.bind(account, "101", m1)
    admin = world.user("admin")
    # The same provider machine cannot be bound twice, nor one machine to two provider machines.
    with pytest.raises(Conflict):
        provider_sync.bind_machine(
            world.session,
            SYSTEM,
            provider_machine_id=pm.id,
            machine_id=m2.id,
            bound_from=world.today,
            user_id=admin.id,
        )
    world.session.rollback()
    from happymining.models import ProviderMachine

    other = world.session.execute(
        select(ProviderMachine).where(ProviderMachine.external_id == "102")
    ).scalar_one()
    with pytest.raises(Conflict):
        provider_sync.bind_machine(
            world.session,
            SYSTEM,
            provider_machine_id=other.id,
            machine_id=m1.id,
            bound_from=world.today,
            user_id=admin.id,
        )
    world.session.rollback()
    # A machine the provider stopped listing cannot be bound.
    provider.dataset["machines"] = [m for m in provider.dataset["machines"] if m["id"] != 102]
    provider_sync.sync_machines(world.session, provider, account)
    world.commit()
    with pytest.raises(Conflict, match="no longer lists"):
        provider_sync.bind_machine(
            world.session,
            SYSTEM,
            provider_machine_id=other.id,
            machine_id=m2.id,
            bound_from=world.today,
            user_id=admin.id,
        )


def test_agent_hint_is_evidence_only_never_a_binding(client, world):
    import hashlib

    owner = world.owner()
    provider = world.provider(dataset({"101": {}}, {}))
    account = world.account(provider)
    machine, token = world.paired_machine(owner)
    hint = "sha256:" + hashlib.sha256(b"101").hexdigest()
    claim = sample(1)
    claim["vast"] = {"daemon_installed": True, "machine_id_hint": hint}
    assert heartbeat(client, token, [claim]).status_code == 200
    world.session.expire_all()
    from happymining.models import Machine, ProviderBindingEvent

    machine = world.session.get(Machine, machine.id)
    assert machine.provider_machine is None  # the claim bound nothing
    world.bind(account, "101", machine)
    event = world.session.execute(select(ProviderBindingEvent)).scalar_one()
    assert event.evidence["agent_hint_matches"] is True and event.evidence["provider_listed_machine"] is True


def test_ownership_cannot_change_while_attribution_is_ambiguous(world):
    from test_earnings_ledger import run_import

    world.fee()
    owner, other = world.owner("A"), world.owner("B")
    provider = world.provider(dataset({"101": dict(IDLE_UNLISTED)}, {"101": {1: "10"}}))
    account = world.account(provider)
    machine, _ = world.paired_machine(owner)
    world.bind(account, "101", machine)
    run_import(world, provider, account, 1, 1)
    admin = world.user("admin")
    # Reported but unreconciled earnings: refuse.
    with pytest.raises(Conflict, match="not yet reconciled"):
        machine_service.transfer_ownership(
            world.session,
            SYSTEM,
            machine_id=machine.id,
            new_owner_id=other.id,
            reason="sale",
            user_id=admin.id,
        )
    world.session.rollback()
    # Active rental: refuse.
    provider.dataset["machines"][0]["rental"] = RENTAL_CASES["active contract"]
    provider_sync.sync_machines(world.session, provider, account)
    world.commit()
    with pytest.raises(Conflict, match="not confirmed idle"):
        machine_service.transfer_ownership(
            world.session,
            SYSTEM,
            machine_id=machine.id,
            new_owner_id=other.id,
            reason="sale",
            user_id=admin.id,
        )


def test_ownership_history_is_preserved_and_old_days_keep_their_owner(world):
    from happymining.models import MachineOwnership
    from happymining.services.earnings import resolve_mapping

    world.fee()
    owner, other = world.owner("A"), world.owner("B")
    provider = world.provider(dataset({"101": dict(IDLE_UNLISTED)}, {}))
    account = world.account(provider)
    machine, _ = world.paired_machine(owner)
    world.bind(account, "101", machine)
    admin = world.user("admin")
    machine_service.transfer_ownership(
        world.session, SYSTEM, machine_id=machine.id, new_owner_id=other.id, reason="sold", user_id=admin.id
    )
    world.commit()
    rows = (
        world.session.execute(select(MachineOwnership).order_by(MachineOwnership.valid_from)).scalars().all()
    )
    assert [(r.owner_id, r.valid_to is None) for r in rows] == [(owner.id, False), (other.id, True)]
    assert resolve_mapping(world.session, account, "101", world.day(3)).owner_id == owner.id
    # The transfer takes effect tomorrow (UTC): today was earned under the previous owner.
    assert resolve_mapping(world.session, account, "101", world.today).owner_id == owner.id
    tomorrow = world.today + timedelta(days=1)
    assert resolve_mapping(world.session, account, "101", tomorrow).owner_id == other.id
    # Overlapping ownership rows are impossible at the database level.
    from sqlalchemy.exc import IntegrityError

    world.session.add(
        MachineOwnership(
            machine_id=machine.id,
            owner_id=owner.id,
            valid_from=world.day(10),
            valid_to=world.day(5),
            reason="overlap",
        )
    )
    with pytest.raises(IntegrityError):
        world.session.flush()
