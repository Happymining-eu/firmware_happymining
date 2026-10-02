"""Pairing codes, device credentials and telemetry ingestion over HTTP."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from helpers import BASE_URL, World, heartbeat, live_settings, make_settings, sample
from sqlalchemy import select, text

from happymining.logging_setup import JsonFormatter
from happymining.main import create_app
from happymining.models import (
    AuditLog,
    Device,
    DeviceCredential,
    EnrollmentRequest,
    Machine,
    TelemetrySample,
)
from happymining.security import parse_pairing_code, redact, redact_text

FP = "sha256:" + "ab" * 32


def enroll(client, code, **extra):
    body = {
        "pairing_code": code,
        "hostname": "gpu-01",
        "machine_fingerprint": FP,
        "agent_version": "0.1.0",
        "os": {"id": "ubuntu", "version_id": "24.04", "kernel": "6.8", "arch": "amd64"},
        **extra,
    }
    return client.post("/api/v1/devices/enroll", json=body)


# --- pairing ---------------------------------------------------------------


def test_pairing_happy_path_binds_device_to_the_requests_owner_and_machine(client, world):
    owner = world.owner()
    issued = world.pairing(owner, "rack-1")
    r = enroll(client, issued.code)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["machine_id"] == str(issued.machine.id)
    token = body["credential"]["token"]
    assert token.startswith("hmd_") and body["credential"]["expires_at"] is None

    world.session.expire_all()
    machine = world.session.get(Machine, issued.machine.id)
    assert machine.owner_id == owner.id and machine.status == "active"
    me = client.get("/api/v1/device/self", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200 and me.json()["machine_id"] == str(machine.id)


def test_code_is_accepted_in_any_case_and_spacing(client, world):
    issued = world.pairing(world.owner())
    sloppy = issued.code.lower().replace("-", " ")
    assert enroll(client, sloppy).status_code == 201


def test_only_a_keyed_hash_of_the_code_is_stored(world):
    issued = world.pairing(world.owner())
    parsed = parse_pairing_code(issued.code)
    row = world.session.execute(select(EnrollmentRequest)).scalar_one()
    assert parsed.secret not in row.code_hash and len(row.code_hash) == 64
    dump = world.session.execute(text("SELECT row_to_json(e)::text FROM enrollment_requests e")).scalar_one()
    assert parsed.secret not in dump
    audit_dump = json.dumps([a.details for a in world.session.execute(select(AuditLog)).scalars()])
    assert parsed.secret not in audit_dump and issued.code not in audit_dump


def test_replayed_code_is_refused(client, world):
    issued = world.pairing(world.owner())
    assert enroll(client, issued.code).status_code == 201
    again = enroll(client, issued.code)
    assert again.status_code == 401 and again.json()["error"]["code"] == "pairing_failed"
    assert world.session.execute(select(Device)).scalars().all().__len__() == 1


def test_expired_code_is_refused(client, world):
    issued = world.pairing(world.owner())
    world.session.execute(text("UPDATE enrollment_requests SET expires_at = now() - interval '1 second'"))
    world.commit()
    r = enroll(client, issued.code)
    assert r.status_code == 401 and r.json()["error"]["code"] == "pairing_failed"
    world.session.expire_all()
    assert world.session.execute(select(EnrollmentRequest.status)).scalar_one() == "expired"


def test_wrong_codes_are_counted_then_the_request_locks(client, world, settings):
    issued = world.pairing(world.owner())
    parsed = parse_pairing_code(issued.code)
    wrong = f"HM-{parsed.locator}-0000-0000-0000-0000"
    for attempt in range(1, settings.pairing_max_attempts + 1):
        r = enroll(client, wrong)
        assert r.status_code == 401
        world.session.expire_all()
        row = world.session.execute(select(EnrollmentRequest)).scalar_one()
        assert row.failed_attempts == attempt
    assert row.status == "locked"
    # The right code no longer works once locked.
    assert enroll(client, issued.code).status_code == 401


def test_every_pairing_failure_looks_the_same(client, world):
    issued = world.pairing(world.owner())
    parsed = parse_pairing_code(issued.code)
    responses = [
        enroll(client, "HM-ZZZZZZ-0000-0000-0000-0000"),  # unknown locator
        enroll(client, f"HM-{parsed.locator}-0000-0000-0000-0000"),  # wrong secret
        enroll(client, "not-a-code"),  # malformed
    ]
    bodies = [{k: v for k, v in r.json()["error"].items() if k != "request_id"} for r in responses]
    assert {r.status_code for r in responses} == {401}
    assert bodies[0] == bodies[1] == bodies[2] == {"code": "pairing_failed", "message": "Pairing failed."}


def test_device_cannot_choose_its_owner_or_machine(client, world):
    owner, other = world.owner("real"), world.owner("other")
    issued = world.pairing(owner)
    for extra in ({"owner_id": str(other.id)}, {"machine_id": "00000000-0000-0000-0000-000000000001"}):
        r = enroll(client, issued.code, **extra)
        assert r.status_code == 422  # unknown fields are rejected outright
    r = enroll(client, issued.code)
    assert world.session.get(Machine, r.json()["machine_id"]).owner_id == owner.id


def test_pairing_is_rate_limited(world):
    limited = create_app(make_settings(pairing_rate_limit_per_minute=3))
    with TestClient(limited, base_url=BASE_URL) as c:
        codes = [enroll(c, "HM-ZZZZZZ-0000-0000-0000-0000").status_code for _ in range(6)]
    assert codes[:3] == [401, 401, 401] and set(codes[3:]) == {429}


def test_new_code_cancels_the_previous_one_for_the_same_machine(client, world, settings):
    from helpers import SYSTEM

    from happymining.services import pairing as pairing_service

    owner = world.owner()
    first = world.pairing(owner)
    admin = world.user("admin")
    second = pairing_service.create_enrollment(
        world.session,
        settings,
        SYSTEM,
        owner_id=owner.id,
        machine_label="",
        machine_id=first.machine.id,
        created_by=admin.id,
    )
    world.commit()
    assert enroll(client, first.code).status_code == 401
    assert enroll(client, second.code).status_code == 201


# --- credentials -----------------------------------------------------------


def test_revoked_credential_is_refused(client, world):
    owner = world.owner()
    machine, token = world.paired_machine(owner)
    admin = world.user("admin")
    assert heartbeat(client, token, [sample(1)]).status_code == 200
    r = client.post(
        f"/api/v1/devices/{machine.device.id}/revoke", headers=world.auth(admin), json={"reason": "lost"}
    )
    assert r.status_code == 200
    r = heartbeat(client, token, [sample(2)])
    assert r.status_code == 401 and r.json()["error"]["code"] == "device_unauthorized"


def test_malformed_and_unknown_tokens_get_the_same_answer(client, world):
    machine, token = world.paired_machine(world.owner())
    cred_id, secret = token.removeprefix("hmd_").split(".")
    forged = [
        "",
        "hmd_garbage",
        f"hmd_{'0' * 32}.{secret}",  # unknown credential id
        f"hmd_{cred_id}.{'A' * 43}",  # right id, wrong secret
        token[:-1] + ("A" if token[-1] != "A" else "B"),
    ]
    for bad in forged:
        r = client.get("/api/v1/device/self", headers={"Authorization": f"Bearer {bad}"})
        assert r.status_code == 401 and r.json()["error"]["code"] == "device_unauthorized", bad


def test_only_a_hash_of_the_device_secret_is_stored(world):
    machine, token = world.paired_machine(world.owner())
    secret = token.split(".")[1]
    row = world.session.execute(select(DeviceCredential)).scalar_one()
    assert secret not in row.secret_hash
    assert (
        secret
        not in world.session.execute(
            text("SELECT row_to_json(c)::text FROM device_credentials c")
        ).scalar_one()
    )


def test_rotation_keeps_the_old_credential_until_the_new_one_is_used(client, world):
    machine, old = world.paired_machine(world.owner())
    r = client.post("/api/v1/device/credential/rotate", headers={"Authorization": f"Bearer {old}"})
    assert r.status_code == 200
    new = r.json()["credential"]["token"]
    assert new != old
    # A crash before the new credential is written must not lock the device out.
    assert client.get("/api/v1/device/self", headers={"Authorization": f"Bearer {old}"}).status_code == 200
    # First use of the new credential retires the old one.
    assert client.get("/api/v1/device/self", headers={"Authorization": f"Bearer {new}"}).status_code == 200
    assert client.get("/api/v1/device/self", headers={"Authorization": f"Bearer {old}"}).status_code == 401
    # A superseded credential cannot itself rotate.
    statuses = sorted(world.session.execute(select(DeviceCredential.status)).scalars())
    assert statuses == ["active", "revoked"]


def test_superseded_credential_expires_after_the_grace_period(client, world):
    machine, old = world.paired_machine(world.owner())
    client.post("/api/v1/device/credential/rotate", headers={"Authorization": f"Bearer {old}"})
    world.session.execute(
        text(
            "UPDATE device_credentials SET superseded_at = now() - interval '25 hours' "
            "WHERE status = 'superseded'"
        )
    )
    world.commit()
    assert client.get("/api/v1/device/self", headers={"Authorization": f"Bearer {old}"}).status_code == 401


# --- telemetry -------------------------------------------------------------


def test_duplicate_telemetry_is_stored_once(client, world):
    machine, token = world.paired_machine(world.owner())
    first = heartbeat(client, token, [sample(1), sample(2), sample(3)]).json()
    assert (first["accepted"], first["duplicates"], first["highest_seq"]) == (3, 0, 3)
    # The agent resends after a lost response, with one new sample.
    second = heartbeat(client, token, [sample(1), sample(2), sample(3), sample(4)]).json()
    assert (second["accepted"], second["duplicates"], second["highest_seq"]) == (1, 3, 4)
    rows = world.session.execute(select(TelemetrySample.seq).order_by(TelemetrySample.seq)).scalars().all()
    assert rows == [1, 2, 3, 4]


def test_samples_with_impossible_timestamps_are_rejected_not_stored(client, world):
    machine, token = world.paired_machine(world.owner())
    now = datetime.now(UTC)
    r = heartbeat(
        client,
        token,
        [
            sample(1, at=now + timedelta(hours=1)),
            sample(2, at=now - timedelta(days=30)),
            sample(3, at=now),
        ],
    ).json()
    assert (r["accepted"], r["rejected"]) == (1, 2)


def test_malformed_telemetry_is_refused(client, world):
    machine, token = world.paired_machine(world.owner())
    h = {"Authorization": f"Bearer {token}"}
    base = {"sent_at": datetime.now(UTC).isoformat(), "boot_id": "b", "agent_version": "0.1.0"}
    bad_bodies = [
        {**base},  # no samples
        {**base, "samples": []},
        {**base, "samples": [sample(i) for i in range(101)]},  # too many
        {**base, "samples": [{**sample(1), "seq": -1}]},
        {**base, "samples": [{**sample(1), "seq": "one"}]},
        {**base, "samples": [{**sample(1), "collected_at": "yesterday"}]},
        {**base, "samples": [{**sample(1), "collected_at": "2026-01-01T00:00:00"}]},  # no UTC offset
        {**base, "samples": [{**sample(1), "gpus": [{"index": 0}] * 33}]},
        {**base, "samples": [{**sample(1), "services": {"docker": "exploded"}}]},
        {**base, "samples": [{**sample(1), "gpus": [{"name": "x" * 500}]}]},
    ]
    for body in bad_bodies:
        r = client.post("/api/v1/device/heartbeat", headers=h, json=body)
        assert r.status_code == 422, body
        assert r.json()["error"]["code"] == "invalid_request"
    r = client.post(
        "/api/v1/device/heartbeat", headers={**h, "Content-Type": "application/json"}, content=b"{not json"
    )
    assert r.status_code == 422
    assert world.session.execute(select(TelemetrySample)).first() is None


def test_oversized_body_is_refused(client, world):
    machine, token = world.paired_machine(world.owner())
    big = json.dumps({"samples": [], "pad": "x" * (300 * 1024)}).encode()
    r = client.post(
        "/api/v1/device/heartbeat",
        content=big,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"


def test_unknown_fields_are_not_stored(client, world):
    """The server keeps only the documented telemetry fields: nothing about renter workloads."""
    machine, token = world.paired_machine(world.owner())
    leaky = sample(
        1, processes=[{"cmdline": "python train.py --secret"}], containers=["C.123"], env={"HF_TOKEN": "hf_x"}
    )
    leaky["gpus"][0]["process_names"] = ["renter-job"]
    assert heartbeat(client, token, [leaky]).json()["accepted"] == 1
    stored = json.dumps(world.session.execute(select(TelemetrySample.payload)).scalar_one())
    for forbidden in ("processes", "cmdline", "containers", "HF_TOKEN", "process_names", "renter-job"):
        assert forbidden not in stored


def test_device_writes_only_to_its_own_machine(client, world):
    """A device cannot redirect telemetry to another machine by claiming its id."""
    owner_a, owner_b = world.owner("A"), world.owner("B")
    machine_a, token_a = world.paired_machine(owner_a, "a")
    machine_b, _ = world.paired_machine(owner_b, "b")
    spoof = sample(
        1, machine_id=str(machine_b.id), device_id=str(machine_b.device.id), owner_id=str(owner_b.id)
    )
    assert heartbeat(client, token_a, [spoof]).json()["accepted"] == 1
    rows = world.session.execute(select(TelemetrySample.machine_id)).scalars().all()
    assert rows == [machine_a.id]


def test_synthetic_telemetry_is_refused_in_live_mode():
    live = live_settings()
    world = World(live)
    try:
        machine, token = world.paired_machine(world.owner())
        assert not machine.is_synthetic
        with TestClient(create_app(live), base_url="https://api.example.test") as c:
            refused = heartbeat(c, token, [sample(1, synthetic=True)])
            accepted = heartbeat(c, token, [sample(2, synthetic=False)])
        assert refused.status_code == 400 and "LIVE" in refused.json()["error"]["message"]
        assert accepted.status_code == 200 and accepted.json()["accepted"] == 1
        seqs = world.session.execute(select(TelemetrySample.seq)).scalars().all()
        assert seqs == [2]
    finally:
        world.close()


def test_real_telemetry_is_refused_for_a_synthetic_machine(client, world):
    machine, token = world.paired_machine(world.owner())
    r = heartbeat(client, token, [sample(1, synthetic=False)])
    assert r.status_code == 400 and "synthetic" in r.json()["error"]["message"]


def test_heartbeat_updates_last_seen_and_inventory(client, world):
    machine, token = world.paired_machine(world.owner())
    heartbeat(client, token, [sample(1)])
    world.session.expire_all()
    machine = world.session.get(Machine, machine.id)
    assert machine.device.last_seen_at is not None and machine.device.last_seq == 1
    assert machine.hardware["gpus"][0]["name"] == "RTX 4090"


# --- redaction -------------------------------------------------------------


def test_secrets_are_redacted_from_logs(world):
    machine, token = world.paired_machine(world.owner())
    code = "HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XA"
    record = logging.LogRecord(
        "t",
        logging.INFO,
        __file__,
        1,
        f"device said Authorization: Bearer {token} and code {code}",
        None,
        None,
    )
    record.headers = {"authorization": f"Bearer {token}"}
    record.body = {"pairing_code": code, "nested": {"password": "hunter2hunter2", "note": f"token {token}"}}
    line = JsonFormatter().format(record)
    assert token not in line and token.split(".")[1] not in line
    assert code not in line and "hunter2hunter2" not in line
    assert "[REDACTED]" in line


def test_redaction_helpers():
    assert redact({"api_key": "abc", "ok": 1, "deep": [{"secret": "s"}]}) == {
        "api_key": "[REDACTED]",
        "ok": 1,
        "deep": [{"secret": "[REDACTED]"}],
    }
    assert "sk_live_123456" not in redact_text("api_key=sk_live_123456 trailing")
    assert "abcdefghijklmnop" not in redact_text("Authorization: Bearer abcdefghijklmnop")


def test_validation_errors_do_not_echo_submitted_values(client):
    r = client.post("/api/v1/auth/login", json={"email": "a@b.c", "password": ["super-secret-value-123"]})
    assert r.status_code == 422 and "super-secret-value-123" not in r.text


def test_audit_trail_never_contains_device_tokens(client, world):
    machine, token = world.paired_machine(world.owner())
    client.post("/api/v1/device/credential/rotate", headers={"Authorization": f"Bearer {token}"})
    dump = json.dumps([a.details for a in world.session.execute(select(AuditLog)).scalars()])
    assert "hmd_" not in dump and token.split(".")[1] not in dump
