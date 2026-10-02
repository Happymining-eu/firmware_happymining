"""The device side of the appliance (docs/appliance.md, section 6).

What an agent sends about its appliance state and what it gets back: nothing
for an agent that does not know about it, the desired-state document with its
sealed secrets for one that does, and only when it does not have it yet. What
a machine reports is cleaned on arrival and never trusted.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from helpers import heartbeat, sample
from sqlalchemy import select
from test_appliance import (
    FIXTURE_CATALOG,
    NAS_BACKUP,
    NAS_DOCS,
    NAS_PUBLIC,
    NIGHTLY,
    SEAL_KEY,
    VECTORIZER,
    appliance_client,
    audit_rows,
    bearer,
    beat,
    report,
    reporting_machine,
    seal,
    stored,
    url,
)
from test_sealing import machine_private_key, open_sealed

from happymining import sealing
from happymining.main import DEVICE_BODY_LIMIT
from happymining.models import MachineAppliance
from happymining.services import appliance as appliance_service
from happymining.services import catalog as catalog_service

AGENT_0_1_0_KEYS = {
    "accepted",
    "duplicates",
    "rejected",
    "highest_seq",
    "server_time",
    "next_interval_s",
    "operations",
}


@pytest.fixture
def api() -> Iterator[TestClient]:
    with appliance_client() as client:
        yield client


def configured(world, client, owner=None):
    """A reporting machine with a small configuration at revision 2. Returns (machine, token, headers)."""
    owner = owner or world.owner()
    machine, token = reporting_machine(world, client, owner)
    h = world.auth(world.user("owner", owner))
    body = {**NAS_DOCS, "sealed_secret": seal("nas.docs.password", b"s3cr3t-nas-pass")}
    assert client.put(url(machine, "/nas/docs"), headers=h, json=body).status_code == 200
    assert client.put(url(machine, "/schedules/nightly-sync"), headers=h, json=NIGHTLY).status_code == 200
    return machine, token, h


# --- an agent that does not know about the appliance ------------------------


def test_agent_0_1_0_sees_no_change(api, world):
    """No ``appliance`` in the request: the answer has exactly the keys it always had."""
    machine, token = world.paired_machine(world.owner())
    r = heartbeat(api, token, [sample(1)])
    assert r.status_code == 200 and set(r.json()) == AGENT_0_1_0_KEYS
    assert r.json()["accepted"] == 1 and r.json()["operations"] == []
    # Nothing about the appliance is created or stored for it.
    assert world.session.execute(select(MachineAppliance)).first() is None
    assert set(api.get("/api/v1/device/operations", headers=bearer(token)).json()) == {"operations"}


def test_an_old_agent_gets_nothing_even_when_the_machine_is_configured(api, world):
    machine, token, h = configured(world, api)
    before = stored(world, machine)
    reported, reported_at, applied = dict(before.reported), before.reported_at, before.applied_revision
    r = heartbeat(api, token, [sample(900)])
    assert r.status_code == 200 and set(r.json()) == AGENT_0_1_0_KEYS
    assert "appliance" not in r.text and "hmseal1." not in r.text and "nas.lan" not in r.text
    # A heartbeat without the object does not overwrite what was last reported either.
    after = stored(world, machine)
    assert (after.reported, after.reported_at, after.applied_revision) == (reported, reported_at, applied)
    # An explicit null is the same as nothing.
    body = {"sent_at": "2026-10-02T07:45:00Z", "samples": [sample(901)], "appliance": None}
    r = api.post("/api/v1/device/heartbeat", headers=bearer(token), json=body)
    assert r.status_code == 200 and set(r.json()) == AGENT_0_1_0_KEYS


def test_an_appliance_object_that_is_not_an_object_is_refused(api, world):
    machine, token = world.paired_machine(world.owner())
    for bad in ([], "cloud", 12, True):
        body = {"sent_at": "2026-10-02T07:45:00Z", "samples": [sample(1)], "appliance": bad}
        r = api.post("/api/v1/device/heartbeat", headers=bearer(token), json=body)
        assert r.status_code == 422, bad
    assert world.session.execute(select(MachineAppliance)).first() is None


# --- delivery of the document (6.2) ----------------------------------------


def test_nothing_is_sent_before_the_first_cloud_revision(api, world):
    machine, token = world.paired_machine(world.owner())
    r = beat(api, token, report())
    assert r.status_code == 200 and set(r.json()) == AGENT_0_1_0_KEYS  # revision 0: no "appliance" yet
    row = stored(world, machine)
    assert row.revision == 0 and row.seal_public_key == SEAL_KEY and row.reported["control"] == "cloud"
    assert row.reported_at is not None and row.document == appliance_service.default_document()


def test_the_document_is_sent_until_the_machine_has_it(api, world):
    machine, token, h = configured(world, api)
    row = stored(world, machine)
    assert row.revision == 2

    answer = beat(api, token, report(applied_revision=0)).json()
    assert set(answer) == AGENT_0_1_0_KEYS | {"appliance"}
    assert set(answer["appliance"]) == {"revision", "document"} and answer["appliance"]["revision"] == 2
    document = answer["appliance"]["document"]
    # The stored document, its revision and the sealed secrets: exactly section 4.
    assert document == {**row.document, "revision": 2, "secrets": row.secrets}
    assert list(document["secrets"]) == ["nas.docs.password"]
    appliance_service.validate_document(document, catalog_service.load_catalog(FIXTURE_CATALOG))

    # Still behind: sent again. The machine applies idempotently.
    assert "document" in beat(api, token, report(applied_revision=1)).json()["appliance"]
    # Up to date: only the revision.
    assert beat(api, token, report(applied_revision=2)).json()["appliance"] == {"revision": 2}
    assert stored(world, machine).applied_revision == 2
    assert api.get(url(machine), headers=h).json()["in_sync"] is True

    # A change later: the new revision goes out once more.
    assert api.put(url(machine, "/nas/pub"), headers=h, json=NAS_PUBLIC).status_code == 200
    assert api.get(url(machine), headers=h).json()["in_sync"] is False
    answer = beat(api, token, report(applied_revision=2)).json()["appliance"]
    assert answer["revision"] == 3 and [n["id"] for n in answer["document"]["nas"]] == ["docs", "pub"]


@pytest.mark.parametrize("claimed", [99, -1, "2", 2.0, None, True, [2], "missing"])
def test_a_revision_the_cloud_never_issued_is_not_taken_for_up_to_date(api, world, claimed):
    machine, token, _ = configured(world, api)
    said = report(applied_revision=claimed)
    if claimed == "missing":
        del said["applied_revision"]
    answer = beat(api, token, said).json()["appliance"]
    assert answer["revision"] == 2 and "document" in answer, claimed
    # What is kept is a number between 0 and the cloud's revision, whatever was claimed.
    assert stored(world, machine).applied_revision == (2 if claimed == 99 else 0)
    assert stored(world, machine).reported["applied_revision"] == (2 if claimed == 99 else 0)


def test_a_machine_under_local_control_is_never_sent_the_document(api, world):
    machine, token, h = configured(world, api)
    for applied in (0, 1, 2, 99):
        answer = beat(api, token, report(control="local", applied_revision=applied)).json()["appliance"]
        assert answer == {"revision": 2}, applied
    seen = api.get(url(machine), headers=h).json()
    assert seen["control"] == "local" and seen["in_sync"] is False
    # Back under cloud control, it gets it.
    assert "document" in beat(api, token, report(control="cloud")).json()["appliance"]
    # Anything else is "unknown" (the agent says so when it cannot reach its helper,
    # which could not apply the document then): the document waits for "cloud".
    for other in ("unknown", "LOCAL", "root", None):
        assert beat(api, token, report(control=other)).json()["appliance"] == {"revision": 2}, other
        assert stored(world, machine).reported["control"] == "unknown"
    seen = api.get(url(machine), headers=h).json()
    assert seen["control"] == "unknown" and seen["in_sync"] is False
    # The configuration can still be changed meanwhile; only "local" refuses changes.
    assert (
        api.put(url(machine, "/update"), headers=h, json={"channel": "beta", "policy": "manual"}).status_code
        == 200
    )
    assert "document" in beat(api, token, report(control="cloud")).json()["appliance"]


def test_a_device_gets_the_document_of_its_own_machine_only(api, world):
    machine_a, token_a, _ = configured(world, api)
    owner_b = world.owner("B")
    machine_b, token_b = reporting_machine(world, api, owner_b)
    h_b = world.auth(world.user("owner", owner_b))
    assert api.put(url(machine_b, "/nas/bk"), headers=h_b, json=NAS_BACKUP).status_code == 200
    a = beat(api, token_a, report()).json()["appliance"]
    b = beat(api, token_b, report()).json()["appliance"]
    assert [n["id"] for n in a["document"]["nas"]] == ["docs"] and a["revision"] == 2
    assert [n["id"] for n in b["document"]["nas"]] == ["bk"] and b["revision"] == 1
    assert b["document"]["secrets"] == {} and "nas.lan" not in json.dumps(b)
    # There is no field with which a device could name another machine.
    claims = report(machine_id=str(machine_a.id), owner_id="x", device_id="y")
    assert beat(api, token_b, claims).json()["appliance"]["document"]["nas"][0]["id"] == "bk"
    # And no other route hands the document to a device.
    for path in ("/api/v1/device/self", "/api/v1/device/operations", "/api/v1/device/update"):
        r = api.get(path, headers=bearer(token_a))
        assert r.status_code == 200 and "hmseal1." not in r.text and "nas.lan" not in r.text
    assert api.get(url(machine_a), headers=bearer(token_a)).status_code == 401


def test_the_document_and_the_report_fit_the_device_body_limit(api, world):
    machine, token = world.paired_machine(world.owner())
    huge = report(apply_detail="x" * (DEVICE_BODY_LIMIT + 1))
    r = beat(api, token, huge)
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"
    assert world.session.execute(select(MachineAppliance)).first() is None


# --- what a machine reports (6.1) ------------------------------------------

FULL_REPORT = {
    "plugins": [
        {"id": "ollama", "state": "running", "detail": "", "version": "1", "ports": [11434]},
        {"id": "assistant", "state": "blocked", "detail": "mode is vast", "version": "3", "ports": []},
    ],
    "nas": [{"id": "docs", "state": "mounted", "detail": ""}],
    "secrets": [{"name": "nas.docs.password", "state": "ok"}],
    "vectorizer": {
        "state": "idle",
        "last_run_at": "2026-10-02T02:30:00Z",
        "last_ok_at": "2026-10-02T02:41:10Z",
        "files_indexed": 1820,
        "files_failed": 3,
        "files_skipped": 12,
        "chunks": 40211,
        "detail": "",
    },
    "backup": {
        "state": "ok",
        "key_present": True,
        "key_id": "9f2c1a7b",
        "last_ok_at": "2026-10-01T03:00:00Z",
        "last_size_bytes": 123456,
        "detail": "",
    },
    "update": {"current_version": "0.2.0", "state": "idle", "target_version": "", "detail": ""},
    "schedules": [
        {
            "id": "nightly-sync",
            "last_run_at": "2026-10-02T02:30:00Z",
            "last_status": "ok",
            "next_run_at": "2026-10-03T02:30:00Z",
        }
    ],
}


def test_a_well_formed_report_is_stored_as_it_is_and_shown(api, world):
    machine, token, h = configured(world, api)
    said = report(applied_revision=2, mode="private_ai", **FULL_REPORT)
    assert beat(api, token, said).status_code == 200
    row = stored(world, machine)
    expected = {k: v for k, v in said.items() if k != "seal_public_key"}
    for section, key in (
        ("vectorizer", "last_run_at"),
        ("vectorizer", "last_ok_at"),
        ("backup", "last_ok_at"),
    ):
        expected[section] = {**expected[section], key: expected[section][key].replace("Z", "+00:00")}
    expected["schedules"] = [
        {
            **expected["schedules"][0],
            "last_run_at": "2026-10-02T02:30:00+00:00",
            "next_run_at": "2026-10-03T02:30:00+00:00",
        }
    ]
    assert row.reported == expected
    assert row.applied_revision == 2 and row.seal_public_key == SEAL_KEY
    seen = api.get(url(machine), headers=h).json()
    assert seen["reported"] == expected and seen["in_sync"] is True and seen["applied_revision"] == 2
    # Processed, but not applied: that is not "in sync".
    for status in ("partial", "rejected", "disabled", "pending"):
        beat(api, token, report(applied_revision=2, apply_status=status))
        assert api.get(url(machine), headers=h).json()["in_sync"] is False, status


def test_a_report_is_bounded_cleaned_and_never_trusted(api, world):
    machine, token, h = configured(world, api)
    hostile = report(
        schema="1",
        control="root",
        applied_revision=2,
        apply_status="owned",
        apply_detail="line1\nline2\x00 password=hunter2 and Bearer abc.def.ghi " + "x" * 2000,
        mode="mining",
        # Not in the contract: dropped, wherever it is.
        owner_id="someone-else",
        management="company",
        command="rm -rf /",
        document={"mode": "private_ai"},
        capabilities={"plugins": True, "nas": "yes", "root": True, "docker": 1},
        catalog=[
            {"id": "ollama", "version": "1", "compose": "x"},
            {"id": "Bad Id"},
            {"id": "qdrant", "version": "v" * 200},
            "ollama",
            None,
        ]
        + [{"id": f"p{i}", "version": "1"} for i in range(60)],
        plugins=[
            {
                "id": "ollama",
                "state": "running",
                "detail": "ok",
                "version": "1",
                "ports": [11434, 0, 70000, "80", True, 443],
                "image": "evil",
            },
            {"id": "ollama", "state": "stopped"},  # a second entry for the same plugin
            {"id": "qdrant", "state": "pwned", "detail": 7, "version": {"x": 1}, "ports": "all"},
            {"id": "../etc", "state": "running"},
            {"state": "running"},
            ["ollama"],
        ],
        nas=[
            {
                "id": "docs",
                "state": "mounted",
                "detail": "api_key=sk-live-123456 token: abcdef",
                "files": ["/secret/plan.pdf"],
            }
        ],
        secrets=[
            {"name": "nas.docs.password", "state": "ok", "value": "hunter2"},
            {"name": "Not A Name", "state": "ok"},
            {"name": "x", "state": "leaked"},
        ],
        vectorizer={
            "state": "indexing",
            "last_run_at": "yesterday",
            "last_ok_at": "2026-10-02 02:41:10",
            "files_indexed": -1,
            "files_failed": 1.5,
            "files_skipped": True,
            "chunks": 2**60,
            "detail": "d",
            "current_file": "/nas/hr/salaries.xlsx",
        },
        backup={
            "state": "ok",
            "key_present": "yes",
            "key_id": "9f2c1a7b00000000",
            "recovery_key": "hmrk1-aaaa-bbbb",
            "last_size_bytes": "12",
        },
        update={
            "current_version": "0.2.0; rm -rf /",
            "state": "idle",
            "target_version": "0.3.0",
            "detail": "hmd_0123456789abcdef0123456789abcdef.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde",
        },
        schedules={"nightly-sync": {"last_status": "ok"}},
    )
    assert beat(api, token, hostile).status_code == 200
    row = stored(world, machine)
    got = row.reported
    assert set(got) == {
        "schema", "control", "applied_revision", "apply_status", "apply_detail", "mode", "capabilities",
        "catalog", "plugins", "nas", "secrets", "vectorizer", "backup", "update",
    }  # fmt: skip
    assert (got["schema"], got["control"], got["applied_revision"]) == (1, "unknown", 2)
    assert got["apply_status"] == "unknown" and got["mode"] == "unknown"
    detail = got["apply_detail"]
    assert len(detail) == 500 and "\n" not in detail and "\x00" not in detail
    assert "hunter2" not in detail and "abc.def.ghi" not in detail and "[REDACTED]" in detail
    assert got["capabilities"] == {"plugins": True}
    # The first 32 entries are looked at; the malformed ones among them are dropped.
    assert len(got["catalog"]) == 29 and got["catalog"][:2] == [
        {"id": "ollama", "version": "1"},
        {"id": "qdrant", "version": ""},
    ]
    assert got["plugins"] == [
        {"id": "ollama", "state": "running", "detail": "ok", "version": "1", "ports": [11434, 443]},
        {"id": "qdrant", "state": "unknown", "detail": "", "version": "", "ports": []},
    ]
    assert got["nas"] == [
        {"id": "docs", "state": "mounted", "detail": "api_key=[REDACTED] token: [REDACTED]"}
    ]
    assert got["secrets"] == [{"name": "nas.docs.password", "state": "ok"}, {"name": "x", "state": "unknown"}]
    assert got["vectorizer"] == {
        "state": "unknown",
        "last_run_at": None,
        "last_ok_at": None,  # no time zone: not a moment
        "files_indexed": None,
        "files_failed": None,
        "files_skipped": None,
        "chunks": None,
        "detail": "d",
    }
    assert got["backup"] == {
        "state": "ok",
        "key_present": False,
        "key_id": "",
        "last_ok_at": None,
        "last_size_bytes": None,
        "detail": "",
    }
    assert got["update"] == {
        "current_version": "",
        "state": "idle",
        "target_version": "0.3.0",
        "detail": "[REDACTED]",
    }
    stored_text = json.dumps(got)
    for leaked in (
        "hunter2",
        "sk-live",
        "salaries",
        "plan.pdf",
        "hmrk1",
        "rm -rf",
        "someone-else",
        "evil",
        "hmd_0123",
    ):
        assert leaked not in stored_text, leaked
    # The page for people shows the same cleaned state, and the claims changed nothing.
    seen = api.get(url(machine), headers=h).json()
    assert seen["reported"] == got and seen["management"] == "company" and seen["document"]["mode"] == "vast"
    # "applied" was not said: the machine is not in sync, whatever revision it names.
    assert seen["in_sync"] is False


def test_sanitise_report_bounds_every_list_and_string():
    raw = report(
        plugins=[
            {"id": f"p{i}", "state": "running", "ports": list(range(1, 200)), "detail": "d" * 5000}
            for i in range(100)
        ],
        nas=[{"id": f"n{i}", "state": "mounted"} for i in range(100)],
        secrets=[{"name": f"s{i}", "state": "ok"} for i in range(100)],
        schedules=[
            {"id": f"s{i}", "last_status": "ok", "last_run_at": "2026-10-02T02:30:00Z" + "x" * 500}
            for i in range(100)
        ],
        catalog=[{"id": f"c{i}", "version": "1"} for i in range(100)],
        applied_revision=10**12,
    )
    clean = appliance_service.sanitise_report(raw, revision=7)
    for key in ("plugins", "nas", "secrets", "schedules", "catalog"):
        assert len(clean[key]) == 32, key
    assert all(len(p["ports"]) == 32 and len(p["detail"]) == 500 for p in clean["plugins"])
    assert all(s["last_run_at"] is None for s in clean["schedules"])
    assert clean["applied_revision"] == 7
    assert len(json.dumps(clean)) < 64 * 1024

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for inner in value.values():
                yield from strings(inner)
        elif isinstance(value, list):
            for inner in value:
                yield from strings(inner)

    assert max(len(s) for s in strings(clean)) == 500
    # Nothing at all is still a report: the machine follows the cloud and has applied nothing.
    assert appliance_service.sanitise_report({}, revision=3) == {
        "schema": 1,
        "control": "unknown",  # not said: the document waits until the machine says "cloud"
        "applied_revision": 0,
        "apply_status": "unknown",
        "apply_detail": "",
        "mode": "unknown",
    }
    for junk in (
        {"plugins": {"id": "x"}},
        {"nas": "docs"},
        {"vectorizer": []},
        {"capabilities": []},
        {"update": "idle"},
    ):
        assert set(appliance_service.sanitise_report(junk, revision=0)) == {
            "schema", "control", "applied_revision", "apply_status", "apply_detail", "mode",
        }  # fmt: skip


def test_the_sealing_key_is_kept_only_when_it_is_a_key_and_a_change_is_on_record(api, world):
    machine, token = world.paired_machine(world.owner())
    assert beat(api, token, report(seal_public_key=None)).status_code == 200
    assert stored(world, machine).seal_public_key is None and audit_rows(world, "appliance.seal_key") == []

    assert beat(api, token, report()).status_code == 200
    (first,) = audit_rows(world, "appliance.seal_key")
    assert (
        first.details["first"] is True and first.actor_type == "device" and first.object_id == str(machine.id)
    )
    assert SEAL_KEY not in json.dumps(first.details) and len(first.details["fingerprint"]) == 16

    # Rubbish, a truncated key, a point that is not on the curve: ignored, the key on record stays.
    raw = bytearray(base64.urlsafe_b64decode(SEAL_KEY[5:] + "="))
    raw[-1] ^= 1
    off_curve = "hmk1." + base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
    for bad in ("", "hmk1.", SEAL_KEY[:-3], off_curve, "x" * 500, 12, ["hmk1"], {"k": SEAL_KEY}):
        assert beat(api, token, report(seal_public_key=bad)).status_code == 200
        assert stored(world, machine).seal_public_key == SEAL_KEY
    # The same key again is not news.
    beat(api, token, report())
    assert len(audit_rows(world, "appliance.seal_key")) == 1

    # A reinstalled machine has a new key. That is recorded: values sealed for the old one no longer open.
    other = sealing.encode_seal_public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
    assert beat(api, token, report(seal_public_key=other)).status_code == 200
    assert stored(world, machine).seal_public_key == other
    second = audit_rows(world, "appliance.seal_key")[-1]
    assert second.details["first"] is False and second.details["fingerprint"] != first.details["fingerprint"]


# --- end to end ------------------------------------------------------------


def test_a_secret_typed_by_the_owner_reaches_the_machine_and_only_the_machine(api, world):
    """Seal in the "browser", configure over HTTP, receive on the device, open with the machine's key."""
    owner = world.owner()
    machine, token = world.paired_machine(owner)
    h = world.auth(world.user("owner", owner))
    private_key = machine_private_key()  # what only the machine's helper has (the published test key)

    # 1. The agent reports; the page learns which key to seal for.
    assert set(beat(api, token, report()).json()) == AGENT_0_1_0_KEYS
    page = api.get(url(machine), headers=h).json()
    key = page["seal_public_key"]
    assert key == sealing.encode_seal_public_key(private_key.public_key())

    # 2. The owner's administrator types the secrets; the page seals them before sending.
    nas_password = "correct horse battery staple é✓".encode()
    api_key = b"sk-live-0123456789abcdef"
    put = lambda suffix, body: api.put(url(machine, suffix), headers=h, json=body)  # noqa: E731
    steps = [
        ("/nas/docs", {**NAS_DOCS, "sealed_secret": sealing.seal(key, "nas.docs.password", nas_password)}),
        ("/nas/bk", NAS_BACKUP),
        ("/plugins/ollama", {"enabled": True, "settings": {"models": ["hermes3:8b", "bge-m3"]}}),
        ("/plugins/qdrant", {"enabled": True}),
        (
            "/vectorizer",
            {
                **VECTORIZER,
                "answer": {
                    "provider": "openai_compatible",
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-4.1-mini",
                    "sealed_secret": sealing.seal(key, "ai.answer.api_key", api_key),
                },
            },
        ),
        ("/plugins/vectorizer", {"enabled": True}),
        ("/schedules/nightly-sync", NIGHTLY),
        ("/mode", {"mode": "vectorize"}),
    ]
    for index, (suffix, body) in enumerate(steps, start=1):
        r = put(suffix, body)
        assert r.status_code == 200 and r.json()["revision"] == index, f"{suffix}: {r.text}"
        assert "hmseal1." not in r.text
    assert r.json()["secrets"] == ["ai.answer.api_key", "nas.docs.password"]

    # 3. The device's next heartbeat brings the whole document.
    answer = beat(api, token, report(applied_revision=0)).json()["appliance"]
    assert answer["revision"] == len(steps)
    document = answer["document"]
    appliance_service.validate_document(document, catalog_service.load_catalog(FIXTURE_CATALOG))
    assert document["mode"] == "vectorize" and document["revision"] == len(steps)
    assert [p["id"] for p in document["plugins"] if p["enabled"]] == ["ollama", "qdrant", "vectorizer"]
    assert document["nas"][0]["secret"] == "nas.docs.password" and document["nas"][0]["username"] == "indexer"
    assert document["vectorizer"]["answer"]["secret"] == "ai.answer.api_key"
    assert document["schedules"] == [{"id": "nightly-sync", **NIGHTLY}]

    # 4. The machine opens what was sealed for it, under the name it was sealed for.
    secrets = document["secrets"]
    assert set(secrets) == {"nas.docs.password", "ai.answer.api_key"}
    assert open_sealed(private_key, "nas.docs.password", secrets["nas.docs.password"]) == nas_password
    assert open_sealed(private_key, "ai.answer.api_key", secrets["ai.answer.api_key"]) == api_key
    with pytest.raises(InvalidTag):
        open_sealed(private_key, "ai.answer.api_key", secrets["nas.docs.password"])

    # 5. The control plane held only the sealed form, the whole time.
    row = stored(world, machine)
    everything_stored = json.dumps([row.document, row.secrets, row.reported]) + json.dumps(
        [a.details for a in audit_rows(world)]
    )
    assert nas_password.decode() not in everything_stored and api_key.decode() not in everything_stored
    assert "correct horse" not in everything_stored and "sk-live" not in everything_stored

    # 6. The machine applies it and says so: in sync, and the document is not sent again.
    applied = report(
        applied_revision=len(steps),
        mode="vectorize",
        nas=[
            {"id": "docs", "state": "mounted", "detail": ""},
            {"id": "bk", "state": "mounted", "detail": ""},
        ],
        secrets=[{"name": name, "state": "ok"} for name in sorted(secrets)],
        plugins=[
            {"id": p, "state": "running", "detail": "", "version": "1", "ports": []}
            for p in ("ollama", "qdrant", "vectorizer")
        ],
    )
    assert beat(api, token, applied).json()["appliance"] == {"revision": len(steps)}
    page = api.get(url(machine), headers=h).json()
    assert page["in_sync"] is True and page["reported"]["mode"] == "vectorize"
    assert [s["state"] for s in page["reported"]["secrets"]] == ["ok", "ok"]
