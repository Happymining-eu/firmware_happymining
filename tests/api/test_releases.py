"""Signed firmware releases (docs/appliance.md, sections 6.6 and 9).

Publishing (manifest, package, channels, withdrawal), what a machine is
offered and may download, installing a release through a typed operation, the
body limit of the one route that takes a large body, and the signing tool.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from helpers import BASE_URL, SYSTEM, make_settings
from sqlalchemy import select, text
from test_appliance import (
    appliance_client,
    appliance_settings,
    audit_rows,
    bearer,
    beat,
    code,
    report,
    reporting_machine,
    url,
)

from happymining import sealing
from happymining.main import DEFAULT_BODY_LIMIT, DEVICE_BODY_LIMIT, BodyLimitMiddleware, create_app
from happymining.models import API_CLIENT_SCOPES, Operation, Release
from happymining.routers.device import ARTIFACT_DOWNLOADS_PER_HOUR
from happymining.services import api_clients

REPO = Path(__file__).resolve().parents[2]
VECTOR = json.loads((REPO / "appliance" / "testdata" / "release-vector.json").read_text())
TEST_KEY = VECTOR["public_key_b64"]
SEED = Ed25519PrivateKey.from_private_bytes(base64.b64decode(VECTOR["private_seed_b64"]))
SIGN_TOOL = REPO / "scripts" / "release-sign.py"
OCTETS = {"Content-Type": "application/octet-stream"}


# --- helpers ---------------------------------------------------------------


def release_client(**overrides: object):
    """An application that trusts the published test key (DEMO only: LIVE refuses it)."""
    return appliance_client(**{"release_public_keys": [TEST_KEY], **overrides})


@pytest.fixture
def api() -> Iterator[TestClient]:
    with release_client() as client:
        yield client


def build(version: str, artifact: bytes | None = None, *, min_from: str = "0.0.0", key=SEED, **extra) -> dict:
    """A release signed here: the request body for POST /releases, and the package."""
    artifact = artifact if artifact is not None else f"package {version}".encode()
    manifest = {
        "schema": 1,
        "product": "happymining-agent",
        "version": version,
        "created_at": "2026-10-02T12:00:00Z",
        "artifact": {
            "filename": f"happymining-agent_{version}_amd64.deb",
            "size": len(artifact),
            "sha256": hashlib.sha256(artifact).hexdigest(),
        },
        "min_upgrade_from": min_from,
        "notes": f"Release {version}.",
        **extra,
    }
    raw = (json.dumps(manifest, indent=2) + "\n").encode()
    return {
        "body": {
            "manifest_b64": base64.b64encode(raw).decode(),
            "signature_b64": sealing.sign_manifest(raw, key),
        },
        "raw": raw,
        "artifact": artifact,
        "version": version,
    }


def upload(client: TestClient, headers: dict, version: str, data: bytes):
    return client.put(f"/api/v1/releases/{version}/artifact", headers={**headers, **OCTETS}, content=data)


def publish(client: TestClient, headers: dict, version: str, channels=("stable",), **kw) -> dict:
    """Manifest, package, channels. Returns what ``build`` returned."""
    release = build(version, **kw)
    r = client.post("/api/v1/releases", headers=headers, json=release["body"])
    assert r.status_code == 201, r.text
    r = upload(client, headers, version, release["artifact"])
    assert r.status_code == 200, r.text
    if channels:
        r = client.post(
            f"/api/v1/releases/{version}/channels", headers=headers, json={"channels": list(channels)}
        )
        assert r.status_code == 200, r.text
    return release


def on_channel(
    world, client: TestClient, channel: str = "stable", *, agent_version: str = "0.1.0", owner=None
):
    """A reporting machine on update channel ``channel``. Returns (machine, device token, owner headers)."""
    owner = owner or world.owner()
    machine, token = reporting_machine(world, client, owner)
    h = world.auth(world.user("owner", owner))
    if channel != "none":
        r = client.put(url(machine, "/update"), headers=h, json={"channel": channel, "policy": "manual"})
        assert r.status_code == 200, r.text
    assert beat(client, token, report(), agent_version=agent_version).status_code == 200
    return machine, token, h


def offered(client: TestClient, token: str) -> str | None:
    r = client.get("/api/v1/device/update", headers=bearer(token))
    assert r.status_code == 200, r.text
    release = r.json()["release"]
    return release["version"] if release else None


def releases_in_db(world) -> dict[str, str]:
    world.session.expire_all()
    return {r.version: r.status for r in world.session.execute(select(Release)).scalars()}


def raw_request(app, method: str, path: str, headers: dict[str, str], chunks: list[bytes]):
    """Straight to the ASGI application. Returns (status, body, how many times the body was asked for)."""
    pending = list(chunks)
    asked = 0
    sent: list[dict] = []

    async def receive() -> dict:
        nonlocal asked
        asked += 1
        if pending:
            chunk = pending.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(pending)}
        await asyncio.sleep(5)
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        sent.append(message)

    raw_headers = {"host": "127.0.0.1:8000", "transfer-encoding": "chunked", **headers}
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in raw_headers.items()],
        "client": ("203.0.113.5", 40000),
        "server": ("127.0.0.1", 8000),
    }
    asyncio.run(app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body, asked


# --- publishing ------------------------------------------------------------


def test_the_release_vector_is_published_step_by_step(api, world):
    admin = world.user("admin")
    h = world.auth(admin)
    manifest = base64.b64decode(VECTOR["manifest_b64"])
    artifact = base64.b64decode(VECTOR["artifact_b64"])
    body = {"manifest_b64": VECTOR["manifest_b64"], "signature_b64": VECTOR["signature_b64"]}

    r = api.post("/api/v1/releases", headers=h, json=body)
    assert r.status_code == 201, r.text
    created = r.json()
    assert created.pop("created_at")
    assert created == {
        "version": "0.2.0",
        "status": "awaiting_artifact",
        "channels": [],
        "filename": "happymining-agent_0.2.0_amd64.deb",
        "size": 11,
        "sha256": hashlib.sha256(artifact).hexdigest(),
        "key_id": VECTOR["key_id"],
        "min_upgrade_from": "0.1.0",
        "notes": "Test release.",
        "created_by": str(admin.id),
        "published_at": None,
        "withdrawn_at": None,
    }
    row = world.session.execute(select(Release)).scalar_one()
    assert bytes(row.manifest) == manifest  # byte for byte: the signature covers exactly these bytes
    assert (row.v_major, row.v_minor, row.v_patch) == (0, 2, 0) and row.signature == VECTOR["signature_b64"]

    # Not offered to anyone, and not assignable, before its package is there.
    r = api.post("/api/v1/releases/0.2.0/channels", headers=h, json={"channels": ["stable"]})
    assert r.status_code == 409 and "awaiting_artifact" in r.json()["error"]["message"]

    r = upload(api, h, "0.2.0", artifact)
    assert r.status_code == 200 and r.json()["status"] == "ready" and r.json()["published_at"] is None
    r = api.post("/api/v1/releases/0.2.0/channels", headers=h, json={"channels": ["stable", "beta"]})
    assert r.status_code == 200 and r.json()["channels"] == ["beta", "stable"] and r.json()["published_at"]

    listed = api.get("/api/v1/releases", headers=h).json()["items"]
    assert [item["version"] for item in listed] == ["0.2.0"] and listed[0]["status"] == "ready"
    assert "artifact" not in listed[0] and "manifest" not in listed[0]

    actions = [a.action for a in audit_rows(world) if a.action.startswith("release.")]
    assert actions == ["release.create", "release.artifact", "release.channels"]
    create = audit_rows(world, "release.create")[0]
    assert create.actor_id == str(admin.id) and create.details["key_id"] == VECTOR["key_id"]
    assert audit_rows(world, "release.channels")[0].details == {
        "version": "0.2.0",
        "from": [],
        "to": ["beta", "stable"],
    }


def test_without_a_configured_key_nothing_can_be_published(world):
    body = {"manifest_b64": VECTOR["manifest_b64"], "signature_b64": VECTOR["signature_b64"]}
    for keys in ([], ["not-a-key"]):
        with appliance_client(release_public_keys=keys) as client:
            h = world.auth(world.user("admin"))
            r = client.post("/api/v1/releases", headers=h, json=body)
            assert r.status_code == 409 and code(r) == "release_keys_not_configured", r.text
            assert "HM_RELEASE_PUBLIC_KEYS" in r.json()["error"]["message"]
            assert client.get("/api/v1/releases", headers=h).json() == {"items": []}
    assert releases_in_db(world) == {}


def test_only_a_manifest_signed_with_a_trusted_key_is_accepted(api, world):
    h = world.auth(world.user("admin"))
    good = build("0.2.0")
    stranger = build("0.2.0", key=Ed25519PrivateKey.generate())
    tampered = {
        **good["body"],
        "manifest_b64": base64.b64encode(good["raw"].replace(b"0.2.0", b"0.9.0")).decode(),
    }
    for why, body, fragment in (
        ("unknown key", stranger["body"], "does not verify"),
        ("tampered", tampered, "does not verify"),
        (
            "other signature",
            {**good["body"], "signature_b64": build("0.3.0")["body"]["signature_b64"]},
            "does not verify",
        ),
        ("signature not base64", {**good["body"], "signature_b64": "!!!"}, "not base64"),
        ("manifest not base64", {**good["body"], "manifest_b64": "{not base64}"}, "not base64"),
        ("signed nonsense", build("0.2.0", product="other")["body"], "not well formed"),
        ("bad version", build("0.2")["body"], "not well formed"),
    ):
        r = api.post("/api/v1/releases", headers=h, json=body)
        assert r.status_code == 400 and code(r) == "invalid_request", why
        assert fragment in r.json()["error"]["message"], why
    for body in (
        {},
        {"manifest_b64": "x"},
        {**good["body"], "url": "https://evil.example/x.deb"},
        {**good["body"], "manifest_b64": 7},
    ):
        assert api.post("/api/v1/releases", headers=h, json=body).status_code == 422
    assert releases_in_db(world) == {} and audit_rows(world, "release.create") == []

    assert api.post("/api/v1/releases", headers=h, json=good["body"]).status_code == 201
    # A version is published once. Not even the identical manifest again.
    for again in (good["body"], build("0.2.0", b"other bytes")["body"]):
        r = api.post("/api/v1/releases", headers=h, json=again)
        assert (
            r.status_code == 409
            and code(r) == "conflict"
            and "already exists" in r.json()["error"]["message"]
        )
    assert releases_in_db(world) == {"0.2.0": "awaiting_artifact"}


def test_only_admins_publish_auditors_read_and_nobody_else_gets_in(api, world):
    owner = world.owner()
    machine, device_token = reporting_machine(world, api, owner)
    admin = world.auth(world.user("admin"))
    publish(api, admin, "0.2.0")
    issued = api_clients.create_client(
        world.session, world.settings, SYSTEM, name="all", scopes=list(API_CLIENT_SCOPES)
    )
    world.commit()
    release = build("0.3.0")
    changes = [
        ("POST", "/api/v1/releases", {"json": release["body"]}),
        ("PUT", "/api/v1/releases/0.3.0/artifact", {"content": release["artifact"], "headers": OCTETS}),
        ("POST", "/api/v1/releases/0.2.0/channels", {"json": {"channels": []}}),
        ("POST", "/api/v1/releases/0.2.0/withdraw", {"json": {"reason": "test"}}),
    ]
    callers = {
        "auditor": (world.auth(world.user("auditor")), 200, 403),
        "org_admin": (world.auth(world.user("owner", owner)), 403, 403),
        "org_viewer": (world.auth(world.user("owner", owner, org_role="org_viewer")), 403, 403),
        "device": (bearer(device_token), 401, 401),
        "api client": (bearer(issued.token), 401, 401),
        "anonymous": ({}, 401, 401),
    }
    for who, (headers, read, change) in callers.items():
        assert api.get("/api/v1/releases", headers=headers).status_code == read, who
        for method, path, kw in changes:
            merged = {**headers, **kw.get("headers", {})}
            r = api.request(method, path, headers=merged, **{k: v for k, v in kw.items() if k != "headers"})
            assert r.status_code == change, f"{who} {method} {path}: {r.status_code}"
    assert releases_in_db(world) == {"0.2.0": "ready"}
    world.session.expire_all()
    assert world.session.execute(select(Release)).scalar_one().channels == ["stable"]


# --- the package -----------------------------------------------------------


def test_the_package_must_be_exactly_what_the_manifest_describes(api, world):
    h = world.auth(world.user("admin"))
    release = build("0.2.0", b"0123456789abcdef" * 64)  # 1024 bytes
    assert api.post("/api/v1/releases", headers=h, json=release["body"]).status_code == 201
    good = release["artifact"]
    flipped = bytes([good[0] ^ 1]) + good[1:]
    for why, data, fragment in (
        ("one byte short", good[:-1], "size stated in the manifest"),
        ("one byte long", good + b"x", "size stated in the manifest"),
        ("empty", b"", "size stated in the manifest"),
        ("same size, other content", flipped, "SHA-256 stated in the manifest"),
    ):
        r = upload(api, h, "0.2.0", data)
        assert r.status_code == 400 and code(r) == "invalid_request", f"{why}: {r.status_code} {r.text}"
        assert fragment in r.json()["error"]["message"], why
    # Not as a form, not as JSON: the raw bytes.
    r = api.put("/api/v1/releases/0.2.0/artifact", headers=h, files={"file": ("x.deb", good)})
    assert r.status_code == 400 and "application/octet-stream" in r.json()["error"]["message"]
    assert api.put("/api/v1/releases/0.2.0/artifact", headers=h, json={"data": "x"}).status_code == 400
    assert releases_in_db(world) == {"0.2.0": "awaiting_artifact"}
    assert audit_rows(world, "release.artifact") == []
    world.session.expire_all()
    assert world.session.execute(select(Release)).scalar_one().artifact is None

    for missing in ("9.9.9", "latest", "0.2", "..", "0.2.0%2F..", "x" * 30):
        r = upload(api, h, missing, good)
        assert r.status_code in (404, 422), f"{missing}: {r.status_code}"

    assert upload(api, h, "0.2.0", good).status_code == 200
    world.session.expire_all()
    assert bytes(world.session.execute(select(Release)).scalar_one().artifact) == good
    # Once stored, a package is never replaced, not even by itself.
    r = upload(api, h, "0.2.0", good)
    assert r.status_code == 409 and "cannot be replaced" in r.json()["error"]["message"]


def test_reading_stops_as_soon_as_the_package_is_larger_than_the_manifest_says(world):
    app = create_app(appliance_settings(release_public_keys=[TEST_KEY]))
    h = world.auth(world.user("admin"))
    release = build("0.2.0", b"x" * 1000)
    with TestClient(app, base_url=BASE_URL) as client:
        assert client.post("/api/v1/releases", headers=h, json=release["body"]).status_code == 201
    pieces = [b"x" * 400] * 200  # 80 000 bytes on offer
    headers = {**{k.lower(): v for k, v in h.items()}, "content-type": "application/octet-stream"}
    status, body, asked = raw_request(app, "PUT", "/api/v1/releases/0.2.0/artifact", headers, pieces)
    assert (
        status == 400
        and "larger than the size stated in the manifest" in json.loads(body)["error"]["message"]
    )
    assert asked == 3, f"the body was asked for {asked} times"  # 1200 bytes read of 80 000, then no more
    # A declared length that is not the manifest's is refused before the first byte.
    declared = {**headers, "content-length": "999"}
    declared.pop("transfer-encoding", None)
    status, _, asked = raw_request(app, "PUT", "/api/v1/releases/0.2.0/artifact", declared, [b"x" * 999])
    assert status == 400 and asked == 0
    assert releases_in_db(world) == {"0.2.0": "awaiting_artifact"}
    # In pieces, and exactly right: accepted.
    exact = [release["artifact"][i : i + 300] for i in range(0, 1000, 300)]
    status, body, _ = raw_request(app, "PUT", "/api/v1/releases/0.2.0/artifact", headers, exact)
    assert status == 200 and json.loads(body)["status"] == "ready"


def test_an_upload_nobody_is_allowed_to_make_is_refused_without_reading_it(world):
    """Authentication, the role, and whether a package is expected at all come before the body."""
    app = create_app(appliance_settings(release_public_keys=[TEST_KEY]))
    owner = world.owner()
    admin = world.auth(world.user("admin"))
    with TestClient(app, base_url=BASE_URL) as client:
        machine, device_token = reporting_machine(world, client, owner)
        publish(client, admin, "0.1.5")
        assert (
            client.post(
                "/api/v1/releases", headers=admin, json=build("0.2.0", b"x" * 1000)["body"]
            ).status_code
            == 201
        )
    pieces = [b"x" * 1000] * 50
    path = "/api/v1/releases/0.2.0/artifact"
    octets = {"content-type": "application/octet-stream"}

    def lower(headers: dict) -> dict:
        return {**{k.lower(): v for k, v in headers.items()}, **octets}

    for who, headers, expected in (
        ("nobody", octets, 401),
        ("a made-up session", {**octets, "authorization": "Bearer hms_" + "x" * 43}, 401),
        ("a device", lower(bearer(device_token)), 401),
        ("an auditor", lower(world.auth(world.user("auditor"))), 403),
        ("the owner's administrator", lower(world.auth(world.user("owner", owner))), 403),
    ):
        status, body, asked = raw_request(app, "PUT", path, headers, list(pieces))
        assert status == expected, f"{who}: {status} {body[:200]}"
        assert asked == 0, f"{who}: the body was read ({asked} times) before the caller was refused"
    # An admin, but no package is expected: unknown release, or one that already has its package.
    for target, expected in (
        ("/api/v1/releases/9.9.9/artifact", 404),
        ("/api/v1/releases/0.1.5/artifact", 409),
    ):
        status, _, asked = raw_request(app, "PUT", target, lower(admin), list(pieces))
        assert status == expected and asked == 0, (target, status, asked)
    assert releases_in_db(world) == {"0.1.5": "ready", "0.2.0": "awaiting_artifact"}


def test_only_the_package_route_has_the_larger_body_limit(world):
    big = 3 * 1024 * 1024
    middleware = BodyLimitMiddleware(app=None, release_max_bytes=big)
    assert middleware.limit_for("PUT", "/api/v1/releases/0.2.0/artifact") == big
    for method, path in (
        ("POST", "/api/v1/releases/0.2.0/artifact"),
        ("PATCH", "/api/v1/releases/0.2.0/artifact"),
        ("PUT", "/api/v1/releases/0.2.0/artifact/"),
        ("PUT", "/api/v1/releases/0.2.0/artifact/extra"),
        ("PUT", "/api/v1/releases/0.2.0/x/artifact"),
        ("PUT", "/api/v1/releases//artifact"),
        ("PUT", "/api/v1/releases/artifact"),
        ("PUT", "/api/v2/releases/0.2.0/artifact"),
        ("PUT", "/x/api/v1/releases/0.2.0/artifact"),
        ("PUT", "/api/v1/releases/0.2.0/channels"),
        ("POST", "/api/v1/releases"),
        ("PUT", "/api/v1/machines/0.2.0/appliance/mode"),
        ("POST", "/api/v1/owners"),
        ("PUT", "/releases/0.2.0/artifact"),
    ):
        assert middleware.limit_for(method, path) == DEFAULT_BODY_LIMIT, (method, path)
    for path in (
        "/api/v1/device/heartbeat",
        "/api/v1/device/update/artifact/0.2.0",
        "/api/v1/devices/enroll",
    ):
        assert middleware.limit_for("PUT", path) == DEVICE_BODY_LIMIT
    assert (
        BodyLimitMiddleware(app=None).limit_for("PUT", "/api/v1/releases/0.2.0/artifact")
        == DEFAULT_BODY_LIMIT
    )

    with release_client(release_max_bytes=big) as client:
        h = world.auth(world.user("admin"))
        # A package of two megabytes goes through, intact...
        package = os.urandom(2 * 1024 * 1024)
        release = publish(client, h, "0.2.0", artifact=package)
        world.session.expire_all()
        assert bytes(world.session.execute(select(Release)).scalar_one().artifact) == release["artifact"]
        # ...and nothing else got any larger.
        padding = b" " * (DEFAULT_BODY_LIMIT + 1)
        json_headers = {**h, "Content-Type": "application/json"}
        for method, path in (
            ("POST", "/api/v1/releases"),
            ("POST", "/api/v1/releases/0.2.0/channels"),
            ("POST", "/api/v1/releases/0.2.0/artifact"),
            ("PUT", "/api/v1/releases/0.2.0/artifact/"),
            ("POST", "/api/v1/owners"),
            ("PUT", f"/api/v1/machines/{'0' * 8}-0000-0000-0000-{'0' * 12}/appliance/mode"),
        ):
            r = client.request(method, path, headers=json_headers, content=b'{"x": 1}' + padding)
            assert r.status_code == 413 and code(r) == "payload_too_large", (
                f"{method} {path}: {r.status_code}"
            )
        # Beyond its own limit the package route refuses too, before looking at who asks.
        r = client.put("/api/v1/releases/0.3.0/artifact", headers=OCTETS, content=b"x" * (big + 1))
        assert r.status_code == 413
        # A manifest that announces a package this server would never take is refused at once.
        too_big = build("0.3.0", b"x")
        manifest = json.loads(too_big["raw"])
        manifest["artifact"]["size"] = big + 1
        raw = json.dumps(manifest).encode()
        body = {
            "manifest_b64": base64.b64encode(raw).decode(),
            "signature_b64": sealing.sign_manifest(raw, SEED),
        }
        r = client.post("/api/v1/releases", headers=h, json=body)
        assert r.status_code == 400 and "HM_RELEASE_MAX_BYTES" in r.json()["error"]["message"]
    assert releases_in_db(world) == {"0.2.0": "ready"}


def test_a_streamed_package_over_the_limit_is_cut_off(world):
    """No Content-Length to check up front: the limit holds while the bytes arrive."""
    limit = 4096
    app = create_app(appliance_settings(release_public_keys=[TEST_KEY], release_max_bytes=limit))
    h = world.auth(world.user("admin"))
    release = build("0.2.0", b"x" * limit)
    with TestClient(app, base_url=BASE_URL) as client:
        assert client.post("/api/v1/releases", headers=h, json=release["body"]).status_code == 201
    headers = {**{k.lower(): v for k, v in h.items()}, "content-type": "application/octet-stream"}
    status, _, asked = raw_request(app, "PUT", "/api/v1/releases/0.2.0/artifact", headers, [b"x" * 1024] * 64)
    assert status in (400, 413) and asked <= 6
    assert releases_in_db(world) == {"0.2.0": "awaiting_artifact"}


# --- channels and withdrawal -----------------------------------------------


def test_channels_are_set_as_a_whole_and_only_for_a_ready_release(api, world):
    h = world.auth(world.user("admin"))
    publish(api, h, "0.2.0", channels=())
    path = "/api/v1/releases/0.2.0/channels"
    for bad in (["nightly"], ["stable", "stable"], ["none"], ["stable", "nightly"]):
        r = api.post(path, headers=h, json={"channels": bad})
        assert r.status_code == 400 and "beta, stable" in r.json()["error"]["message"], bad
    for malformed in ({}, {"channels": "stable"}, {"channels": ["stable"], "force": True}, {"channels": [1]}):
        assert api.post(path, headers=h, json=malformed).status_code == 422
    assert api.post(path, headers=h, json={"channels": ["beta"]}).json()["channels"] == ["beta"]
    first = api.post(path, headers=h, json={"channels": ["stable", "beta"]}).json()
    assert first["channels"] == ["beta", "stable"]
    emptied = api.post(path, headers=h, json={"channels": []}).json()
    assert (
        emptied["channels"] == []
        and emptied["status"] == "ready"
        and emptied["published_at"] == first["published_at"]
    )
    assert api.post("/api/v1/releases/9.9.9/channels", headers=h, json={"channels": []}).status_code == 404
    assert [a.details["to"] for a in audit_rows(world, "release.channels")] == [
        ["beta"],
        ["beta", "stable"],
        [],
    ]


def test_a_withdrawn_release_is_offered_to_nobody_and_stays_withdrawn(api, world):
    h = world.auth(world.user("admin"))
    machine, token, owner_headers = on_channel(world, api, "stable")
    publish(api, h, "0.2.0")
    assert api.post("/api/v1/releases", headers=h, json=build("0.3.0")["body"]).status_code == 201
    assert offered(api, token) == "0.2.0"
    queued = api.post(url(machine, "/install-update"), headers=owner_headers, json={"version": "0.2.0"})
    assert queued.status_code == 201

    for malformed in ({}, {"reason": ""}, {"reason": "x", "delete": True}):
        assert api.post("/api/v1/releases/0.2.0/withdraw", headers=h, json=malformed).status_code == 422
    r = api.post("/api/v1/releases/0.3.0/withdraw", headers=h, json={"reason": "wrong"})
    assert r.status_code == 409 and "no package yet" in r.json()["error"]["message"]
    r = api.post("/api/v1/releases/0.2.0/withdraw", headers=h, json={"reason": "breaks the vectorizer"})
    assert r.status_code == 200 and r.json()["status"] == "withdrawn" and r.json()["withdrawn_at"]

    assert offered(api, token) is None
    assert api.get("/api/v1/device/update/artifact/0.2.0", headers=bearer(token)).status_code == 404
    # The update that was queued and not yet handed over does not leave.
    world.session.expire_all()
    operation = world.session.get(Operation, queued.json()["id"])
    assert operation.status == "cancelled" and operation.detail == "the release was withdrawn"
    assert beat(api, token, report()).json()["operations"] == []
    again = api.post(url(machine, "/install-update"), headers=owner_headers, json={"version": "0.2.0"})
    assert again.status_code == 409 and "withdrawn" in again.json()["error"]["message"]

    for path, body in (
        ("/api/v1/releases/0.2.0/withdraw", {"reason": "again"}),
        ("/api/v1/releases/0.2.0/channels", {"channels": ["beta"]}),
    ):
        assert api.post(path, headers=h, json=body).status_code == 409
    assert upload(api, h, "0.2.0", b"package 0.2.0").status_code == 409
    row = audit_rows(world, "release.withdraw")[0]
    assert row.details == {
        "version": "0.2.0",
        "reason": "breaks the vectorizer",
        "channels": ["stable"],
        "operations_cancelled": 1,
    }


# --- what a machine is offered (6.6) ---------------------------------------


def test_a_machine_without_a_channel_is_offered_nothing(api, world):
    admin = world.auth(world.user("admin"))
    publish(api, admin, "0.2.0", channels=("stable", "beta"))
    machine, token, h = on_channel(world, api, "none")
    r = api.get("/api/v1/device/update", headers=bearer(token))
    assert r.status_code == 200
    assert r.json() == {"channel": "none", "policy": "manual", "window": None, "release": None}
    # Explicitly "none" is the same.
    assert (
        api.put(url(machine, "/update"), headers=h, json={"channel": "none", "policy": "manual"}).status_code
        == 200
    )
    assert api.get("/api/v1/device/update", headers=bearer(token)).json()["release"] is None
    assert api.get("/api/v1/device/update/artifact/0.2.0", headers=bearer(token)).status_code == 404


def test_the_offer_is_what_the_machine_needs_to_verify_and_fetch_the_release(api, world):
    admin = world.auth(world.user("admin"))
    release = publish(api, admin, "0.2.0", min_from="0.1.0")
    machine, token, h = on_channel(world, api, "stable")
    window = {"start_hour": 22, "end_hour": 4}
    assert (
        api.put(
            url(machine, "/update"), headers=h, json={"channel": "stable", "policy": "auto", "window": window}
        ).status_code
        == 200
    )

    answer = api.get("/api/v1/device/update", headers=bearer(token)).json()
    assert answer == {
        "channel": "stable",
        "policy": "auto",
        "window": window,
        "release": {
            "version": "0.2.0",
            "manifest_b64": release["body"]["manifest_b64"],
            "signature_b64": release["body"]["signature_b64"],
            "size": len(release["artifact"]),
            "sha256": hashlib.sha256(release["artifact"]).hexdigest(),
            "artifact_path": "/api/v1/device/update/artifact/0.2.0",
        },
    }
    # The machine checks all of it itself: signature over the exact bytes, then the package.
    offer = answer["release"]
    manifest = sealing.verify_manifest(
        base64.b64decode(offer["manifest_b64"]),
        offer["signature_b64"],
        sealing.load_release_public_keys([TEST_KEY]),
    )
    package = api.get(offer["artifact_path"], headers=bearer(token))
    assert package.status_code == 200 and package.headers["content-type"] == "application/octet-stream"
    assert package.content == release["artifact"] and len(package.content) == manifest.size
    assert hashlib.sha256(package.content).hexdigest() == manifest.sha256


def test_the_newest_release_the_machine_can_install_is_offered(api, world):
    admin = world.auth(world.user("admin"))
    machine, token, _ = on_channel(world, api, "stable", agent_version="0.1.0")
    assert offered(api, token) is None  # nothing published

    publish(api, admin, "0.1.0")
    publish(api, admin, "0.0.9")
    assert offered(api, token) is None  # nothing newer than what it runs: never the same, never older
    publish(api, admin, "0.2.0", min_from="0.1.0")
    assert offered(api, token) == "0.2.0"
    publish(api, admin, "0.10.0", min_from="0.2.0")  # numbers, not text: 0.10.0 is newer than 0.9.0
    publish(api, admin, "0.9.0", min_from="0.2.0")
    # Not reachable in one step from 0.1.0: the stepping stone is offered instead of nothing.
    assert offered(api, token) == "0.2.0"
    assert beat(api, token, report(), agent_version="0.2.0").status_code == 200
    assert offered(api, token) == "0.10.0"
    assert beat(api, token, report(), agent_version="0.10.0").status_code == 200
    assert offered(api, token) is None

    # A version the server cannot compare is offered nothing rather than something wrong.
    for unknown in ("", "0.2.0-dev", "v0.2.0", "0.2", "unknown"):
        assert beat(api, token, report(), agent_version=unknown).status_code == 200
        assert offered(api, token) is None, unknown
    # The version comes from the device's heartbeat, where an agent always sends it; not from
    # the appliance report.
    said = report(update={"current_version": "0.1.0", "state": "idle", "target_version": "", "detail": ""})
    assert beat(api, token, said, agent_version="0.10.0").status_code == 200
    assert offered(api, token) is None


def test_only_ready_releases_of_the_machines_own_channel_are_offered(api, world):
    admin = world.auth(world.user("admin"))
    stable_machine, stable, _ = on_channel(world, api, "stable")
    beta_machine, beta, _ = on_channel(world, api, "beta")
    publish(api, admin, "0.2.0", channels=("stable",))
    publish(api, admin, "0.3.0", channels=("beta",))
    publish(api, admin, "0.4.0", channels=())  # ready, on no channel
    assert (
        api.post("/api/v1/releases", headers=admin, json=build("0.5.0")["body"]).status_code == 201
    )  # no package
    assert (offered(api, stable), offered(api, beta)) == ("0.2.0", "0.3.0")

    def download(token: str, version: str) -> int:
        return api.get(f"/api/v1/device/update/artifact/{version}", headers=bearer(token)).status_code

    assert {v: download(stable, v) for v in ("0.2.0", "0.3.0", "0.4.0", "0.5.0", "9.9.9")} == {
        "0.2.0": 200,
        "0.3.0": 404,  # another channel's release
        "0.4.0": 404,
        "0.5.0": 404,
        "9.9.9": 404,
    }
    assert {v: download(beta, v) for v in ("0.2.0", "0.3.0")} == {"0.2.0": 404, "0.3.0": 200}
    for not_a_version in ("latest", "0.2", "0.2.0.0", "..%2F0.2.0", "0.2.0%00"):
        assert download(stable, not_a_version) in (404, 422), not_a_version

    # Moving a release between channels moves who gets it.
    assert (
        api.post(
            "/api/v1/releases/0.3.0/channels", headers=admin, json={"channels": ["beta", "stable"]}
        ).status_code
        == 200
    )
    assert offered(api, stable) == "0.3.0" and download(stable, "0.3.0") == 200
    assert (
        api.post("/api/v1/releases/0.3.0/channels", headers=admin, json={"channels": []}).status_code == 200
    )
    assert (offered(api, stable), offered(api, beta)) == ("0.2.0", None)
    assert download(beta, "0.3.0") == 404


def test_the_package_is_for_device_credentials_only(api, world):
    admin = world.auth(world.user("admin"))
    publish(api, admin, "0.2.0")
    machine, token, owner_headers = on_channel(world, api, "stable")
    issued = api_clients.create_client(
        world.session, world.settings, SYSTEM, name="all", scopes=list(API_CLIENT_SCOPES)
    )
    world.commit()
    for path in ("/api/v1/device/update", "/api/v1/device/update/artifact/0.2.0"):
        assert api.get(path, headers=bearer(token)).status_code == 200
        for who, headers in (
            ("admin", admin),
            ("owner", owner_headers),
            ("client", bearer(issued.token)),
            ("nobody", {}),
        ):
            r = api.get(path, headers=headers)
            assert r.status_code == 401 and code(r) == "device_unauthorized", f"{who} {path}"
    # People have no route to the bytes at all.
    for path in ("/api/v1/releases/0.2.0", "/api/v1/releases/0.2.0/artifact"):
        assert api.get(path, headers=admin).status_code in (404, 405)


def test_package_downloads_are_rate_limited_per_device(api, world):
    admin = world.auth(world.user("admin"))
    publish(api, admin, "0.2.0")
    _, token, _ = on_channel(world, api, "stable")
    _, other, _ = on_channel(world, api, "stable")
    path = "/api/v1/device/update/artifact/0.2.0"
    codes = [api.get(path, headers=bearer(token)).status_code for _ in range(ARTIFACT_DOWNLOADS_PER_HOUR + 2)]
    assert codes == [200] * ARTIFACT_DOWNLOADS_PER_HOUR + [429, 429]
    assert api.get(path, headers=bearer(other)).status_code == 200  # each device has its own count


def test_a_release_whose_signing_key_is_no_longer_trusted_is_not_distributed(world):
    """Taking a key out of HM_RELEASE_PUBLIC_KEYS stops everything signed with it."""
    with release_client() as client:
        admin = world.auth(world.user("admin"))
        publish(client, admin, "0.2.0")
        assert client.post("/api/v1/releases", headers=admin, json=build("0.3.0")["body"]).status_code == 201
        machine, token, owner_headers = on_channel(world, client, "stable")
        assert offered(client, token) == "0.2.0"
    other = base64.b64encode(os.urandom(32)).decode()
    for keys in ([], [other]):
        with appliance_client(release_public_keys=keys) as client:
            assert offered(client, token) is None
            assert (
                client.get("/api/v1/device/update/artifact/0.2.0", headers=bearer(token)).status_code == 404
            )
            r = client.post(url(machine, "/install-update"), headers=owner_headers, json={"version": "0.2.0"})
            assert r.status_code == 409 and "not offered" in r.json()["error"]["message"]
            assert upload(client, admin, "0.3.0", b"package 0.3.0").status_code == 409
            r = client.post("/api/v1/releases/0.2.0/channels", headers=admin, json={"channels": ["beta"]})
            assert r.status_code == 409 and "trusts" in r.json()["error"]["message"]
            # Taking it off every channel, and withdrawing it, still work.
            assert client.get("/api/v1/releases", headers=admin).status_code == 200
    with release_client() as client:
        assert offered(client, token) == "0.2.0"


def test_a_manifest_changed_in_the_database_is_not_distributed(api, world):
    """The stored manifest is checked against its signature again whenever a release is offered."""
    admin = world.auth(world.user("admin"))
    publish(api, admin, "0.2.0")
    _, token, _ = on_channel(world, api, "stable")
    assert offered(api, token) == "0.2.0"
    world.session.execute(text("UPDATE releases SET manifest = manifest || ' '::bytea"))
    world.commit()
    assert offered(api, token) is None
    assert api.get("/api/v1/device/update/artifact/0.2.0", headers=bearer(token)).status_code == 404


# --- installing: a typed operation -----------------------------------------


def test_installing_a_release_is_a_typed_operation_requested_by_an_administrator(api, world):
    admin = world.auth(world.user("admin"))
    publish(api, admin, "0.2.0", min_from="0.1.0")
    owner = world.owner()
    machine, token, h = on_channel(world, api, "stable", owner=owner)
    org_admin = world.user("owner", owner)

    r = api.post(url(machine, "/install-update"), headers=world.auth(org_admin), json={"version": "0.2.0"})
    assert r.status_code == 201, r.text
    queued = r.json()
    assert queued["type"] == "install_update" and queued["params"] == {"version": "0.2.0"}
    assert queued["status"] == "pending" and queued["requested_by"] == str(org_admin.id)
    assert queued["safety"]["checks"] == {"disruptive": False}
    # The operation names a version. It carries no URL, no file name and no bytes.
    (delivered,) = beat(api, token, report(), agent_version="0.1.0").json()["operations"]
    assert delivered["type"] == "install_update" and delivered["params"] == {"version": "0.2.0"}
    assert audit_rows(world, "operation.request")[-1].details["params"] == {"version": "0.2.0"}

    operator = world.auth(world.user("owner", owner, org_role="org_operator"))
    assert (
        api.post(url(machine, "/install-update"), headers=operator, json={"version": "0.2.0"}).status_code
        == 403
    )
    # HappyMining staff install on a machine they manage.
    assert (
        api.post(url(machine, "/install-update"), headers=admin, json={"version": "0.2.0"}).status_code == 201
    )
    for malformed in (
        {},
        {"version": 2},
        {"version": "0.2.0", "url": "https://evil.example/pkg.deb"},
        {"version": "x" * 30},
    ):
        assert api.post(url(machine, "/install-update"), headers=h, json=malformed).status_code == 422


def test_an_update_that_could_not_be_installed_is_refused_instead_of_queued(api, world):
    admin = world.auth(world.user("admin"))
    publish(api, admin, "0.1.0")
    publish(api, admin, "0.2.0", min_from="0.1.0")
    publish(api, admin, "0.4.0", min_from="0.3.0")
    publish(api, admin, "0.5.0", channels=("beta",))
    publish(api, admin, "0.6.0", channels=())
    assert api.post("/api/v1/releases", headers=admin, json=build("0.7.0")["body"]).status_code == 201
    machine, token, h = on_channel(world, api, "stable", agent_version="0.1.0")

    def install(version: str, headers=h, target=machine):
        return api.post(url(target, "/install-update"), headers=headers, json={"version": version})

    for version, status, fragment in (
        ("9.9.9", 404, "no such release"),
        ("latest", 404, "no such release"),
        ("0.7.0", 409, "awaiting artifact"),
        ("0.1.0", 409, "only a newer release can be installed, never an older one"),  # what it runs
        ("0.4.0", 409, "can only be installed over 0.3.0 or newer"),
        ("0.5.0", 409, "not offered on this machine's update channel (stable)"),
        ("0.6.0", 409, "not offered on this machine's update channel (stable)"),
    ):
        r = install(version)
        assert r.status_code == status and fragment in r.json()["error"]["message"], f"{version}: {r.text}"

    assert beat(api, token, report(), agent_version="0.3.0").status_code == 200
    r = install("0.2.0")  # a downgrade
    assert r.status_code == 409 and "never an older one" in r.json()["error"]["message"]
    assert beat(api, token, report(), agent_version="nightly").status_code == 200
    assert "cannot be compared" not in install("0.4.0").text and install("0.4.0").status_code == 409

    no_channel, _, h2 = on_channel(world, api, "none")
    r = install("0.2.0", h2, no_channel)
    assert r.status_code == 409 and "update channel (none)" in r.json()["error"]["message"]
    unpaired = world.pairing(world.owner()).machine
    r = install("0.2.0", admin, unpaired)
    assert r.status_code == 409 and "no active paired device" in r.json()["error"]["message"]

    world.session.expire_all()
    assert world.session.execute(select(Operation)).first() is None
    # With the right version and channel it goes through.
    assert beat(api, token, report(), agent_version="0.3.0").status_code == 200
    assert install("0.4.0").status_code == 201


def test_only_the_release_the_machine_is_offered_can_be_installed(api, world):
    """The machine receives the newest release its channel offers it, with that release's
    manifest and signature: asked to install another one, it could only fail."""
    admin = world.auth(world.user("admin"))
    publish(api, admin, "0.2.0", min_from="0.1.0")
    publish(api, admin, "0.3.0", min_from="0.1.0")
    machine, _, h = on_channel(world, api, "stable", agent_version="0.1.0")
    r = api.post(url(machine, "/install-update"), headers=h, json={"version": "0.2.0"})
    assert r.status_code == 409 and "offered (0.3.0)" in r.json()["error"]["message"], r.text
    assert api.post(url(machine, "/install-update"), headers=h, json={"version": "0.3.0"}).status_code == 201


# --- the signing tool ------------------------------------------------------


def tool(*args: object, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SIGN_TOOL), *map(str, args)], capture_output=True, text=True, cwd=cwd, timeout=60
    )


def keygen(directory: Path) -> tuple[Path, Path]:
    out = tool("keygen", "--out", directory)
    assert out.returncode == 0, out.stderr
    (private,) = directory.glob("*.key")
    (public,) = directory.glob("*.pub")
    return private, public


def test_keygen_writes_a_private_key_only_its_owner_can_read_and_the_public_key_the_agent_installs(tmp_path):
    private, public = keygen(tmp_path / "keys")
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "keys").stat().st_mode) == 0o700
    raw = base64.b64decode(public.read_text().strip(), validate=True)
    assert len(raw) == 32 and public.read_text().endswith("\n") and len(public.read_text().splitlines()) == 1
    key_id = sealing.release_key_id(raw)
    assert (
        private.name == f"happymining-release-{key_id}.key"
        and public.name == f"happymining-release-{key_id}.pub"
    )
    # The same text is what HM_RELEASE_PUBLIC_KEYS takes.
    assert list(sealing.load_release_public_keys([public.read_text().strip()])) == [key_id]
    assert make_settings(release_public_keys=public.read_text().strip()).problems() == []
    # A second run makes a second key; nothing is overwritten.
    keygen(tmp_path / "keys2")
    assert len(list((tmp_path / "keys").iterdir())) == 2


def test_keygen_refuses_to_write_a_signing_key_into_a_repository(tmp_path):
    for inside in (REPO / "dist" / "release-keys-test", REPO / "scripts" / "k", REPO):
        out = tool("keygen", "--out", inside)
        assert out.returncode == 1 and "never written into a repository" in out.stderr, inside
        assert not list(inside.glob("happymining-release-*")), inside
    assert not (REPO / "dist" / "release-keys-test").exists() and not (REPO / "scripts" / "k").exists()
    # Any working tree, not only this one.
    other = tmp_path / "other-project"
    (other / ".git").mkdir(parents=True)
    out = tool("keygen", "--out", other / "keys")
    assert out.returncode == 1 and not (other / "keys").exists()
    out = tool("keygen", "--out", "keys", cwd=other)  # a relative path is resolved first
    assert out.returncode == 1 and not (other / "keys").exists()


def test_a_release_signed_with_the_tool_is_accepted_by_the_api_and_verifiable(tmp_path, world):
    private, public = keygen(tmp_path / "keys")
    package = tmp_path / "happymining-agent_0.3.0_amd64.deb"
    package.write_bytes(os.urandom(5000))
    out = tool(
        "manifest", "--deb", package, "--version", "0.3.0", "--min-upgrade-from", "0.2.0",
        "--notes", "Adds the appliance.", "--key", private, "--out", tmp_path / "out",
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    raw = (tmp_path / "out" / "manifest.json").read_bytes()
    signature = (tmp_path / "out" / "manifest.sig").read_text().strip()
    document = json.loads(raw)
    assert document == {
        "schema": 1,
        "product": "happymining-agent",
        "version": "0.3.0",
        "created_at": document["created_at"],
        "artifact": {
            "filename": "happymining-agent_0.3.0_amd64.deb",
            "size": 5000,
            "sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
        },
        "min_upgrade_from": "0.2.0",
        "notes": "Adds the appliance.",
    }
    assert document["created_at"].endswith("Z") and len(raw) < 16 * 1024

    # The reference implementation accepts it...
    key = public.read_text().strip()
    manifest = sealing.verify_manifest(raw, signature, sealing.load_release_public_keys([key]))
    assert (manifest.version, manifest.size, manifest.min_upgrade_from) == ("0.3.0", 5000, "0.2.0")
    # ...the tool's own check does, and notices a package or a manifest that is not the signed one...
    check = (
        "verify",
        "--manifest",
        tmp_path / "out" / "manifest.json",
        "--signature",
        tmp_path / "out" / "manifest.sig",
        "--pub",
        public,
    )
    assert tool(*check, "--deb", package).returncode == 0
    other_package = tmp_path / "other.deb"
    other_package.write_bytes(package.read_bytes()[:-1] + b"x")
    assert tool(*check, "--deb", other_package).returncode == 1
    _, other_public = keygen(tmp_path / "other-keys")
    wrong_key = tool(
        "verify",
        "--manifest",
        tmp_path / "out" / "manifest.json",
        "--signature",
        tmp_path / "out" / "manifest.sig",
        "--pub",
        other_public,
    )
    assert wrong_key.returncode == 1 and "does NOT verify" in wrong_key.stderr
    (tmp_path / "tampered.json").write_bytes(raw.replace(b"0.3.0", b"0.3.1"))
    assert (
        tool(
            "verify",
            "--manifest",
            tmp_path / "tampered.json",
            "--signature",
            tmp_path / "out" / "manifest.sig",
            "--pub",
            public,
        ).returncode
        == 1
    )

    # ...and so does the API, once the public key is configured, and only then.
    body = {"manifest_b64": base64.b64encode(raw).decode(), "signature_b64": signature}
    admin = world.auth(world.user("admin"))
    with release_client() as client:  # trusts another key
        assert client.post("/api/v1/releases", headers=admin, json=body).status_code == 400
    with appliance_client(release_public_keys=[key]) as client:
        assert client.post("/api/v1/releases", headers=admin, json=body).status_code == 201
        r = upload(client, admin, "0.3.0", package.read_bytes())
        assert (
            r.status_code == 200 and r.json()["status"] == "ready" and r.json()["key_id"] == manifest.key_id
        )
    # The private key was never anywhere but in its file.
    assert private.read_bytes() not in raw and "PRIVATE KEY" not in out.stdout + out.stderr


def test_the_tool_refuses_what_it_should_not_sign(tmp_path):
    private, _ = keygen(tmp_path / "keys")
    package = tmp_path / "happymining-agent_0.3.0_amd64.deb"
    package.write_bytes(b"deb")
    base = ["--key", private, "--out", tmp_path / "out"]
    wrong_name = tmp_path / "something.deb"
    wrong_name.write_bytes(b"deb")
    empty = tmp_path / "empty" / "happymining-agent_0.3.0_amd64.deb"
    empty.parent.mkdir()
    empty.write_bytes(b"")
    not_a_key = tmp_path / "not-a-key.pem"
    not_a_key.write_text("hello")
    for why, args in {
        "a file that is not the package of this version": ["--deb", wrong_name, "--version", "0.3.0", *base],
        "a version that is not one": ["--deb", package, "--version", "0.3", *base],
        "a version with a suffix": ["--deb", package, "--version", "0.3.0-rc1", *base],
        "min-upgrade-from newer than the release": [
            "--deb",
            package,
            "--version",
            "0.3.0",
            "--min-upgrade-from",
            "0.4.0",
            *base,
        ],
        "an empty package": ["--deb", empty, "--version", "0.3.0", *base],
        "a missing package": ["--deb", tmp_path / "nope" / package.name, "--version", "0.3.0", *base],
        "something that is not a key": [
            "--deb",
            package,
            "--version",
            "0.3.0",
            "--key",
            not_a_key,
            "--out",
            tmp_path / "out",
        ],
        "notes with control characters": ["--deb", package, "--version", "0.3.0", "--notes", "a\x07b", *base],
    }.items():
        out = tool("manifest", *args)
        assert out.returncode == 1 and out.stderr.startswith("release-sign: "), (
            f"{why}: {out.returncode} {out.stderr}"
        )
    assert not (tmp_path / "out").exists()
    assert tool().returncode == 2 and tool("sign-anything").returncode == 2
