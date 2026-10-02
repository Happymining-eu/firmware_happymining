"""The appliance configuration of a machine (docs/appliance.md, sections 2, 4, 7 and 12).

The plugin catalog, the desired-state document and its validation, every
route with who may call it, optimistic concurrency, the rental-protection gate
on leaving ``vast`` mode, sealed secrets that never show up anywhere, and what
happens to a configuration when a machine changes owner.

The device side (heartbeat, reported state, updates) is in
``test_appliance_device.py``; releases are in ``test_releases.py``.
"""

from __future__ import annotations

import itertools
import json
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import BASE_URL, IDLE_UNLISTED, SYSTEM, World, dataset, make_settings, sample
from sqlalchemy import select, text

from happymining import sealing
from happymining.config import Settings
from happymining.errors import InvalidRequest
from happymining.main import create_app
from happymining.models import (
    API_CLIENT_SCOPES,
    AuditLog,
    Machine,
    MachineAppliance,
    Operation,
    RemoteAccessGrant,
    utcnow,
)
from happymining.services import api_clients, operations, provider_sync
from happymining.services import appliance as appliance_service
from happymining.services import catalog as catalog_service
from happymining.services import machines as machine_service
from happymining.services.maintenance import DISRUPTIVE_TYPES, GATED_ACTIONS, LEAVE_VAST_MODE, evaluate

REPO = Path(__file__).resolve().parents[2]
TESTDATA = REPO / "appliance" / "testdata"
FIXTURE_CATALOG = TESTDATA / "catalog"
DOCUMENTS = TESTDATA / "documents"
SEAL_VECTORS = json.loads((TESTDATA / "seal-vectors.json").read_text())
SEAL_KEY = SEAL_VECTORS["machine_public_key"]
FIXTURE_PLUGINS = ("assistant", "ollama", "qdrant", "vectorizer")
UUID0 = "00000000-0000-0000-0000-000000000000"

NAS_DOCS = {"kind": "smb", "host": "nas.lan", "share": "documents", "username": "indexer", "access": "read"}
NAS_PUBLIC = {"kind": "smb", "host": "10.0.0.5", "share": "Public Share", "username": "", "access": "read"}
NAS_BACKUP = {"kind": "nfs", "host": "192.168.1.20", "export": "/volume1/backup", "access": "write"}
VECTORIZER = {
    "sources": ["docs"],
    "extensions": ["pdf", "md", "txt"],
    "exclude": ["#recycle"],
    "max_file_mib": 64,
    "embedding_model": "bge-m3",
    "ocr": False,
    "answer": {"provider": "none"},
}
BACKUP_TO_NAS = {
    "enabled": True,
    "destination": {"kind": "nas", "nas_id": "bk", "subpath": "happymining"},
    "include_models": False,
    "keep": 7,
}
BACKUP_TO_S3 = {
    "enabled": True,
    "destination": {
        "kind": "s3",
        "endpoint": "https://s3.eu-central-1.amazonaws.com",
        "region": "eu-central-1",
        "bucket": "acme-hm-backups",
        "prefix": "site1/",
        "access_key_id": "AKIAEXAMPLEKEY000001",
    },
    "include_models": False,
    "keep": 7,
}
NIGHTLY = {"job": "vectorize_sync", "every": "daily", "hour": 2, "minute": 30, "enabled": True}
ACTIVE_CONTRACT = {
    "state": "active_contracts",
    "listed": False,
    "active_contracts": 1,
    "stopped_instances": 0,
    "stored_data": True,
}
STATE_UNKNOWN = {
    "state": "unknown",
    "listed": None,
    "active_contracts": None,
    "stopped_instances": None,
    "stored_data": None,
}

_seq = itertools.count(1)


# --- helpers (also used by test_appliance_device.py and test_releases.py) ----


def appliance_settings(**overrides: object) -> Settings:
    """The test settings with the fixture catalog instead of the one shipped with the code."""
    return make_settings(**{"catalog_dir": str(FIXTURE_CATALOG), **overrides})


@contextmanager
def appliance_client(**overrides: object) -> Iterator[TestClient]:
    with TestClient(create_app(appliance_settings(**overrides)), base_url=BASE_URL) as client:
        yield client


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def envelope(response) -> dict[str, str]:
    body = response.json()
    assert set(body) == {"error"}, body
    return {k: v for k, v in body["error"].items() if k != "request_id"}


def code(response) -> str:
    return response.json()["error"]["code"]


def seal(name: str, plaintext: bytes = b"correct horse battery staple") -> str:
    return sealing.seal(SEAL_KEY, name, plaintext)


def report(**changes: Any) -> dict[str, Any]:
    """What an agent that knows about the appliance says in a heartbeat."""
    return {
        "schema": 1,
        "control": "cloud",
        "applied_revision": 0,
        "apply_status": "applied",
        "apply_detail": "",
        "mode": "vast",
        "seal_public_key": SEAL_KEY,
        "capabilities": {"plugins": True, "nas": True, "backup": True, "update": True, "docker": True},
        "catalog": [{"id": plugin, "version": "1"} for plugin in FIXTURE_PLUGINS],
        **changes,
    }


def beat(client: TestClient, token: str, appliance: dict | None = None, *, agent_version: str = "0.2.0"):
    """One heartbeat. Without ``appliance`` it is exactly what agent 0.1.0 sends."""
    body: dict[str, Any] = {
        "sent_at": datetime.now(UTC).isoformat(),
        "boot_id": "b",
        "agent_version": agent_version,
        "samples": [sample(next(_seq))],
    }
    if appliance is not None:
        body["appliance"] = appliance
    return client.post("/api/v1/device/heartbeat", headers=bearer(token), json=body)


def reporting_machine(world: World, client: TestClient, owner=None, **changes: Any):
    """A paired machine whose agent has reported its sealing key and catalog. Returns (machine, token)."""
    machine, token = world.paired_machine(owner or world.owner())
    assert beat(client, token, report(**changes)).status_code == 200
    return machine, token


def url(machine, suffix: str = "") -> str:
    return f"/api/v1/machines/{machine.id}/appliance{suffix}"


def stored(world: World, machine) -> MachineAppliance:
    world.session.expire_all()
    return world.session.execute(
        select(MachineAppliance).where(MachineAppliance.machine_id == machine.id)
    ).scalar_one()


def audit_rows(world: World, action: str | None = None) -> list[AuditLog]:
    world.session.expire_all()
    query = select(AuditLog).order_by(AuditLog.id)
    if action is not None:
        query = query.where(AuditLog.action == action)
    return list(world.session.execute(query).scalars())


def set_management(world: World, machine, management: str) -> None:
    world.session.execute(
        text("UPDATE machines SET management = :m WHERE id = :id"), {"m": management, "id": machine.id}
    )
    world.commit()
    world.session.refresh(machine)


def grant(world: World, machine, level: str, *, hours: float | None = None, revoked: bool = False):
    """A remote-access grant written straight into the database, as an org_admin would issue it."""
    org_admin = world.user("owner", world.session.get(Machine, machine.id).owner)
    row = RemoteAccessGrant(
        machine_id=machine.id,
        owner_id=machine.owner_id,
        level=level,
        reason="test",
        granted_by=org_admin.id,
        expires_at=utcnow() + timedelta(hours=hours) if hours is not None else None,
        revoked_at=utcnow() if revoked else None,
        revoked_by=org_admin.id if revoked else None,
    )
    world.session.add(row)
    world.commit()
    return row


def bound_machine(world: World, client: TestClient, rental: dict | None = None):
    """A reporting machine bound to provider machine 101. Returns (machine, token, provider)."""
    provider = world.provider(dataset({"101": {"rental": rental} if rental else dict(IDLE_UNLISTED)}, {}))
    account = world.account(provider)
    machine, token = reporting_machine(world, client)
    world.bind(account, "101", machine)
    world.session.refresh(machine)
    return machine, token, provider


@pytest.fixture
def api() -> Iterator[TestClient]:
    with appliance_client() as client:
        yield client


@pytest.fixture
def catalog():
    return catalog_service.load_catalog(FIXTURE_CATALOG)


# =============================================================================
# The plugin catalog (section 7, plugin.json)
# =============================================================================


def plugin_json(**changes: Any) -> dict[str, Any]:
    base = json.loads((FIXTURE_CATALOG / "assistant" / "plugin.json").read_text())
    base.update({"requires": [], **changes})
    return base


def write_catalog(root: Path, entries: dict[str, Any]) -> Path:
    for name, content in entries.items():
        (root / name).mkdir(parents=True, exist_ok=True)
        text_ = content if isinstance(content, str) else json.dumps(content)
        (root / name / "plugin.json").write_text(text_)
    return root


def test_the_fixture_catalog_loads_and_describes_its_plugins(catalog):
    assert sorted(entry.id for entry in catalog) == sorted(FIXTURE_PLUGINS) and len(catalog) == 4
    assert "ollama" in catalog and "nope" not in catalog and catalog.get("nope") is None
    assistant = catalog.get("assistant")
    assert assistant.requires == ("ollama",) and assistant.modes == ("private_ai",) and not assistant.gpu
    assert assistant.secret_names().keys() == {"plugin.assistant.api_key"}
    assert assistant.images_verified is True
    assert catalog.get("vectorizer").images_verified is False  # its base image has no verified digest
    public = assistant.public()
    assert public == {
        "id": "assistant",
        "version": "3",
        "name": "Assistant (fixture)",
        "summary": "An agent with a web page.",
        "homepage": "https://example.invalid/assistant",
        "license": "MIT",
        "gpu": False,
        "modes": ["private_ai"],
        "requires": ["ollama"],
        "ports": [{"name": "web", "port": 18789, "protocol": "http", "ui": True}],
        "settings": {
            "bind": {
                "type": "enum",
                "label": "Reachable from",
                "default": "lan",
                "values": ["lan", "localhost"],
            },
            "workers": {"type": "int", "label": "Workers", "default": 2, "min": 1, "max": 8},
            "telemetry": {"type": "bool", "label": "Send usage statistics", "default": False},
            "model": {
                "type": "string",
                "label": "Default model",
                "default": "hermes3:8b",
                "pattern": "^[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?$",
                "max_len": 100,
            },
        },
        "secrets": [
            {
                "key": "api_key",
                "name": "plugin.assistant.api_key",
                "label": "Cloud API key",
                "required": False,
            }
        ],
        "images_verified": True,
    }
    # What the panel gets says nothing about how the plugin is run on the machine.
    dumped = json.dumps(catalog.public())
    for internal in ("HM_SET_", "ASSISTANT_API_KEY", "ghcr.io", "sha256:", "post_start", "ollama pull"):
        assert internal not in dumped


def test_a_missing_or_empty_catalog_directory_is_an_empty_catalog(tmp_path):
    assert len(catalog_service.load_catalog(tmp_path / "does-not-exist")) == 0
    assert len(catalog_service.load_catalog(tmp_path)) == 0
    (tmp_path / "README.md").write_text("not a plugin")
    (tmp_path / ".git").mkdir()
    (tmp_path / "__pycache__").mkdir()
    assert catalog_service.load_catalog(tmp_path).public() == []


def test_the_catalog_shipped_with_the_code_is_valid_whatever_it_holds():
    """``appliance/catalog`` is what a deployed API offers. Empty is fine; broken is not."""
    assert catalog_service.SHIPPED_CATALOG_DIR == REPO / "appliance" / "catalog"
    assert catalog_service.catalog_dir(make_settings(catalog_dir="")) == REPO / "appliance" / "catalog"
    shipped = catalog_service.load_catalog(catalog_service.SHIPPED_CATALOG_DIR)
    for entry in shipped:
        assert entry.public()["id"] == entry.id
        assert "vast" not in entry.modes
        for other in entry.requires:
            assert other in shipped


def test_the_catalog_is_read_once_per_directory_until_reloaded(tmp_path):
    settings = make_settings(catalog_dir=str(write_catalog(tmp_path, {"assistant": plugin_json()})))
    first = catalog_service.get_catalog(settings)
    assert [entry.id for entry in first] == ["assistant"]
    write_catalog(tmp_path, {"other": plugin_json(id="other")})
    assert catalog_service.get_catalog(settings) is first  # still the one that was read
    assert sorted(e.id for e in catalog_service.reload(settings)) == ["assistant", "other"]
    assert len(catalog_service.get_catalog(settings)) == 2
    assert catalog_service.reload() is None
    # Another directory is another catalog.
    assert len(catalog_service.get_catalog(appliance_settings())) == 4


BROKEN_PLUGINS = {
    "unknown key": dict(command="rm -rf /"),
    "schema 2": dict(schema=2),
    "schema as a string": dict(schema="1"),
    "id is not the directory": dict(id="other"),
    "runs in vast mode": dict(modes=["vast", "private_ai"]),
    "no mode": dict(modes=[]),
    "mode listed twice": dict(modes=["private_ai", "private_ai"]),
    "requires itself": dict(requires=["assistant"]),
    "requires a plugin that is not there": dict(requires=["nope"]),
    "gpu as a string": dict(gpu="yes"),
    "no image": dict(images=[]),
    "image without a tag": dict(
        images=[{"ref": "ghcr.io/example/assistant", "digest": None, "verified": False}]
    ),
    "verified without a digest": dict(images=[{"ref": "x/y:1", "digest": None, "verified": True}]),
    "malformed digest": dict(images=[{"ref": "x/y:1", "digest": "sha256:abc", "verified": False}]),
    "port out of range": dict(ports=[{"name": "web", "port": 70000, "protocol": "http", "ui": True}]),
    "port as a string": dict(ports=[{"name": "web", "port": "80", "protocol": "http", "ui": True}]),
    "port with an unknown key": dict(
        ports=[{"name": "web", "port": 80, "protocol": "http", "ui": True, "x": 1}]
    ),
    "volume policy": dict(volumes=[{"name": "data", "backup": "sometimes"}]),
    "secret key": dict(secrets=[{"key": "API-KEY", "env": "A_KEY", "label": "x", "required": False}]),
    "secret env": dict(secrets=[{"key": "api_key", "env": "lower", "label": "x", "required": False}]),
    "secret env reserved": dict(
        secrets=[{"key": "api_key", "env": "HM_BIND", "label": "x", "required": False}]
    ),
    "secret env shadows a setting": dict(
        secrets=[{"key": "api_key", "env": "HM_SET_BIND", "label": "x", "required": False}]
    ),
    "secret required as a string": dict(
        secrets=[{"key": "k", "env": "A_KEY", "label": "x", "required": "no"}]
    ),
    "build context with a path": dict(build={"context": "../etc", "image": "x/y:1"}),
    "post_start as a shell string": dict(post_start=[{"service": "assistant", "exec": "ollama pull x"}]),
    "post_start for_each of nothing": dict(
        post_start=[{"service": "assistant", "exec": ["pull", "{item}"], "for_each": "models"}]
    ),
    "post_start item without for_each": dict(
        post_start=[{"service": "assistant", "exec": ["pull", "{item}"]}]
    ),
    "post_start for_each of a string": dict(
        post_start=[{"service": "assistant", "exec": ["pull", "{item}"], "for_each": "model"}]
    ),
}


@pytest.mark.parametrize("why", sorted(BROKEN_PLUGINS))
def test_a_broken_catalog_entry_is_an_error_for_the_whole_catalog(tmp_path, why):
    write_catalog(tmp_path, {"qdrant": json.loads((FIXTURE_CATALOG / "qdrant" / "plugin.json").read_text())})
    assert len(catalog_service.load_catalog(tmp_path)) == 1
    write_catalog(tmp_path, {"assistant": plugin_json(**BROKEN_PLUGINS[why])})
    with pytest.raises(catalog_service.CatalogError, match=r"assistant/plugin\.json") as caught:
        catalog_service.load_catalog(tmp_path)
    assert caught.value.status_code == 500 and caught.value.code == "catalog_invalid"


def test_catalog_files_must_be_strict_json(tmp_path):
    good = json.dumps(plugin_json())
    for why, content in {
        "not json": "{",
        "a list": "[]",
        "duplicate key": good[:-1] + ', "gpu": true}',
        "not a number": good.replace('"version": "3"', '"version": NaN'),
        "too large": good[:-1] + ', "summary": "' + "x" * 70000 + '"}',
    }.items():
        root = tmp_path / why.replace(" ", "-")
        write_catalog(root, {"assistant": content})
        with pytest.raises(catalog_service.CatalogError):
            catalog_service.load_catalog(root)
    (tmp_path / "empty" / "assistant").mkdir(parents=True)
    with pytest.raises(catalog_service.CatalogError, match="is missing"):
        catalog_service.load_catalog(tmp_path / "empty")


def setting(**spec: Any) -> dict[str, Any]:
    return plugin_json(settings={"x": {"label": "X", "env": "HM_SET_X", **spec}})


BROKEN_SETTINGS = {
    "unknown type": dict(type="float", default=1.5),
    "no label": dict(type="bool", default=True, label=""),
    "env without the prefix": dict(type="bool", default=True, env="X"),
    "env in lower case": dict(type="bool", default=True, env="HM_SET_x"),
    "bool default": dict(type="bool", default="true"),
    "bool with a pattern": dict(type="bool", default=True, pattern="^a$"),
    "int without bounds": dict(type="int", default=1),
    "int bounds reversed": dict(type="int", default=1, min=5, max=1),
    "int default outside": dict(type="int", default=9, min=1, max=8),
    "int default is a boolean": dict(type="int", default=True, min=0, max=8),
    "enum without values": dict(type="enum", default="a", values=[]),
    "enum default not a value": dict(type="enum", default="c", values=["a", "b"]),
    "enum value with a dollar": dict(type="enum", default="a", values=["a", "$HOME"]),
    "enum value twice": dict(type="enum", default="a", values=["a", "a"]),
    "string without a pattern": dict(type="string", default="a", max_len=10),
    "string without max_len": dict(type="string", default="a", pattern="^[a-z]+$"),
    "string max_len above 200": dict(type="string", default="a", pattern="^[a-z]+$", max_len=201),
    "string default does not match": dict(type="string", default="A", pattern="^[a-z]+$", max_len=10),
    "string default too long": dict(type="string", default="abc", pattern="^[a-z]+$", max_len=2),
    "list max_items above 32": dict(type="string_list", default=[], pattern="^[a-z]+$", max_items=33),
    "list default is a string": dict(type="string_list", default="a", pattern="^[a-z]+$", max_items=4),
    "list default too long": dict(type="string_list", default=["a", "b"], pattern="^[a-z]+$", max_items=1),
}


@pytest.mark.parametrize("why", sorted(BROKEN_SETTINGS))
def test_a_setting_must_be_fully_and_consistently_declared(tmp_path, why):
    write_catalog(tmp_path, {"assistant": setting(**BROKEN_SETTINGS[why])})
    with pytest.raises(catalog_service.CatalogError, match=r"settings\.x"):
        catalog_service.load_catalog(tmp_path)


@pytest.mark.parametrize(
    ("pattern", "for_list", "problem"),
    [
        # Could let a character through that breaks out of an environment file or a command line.
        ("^.*$", False, "construct"),
        ("^[^a]+$", False, "construct"),
        ("^[^ab]+$", False, "negated"),
        (r"^\S+$", False, "character class"),
        (r"^\s*$", False, "character class"),
        (r"^[a-z\s]+$", False, "character class"),
        ("^[a-z$]+$", False, "can match '$'"),
        (r"^a\$b$", False, "can match '$'"),
        ('^[a-z"]+$', False, "can match '\"'"),
        ("^[a-z']+$", False, 'can match "\'"'),
        ("^[a-z`]+$", False, "can match '`'"),
        (r"^[a-z\\]+$", False, "can match"),
        ("^[A-z]+$", False, "range that includes"),  # A-z spans [ \ ] ^ _ `
        ("^[ -~]+$", False, "range that includes"),
        ("^[a-z\n]+$", False, "control character"),
        (r"^[a-z\t]+$", False, "control character"),
        ("^[\x00-z]+$", False, "range that includes"),
        ("^(a|b|\\$)+$", False, "can match '$'"),
        ('^(?:a|[b-d]|(e["]))$', False, "can match"),
        # A list travels as one space-separated variable.
        ("^[a-z ]+$", True, "can match a space"),
        ("^a b$", True, "can match a space"),
        # Not anchored: an implementation that searches instead of matching would accept anything.
        ("[a-z]+", False, "anchored"),
        ("^[a-z]+", False, "anchored"),
        ("[a-z]+$", False, "anchored"),
        (r"^[a-z]+\$", False, "anchored"),
        # Flags, look-around and back-references change what a pattern means between languages.
        ("(?i)^[a-z]+$", False, "anchored"),
        ("^(?i:[a-z]+)$", False, "flags"),
        ("^(?=a)[a-z]+$", False, "construct"),
        (r"^([a-z])\1$", False, "construct"),
        (r"^\bfoo$", False, "assertion"),
        ("^[a-z+$", False, "not a valid regular expression"),
        ("", False, "2 to 300"),
        (None, False, "2 to 300"),
    ],
)
def test_a_setting_pattern_that_could_let_a_dangerous_character_through_is_refused(
    pattern, for_list, problem
):
    found = catalog_service.pattern_problem(pattern, for_list=for_list)
    assert found is not None and problem in found, found


@pytest.mark.parametrize(
    ("pattern", "for_list"),
    [
        ("^[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?$", True),
        ("^[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?$", False),
        (r"^\d{1,5}$", True),
        (r"^\w+$", True),
        ("^[A-Za-z0-9 ._-]{1,40}$", False),  # a space is fine in a single string
        ("^(lan|localhost)$", True),
        ("^a{2,3}?b*c+$", True),
        ("^https://[a-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$", False),
    ],
)
def test_ordinary_patterns_are_accepted(pattern, for_list):
    assert catalog_service.pattern_problem(pattern, for_list=for_list) is None


def test_a_setting_value_is_checked_twice_by_the_pattern_and_by_the_forbidden_characters(tmp_path):
    write_catalog(
        tmp_path,
        {
            "assistant": plugin_json(
                settings={
                    "name": {
                        "type": "string",
                        "label": "Name",
                        "env": "HM_SET_NAME",
                        "pattern": "^[A-Za-z ]{0,20}$",
                        "max_len": 20,
                        "default": "",
                    },
                    "tags": {
                        "type": "string_list",
                        "label": "Tags",
                        "env": "HM_SET_TAGS",
                        "pattern": r"^\w{1,8}$",
                        "max_items": 2,
                        "default": [],
                    },
                }
            )
        },
    )
    entry = catalog_service.load_catalog(tmp_path).get("assistant")
    name, tags = entry.settings["name"], entry.settings["tags"]
    assert name.problem("Ada Lovelace") is None and name.problem("") is None
    for bad in ("x" * 21, "ada1", "a\nb", "$x", 5, None, ["a"]):
        assert name.problem(bad) is not None
    assert tags.problem(["a_1", "b"]) is None and tags.problem([]) is None
    # \w is ASCII only here, as it is in the machine's helper.
    for bad in (["a b"], ["é"], ["a", "b", "c"], "a", [1], ["toolongvalue"], [""]):
        assert tags.problem(bad) is not None
    # A refusal never repeats the value.
    assert "hunter2" not in (name.problem("hunter2!") or "")


def test_a_plugin_secret_name_must_fit_in_a_secret_name(tmp_path):
    long_id = "a" + "b" * 30
    entry = plugin_json(
        id=long_id, secrets=[{"key": "k" * 31, "env": "A_KEY", "label": "x", "required": False}]
    )
    write_catalog(tmp_path, {long_id: entry})
    with pytest.raises(catalog_service.CatalogError, match="secret name"):
        catalog_service.load_catalog(tmp_path)


def test_a_broken_catalog_fails_the_routes_that_need_it_and_not_the_device(world, tmp_path):
    """A broken catalog must not be half used, and must not take telemetry down with it."""
    broken = write_catalog(tmp_path, {"assistant": plugin_json(command="x")})
    with appliance_client(catalog_dir=str(broken)) as client:
        machine, token = reporting_machine(world, client)
        h = world.auth(world.user("admin"))
        for response in (
            client.get("/api/v1/appliance/catalog", headers=h),
            client.get(url(machine), headers=h),
        ):
            assert response.status_code == 500 and code(response) == "catalog_invalid"
        refused = client.put(url(machine, "/mode"), headers=h, json={"mode": "private_ai"})
        assert refused.status_code == 500 and stored(world, machine).revision == 0
        assert beat(client, token, report()).status_code == 200


# =============================================================================
# The document (section 4)
# =============================================================================


def fixture_documents(kind: str) -> list[Any]:
    return [
        pytest.param(json.loads(path.read_text()), id=path.stem)
        for path in sorted((DOCUMENTS / kind).glob("*.json"))
    ]


def test_the_fixture_set_is_the_one_shared_with_the_agent():
    assert len(list((DOCUMENTS / "valid").glob("*.json"))) >= 16
    assert len(list((DOCUMENTS / "invalid").glob("*.json"))) >= 140


@pytest.mark.parametrize("fixture", fixture_documents("valid"))
def test_every_valid_fixture_is_accepted(catalog, fixture):
    appliance_service.validate_document(fixture["document"], catalog)


@pytest.mark.parametrize("fixture", fixture_documents("invalid"))
def test_every_invalid_fixture_is_refused(catalog, fixture):
    with pytest.raises(appliance_service.DocumentInvalid) as caught:
        appliance_service.validate_document(fixture["document"], catalog)
    assert caught.value.status_code == 400 and caught.value.code == "invalid_request", fixture["why"]
    # The reason names a place and a rule. It never repeats a sealed value or a clear-text one.
    assert "hmseal1." not in caught.value.message and "hunter2" not in caught.value.message


def full_document() -> dict[str, Any]:
    return json.loads((DOCUMENTS / "valid" / "full.json").read_text())["document"]


def refused(catalog, document: Any) -> str:
    with pytest.raises(appliance_service.DocumentInvalid) as caught:
        appliance_service.validate_document(document, catalog)
    return caught.value.message


def test_rules_the_fixtures_do_not_exercise(catalog):
    document = full_document()
    appliance_service.validate_document(document, catalog)

    for not_a_document in (None, [], "x", 12):
        assert "must be an object" in refused(catalog, not_a_document)

    big = full_document()
    big["vectorizer"]["exclude"] = [f"{'d' * 190}{i:04d}" for i in range(32)]
    big["nas"][0]["subpath"] = "/".join(["s" * 100] * 5)
    appliance_service.validate_document(big, catalog)  # large, and still under the limit
    padded = {**full_document(), "padding": "x" * (64 * 1024)}
    assert "larger than 64 KiB" in refused(catalog, padded)

    nested: Any = "x"
    for _ in range(12):
        nested = [nested]
    deep = full_document()
    deep["plugins"][0]["settings"]["models"] = nested
    assert "nested too deeply" in refused(catalog, deep)

    for where, change in {
        "revision": lambda d: d.update(revision=2**31),
        "vectorizer.extensions[1]": lambda d: d["vectorizer"].update(extensions=["pdf", "pdf"]),
        "vectorizer.exclude[1]": lambda d: d["vectorizer"].update(exclude=["a", "a"]),
        "vectorizer.exclude[0]": lambda d: d["vectorizer"].update(exclude=[""]),
        "vectorizer.answer.base_url": lambda d: d["vectorizer"]["answer"].update(base_url="https://h:0/v1"),
        "backup.destination.subpath": lambda d: d["backup"]["destination"].update(subpath="a/./b"),
        "nas[0].subpath": lambda d: d["nas"][0].update(subpath="x" * 513),
        "nas[0].username": lambda d: d["nas"][0].update(username="u" * 65),
        "nas[0].host": lambda d: d["nas"][0].update(host="h" * 254),
        "nas[1].export": lambda d: d["nas"][1].update(export="/a/../b"),
        "update.window": lambda d: d["update"].update(window={"start_hour": 2}),
        "update": lambda d: d["update"].pop("window"),
        "schedules[0].minute": lambda d: d["schedules"][0].update(minute=True),
        "plugins": lambda d: d.update(plugins=d["plugins"] * 9),
        "secrets": lambda d: d["secrets"].update({"Bad Name": d["secrets"]["nas.docs.password"]}),
        "document": lambda d: d.update({"bad\nkey": 1}),
        "mode": lambda d: d.update(mode=None),
    }.items():
        changed = full_document()
        change(changed)
        assert refused(catalog, changed).startswith(where + ":"), where

    for port in ("65536", "08", "0"):
        changed = full_document()
        changed["vectorizer"]["answer"]["base_url"] = f"https://api.example.com:{port}/v1"
        assert "base_url" in refused(catalog, changed)
    changed = full_document()
    changed["vectorizer"]["answer"]["base_url"] = "https://api.example.com:8443"
    appliance_service.validate_document(changed, catalog)

    # A lone surrogate is not text any implementation agrees on.
    changed = full_document()
    changed["nas"][0]["subpath"] = "a\ud800b"
    assert "not a JSON document" in refused(catalog, changed)


def test_a_required_plugin_secret_must_be_present_as_soon_as_the_plugin_is_listed(tmp_path):
    entry = plugin_json(secrets=[{"key": "api_key", "env": "A_KEY", "label": "Key", "required": True}])
    catalog = catalog_service.load_catalog(write_catalog(tmp_path, {"assistant": entry}))
    document = {
        "schema": 1,
        "revision": 1,
        "mode": "vast",
        "plugins": [{"id": "assistant", "enabled": False, "settings": {}}],
    }
    assert "the secret plugin.assistant.api_key is not in secrets" in refused(catalog, document)
    document["secrets"] = {"plugin.assistant.api_key": seal("plugin.assistant.api_key")}
    appliance_service.validate_document(document, catalog)
    # ...and goes with the plugin.
    document["plugins"] = []
    assert "nothing refers to this secret" in refused(catalog, document)


# =============================================================================
# Routes: the happy path (section 12)
# =============================================================================


def test_catalog_route_is_for_any_signed_in_user(api, world):
    owner = world.owner()
    assert api.get("/api/v1/appliance/catalog").status_code == 401
    users = [
        world.user("admin"),
        world.user("auditor"),
        *[world.user("owner", owner, org_role=role) for role in ("org_admin", "org_operator", "org_viewer")],
    ]
    for user in users:
        r = api.get("/api/v1/appliance/catalog", headers=world.auth(user))
        assert r.status_code == 200, r.text
        assert [item["id"] for item in r.json()["items"]] == sorted(FIXTURE_PLUGINS)
        assert r.json()["items"][0]["secrets"][0]["name"] == "plugin.assistant.api_key"


def test_a_machine_nothing_was_configured_for(api, world):
    owner = world.owner()
    machine, token = world.paired_machine(owner)
    h = world.auth(world.user("owner", owner))
    r = api.get(url(machine), headers=h)
    assert r.status_code == 200 and r.headers["etag"] == '"0"'
    assert r.json() == {
        "machine_id": str(machine.id),
        "management": "company",
        "revision": 0,
        "applied_revision": 0,
        "in_sync": True,
        "control": "cloud",
        "updated_at": None,
        "updated_by": None,
        "document": {"schema": 1, "mode": "vast", "plugins": [], "nas": [], "schedules": []},
        "secrets": [],
        "seal_public_key": None,
        "reported": None,
        "reported_at": None,
        "catalog": [
            {**entry, "on_machine": None, "machine_version": None}
            for entry in api.get("/api/v1/appliance/catalog", headers=h).json()["items"]
        ],
        "can_operate": True,
        "can_admin": True,
    }
    # Looking at it creates nothing.
    assert world.session.execute(select(MachineAppliance)).first() is None
    assert api.get(f"/api/v1/machines/{UUID0}/appliance", headers=h).status_code == 404

    # Once the agent has reported, the page knows the key to seal for and what the firmware has.
    assert beat(api, token, report(catalog=[{"id": "ollama", "version": "7"}])).status_code == 200
    seen = api.get(url(machine), headers=h).json()
    assert seen["seal_public_key"] == SEAL_KEY and seen["revision"] == 0 and seen["in_sync"] is True
    assert seen["reported"]["control"] == "cloud" and seen["reported_at"] is not None
    assert {e["id"]: (e["on_machine"], e["machine_version"]) for e in seen["catalog"]} == {
        "assistant": (False, None),
        "ollama": (True, "7"),
        "qdrant": (False, None),
        "vectorizer": (False, None),
    }


def test_an_administrator_configures_everything_and_takes_it_apart_again(api, world):
    owner = world.owner()
    machine, token = reporting_machine(world, api, owner)
    user = world.user("owner", owner)
    h = world.auth(user)

    def put(suffix: str, body: dict, expect: int):
        r = api.put(url(machine, suffix), headers=h, json=body)
        assert r.status_code == 200, f"{suffix}: {r.status_code} {r.text}"
        assert r.json()["revision"] == expect and r.headers["etag"] == f'"{expect}"'
        return r.json()

    def delete(suffix: str, expect: int):
        r = api.delete(url(machine, suffix), headers=h)
        assert r.status_code == 200, f"{suffix}: {r.status_code} {r.text}"
        assert r.json()["revision"] == expect
        return r.json()

    seen = put("/nas/docs", {**NAS_DOCS, "sealed_secret": seal("nas.docs.password")}, 1)
    assert seen["document"]["nas"] == [
        {
            "id": "docs",
            "kind": "smb",
            "host": "nas.lan",
            "share": "documents",
            "subpath": "",
            "username": "indexer",
            "domain": "",
            "access": "read",
            "secret": "nas.docs.password",
        }
    ]
    assert seen["secrets"] == ["nas.docs.password"] and seen["updated_by"] == str(user.id)
    put("/nas/bk", NAS_BACKUP, 2)
    put("/plugins/ollama", {"enabled": True, "settings": {"models": ["hermes3:8b", "bge-m3"]}}, 3)
    put("/plugins/qdrant", {"enabled": True}, 4)
    answer = {
        "provider": "anthropic",
        "model": "claude-sonnet-4-5",
        "sealed_secret": seal("ai.answer.api_key"),
    }
    seen = put("/vectorizer", {**VECTORIZER, "answer": answer}, 5)
    assert seen["document"]["vectorizer"]["answer"] == {
        "provider": "anthropic",
        "model": "claude-sonnet-4-5",
        "secret": "ai.answer.api_key",
    }
    put("/plugins/vectorizer", {"enabled": True, "settings": {}}, 6)
    put("/plugins/assistant", {"enabled": True, "settings": {"workers": 4}}, 7)
    seen = put(
        "/plugins/assistant",
        {"enabled": True, "sealed_secrets": {"api_key": seal("plugin.assistant.api_key")}},
        8,
    )
    assert seen["document"]["plugins"][3] == {"id": "assistant", "enabled": True, "settings": {}}
    put("/backup", BACKUP_TO_NAS, 9)
    s3 = {
        **BACKUP_TO_S3,
        "destination": {**BACKUP_TO_S3["destination"], "sealed_secret": seal("backup.s3.secret_key")},
    }
    seen = put("/backup", s3, 10)
    assert seen["document"]["backup"]["destination"]["secret"] == "backup.s3.secret_key"
    put("/schedules/nightly-sync", NIGHTLY, 11)
    put(
        "/schedules/restart-llm",
        {"job": "plugin_restart", "plugin": "ollama", "every": "hourly", "minute": 5, "enabled": False},
        12,
    )
    put("/update", {"channel": "stable", "policy": "auto", "window": {"start_hour": 2, "end_hour": 5}}, 13)
    seen = put("/mode", {"mode": "private_ai"}, 14)
    assert seen["secrets"] == [
        "ai.answer.api_key",
        "backup.s3.secret_key",
        "nas.docs.password",
        "plugin.assistant.api_key",
    ]
    assert seen["in_sync"] is False and seen["applied_revision"] == 0

    # What is stored is a document the machine's validator accepts, with its revision and secrets.
    row = stored(world, machine)
    assert "revision" not in row.document and "secrets" not in row.document
    whole = {**row.document, "revision": row.revision, "secrets": row.secrets}
    appliance_service.validate_document(whole, catalog_service.load_catalog(FIXTURE_CATALOG))
    assert sorted(row.secrets) == seen["secrets"] and all(
        v.startswith("hmseal1.") for v in row.secrets.values()
    )

    # Replacing an entry keeps its sealed value unless a new one is sent, it is no longer
    # needed, or the entry now points at another server (then it must be sent again:
    # test_a_stored_secret_is_not_carried_over_to_a_new_destination).
    before = dict(row.secrets)
    put("/nas/docs", {**NAS_DOCS, "subpath": "projects"}, 15)
    assert stored(world, machine).secrets == before
    put("/nas/docs", {**NAS_DOCS, "host": "nas2.lan", "sealed_secret": seal("nas.docs.password", b"new")}, 16)
    after = stored(world, machine).secrets
    assert after["nas.docs.password"] != before["nas.docs.password"]
    assert {k: v for k, v in after.items() if k != "nas.docs.password"} == {
        k: v for k, v in before.items() if k != "nas.docs.password"
    }
    seen = put("/nas/docs", {**NAS_DOCS, "username": ""}, 17)  # guest access: the password goes
    assert "nas.docs.password" not in seen["secrets"] and "secret" not in seen["document"]["nas"][0]
    seen = put("/vectorizer", VECTORIZER, 18)  # search only: the API key goes
    assert "ai.answer.api_key" not in seen["secrets"]
    seen = put("/plugins/assistant", {"enabled": False, "sealed_secrets": {"api_key": None}}, 19)
    assert "plugin.assistant.api_key" not in seen["secrets"]

    # The same request again changes nothing and does not count as a change.
    unchanged = api.put(url(machine, "/vectorizer"), headers=h, json=VECTORIZER)
    assert unchanged.status_code == 200 and unchanged.json()["revision"] == 19

    delete("/schedules/restart-llm", 20)
    delete("/schedules/nightly-sync", 21)
    seen = delete("/backup", 22)
    assert seen["secrets"] == [] and "backup" not in seen["document"]
    delete("/plugins/assistant", 23)
    delete("/plugins/vectorizer", 24)
    delete("/vectorizer", 25)
    delete("/plugins/ollama", 26)
    delete("/plugins/qdrant", 27)
    delete("/nas/docs", 28)
    delete("/nas/bk", 29)
    put("/update", {"channel": "none", "policy": "manual"}, 30)
    seen = put("/mode", {"mode": "vast"}, 31)
    assert seen["document"] == {
        "schema": 1,
        "mode": "vast",
        "plugins": [],
        "nas": [],
        "schedules": [],
        "update": {"channel": "none", "policy": "manual"},
    }

    # Every accepted change is on record, with who made it and what it touched, in order.
    rows = [
        r for r in audit_rows(world) if r.action.startswith("appliance.") and r.action != "appliance.seal_key"
    ]
    assert [r.details["revision"] for r in rows] == list(range(1, 32))
    assert {r.actor_id for r in rows} == {str(user.id)} and {r.owner_id for r in rows} == {owner.id}
    assert {r.object_id for r in rows} == {str(machine.id)}
    first = rows[0]
    assert first.action == "appliance.nas.set" and first.details == {
        "nas": "docs",
        "kind": "smb",
        "access": "read",
        "added": True,
        "changed": ["access", "domain", "host", "kind", "secret", "share", "subpath", "username"],
        "revision": 1,
        "sealed_set": ["nas.docs.password"],
        "sealed_removed": [],
    }
    assert rows[14].details["changed"] == ["host"] and rows[14].details["sealed_set"] == []
    assert rows[16].details["sealed_removed"] == ["nas.docs.password"]
    assert rows[13].action == "appliance.mode" and rows[13].details["from"] == "vast"
    assert rows[13].details["to"] == "private_ai" and rows[13].details["gate"] == {"checked": False}
    assert [r.action for r in rows[19:25]] == [
        "appliance.schedule.remove",
        "appliance.schedule.remove",
        "appliance.backup.remove",
        "appliance.plugin.remove",
        "appliance.plugin.remove",
        "appliance.vectorizer.remove",
    ]
    # The trail says which NAS entry changed, never where it points: staff who may not
    # read a customer's configuration can read the trail.
    assert "nas.lan" not in json.dumps([r.details for r in rows]) and "indexer" not in json.dumps(
        [r.details for r in rows]
    )


@pytest.mark.parametrize(
    ("suffix", "body", "where"),
    [
        ("/mode", {"mode": "mining"}, "mode"),
        ("/plugins/ollama", {"enabled": True, "settings": {"models": ["a b"]}}, "plugins[0].settings.models"),
        ("/plugins/ollama", {"enabled": True, "settings": {"command": "id"}}, "plugins[0].settings"),
        ("/plugins/assistant", {"enabled": True}, "plugins[0]"),  # requires ollama
        ("/plugins/vectorizer", {"enabled": False, "sealed_secrets": {"nope": None}}, "sealed_secrets"),
        ("/nas/docs", {**NAS_PUBLIC, "host": "-o"}, "nas[0].host"),
        (
            "/nas/docs",
            {**NAS_DOCS, "username": "indexer,uid=0", "sealed_secret": "SEALED"},
            "nas[0].username",
        ),
        ("/nas/docs", {**NAS_BACKUP, "username": "root"}, "nas[0]"),
        ("/nas/docs", NAS_DOCS, "sealed_secret"),  # a user name without its password
        ("/nas/docs", {**NAS_PUBLIC, "sealed_secret": "SEALED"}, "sealed_secret"),
        ("/nas/docs", {**NAS_BACKUP, "sealed_secret": "SEALED"}, "sealed_secret"),
        ("/nas/docs", {**NAS_DOCS, "sealed_secret": "hunter2"}, "this value is not sealed"),
        ("/vectorizer", VECTORIZER, "vectorizer.sources[0]"),  # no such NAS entry
        (
            "/vectorizer",
            {**VECTORIZER, "answer": {"provider": "openai_compatible", "model": "m"}},
            "sealed_secret",
        ),
        ("/backup", BACKUP_TO_NAS, "backup.destination.nas_id"),
        ("/backup", BACKUP_TO_S3, "sealed_secret"),
        ("/schedules/x", {**NIGHTLY, "every": "*/5 * * * *"}, "schedules[0].every"),
        ("/schedules/x", {**NIGHTLY, "job": "set_mode"}, "schedules[0].job"),
        (
            "/schedules/x",
            {"job": "plugin_restart", "plugin": "ollama", "every": "hourly", "minute": 1, "enabled": True},
            "schedules[0].plugin",
        ),
        ("/update", {"channel": "stable", "policy": "auto"}, "update"),
        ("/update", {"channel": "nightly", "policy": "manual"}, "update.channel"),
    ],
)
def test_a_change_that_would_make_the_document_invalid_is_refused_whole(api, world, suffix, body, where):
    owner = world.owner()
    machine, _ = reporting_machine(world, api, owner)
    h = world.auth(world.user("owner", owner))
    body = json.loads(json.dumps(body).replace("SEALED", seal("nas.docs.password")))
    r = api.put(url(machine, suffix), headers=h, json=body)
    assert r.status_code == 400 and code(r) == "invalid_request", r.text
    assert where in r.json()["error"]["message"], r.text
    assert "hunter2" not in r.text and "hmseal1." not in r.text
    row = stored(world, machine)
    assert row.revision == 0 and row.secrets == {} and row.document == appliance_service.default_document()
    assert not [
        a for a in audit_rows(world) if a.action.startswith("appliance.") and a.action != "appliance.seal_key"
    ]


@pytest.mark.parametrize(
    ("suffix", "body"),
    [
        ("/mode", {}),
        ("/mode", {"mode": "vast", "revision": 3}),
        ("/mode", {"mode": 1}),
        ("/plugins/ollama", {"enabled": "yes"}),
        ("/plugins/ollama", {"enabled": 1}),
        ("/plugins/ollama", {"enabled": True, "image": "evil/image"}),
        ("/plugins/ollama", {"enabled": True, "compose": "services: {}"}),
        ("/plugins/ollama", {"enabled": True, "secrets": {"api_key": "clear"}}),
        ("/plugins/Ollama", {"enabled": True}),
        ("/plugins/x.y", {"enabled": True}),
        ("/nas/docs", {**NAS_DOCS, "options": "rw,suid"}),
        ("/nas/docs", {**NAS_DOCS, "password": "hunter2"}),
        ("/nas/docs", {**NAS_DOCS, "secret": "nas.docs.password"}),
        ("/nas/docs", {**NAS_DOCS, "id": "other"}),
        ("/nas/" + "a" * 32, NAS_BACKUP),
        ("/vectorizer", {**VECTORIZER, "max_file_mib": "64"}),
        ("/vectorizer", {**VECTORIZER, "max_file_mib": 64.0}),
        ("/vectorizer", {**VECTORIZER, "ocr": 0}),
        ("/vectorizer", {**VECTORIZER, "answer": {"provider": "none", "api_key": "sk-clear"}}),
        ("/backup", {**BACKUP_TO_NAS, "passphrase": "x"}),
        ("/backup", {**BACKUP_TO_NAS, "keep": True}),
        ("/schedules/x", {**NIGHTLY, "command": "reboot"}),
        ("/schedules/x", {**NIGHTLY, "minute": "30"}),
        ("/update", {"channel": "stable", "policy": "manual", "url": "https://evil.example/pkg.deb"}),
    ],
)
def test_a_request_of_the_wrong_shape_is_refused_before_anything_is_read(api, world, suffix, body):
    """Unknown keys, coerced types, clear-text secret fields, ids that are not ids."""
    owner = world.owner()
    machine, _ = reporting_machine(world, api, owner)
    r = api.put(url(machine, suffix), headers=world.auth(world.user("owner", owner)), json=body)
    assert r.status_code == 422 and code(r) == "invalid_request", f"{r.status_code} {r.text}"
    assert "hunter2" not in r.text and "sk-clear" not in r.text
    assert stored(world, machine).revision == 0


def test_removing_what_is_not_there_is_not_found(api, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, api, owner)
    h = world.auth(world.user("owner", owner))
    for suffix in ("/plugins/ollama", "/nas/docs", "/vectorizer", "/backup", "/schedules/nightly"):
        r = api.delete(url(machine, suffix), headers=h)
        assert r.status_code == 404 and code(r) == "not_found", suffix
    assert api.put(url(machine, "/plugins/notthere"), headers=h, json={"enabled": False}).status_code == 404
    assert stored(world, machine).revision == 0


# =============================================================================
# Who may do what (section 3 and the table of section 12)
# =============================================================================

HOURLY = {"job": "update_check", "every": "hourly", "minute": 17, "enabled": True}
VECTORIZER_PUB = {**VECTORIZER, "sources": ["pub"]}
# (method, path under /appliance, body, the lowest organisation role that may). In an
# order in which each one succeeds on the machine prepared by ``prepared_machine``.
CHANGES = [
    ("PUT", "/mode", {"mode": "private_ai"}, "org_admin"),
    ("PUT", "/plugins/ollama", {"enabled": True}, "org_operator"),
    ("DELETE", "/plugins/qdrant", None, "org_operator"),
    ("PUT", "/nas/docs2", NAS_PUBLIC, "org_admin"),
    ("PUT", "/vectorizer", {**VECTORIZER_PUB, "ocr": True}, "org_admin"),
    ("DELETE", "/vectorizer", None, "org_admin"),
    ("DELETE", "/nas/pub", None, "org_admin"),
    ("PUT", "/backup", {**BACKUP_TO_NAS, "keep": 3}, "org_admin"),
    ("DELETE", "/backup", None, "org_admin"),
    ("PUT", "/schedules/hourly", HOURLY, "org_operator"),
    ("DELETE", "/schedules/old", None, "org_operator"),
    ("PUT", "/update", {"channel": "beta", "policy": "manual"}, "org_admin"),
    ("POST", "/jobs", {"job": "update_check"}, "org_operator"),
    ("POST", "/install-update", {"version": "9.9.9"}, "org_admin"),
]
RANK = {"org_viewer": 1, "org_operator": 2, "org_admin": 3}


def prepared_machine(world: World, client: TestClient, owner=None):
    """A machine with one of everything, so that each entry of CHANGES has something to act on."""
    owner = owner or world.owner()
    machine, token = reporting_machine(world, client, owner)
    h = world.auth(world.user("owner", owner))
    for suffix, body in (
        ("/nas/pub", NAS_PUBLIC),
        ("/nas/bk", NAS_BACKUP),
        ("/plugins/qdrant", {"enabled": True}),
        ("/vectorizer", VECTORIZER_PUB),
        ("/backup", BACKUP_TO_NAS),
        ("/schedules/old", NIGHTLY),
    ):
        r = client.put(url(machine, suffix), headers=h, json=body)
        assert r.status_code == 200, r.text
    return machine, token, owner


def attempt(client: TestClient, headers: dict, machine, method: str, suffix: str, body: dict | None):
    return client.request(method, url(machine, suffix), headers=headers, **({"json": body} if body else {}))


def passed_the_permission_check(response, suffix: str) -> bool:
    if suffix == "/install-update":
        # Nothing is published in these tests: allowed means reaching the release lookup.
        return response.status_code == 404 and response.json()["error"]["message"] == "no such release"
    return response.status_code in (200, 201)


@pytest.mark.parametrize("org_role", ["org_admin", "org_operator", "org_viewer"])
def test_organisation_roles(api, world, org_role):
    machine, _, owner = prepared_machine(world, api)
    h = world.auth(world.user("owner", owner, org_role=org_role))
    seen = api.get(url(machine), headers=h)
    assert seen.status_code == 200
    assert seen.json()["can_operate"] is (RANK[org_role] >= 2) and seen.json()["can_admin"] is (
        RANK[org_role] >= 3
    )
    assert seen.json()["document"]["nas"][0]["host"] == "10.0.0.5"  # every role of the organisation reads it
    for method, suffix, body, minimum in CHANGES:
        before = stored(world, machine).revision
        operations_before = world.session.execute(select(Operation)).scalars().all()
        r = attempt(api, h, machine, method, suffix, body)
        if RANK[org_role] >= RANK[minimum]:
            assert passed_the_permission_check(r, suffix), (
                f"{org_role} {method} {suffix}: {r.status_code} {r.text}"
            )
        else:
            assert r.status_code == 403 and code(r) == "forbidden", (
                f"{org_role} {method} {suffix}: {r.status_code}"
            )
            assert minimum in r.json()["error"]["message"]
            assert stored(world, machine).revision == before
            world.session.expire_all()
            assert len(world.session.execute(select(Operation)).scalars().all()) == len(operations_before)
            # ...and a malformed request from someone who may not make it is refused the same way.
            malformed = api.request(method, url(machine, suffix), headers=h, json={"nonsense": True})
            assert malformed.status_code == 403, f"{org_role} {method} {suffix}: {malformed.status_code}"


def test_plugin_secrets_are_for_administrators_even_though_plugins_are_for_operators(api, world):
    machine, _, owner = prepared_machine(world, api)
    operator = world.auth(world.user("owner", owner, org_role="org_operator"))
    administrator = world.auth(world.user("owner", owner, org_role="org_admin"))
    assert (
        api.put(url(machine, "/plugins/ollama"), headers=operator, json={"enabled": True}).status_code == 200
    )
    with_secret = {"enabled": True, "sealed_secrets": {"api_key": seal("plugin.assistant.api_key")}}
    removing = {"enabled": True, "sealed_secrets": {"api_key": None}}
    for body in (with_secret, removing):
        r = api.put(url(machine, "/plugins/assistant"), headers=operator, json=body)
        assert r.status_code == 403 and "org_admin" in r.json()["error"]["message"]
    assert stored(world, machine).secrets == {}
    # An empty object carries no secret.
    empty = api.put(
        url(machine, "/plugins/assistant"), headers=operator, json={"enabled": True, "sealed_secrets": {}}
    )
    assert empty.status_code == 200
    r = api.put(url(machine, "/plugins/assistant"), headers=administrator, json=with_secret)
    assert r.status_code == 200 and r.json()["secrets"] == ["plugin.assistant.api_key"]
    # The operator keeps configuring the plugin; the secret stays, untouched and unseen.
    kept = stored(world, machine).secrets
    r = api.put(
        url(machine, "/plugins/assistant"),
        headers=operator,
        json={"enabled": True, "settings": {"workers": 8}},
    )
    assert r.status_code == 200 and stored(world, machine).secrets == kept
    # Removing the plugin, which an operator may do, takes its secret with it.
    r = api.delete(url(machine, "/plugins/assistant"), headers=operator)
    assert r.status_code == 200 and r.json()["secrets"] == []


def test_another_organisation_does_not_see_the_machine_at_all(api, world):
    machine, _, _ = prepared_machine(world, api)
    before = stored(world, machine).revision
    stranger = world.auth(world.user("owner", world.owner("Someone else")))
    assert api.get(url(machine), headers=stranger).status_code == 404
    for method, suffix, body, _ in CHANGES:
        r = attempt(api, stranger, machine, method, suffix, body)
        assert r.status_code == 404 and code(r) == "not_found", f"{method} {suffix}: {r.status_code}"
    assert stored(world, machine).revision == before
    world.session.expire_all()
    assert world.session.execute(select(Operation)).first() is None


def test_nobody_gets_in_without_a_session(api, world):
    machine, token, _ = prepared_machine(world, api)
    issued = api_clients.create_client(
        world.session, world.settings, SYSTEM, name="all", scopes=list(API_CLIENT_SCOPES)
    )
    world.commit()
    for headers in ({}, bearer(token), bearer(issued.token), bearer("hms_" + "x" * 43)):
        assert api.get(url(machine), headers=headers).status_code == 401
        for method, suffix, body, _ in CHANGES:
            assert attempt(api, headers, machine, method, suffix, body).status_code == 401


STAFF_CASES = {
    # management, grant -> (may view, may manage)
    "company": ("company", None, True, True),
    "customer without a grant": ("customer", None, False, False),
    "customer, view grant": ("customer", dict(level="view"), True, False),
    "customer, manage grant": ("customer", dict(level="manage"), True, True),
    "customer, manage grant for a day": ("customer", dict(level="manage", hours=24), True, True),
    "customer, expired grant": ("customer", dict(level="manage", hours=-1), False, False),
    "customer, revoked grant": ("customer", dict(level="manage", revoked=True), False, False),
}


@pytest.mark.parametrize("case", sorted(STAFF_CASES))
def test_staff_follow_the_management_of_the_machine(api, world, case):
    management, grant_kw, may_view, may_manage = STAFF_CASES[case]
    machine, _, owner = prepared_machine(world, api)
    set_management(world, machine, management)
    if grant_kw is not None:
        grant(world, machine, **grant_kw)
    admin, auditor = world.auth(world.user("admin")), world.auth(world.user("auditor"))

    for who, headers in (("admin", admin), ("auditor", auditor)):
        r = api.get(url(machine), headers=headers)
        if may_view:
            assert r.status_code == 200, f"{who}: {r.status_code}"
            assert r.json()["management"] == management
            assert r.json()["can_admin"] is (may_manage and who == "admin")
            assert r.json()["can_operate"] is (may_manage and who == "admin")
        else:
            assert r.status_code == 403 and code(r) == "remote_access_required", f"{who}: {r.status_code}"
            assert "10.0.0.5" not in r.text and "document" not in r.text  # nothing of the configuration

    for method, suffix, body, _ in CHANGES:
        before = stored(world, machine).revision
        refused = attempt(api, auditor, machine, method, suffix, body)
        assert refused.status_code == 403 and code(refused) == "forbidden", f"auditor {method} {suffix}"
        r = attempt(api, admin, machine, method, suffix, body)
        if may_manage:
            assert passed_the_permission_check(r, suffix), f"{method} {suffix}: {r.status_code} {r.text}"
        else:
            assert r.status_code == 403 and code(r) == "remote_access_required", (
                f"{method} {suffix}: {r.status_code}"
            )
            assert stored(world, machine).revision == before

    # The owner's organisation is never affected by any of this.
    assert api.get(url(machine), headers=world.auth(world.user("owner", owner))).status_code == 200


def test_a_change_made_by_staff_under_a_grant_says_so_in_the_audit_trail(api, world):
    machine, _, owner = prepared_machine(world, api)
    set_management(world, machine, "customer")
    view_only = grant(world, machine, "view")
    manage = grant(world, machine, "manage", hours=2)
    admin = world.user("admin")
    r = api.put(url(machine, "/schedules/hourly"), headers=world.auth(admin), json=HOURLY)
    assert r.status_code == 200
    row = audit_rows(world, "appliance.schedule.set")[-1]
    assert row.actor_id == str(admin.id) and row.details["remote_access_grants"] == [str(manage.id)]
    assert str(view_only.id) not in json.dumps(row.details)
    # The organisation's own changes, and staff on a company-managed machine, rely on no grant.
    api.put(
        url(machine, "/schedules/hourly"),
        headers=world.auth(world.user("owner", owner)),
        json={**HOURLY, "minute": 1},
    )
    assert "remote_access_grants" not in audit_rows(world, "appliance.schedule.set")[-1].details
    set_management(world, machine, "company")
    api.put(url(machine, "/schedules/hourly"), headers=world.auth(admin), json={**HOURLY, "minute": 2})
    assert "remote_access_grants" not in audit_rows(world, "appliance.schedule.set")[-1].details


def test_a_grant_given_by_a_previous_owner_does_not_count(api, world):
    machine, _, old_owner = prepared_machine(world, api)
    set_management(world, machine, "customer")
    grant(world, machine, "manage")
    admin = world.auth(world.user("admin"))
    assert api.get(url(machine), headers=admin).status_code == 200
    new_owner = world.owner("New owner")
    machine_service.transfer_ownership(
        world.session,
        SYSTEM,
        machine_id=machine.id,
        new_owner_id=new_owner.id,
        reason="sold",
        user_id=world.user("admin").id,
    )
    world.commit()
    r = api.get(url(machine), headers=admin)
    assert r.status_code == 403 and code(r) == "remote_access_required"
    assert api.get(url(machine), headers=world.auth(world.user("owner", old_owner))).status_code == 404
    assert api.get(url(machine), headers=world.auth(world.user("owner", new_owner))).status_code == 200


def test_what_a_device_reports_gives_nobody_any_permission(api, world):
    """A device that claims roles, management or access changes nothing about who may do what."""
    machine, token, owner = prepared_machine(world, api)
    set_management(world, machine, "customer")
    claims = report(
        management="company",
        owner_id=str(world.owner("Mallory").id),
        can_admin=True,
        can_operate=True,
        staff_access="manage",
        grants=[{"level": "manage"}],
        mode="private_ai",
    )
    assert beat(api, token, claims).status_code == 200
    world.session.refresh(machine)
    assert machine.management == "customer" and machine.owner_id == owner.id
    admin = world.auth(world.user("admin"))
    assert code(api.get(url(machine), headers=admin)) == "remote_access_required"
    assert (
        code(api.put(url(machine, "/mode"), headers=admin, json={"mode": "private_ai"}))
        == "remote_access_required"
    )
    viewer = world.auth(world.user("owner", owner, org_role="org_viewer"))
    seen = api.get(url(machine), headers=viewer).json()
    assert seen["can_admin"] is False and seen["can_operate"] is False and seen["management"] == "customer"
    assert seen["document"]["mode"] == "vast"  # the desired mode is the cloud's, whatever the machine says
    assert set(seen["reported"]) <= {
        "schema",
        "control",
        "applied_revision",
        "apply_status",
        "apply_detail",
        "mode",
        "capabilities",
        "catalog",
    }


# =============================================================================
# Optimistic concurrency
# =============================================================================


def test_if_match_detects_a_change_made_in_the_meantime(api, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, api, owner)
    h = world.auth(world.user("owner", owner))
    put = lambda minute, **headers: api.put(  # noqa: E731
        url(machine, "/schedules/hourly"), headers={**h, **headers}, json={**HOURLY, "minute": minute}
    )
    first = put(1, **{"If-Match": "0"})
    assert first.status_code == 200 and first.headers["etag"] == '"1"'
    # The page still has revision 0: someone else changed the configuration since.
    stale = put(2, **{"If-Match": "0"})
    assert stale.status_code == 409 and envelope(stale)["code"] == "conflict"
    assert "revision 1" in envelope(stale)["message"]
    assert stored(world, machine).document["schedules"][0]["minute"] == 1
    # The ETag of the last answer is accepted as it is, quoted or not.
    assert put(3, **{"If-Match": first.headers["etag"]}).status_code == 200
    assert put(4, **{"If-Match": "2"}).status_code == 200
    assert put(5, **{"If-Match": 'W/"3"'}).status_code == 200
    # Without the header the change is applied on whatever is there.
    assert put(6).json()["revision"] == 5
    for bad in ("abc", "-1", "1.5", "*", '""'):
        r = put(7, **{"If-Match": bad})
        assert r.status_code == 400 and "If-Match" in envelope(r)["message"], bad
    assert api.delete(url(machine, "/schedules/hourly"), headers={**h, "If-Match": "3"}).status_code == 409
    assert api.delete(url(machine, "/schedules/hourly"), headers={**h, "If-Match": "5"}).status_code == 200
    assert stored(world, machine).revision == 6


def simultaneously(app, sends) -> list:
    """Each request on its own connection, released at the same moment."""
    barrier = threading.Barrier(len(sends))
    out: list = [None] * len(sends)

    def one(index: int) -> None:
        with TestClient(app, base_url=BASE_URL) as client:
            barrier.wait(timeout=30)
            out[index] = sends[index](client)

    threads = [threading.Thread(target=one, args=(i,)) for i in range(len(sends))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=90)
    assert all(response is not None for response in out)
    return out


def test_two_simultaneous_changes_cannot_both_be_based_on_the_same_revision(world):
    app = create_app(appliance_settings())
    owner = world.owner()
    with TestClient(app, base_url=BASE_URL) as setup:
        machine, _ = reporting_machine(world, setup, owner)
    h = world.auth(world.user("owner", owner))
    n = 8

    def change(index: int, if_match: str | None):
        headers = {**h, **({"If-Match": if_match} if if_match is not None else {})}
        body = {**HOURLY, "minute": index}
        return lambda client: client.put(url(machine, f"/schedules/s{index}"), headers=headers, json=body)

    # All based on revision 0: exactly one is accepted, the others are told to load again.
    responses = simultaneously(app, [change(i, "0") for i in range(n)])
    assert sorted(r.status_code for r in responses) == [200] + [409] * (n - 1), [r.text for r in responses]
    row = stored(world, machine)
    assert row.revision == 1 and len(row.document["schedules"]) == 1
    winner = next(r for r in responses if r.status_code == 200)
    assert winner.json()["document"]["schedules"] == row.document["schedules"]
    assert {code(r) for r in responses if r.status_code == 409} == {"conflict"}

    # Without If-Match none is lost: each is applied on the result of the one before.
    responses = simultaneously(app, [change(10 + i, None) for i in range(n)])
    assert [r.status_code for r in responses] == [200] * n, [r.text for r in responses]
    assert sorted(r.json()["revision"] for r in responses) == list(range(2, 2 + n))
    row = stored(world, machine)
    assert row.revision == 1 + n and len(row.document["schedules"]) == 1 + n
    revisions = [a.details["revision"] for a in audit_rows(world, "appliance.schedule.set")]
    assert revisions == list(range(1, 2 + n))  # one audit row per revision, none twice


def test_the_first_changes_of_a_machine_arriving_together_create_one_row(world):
    """Nothing exists for the machine yet: the row itself is created under concurrency."""
    app = create_app(appliance_settings())
    owner = world.owner()
    machine, _ = world.paired_machine(owner)
    h = world.auth(world.user("owner", owner))
    sends = [
        (
            lambda client, i=i: client.put(
                url(machine, f"/schedules/s{i}"), headers=h, json={**HOURLY, "minute": i}
            )
        )
        for i in range(6)
    ]
    responses = simultaneously(app, sends)
    assert [r.status_code for r in responses] == [200] * 6, [r.text for r in responses]
    world.session.expire_all()
    rows = world.session.execute(select(MachineAppliance)).scalars().all()
    assert len(rows) == 1 and rows[0].revision == 6 and len(rows[0].document["schedules"]) == 6


# =============================================================================
# Modes and the rental-protection gate (section 2)
# =============================================================================

ENABLED = dict(disruptive_operations_enabled=True)


def mode_of(world: World, machine) -> str:
    return appliance_service.stored_document(stored(world, machine))["mode"]


def test_leaving_vast_mode_is_a_gated_action_and_not_an_operation_type():
    assert LEAVE_VAST_MODE == "leave_vast_mode" and LEAVE_VAST_MODE in GATED_ACTIONS
    assert LEAVE_VAST_MODE not in DISRUPTIVE_TYPES and LEAVE_VAST_MODE not in operations.OPERATION_TYPES
    assert DISRUPTIVE_TYPES | {LEAVE_VAST_MODE} == GATED_ACTIONS
    # The operation classification the gate had before is untouched.
    assert {"restart_vast_daemon", "reboot", "run_benchmark", "apply_hardware_profile"} == DISRUPTIVE_TYPES


def test_an_unbound_machine_changes_mode_freely(api, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, api, owner)
    h = world.auth(world.user("owner", owner))
    for expect, mode in enumerate(("private_ai", "vectorize", "vast", "vectorize"), start=1):
        r = api.put(url(machine, "/mode"), headers=h, json={"mode": mode})
        assert (
            r.status_code == 200 and r.json()["document"]["mode"] == mode and r.json()["revision"] == expect
        )
    assert all(row.details["gate"] == {"checked": False} for row in audit_rows(world, "appliance.mode"))
    assert audit_rows(world, "appliance.mode_blocked") == []


def test_a_bound_machine_leaves_vast_only_when_the_gate_allows_it(world):
    with appliance_client(**ENABLED) as client:
        machine, _, _ = bound_machine(world, client)  # idle and unlisted
        h = world.auth(world.user("owner", world.session.get(Machine, machine.id).owner))
        r = client.put(url(machine, "/mode"), headers=h, json={"mode": "private_ai"})
        assert r.status_code == 200 and r.json()["document"]["mode"] == "private_ai", r.text
    (row,) = audit_rows(world, "appliance.mode")
    gate = row.details["gate"]
    assert gate["checked"] is True and gate["allowed"] is True and gate["reasons"] == []
    assert gate["checks"]["rental_state"] == "idle" and gate["checks"]["listed"] is False


BLOCKING = {
    "state unknown": (STATE_UNKNOWN, False, "rental state is unknown"),
    "active contract": (ACTIVE_CONTRACT, False, "there are active rental contracts"),
    "still listed": ({**IDLE_UNLISTED["rental"], "listed": True}, False, "machine is still listed"),
    "provider unreachable": (None, True, "provider state could not be read"),
}


@pytest.mark.parametrize("case", sorted(BLOCKING))
def test_a_blocked_mode_change_is_a_409_is_audited_and_changes_nothing(world, case):
    rental, outage, reason = BLOCKING[case]
    with appliance_client(**ENABLED) as client:
        machine, token, provider = bound_machine(world, client, rental)
        provider.outage = outage
        owner = world.session.get(Machine, machine.id).owner
        user = world.user("owner", owner)
        h = world.auth(user)
        # Every GPU idle for as long as anyone looks: it proves nothing and is not looked at.
        for _ in range(3):
            assert beat(client, token, report()).status_code == 200
        before = stored(world, machine)
        for target in ("private_ai", "vectorize"):
            r = client.put(url(machine, "/mode"), headers=h, json={"mode": target})
            assert r.status_code == 409 and envelope(r)["code"] == "maintenance_blocked", r.text
            assert envelope(r)["message"].startswith("Blocked; requires operator handling: ")
            assert reason in envelope(r)["message"]
        seen = client.get(url(machine), headers=h).json()
        assert seen["document"]["mode"] == "vast" and seen["revision"] == before.revision == 0
        # Staying in vast, or going back to it, is never blocked.
        assert client.put(url(machine, "/mode"), headers=h, json={"mode": "vast"}).status_code == 200
    blocked = audit_rows(world, "appliance.mode_blocked")
    assert [b.details["to"] for b in blocked] == ["private_ai", "vectorize"]
    assert all(b.details["from"] == "vast" and reason in "; ".join(b.details["reasons"]) for b in blocked)
    assert all(b.actor_id == str(user.id) and b.object_id == str(machine.id) for b in blocked)
    assert mode_of(world, machine) == "vast" and stored(world, machine).secrets == {}


def test_with_disruptive_actions_switched_off_a_bound_machine_never_leaves_vast(api, world):
    """The default configuration. Idle and unlisted is not enough while the switch is off."""
    machine, _, _ = bound_machine(world, api)
    h = world.auth(world.user("admin"))
    r = api.put(url(machine, "/mode"), headers=h, json={"mode": "private_ai"})
    assert r.status_code == 409 and code(r) == "maintenance_blocked"
    assert "HM_DISRUPTIVE_OPERATIONS_ENABLED=false" in r.json()["error"]["message"]
    assert mode_of(world, machine) == "vast" and len(audit_rows(world, "appliance.mode_blocked")) == 1
    # Everything that is not the mode can still be prepared while the machine is rented out.
    assert api.put(url(machine, "/plugins/ollama"), headers=h, json={"enabled": True}).status_code == 200
    assert api.put(url(machine, "/nas/bk"), headers=h, json=NAS_BACKUP).status_code == 200


def test_the_gate_is_about_leaving_vast_and_nothing_else(world):
    with appliance_client(**ENABLED) as client:
        owner = world.owner()
        machine, token = reporting_machine(world, client, owner)
        h = world.auth(world.user("owner", owner))
        assert client.put(url(machine, "/mode"), headers=h, json={"mode": "private_ai"}).status_code == 200
        # The machine is bound afterwards, and rented.
        provider = world.provider(dataset({"101": {"rental": ACTIVE_CONTRACT}}, {}))
        world.bind(world.account(provider), "101", machine)
        # Between the owner's own modes there is nothing to protect that was not already given up.
        assert client.put(url(machine, "/mode"), headers=h, json={"mode": "vectorize"}).status_code == 200
        # Back to vast: always. Out of it again: not while there is a contract.
        assert client.put(url(machine, "/mode"), headers=h, json={"mode": "vast"}).status_code == 200
        r = client.put(url(machine, "/mode"), headers=h, json={"mode": "private_ai"})
        assert r.status_code == 409 and code(r) == "maintenance_blocked"
        assert mode_of(world, machine) == "vast"
        # The contract ends, the machine is still listed: a new rental could start at any moment.
        provider.dataset["machines"][0]["rental"] = {**IDLE_UNLISTED["rental"], "listed": True}
        r = client.put(url(machine, "/mode"), headers=h, json={"mode": "private_ai"})
        assert r.status_code == 409 and "machine is still listed" in r.json()["error"]["message"]
        # The operator confirms the machine is empty and removes the binding: then it is the owner's.
        pm = provider_sync.unbind_machine(
            world.session,
            SYSTEM,
            provider_machine_id=world.session.execute(text("SELECT id FROM provider_machines")).scalar_one(),
            user_id=world.user("admin").id,
        )
        world.commit()
        assert pm.machine_id is None
        assert client.put(url(machine, "/mode"), headers=h, json={"mode": "private_ai"}).status_code == 200
    assert mode_of(world, machine) == "private_ai"
    assert audit_rows(world, "appliance.mode")[-1].details["gate"] == {"checked": False}
    assert len(audit_rows(world, "appliance.mode_blocked")) == 2


def test_the_gate_decides_from_the_provider_and_never_from_telemetry(world, db):
    settings = appliance_settings(**ENABLED)
    with appliance_client(**ENABLED) as client:
        machine, token, provider = bound_machine(world, client, ACTIVE_CONTRACT)
        for _ in range(5):
            beat(client, token, report())  # GPU utilisation 0 in every sample
    decision = evaluate(db, settings, provider, machine, LEAVE_VAST_MODE)
    assert decision.allowed is False and decision.checks["disruptive"] is True
    assert "gpu" not in json.dumps(decision.as_dict()).lower() and "util" not in json.dumps(
        decision.as_dict()
    )
    assert evaluate(db, settings, None, machine, LEAVE_VAST_MODE).reasons == [
        "no provider adapter is available"
    ]
    # Operations are decided as before: the new action added nothing to them.
    for harmless in ("refresh_inventory", "appliance_run_job", "install_update", "anything-else"):
        assert evaluate(db, settings, provider, machine, harmless).as_dict() == {
            "allowed": True,
            "reasons": [],
            "checks": {"disruptive": False},
        }
    assert evaluate(db, settings, provider, machine, "reboot").allowed is False


def test_a_stale_revision_is_reported_before_the_gate_is_asked(world):
    with appliance_client(**ENABLED) as client:
        machine, _, _ = bound_machine(world, client, ACTIVE_CONTRACT)
        h = world.auth(world.user("admin"))
        r = client.put(url(machine, "/mode"), headers={**h, "If-Match": "7"}, json={"mode": "private_ai"})
        assert r.status_code == 409 and code(r) == "conflict"
    assert audit_rows(world, "appliance.mode_blocked") == []


# =============================================================================
# Secrets: sealed on arrival, stored, forwarded, never shown
# =============================================================================


def test_a_secret_is_accepted_only_once_the_machine_has_reported_its_sealing_key(api, world):
    owner = world.owner()
    machine, token = world.paired_machine(owner)
    h = world.auth(world.user("owner", owner))
    with_password = {**NAS_DOCS, "sealed_secret": seal("nas.docs.password")}
    for suffix, body in (
        ("/nas/docs", with_password),
        (
            "/plugins/assistant",
            {"enabled": False, "sealed_secrets": {"api_key": seal("plugin.assistant.api_key")}},
        ),
    ):
        r = api.put(url(machine, suffix), headers=h, json=body)
        assert r.status_code == 409 and code(r) == "no_sealing_key", r.text
    # An agent that reports, but no usable key (none, or rubbish): still nothing to seal for.
    for key in (None, "hmk1.rubbish", "", 12):
        assert beat(api, token, report(seal_public_key=key)).status_code == 200
        assert code(api.put(url(machine, "/nas/docs"), headers=h, json=with_password)) == "no_sealing_key"
    assert stored(world, machine).revision == 0 and stored(world, machine).secrets == {}
    # What needs no secret is not held up.
    assert api.put(url(machine, "/nas/pub"), headers=h, json=NAS_PUBLIC).status_code == 200
    assert beat(api, token, report()).status_code == 200
    assert api.put(url(machine, "/nas/docs"), headers=h, json=with_password).status_code == 200
    assert sorted(stored(world, machine).secrets) == ["nas.docs.password"]


def test_the_caller_never_chooses_the_name_a_secret_is_stored_under(api, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, api, owner)
    h = world.auth(world.user("owner", owner))
    assert (
        api.put(
            url(machine, "/nas/a"), headers=h, json={**NAS_DOCS, "sealed_secret": seal("nas.a.password")}
        ).status_code
        == 200
    )
    assert (
        api.put(
            url(machine, "/nas/b"), headers=h, json={**NAS_DOCS, "sealed_secret": seal("nas.b.password")}
        ).status_code
        == 200
    )
    row = stored(world, machine)
    assert sorted(row.secrets) == ["nas.a.password", "nas.b.password"]
    assert [entry["secret"] for entry in row.document["nas"]] == ["nas.a.password", "nas.b.password"]
    # There is no field for a name anywhere, and no route that takes one.
    for body in (
        {**NAS_DOCS, "secret": "nas.b.password"},
        {**NAS_DOCS, "sealed_secret": seal("nas.a.password"), "secret_name": "backup.s3.secret_key"},
    ):
        assert api.put(url(machine, "/nas/a"), headers=h, json=body).status_code == 422
    for path in ("/secrets", "/secrets/nas.a.password"):
        for method in ("GET", "PUT", "POST", "DELETE"):
            assert api.request(method, url(machine, path), headers=h, json={}).status_code in (404, 405)


def test_a_stored_secret_is_not_carried_over_to_a_new_destination(api, world):
    """Whoever may edit the configuration must not be able to send a customer's NAS
    password or API key to a server of their choice by changing only the address."""
    owner = world.owner()
    machine, _ = reporting_machine(world, api, owner)
    h = world.auth(world.user("owner", owner))

    first = seal("nas.docs.password")
    r = api.put(url(machine, "/nas/docs"), headers=h, json={**NAS_DOCS, "sealed_secret": first})
    assert r.status_code == 200, r.text
    # Another folder of the same share: the password stays.
    r = api.put(url(machine, "/nas/docs"), headers=h, json={**NAS_DOCS, "subpath": "projects"})
    assert r.status_code == 200, r.text
    assert stored(world, machine).secrets["nas.docs.password"] == first
    # Another server, share, user or domain: it does not follow.
    changes = ({"host": "collector.example"}, {"share": "other"}, {"username": "someone"}, {"domain": "CORP"})
    for change in changes:
        moved = {**NAS_DOCS, "subpath": "projects", **change}
        r = api.put(url(machine, "/nas/docs"), headers=h, json=moved)
        assert r.status_code == 400 and "not carried over" in r.text, (change, r.text)
        row = stored(world, machine)
        assert row.document["nas"][0]["host"] == "nas.lan" and row.secrets["nas.docs.password"] == first
    second = seal("nas.docs.password", b"another password")
    body = {**NAS_DOCS, "host": "nas2.lan", "sealed_secret": second}
    r = api.put(url(machine, "/nas/docs"), headers=h, json=body)
    assert r.status_code == 200, r.text
    assert stored(world, machine).secrets["nas.docs.password"] == second

    # The cloud answer key is bound to the provider and its address, not to the model.
    answer = {
        "provider": "openai_compatible",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4.1-mini",
    }
    body = {**VECTORIZER, "answer": {**answer, "sealed_secret": seal("ai.answer.api_key")}}
    assert api.put(url(machine, "/vectorizer"), headers=h, json=body).status_code == 200
    body = {**VECTORIZER, "answer": {**answer, "model": "gpt-4.1"}}
    assert api.put(url(machine, "/vectorizer"), headers=h, json=body).status_code == 200
    for change in ({"base_url": "https://collector.example/v1"}, {"provider": "anthropic", "base_url": None}):
        moved = {k: v for k, v in {**answer, **change}.items() if v is not None}
        r = api.put(url(machine, "/vectorizer"), headers=h, json={**VECTORIZER, "answer": moved})
        assert r.status_code == 400 and "not carried over" in r.text, (change, r.text)
    assert stored(world, machine).document["vectorizer"]["answer"]["base_url"] == "https://api.openai.com/v1"

    # The S3 secret key is bound to the endpoint and the access key id, not to the bucket prefix.
    s3 = BACKUP_TO_S3["destination"]
    body = {**BACKUP_TO_S3, "destination": {**s3, "sealed_secret": seal("backup.s3.secret_key")}}
    assert api.put(url(machine, "/backup"), headers=h, json=body).status_code == 200
    body = {**BACKUP_TO_S3, "destination": {**s3, "prefix": "site2/"}}
    assert api.put(url(machine, "/backup"), headers=h, json=body).status_code == 200
    for change in ({"endpoint": "https://s3.collector.example"}, {"access_key_id": "AKIAOTHERKEY00000002"}):
        body = {**BACKUP_TO_S3, "destination": {**s3, **change}}
        r = api.put(url(machine, "/backup"), headers=h, json=body)
        assert r.status_code == 400 and "not carried over" in r.text, (change, r.text)


def test_sealed_values_appear_in_no_response_no_audit_row_and_no_log_line(world, capsys):
    values: list[str] = []

    def sealed(name: str) -> str:
        values.append(seal(name, f"clear-{name}".encode()))
        return values[-1]

    texts: list[str] = []
    with appliance_client(log_level="INFO") as client:
        owner = world.owner()
        machine, token = reporting_machine(world, client, owner)
        h = world.auth(world.user("owner", owner))
        admin = world.auth(world.user("admin"))
        answer = {
            "provider": "openai_compatible",
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-4.1-mini",
        }
        s3 = {**BACKUP_TO_S3["destination"], "sealed_secret": sealed("backup.s3.secret_key")}
        calls = [
            ("PUT", "/nas/docs", {**NAS_DOCS, "sealed_secret": sealed("nas.docs.password")}),
            ("PUT", "/plugins/ollama", {"enabled": True}),
            (
                "PUT",
                "/plugins/assistant",
                {"enabled": True, "sealed_secrets": {"api_key": sealed("plugin.assistant.api_key")}},
            ),
            (
                "PUT",
                "/vectorizer",
                {**VECTORIZER, "answer": {**answer, "sealed_secret": sealed("ai.answer.api_key")}},
            ),
            ("PUT", "/backup", {**BACKUP_TO_S3, "destination": s3}),
            ("PUT", "/nas/docs", {**NAS_DOCS, "sealed_secret": sealed("nas.docs.password")}),  # replaced
            # Refused requests carry secrets too.
            ("PUT", "/nas/bad", {**NAS_DOCS, "host": "-o", "sealed_secret": sealed("nas.bad.password")}),
            ("PUT", "/nas/docs", {**NAS_DOCS, "sealed_secret": sealed("nas.docs.password"), "nonsense": 1}),
            (
                "PUT",
                "/plugins/ollama",
                {"enabled": True, "sealed_secrets": {"nope": sealed("plugin.ollama.nope")}},
            ),
            ("GET", "", None),
            ("DELETE", "/plugins/assistant", None),
            ("DELETE", "/backup", None),
        ]
        for method, suffix, body in calls:
            r = client.request(method, url(machine, suffix), headers=h, **({"json": body} if body else {}))
            texts.append(r.text + json.dumps(dict(r.headers)))
        stale = client.put(url(machine, "/nas/docs"), headers={**h, "If-Match": "1"}, json=calls[0][2])
        assert stale.status_code == 409
        texts.append(stale.text)
        for path in (
            url(machine),
            f"/api/v1/machines/{machine.id}",
            "/api/v1/audit-log?limit=200",
            f"/api/v1/machines/{machine.id}/operations",
        ):
            r = client.get(path, headers=admin)
            assert r.status_code == 200, path
            texts.append(r.text)
        # The one place a sealed value goes: the machine's own heartbeat answer.
        delivered = beat(client, token, report()).json()["appliance"]["document"]["secrets"]
    assert len(values) == 8 and len(set(values)) == 8
    row = stored(world, machine)
    assert sorted(row.secrets) == ["ai.answer.api_key", "nas.docs.password"] and delivered == row.secrets
    assert row.secrets["nas.docs.password"] == values[4]  # the replacement, not the first one

    logged = capsys.readouterr()
    places = {
        "responses to people": "\n".join(texts),
        "audit trail": json.dumps(
            [[a.action, a.actor_id, a.object_type, a.object_id, a.details, a.hash] for a in audit_rows(world)]
        ),
        "log": logged.out + logged.err,
        "stored document": json.dumps(row.document),
        "reported state": json.dumps(row.reported),
    }
    assert (
        '"appliance.nas.set"' in places["audit trail"]
        and '"route": "/api/v1/machines/{machine_id}/appliance/nas/{nas_id}"' in places["log"]
    )
    for where, haystack in places.items():
        assert "hmseal1." not in haystack, f"a sealed value reached: {where}"
        for value in values:
            assert value not in haystack and value[8:40] not in haystack, where
        assert "clear-" not in haystack, where
    # Names are what people see instead.
    assert '"sealed_set": ["nas.docs.password"]' in places["audit trail"]
    assert '"secrets":["ai.answer.api_key","nas.docs.password"]' in places["responses to people"].replace(
        " ", ""
    )


# =============================================================================
# The two functional guards that read the reported state
# =============================================================================


def test_a_machine_that_follows_its_own_profile_is_not_changed_from_the_cloud(api, world):
    owner = world.owner()
    machine, token = reporting_machine(world, api, owner)
    h = world.auth(world.user("owner", owner))
    assert api.put(url(machine, "/schedules/hourly"), headers=h, json=HOURLY).status_code == 200
    assert beat(api, token, report(control="local")).status_code == 200
    seen = api.get(url(machine), headers=h).json()
    assert seen["control"] == "local" and seen["in_sync"] is False and seen["revision"] == 1
    for method, suffix, body, _ in CHANGES[:-2]:
        r = attempt(api, h, machine, method, suffix, body)
        assert r.status_code == 409 and code(r) == "locally_controlled", (
            f"{method} {suffix}: {r.status_code} {r.text}"
        )
        assert "on the machine" in r.json()["error"]["message"]
    assert stored(world, machine).revision == 1
    # Staff are told the same. It is not a permission: nobody is allowed more or less by it.
    admin = world.auth(world.user("admin"))
    assert code(api.put(url(machine, "/mode"), headers=admin, json={"mode": "vast"})) == "locally_controlled"
    viewer = world.auth(world.user("owner", owner, org_role="org_viewer"))
    assert code(api.put(url(machine, "/mode"), headers=viewer, json={"mode": "vast"})) == "forbidden"
    # A job is an operation, not a change to the document: the machine's own switches decide.
    assert api.post(url(machine, "/jobs"), headers=h, json={"job": "update_check"}).status_code == 201
    # Back under cloud control (the profile file was removed): changes are accepted again.
    assert beat(api, token, report(control="cloud")).status_code == 200
    assert (
        api.put(url(machine, "/schedules/hourly"), headers=h, json={**HOURLY, "minute": 3}).status_code == 200
    )


def test_a_plugin_the_machines_firmware_does_not_have_cannot_be_added_or_enabled(api, world):
    owner = world.owner()
    machine, token = world.paired_machine(owner)
    h = world.auth(world.user("owner", owner))
    # Before the machine has said what it has, the control plane's catalog is all there is.
    assert api.put(url(machine, "/plugins/qdrant"), headers=h, json={"enabled": True}).status_code == 200
    assert beat(api, token, report(catalog=[{"id": "ollama", "version": "1"}])).status_code == 200
    for body in ({"enabled": True}, {"enabled": False}):
        r = api.put(url(machine, "/plugins/assistant"), headers=h, json=body)
        assert r.status_code == 409 and code(r) == "plugin_not_on_machine", r.text
    assert (
        code(api.put(url(machine, "/plugins/qdrant"), headers=h, json={"enabled": True, "settings": {}}))
        == "plugin_not_on_machine"
    )
    # What is already configured can be switched off, or removed.
    off = api.put(url(machine, "/plugins/qdrant"), headers=h, json={"enabled": False})
    assert off.status_code == 200 and off.json()["document"]["plugins"] == [
        {"id": "qdrant", "enabled": False, "settings": {}}
    ]
    assert api.put(url(machine, "/plugins/ollama"), headers=h, json={"enabled": True}).status_code == 200
    assert api.delete(url(machine, "/plugins/qdrant"), headers=h).status_code == 200
    # A machine that reports an empty catalog has no plugin at all.
    assert beat(api, token, report(catalog=[])).status_code == 200
    assert (
        code(api.put(url(machine, "/plugins/qdrant"), headers=h, json={"enabled": True}))
        == "plugin_not_on_machine"
    )
    # A plugin the control plane itself does not know is simply not found.
    assert api.put(url(machine, "/plugins/notthere"), headers=h, json={"enabled": True}).status_code == 404


# =============================================================================
# Removal rules
# =============================================================================


def test_what_is_still_in_use_cannot_be_removed(api, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, api, owner)
    h = world.auth(world.user("owner", owner))
    for suffix, body in (
        ("/nas/pub", NAS_PUBLIC),
        ("/nas/bk", NAS_BACKUP),
        ("/plugins/ollama", {"enabled": True}),
        ("/plugins/qdrant", {"enabled": True}),
        ("/vectorizer", VECTORIZER_PUB),
        ("/plugins/vectorizer", {"enabled": True}),
        ("/plugins/assistant", {"enabled": True}),
        ("/backup", BACKUP_TO_NAS),
        (
            "/schedules/restart",
            {"job": "plugin_restart", "plugin": "qdrant", "every": "hourly", "minute": 0, "enabled": True},
        ),
    ):
        assert api.put(url(machine, suffix), headers=h, json=body).status_code == 200, suffix
    revision = stored(world, machine).revision

    def refused_delete(suffix: str, because: str) -> None:
        r = api.delete(url(machine, suffix), headers=h)
        assert r.status_code == 409 and code(r) == "in_use", f"{suffix}: {r.status_code} {r.text}"
        assert because in r.json()["error"]["message"]
        assert stored(world, machine).revision == revision

    refused_delete("/nas/pub", "vectorization still reads this NAS entry")
    refused_delete("/nas/bk", "the backup still writes to this NAS entry")
    refused_delete("/plugins/ollama", "assistant, vectorizer is enabled and requires this plugin")
    refused_delete("/plugins/qdrant", "vectorizer is enabled and requires this plugin")
    refused_delete("/vectorizer", "the vectorizer plugin is enabled")
    # Disabling what a plugin requires is refused by the rules of the document itself.
    r = api.put(url(machine, "/plugins/ollama"), headers=h, json={"enabled": False})
    assert r.status_code == 400 and "needs the plugin ollama to be enabled" in r.json()["error"]["message"]
    # So is turning a source into a backup destination.
    r = api.put(url(machine, "/nas/pub"), headers=h, json={**NAS_PUBLIC, "access": "write"})
    assert r.status_code == 400 and "vectorizer.sources[0]" in r.json()["error"]["message"]
    assert stored(world, machine).revision == revision

    # In the right order everything comes apart.
    assert api.put(url(machine, "/plugins/vectorizer"), headers=h, json={"enabled": False}).status_code == 200
    revision += 1
    refused_delete("/plugins/qdrant", "the schedule restart restarts this plugin")
    for suffix in (
        "/schedules/restart",
        "/plugins/qdrant",
        "/vectorizer",
        "/nas/pub",
        "/backup",
        "/nas/bk",
        "/plugins/assistant",
        "/plugins/ollama",
        "/plugins/vectorizer",
    ):
        r = api.delete(url(machine, suffix), headers=h)
        assert r.status_code == 200, f"{suffix}: {r.text}"
    assert stored(world, machine).document == appliance_service.default_document()


def test_removing_something_removes_only_the_secrets_it_referred_to(api, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, api, owner)
    h = world.auth(world.user("owner", owner))
    s3 = {
        **BACKUP_TO_S3,
        "destination": {**BACKUP_TO_S3["destination"], "sealed_secret": seal("backup.s3.secret_key")},
    }
    for suffix, body in (
        ("/nas/a", {**NAS_DOCS, "sealed_secret": seal("nas.a.password")}),
        ("/nas/b", {**NAS_DOCS, "sealed_secret": seal("nas.b.password")}),
        ("/plugins/ollama", {"enabled": True}),
        (
            "/plugins/assistant",
            {"enabled": True, "sealed_secrets": {"api_key": seal("plugin.assistant.api_key")}},
        ),
        ("/backup", s3),
    ):
        assert api.put(url(machine, suffix), headers=h, json=body).status_code == 200, suffix
    everything = dict(stored(world, machine).secrets)
    assert sorted(everything) == [
        "backup.s3.secret_key",
        "nas.a.password",
        "nas.b.password",
        "plugin.assistant.api_key",
    ]

    def after(method: str, suffix: str, body: dict | None, gone: str) -> None:
        r = attempt(api, h, machine, method, suffix, body)
        assert r.status_code == 200, r.text
        left = stored(world, machine).secrets
        assert gone in everything and gone not in left
        del everything[gone]
        assert left == everything  # the others are exactly as they were
        assert audit_rows(world)[-1].details["sealed_removed"] == [gone]

    after("DELETE", "/nas/a", None, "nas.a.password")
    after("DELETE", "/plugins/assistant", None, "plugin.assistant.api_key")
    after("DELETE", "/backup", None, "backup.s3.secret_key")
    after("PUT", "/nas/b", NAS_PUBLIC, "nas.b.password")
    assert stored(world, machine).secrets == {}


# =============================================================================
# Ownership transfer
# =============================================================================


def test_a_new_owner_inherits_nothing_of_the_previous_owners_configuration(api, world):
    machine, token, old_owner = prepared_machine(world, api)
    old_admin = world.auth(world.user("owner", old_owner))
    assert (
        api.put(
            url(machine, "/nas/docs"),
            headers=old_admin,
            json={**NAS_DOCS, "sealed_secret": seal("nas.docs.password")},
        ).status_code
        == 200
    )
    assert api.put(url(machine, "/mode"), headers=old_admin, json={"mode": "private_ai"}).status_code == 200
    assert api.post(url(machine, "/jobs"), headers=old_admin, json={"job": "backup_run"}).status_code == 201
    before = stored(world, machine).revision
    applied = report(
        applied_revision=before,
        mode="private_ai",
        nas=[{"id": "docs", "state": "mounted", "detail": ""}],
        plugins=[{"id": "qdrant", "state": "running", "detail": "", "version": "1", "ports": [6333]}],
        secrets=[{"name": "nas.docs.password", "state": "ok"}],
        backup={"state": "ok", "key_present": True, "key_id": "9f2c1a7b"},
    )
    new_owner = world.owner("New owner")
    staff = world.user("admin")
    r = api.post(
        f"/api/v1/machines/{machine.id}/transfer-ownership",
        headers=world.auth(staff),
        json={"new_owner_id": str(new_owner.id), "reason": "sold"},
    )
    assert r.status_code == 200, r.text

    row = stored(world, machine)
    assert row.revision == before + 1 and row.updated_by == staff.id
    assert row.document == appliance_service.default_document() and row.secrets == {}
    assert row.seal_public_key == SEAL_KEY  # the machine's key is the machine's
    assert set(row.reported) <= {"schema", "control", "capabilities", "catalog", "update"}
    world.session.expire_all()
    (job,) = world.session.execute(select(Operation)).scalars().all()
    assert job.status == "cancelled" and job.detail == "the machine changed owner"

    reset = audit_rows(world, "appliance.reset")[-1]
    assert reset.owner_id == new_owner.id and reset.actor_id == str(staff.id)
    assert reset.details == {
        "reason": "ownership transfer",
        "revision": row.revision,
        "previous_mode": "private_ai",
        "plugins_removed": 1,
        "nas_removed": 3,
        "schedules_removed": 1,
        "sealed_removed": ["nas.docs.password"],
        "operations_cancelled": 1,
    }

    new_admin = world.auth(world.user("owner", new_owner))
    seen = api.get(url(machine), headers=new_admin)
    assert seen.status_code == 200
    body = seen.json()
    assert body["document"] == appliance_service.default_document() and body["secrets"] == []
    assert body["in_sync"] is False
    for trace in ("10.0.0.5", "nas.lan", "indexer", "nas.docs.password", "9f2c1a7b", "documents"):
        assert trace not in seen.text, trace
    assert api.get(url(machine), headers=old_admin).status_code == 404

    # The machine is told to go back to nothing: mode vast, no plugin, no NAS, no secret.
    answer = beat(api, token, applied).json()
    assert answer["operations"] == []
    assert answer["appliance"] == {
        "revision": row.revision,
        "document": {**appliance_service.default_document(), "revision": row.revision, "secrets": {}},
    }
    # The new owner starts from there.
    r = api.put(url(machine, "/nas/mine"), headers=new_admin, json=NAS_PUBLIC)
    assert r.status_code == 200 and [n["id"] for n in r.json()["document"]["nas"]] == ["mine"]


def test_a_machine_that_was_never_configured_is_reset_all_the_same(world, db):
    """A start-up profile on the machine may hold the previous owner's set-up: revision 1 replaces it."""
    old_owner, new_owner = world.owner(), world.owner()
    machine, _ = world.paired_machine(old_owner)
    machine_service.transfer_ownership(
        world.session,
        SYSTEM,
        machine_id=machine.id,
        new_owner_id=new_owner.id,
        reason="sold",
        user_id=world.user("admin").id,
    )
    world.commit()
    row = stored(world, machine)
    assert (
        row.revision == 1 and row.document == appliance_service.default_document() and row.updated_by is None
    )
    assert audit_rows(world, "appliance.reset")[-1].details["sealed_removed"] == []


# =============================================================================
# Jobs: typed operations (section 6.5)
# =============================================================================


def test_a_job_reaches_the_machine_as_a_typed_operation(api, world):
    owner = world.owner()
    machine, token = reporting_machine(world, api, owner)
    operator = world.user("owner", owner, org_role="org_operator")
    h = world.auth(operator)
    assert api.put(url(machine, "/plugins/ollama"), headers=h, json={"enabled": True}).status_code == 200
    revision = stored(world, machine).revision

    r = api.post(url(machine, "/jobs"), headers=h, json={"job": "plugin_restart", "plugin": "ollama"})
    assert r.status_code == 201, r.text
    queued = r.json()
    assert queued["type"] == "appliance_run_job" and queued["params"] == {
        "job": "plugin_restart",
        "plugin": "ollama",
    }
    assert queued["status"] == "pending" and queued["requested_by"] == str(operator.id)
    assert queued["safety"] == {"allowed": True, "reasons": [], "checks": {"disruptive": False}}
    assert stored(world, machine).revision == revision  # a job is not a change to the document

    (delivered,) = beat(api, token, report()).json()["operations"]
    assert delivered["id"] == queued["id"] and delivered["type"] == "appliance_run_job"
    assert delivered["params"] == {"job": "plugin_restart", "plugin": "ollama"}
    assert set(delivered) == {"id", "type", "params", "issued_at", "expires_at", "nonce"}
    ack = api.post(
        f"/api/v1/device/operations/{queued['id']}/ack",
        headers=bearer(token),
        json={"status": "succeeded", "nonce": delivered["nonce"], "detail": "started"},
    )
    assert ack.status_code == 200
    request_row = audit_rows(world, "operation.request")[-1]
    assert request_row.actor_id == str(operator.id) and request_row.details["type"] == "appliance_run_job"

    for job in ("vectorize_sync", "backup_run", "update_check"):
        assert api.post(url(machine, "/jobs"), headers=h, json={"job": job}).status_code == 201


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"job": "shell"}, 400),
        ({"job": "set_mode"}, 400),
        ({"job": "plugin_restart"}, 400),
        ({"job": "backup_run", "plugin": "ollama"}, 400),
        ({"job": "plugin_restart", "plugin": "Ollama; reboot"}, 400),
        ({"job": "plugin_restart", "plugin": "qdrant"}, 409),  # in the catalog, not configured here
        ({"job": "backup_run", "command": "id"}, 422),
        ({"job": "backup_run", "params": {"path": "/"}}, 422),
        ({}, 422),
    ],
)
def test_a_job_is_one_of_four_names_and_nothing_else(api, world, body, status):
    owner = world.owner()
    machine, token = reporting_machine(world, api, owner)
    h = world.auth(world.user("owner", owner))
    assert api.put(url(machine, "/plugins/ollama"), headers=h, json={"enabled": True}).status_code == 200
    r = api.post(url(machine, "/jobs"), headers=h, json=body)
    assert r.status_code == status, r.text
    world.session.expire_all()
    assert world.session.execute(select(Operation)).first() is None
    assert beat(api, token, report()).json()["operations"] == []


def test_a_job_needs_a_paired_machine(api, world):
    owner = world.owner()
    machine = world.pairing(owner).machine  # a machine record nothing has paired with yet
    r = api.post(
        url(machine, "/jobs"), headers=world.auth(world.user("owner", owner)), json={"job": "backup_run"}
    )
    assert r.status_code == 409 and "no active paired device" in r.json()["error"]["message"]


OPERATION_PARAMETERS = {
    "appliance_run_job": (
        [{"job": job} for job in operations.APPLIANCE_JOBS[:3]]
        + [{"job": "plugin_restart", "plugin": "ollama"}],
        [
            {},
            {"job": "shell"},
            {"job": ["backup_run"]},
            {"job": "backup_run", "plugin": "ollama"},
            {"job": "plugin_restart"},
            {"job": "plugin_restart", "plugin": ""},
            {"job": "plugin_restart", "plugin": "a b"},
            {"job": "plugin_restart", "plugin": "../x"},
            {"job": "plugin_restart", "plugin": 7},
            {"job": "plugin_restart", "plugin": "ollama", "args": ["-f"]},
            {"job": "backup_run", "command": "id"},
        ],
    ),
    "install_update": (
        [{"version": "0.2.0"}, {"version": "10.20.30"}],
        [
            {},
            {"version": "latest"},
            {"version": "0.2"},
            {"version": "0.2.0-rc1"},
            {"version": "0.2.0\n"},
            {"version": 2},
            {"version": "0.2.0", "url": "https://evil.example/pkg.deb"},
            {"version": "0.2.0", "force": True},
            {"url": "https://evil.example/pkg.deb"},
        ],
    ),
}


@pytest.mark.parametrize("op_type", sorted(OPERATION_PARAMETERS))
def test_the_new_operation_types_take_exactly_their_parameters(op_type):
    good, bad = OPERATION_PARAMETERS[op_type]
    validate = operations.OPERATION_TYPES[op_type]
    for params in good:
        assert validate(dict(params)) == params
    for params in bad:
        with pytest.raises(InvalidRequest):
            validate(params)
    assert op_type not in DISRUPTIVE_TYPES and op_type not in operations.NOT_IMPLEMENTED_TYPES


def test_the_remote_surface_is_one_table_and_the_appliance_types_have_their_own_door(api, world):
    assert set(operations.OPERATION_TYPES) == {
        "refresh_inventory",
        "collect_diagnostics",
        "run_preflight",
        "rotate_credential",
        "restart_vast_daemon",
        "reboot",
        "run_benchmark",
        "apply_hardware_profile",
        "appliance_run_job",
        "install_update",
    }
    assert {"appliance_run_job", "install_update"} == operations.APPLIANCE_ONLY_TYPES
    assert set(operations.GENERAL_TYPES) == set(operations.OPERATION_TYPES) - operations.APPLIANCE_ONLY_TYPES

    # The general operation routes do not queue them: not for an admin, not for an API client.
    owner = world.owner()
    machine, token = reporting_machine(world, api, owner)
    admin = world.auth(world.user("admin"))
    issued = api_clients.create_client(
        world.session, world.settings, SYSTEM, name="all", scopes=list(API_CLIENT_SCOPES)
    )
    world.commit()
    for op_type, params in (
        ("appliance_run_job", {"job": "backup_run"}),
        ("install_update", {"version": "9.9.9"}),
    ):
        r = api.post(
            f"/api/v1/machines/{machine.id}/operations",
            headers=admin,
            json={"type": op_type, "params": params},
        )
        assert r.status_code == 400 and "appliance routes" in r.json()["error"]["message"], r.text
        r = api.post(
            f"/api/v1/integration/machines/{machine.id}/operations",
            headers={**bearer(issued.token), "Idempotency-Key": f"appliance-{op_type}"},
            json={"type": op_type, "params": params},
        )
        assert r.status_code == 400 and code(r) == "invalid_request", r.text
    listed = api.get("/api/v1/integration/operation-types", headers=bearer(issued.token)).json()
    assert listed["types"] == list(operations.GENERAL_TYPES) and "install_update" not in listed["types"]
    world.session.expire_all()
    assert world.session.execute(select(Operation)).first() is None
    assert beat(api, token, report()).json()["operations"] == []


# =============================================================================
# The integration API: appliance:read (sections 3 and 12)
# =============================================================================

INTEGRATION = "/api/v1/integration"


def client_token(world: World, scopes=("fleet:read", "appliance:read"), **kw) -> str:
    issued = api_clients.create_client(
        world.session,
        world.settings,
        SYSTEM,
        name=f"client-{uuid.uuid4().hex[:8]}",
        scopes=list(scopes),
        **kw,
    )
    world.commit()
    return issued.token


def test_an_api_client_reads_state_and_no_configuration(api, world):
    machine, token, owner = prepared_machine(world, api)
    h = world.auth(world.user("owner", owner))
    assert (
        api.put(
            url(machine, "/nas/docs"),
            headers=h,
            json={**NAS_DOCS, "sealed_secret": seal("nas.docs.password")},
        ).status_code
        == 200
    )
    assert (
        api.put(url(machine, "/update"), headers=h, json={"channel": "beta", "policy": "manual"}).status_code
        == 200
    )
    revision = stored(world, machine).revision
    said = report(
        applied_revision=revision,
        mode="vast",
        plugins=[
            {
                "id": "qdrant",
                "state": "blocked",
                "detail": "mode is vast; see \\\\nas.lan\\documents",
                "version": "1",
                "ports": [6333],
            }
        ],
        nas=[{"id": "docs", "state": "error", "detail": "mount //nas.lan/documents as indexer failed"}],
        secrets=[{"name": "nas.docs.password", "state": "ok"}],
        vectorizer={
            "state": "idle",
            "last_run_at": "2026-10-02T02:30:00Z",
            "last_ok_at": "2026-10-02T02:41:10Z",
            "files_indexed": 1820,
            "files_failed": 3,
            "files_skipped": 12,
            "chunks": 40211,
            "detail": "x",
        },
        backup={
            "state": "ok",
            "key_present": True,
            "key_id": "9f2c1a7b",
            "last_ok_at": "2026-10-01T03:00:00Z",
            "last_size_bytes": 123456,
            "detail": "to //nas",
        },
        update={"current_version": "0.2.0", "state": "idle", "target_version": "", "detail": ""},
    )
    assert beat(api, token, said).status_code == 200

    r = api.get(f"{INTEGRATION}/machines/{machine.id}/appliance", headers=bearer(client_token(world)))
    assert r.status_code == 200, r.text
    seen = r.json()
    assert seen.pop("reported_at") is not None
    assert seen == {
        "machine_id": str(machine.id),
        "mode": "vast",
        "reported_mode": "vast",
        "management": "company",
        "control": "cloud",
        "revision": revision,
        "applied_revision": revision,
        "apply_status": "applied",
        "in_sync": True,
        "plugins": [{"id": "qdrant", "enabled": True, "state": "blocked", "version": "1"}],
        "vectorizer": {
            "configured": True,
            "state": "idle",
            "last_run_at": "2026-10-02T02:30:00+00:00",
            "last_ok_at": "2026-10-02T02:41:10+00:00",
            "files_indexed": 1820,
            "files_failed": 3,
            "files_skipped": 12,
            "chunks": 40211,
        },
        "backup": {
            "configured": True,
            "enabled": True,
            "state": "ok",
            "key_present": True,
            "last_ok_at": "2026-10-01T03:00:00+00:00",
            "last_size_bytes": 123456,
        },
        "update": {
            "channel": "beta",
            "policy": "manual",
            "current_version": "0.2.0",
            "state": "idle",
            "target_version": "",
        },
    }
    # No NAS host, share or user name, no secret name, no backup key id, no free text from the machine.
    for hidden in (
        "nas.lan",
        "10.0.0.5",
        "192.168.1.20",
        "documents",
        "indexer",
        "password",
        "9f2c1a7b",
        "detail",
        "hmseal1",
        "hmk1.",
    ):
        assert hidden not in r.text, hidden

    # A machine nothing was configured for, and one nothing reported for, read the same way.
    bare, _ = world.paired_machine(owner)
    empty = api.get(f"{INTEGRATION}/machines/{bare.id}/appliance", headers=bearer(client_token(world))).json()
    assert empty["mode"] == "vast" and empty["plugins"] == [] and empty["in_sync"] is True
    assert empty["vectorizer"] == {
        "configured": False,
        "state": None,
        "last_run_at": None,
        "last_ok_at": None,
        "files_indexed": None,
        "files_failed": None,
        "files_skipped": None,
        "chunks": None,
    }
    assert empty["update"] == {
        "channel": "none",
        "policy": "manual",
        "current_version": None,
        "state": None,
        "target_version": None,
    }


def test_the_appliance_scope_reads_one_route_and_changes_nothing(api, world):
    machine, _, owner = prepared_machine(world, api)
    only = bearer(client_token(world, scopes=("appliance:read",)))
    assert api.get(f"{INTEGRATION}/machines/{machine.id}/appliance", headers=only).status_code == 200
    without = bearer(client_token(world, scopes=[s for s in API_CLIENT_SCOPES if s != "appliance:read"]))
    r = api.get(f"{INTEGRATION}/machines/{machine.id}/appliance", headers=without)
    assert r.status_code == 403 and "appliance:read" in r.json()["error"]["message"]
    everything = bearer(client_token(world, scopes=API_CLIENT_SCOPES))
    before = stored(world, machine).revision
    # An API client token opens none of the routes for people, and the integration API has no
    # route that changes the appliance.
    for method, suffix, body, _ in CHANGES:
        assert attempt(api, everything, machine, method, suffix, body).status_code == 401
        r = api.request(
            method,
            f"{INTEGRATION}/machines/{machine.id}/appliance{suffix}",
            headers=everything,
            json=body or {},
        )
        assert r.status_code in (404, 405), f"{method} {suffix}: {r.status_code}"
    for method in ("PUT", "POST", "PATCH", "DELETE"):
        r = api.request(
            method,
            f"{INTEGRATION}/machines/{machine.id}/appliance",
            headers=everything,
            json={"mode": "vast"},
        )
        assert r.status_code == 405
    assert stored(world, machine).revision == before
    assert "Changes nothing" in api_clients.SCOPE_HELP["appliance:read"]


def test_api_clients_follow_the_rule_of_whoever_they_act_for(api, world):
    machine, _, owner = prepared_machine(world, api)
    other = world.owner("Other")
    other_machine, _ = world.paired_machine(other)
    assert (
        api.put(
            url(machine, "/mode"), headers=world.auth(world.user("owner", owner)), json={"mode": "private_ai"}
        ).status_code
        == 200
    )
    fleet = bearer(client_token(world))
    scoped = bearer(client_token(world, owner_id=owner.id))
    path = f"{INTEGRATION}/machines/{machine.id}"

    def modes(headers) -> dict[str, str | None]:
        items = api.get(f"{INTEGRATION}/machines", headers=headers).json()["items"]
        return {item["id"]: item["mode"] for item in items}

    # Company-managed: HappyMining's own software reads it, like staff.
    assert api.get(f"{path}/appliance", headers=fleet).status_code == 200
    assert api.get(path, headers=fleet).json()["mode"] == "private_ai"
    assert modes(fleet) == {str(machine.id): "private_ai", str(other_machine.id): "vast"}
    assert modes(scoped) == {str(machine.id): "private_ai"}

    # Customer-managed, no grant: the fleet-wide client still sees the machine, not its appliance.
    set_management(world, machine, "customer")
    r = api.get(f"{path}/appliance", headers=fleet)
    assert r.status_code == 403 and code(r) == "remote_access_required"
    assert (
        api.get(path, headers=fleet).status_code == 200
        and api.get(path, headers=fleet).json()["mode"] is None
    )
    assert modes(fleet) == {str(machine.id): None, str(other_machine.id): "vast"}
    # A client limited to the owner acts for the owner.
    assert api.get(f"{path}/appliance", headers=scoped).status_code == 200
    assert api.get(path, headers=scoped).json()["mode"] == "private_ai"
    # Another owner's machine does not exist for it.
    assert api.get(f"{INTEGRATION}/machines/{other_machine.id}/appliance", headers=scoped).status_code == 404

    grant(world, machine, "view")
    assert api.get(f"{path}/appliance", headers=fleet).json()["mode"] == "private_ai"
    assert modes(fleet)[str(machine.id)] == "private_ai"
