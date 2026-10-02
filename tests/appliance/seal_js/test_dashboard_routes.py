"""The routes of ``dashboard_appliance.py`` run against fakes: no database at all.

The full behaviour, against PostgreSQL and the real services, is in
``tests/api/test_dashboard_appliance.py``. This file runs the same routes through the real
application (middleware, CSRF check, templates, error pages) with the session, the database
session and the service functions replaced by fakes that record how they were called. What it
shows: the CSRF token is checked before anything else; every route asks ``access.require_manage``
for the minimum role the matching JSON API route asks for (``org_admin`` for a plugin form that
carries a secret); the service receives the revision of the form and the fields in the shape of
the API's request body; a refusal of permission is an error page, anything else the service
objects to goes back to the page as a message, after a rollback; a refusal the service recorded
(``maintenance_blocked``, a blocked job) is committed first; the page has the CSP header, no
inline script and is not cached.
"""

from __future__ import annotations

import base64
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from test_dashboard_templates import MACHINE, SEAL_KEY, make_view

from happymining import dashboard_appliance as da
from happymining import sealing
from happymining.audit import Actor
from happymining.config import Settings
from happymining.dashboard import page_principal
from happymining.db import get_db
from happymining.errors import Conflict, Forbidden, NotFound
from happymining.main import create_app
from happymining.routers import views
from happymining.services import access
from happymining.services import appliance as appliance_service
from happymining.services import releases as release_service
from happymining.services.maintenance import SafetyDecision

REPO = Path(__file__).resolve().parents[3]
BASE = "http://127.0.0.1:8000"
CSRF = "the-csrf-token-of-this-session"
MACHINE_ID = uuid.UUID(MACHINE["id"])
PAGE = f"/machines/{MACHINE_ID}/appliance"


def settings() -> Settings:
    return Settings(
        mode="demo",
        provider="fake",
        database_url="postgresql+psycopg://nobody@127.0.0.1:9/never-connected",
        secret_key="pytest-" + "k" * 40,
        field_encryption_key="cHl0ZXN0LWZpZWxkLWVuY3J5cHRpb24ta2V5LTAwMDA=",
        public_base_url=BASE,
        allowed_hosts=["127.0.0.1", "localhost"],
        cookie_secure=False,
        catalog_dir=str(REPO / "appliance" / "testdata" / "catalog"),
    )


class FakeDB:
    def __init__(self) -> None:
        self.events: list[str] = []

    def commit(self) -> None:
        self.events.append("commit")

    def rollback(self) -> None:
        self.events.append("rollback")


class World:
    """The fakes of one test, and what was asked of them."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.monkeypatch = monkeypatch
        self.db = FakeDB()
        self.calls: list[tuple[str, tuple, dict]] = []
        self.role, self.org_role = "owner", "org_admin"
        self.forbid: Forbidden | None = None
        self.machine = SimpleNamespace(
            id=MACHINE_ID, owner_id=uuid.uuid4(), device=SimpleNamespace(hostname="gpu-01")
        )
        monkeypatch.setattr(da, "load_machine", self._load_machine)
        monkeypatch.setattr(access, "require_manage", self._require_manage)
        monkeypatch.setattr(
            access, "require_view", lambda db, principal, machine: self.calls.append(("require_view", (), {}))
        )
        monkeypatch.setattr(access, "staff_access", lambda db, machine: "manage")
        monkeypatch.setattr(appliance_service, "view", lambda db, s, principal, machine: make_view())
        monkeypatch.setattr(views, "machine_view", lambda s, machine, staff: dict(MACHINE))

    @property
    def principal(self) -> Any:
        user = SimpleNamespace(
            id=uuid.uuid4(),
            email=f"{self.role}@test.invalid",
            org_role=self.org_role,
            is_demo=True,
            role=self.role,
        )
        return SimpleNamespace(
            user=user,
            session=SimpleNamespace(csrf_token=CSRF),
            role=self.role,
            owner_id=self.machine.owner_id if self.role == "owner" else None,
            org_role=self.org_role,
            is_staff=self.role in ("admin", "auditor"),
            is_admin=self.role == "admin",
            actor=lambda ip="": Actor("user", str(user.id), ip),
        )

    def _load_machine(self, db, principal, machine_id, *, lock=False):
        self.calls.append(("load_machine", (machine_id,), {"lock": lock}))
        return self.machine

    def _require_manage(self, db, principal, machine, minimum_org_role="org_admin"):
        self.calls.append(("require_manage", (), {"minimum": minimum_org_role}))
        if self.forbid is not None:
            raise self.forbid

    def service(self, module: Any, name: str, result: Any = None, error: Exception | None = None) -> None:
        def fake(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            if error is not None:
                raise error
            return result

        self.monkeypatch.setattr(module, name, fake)

    def called(self, name: str) -> list[tuple[tuple, dict]]:
        return [(args, kwargs) for called, args, kwargs in self.calls if called == name]


@pytest.fixture
def world(monkeypatch) -> World:
    return World(monkeypatch)


@pytest.fixture
def browser(world) -> Iterator[TestClient]:
    app = create_app(settings())
    app.dependency_overrides[page_principal] = lambda: world.principal

    def fake_db():
        yield world.db

    app.dependency_overrides[get_db] = fake_db
    # Not entered as a context manager: the lifespan, which opens the database, does not run.
    yield TestClient(app, base_url=BASE)


def change(revision: int = 13, mode: str = "private_ai", changed: bool = True):
    return appliance_service.Change(
        row=SimpleNamespace(revision=revision, document={"mode": mode}), changed=changed
    )


def outcome(response) -> tuple[str, str, str]:
    """(path, "msg" or "err", text) of a form post's redirect."""
    assert response.status_code == 303, (response.status_code, response.text[:400])
    location = urlsplit(response.headers["location"])
    ((kind, (text,)),) = parse_qs(location.query).items()
    return location.path, kind, text


SEALED_NAS = sealing.seal(SEAL_KEY, "nas.docs.password", b"pw")
SEALED_KEY = sealing.seal(SEAL_KEY, "plugin.assistant.api_key", b"sk")

# (path under the page, form fields, service module, function, lowest organisation role,
#  arguments the function must receive after (db, settings, actor[, provider], machine)).
ROUTES = [
    ("/mode", {"mode": "private_ai"}, appliance_service, "set_mode", "org_admin", {"mode": "private_ai"}),
    (
        "/plugins/ollama",
        {"enabled": "true", "setting.models": "hermes3:8b\nbge-m3"},
        appliance_service,
        "set_plugin",
        "org_operator",
        {"enabled": True, "values": {"models": ["hermes3:8b", "bge-m3"]}, "sealed_secrets": None},
    ),
    (
        "/plugins/assistant",
        {
            "setting.bind": "lan",
            "setting.workers": "2",
            "setting.model": "m",
            "sealed_secret.api_key": SEALED_KEY,
        },
        appliance_service,
        "set_plugin",
        "org_admin",
        {"enabled": False, "sealed_secrets": {"api_key": SEALED_KEY}},
    ),
    ("/plugins/ollama/remove", {}, appliance_service, "remove_plugin", "org_operator", {}),
    (
        "/nas",
        {
            "nas_id": "docs",
            "kind": "smb",
            "host": "nas.lan",
            "share": "s",
            "username": "u",
            "access": "read",
            "sealed_secret": SEALED_NAS,
        },
        appliance_service,
        "set_nas",
        "org_admin",
        {
            "entry": {
                "kind": "smb",
                "host": "nas.lan",
                "share": "s",
                "username": "u",
                "domain": "",
                "access": "read",
            },
            "sealed_secret": SEALED_NAS,
        },
    ),
    ("/nas/docs/remove", {}, appliance_service, "remove_nas", "org_admin", {}),
    (
        "/vectorizer",
        {
            "sources": "docs",
            "extensions": "pdf",
            "max_file_mib": "8",
            "embedding_model": "bge-m3",
            "answer_provider": "none",
        },
        appliance_service,
        "set_vectorizer",
        "org_admin",
        {"sealed_secret": None},
    ),
    ("/vectorizer/remove", {}, appliance_service, "remove_vectorizer", "org_admin", {}),
    (
        "/backup",
        {"enabled": "true", "destination_kind": "nas", "destination_nas_id": "bk", "keep": "3"},
        appliance_service,
        "set_backup",
        "org_admin",
        {
            "section": {
                "enabled": True,
                "destination": {"kind": "nas", "nas_id": "bk"},
                "include_models": False,
                "keep": 3,
            },
            "sealed_secret": None,
        },
    ),
    ("/backup/remove", {}, appliance_service, "remove_backup", "org_admin", {}),
    (
        "/schedules",
        {
            "schedule_id": "nightly",
            "job": "backup_run",
            "every": "daily",
            "hour": "2",
            "minute": "30",
            "enabled": "true",
        },
        appliance_service,
        "set_schedule",
        "org_operator",
        {"entry": {"job": "backup_run", "every": "daily", "hour": 2, "minute": 30, "enabled": True}},
    ),
    ("/schedules/nightly/remove", {}, appliance_service, "remove_schedule", "org_operator", {}),
    (
        "/update",
        {"channel": "beta", "policy": "manual"},
        appliance_service,
        "set_update",
        "org_admin",
        {"section": {"channel": "beta", "policy": "manual"}},
    ),
]
OPERATIONS = [
    (
        "/jobs",
        {"job": "update_check"},
        appliance_service,
        "request_job",
        "org_operator",
        {"job": "update_check", "plugin": None},
    ),
    (
        "/install-update",
        {"version": "0.3.0"},
        release_service,
        "request_install",
        "org_admin",
        {"version": "0.3.0"},
    ),
]


def test_the_page_renders_with_the_security_headers_and_only_seal_js(world, browser):
    r = browser.get(PAGE)
    assert r.status_code == 200, r.text[:500]
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    assert r.text.count("<script") == 1 and '<script src="/static/seal.js" defer></script>' in r.text
    assert f'action="{PAGE}/mode"' in r.text and f'name="csrf_token" value="{CSRF}"' in r.text
    assert [name for name, *_ in world.calls] == ["load_machine", "require_view"]


def test_a_refused_view_is_an_error_page_with_the_services_reason(world, browser, monkeypatch):
    def refuse(db, principal, machine):
        raise Forbidden("this machine is managed by its owner; grant first", code="remote_access_required")

    monkeypatch.setattr(access, "require_view", refuse)
    r = browser.get(PAGE)
    assert r.status_code == 403 and "managed by its owner" in r.text
    assert f'action="{PAGE}' not in r.text and world.called("load_machine")


@pytest.mark.parametrize("route", ROUTES + OPERATIONS, ids=lambda r: r[0])
def test_without_the_csrf_token_nothing_is_even_looked_up(world, browser, route):
    suffix, fields, module, name, _, _ = route
    world.service(module, name, result=change())
    for token in ({}, {"csrf_token": "wrong"}):
        r = browser.post(PAGE + suffix, data={**fields, "revision": "12", **token}, follow_redirects=False)
        assert r.status_code == 403 and "CSRF token" in r.text
    r = browser.post(
        PAGE + suffix,
        data={**fields, "revision": "12", "csrf_token": CSRF},
        headers={"Origin": "https://attacker.example"},
        follow_redirects=False,
    )
    assert r.status_code == 403 and "cross-origin" in r.text
    assert world.calls == [] and world.db.events == []


@pytest.mark.parametrize("route", ROUTES, ids=lambda r: r[0])
def test_each_change_asks_for_the_apis_role_and_passes_the_form_to_the_service(world, browser, route):
    suffix, fields, module, name, minimum, expected = route
    world.service(module, name, result=change())
    r = browser.post(
        PAGE + suffix, data={**fields, "revision": "12", "csrf_token": CSRF}, follow_redirects=False
    )
    path, kind, text = outcome(r)
    assert (path, kind) == (PAGE, "msg") and "Saved as revision 13" in text, text
    assert [call for call, *_ in world.calls] == ["load_machine", "require_manage", name]
    assert world.called("load_machine") == [((MACHINE_ID,), {"lock": True})]
    assert world.called("require_manage") == [((), {"minimum": minimum})]
    ((args, kwargs),) = world.called(name)
    assert world.machine in args and kwargs["expected_revision"] == 12
    assert kwargs["user_id"] is not None
    for key, value in expected.items():
        assert kwargs[key] == value, key
    assert world.db.events == ["commit"]


@pytest.mark.parametrize("route", OPERATIONS, ids=lambda r: r[0])
def test_jobs_and_updates_are_operations_without_a_revision(world, browser, route):
    suffix, fields, module, name, minimum, expected = route
    world.service(module, name, result=SimpleNamespace(status="pending", params=dict(fields), detail=""))
    r = browser.post(PAGE + suffix, data={**fields, "csrf_token": CSRF}, follow_redirects=False)
    path, kind, text = outcome(r)
    assert (path, kind) == (PAGE, "msg") and "queued" in text
    assert world.called("require_manage") == [((), {"minimum": minimum})]
    ((args, kwargs),) = world.called(name)
    assert "expected_revision" not in kwargs and world.machine in args
    for key, value in expected.items():
        assert kwargs[key] == value, key
    assert world.db.events == ["commit"]


@pytest.mark.parametrize("route", ROUTES + OPERATIONS, ids=lambda r: r[0])
def test_a_permission_refusal_is_an_error_page_and_the_service_is_never_called(world, browser, route):
    suffix, fields, module, name, minimum, _ = route
    world.service(module, name, result=change())
    world.forbid = Forbidden(f"this needs the {minimum} role in your organisation")
    r = browser.post(
        PAGE + suffix, data={**fields, "revision": "12", "csrf_token": CSRF}, follow_redirects=False
    )
    assert r.status_code == 403 and f"this needs the {minimum} role" in r.text
    assert world.called(name) == [] and world.db.events == ["rollback"]


def test_a_machine_that_does_not_exist_for_the_caller_is_not_found(world, browser, monkeypatch):
    def missing(db, principal, machine_id, *, lock=False):
        raise NotFound()

    monkeypatch.setattr(da, "load_machine", missing)
    world.service(appliance_service, "set_mode", result=change())
    r = browser.post(
        PAGE + "/mode", data={"mode": "vast", "revision": "1", "csrf_token": CSRF}, follow_redirects=False
    )
    assert r.status_code == 404 and world.called("set_mode") == []


@pytest.mark.parametrize(
    "error",
    [
        Conflict("this machine follows its own profile file (control: local)", code="locally_controlled"),
        Conflict("the machine has not reported its sealing key yet", code="no_sealing_key"),
        Conflict("the configuration changed in the meantime (it is at revision 13)"),
        NotFound("this NAS entry is not configured on the machine"),
    ],
    ids=lambda e: e.code,
)
def test_what_the_service_objects_to_goes_back_to_the_page(world, browser, error):
    world.service(appliance_service, "set_mode", error=error)
    r = browser.post(
        PAGE + "/mode", data={"mode": "vast", "revision": "12", "csrf_token": CSRF}, follow_redirects=False
    )
    assert outcome(r) == (PAGE, "err", error.message)
    assert world.db.events == ["rollback"]
    page = browser.get(r.headers["location"])
    assert error.message.replace("(", "").split(" ")[0] in page.text and 'class="flash err"' in page.text


def test_a_form_without_its_revision_is_refused_before_the_service(world, browser):
    world.service(appliance_service, "set_mode", result=change())
    r = browser.post(PAGE + "/mode", data={"mode": "vast", "csrf_token": CSRF}, follow_redirects=False)
    path, kind, text = outcome(r)
    assert kind == "err" and "which revision" in text and world.called("set_mode") == []


def test_a_blocked_mode_change_is_committed_then_reported(world, browser):
    decision = SafetyDecision(allowed=False, reasons=["rental state is unknown"], checks={})
    world.service(
        appliance_service,
        "set_mode",
        result=appliance_service.Change(row=None, changed=False, blocked=decision),
    )
    r = browser.post(
        PAGE + "/mode",
        data={"mode": "private_ai", "revision": "12", "csrf_token": CSRF},
        follow_redirects=False,
    )
    assert outcome(r) == (PAGE, "err", "Blocked; requires operator handling: rental state is unknown")
    assert world.db.events == ["commit"]  # the refusal is in the audit trail


def test_a_blocked_job_is_committed_then_reported(world, browser):
    world.service(
        appliance_service,
        "request_job",
        result=SimpleNamespace(
            status="blocked", params={"job": "update_check"}, detail="Blocked; requires operator handling: x"
        ),
    )
    r = browser.post(PAGE + "/jobs", data={"job": "update_check", "csrf_token": CSRF}, follow_redirects=False)
    assert outcome(r) == (PAGE, "err", "Blocked; requires operator handling: x") and world.db.events == [
        "commit"
    ]


def test_nothing_changed_is_said_so(world, browser):
    world.service(appliance_service, "set_mode", result=change(changed=False))
    r = browser.post(
        PAGE + "/mode", data={"mode": "vast", "revision": "12", "csrf_token": CSRF}, follow_redirects=False
    )
    assert "Nothing changed" in outcome(r)[2]


def test_a_plugin_form_that_removes_a_stored_secret_is_an_administrators(world, browser):
    world.service(appliance_service, "set_plugin", result=change())
    fields = {
        "setting.bind": "lan",
        "setting.workers": "2",
        "setting.model": "m",
        "remove_secret.api_key": "true",
    }
    r = browser.post(
        PAGE + "/plugins/assistant",
        data={**fields, "revision": "12", "csrf_token": CSRF},
        follow_redirects=False,
    )
    assert outcome(r)[1] == "msg"
    assert world.called("require_manage") == [((), {"minimum": "org_admin"})]
    assert world.called("set_plugin")[0][1]["sealed_secrets"] == {"api_key": None}


def test_a_plugin_that_is_not_in_the_catalog_is_reported(world, browser):
    world.service(appliance_service, "set_plugin", result=change())
    for plugin in ("nope", "Bad_Id"):
        r = browser.post(
            PAGE + f"/plugins/{plugin}", data={"revision": "12", "csrf_token": CSRF}, follow_redirects=False
        )
        assert outcome(r) == (PAGE, "err", "this plugin is not in the catalog")
    assert world.called("set_plugin") == []


# --- releases ------------------------------------------------------------------


def test_the_releases_page_is_for_staff(world, browser, monkeypatch):
    monkeypatch.setattr(release_service, "list_releases", lambda db: [])
    world.role, world.org_role = "admin", None
    r = browser.get("/admin/releases")
    assert r.status_code == 200 and "No release yet." in r.text and "<script" not in r.text
    assert "nothing can be published" in r.text  # no key configured in these settings
    world.role, world.org_role = "owner", "org_admin"
    assert browser.get("/admin/releases").status_code == 403


def test_publishing_passes_the_manifest_bytes_and_the_signature_to_the_service(world, browser):
    world.role, world.org_role = "admin", None
    world.service(release_service, "create_release", result=SimpleNamespace(version="0.3.0"))
    manifest = b'{"schema": 1}\n'
    r = browser.post(
        "/admin/releases",
        data={"csrf_token": CSRF},
        files={
            "manifest": ("manifest.json", manifest, "application/json"),
            "signature_file": ("manifest.sig", b"c2ln\n", "text/plain"),
        },
        follow_redirects=False,
    )
    assert outcome(r) == (
        "/admin/releases",
        "msg",
        "Release 0.3.0 accepted. Upload its package next (see below).",
    )
    ((_, kwargs),) = world.called("create_release")
    assert kwargs["manifest_b64"] == base64.b64encode(manifest).decode() and kwargs["signature_b64"] == "c2ln"
    # A manifest larger than a manifest may be, or none at all: refused before the service.
    for files in ({"manifest": ("m.json", b"x" * (16 * 1024 + 1), "application/json")}, {}):
        r = browser.post(
            "/admin/releases",
            data={"csrf_token": CSRF, "signature": "c2ln"},
            files=files or None,
            follow_redirects=False,
        )
        assert outcome(r)[1] == "err"
    assert len(world.called("create_release")) == 1
    # An auditor: refused after the CSRF check, before anything else.
    world.role = "auditor"
    r = browser.post(
        "/admin/releases",
        data={"csrf_token": CSRF},
        files={"manifest": ("m.json", manifest, "application/json")},
        follow_redirects=False,
    )
    assert r.status_code == 403 and len(world.called("create_release")) == 1


def test_channels_and_withdrawal_go_through_the_release_service(world, browser):
    world.role, world.org_role = "admin", None
    world.service(
        release_service, "set_channels", result=SimpleNamespace(version="0.3.0", channels=["beta", "stable"])
    )
    world.service(release_service, "withdraw", result=SimpleNamespace(version="0.3.0"))
    r = browser.post(
        "/admin/releases/0.3.0/channels",
        data={"csrf_token": CSRF, "channels": ["beta", "stable"]},
        follow_redirects=False,
    )
    assert outcome(r) == ("/admin/releases", "msg", "Release 0.3.0 is offered on: beta, stable.")
    ((args, _),) = world.called("set_channels")
    assert args[-2:] == ("0.3.0", ["beta", "stable"])
    r = browser.post(
        "/admin/releases/0.3.0/withdraw",
        data={"csrf_token": CSRF, "reason": "bad build"},
        follow_redirects=False,
    )
    assert outcome(r)[1] == "msg"
    ((args, _),) = world.called("withdraw")
    assert args[-2:] == ("0.3.0", "bad build")
    for path in ("/admin/releases/0.3.0/channels", "/admin/releases/0.3.0/withdraw"):
        assert browser.post(path, data={"reason": "x"}, follow_redirects=False).status_code == 403
    assert len(world.called("set_channels")) == 1 and len(world.called("withdraw")) == 1
