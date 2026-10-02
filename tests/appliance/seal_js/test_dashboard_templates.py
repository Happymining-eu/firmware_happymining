"""The appliance and releases pages of the dashboard, without a database.

What can be checked without PostgreSQL is checked here; the routes themselves, with sessions,
CSRF and permissions, are in ``tests/api/test_dashboard_appliance.py``.

1. The new templates render with the dashboard's own Jinja environment (autoescape on), and
   also with undefined names made errors, from hand-built context objects that have the shape
   ``services/appliance.view`` returns (fed through the same ``appliance_context`` the route
   uses).
2. The Content-Security-Policy rule (``script-src 'self'``, ``style-src 'self'``): no template
   has a ``<script>`` without ``src``, an ``on…=`` handler or a ``style`` attribute.
3. Secrets: every password field has no ``name``; it names a hidden input of its own form and
   the secret name it is sealed under, which is exactly the name the service stores it as; its
   form carries the machine's key; without a key the fields are disabled and say why.
4. Each form is there only for whoever may use it, by the ``can_operate`` / ``can_admin`` the
   service computes, and none but the jobs and updates under ``control: local``.
5. The form readers put fields into exactly the request bodies of the JSON API.
"""

from __future__ import annotations

import copy
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from jinja2 import StrictUndefined
from markupsafe import escape
from starlette.datastructures import FormData, UploadFile

from happymining import dashboard_appliance as da
from happymining import sealing
from happymining.dashboard import TEMPLATES
from happymining.errors import InvalidRequest
from happymining.services import appliance as appliance_service
from happymining.services import catalog as catalog_service

REPO = Path(__file__).resolve().parents[3]
TEMPLATE_DIR = REPO / "dashboard" / "templates"
NEW_TEMPLATES = ("appliance.html", "appliance_macros.html", "admin_releases.html")
CATALOG = catalog_service.load_catalog(REPO / "appliance" / "testdata" / "catalog")
SEAL_KEY = json.loads((REPO / "appliance" / "testdata" / "seal-vectors.json").read_text())[
    "machine_public_key"
]
MACHINE_ID = "6f1c1b7e-0000-4000-8000-000000000001"
CSRF = "csrf-token-of-this-session"
SEALED = sealing.seal(SEAL_KEY, "nas.docs.password", b"correct horse battery staple")

STRICT = TEMPLATES.env.overlay(undefined=StrictUndefined)


# --- context builders --------------------------------------------------------


def full_document() -> dict[str, Any]:
    """Everything configured, as services/appliance.stored_document returns it."""
    return {
        "schema": 1,
        "mode": "private_ai",
        "plugins": [
            {"id": "ollama", "enabled": True, "settings": {"models": ["hermes3:8b", "bge-m3"]}},
            {"id": "qdrant", "enabled": True, "settings": {}},
            {"id": "vectorizer", "enabled": True, "settings": {}},
        ],
        "nas": [
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
            },
            {
                "id": "bk",
                "kind": "nfs",
                "host": "192.168.1.20",
                "export": "/volume1/backup",
                "access": "write",
            },
        ],
        "vectorizer": {
            "sources": ["docs"],
            "extensions": ["pdf", "md"],
            "exclude": ["#recycle"],
            "max_file_mib": 64,
            "embedding_model": "bge-m3",
            "ocr": False,
            "answer": {
                "provider": "openai_compatible",
                "model": "gpt-4.1-mini",
                "base_url": "https://api.openai.com/v1",
                "secret": "ai.answer.api_key",
            },
        },
        "backup": {
            "enabled": True,
            "destination": {
                "kind": "s3",
                "endpoint": "https://s3.eu-central-1.amazonaws.com",
                "region": "eu-central-1",
                "bucket": "acme-hm-backups",
                "prefix": "site1/",
                "access_key_id": "AKIAEXAMPLEKEY000001",
                "secret": "backup.s3.secret_key",
            },
            "include_models": False,
            "keep": 7,
        },
        "schedules": [
            {
                "id": "nightly-sync",
                "job": "vectorize_sync",
                "every": "daily",
                "hour": 2,
                "minute": 30,
                "enabled": True,
            },
            {
                "id": "restart-llm",
                "job": "plugin_restart",
                "plugin": "ollama",
                "every": "hourly",
                "minute": 5,
                "enabled": False,
            },
            {
                "id": "weekly-backup",
                "job": "backup_run",
                "every": "weekly",
                "weekday": 6,
                "hour": 3,
                "minute": 0,
                "enabled": True,
            },
        ],
        "update": {"channel": "stable", "policy": "auto", "window": {"start_hour": 2, "end_hour": 5}},
    }


def full_report() -> dict[str, Any]:
    """What a machine reports, after services/appliance.sanitise_report."""
    return {
        "schema": 1,
        "control": "cloud",
        "applied_revision": 11,
        "apply_status": "partial",
        "apply_detail": "qdrant: <b>could not start</b>",
        "mode": "private_ai",
        "capabilities": {"plugins": True, "nas": True, "backup": True, "update": False, "docker": True},
        "catalog": [{"id": p, "version": "1"} for p in ("ollama", "qdrant", "vectorizer")],
        "plugins": [
            {"id": "ollama", "state": "running", "detail": "", "version": "1", "ports": [11434]},
            {
                "id": "qdrant",
                "state": "error",
                "detail": "<script>alert(1)</script>",
                "version": "1",
                "ports": [],
            },
        ],
        "nas": [
            {"id": "docs", "state": "mounted", "detail": ""},
            {"id": "bk", "state": "error", "detail": "timeout"},
        ],
        "secrets": [
            {"name": "nas.docs.password", "state": "ok"},
            {"name": "ai.answer.api_key", "state": "unreadable"},
        ],
        "vectorizer": {
            "state": "idle",
            "last_run_at": "2026-10-02T02:30:00+00:00",
            "last_ok_at": "2026-10-02T02:41:10+00:00",
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
            "last_ok_at": "2026-10-02T03:10:00+00:00",
            "last_size_bytes": 123456,
            "detail": "",
        },
        "update": {"current_version": "0.2.0", "state": "idle", "target_version": "", "detail": ""},
        "schedules": [
            {
                "id": "nightly-sync",
                "last_run_at": "2026-10-02T02:30:00+00:00",
                "last_status": "ok",
                "next_run_at": "2026-10-03T02:30:00+00:00",
            }
        ],
    }


def catalog_view(on_machine: set[str] | None) -> list[dict[str, Any]]:
    return [
        {
            **entry.public(),
            "on_machine": None if on_machine is None else entry.id in on_machine,
            "machine_version": "1" if on_machine and entry.id in on_machine else None,
        }
        for entry in CATALOG
    ]


def make_view(*, can_operate: bool = True, can_admin: bool = True, **changes: Any) -> dict[str, Any]:
    """The shape of services/appliance.view(): a machine with everything configured."""
    view = {
        "machine_id": MACHINE_ID,
        "management": "company",
        "revision": 12,
        "applied_revision": 11,
        "in_sync": False,
        "control": "cloud",
        "updated_at": "2026-10-02T10:00:00+00:00",
        "updated_by": None,
        "document": full_document(),
        "secrets": ["ai.answer.api_key", "backup.s3.secret_key", "nas.docs.password"],
        "seal_public_key": SEAL_KEY,
        "reported": full_report(),
        "reported_at": "2026-10-02T10:01:00+00:00",
        "catalog": catalog_view({"ollama", "qdrant", "vectorizer"}),
        "can_operate": can_operate,
        "can_admin": can_admin,
    }
    view.update(changes)
    return view


def empty_view(**changes: Any) -> dict[str, Any]:
    """A machine nothing was configured for and that never reported."""
    return make_view(
        revision=0,
        applied_revision=0,
        in_sync=True,
        document=appliance_service.stored_document(None),
        secrets=[],
        seal_public_key=None,
        reported=None,
        reported_at=None,
        updated_at=None,
        catalog=catalog_view(None),
        **changes,
    )


MACHINE = {
    "id": MACHINE_ID,
    "label": "gpu-01 <&>",
    "synthetic": True,
    "agent_version": "0.2.0",
    "provider": None,
    "connection": "online",
}


def base_context(role: str, org_role: str | None) -> dict[str, Any]:
    user = SimpleNamespace(email=f"{role}@test.invalid", org_role=org_role, is_demo=True)
    return {
        "settings": SimpleNamespace(),
        "demo": True,
        "user": user,
        "role": role,
        "csrf": CSRF,
        "message": "",
        "error": "",
        "now": None,
    }


def flat(html: str) -> str:
    """The page with every run of white space as one space, for checks on its text."""
    return " ".join(html.split())


def render_appliance(
    view: dict[str, Any],
    *,
    role: str = "owner",
    org_role: str | None = "org_admin",
    strict: bool = True,
    **facts,
) -> str:
    context = da.appliance_context(view, hostname="gpu-01", **facts)
    env = STRICT if strict else TEMPLATES.env
    return env.get_template("appliance.html").render(
        **base_context(role, org_role), machine=dict(MACHINE), a=context
    )


# --- a small HTML reader -----------------------------------------------------


class Page(HTMLParser):
    """Forms with their fields, scripts, and every start tag with its attributes."""

    def __init__(self, html: str):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self.scripts: list[dict[str, str | None]] = []
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self._form: dict[str, Any] | None = None
        self.feed(html)
        self.close()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        self.tags.append((tag, attributes))
        if tag == "form":
            self._form = {"attrs": attributes, "fields": []}
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea") and self._form is not None:
            self._form["fields"].append({"tag": tag, **attributes})
        elif tag == "script":
            self.scripts.append(attributes)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None

    def post_forms(self) -> list[dict[str, Any]]:
        return [f for f in self.forms if (f["attrs"].get("method") or "").lower() == "post"]

    def actions(self) -> list[str]:
        return [f["attrs"]["action"] for f in self.post_forms() if f["attrs"]["action"] != "/logout"]

    def passwords(self) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        return [
            (form, field)
            for form in self.forms
            for field in form["fields"]
            if field["tag"] == "input" and field.get("type") == "password"
        ]


def named(form: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return [field for field in form["fields"] if field.get("name") == name]


APPLIANCE = f"/machines/{MACHINE_ID}/appliance"
CONFIG_ACTIONS = ("/mode", "/nas", "/vectorizer", "/backup", "/update")
OPERATOR_ACTIONS = ("/plugins/", "/schedules")


def kinds(actions: list[str]) -> set[str]:
    """The kind of each form: /mode, /plugins/, /nas, ..., /jobs, /install-update."""
    out = set()
    for action in actions:
        assert action.startswith(APPLIANCE), action
        rest = action[len(APPLIANCE) :]
        out.add("/plugins/" if rest.startswith("/plugins/") else "/" + rest.split("/")[1])
    return out


# --- 1. rendering --------------------------------------------------------------


@pytest.mark.parametrize(
    "view",
    [make_view(), empty_view(), make_view(can_operate=False, can_admin=False), make_view(can_admin=False)],
    ids=["everything", "nothing yet", "viewer", "operator"],
)
def test_the_appliance_page_renders_with_undefined_names_as_errors(view):
    html = render_appliance(view)
    assert "Appliance of gpu-01 &lt;&amp;&gt;" in html  # autoescape is on
    Page(html)


def test_the_page_shows_desired_and_applied_state_and_what_the_machine_reports():
    html = flat(render_appliance(make_view(), staff_access="manage", may_see_remote_access=True))
    for text in (
        "revision 12",
        "Applied by the machine: 11",
        "not in sync",
        "partial",
        "HappyMining's access: manage",
        f'href="/machines/{MACHINE_ID}#remote-access"',
        "http://gpu-01:11434/",  # the LAN hint of a plugin port
        "published ports: 11434",
        "1820",  # vectorizer counters
        "40211",
        "9f2c1a7b",  # backup key id
        "0.2.0",
        "every day at 02:30",
        "every hour at :05",
        "every Sunday at 03:00",
        "installs between 02:00 and 05:00",
        "does not open with this machine's key: enter it again",
        "The machine cannot open some of its secrets",
    ):
        assert text in html, text
    # What the machine says is text, never markup.
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<b>could not start</b>" not in html
    # Secrets are names, never values.
    assert "hmseal1." not in html and SEALED not in html


def test_without_a_key_on_the_machine_the_backup_section_says_what_to_run():
    view = make_view()
    view["reported"]["backup"] = {
        **view["reported"]["backup"],
        "key_present": False,
        "key_id": "",
        "state": "no_key",
    }
    html = flat(render_appliance(view))
    assert 'No key: run <span class="mono">sudo happyminingctl backup init</span> on the machine' in html


def test_the_mode_section_explains_each_mode_and_the_vast_gate_when_bound():
    bound = flat(render_appliance(make_view(), provider_bound=True))
    free = flat(render_appliance(make_view(), provider_bound=False))
    for mode, text in da.MODE_HELP.items():
        assert str(escape(text)) in bound and mode.replace("_", " ") in bound
    assert "bound to a provider machine on Vast" in bound and "rental-protection" in bound
    assert "Vast does not expose the rental state" in bound
    assert "not bound to a provider machine" in free and "bound to a provider machine on Vast" not in free


def test_a_cloud_answer_provider_comes_with_the_contracts_warning():
    html = flat(render_appliance(make_view()))
    assert "each question and the passages retrieved for it" in html
    assert "are sent to that provider, with your key, from your machine" in html


def test_the_releases_page_renders_for_staff():
    releases = [
        {
            "version": "0.3.0",
            "status": "awaiting_artifact",
            "channels": [],
            "filename": "happymining-agent_0.3.0_amd64.deb",
            "size": 9412345,
            "sha256": "a" * 64,
            "key_id": "0123456789abcdef",
            "min_upgrade_from": "0.1.0",
            "notes": "<i>notes</i>",
            "created_at": "2026-10-02T12:00:00+00:00",
            "created_by": None,
            "published_at": None,
            "withdrawn_at": None,
        },
        {
            "version": "0.2.0",
            "status": "ready",
            "channels": ["stable"],
            "filename": "happymining-agent_0.2.0_amd64.deb",
            "size": 9000000,
            "sha256": "b" * 64,
            "key_id": "0123456789abcdef",
            "min_upgrade_from": "0.1.0",
            "notes": "",
            "created_at": "2026-09-02T12:00:00+00:00",
            "created_by": None,
            "published_at": "2026-09-02T13:00:00+00:00",
            "withdrawn_at": None,
        },
    ]
    common = {
        "releases": releases,
        "key_ids": ["0123456789abcdef"],
        "key_problem": "",
        "channels": ("beta", "stable"),
        "max_bytes": 128 * 1024 * 1024,
        "api_base": "https://hm.example.test/api/v1",
    }
    template = STRICT.get_template("admin_releases.html")
    admin = Page(html := template.render(**base_context("admin", None), **common))
    assert (
        "&lt;i&gt;notes&lt;/i&gt;" in html
        and "PUT https://hm.example.test/api/v1/releases/X.Y.Z/artifact" in html
    )
    assert "limited to 1 MiB" in html and "scripts/release-sign.py" in html
    actions = admin.actions()
    assert actions == ["/admin/releases/0.2.0/channels", "/admin/releases/0.2.0/withdraw", "/admin/releases"]
    upload = admin.post_forms()[-1]
    assert upload["attrs"]["enctype"] == "multipart/form-data"
    assert {f.get("name") for f in upload["fields"]} == {
        "csrf_token",
        "manifest",
        "signature_file",
        "signature",
    }
    for form in admin.post_forms():
        assert [f["value"] for f in named(form, "csrf_token")] == [CSRF]
    auditor = Page(template.render(**base_context("auditor", None), **common))
    assert auditor.actions() == []
    nothing = template.render(**base_context("admin", None), **{**common, "key_ids": [], "releases": []})
    assert "nothing can be published" in nothing and "No release yet." in nothing


def test_the_machine_page_links_to_the_appliance_for_whoever_may_see_it():
    template = TEMPLATES.env.get_template("machine.html")
    common = {
        "machine": dict(MACHINE, last_seen_age_s=5),
        "latest": None,
        "samples": [],
        "operations": [],
        "safe_types": (),
        "grant_users": {},
        "staff_may_manage": False,
        "grant_durations": [],
    }
    link = f'href="/machines/{MACHINE_ID}/appliance"'
    owner = template.render(**base_context("owner", "org_viewer"), remote=None, is_org_admin=False, **common)
    assert link in owner
    remote = {"management": "customer", "staff_access": "none", "grants": [], "past_grants": []}
    staff = template.render(**base_context("admin", None), remote=remote, is_org_admin=False, **common)
    assert link not in staff and "no access" in staff and 'id="remote-access"' in staff
    granted = template.render(
        **base_context("auditor", None),
        remote={**remote, "staff_access": "view"},
        is_org_admin=False,
        **common,
    )
    assert link in granted
    assert "<script" not in owner + staff + granted


# --- 2. the Content-Security-Policy -----------------------------------------------

INLINE_HANDLER = re.compile(r"<[^>]*\son[a-z]+\s*=", re.IGNORECASE)
SCRIPT_TAG = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)


@pytest.mark.parametrize("path", sorted(TEMPLATE_DIR.glob("*.html")), ids=lambda p: p.name)
def test_no_template_has_an_inline_script_or_handler(path):
    text = path.read_text()
    for attributes in SCRIPT_TAG.findall(text):
        assert re.search(r'\ssrc="/static/[a-z0-9_.-]+\.js"', attributes), (
            f"{path.name}: <script{attributes}>"
        )
    assert not INLINE_HANDLER.search(text), path.name
    assert "javascript:" not in text.lower(), path.name


@pytest.mark.parametrize("name", NEW_TEMPLATES)
def test_the_new_templates_have_no_inline_style(name):
    text = (TEMPLATE_DIR / name).read_text()
    assert not re.search(r"\sstyle\s*=", text, re.IGNORECASE) and "<style" not in text.lower()


def test_the_rendered_page_loads_only_seal_js_and_only_for_those_who_enter_secrets():
    for view, expected in (
        (make_view(), [{"src": "/static/seal.js", "defer": None}]),
        (make_view(can_admin=False), []),
        (make_view(can_operate=False, can_admin=False), []),
    ):
        page = Page(html := render_appliance(view))
        assert page.scripts == expected
        assert not INLINE_HANDLER.search(html)
        assert all(not name.startswith("on") for _, attrs in page.tags for name in attrs)
        assert all("style" not in attrs for _, attrs in page.tags)


# --- 3. secrets ----------------------------------------------------------------------


def expected_secret_names() -> set[str]:
    """The names the service stores the secrets of the full view under."""
    return {
        appliance_service.nas_secret_name("docs"),
        appliance_service.ANSWER_KEY_NAME,
        appliance_service.S3_KEY_NAME,
        # ollama, qdrant and vectorizer take no secret; the assistant's form is the "add" one.
        CATALOG.get("assistant").secret_name("api_key"),
    }


def test_password_fields_have_no_name_and_seal_into_a_hidden_field_of_their_own_form():
    page = Page(render_appliance(make_view()))
    passwords = page.passwords()
    # docs, bk (its form can turn it into an SMB entry), a new NAS entry, the answer key, the S3 key,
    # the assistant's key.
    assert len(passwords) == 6
    names, templates = set(), set()
    for form, field in passwords:
        assert "name" not in field, field
        assert form["attrs"].get("data-seal-key") == SEAL_KEY
        assert "disabled" not in field and field.get("autocomplete") == "new-password"
        (target,) = named(form, field["data-seal-target"])
        assert target["tag"] == "input" and target["type"] == "hidden" and target["value"] == ""
        if "data-seal-name" in field:
            names.add(field["data-seal-name"])
        else:
            templates.add((field["data-seal-name-template"], field["data-seal-name-field"]))
            # The id the name is built from is a field of the same form.
            assert named(form, field["data-seal-name-field"])
        assert [f["value"] for f in named(form, "csrf_token")] == [CSRF]
    assert names == expected_secret_names() | {appliance_service.nas_secret_name("bk")}
    assert templates == {(appliance_service.nas_secret_name("{id}"), "nas_id")}
    assert appliance_service.nas_secret_name("{id}").replace("{id}", "docs") == "nas.docs.password"


def test_the_hidden_fields_are_the_ones_the_route_reads():
    page = Page(render_appliance(make_view()))
    targets = {field["data-seal-target"] for _, field in page.passwords()}
    assert targets == {
        da.NAS_SECRET_FIELD,
        da.ANSWER_SECRET_FIELD,
        da.S3_SECRET_FIELD,
        da.PLUGIN_SECRET_PREFIX + "api_key",
    }


def test_without_a_sealing_key_the_secret_fields_are_disabled_and_say_why():
    html = flat(render_appliance(make_view(seal_public_key=None)))
    page = Page(html)
    assert page.passwords() and all("disabled" in field for _, field in page.passwords())
    assert "the machine has not reported its sealing key yet" in html
    assert "Secret fields are disabled" in html


def test_a_stored_secret_is_shown_by_name_and_state_only():
    html = render_appliance(make_view())
    assert "stored; leave empty to keep it" in html
    for name in expected_secret_names() - {"plugin.assistant.api_key"}:
        assert name in html


# --- 4. who sees which form ------------------------------------------------------------


def test_an_administrator_has_every_form():
    page = Page(render_appliance(make_view()))
    assert kinds(page.actions()) == {
        "/mode",
        "/plugins/",
        "/nas",
        "/vectorizer",
        "/backup",
        "/schedules",
        "/update",
        "/jobs",
        "/install-update",
    }
    for form in page.post_forms():
        action = form["attrs"]["action"]
        assert [f["value"] for f in named(form, "csrf_token")] == [CSRF], action
        revision = named(form, "revision")
        if action.endswith(("/jobs", "/install-update")) or action == "/logout":
            assert revision == [], action  # operations, not changes to the document
        else:
            assert [f["value"] for f in revision] == ["12"], action


def test_an_operator_has_plugins_schedules_and_jobs_and_no_secret_field():
    html = flat(render_appliance(make_view(can_admin=False), org_role="org_operator"))
    page = Page(html)
    assert kinds(page.actions()) == {"/plugins/", "/schedules", "/jobs"}
    assert page.passwords() == [] and "set by an administrator" in html
    assert not any(f["attrs"].get("data-seal-key") is not None for f in page.forms)


def test_a_viewer_has_no_form_at_all():
    page = Page(render_appliance(make_view(can_operate=False, can_admin=False), org_role="org_viewer"))
    assert page.actions() == [] and page.passwords() == []


def test_a_locally_controlled_machine_is_read_only_here_but_for_jobs_and_updates():
    view = make_view(control="local")
    view["reported"]["control"] = "local"
    html = flat(render_appliance(view))
    assert "control: local" in html and "cannot be changed from this page" in html
    page = Page(html)
    assert kinds(page.actions()) == {"/jobs", "/install-update"} and page.passwords() == []


def test_plugin_forms_are_generated_from_the_catalog_entry():
    page = Page(render_appliance(make_view()))
    (assistant,) = [f for f in page.post_forms() if f["attrs"]["action"] == f"{APPLIANCE}/plugins/assistant"]
    fields = {f.get("name"): f for f in assistant["fields"] if f.get("name")}
    assert fields["enabled"]["type"] == "checkbox" and fields["enabled"]["value"] == "true"
    assert fields["setting.telemetry"]["type"] == "checkbox" and "checked" not in fields["setting.telemetry"]
    assert fields["setting.workers"]["type"] == "number"
    assert (fields["setting.workers"]["min"], fields["setting.workers"]["max"]) == ("1", "8")
    assert fields["setting.workers"]["value"] == "2"
    assert fields["setting.bind"]["tag"] == "select"
    assert fields["setting.model"]["value"] == "hermes3:8b" and fields["setting.model"]["maxlength"] == "100"
    assert "sealed_secret.api_key" in fields
    (ollama,) = [f for f in page.post_forms() if f["attrs"]["action"] == f"{APPLIANCE}/plugins/ollama"]
    (models,) = named(ollama, "setting.models")
    assert models["tag"] == "textarea"
    html = render_appliance(make_view())
    assert "hermes3:8b\nbge-m3</textarea>" in html


def test_a_plugin_the_firmware_does_not_have_is_flagged():
    view = make_view(catalog=catalog_view({"ollama"}))
    assert "This machine's firmware does not have this plugin" in flat(render_appliance(view))


# --- 5. from form fields to the API's request bodies ----------------------------------------


def form(*items: tuple[str, Any]) -> FormData:
    return FormData(list(items))


def test_plugin_settings_are_typed_after_the_catalog():
    spec = CATALOG.get("assistant")
    body = da.plugin_request(
        spec,
        form(
            ("enabled", "true"),
            ("setting.bind", "localhost"),
            ("setting.workers", " 4 "),
            ("setting.model", "llama3:8b"),
            # unchecked: telemetry absent
        ),
    )
    assert body.enabled is True and body.sealed_secrets is None
    assert body.settings == {"bind": "localhost", "workers": 4, "telemetry": False, "model": "llama3:8b"}
    lists = da.plugin_request(CATALOG.get("ollama"), form(("setting.models", "hermes3:8b\r\n\n  bge-m3 \n")))
    assert lists.enabled is False and lists.settings == {"models": ["hermes3:8b", "bge-m3"]}
    # A field for a setting the catalog does not have reaches the service, which refuses it.
    odd = da.plugin_request(CATALOG.get("qdrant"), form(("setting.shell", "x")))
    assert odd.settings == {"shell": "x"}
    document = {
        "schema": 1,
        "revision": 1,
        "mode": "vast",
        "plugins": [{"id": "qdrant", "enabled": False, "settings": odd.settings}],
    }
    with pytest.raises(appliance_service.DocumentInvalid, match="has a setting this plugin does not take"):
        appliance_service.validate_document(document, CATALOG)
    with pytest.raises(InvalidRequest, match=r"setting\.workers: must be a whole number"):
        da.plugin_request(spec, form(("setting.workers", "four")))


def test_plugin_secrets_and_who_may_send_them():
    sealed = sealing.seal(SEAL_KEY, "plugin.assistant.api_key", b"sk-1")
    assert da.touches_plugin_secrets(form(("sealed_secret.api_key", ""))) is False
    assert da.touches_plugin_secrets(form(("sealed_secret.api_key", sealed))) is True
    assert da.touches_plugin_secrets(form(("remove_secret.api_key", "true"))) is True
    assert da.touches_plugin_secrets(form(("enabled", "true"), ("setting.workers", "2"))) is False
    spec = CATALOG.get("assistant")
    settings = (("setting.bind", "lan"), ("setting.workers", "2"), ("setting.model", "hermes3:8b"))

    def sent(*items):
        return da.plugin_request(spec, form(*settings, *items)).sealed_secrets

    assert sent(("sealed_secret.api_key", sealed)) == {"api_key": sealed}
    assert sent(("remove_secret.api_key", "true")) == {"api_key": None}
    # The check reads the form exactly as the removal does: padding does not
    # turn a removal into an operator's change.
    for padded in (" true", "true ", "\ttrue"):
        assert sent(("remove_secret.api_key", padded)) == {"api_key": None}
        assert da.touches_plugin_secrets(form(("remove_secret.api_key", padded))) is True
    assert sent(("sealed_secret.api_key", "")) is None
    # Whatever is posted as a sealed value goes to the service as it is: it refuses clear text.
    assert sent(("sealed_secret.api_key", "hunter2")) == {"api_key": "hunter2"}
    # A key the plugin does not have goes too: the service refuses it.
    assert sent(("sealed_secret.other", sealed)) == {"other": sealed}


def test_nas_fields_become_the_body_of_the_nas_route():
    smb = form(
        ("nas_id", "docs"),
        ("kind", "smb"),
        ("host", " nas.lan "),
        ("access", "read"),
        ("subpath", ""),
        ("share", "documents"),
        ("username", "indexer"),
        ("domain", ""),
        ("export", "/ignored/for/smb"),
        (da.NAS_SECRET_FIELD, SEALED),
    )
    entry, sealed = da.nas_request(smb)
    assert entry == {
        "kind": "smb",
        "host": "nas.lan",
        "access": "read",
        "share": "documents",
        "username": "indexer",
        "domain": "",
    }
    assert sealed == SEALED
    nfs = form(
        ("kind", "nfs"),
        ("host", "192.168.1.20"),
        ("access", "write"),
        ("export", "/volume1/backup"),
        ("share", "ignored"),
        ("username", "ignored"),
        (da.NAS_SECRET_FIELD, SEALED),  # an NFS entry has no password: not taken
    )
    assert da.nas_request(nfs) == (
        {"kind": "nfs", "host": "192.168.1.20", "access": "write", "export": "/volume1/backup"},
        None,
    )


def test_vectorizer_fields_become_the_body_of_the_vectorizer_route():
    sealed = sealing.seal(SEAL_KEY, "ai.answer.api_key", b"sk-1")
    common = [
        ("sources", "docs"),
        ("sources", "pub"),
        ("extensions", "pdf, md,txt\nhtml"),
        ("exclude", "#recycle\n\nprivate/hr\n"),
        ("max_file_mib", "64"),
        ("embedding_model", "bge-m3"),
        ("answer_model", "gpt-4.1-mini"),
        ("answer_base_url", "https://api.openai.com/v1"),
    ]
    section, key = da.vectorizer_request(
        form(*common, ("answer_provider", "openai_compatible"), (da.ANSWER_SECRET_FIELD, sealed))
    )
    assert key == sealed
    assert section == {
        "sources": ["docs", "pub"],
        "extensions": ["pdf", "md", "txt", "html"],
        "exclude": ["#recycle", "private/hr"],
        "max_file_mib": 64,
        "embedding_model": "bge-m3",
        "ocr": False,
        "answer": {
            "provider": "openai_compatible",
            "model": "gpt-4.1-mini",
            "base_url": "https://api.openai.com/v1",
        },
    }
    local, _ = da.vectorizer_request(form(*common, ("answer_provider", "local"), ("ocr", "true")))
    assert local["answer"] == {"provider": "local", "model": "gpt-4.1-mini"} and local["ocr"] is True
    none, no_key = da.vectorizer_request(form(*common, ("answer_provider", "none")))
    assert none["answer"] == {"provider": "none"} and no_key is None


def test_backup_fields_become_the_body_of_the_backup_route():
    sealed = sealing.seal(SEAL_KEY, "backup.s3.secret_key", b"secret")
    nas = form(
        ("enabled", "true"),
        ("destination_kind", "nas"),
        ("destination_nas_id", "bk"),
        ("destination_subpath", "happymining"),
        ("endpoint", "https://ignored.example"),
        ("keep", "7"),
    )
    assert da.backup_request(nas) == (
        {
            "enabled": True,
            "destination": {"kind": "nas", "nas_id": "bk", "subpath": "happymining"},
            "include_models": False,
            "keep": 7,
        },
        None,
    )
    s3 = form(
        ("destination_kind", "s3"),
        ("endpoint", "https://s3.eu-central-1.amazonaws.com"),
        ("region", "eu-central-1"),
        ("bucket", "acme-hm-backups"),
        ("prefix", ""),
        ("access_key_id", "AKIAEXAMPLEKEY000001"),
        (da.S3_SECRET_FIELD, sealed),
        ("include_models", "true"),
        ("keep", "3"),
    )
    section, key = da.backup_request(s3)
    assert key == sealed and section == {
        "enabled": False,
        "destination": {
            "kind": "s3",
            "endpoint": "https://s3.eu-central-1.amazonaws.com",
            "region": "eu-central-1",
            "bucket": "acme-hm-backups",
            "prefix": "",
            "access_key_id": "AKIAEXAMPLEKEY000001",
        },
        "include_models": True,
        "keep": 3,
    }


def test_schedule_fields_keep_only_what_the_chosen_every_and_job_take():
    hourly = form(
        ("job", "update_check"),
        ("every", "hourly"),
        ("hour", "4"),
        ("weekday", "2"),
        ("minute", "17"),
        ("plugin", "ollama"),
        ("enabled", "true"),
    )
    assert da.schedule_request(hourly) == {
        "job": "update_check",
        "every": "hourly",
        "minute": 17,
        "enabled": True,
    }
    weekly = form(
        ("job", "plugin_restart"),
        ("plugin", "ollama"),
        ("every", "weekly"),
        ("weekday", "6"),
        ("hour", "3"),
        ("minute", "0"),
    )
    assert da.schedule_request(weekly) == {
        "job": "plugin_restart",
        "plugin": "ollama",
        "every": "weekly",
        "weekday": 6,
        "hour": 3,
        "minute": 0,
        "enabled": False,
    }
    # A daily schedule without its hour: the service says what is missing.
    daily = da.schedule_request(
        form(("job", "backup_run"), ("every", "daily"), ("hour", ""), ("minute", "5"))
    )
    assert "hour" not in daily
    document = {"schema": 1, "revision": 1, "mode": "vast", "schedules": [{"id": "x", **daily}]}
    with pytest.raises(appliance_service.DocumentInvalid, match="hour is required for a daily schedule"):
        appliance_service.validate_document(document, CATALOG)


def test_update_fields_and_the_window():
    assert da.update_request(
        form(("channel", "stable"), ("policy", "auto"), ("start_hour", "22"), ("end_hour", "5"))
    ) == {
        "channel": "stable",
        "policy": "auto",
        "window": {"start_hour": 22, "end_hour": 5},
    }
    assert da.update_request(
        form(("channel", "beta"), ("policy", "manual"), ("start_hour", ""), ("end_hour", ""))
    ) == {
        "channel": "beta",
        "policy": "manual",
    }
    with pytest.raises(InvalidRequest, match="give both"):
        da.update_request(form(("channel", "beta"), ("policy", "auto"), ("start_hour", "2")))


def test_a_job_takes_a_plugin_only_for_a_plugin_restart():
    assert da.job_request(form(("job", "vectorize_sync"), ("plugin", "ollama"))).model_dump() == {
        "job": "vectorize_sync",
        "plugin": None,
    }
    assert da.job_request(form(("job", "plugin_restart"), ("plugin", "ollama"))).model_dump() == {
        "job": "plugin_restart",
        "plugin": "ollama",
    }


def test_what_the_api_models_refuse_is_refused_without_echoing_the_value():
    with pytest.raises(InvalidRequest) as refused:
        da.nas_request(
            form(("kind", "smb"), ("host", "h"), ("access", "read"), ("share", "s" * 300), ("username", ""))
        )
    assert "share" in refused.value.message and "s" * 300 not in refused.value.message
    with pytest.raises(InvalidRequest, match="is longer than"):
        da.form_text(form(("host", "x" * (da.MAX_FIELD + 1))), "host")
    with pytest.raises(InvalidRequest, match="must be text, not a file"):
        da.form_text(form(("host", UploadFile(file=None, filename="x"))), "host")  # type: ignore[arg-type]
    with pytest.raises(InvalidRequest, match="must be checked or not"):
        da.form_flag(form(("enabled", "yes")), "enabled")


def test_every_change_needs_the_revision_the_page_showed():
    assert da.form_revision(form(("revision", "12"))) == 12
    for value in ("", "-1", "1.5", "12a", "1" * 11, "١٢"):
        with pytest.raises(InvalidRequest, match="which revision"):
            da.form_revision(form(("revision", value)))


def test_a_document_built_from_the_forms_is_one_the_validator_accepts():
    """The dashboard's request bodies, put together as the service does, pass the machine's rules."""
    sealed = {
        name: sealing.seal(SEAL_KEY, name, b"x")
        for name in ("nas.docs.password", "ai.answer.api_key", "backup.s3.secret_key")
    }
    docs, _ = da.nas_request(
        form(
            ("kind", "smb"),
            ("host", "nas.lan"),
            ("access", "read"),
            ("share", "documents"),
            ("username", "indexer"),
        )
    )
    bk, _ = da.nas_request(
        form(("kind", "nfs"), ("host", "192.168.1.20"), ("access", "write"), ("export", "/volume1/backup"))
    )
    vectorizer, _ = da.vectorizer_request(
        form(
            ("sources", "docs"),
            ("extensions", "pdf"),
            ("max_file_mib", "64"),
            ("embedding_model", "bge-m3"),
            ("answer_provider", "anthropic"),
            ("answer_model", "claude-sonnet-4-5"),
        )
    )
    backup, _ = da.backup_request(
        form(("enabled", "true"), ("destination_kind", "nas"), ("destination_nas_id", "bk"), ("keep", "7"))
    )
    document = copy.deepcopy(
        {
            "schema": 1,
            "revision": 5,
            "mode": "vectorize",
            "plugins": [
                {
                    "id": "ollama",
                    "enabled": True,
                    "settings": da.plugin_request(
                        CATALOG.get("ollama"), form(("setting.models", "bge-m3"))
                    ).settings,
                },
                {"id": "qdrant", "enabled": True, "settings": {}},
                {"id": "vectorizer", "enabled": True, "settings": {}},
            ],
            # What services/appliance.set_nas adds: the defaults of an SMB entry and the secret's name.
            "nas": [{"id": "docs", "subpath": "", **docs, "secret": "nas.docs.password"}, {"id": "bk", **bk}],
            "vectorizer": {**vectorizer, "answer": {**vectorizer["answer"], "secret": "ai.answer.api_key"}},
            "backup": backup,
            "schedules": [
                {
                    "id": "nightly",
                    **da.schedule_request(
                        form(
                            ("job", "vectorize_sync"),
                            ("every", "daily"),
                            ("hour", "2"),
                            ("minute", "30"),
                            ("enabled", "true"),
                        )
                    ),
                }
            ],
            "update": da.update_request(
                form(("channel", "stable"), ("policy", "auto"), ("start_hour", "2"), ("end_hour", "5"))
            ),
            "secrets": {k: v for k, v in sealed.items() if k != "backup.s3.secret_key"},
        }
    )
    appliance_service.validate_document(document, CATALOG)
