"""The appliance page of the dashboard and the releases page (docs/appliance.md, sections 3, 5, 9, 12).

The forms of ``/machines/{id}/appliance`` and ``/admin/releases`` call the same service
functions as the JSON API. Covered here: every page renders for every role that may see it and
for nobody else; each form is shown only to whoever may use it; every POST needs the session's
CSRF token and the caller's permission, and does nothing otherwise; a secret posted in clear text
is refused, a sealed one is stored and never shown; the service's refusals reach the page
(``maintenance_blocked``, ``locally_controlled``, ``no_sealing_key``, ``remote_access_required``,
a concurrent change); the Content-Security-Policy is sent and the pages have no inline script.

What does not need the database (templates, the CSP rules of every template, the form readers,
``seal.js`` itself) is in ``tests/appliance/seal_js/``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from helpers import BASE_URL, World
from sqlalchemy import func, select
from test_appliance import (
    FIXTURE_CATALOG,
    appliance_settings,
    audit_rows,
    beat,
    bound_machine,
    grant,
    report,
    reporting_machine,
    seal,
    set_management,
)
from test_releases import OCTETS, TEST_KEY, build

from happymining.main import create_app
from happymining.models import Machine, MachineAppliance, Operation, Release
from happymining.services import appliance as appliance_service
from happymining.services import catalog as catalog_service

SCRIPT_TAG = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)
INLINE_HANDLER = re.compile(r"<[^>]*\son[a-z]+\s*=", re.IGNORECASE)
POST_FORM = re.compile(r'<form\b[^>]*\smethod="post"[^>]*\saction="([^"]+)"')
PASSWORD_INPUT = re.compile(r'<input\b[^>]*type="password"[^>]*>')


# --- helpers ---------------------------------------------------------------


@pytest.fixture
def dash() -> Iterator[TestClient]:
    """The application with the fixture catalog and the published test release key (DEMO only)."""
    app = create_app(appliance_settings(release_public_keys=[TEST_KEY]))
    with TestClient(app, base_url=BASE_URL) as client:
        yield client


def browser_for(api: TestClient, user) -> TestClient:
    """A browser signed in as ``user`` (session cookie), on the same application."""
    browser = TestClient(api.app, base_url=BASE_URL)
    r = browser.post("/demo-login", data={"email": user.email}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard", r.headers
    return browser


def csrf_of(browser: TestClient) -> str:
    return browser.get("/api/v1/auth/me").json()["csrf_token"]


def page_of(machine) -> str:
    return f"/machines/{machine.id}/appliance"


def revision_of(world: World, machine) -> int:
    world.session.expire_all()
    row = world.session.execute(
        select(MachineAppliance).where(MachineAppliance.machine_id == machine.id)
    ).scalar_one_or_none()
    return row.revision if row is not None else 0


def row_of(world: World, machine) -> MachineAppliance:
    world.session.expire_all()
    return world.session.execute(
        select(MachineAppliance).where(MachineAppliance.machine_id == machine.id)
    ).scalar_one()


def operations(world: World) -> int:
    world.session.expire_all()
    return world.session.execute(select(func.count()).select_from(Operation)).scalar_one()


def changes_audited(world: World) -> list[str]:
    """Appliance changes and refusals in the audit trail (the machine reporting its key is not one)."""
    return [
        row.action
        for row in audit_rows(world)
        if row.action.startswith("appliance.") and row.action != "appliance.seal_key"
    ]


def outcome(response, path: str) -> tuple[str, str]:
    """A form post's answer: a redirect back to ``path`` with ("msg" or "err", the text)."""
    assert response.status_code == 303, (response.status_code, response.text[:500])
    location = urlsplit(response.headers["location"])
    assert location.path == path, response.headers["location"]
    query = parse_qs(location.query)
    assert len(query) == 1 and set(query) <= {"msg", "err"}, query
    ((kind, (text,)),) = query.items()
    return kind, text


def ok(response, path: str) -> str:
    kind, text = outcome(response, path)
    assert kind == "msg", text
    return text


def refused(response, path: str) -> str:
    kind, text = outcome(response, path)
    assert kind == "err", text
    return text


def actions(html: str) -> list[str]:
    return [a for a in POST_FORM.findall(html) if a != "/logout"]


def kinds(html: str, machine) -> set[str]:
    """The kinds of change form on the page: /mode, /plugins/, /nas, ..., /jobs, /install-update."""
    base = page_of(machine)
    out = set()
    for action in actions(html):
        assert action.startswith(base), action
        rest = action[len(base) :]
        out.add("/plugins/" if rest.startswith("/plugins/") else "/" + rest.split("/")[1])
    return out


def no_inline_script(html: str) -> bool:
    return all('src="/static/' in attrs for attrs in SCRIPT_TAG.findall(html)) and not INLINE_HANDLER.search(
        html
    )


EVERY_FORM = {
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
OPERATOR_FORMS = {"/plugins/", "/schedules", "/jobs"}

NAS_FORM = {
    "nas_id": "docs",
    "kind": "smb",
    "host": "nas.lan",
    "share": "documents",
    "subpath": "",
    "username": "indexer",
    "domain": "",
    "access": "read",
    "export": "",
}
NAS_BK_FORM = {
    "nas_id": "bk",
    "kind": "nfs",
    "host": "192.168.1.20",
    "export": "/volume1/backup",
    "access": "write",
}
VECTORIZER_FORM = {
    "sources": "docs",
    "extensions": "pdf, md, txt",
    "exclude": "#recycle",
    "max_file_mib": "64",
    "embedding_model": "bge-m3",
    "answer_provider": "anthropic",
    "answer_model": "claude-sonnet-4-5",
    "answer_base_url": "",
}
BACKUP_S3_FORM = {
    "enabled": "true",
    "destination_kind": "s3",
    "endpoint": "https://s3.eu-central-1.amazonaws.com",
    "region": "eu-central-1",
    "bucket": "acme-hm-backups",
    "prefix": "site1/",
    "access_key_id": "AKIAEXAMPLEKEY000001",
    "keep": "7",
}
SCHEDULE_FORM = {
    "schedule_id": "nightly",
    "job": "vectorize_sync",
    "plugin": "",
    "every": "daily",
    "weekday": "",
    "hour": "2",
    "minute": "30",
    "enabled": "true",
}
UPDATE_FORM = {"channel": "stable", "policy": "auto", "start_hour": "2", "end_hour": "5"}
ASSISTANT_SETTINGS = {"setting.bind": "lan", "setting.workers": "2", "setting.model": "hermes3:8b"}


def every_post(machine) -> list[tuple[str, dict[str, str], str]]:
    """(path, fields without csrf_token and revision, the lowest organisation role that may) per form."""
    base = page_of(machine)
    return [
        (f"{base}/mode", {"mode": "private_ai"}, "org_admin"),
        (f"{base}/plugins/ollama", {"enabled": "true", "setting.models": "bge-m3"}, "org_operator"),
        (f"{base}/plugins/ollama/remove", {}, "org_operator"),
        (f"{base}/nas", NAS_BK_FORM, "org_admin"),
        (f"{base}/nas/bk/remove", {}, "org_admin"),
        (f"{base}/vectorizer", VECTORIZER_FORM, "org_admin"),
        (f"{base}/vectorizer/remove", {}, "org_admin"),
        (
            f"{base}/backup",
            {**BACKUP_S3_FORM, "destination_kind": "nas", "destination_nas_id": "bk"},
            "org_admin",
        ),
        (f"{base}/backup/remove", {}, "org_admin"),
        (f"{base}/schedules", {**SCHEDULE_FORM, "job": "update_check"}, "org_operator"),
        (f"{base}/schedules/nightly/remove", {}, "org_operator"),
        (f"{base}/update", UPDATE_FORM, "org_admin"),
        (f"{base}/jobs", {"job": "update_check"}, "org_operator"),
        (f"{base}/install-update", {"version": "0.9.0"}, "org_admin"),
    ]


ORG_RANK = {"org_viewer": 1, "org_operator": 2, "org_admin": 3}


def post(browser: TestClient, path: str, fields: dict, *, csrf: str, revision: int | None = None, **kw):
    data = {**fields, "csrf_token": csrf}
    if revision is not None:
        data["revision"] = str(revision)
    return browser.post(path, data=data, follow_redirects=False, **kw)


# =============================================================================
# The page, for whoever may view it
# =============================================================================


def test_the_page_renders_for_everyone_who_may_view_it_and_for_nobody_else(dash, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    path = page_of(machine)
    for user in (
        world.user("owner", owner),
        world.user("owner", owner, org_role="org_operator"),
        world.user("owner", owner, org_role="org_viewer"),
        world.user("admin"),
        world.user("auditor"),
    ):
        r = browser_for(dash, user).get(path)
        assert r.status_code == 200, (user.email, r.status_code)
        assert "Appliance of" in r.text and "revision 0" in r.text and "nothing configured yet" in r.text
        policy = r.headers["content-security-policy"]
        assert (
            "script-src 'self'" in policy and "style-src 'self'" in policy and "default-src 'self'" in policy
        )
        assert r.headers["cache-control"] == "no-store"
        assert no_inline_script(r.text), user.email
    # Another organisation's people: the machine does not exist for them.
    stranger = browser_for(dash, world.user("owner", world.owner("Other")))
    assert stranger.get(path).status_code == 404
    # Nobody signed in: to the login page.
    anonymous = TestClient(dash.app, base_url=BASE_URL).get(path, follow_redirects=False)
    assert anonymous.status_code == 303 and anonymous.headers["location"] == "/login"
    # The machine page links to it.
    machine_page = browser_for(dash, world.user("owner", owner, org_role="org_viewer")).get(
        f"/machines/{machine.id}"
    )
    assert f'href="{path}"' in machine_page.text


@pytest.mark.parametrize(
    ("who", "expected"),
    [
        ("org_admin", EVERY_FORM),
        ("org_operator", OPERATOR_FORMS),
        ("org_viewer", set()),
        ("admin", EVERY_FORM),
        ("auditor", set()),
    ],
)
def test_each_form_is_shown_to_those_who_may_use_it(dash, world, who, expected):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    user = world.user("owner", owner, org_role=who) if who.startswith("org_") else world.user(who)
    html = browser_for(dash, user).get(page_of(machine)).text
    assert kinds(html, machine) == expected
    passwords = PASSWORD_INPUT.findall(html)
    if who in ("org_admin", "admin"):
        assert passwords and '<script src="/static/seal.js" defer></script>' in html
    else:
        assert passwords == [] and "<script" not in html


def test_staff_follow_the_management_of_the_machine(dash, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    set_management(world, machine, "customer")
    staff = browser_for(dash, world.user("admin"))
    path = page_of(machine)

    # No grant: the page is refused, with the reason.
    r = staff.get(path)
    assert r.status_code == 403 and "grant remote access first" in r.text
    machine_page = staff.get(f"/machines/{machine.id}").text
    assert f'href="{path}"' not in machine_page and "no access" in machine_page
    # View: the page, without a single form.
    grant(world, machine, "view", hours=1)
    r = staff.get(path)
    assert r.status_code == 200 and actions(r.text) == [] and "HappyMining's access: view" in r.text
    # Manage: every form.
    grant(world, machine, "manage", hours=1)
    assert kinds(staff.get(path).text, machine) == EVERY_FORM
    # The owner's administrator sees the link to the remote-access card.
    boss = browser_for(dash, world.user("owner", owner)).get(path).text
    assert f'href="/machines/{machine.id}#remote-access"' in boss


# =============================================================================
# CSRF and permissions
# =============================================================================


def test_every_form_needs_the_csrf_token_of_the_session(dash, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    boss = browser_for(dash, world.user("owner", owner))
    csrf = csrf_of(boss)
    for path, fields, _ in every_post(machine):
        for token in ("", "not-the-token"):
            r = post(boss, path, fields, csrf=token, revision=0)
            assert r.status_code == 403 and "CSRF token" in r.text, path
        foreign = post(
            boss, path, fields, csrf=csrf, revision=0, headers={"Origin": "https://attacker.example"}
        )
        assert foreign.status_code == 403 and "cross-origin" in foreign.text, path
    assert revision_of(world, machine) == 0 and changes_audited(world) == [] and operations(world) == 0


def test_every_form_needs_the_permission_the_api_route_needs(dash, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    for org_role in ("org_operator", "org_viewer"):
        browser = browser_for(dash, world.user("owner", owner, org_role=org_role))
        csrf = csrf_of(browser)
        for path, fields, minimum in every_post(machine):
            r = post(browser, path, fields, csrf=csrf, revision=revision_of(world, machine))
            if ORG_RANK[org_role] >= ORG_RANK[minimum]:
                # Past the permission check: the service answers (a change, or why not).
                outcome(r, page_of(machine))
            else:
                assert r.status_code == 403 and f"needs the {minimum} role" in r.text, (org_role, path)
    # What an operator could do was done; nothing an operator may not do was.
    done = changes_audited(world)
    assert (
        "appliance.mode" not in done
        and "appliance.nas.set" not in done
        and "appliance.update.set" not in done
    )
    assert "appliance.plugin.set" in done and "appliance.schedule.set" in done
    before = revision_of(world, machine)

    for user in (world.user("auditor"), world.user("owner", world.owner("Other"))):
        browser = browser_for(dash, user)
        csrf = csrf_of(browser)
        for path, fields, _ in every_post(machine):
            r = post(browser, path, fields, csrf=csrf, revision=before)
            assert r.status_code == (404 if user.role == "owner" else 403), (user.email, path)
    assert revision_of(world, machine) == before


def test_plugin_secrets_are_for_administrators_even_on_an_operators_form(dash, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    path = f"{page_of(machine)}/plugins/assistant"
    operator = browser_for(dash, world.user("owner", owner, org_role="org_operator"))
    sealed = {"sealed_secret.api_key": seal("plugin.assistant.api_key")}
    for extra in (sealed, {"remove_secret.api_key": "true"}):
        r = post(
            operator,
            path,
            {"enabled": "false", **ASSISTANT_SETTINGS, **extra},
            csrf=csrf_of(operator),
            revision=0,
        )
        assert r.status_code == 403 and "org_admin" in r.text
    assert revision_of(world, machine) == 0
    # Without a secret the operator configures the plugin.
    ok(
        post(operator, path, {"enabled": "false", **ASSISTANT_SETTINGS}, csrf=csrf_of(operator), revision=0),
        page_of(machine),
    )
    assert row_of(world, machine).document["plugins"] == [
        {
            "id": "assistant",
            "enabled": False,
            "settings": {"bind": "lan", "workers": 2, "telemetry": False, "model": "hermes3:8b"},
        }
    ]
    boss = browser_for(dash, world.user("owner", owner))
    ok(
        post(
            boss, path, {"enabled": "false", **ASSISTANT_SETTINGS, **sealed}, csrf=csrf_of(boss), revision=1
        ),
        page_of(machine),
    )
    assert row_of(world, machine).secrets == {"plugin.assistant.api_key": sealed["sealed_secret.api_key"]}


def test_staff_without_a_manage_grant_change_nothing(dash, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    set_management(world, machine, "customer")
    staff = browser_for(dash, world.user("admin"))
    csrf = csrf_of(staff)
    for level in (None, "view"):
        if level:
            grant(world, machine, level, hours=1)
        for path, fields, _ in every_post(machine):
            r = post(staff, path, fields, csrf=csrf, revision=0)
            assert r.status_code == 403 and "remote-access grant with the manage level" in r.text, (
                level,
                path,
            )
    assert revision_of(world, machine) == 0 and changes_audited(world) == [] and operations(world) == 0
    # With one, staff change the machine like the owner's administrator, and it is recorded so.
    grant(world, machine, "manage", hours=1)
    ok(
        post(staff, f"{page_of(machine)}/mode", {"mode": "private_ai"}, csrf=csrf, revision=0),
        page_of(machine),
    )
    (row,) = audit_rows(world, "appliance.mode")
    assert row.details["remote_access_grants"]


# =============================================================================
# Secrets
# =============================================================================


def test_a_secret_in_clear_text_is_refused_and_a_sealed_one_is_stored_and_never_shown(dash, world, capsys):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    boss = browser_for(dash, world.user("owner", owner))
    csrf = csrf_of(boss)
    path = page_of(machine)
    clear = "correct horse battery staple"

    # Clear text where a sealed value is expected: refused, nothing stored, never repeated.
    for fields in (
        {**NAS_FORM, "sealed_secret": clear},
        {"enabled": "false", **ASSISTANT_SETTINGS, "sealed_secret.api_key": clear},
    ):
        target = f"{path}/nas" if "nas_id" in fields else f"{path}/plugins/assistant"
        r = post(boss, target, fields, csrf=csrf, revision=0)
        message = refused(r, path)
        assert "not sealed for the machine" in message and clear not in r.headers["location"]
        assert clear not in boss.get(r.headers["location"]).text
    assert revision_of(world, machine) == 0 and row_of(world, machine).secrets == {}

    # Sealed, under the names the page renders: stored as they are, and only their names are shown.
    values = {
        "nas.docs.password": seal("nas.docs.password"),
        "ai.answer.api_key": seal("ai.answer.api_key"),
        "backup.s3.secret_key": seal("backup.s3.secret_key"),
    }
    ok(
        post(
            boss,
            f"{path}/nas",
            {**NAS_FORM, "sealed_secret": values["nas.docs.password"]},
            csrf=csrf,
            revision=0,
        ),
        path,
    )
    ok(
        post(
            boss,
            f"{path}/vectorizer",
            {**VECTORIZER_FORM, "answer_sealed_secret": values["ai.answer.api_key"]},
            csrf=csrf,
            revision=1,
        ),
        path,
    )
    ok(
        post(
            boss,
            f"{path}/backup",
            {**BACKUP_S3_FORM, "s3_sealed_secret": values["backup.s3.secret_key"]},
            csrf=csrf,
            revision=2,
        ),
        path,
    )
    row = row_of(world, machine)
    assert row.secrets == values and row.revision == 3
    assert row.document["nas"][0]["secret"] == "nas.docs.password"
    assert row.document["vectorizer"]["answer"] == {
        "provider": "anthropic",
        "model": "claude-sonnet-4-5",
        "secret": "ai.answer.api_key",
    }
    assert row.document["backup"]["destination"]["secret"] == "backup.s3.secret_key"

    html = boss.get(path).text
    for name, value in values.items():
        assert value not in html and value[8:40] not in html
        assert f'data-seal-name="{name}"' in html  # the field that would replace it seals under that name
    assert "hmseal1." not in html and "stored; leave empty to keep it" in html
    for audit_row in audit_rows(world):
        assert "hmseal1." not in json.dumps(audit_row.details), audit_row.action
    out = capsys.readouterr()
    assert "hmseal1." not in out.out + out.err and clear not in out.out + out.err

    # Leaving a secret field empty keeps the stored value.
    ok(post(boss, f"{path}/nas", {**NAS_FORM, "host": "nas2.lan"}, csrf=csrf, revision=3), path)
    assert row_of(world, machine).secrets == values


def test_password_fields_have_no_name_and_seal_for_the_machines_key(dash, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    html = browser_for(dash, world.user("owner", owner)).get(page_of(machine)).text
    fields = PASSWORD_INPUT.findall(html)
    assert fields
    for field in fields:
        assert not re.search(r'\sname="', field), field
        assert 'data-seal-target="' in field and " disabled" not in field
    key = row_of(world, machine).seal_public_key
    assert key and f'data-seal-key="{key}"' in html


def test_without_a_sealing_key_secret_fields_are_disabled_and_a_secret_is_refused(dash, world):
    owner = world.owner()
    machine, _ = world.paired_machine(owner)  # its agent never reported the appliance object
    boss = browser_for(dash, world.user("owner", owner))
    path = page_of(machine)
    html = boss.get(path).text
    fields = PASSWORD_INPUT.findall(html)
    assert fields and all(" disabled" in field for field in fields)
    assert "Secret fields are disabled" in html
    r = post(
        boss,
        f"{path}/nas",
        {**NAS_FORM, "sealed_secret": seal("nas.docs.password")},
        csrf=csrf_of(boss),
        revision=0,
    )
    assert "has not reported its sealing key" in refused(r, path)
    assert revision_of(world, machine) == 0


# =============================================================================
# The service's answers reach the page
# =============================================================================


def test_an_administrator_configures_everything_through_the_forms(dash, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    boss = browser_for(dash, world.user("owner", owner))
    csrf = csrf_of(boss)
    path = page_of(machine)
    steps = [
        (f"{path}/nas", {**NAS_FORM, "sealed_secret": seal("nas.docs.password")}),
        (f"{path}/plugins/ollama", {"enabled": "true", "setting.models": "hermes3:8b\nbge-m3"}),
        (f"{path}/plugins/qdrant", {"enabled": "true"}),
        (f"{path}/vectorizer", {**VECTORIZER_FORM, "answer_sealed_secret": seal("ai.answer.api_key")}),
        (f"{path}/plugins/vectorizer", {"enabled": "true"}),
        (
            f"{path}/plugins/assistant",
            {
                "enabled": "true",
                **ASSISTANT_SETTINGS,
                "sealed_secret.api_key": seal("plugin.assistant.api_key"),
            },
        ),
        (f"{path}/nas", NAS_BK_FORM),
        (f"{path}/backup", {**BACKUP_S3_FORM, "s3_sealed_secret": seal("backup.s3.secret_key")}),
        (f"{path}/schedules", SCHEDULE_FORM),
        (
            f"{path}/schedules",
            {
                **SCHEDULE_FORM,
                "schedule_id": "restart-llm",
                "job": "plugin_restart",
                "plugin": "ollama",
                "every": "hourly",
                "minute": "5",
                "enabled": "",
            },
        ),
        (f"{path}/update", UPDATE_FORM),
        (f"{path}/mode", {"mode": "private_ai"}),
    ]
    for number, (target, fields) in enumerate(steps, start=1):
        message = ok(post(boss, target, fields, csrf=csrf, revision=number - 1), path)
        assert f"Saved as revision {number}" in message, (target, message)
    row = row_of(world, machine)
    assert row.document["mode"] == "private_ai" and row.revision == len(steps)
    assert row.document["plugins"][0] == {
        "id": "ollama",
        "enabled": True,
        "settings": {"models": ["hermes3:8b", "bge-m3"]},
    }
    assert row.document["schedules"][1] == {
        "id": "restart-llm",
        "job": "plugin_restart",
        "plugin": "ollama",
        "every": "hourly",
        "minute": 5,
        "enabled": False,
    }
    assert row.document["update"] == {
        "channel": "stable",
        "policy": "auto",
        "window": {"start_hour": 2, "end_hour": 5},
    }
    # What the forms made is a document the machine's validator accepts.
    appliance_service.validate_document(
        {**row.document, "revision": row.revision, "secrets": row.secrets},
        catalog_service.load_catalog(FIXTURE_CATALOG),
    )
    assert sorted(row.secrets) == [
        "ai.answer.api_key",
        "backup.s3.secret_key",
        "nas.docs.password",
        "plugin.assistant.api_key",
    ]

    # The same again changes nothing and says so.
    assert "Nothing changed" in ok(
        post(boss, f"{path}/mode", {"mode": "private_ai"}, csrf=csrf, revision=len(steps)), path
    )
    # What is still in use cannot be removed; the service says why.
    assert "requires this plugin" in refused(
        post(boss, f"{path}/plugins/qdrant/remove", {}, csrf=csrf, revision=len(steps)), path
    )
    # ollama: two enabled plugins need it (checked before the schedule that restarts it).
    message = refused(post(boss, f"{path}/plugins/ollama/remove", {}, csrf=csrf, revision=len(steps)), path)
    assert "assistant, vectorizer is enabled and requires this plugin" in message
    # Taking it apart again, in order.
    for target in ("/schedules/restart-llm/remove", "/backup/remove", "/nas/bk/remove"):
        ok(post(boss, path + target, {}, csrf=csrf, revision=revision_of(world, machine)), path)
    row = row_of(world, machine)
    assert "backup" not in row.document and "backup.s3.secret_key" not in row.secrets
    html = boss.get(path).text
    assert "restart-llm" not in html and "nightly" in html and "every day at 02:30" in html


def test_a_change_based_on_an_old_revision_is_refused(dash, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    first, second = (browser_for(dash, world.user("owner", owner)) for _ in range(2))
    path = page_of(machine)
    ok(post(first, f"{path}/schedules", SCHEDULE_FORM, csrf=csrf_of(first), revision=0), path)
    # The second page was loaded at revision 0, before the first change.
    message = refused(
        post(second, f"{path}/mode", {"mode": "vectorize"}, csrf=csrf_of(second), revision=0), path
    )
    assert "changed in the meantime" in message and "revision 1" in message
    # A form without its revision is refused as well.
    assert "which revision" in refused(
        post(second, f"{path}/mode", {"mode": "vectorize"}, csrf=csrf_of(second)), path
    )
    assert revision_of(world, machine) == 1 and row_of(world, machine).document["mode"] == "vast"


def test_a_blocked_mode_change_shows_the_gates_reasons_and_is_recorded(dash, world):
    machine, _, _ = bound_machine(world, dash)  # idle and unlisted; disruptive actions are off by default
    owner = world.session.get(Machine, machine.id).owner
    boss = browser_for(dash, world.user("owner", owner))
    path = page_of(machine)
    html = boss.get(path).text
    assert "bound to a provider machine on Vast" in html and "rental-protection" in html
    message = refused(
        post(boss, f"{path}/mode", {"mode": "private_ai"}, csrf=csrf_of(boss), revision=0), path
    )
    assert message.startswith("Blocked; requires operator handling: ")
    assert "HM_DISRUPTIVE_OPERATIONS_ENABLED=false" in message
    assert changes_audited(world) == ["appliance.mode_blocked"] and revision_of(world, machine) == 0
    # Going to vast, and everything that is not the mode, is not held up.
    ok(post(boss, f"{path}/schedules", SCHEDULE_FORM, csrf=csrf_of(boss), revision=0), path)


def test_a_locally_controlled_machine_is_read_only_here(dash, world):
    owner = world.owner()
    machine, token = reporting_machine(world, dash, owner)
    assert beat(dash, token, report(control="local")).status_code == 200
    boss = browser_for(dash, world.user("owner", owner))
    csrf = csrf_of(boss)
    path = page_of(machine)
    html = boss.get(path).text
    assert "control: local" in html and "cannot be changed from this page" in html
    assert kinds(html, machine) == {"/jobs", "/install-update"} and PASSWORD_INPUT.findall(html) == []
    # Posting a change anyway: the service's refusal.
    message = refused(post(boss, f"{path}/schedules", SCHEDULE_FORM, csrf=csrf, revision=0), path)
    assert "control: local" in message and "on the machine" in message
    # A job is an operation, not a change to the document.
    ok(post(boss, f"{path}/jobs", {"job": "update_check"}, csrf=csrf), path)
    assert operations(world) == 1


def test_a_job_reaches_the_machine_as_a_typed_operation(dash, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    operator = browser_for(dash, world.user("owner", owner, org_role="org_operator"))
    csrf = csrf_of(operator)
    path = page_of(machine)
    assert "queued" in ok(
        post(operator, f"{path}/jobs", {"job": "vectorize_sync", "plugin": "ollama"}, csrf=csrf), path
    )
    # plugin_restart needs a configured plugin: the service says so.
    assert "not configured" in refused(
        post(operator, f"{path}/jobs", {"job": "plugin_restart", "plugin": "ollama"}, csrf=csrf), path
    )
    assert "params must be" in refused(post(operator, f"{path}/jobs", {"job": "rm -rf"}, csrf=csrf), path)
    world.session.expire_all()
    (operation,) = world.session.execute(select(Operation)).scalars()
    assert operation.type == "appliance_run_job" and operation.params == {"job": "vectorize_sync"}


def test_installing_an_update_goes_through_the_release_service(dash, world):
    owner = world.owner()
    machine, _ = reporting_machine(world, dash, owner)
    boss = browser_for(dash, world.user("owner", owner))
    path = page_of(machine)
    assert (
        refused(post(boss, f"{path}/install-update", {"version": "9.9.9"}, csrf=csrf_of(boss)), path)
        == "no such release"
    )
    assert operations(world) == 0


# =============================================================================
# Releases (staff)
# =============================================================================


def test_the_releases_page_is_for_staff(dash, world):
    owner = world.owner()
    assert browser_for(dash, world.user("admin")).get("/admin/releases").status_code == 200
    auditor = browser_for(dash, world.user("auditor")).get("/admin/releases")
    assert auditor.status_code == 200 and actions(auditor.text) == []
    for org_role in ("org_admin", "org_operator", "org_viewer"):
        assert (
            browser_for(dash, world.user("owner", owner, org_role=org_role))
            .get("/admin/releases")
            .status_code
            == 403
        )
    page = browser_for(dash, world.user("admin")).get("/admin/releases")
    assert no_inline_script(page.text) and "<script" not in page.text
    assert "/api/v1/releases/X.Y.Z/artifact" in page.text and "limited to 1 MiB" in page.text


def test_a_release_is_published_withdrawn_and_put_on_channels_from_the_page(dash, world):
    admin = world.user("admin")
    browser = browser_for(dash, admin)
    csrf = csrf_of(browser)
    release = build("0.3.0")
    signature = release["body"]["signature_b64"]
    files = {
        "manifest": ("manifest.json", release["raw"], "application/json"),
        "signature_file": ("manifest.sig", (signature + "\n").encode(), "text/plain"),
    }

    # Without the CSRF token, or by an auditor: nothing.
    assert browser.post("/admin/releases", data={}, files=files, follow_redirects=False).status_code == 403
    auditor = browser_for(dash, world.user("auditor"))
    r = auditor.post(
        "/admin/releases", data={"csrf_token": csrf_of(auditor)}, files=files, follow_redirects=False
    )
    assert r.status_code == 403
    # A signature that does not verify: refused by the service.
    bad = {"manifest": files["manifest"], "signature_file": ("manifest.sig", b"A" * 88, "text/plain")}
    assert "does not verify" in refused(
        browser.post("/admin/releases", data={"csrf_token": csrf}, files=bad, follow_redirects=False),
        "/admin/releases",
    )
    world.session.expire_all()
    assert world.session.execute(select(func.count()).select_from(Release)).scalar_one() == 0

    # The signed manifest: accepted, waiting for its package.
    r = browser.post("/admin/releases", data={"csrf_token": csrf}, files=files, follow_redirects=False)
    assert "0.3.0 accepted" in ok(r, "/admin/releases")
    world.session.expire_all()
    assert world.session.execute(select(Release.status)).scalar_one() == "awaiting_artifact"
    assert "waiting for its package" in browser.get("/admin/releases").text
    # A pasted signature works the same (here: a version published once is refused).
    pasted = browser.post(
        "/admin/releases",
        data={"csrf_token": csrf, "signature": signature},
        files={"manifest": files["manifest"]},
        follow_redirects=False,
    )
    assert "already exists" in refused(pasted, "/admin/releases")

    # The package goes through the JSON API, then the channels and the withdrawal through the page.
    headers = {**world.auth(admin), **OCTETS}
    assert (
        dash.put("/api/v1/releases/0.3.0/artifact", headers=headers, content=release["artifact"]).status_code
        == 200
    )
    r = browser.post(
        "/admin/releases/0.3.0/channels",
        data={"csrf_token": csrf, "channels": ["beta", "stable"]},
        follow_redirects=False,
    )
    assert "offered on: beta, stable" in ok(r, "/admin/releases")
    for token in ("", "nope"):
        r = browser.post(
            "/admin/releases/0.3.0/withdraw",
            data={"csrf_token": token, "reason": "x"},
            follow_redirects=False,
        )
        assert r.status_code == 403
    empty = browser.post(
        "/admin/releases/0.3.0/withdraw", data={"csrf_token": csrf, "reason": ""}, follow_redirects=False
    )
    assert refused(empty, "/admin/releases").startswith("reason: ")
    r = browser.post(
        "/admin/releases/0.3.0/withdraw",
        data={"csrf_token": csrf, "reason": "bad build"},
        follow_redirects=False,
    )
    assert "withdrawn" in ok(r, "/admin/releases")
    world.session.expire_all()
    stored_release = world.session.execute(select(Release)).scalar_one()
    assert stored_release.status == "withdrawn" and stored_release.channels == ["beta", "stable"]
    assert [row.action for row in audit_rows(world) if row.action.startswith("release.")] == [
        "release.create",
        "release.artifact",
        "release.channels",
        "release.withdraw",
    ]
    assert stored_release.created_by == admin.id
