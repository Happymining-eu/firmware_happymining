"""Dashboard pages for the appliance of a machine, and for firmware releases (docs/appliance.md).

- ``/machines/{id}/appliance``: the mode, plugins, NAS entries, vectorization, backup,
  schedules and update policy the cloud holds for the machine, what the machine reports
  about itself, and the forms to change them. Each form is shown only to those who may use it
  (section 3); the page itself to everyone who may view the appliance.
- ``/admin/releases``: staff list releases, publish a signed manifest, put a release on
  channels and withdraw it (section 9). The package itself goes through the JSON API.

Same conventions as ``dashboard.py`` and ``dashboard_org.py``, whose router and helpers are
used here: server-rendered, every form carries the session's CSRF token, which is checked
before anything else; a POST answers with a redirect. Each handler calls the same functions
as the JSON API: ``services/access.py`` decides who may see or change the machine,
``services/appliance.py`` and ``services/releases.py`` make the change and enforce every rule
of the document. Nothing here decides a permission or a rule of its own; the form fields are
only put in the shape of the API's request bodies (``schemas_appliance``) before the service
is called. Every change carries the revision the page was rendered from, as the API's
``If-Match`` does, so a change made in the meantime is reported instead of overwritten.

A permission refusal (403, ``remote_access_required`` included) or a machine that does not
exist for the caller (404) is an error page with its status code. Anything else the service
objects to (an invalid value, ``maintenance_blocked``, ``locally_controlled``,
``no_sealing_key``, a concurrent change) goes back to the page as a message.

**Secrets.** A password field on the page has no ``name``: without JavaScript nothing secret
is ever submitted. ``dashboard/static/seal.js`` seals what is typed, in the browser, with the
machine's public key and under the exact name the service stores the secret as, puts the
sealed value into a hidden field (``*_FIELD`` below) and clears the password field. The
service takes a secret only sealed (``sealing.check_sealed``) and never echoes it.
"""

from __future__ import annotations

import base64
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session
from starlette.datastructures import FormData, UploadFile

from .config import Settings
from .dashboard import back, check_csrf, need, page_principal, render, router
from .db import get_db
from .deps import client_ip, load_machine, settings_dep
from .errors import AppError, Forbidden, InvalidRequest, NotFound
from .models import RELEASE_CHANNELS, Machine
from .providers.registry import get_provider
from .routers import views
from .schemas_appliance import (
    BackupIn,
    ChannelsIn,
    InstallUpdateIn,
    JobIn,
    ModeIn,
    NasIn,
    PluginIn,
    ReleaseIn,
    ScheduleIn,
    UpdateIn,
    VectorizerIn,
    WithdrawIn,
)
from .sealing import MAX_MANIFEST_BYTES
from .services import access
from .services import appliance as appliance_service
from .services import releases as release_service
from .services.accounts import Principal
from .services.catalog import ID_RE, get_catalog
from .services.maintenance import describe_blocked

# --- the names of the form fields that carry sealed secrets -----------------
#
# The password field itself has no name. seal.js puts the sealed value into the hidden input
# named here; the secret name it seals under is rendered next to it (data-seal-name) and is
# the name the service stores the secret as. (Names of fields, not secrets: hence the noqa.)

NAS_SECRET_FIELD = "sealed_secret"  # noqa: S105  -> nas.<nas id>.password
ANSWER_SECRET_FIELD = "answer_sealed_secret"  # noqa: S105  -> ai.answer.api_key
S3_SECRET_FIELD = "s3_sealed_secret"  # noqa: S105  -> backup.s3.secret_key
PLUGIN_SECRET_PREFIX = "sealed_secret."  # noqa: S105  sealed_secret.<key> -> plugin.<plugin id>.<key>
PLUGIN_SECRET_REMOVE_PREFIX = "remove_secret."  # noqa: S105  remove_secret.<key>=true removes a stored one
PLUGIN_SETTING_PREFIX = "setting."  # setting.<key>: one field per catalog setting

# Bounds of what a form field may carry before the service sees it. The API's request
# models (schemas_appliance) apply their own, tighter ones afterwards.
MAX_FIELD = 2000
MAX_SEALED_FIELD = 6000
MAX_LIST_FIELD = 20000
MAX_SIGNATURE_FILE = 1024
MAX_VERSION_LEN = 24

_INT_RE = re.compile(r"-?[0-9]{1,10}")

MODE_HELP = {
    "vast": "Reserved for Vast hosting. No plugin runs, and Vast's own software is not touched. "
    "This is the default.",
    "private_ai": "The owner uses the machine: every enabled plugin runs.",
    "vectorize": "The machine only indexes the NAS: only the plugins made for it run (the vector "
    "database, the embedding runtime, the vectorizer). Answers come from a cloud AI with your own "
    "key, or from search alone.",
}
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
JOB_HELP = {
    "vectorize_sync": "index the NAS sources now",
    "backup_run": "make a backup now",
    "update_check": "look for a firmware update now",
    "plugin_restart": "restart one plugin",
}
# Prefilled in the vectorization form before anything is configured (the contract's example).
VECTORIZER_START = {
    "sources": [],
    "extensions": ["pdf", "docx", "pptx", "xlsx", "html", "md", "txt"],
    "exclude": [],
    "max_file_mib": 64,
    "embedding_model": "bge-m3",
    "ocr": False,
    "answer": {"provider": "none"},
}
BACKUP_START = {
    "enabled": True,
    "destination": {"kind": "nas", "nas_id": "", "subpath": "happymining"},
    "include_models": False,
    "keep": 7,
}


def page_path(machine_id: uuid.UUID | str) -> str:
    return f"/machines/{machine_id}/appliance"


# =============================================================================
# Reading form fields
# =============================================================================


async def form_data(request: Request) -> FormData:
    """The submitted form, for handlers whose field names depend on the catalog."""
    return await request.form()


def form_text(form: FormData, name: str, *, max_len: int = MAX_FIELD, strip: bool = True) -> str:
    """One text field; absent is empty. Never echoes the value in an error."""
    value = form.get(name)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise InvalidRequest(f"{name}: must be text, not a file")
    if len(value) > max_len:
        raise InvalidRequest(f"{name}: is longer than {max_len} characters")
    return value.strip() if strip else value


def form_flag(form: FormData, name: str) -> bool:
    """A checkbox: checked sends ``true``; unchecked sends nothing."""
    value = form_text(form, name)
    if value not in ("", "true"):
        raise InvalidRequest(f"{name}: must be checked or not")
    return value == "true"


def form_int(form: FormData, name: str, *, optional: bool = False) -> int | None:
    value = form_text(form, name)
    if value == "" and optional:
        return None
    if not _INT_RE.fullmatch(value):
        raise InvalidRequest(f"{name}: must be a whole number")
    return int(value)


def form_lines(form: FormData, name: str) -> list[str]:
    """A textarea of one value per line; blank lines are ignored."""
    text = form_text(form, name, max_len=MAX_LIST_FIELD, strip=False)
    return [line.strip() for line in text.splitlines() if line.strip()]


def form_words(form: FormData, name: str) -> list[str]:
    """Values separated by commas, spaces or line breaks."""
    text = form_text(form, name, max_len=MAX_LIST_FIELD, strip=False)
    return [word for word in re.split(r"[\s,]+", text) if word]


def form_values(form: FormData, name: str) -> list[str]:
    """Every value of a repeated field (checkboxes with the same name)."""
    out = []
    for value in form.getlist(name):
        if not isinstance(value, str) or len(value) > MAX_FIELD:
            raise InvalidRequest(f"{name}: must be text")
        out.append(value.strip())
    return out


def form_revision(form: FormData) -> int:
    """The revision the page was rendered from: the change is refused if it moved on since."""
    value = form_text(form, "revision")
    if not (value.isascii() and value.isdigit()) or len(value) > 10:
        raise InvalidRequest("the form does not say which revision it was based on; load the page again")
    return int(value)


def shaped(model: type[BaseModel], data: dict[str, Any]) -> Any:
    """Check ``data`` against the JSON API's request model for the same change."""
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        # Field paths and reasons only. Submitted values are never echoed back.
        problems = [
            ".".join(str(part) for part in error.get("loc", ())) + ": " + str(error.get("msg", "invalid"))
            for error in exc.errors()[:3]
        ]
        raise InvalidRequest("; ".join(problems) or "invalid form") from None


def given(body: BaseModel, *, without: tuple[str, ...] = ()) -> dict[str, Any]:
    """The fields that were filled in, as they go into the document (the API's ``_given``)."""
    return body.model_dump(exclude_none=True, exclude=set(without))


def _entry_id(value: str, what: str) -> str:
    if not ID_RE.fullmatch(value):
        raise InvalidRequest(
            f"{what}: must be a lower-case letter followed by up to 30 lower-case letters, digits or -"
        )
    return value


# =============================================================================
# From a form to the arguments of a service function
# =============================================================================


def touches_plugin_secrets(form: FormData) -> bool:
    """Whether a plugin form sets or removes a secret: that is an administrator's change.

    Decided by the very function that reads the change (``plugin_sealed``), so
    that what the permission check sees is exactly what is done. A separate
    reading once let `` true`` (with a space) remove a secret at the
    operator's level: the check compared the raw value, the removal stripped it.
    """
    return plugin_sealed(form) is not None


def plugin_values(spec: Any, form: FormData) -> dict[str, Any]:
    """The settings of a plugin, typed after its catalog entry. Every setting is sent."""
    values: dict[str, Any] = {}
    for key, setting in spec.settings.items():
        field = PLUGIN_SETTING_PREFIX + key
        if setting.type == "bool":
            values[key] = form_flag(form, field)
        elif setting.type == "int":
            values[key] = form_int(form, field)
        elif setting.type == "string_list":
            values[key] = form_lines(form, field)
        else:  # enum and string: as typed
            values[key] = form_text(form, field, strip=False)
    # A field for a setting the catalog does not have goes to the service as it is,
    # which refuses it ("has a setting this plugin does not take").
    for name in form:
        key = name[len(PLUGIN_SETTING_PREFIX) :]
        if name.startswith(PLUGIN_SETTING_PREFIX) and key not in spec.settings:
            values[key] = form_text(form, name, strip=False)
    return values


def plugin_sealed(form: FormData) -> dict[str, str | None] | None:
    """Catalog secret key -> sealed value, or None to remove a stored one. None: keep all."""
    sealed: dict[str, str | None] = {}
    for name in form:
        if name.startswith(PLUGIN_SECRET_REMOVE_PREFIX) and form_flag(form, name):
            sealed[name[len(PLUGIN_SECRET_REMOVE_PREFIX) :]] = None
    for name in form:
        if name.startswith(PLUGIN_SECRET_PREFIX):
            value = form_text(form, name, max_len=MAX_SEALED_FIELD)
            if value:
                sealed[name[len(PLUGIN_SECRET_PREFIX) :]] = value
    return sealed or None


def plugin_request(spec: Any, form: FormData) -> PluginIn:
    return shaped(
        PluginIn,
        {
            "enabled": form_flag(form, "enabled"),
            "settings": plugin_values(spec, form),
            "sealed_secrets": plugin_sealed(form),
        },
    )


def nas_request(form: FormData) -> tuple[dict[str, Any], str | None]:
    """(entry without id, sealed password or None) of a NAS entry (section 4.3)."""
    kind = form_text(form, "kind")
    data: dict[str, Any] = {
        "kind": kind,
        "host": form_text(form, "host"),
        "access": form_text(form, "access"),
        "subpath": form_text(form, "subpath") or None,
    }
    if kind == "smb":
        data.update(
            share=form_text(form, "share"),
            username=form_text(form, "username"),
            domain=form_text(form, "domain"),
            sealed_secret=form_text(form, NAS_SECRET_FIELD, max_len=MAX_SEALED_FIELD) or None,
        )
    elif kind == "nfs":
        data["export"] = form_text(form, "export")
    body = shaped(NasIn, data)
    return given(body, without=("sealed_secret",)), body.sealed_secret


def vectorizer_request(form: FormData) -> tuple[dict[str, Any], str | None]:
    """(section, sealed API key or None) of the vectorization (section 4.4)."""
    provider = form_text(form, "answer_provider")
    answer: dict[str, Any] = {"provider": provider}
    if provider != "none":
        answer["model"] = form_text(form, "answer_model") or None
    if provider in appliance_service.CLOUD_ANSWER_PROVIDERS:
        answer["base_url"] = form_text(form, "answer_base_url") or None
    answer["sealed_secret"] = form_text(form, ANSWER_SECRET_FIELD, max_len=MAX_SEALED_FIELD) or None
    body = shaped(
        VectorizerIn,
        {
            "sources": form_values(form, "sources"),
            "extensions": form_words(form, "extensions"),
            "exclude": form_lines(form, "exclude"),
            "max_file_mib": form_int(form, "max_file_mib"),
            "embedding_model": form_text(form, "embedding_model"),
            "ocr": form_flag(form, "ocr"),
            "answer": {key: value for key, value in answer.items() if value is not None},
        },
    )
    section = given(body)
    section["answer"].pop("sealed_secret", None)
    return section, body.answer.sealed_secret


def backup_request(form: FormData) -> tuple[dict[str, Any], str | None]:
    """(section, sealed S3 secret key or None) of the backup (section 4.5)."""
    kind = form_text(form, "destination_kind")
    destination: dict[str, Any] = {"kind": kind}
    if kind == "nas":
        destination["nas_id"] = form_text(form, "destination_nas_id")
        destination["subpath"] = form_text(form, "destination_subpath") or None
    elif kind == "s3":
        destination.update(
            endpoint=form_text(form, "endpoint"),
            region=form_text(form, "region"),
            bucket=form_text(form, "bucket"),
            prefix=form_text(form, "prefix"),
            access_key_id=form_text(form, "access_key_id"),
            sealed_secret=form_text(form, S3_SECRET_FIELD, max_len=MAX_SEALED_FIELD) or None,
        )
    body = shaped(
        BackupIn,
        {
            "enabled": form_flag(form, "enabled"),
            "destination": {key: value for key, value in destination.items() if value is not None},
            "include_models": form_flag(form, "include_models"),
            "keep": form_int(form, "keep"),
        },
    )
    section = given(body)
    section["destination"].pop("sealed_secret", None)
    return section, body.destination.sealed_secret


def schedule_request(form: FormData) -> dict[str, Any]:
    """A schedule entry without its id (section 4.6). The form has every field; what the
    chosen ``every`` and ``job`` do not take is left out."""
    job = form_text(form, "job")
    every = form_text(form, "every")
    data: dict[str, Any] = {
        "job": job,
        "every": every,
        "minute": form_int(form, "minute"),
        "enabled": form_flag(form, "enabled"),
    }
    if every != "hourly":
        data["hour"] = form_int(form, "hour", optional=True)
    if every == "weekly":
        data["weekday"] = form_int(form, "weekday", optional=True)
    if job == "plugin_restart":
        data["plugin"] = form_text(form, "plugin") or None
    return given(shaped(ScheduleIn, {key: value for key, value in data.items() if value is not None}))


def update_request(form: FormData) -> dict[str, Any]:
    """The update policy (section 4.7)."""
    data: dict[str, Any] = {"channel": form_text(form, "channel"), "policy": form_text(form, "policy")}
    start = form_int(form, "start_hour", optional=True)
    end = form_int(form, "end_hour", optional=True)
    if (start is None) != (end is None):
        raise InvalidRequest("update window: give both the first and the last hour, or neither")
    if start is not None:
        data["window"] = {"start_hour": start, "end_hour": end}
    return given(shaped(UpdateIn, data))


def job_request(form: FormData) -> JobIn:
    job = form_text(form, "job")
    plugin = form_text(form, "plugin") if job == "plugin_restart" else ""
    return shaped(JobIn, {"job": job, "plugin": plugin or None})


# =============================================================================
# What the page shows
# =============================================================================


def _field(setting: dict[str, Any], key: str, value: Any) -> dict[str, Any]:
    """One settings field of a plugin form, from the catalog's public description."""
    out = {**setting, "key": key, "name": PLUGIN_SETTING_PREFIX + key, "value": value}
    if setting["type"] == "string_list":
        out["text"] = "\n".join(str(item) for item in value) if isinstance(value, list) else ""
    return out


def _lan_hints(ports: list[dict[str, Any]], hostname: str) -> list[dict[str, Any]]:
    """Where a plugin is reached on the owner's network. A hint: the address is the machine's."""
    host = hostname or "<machine address>"
    out = []
    for port in ports:
        protocol = port.get("protocol", "")
        if protocol in ("http", "https"):
            where = f"{protocol}://{host}:{port['port']}/"
        else:
            where = f"{host}:{port['port']} ({protocol})"
        out.append({**port, "where": where})
    return out


def appliance_context(
    view: dict[str, Any],
    *,
    hostname: str = "",
    staff_access: str = "none",
    provider_bound: bool = False,
    may_see_remote_access: bool = False,
) -> dict[str, Any]:
    """Everything the appliance page shows, from ``services/appliance.view`` and a few facts.

    Pure: no database. What may be changed comes from the service's ``can_operate`` and
    ``can_admin`` (``services/access.py``); nothing here decides a permission.
    """
    document = view["document"]
    reported = view.get("reported") or {}
    local = view["control"] == "local"
    seal_key = view.get("seal_public_key") or ""
    stored_secrets = set(view.get("secrets") or [])
    reported_secrets = {item["name"]: item["state"] for item in reported.get("secrets") or []}
    catalog = {entry["id"]: entry for entry in view["catalog"]}
    plugin_states = {item["id"]: item for item in reported.get("plugins") or []}
    mode = document["mode"]

    def plugin_card(entry: dict[str, Any] | None, plugin_id: str, current: dict[str, Any] | None):
        values = (current or {}).get("settings") or {}
        settings = (entry or {}).get("settings") or {}
        return {
            "id": plugin_id,
            "entry": entry,
            "configured": current is not None,
            "enabled": bool((current or {}).get("enabled")) if current is not None else True,
            "settings": values,
            "fields": [
                _field(spec, key, values[key] if key in values else spec["default"])
                for key, spec in settings.items()
            ],
            "secrets": [
                {
                    **secret,
                    "field": PLUGIN_SECRET_PREFIX + secret["key"],
                    "remove_field": PLUGIN_SECRET_REMOVE_PREFIX + secret["key"],
                    "stored": secret["name"] in stored_secrets,
                    "state": reported_secrets.get(secret["name"]),
                }
                for secret in (entry or {}).get("secrets") or []
            ],
            "state": plugin_states.get(plugin_id),
            "runs_in_mode": entry is not None and mode in entry["modes"],
            "lan": _lan_hints((entry or {}).get("ports") or [], hostname),
            "requires": (entry or {}).get("requires") or [],
            "restarted_by": [s["id"] for s in document["schedules"] if s.get("plugin") == plugin_id],
        }

    plugins = [plugin_card(catalog.get(p["id"]), p["id"], p) for p in document["plugins"]]
    configured = {p["id"] for p in document["plugins"]}
    available = [
        plugin_card(entry, entry["id"], None) for entry in view["catalog"] if entry["id"] not in configured
    ]

    nas_states = {item["id"]: item for item in reported.get("nas") or []}
    nas = []
    for entry in document["nas"]:
        name = appliance_service.nas_secret_name(entry["id"])
        nas.append(
            {
                **entry,
                "secret_name": name,
                "secret_stored": name in stored_secrets,
                "secret_state": reported_secrets.get(name),
                "state": nas_states.get(entry["id"]),
            }
        )

    vectorizer = document.get("vectorizer")
    answer = (vectorizer or {}).get("answer") or {}
    backup = document.get("backup")
    schedule_states = {item["id"]: item for item in reported.get("schedules") or []}
    secrets_rows = [
        {"name": name, "stored": name in stored_secrets, "state": reported_secrets.get(name)}
        for name in sorted(stored_secrets | set(reported_secrets))
    ]
    backup_report = reported.get("backup")
    return {
        "machine_id": view["machine_id"],
        "revision": view["revision"],
        "applied_revision": view["applied_revision"],
        "in_sync": view["in_sync"],
        "control": view["control"],
        "local": local,
        "updated_at": view.get("updated_at"),
        "reported_at": view.get("reported_at"),
        "management": view["management"],
        "staff_access": staff_access,
        "may_see_remote_access": may_see_remote_access,
        "provider_bound": provider_bound,
        "mode": mode,
        "modes": list(MODE_HELP),
        "mode_help": MODE_HELP,
        # Who may use which form: from services/access.py, through the service's view.
        "may_operate": bool(view["can_operate"]) and not local,
        "may_admin": bool(view["can_admin"]) and not local,
        "may_run_jobs": bool(view["can_operate"]),
        "may_install": bool(view["can_admin"]),
        "seal_key": seal_key,
        "secrets_need_attention": any(row["state"] in ("unreadable", "missing") for row in secrets_rows),
        "secrets": secrets_rows,
        "plugins": plugins,
        "available": available,
        "nas": nas,
        "nas_read": [entry["id"] for entry in document["nas"] if entry.get("access") == "read"],
        "nas_write": [entry["id"] for entry in document["nas"] if entry.get("access") == "write"],
        "nas_secret_template": appliance_service.nas_secret_name("{id}"),
        "nas_secret_field": NAS_SECRET_FIELD,
        "vectorizer": vectorizer,
        "vectorizer_form": vectorizer or VECTORIZER_START,
        "answer": answer,
        "answer_cloud": answer.get("provider") in appliance_service.CLOUD_ANSWER_PROVIDERS,
        "answer_providers": appliance_service.ANSWER_PROVIDERS,
        "cloud_answer_providers": appliance_service.CLOUD_ANSWER_PROVIDERS,
        "answer_secret_name": appliance_service.ANSWER_KEY_NAME,
        "answer_secret_field": ANSWER_SECRET_FIELD,
        "answer_secret_stored": appliance_service.ANSWER_KEY_NAME in stored_secrets,
        "backup": backup,
        "backup_form": backup or BACKUP_START,
        "s3_secret_name": appliance_service.S3_KEY_NAME,
        "s3_secret_field": S3_SECRET_FIELD,
        "s3_secret_stored": appliance_service.S3_KEY_NAME in stored_secrets,
        "schedules": [
            {**entry, "state": schedule_states.get(entry["id"])} for entry in document["schedules"]
        ],
        "jobs": appliance_service.SCHEDULE_JOBS,
        "job_help": JOB_HELP,
        "everies": appliance_service.SCHEDULE_EVERY,
        "weekdays": WEEKDAYS,
        # Not "update": in a template, a.update would be the dict's own method.
        "update_policy": document.get("update"),
        "update_form": document.get("update") or {"channel": "none", "policy": "manual"},
        "channels": appliance_service.UPDATE_CHANNELS,
        "policies": appliance_service.UPDATE_POLICIES,
        "reported": reported,
        "reported_vectorizer": reported.get("vectorizer"),
        "reported_backup": backup_report,
        "backup_key_missing": backup_report is not None and not backup_report.get("key_present"),
        "reported_update": reported.get("update"),
        "capabilities": reported.get("capabilities") or {},
    }


# =============================================================================
# The appliance page
# =============================================================================


@router.get("/machines/{machine_id}/appliance", response_class=HTMLResponse)
def appliance_page(
    machine_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    machine = load_machine(db, principal, machine_id)
    access.require_view(db, principal, machine)
    view = appliance_service.view(db, settings, principal, machine)
    machine_info = views.machine_view(settings, machine, staff=principal.role != "owner")
    context = appliance_context(
        view,
        hostname=machine.device.hostname if machine.device is not None else "",
        staff_access=access.staff_access(db, machine),
        provider_bound=machine_info["provider"] is not None,
        # The remote-access card of the machine page is for these two.
        may_see_remote_access=principal.is_staff or access.has_org_role(principal, "org_admin"),
    )
    response = render(request, settings, principal, "appliance.html", machine=machine_info, a=context)
    response.headers["Cache-Control"] = "no-store"
    return response


@dataclass(frozen=True)
class Refused:
    """A refusal the service recorded (audit trail) and that is reported as an error."""

    message: str


def _provider_or_none(settings: Settings):
    try:
        return get_provider(settings)
    except Exception:
        # Without a provider the rental-protection gate blocks.
        return None


def _saved(change: appliance_service.Change, what: str) -> str:
    if not change.changed:
        return "Nothing changed: the configuration was already like that."
    return f"{what} Saved as revision {change.row.revision}; the machine applies it at its next heartbeat."


def _apply(
    request: Request,
    principal: Principal,
    db: Session,
    settings: Settings,
    machine_id: uuid.UUID,
    form: FormData,
    *,
    minimum: str,
    change: Callable[[Machine], Any],
    done: Callable[[Any], str],
) -> RedirectResponse:
    """One change from a form: CSRF, then who may, then the service. Commit, then redirect."""
    check_csrf(request, principal, settings, form_text(form, "csrf_token"))
    path = page_path(machine_id)
    try:
        # The same two calls as the JSON API's routes: the tenant scope, then section 3.
        machine = load_machine(db, principal, machine_id, lock=True)
        access.require_manage(db, principal, machine, minimum)
    except AppError:
        db.rollback()
        raise
    try:
        result = change(machine)
        db.commit()
    except Forbidden:
        db.rollback()
        raise
    except AppError as exc:
        db.rollback()
        return back(path, err=exc.message)
    if isinstance(result, Refused):
        return back(path, err=result.message)
    return back(path, msg=done(result))


def _actor(principal: Principal, request: Request):
    return principal.actor(client_ip(request))


@router.post("/machines/{machine_id}/appliance/mode")
def appliance_mode(
    machine_id: uuid.UUID,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    def change(machine: Machine):
        body = shaped(ModeIn, {"mode": form_text(form, "mode")})
        result = appliance_service.set_mode(
            db,
            settings,
            _actor(principal, request),
            _provider_or_none(settings),
            machine,
            mode=body.mode,
            user_id=principal.user.id,
            expected_revision=form_revision(form),
        )
        if result.blocked is not None:
            # Recorded in the audit trail (committed), then reported as an error.
            return Refused(describe_blocked(result.blocked))
        return result

    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_admin",
        change=change,
        done=lambda c: _saved(c, f"Mode: {appliance_service.stored_document(c.row)['mode']}."),
    )


@router.post("/machines/{machine_id}/appliance/plugins/{plugin_id}")
def appliance_plugin(
    machine_id: uuid.UUID,
    plugin_id: str,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    def change(machine: Machine):
        spec = get_catalog(settings).get(plugin_id) if ID_RE.fullmatch(plugin_id) else None
        if spec is None:
            raise NotFound("this plugin is not in the catalog")
        body = plugin_request(spec, form)
        return appliance_service.set_plugin(
            db,
            settings,
            _actor(principal, request),
            machine,
            plugin_id,
            enabled=body.enabled,
            values=body.settings,
            sealed_secrets=body.sealed_secrets,
            user_id=principal.user.id,
            expected_revision=form_revision(form),
        )

    # Enabling and configuring a plugin is an operator's work; its secrets are an administrator's.
    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_admin" if touches_plugin_secrets(form) else "org_operator",
        change=change,
        done=lambda c: _saved(c, f"Plugin {plugin_id}."),
    )


@router.post("/machines/{machine_id}/appliance/plugins/{plugin_id}/remove")
def appliance_plugin_remove(
    machine_id: uuid.UUID,
    plugin_id: str,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    def change(machine: Machine):
        if not ID_RE.fullmatch(plugin_id):
            raise NotFound("this plugin is not configured on the machine")
        return appliance_service.remove_plugin(
            db,
            settings,
            _actor(principal, request),
            machine,
            plugin_id,
            user_id=principal.user.id,
            expected_revision=form_revision(form),
        )

    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_operator",
        change=change,
        done=lambda c: _saved(c, f"Plugin {plugin_id} removed; its data stays on the machine."),
    )


@router.post("/machines/{machine_id}/appliance/nas")
def appliance_nas(
    machine_id: uuid.UUID,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    def change(machine: Machine):
        nas_id = _entry_id(form_text(form, "nas_id"), "NAS id")
        entry, sealed = nas_request(form)
        return appliance_service.set_nas(
            db,
            settings,
            _actor(principal, request),
            machine,
            nas_id,
            entry=entry,
            sealed_secret=sealed,
            user_id=principal.user.id,
            expected_revision=form_revision(form),
        )

    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_admin",
        change=change,
        done=lambda c: _saved(c, "NAS entry."),
    )


@router.post("/machines/{machine_id}/appliance/nas/{nas_id}/remove")
def appliance_nas_remove(
    machine_id: uuid.UUID,
    nas_id: str,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    def change(machine: Machine):
        if not ID_RE.fullmatch(nas_id):
            raise NotFound("this NAS entry is not configured on the machine")
        return appliance_service.remove_nas(
            db,
            settings,
            _actor(principal, request),
            machine,
            nas_id,
            user_id=principal.user.id,
            expected_revision=form_revision(form),
        )

    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_admin",
        change=change,
        done=lambda c: _saved(c, f"NAS entry {nas_id} removed."),
    )


@router.post("/machines/{machine_id}/appliance/vectorizer")
def appliance_vectorizer(
    machine_id: uuid.UUID,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    def change(machine: Machine):
        section, sealed = vectorizer_request(form)
        return appliance_service.set_vectorizer(
            db,
            settings,
            _actor(principal, request),
            machine,
            section=section,
            sealed_secret=sealed,
            user_id=principal.user.id,
            expected_revision=form_revision(form),
        )

    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_admin",
        change=change,
        done=lambda c: _saved(c, "Vectorization."),
    )


@router.post("/machines/{machine_id}/appliance/vectorizer/remove")
def appliance_vectorizer_remove(
    machine_id: uuid.UUID,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_admin",
        change=lambda machine: appliance_service.remove_vectorizer(
            db,
            settings,
            _actor(principal, request),
            machine,
            user_id=principal.user.id,
            expected_revision=form_revision(form),
        ),
        done=lambda c: _saved(c, "Vectorization removed; the index stays on the machine."),
    )


@router.post("/machines/{machine_id}/appliance/backup")
def appliance_backup(
    machine_id: uuid.UUID,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    def change(machine: Machine):
        section, sealed = backup_request(form)
        return appliance_service.set_backup(
            db,
            settings,
            _actor(principal, request),
            machine,
            section=section,
            sealed_secret=sealed,
            user_id=principal.user.id,
            expected_revision=form_revision(form),
        )

    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_admin",
        change=change,
        done=lambda c: _saved(c, "Backup."),
    )


@router.post("/machines/{machine_id}/appliance/backup/remove")
def appliance_backup_remove(
    machine_id: uuid.UUID,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_admin",
        change=lambda machine: appliance_service.remove_backup(
            db,
            settings,
            _actor(principal, request),
            machine,
            user_id=principal.user.id,
            expected_revision=form_revision(form),
        ),
        done=lambda c: _saved(c, "Backup removed; archives already made stay where they are."),
    )


@router.post("/machines/{machine_id}/appliance/schedules")
def appliance_schedule(
    machine_id: uuid.UUID,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    def change(machine: Machine):
        schedule_id = _entry_id(form_text(form, "schedule_id"), "schedule id")
        return appliance_service.set_schedule(
            db,
            settings,
            _actor(principal, request),
            machine,
            schedule_id,
            entry=schedule_request(form),
            user_id=principal.user.id,
            expected_revision=form_revision(form),
        )

    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_operator",
        change=change,
        done=lambda c: _saved(c, "Schedule."),
    )


@router.post("/machines/{machine_id}/appliance/schedules/{schedule_id}/remove")
def appliance_schedule_remove(
    machine_id: uuid.UUID,
    schedule_id: str,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    def change(machine: Machine):
        if not ID_RE.fullmatch(schedule_id):
            raise NotFound("this schedule is not configured on the machine")
        return appliance_service.remove_schedule(
            db,
            settings,
            _actor(principal, request),
            machine,
            schedule_id,
            user_id=principal.user.id,
            expected_revision=form_revision(form),
        )

    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_operator",
        change=change,
        done=lambda c: _saved(c, f"Schedule {schedule_id} removed."),
    )


@router.post("/machines/{machine_id}/appliance/update")
def appliance_update(
    machine_id: uuid.UUID,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_admin",
        change=lambda machine: appliance_service.set_update(
            db,
            settings,
            _actor(principal, request),
            machine,
            section=update_request(form),
            user_id=principal.user.id,
            expected_revision=form_revision(form),
        ),
        done=lambda c: _saved(c, "Update policy."),
    )


@router.post("/machines/{machine_id}/appliance/jobs")
def appliance_job(
    machine_id: uuid.UUID,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Run one job now: the typed operation ``appliance_run_job``. Not a change to the document."""

    def change(machine: Machine):
        body = job_request(form)
        operation = appliance_service.request_job(
            db,
            settings,
            _actor(principal, request),
            _provider_or_none(settings),
            machine,
            job=body.job,
            plugin=body.plugin,
            user_id=principal.user.id,
        )
        if operation.status == "blocked":
            return Refused(operation.detail)
        return operation

    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_operator",
        change=change,
        done=lambda op: f"Job {op.params.get('job')} queued; the machine receives it at its next heartbeat.",
    )


@router.post("/machines/{machine_id}/appliance/install-update")
def appliance_install_update(
    machine_id: uuid.UUID,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """Install one published release: the typed operation ``install_update``."""

    def change(machine: Machine):
        body = shaped(InstallUpdateIn, {"version": form_text(form, "version")})
        operation = release_service.request_install(
            db,
            settings,
            _actor(principal, request),
            _provider_or_none(settings),
            machine,
            version=body.version,
            user_id=principal.user.id,
        )
        if operation.status == "blocked":
            return Refused(operation.detail)
        return operation

    return _apply(
        request,
        principal,
        db,
        settings,
        machine_id,
        form,
        minimum="org_admin",
        change=change,
        done=lambda op: (
            f"Installation of {op.params.get('version')} queued; the machine downloads, verifies and "
            "installs it after its next heartbeat."
        ),
    )


# =============================================================================
# Releases (staff)
# =============================================================================

RELEASES_PATH = "/admin/releases"


def _release_version(version: str) -> str:
    if len(version) > MAX_VERSION_LEN:
        raise NotFound("no such release")
    return version


def _release_action(
    request: Request,
    principal: Principal,
    db: Session,
    settings: Settings,
    form: FormData,
    fn: Callable[[], Any],
    ok: Callable[[Any], str],
) -> RedirectResponse:
    check_csrf(request, principal, settings, form_text(form, "csrf_token"))
    need(principal, "admin")
    try:
        result = fn()
        db.commit()
    except Forbidden:
        db.rollback()
        raise
    except AppError as exc:
        db.rollback()
        return back(RELEASES_PATH, err=exc.message)
    return back(RELEASES_PATH, msg=ok(result))


@router.get(RELEASES_PATH, response_class=HTMLResponse)
def releases_page(
    request: Request,
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> Response:
    need(principal, "admin", "auditor")
    key_problem = ""
    try:
        key_ids = sorted(release_service.trusted_keys(settings))
    except AppError as exc:
        key_ids, key_problem = [], exc.message
    return render(
        request,
        settings,
        principal,
        "admin_releases.html",
        releases=[release_service.release_view(r) for r in release_service.list_releases(db)],
        key_ids=key_ids,
        key_problem=key_problem,
        channels=RELEASE_CHANNELS,
        max_bytes=settings.release_max_bytes,
        api_base=settings.public_base_url.rstrip("/") + "/api/v1",
    )


def _read_upload(value: Any, what: str, limit: int) -> bytes:
    """The bytes of an uploaded file, refused beyond ``limit``. Absent or empty: b""."""
    if value is None or isinstance(value, str):
        if value:
            raise InvalidRequest(f"{what}: choose a file")
        return b""
    if not isinstance(value, UploadFile):
        raise InvalidRequest(f"{what}: choose a file")
    data = value.file.read(limit + 1)
    if len(data) > limit:
        raise InvalidRequest(f"{what}: is larger than {limit} bytes")
    return data


@router.post(RELEASES_PATH)
def releases_create(
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    """First step of publishing: the signed manifest (``manifest.json``) and its signature."""

    def create():
        manifest = _read_upload(form.get("manifest"), "manifest", MAX_MANIFEST_BYTES)
        if not manifest:
            raise InvalidRequest("manifest: choose the manifest.json written by scripts/release-sign.py")
        signature_file = _read_upload(form.get("signature_file"), "signature", MAX_SIGNATURE_FILE)
        try:
            signature = signature_file.decode("ascii").strip() if signature_file else ""
        except UnicodeDecodeError:
            raise InvalidRequest("signature: the file is not the base64 text of manifest.sig") from None
        signature = signature or form_text(form, "signature")
        if not signature:
            raise InvalidRequest("signature: choose manifest.sig or paste its content")
        body = shaped(
            ReleaseIn,
            {"manifest_b64": base64.b64encode(manifest).decode(), "signature_b64": signature},
        )
        return release_service.create_release(
            db,
            settings,
            _actor(principal, request),
            manifest_b64=body.manifest_b64,
            signature_b64=body.signature_b64,
            user_id=principal.user.id,
        )

    return _release_action(
        request,
        principal,
        db,
        settings,
        form,
        create,
        lambda release: f"Release {release.version} accepted. Upload its package next (see below).",
    )


@router.post(RELEASES_PATH + "/{version}/channels")
def releases_channels(
    version: str,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    def assign():
        body = shaped(ChannelsIn, {"channels": form_values(form, "channels")})
        return release_service.set_channels(
            db, settings, _actor(principal, request), _release_version(version), body.channels
        )

    return _release_action(
        request,
        principal,
        db,
        settings,
        form,
        assign,
        lambda release: (
            f"Release {release.version} is offered on: {', '.join(release.channels)}."
            if release.channels
            else f"Release {release.version} is offered on no channel."
        ),
    )


@router.post(RELEASES_PATH + "/{version}/withdraw")
def releases_withdraw(
    version: str,
    request: Request,
    form: FormData = Depends(form_data),
    principal: Principal = Depends(page_principal),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
):
    def withdraw():
        body = shaped(WithdrawIn, {"reason": form_text(form, "reason")})
        return release_service.withdraw(
            db, _actor(principal, request), _release_version(version), body.reason
        )

    return _release_action(
        request,
        principal,
        db,
        settings,
        form,
        withdraw,
        lambda release: f"Release {release.version} withdrawn; it is no longer offered to any machine.",
    )
