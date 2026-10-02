"""A machine's appliance configuration (docs/appliance.md, sections 2, 4, 6 and 12).

Three things live here:

- the **desired-state document**: what the machine should run. One per machine,
  with a revision that goes up by one at every accepted change. It is checked
  as a whole, against the plugin catalog, before anything is stored, and the
  machine checks it again and trusts none of it;
- the **sealed secrets** that belong to it. They arrive already encrypted for
  the machine's own key; this process stores and forwards them and has no key
  to open them. They are never written to the audit trail, a log or a response
  for people: only their names are;
- what the machine **reports** about itself. It is cleaned and bounded on
  arrival, then displayed. Nothing in it decides what anyone may do. Two
  functional guards read it, and neither is a permission: a machine that says
  it follows its own profile file is not sent changes it would ignore, and a
  plugin the machine's firmware does not have cannot be switched on.

Who may call what is decided by the routes, through ``services/access.py``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..audit import Actor, audit
from ..config import Settings
from ..errors import Conflict, InvalidRequest, NotFound
from ..models import (
    APPLIANCE_MODES,
    Machine,
    MachineAppliance,
    Operation,
    ProviderMachine,
    User,
    new_id,
    utcnow,
)
from ..providers.base import Provider
from ..sealing import SECRET_NAME_RE, check_sealed, parse_seal_public_key
from ..security import redact_text
from . import access
from . import operations as operation_service
from .accounts import Principal
from .catalog import ID_RE, Catalog, get_catalog, has_control_character
from .maintenance import LEAVE_VAST_MODE, SafetyDecision, evaluate

DOCUMENT_SCHEMA = 1
MAX_DOCUMENT_BYTES = 64 * 1024
MAX_DEPTH = 8
MAX_REVISION = 2**31 - 1

MAX_PLUGINS = 32
MAX_NAS = 8
MAX_SCHEDULES = 16
MAX_SECRETS = 32

NAS_KINDS = ("smb", "nfs")
NAS_ACCESS = ("read", "write")
ANSWER_PROVIDERS = ("none", "local", "openai_compatible", "anthropic")
CLOUD_ANSWER_PROVIDERS = ("openai_compatible", "anthropic")
DESTINATION_KINDS = ("nas", "s3")
SCHEDULE_JOBS = ("vectorize_sync", "backup_run", "update_check", "plugin_restart")
SCHEDULE_EVERY = ("hourly", "daily", "weekly")
UPDATE_CHANNELS = ("stable", "beta", "none")
UPDATE_POLICIES = ("manual", "auto")

ANSWER_KEY_NAME = "ai.answer.api_key"
S3_KEY_NAME = "backup.s3.secret_key"
VECTORIZER_PLUGIN = "vectorizer"

_HOST = r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?"
HOST_RE = re.compile(_HOST)
SHARE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._$-]{0,79}")
EXPORT_RE = re.compile(r"/[A-Za-z0-9._/-]{0,254}")
DOMAIN_RE = re.compile(r"[A-Za-z0-9._-]{0,64}")
EXTENSION_RE = re.compile(r"[a-z0-9]{1,8}")
MODEL_REF_RE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?")
ANSWER_MODEL_RE = re.compile(r"[A-Za-z0-9._:/-]{1,100}")
REGION_RE = re.compile(r"[a-z0-9-]{1,40}")
BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
PREFIX_RE = re.compile(r"[A-Za-z0-9._/-]{0,200}")
ACCESS_KEY_RE = re.compile(r"[A-Za-z0-9]{4,128}")
# https://host[:port][/path]: no user info, no query, no fragment.
_URL = rf"https://(?P<host>{_HOST})(:(?P<port>[0-9]{{1,5}}))?"
BASE_URL_RE = re.compile(_URL + r"(?P<path>(/[A-Za-z0-9._~-]*)*)")
ENDPOINT_RE = re.compile(_URL)
USERNAME_FORBIDDEN = frozenset(",=\\/:")
_SHOWABLE_KEY_RE = re.compile(r"[A-Za-z0-9_.-]{1,40}")


class DocumentInvalid(InvalidRequest):
    """The desired-state document, or a change to it, breaks a rule of the contract."""


def default_document() -> dict[str, Any]:
    """What a machine has before anything was configured in the cloud (revision 0)."""
    return {"schema": DOCUMENT_SCHEMA, "mode": "vast", "plugins": [], "nas": [], "schedules": []}


def nas_secret_name(nas_id: str) -> str:
    return f"nas.{nas_id}.password"


# =============================================================================
# Validation (section 4). Messages name the place and the rule, never the value.
# =============================================================================


def _fail(path: str, reason: str) -> None:
    raise DocumentInvalid(f"{path}: {reason}")


def _is_int(value: Any) -> bool:
    """A JSON integer: not a string, not a fraction, not a boolean."""
    return isinstance(value, int) and not isinstance(value, bool)


def _int_in(obj: dict[str, Any], key: str, path: str, low: int, high: int) -> int:
    value = obj[key]
    if not _is_int(value) or not (low <= value <= high):
        _fail(f"{path}.{key}", f"must be an integer from {low} to {high}")
    return value


def _bool_in(obj: dict[str, Any], key: str, path: str) -> bool:
    if not isinstance(obj[key], bool):
        _fail(f"{path}.{key}", "must be true or false")
    return obj[key]


def _one_of(obj: dict[str, Any], key: str, path: str, allowed: tuple[str, ...]) -> str:
    value = obj[key]
    if not isinstance(value, str) or value not in allowed:
        _fail(f"{path}.{key}", "must be one of: " + ", ".join(allowed))
    return value


def _matching(obj: dict[str, Any], key: str, path: str, pattern: re.Pattern[str], what: str) -> str:
    value = obj[key]
    if not isinstance(value, str) or not pattern.fullmatch(value):
        _fail(f"{path}.{key}", what)
    return value


def _keys(
    value: Any,
    path: str,
    required: tuple[str, ...],
    optional: tuple[str, ...] = (),
    *,
    unknown: str = "",
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    extra = sorted(str(key) for key in set(value) - set(required) - set(optional))
    if extra:
        shown = f" {extra[0]!r}" if _SHOWABLE_KEY_RE.fullmatch(extra[0]) else ""
        _fail(path, unknown or f"unknown key{shown}")
    for key in required:
        if key not in value:
            _fail(path, f"{key} is required")
    return value


def _list_of(value: Any, path: str, low: int, high: int) -> list[Any]:
    if not isinstance(value, list):
        _fail(path, "must be a list")
    if not (low <= len(value) <= high):
        _fail(path, f"must have {low} to {high} entries")
    return value


def _identifier(obj: dict[str, Any], path: str, seen: dict[str, Any]) -> str:
    value = obj["id"]
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        _fail(
            f"{path}.id", "must be a lower-case letter followed by up to 30 lower-case letters, digits or -"
        )
    if value in seen:
        _fail(f"{path}.id", "is used twice")
    return value


def _relative_path_problem(value: Any, max_len: int, *, allow_empty: bool) -> str | None:
    if not isinstance(value, str):
        return "must be a string"
    if value == "":
        return None if allow_empty else "must not be empty"
    if len(value) > max_len:
        return f"must be at most {max_len} characters"
    if any(segment in ("", ".", "..") for segment in value.split("/")):
        return "must be a relative path without empty, . or .. segments and without a leading or trailing /"
    return None


def _port_ok(text: str | None) -> bool:
    return text is None or (not text.startswith("0") and 1 <= int(text) <= 65535)


def _check_text(document: Any) -> None:
    """No string, and no key, contains a control character. Also bounds the nesting."""
    stack: list[tuple[Any, str, int]] = [(document, "document", 0)]
    while stack:
        value, path, depth = stack.pop()
        if depth > MAX_DEPTH:
            _fail(path, "is nested too deeply")
        if isinstance(value, str):
            if has_control_character(value):
                _fail(path, "contains a control character")
        elif isinstance(value, dict):
            for key, inner in value.items():
                if not isinstance(key, str) or has_control_character(key):
                    _fail(path, "has a key that is not plain text")
                shown = key if _SHOWABLE_KEY_RE.fullmatch(key) else "?"
                stack.append((inner, f"{path}.{shown}" if path != "document" else shown, depth + 1))
        elif isinstance(value, list):
            stack.extend((inner, f"{path}[{index}]", depth + 1) for index, inner in enumerate(value))
        elif isinstance(value, float):
            _fail(path, "must be an integer, not a fraction")
        elif value is not None and not isinstance(value, int):
            _fail(path, "is not a JSON value")


def _check_plugins(document: dict[str, Any], catalog: Catalog) -> dict[str, dict[str, Any]]:
    plugins: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(_list_of(document.get("plugins", []), "plugins", 0, MAX_PLUGINS)):
        path = f"plugins[{index}]"
        _keys(entry, path, ("id", "enabled"), ("settings",))
        plugin_id = _identifier(entry, path, plugins)
        _bool_in(entry, "enabled", path)
        spec = catalog.get(plugin_id)
        if spec is None:
            _fail(f"{path}.id", "is not in the plugin catalog")
        values = entry.get("settings", {})
        if not isinstance(values, dict):
            _fail(f"{path}.settings", "must be an object")
        for key, value in values.items():
            setting = spec.settings.get(key)
            if setting is None:
                _fail(f"{path}.settings", "has a setting this plugin does not take")
            problem = setting.problem(value)
            if problem:
                _fail(f"{path}.settings.{key}", problem)
        plugins[plugin_id] = entry
    for index, (plugin_id, entry) in enumerate(plugins.items()):
        if not entry["enabled"]:
            continue
        for other in catalog.get(plugin_id).requires:
            if other not in plugins or not plugins[other]["enabled"]:
                _fail(f"plugins[{index}]", f"needs the plugin {other} to be enabled as well")
    return plugins


def _check_nas(document: dict[str, Any], references: dict[str, str]) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(_list_of(document.get("nas", []), "nas", 0, MAX_NAS)):
        path = f"nas[{index}]"
        if not isinstance(entry, dict):
            _fail(path, "must be an object")
        if "kind" not in entry:
            _fail(path, "kind is required")
        kind = _one_of(entry, "kind", path, NAS_KINDS)
        if kind == "smb":
            _keys(
                entry,
                path,
                ("id", "kind", "host", "share", "username", "access"),
                ("subpath", "domain", "secret"),
                unknown="an smb entry takes id, kind, host, share, subpath, username, domain, "
                "secret and access",
            )
        else:
            _keys(
                entry,
                path,
                ("id", "kind", "host", "export", "access"),
                ("subpath",),
                unknown="an nfs entry takes id, kind, host, export, subpath and access; "
                "it has no share, username, domain or secret",
            )
        nas_id = _identifier(entry, path, entries)
        _matching(entry, "host", path, HOST_RE, "must be a host name or an IPv4 address")
        _one_of(entry, "access", path, NAS_ACCESS)
        problem = _relative_path_problem(entry.get("subpath", ""), 512, allow_empty=True)
        # The subpath becomes part of the mount source (//host/share/subpath) and
        # mount.cifs passes it to the kernel as prefixpath=<subpath>, unescaped:
        # a comma would add mount options. A backslash is an SMB path separator.
        if problem is None and any(c in entry.get("subpath", "") for c in ",\\"):
            problem = "must not contain a comma or a backslash"
        if problem:
            _fail(f"{path}.subpath", problem)
        if kind == "smb":
            share = _matching(
                entry, "share", path, SHARE_RE, "must be a share name of letters, digits, space and . _ $ -"
            )
            if share.endswith(" "):
                _fail(f"{path}.share", "must not end with a space")
            username = entry["username"]
            if (
                not isinstance(username, str)
                or len(username) > 64
                or any(ch in USERNAME_FORBIDDEN or ch.isspace() for ch in username)
            ):
                _fail(f"{path}.username", "must be at most 64 characters without , = \\ / : or white space")
            if not isinstance(entry.get("domain", ""), str) or not DOMAIN_RE.fullmatch(
                entry.get("domain", "")
            ):
                _fail(f"{path}.domain", "must be at most 64 letters, digits, . _ or -")
            if username == "":
                if "secret" in entry:
                    _fail(f"{path}.secret", "guest access (an empty username) has no password")
            else:
                if "secret" not in entry:
                    _fail(f"{path}.secret", "a user name needs its password")
                if entry["secret"] != nas_secret_name(nas_id):
                    _fail(f"{path}.secret", f"must be exactly {nas_secret_name(nas_id)}")
                references[nas_secret_name(nas_id)] = f"{path}.secret"
        else:
            export = _matching(
                entry, "export", path, EXPORT_RE, "must be an absolute path of letters, digits and . _ / -"
            )
            if ".." in export.split("/"):
                _fail(f"{path}.export", "must not contain a .. segment")
        entries[nas_id] = entry
    return entries


def _check_base_url(answer: dict[str, Any], path: str) -> None:
    value = answer["base_url"]
    match = BASE_URL_RE.fullmatch(value) if isinstance(value, str) and len(value) <= 200 else None
    if match is None or not _port_ok(match.group("port")):
        _fail(
            f"{path}.base_url",
            "must be https://host[:port][/path], at most 200 characters, "
            "without user info, query or fragment",
        )


def _check_vectorizer(
    document: dict[str, Any], nas: dict[str, dict[str, Any]], references: dict[str, str]
) -> None:
    if "vectorizer" not in document:
        return
    path = "vectorizer"
    section = _keys(
        document["vectorizer"],
        path,
        ("sources", "extensions", "exclude", "max_file_mib", "embedding_model", "ocr", "answer"),
    )
    sources = _list_of(section["sources"], f"{path}.sources", 1, 8)
    for index, source in enumerate(sources):
        where = f"{path}.sources[{index}]"
        if not isinstance(source, str) or source not in nas or nas[source]["access"] != "read":
            _fail(where, "must be the id of a NAS entry with access read")
        if source in sources[:index]:
            _fail(where, "is listed twice")
    extensions = _list_of(section["extensions"], f"{path}.extensions", 1, 40)
    for index, extension in enumerate(extensions):
        where = f"{path}.extensions[{index}]"
        if not isinstance(extension, str) or not EXTENSION_RE.fullmatch(extension):
            _fail(where, "must be 1 to 8 lower-case letters or digits, without a dot")
        if extension in extensions[:index]:
            _fail(where, "is listed twice")
    excludes = _list_of(section["exclude"], f"{path}.exclude", 0, 32)
    for index, exclude in enumerate(excludes):
        where = f"{path}.exclude[{index}]"
        problem = _relative_path_problem(exclude, 200, allow_empty=False)
        if problem:
            _fail(where, problem)
        if exclude in excludes[:index]:
            _fail(where, "is listed twice")
    _int_in(section, "max_file_mib", path, 1, 2048)
    _matching(section, "embedding_model", path, MODEL_REF_RE, "must be a model reference such as bge-m3")
    _bool_in(section, "ocr", path)

    where = f"{path}.answer"
    answer = section["answer"]
    if not isinstance(answer, dict):
        _fail(where, "must be an object")
    if "provider" not in answer:
        _fail(where, "provider is required")
    provider = _one_of(answer, "provider", where, ANSWER_PROVIDERS)
    if provider == "none":
        _keys(answer, where, ("provider",), unknown="the provider none takes nothing else")
        return
    if provider == "local":
        _keys(answer, where, ("provider", "model"), unknown="a local model has no base_url and no secret")
    elif provider == "openai_compatible":
        _keys(answer, where, ("provider", "model", "base_url", "secret"))
    else:
        _keys(answer, where, ("provider", "model", "secret"), ("base_url",))
    _matching(answer, "model", where, ANSWER_MODEL_RE, "must be 1 to 100 letters, digits or . _ : / -")
    if "base_url" in answer:
        _check_base_url(answer, where)
    if provider in CLOUD_ANSWER_PROVIDERS:
        if answer["secret"] != ANSWER_KEY_NAME:
            _fail(f"{where}.secret", f"must be exactly {ANSWER_KEY_NAME}")
        references[ANSWER_KEY_NAME] = f"{where}.secret"


def _check_backup(
    document: dict[str, Any], nas: dict[str, dict[str, Any]], references: dict[str, str]
) -> None:
    if "backup" not in document:
        return
    path = "backup"
    section = _keys(document["backup"], path, ("enabled", "destination", "include_models", "keep"))
    _bool_in(section, "enabled", path)
    _bool_in(section, "include_models", path)
    _int_in(section, "keep", path, 1, 365)
    where = f"{path}.destination"
    destination = section["destination"]
    if not isinstance(destination, dict):
        _fail(where, "must be an object")
    if "kind" not in destination:
        _fail(where, "kind is required")
    kind = _one_of(destination, "kind", where, DESTINATION_KINDS)
    if kind == "nas":
        _keys(
            destination,
            where,
            ("kind", "nas_id"),
            ("subpath",),
            unknown="a nas destination takes nas_id and subpath",
        )
        target = destination["nas_id"]
        if not isinstance(target, str) or target not in nas or nas[target]["access"] != "write":
            _fail(f"{where}.nas_id", "must be the id of a NAS entry with access write")
        problem = _relative_path_problem(destination.get("subpath", ""), 512, allow_empty=True)
        if problem:
            _fail(f"{where}.subpath", problem)
        return
    _keys(
        destination,
        where,
        ("kind", "endpoint", "region", "bucket", "prefix", "access_key_id", "secret"),
        unknown="an s3 destination takes endpoint, region, bucket, prefix, access_key_id and secret",
    )
    endpoint = destination["endpoint"]
    match = ENDPOINT_RE.fullmatch(endpoint) if isinstance(endpoint, str) and len(endpoint) <= 200 else None
    if match is None or not _port_ok(match.group("port")):
        _fail(f"{where}.endpoint", "must be https://host[:port], without a path")
    _matching(destination, "region", where, REGION_RE, "must be 1 to 40 lower-case letters, digits or -")
    _matching(
        destination, "bucket", where, BUCKET_RE, "must be a lower-case bucket name of 3 to 63 characters"
    )
    prefix = _matching(
        destination, "prefix", where, PREFIX_RE, "must be at most 200 letters, digits or . _ / -"
    )
    if ".." in prefix:
        _fail(f"{where}.prefix", "must not contain ..")
    _matching(destination, "access_key_id", where, ACCESS_KEY_RE, "must be 4 to 128 letters or digits")
    if destination["secret"] != S3_KEY_NAME:
        _fail(f"{where}.secret", f"must be exactly {S3_KEY_NAME}")
    references[S3_KEY_NAME] = f"{where}.secret"


def _check_schedules(document: dict[str, Any], plugins: dict[str, dict[str, Any]]) -> None:
    seen: dict[str, Any] = {}
    for index, entry in enumerate(_list_of(document.get("schedules", []), "schedules", 0, MAX_SCHEDULES)):
        path = f"schedules[{index}]"
        _keys(entry, path, ("id", "job", "every", "minute", "enabled"), ("plugin", "hour", "weekday"))
        seen[_identifier(entry, path, seen)] = entry
        job = _one_of(entry, "job", path, SCHEDULE_JOBS)
        every = _one_of(entry, "every", path, SCHEDULE_EVERY)
        _int_in(entry, "minute", path, 0, 59)
        _bool_in(entry, "enabled", path)
        if every == "hourly":
            if "hour" in entry:
                _fail(f"{path}.hour", "an hourly schedule has no hour")
        else:
            if "hour" not in entry:
                _fail(path, f"hour is required for a {every} schedule")
            _int_in(entry, "hour", path, 0, 23)
        if every == "weekly":
            if "weekday" not in entry:
                _fail(path, "weekday is required for a weekly schedule")
            _int_in(entry, "weekday", path, 0, 6)
        elif "weekday" in entry:
            _fail(f"{path}.weekday", "only a weekly schedule has a weekday")
        if job == "plugin_restart":
            if "plugin" not in entry:
                _fail(path, "plugin is required for plugin_restart")
            if not isinstance(entry["plugin"], str) or entry["plugin"] not in plugins:
                _fail(f"{path}.plugin", "must be the id of a plugin in plugins")
        elif "plugin" in entry:
            _fail(f"{path}.plugin", "only plugin_restart takes a plugin")


def _check_update(document: dict[str, Any]) -> None:
    if "update" not in document:
        return
    path = "update"
    section = _keys(document["update"], path, ("channel", "policy"), ("window",))
    _one_of(section, "channel", path, UPDATE_CHANNELS)
    policy = _one_of(section, "policy", path, UPDATE_POLICIES)
    if "window" not in section:
        if policy == "auto":
            _fail(path, "window is required with the auto policy")
        return
    window = _keys(section["window"], f"{path}.window", ("start_hour", "end_hour"))
    start = _int_in(window, "start_hour", f"{path}.window", 0, 23)
    end = _int_in(window, "end_hour", f"{path}.window", 0, 23)
    if start == end:
        _fail(f"{path}.window", "start_hour and end_hour must differ")


def _plugin_secret_names(
    plugins: dict[str, dict[str, Any]] | list[Any], catalog: Catalog
) -> tuple[set[str], dict[str, str]]:
    """Names a plugin list may have in ``secrets``, and those it must have (name -> where)."""
    allowed: set[str] = set()
    required: dict[str, str] = {}
    ids = plugins if isinstance(plugins, dict) else [p.get("id") for p in plugins if isinstance(p, dict)]
    for index, plugin_id in enumerate(ids):
        spec = catalog.get(plugin_id) if isinstance(plugin_id, str) else None
        if spec is None:
            continue
        for name, secret in spec.secret_names().items():
            allowed.add(name)
            if secret.required:
                required[name] = f"plugins[{index}]"
    return allowed, required


def _check_secrets(
    document: dict[str, Any], plugins: dict[str, dict[str, Any]], references: dict[str, str], catalog: Catalog
) -> None:
    secrets = document.get("secrets", {})
    if not isinstance(secrets, dict):
        _fail("secrets", "must be an object of name to sealed value")
    if len(secrets) > MAX_SECRETS:
        _fail("secrets", f"must have at most {MAX_SECRETS} entries")
    allowed, required = _plugin_secret_names(plugins, catalog)
    for name, where in {**required, **references}.items():
        if name not in secrets:
            _fail(where, f"the secret {name} is not in secrets")
    allowed |= set(references)
    for name, value in secrets.items():
        if not SECRET_NAME_RE.fullmatch(name):
            _fail("secrets", "has a name that is not a secret name")
        if name not in allowed:
            _fail(f"secrets.{name}", "nothing refers to this secret")
        try:
            check_sealed(value)
        except InvalidRequest:
            _fail(f"secrets.{name}", "must be a value sealed for the machine, never clear text")


def validate_document(document: Any, catalog: Catalog) -> None:
    """Check a complete desired-state document (with ``revision`` and ``secrets``).

    Raises ``DocumentInvalid`` (HTTP 400) naming the first rule that is broken.
    The same rules are implemented by the machine's helper, against the same
    fixtures (``appliance/testdata/documents``).
    """
    if not isinstance(document, dict):
        _fail("document", "must be an object")
    try:
        size = len(json.dumps(document, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode())
    except (TypeError, ValueError, RecursionError):  # includes text that is not valid Unicode
        _fail("document", "is not a JSON document")
    if size > MAX_DOCUMENT_BYTES:
        _fail("document", "is larger than 64 KiB")
    _check_text(document)
    _keys(
        document,
        "document",
        ("schema", "revision", "mode"),
        ("plugins", "nas", "vectorizer", "backup", "schedules", "update", "secrets"),
    )
    if not _is_int(document["schema"]) or document["schema"] != DOCUMENT_SCHEMA:
        _fail("schema", f"must be {DOCUMENT_SCHEMA}")
    if not _is_int(document["revision"]) or not (1 <= document["revision"] <= MAX_REVISION):
        _fail("revision", "must be an integer of 1 or more")
    if not isinstance(document["mode"], str) or document["mode"] not in APPLIANCE_MODES:
        _fail("mode", "must be one of: " + ", ".join(APPLIANCE_MODES))

    references: dict[str, str] = {}  # secret name -> the place that refers to it
    plugins = _check_plugins(document, catalog)
    nas = _check_nas(document, references)
    _check_vectorizer(document, nas, references)
    if (
        VECTORIZER_PLUGIN in plugins
        and plugins[VECTORIZER_PLUGIN]["enabled"]
        and "vectorizer" not in document
    ):
        _fail("plugins", "the vectorizer plugin can be enabled only once vectorization is configured")
    _check_backup(document, nas, references)
    _check_schedules(document, plugins)
    _check_update(document)
    _check_secrets(document, plugins, references, catalog)


def referenced_secret_names(document: dict[str, Any], catalog: Catalog) -> set[str]:
    """Every secret name the (stored) document can have a value for."""
    names, _ = _plugin_secret_names(document.get("plugins") or [], catalog)
    for entry in document.get("nas") or []:
        if isinstance(entry, dict) and isinstance(entry.get("secret"), str):
            names.add(entry["secret"])
    answer = (document.get("vectorizer") or {}).get("answer") or {}
    if isinstance(answer.get("secret"), str):
        names.add(answer["secret"])
    destination = (document.get("backup") or {}).get("destination") or {}
    if isinstance(destination.get("secret"), str):
        names.add(destination["secret"])
    return names


# =============================================================================
# Storage
# =============================================================================


def _row(
    db: Session, machine_id: uuid.UUID, *, lock: bool = False, create: bool = False
) -> MachineAppliance | None:
    """The appliance row of a machine. It is created on first use."""
    query = select(MachineAppliance).where(MachineAppliance.machine_id == machine_id)
    if lock:
        db.flush()
        query = query.with_for_update().execution_options(populate_existing=True)
    row = db.execute(query).scalar_one_or_none()
    if row is None and create:
        # Two first uses at the same moment: one inserts, both then read the same row.
        db.execute(
            pg_insert(MachineAppliance)
            .values(
                id=new_id(),
                machine_id=machine_id,
                revision=0,
                document=default_document(),
                secrets={},
                reported={},
                applied_revision=0,
            )
            .on_conflict_do_nothing(index_elements=[MachineAppliance.machine_id])
        )
        row = db.execute(query).scalar_one()
    return row


def stored_document(row: MachineAppliance | None) -> dict[str, Any]:
    """The document as stored (no revision, no secrets), with the defaults filled in."""
    return {**default_document(), **copy.deepcopy((row.document if row is not None else None) or {})}


def desired_modes(db: Session, machine_ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
    """The mode each machine should be in. A machine nothing was configured for is in ``vast``."""
    modes = dict.fromkeys(machine_ids, "vast")
    if machine_ids:
        rows = db.execute(
            select(MachineAppliance.machine_id, MachineAppliance.document).where(
                MachineAppliance.machine_id.in_(machine_ids)
            )
        )
        for machine_id, document in rows:
            mode = (document or {}).get("mode")
            if mode in APPLIANCE_MODES:
                modes[machine_id] = mode
    return modes


def _control(row: MachineAppliance | None) -> str:
    """What the machine last said about who configures it: ``cloud``, ``local``, or
    ``unknown`` (its agent could not reach the helper, or said something else).
    A machine that has reported nothing yet is ``cloud``: it can be configured
    before it first applies anything."""
    if row is None or not row.reported:
        return "cloud"
    control = row.reported.get("control")
    return control if control in CONTROL_VALUES else "cloud"


# =============================================================================
# Changes (section 12). One function per route.
# =============================================================================


@dataclass(frozen=True)
class Change:
    row: MachineAppliance
    changed: bool
    # Set when the rental-protection gate refused a mode change: nothing was changed.
    blocked: SafetyDecision | None = None


def _begin(db: Session, machine: Machine, expected_revision: int | None) -> MachineAppliance:
    """Lock the row and refuse what cannot be changed right now."""
    row = _row(db, machine.id, lock=True, create=True)
    if expected_revision is not None and expected_revision != row.revision:
        raise Conflict(
            f"the configuration changed in the meantime (it is at revision {row.revision}); "
            "load it again before changing it"
        )
    if _control(row) == "local":
        raise Conflict(
            "this machine follows its own profile file (control: local); "
            "its configuration is changed on the machine, not from here",
            code="locally_controlled",
        )
    return row


def _accept_sealed(row: MachineAppliance, value: Any) -> str:
    """A secret is taken only sealed, and only once the machine has said which key to seal for."""
    sealed = check_sealed(value)
    if not row.seal_public_key:
        raise Conflict(
            "the machine has not reported its sealing key yet; a secret can only be stored once it has",
            code="no_sealing_key",
        )
    return sealed


def _via_grant(db: Session, machine: Machine, user_id: uuid.UUID | None) -> list[str] | None:
    """The remote-access grants a change by staff relied on, for the audit trail."""
    if machine.management != "customer" or user_id is None:
        return None
    user = db.get(User, user_id)
    if user is None or user.role == "owner":
        return None
    return [str(grant.id) for grant in access.active_grants(db, machine) if grant.level == "manage"]


Apply = Callable[[dict[str, Any], dict[str, Any], MachineAppliance, Catalog], dict[str, Any]]


def _change(
    db: Session,
    settings: Settings,
    actor: Actor,
    machine: Machine,
    *,
    user_id: uuid.UUID | None,
    expected_revision: int | None,
    action: str,
    apply: Apply,
) -> Change:
    """Apply one change to a copy, check the whole result, then store, count and record it."""
    catalog = get_catalog(settings)
    row = _begin(db, machine, expected_revision)
    before_document = stored_document(row)
    before_secrets = dict(row.secrets or {})
    document = copy.deepcopy(before_document)
    secrets = dict(before_secrets)

    details = apply(document, secrets, row, catalog)

    # A secret goes when the last thing that referred to it goes.
    keep = referenced_secret_names(document, catalog)
    for name in [name for name in secrets if name not in keep]:
        del secrets[name]
    if document == before_document and secrets == before_secrets and row.revision > 0:
        return Change(row=row, changed=False)

    revision = row.revision + 1
    validate_document({**document, "revision": revision, "secrets": secrets}, catalog)
    row.document = document
    row.secrets = secrets
    row.revision = revision
    row.updated_by = user_id
    row.updated_at = utcnow()
    db.flush()
    # Names only. A sealed value never reaches the audit trail.
    details = {
        **details,
        "revision": revision,
        "sealed_set": sorted(n for n, v in secrets.items() if before_secrets.get(n) != v),
        "sealed_removed": sorted(set(before_secrets) - set(secrets)),
    }
    grants = _via_grant(db, machine, user_id)
    if grants is not None:
        details["remote_access_grants"] = grants
    audit(
        db,
        actor,
        action,
        object_type="machine",
        object_id=machine.id,
        owner_id=machine.owner_id,
        details=details,
    )
    return Change(row=row, changed=True)


def _find(entries: list[Any], entry_id: str) -> dict[str, Any] | None:
    return next((e for e in entries if isinstance(e, dict) and e.get("id") == entry_id), None)


def _put(entries: list[Any], entry: dict[str, Any]) -> tuple[bool, list[str]]:
    """Replace the entry with the same id, or append it. Returns (added, names of changed fields)."""
    existing = _find(entries, entry["id"])
    if existing is None:
        entries.append(entry)
        return True, sorted(k for k in entry if k != "id")
    changed = sorted(k for k in set(existing) | set(entry) if existing.get(k) != entry.get(k))
    entries[entries.index(existing)] = entry
    return False, changed


def _changed_fields(before: dict[str, Any] | None, after: dict[str, Any]) -> list[str]:
    before = before or {}
    return sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))


def _store_secret(
    row: MachineAppliance,
    secrets: dict[str, Any],
    name: str,
    sealed: Any,
    *,
    wanted: bool,
    what: str,
    moved: str | None = None,
) -> None:
    """Keep, replace or require the sealed value an object refers to.

    ``moved`` names what changed when the object now points somewhere else
    (another server, another API address). A stored secret is bound to where it
    was meant to go: it is not carried over to a new destination, or whoever
    may edit the configuration could send a customer's password or API key to a
    host of their choice without ever knowing it. It has to be sent again.
    """
    if sealed is not None:
        if not wanted:
            raise DocumentInvalid(f"sealed_secret: only {what} has a secret")
        secrets[name] = _accept_sealed(row, sealed)
    elif wanted and moved and name in secrets:
        raise DocumentInvalid(
            f"sealed_secret: {moved} changed, and the stored secret of {what} is not carried over to a new "
            "destination; send it again, sealed for the machine"
        )
    elif wanted and name not in secrets:
        raise DocumentInvalid(f"sealed_secret: {what} needs its secret, sealed for the machine")


def _moved(before: Any, after: dict[str, Any], keys: tuple[str, ...], what: str) -> str | None:
    """``what`` when ``before`` existed and any of ``keys`` differs, else None."""
    if not isinstance(before, dict):
        return None
    if any(before.get(key) != after.get(key) for key in keys):
        return what
    return None


# What a secret is bound to: change any of these and the secret must be sent again.
NAS_SECRET_BINDING = ("kind", "host", "share", "username", "domain")
ANSWER_SECRET_BINDING = ("provider", "base_url")
S3_SECRET_BINDING = ("kind", "endpoint", "access_key_id")


def set_mode(
    db: Session,
    settings: Settings,
    actor: Actor,
    provider: Provider | None,
    machine: Machine,
    *,
    mode: str,
    user_id: uuid.UUID | None,
    expected_revision: int | None = None,
) -> Change:
    """Change the mode. Leaving ``vast`` on a machine bound to a provider machine goes
    through the rental-protection gate; telemetry is never consulted."""
    if mode not in APPLIANCE_MODES:
        raise DocumentInvalid("mode: must be one of: " + ", ".join(APPLIANCE_MODES))
    row = _begin(db, machine, expected_revision)
    current = stored_document(row)["mode"]
    gate: dict[str, Any] = {"checked": False}
    if current == "vast" and mode != "vast":
        # Queried explicitly: a relationship cached on the object could be stale.
        bound = db.execute(select(ProviderMachine.id).where(ProviderMachine.machine_id == machine.id)).first()
        if bound is not None:
            decision = evaluate(db, settings, provider, machine, LEAVE_VAST_MODE)
            if not decision.allowed:
                audit(
                    db,
                    actor,
                    "appliance.mode_blocked",
                    object_type="machine",
                    object_id=machine.id,
                    owner_id=machine.owner_id,
                    details={"from": current, "to": mode, "reasons": decision.reasons},
                )
                return Change(row=row, changed=False, blocked=decision)
            gate = {"checked": True, **decision.as_dict()}

    def apply(
        document: dict[str, Any], _secrets: dict[str, Any], _row: Any, _catalog: Catalog
    ) -> dict[str, Any]:
        document["mode"] = mode
        return {"from": current, "to": mode, "gate": gate}

    return _change(
        db,
        settings,
        actor,
        machine,
        user_id=user_id,
        expected_revision=expected_revision,
        action="appliance.mode",
        apply=apply,
    )


def set_plugin(
    db: Session,
    settings: Settings,
    actor: Actor,
    machine: Machine,
    plugin_id: str,
    *,
    enabled: bool,
    values: dict[str, Any],
    sealed_secrets: dict[str, Any] | None,
    user_id: uuid.UUID | None,
    expected_revision: int | None = None,
) -> Change:
    """Add or replace one plugin entry. ``sealed_secrets`` maps a catalog secret key to a
    sealed value (stored as ``plugin.<id>.<key>``) or to None (the stored one is removed)."""

    def apply(
        document: dict[str, Any], secrets: dict[str, Any], row: Any, catalog: Catalog
    ) -> dict[str, Any]:
        spec = catalog.get(plugin_id)
        if spec is None:
            raise NotFound("this plugin is not in the catalog")
        existing = _find(document["plugins"], plugin_id)
        on_machine = (row.reported or {}).get("catalog")
        if (
            (enabled or existing is None)
            and isinstance(on_machine, list)
            and plugin_id not in {item.get("id") for item in on_machine}
        ):
            raise Conflict(
                "the firmware on this machine does not have this plugin; update the machine first",
                code="plugin_not_on_machine",
            )
        known = {secret.key for secret in spec.secrets}
        for key, sealed in (sealed_secrets or {}).items():
            if key not in known:
                raise DocumentInvalid("sealed_secrets: this plugin has no secret of that name")
            if sealed is None:
                secrets.pop(spec.secret_name(key), None)
            else:
                secrets[spec.secret_name(key)] = _accept_sealed(row, sealed)
        for secret in spec.secrets:
            if secret.required and spec.secret_name(secret.key) not in secrets:
                raise DocumentInvalid(
                    f"sealed_secrets.{secret.key}: this plugin needs it, sealed for the machine"
                )
        added, changed = _put(
            document["plugins"], {"id": plugin_id, "enabled": enabled, "settings": dict(values)}
        )
        return {"plugin": plugin_id, "enabled": enabled, "added": added, "changed": changed}

    return _change(
        db,
        settings,
        actor,
        machine,
        user_id=user_id,
        expected_revision=expected_revision,
        action="appliance.plugin.set",
        apply=apply,
    )


def remove_plugin(
    db: Session,
    settings: Settings,
    actor: Actor,
    machine: Machine,
    plugin_id: str,
    *,
    user_id: uuid.UUID | None,
    expected_revision: int | None = None,
) -> Change:
    """Take a plugin off the list. The machine stops it and keeps its data."""

    def apply(
        document: dict[str, Any], _secrets: dict[str, Any], _row: Any, catalog: Catalog
    ) -> dict[str, Any]:
        existing = _find(document["plugins"], plugin_id)
        if existing is None:
            raise NotFound("this plugin is not configured on the machine")
        needing = sorted(
            other["id"]
            for other in document["plugins"]
            if other is not existing
            and other.get("enabled")
            and catalog.get(other.get("id")) is not None
            and plugin_id in catalog.get(other["id"]).requires
        )
        if needing:
            raise Conflict(
                f"{', '.join(needing)} is enabled and requires this plugin; disable or remove it first",
                code="in_use",
            )
        restarting = sorted(s["id"] for s in document["schedules"] if s.get("plugin") == plugin_id)
        if restarting:
            raise Conflict(
                f"the schedule {', '.join(restarting)} restarts this plugin; remove it first", code="in_use"
            )
        document["plugins"].remove(existing)
        return {"plugin": plugin_id}

    return _change(
        db,
        settings,
        actor,
        machine,
        user_id=user_id,
        expected_revision=expected_revision,
        action="appliance.plugin.remove",
        apply=apply,
    )


def set_nas(
    db: Session,
    settings: Settings,
    actor: Actor,
    machine: Machine,
    nas_id: str,
    *,
    entry: dict[str, Any],
    sealed_secret: Any,
    user_id: uuid.UUID | None,
    expected_revision: int | None = None,
) -> Change:
    """Add or replace one NAS entry. The password of an SMB user travels sealed, in
    ``sealed_secret``, and is stored as ``nas.<id>.password``; omitted, the stored one stays."""

    def apply(
        document: dict[str, Any], secrets: dict[str, Any], row: Any, _catalog: Catalog
    ) -> dict[str, Any]:
        new = {"id": nas_id, **{k: v for k, v in entry.items() if k not in ("id", "secret")}}
        if new.get("kind") == "smb":
            new = {"subpath": "", "username": "", "domain": "", **new}
        name = nas_secret_name(nas_id)
        with_password = new.get("kind") == "smb" and bool(new.get("username"))
        _store_secret(
            row,
            secrets,
            name,
            sealed_secret,
            wanted=with_password,
            what="an SMB entry with a user name",
            moved=_moved(
                _find(document["nas"], nas_id), new, NAS_SECRET_BINDING, "the server, share or user name"
            ),
        )
        if with_password:
            new["secret"] = name
        added, changed = _put(document["nas"], new)
        return {
            "nas": nas_id,
            "kind": new.get("kind"),
            "access": new.get("access"),
            "added": added,
            "changed": changed,
        }

    return _change(
        db,
        settings,
        actor,
        machine,
        user_id=user_id,
        expected_revision=expected_revision,
        action="appliance.nas.set",
        apply=apply,
    )


def remove_nas(
    db: Session,
    settings: Settings,
    actor: Actor,
    machine: Machine,
    nas_id: str,
    *,
    user_id: uuid.UUID | None,
    expected_revision: int | None = None,
) -> Change:
    def apply(
        document: dict[str, Any], _secrets: dict[str, Any], _row: Any, _catalog: Catalog
    ) -> dict[str, Any]:
        existing = _find(document["nas"], nas_id)
        if existing is None:
            raise NotFound("this NAS entry is not configured on the machine")
        if nas_id in ((document.get("vectorizer") or {}).get("sources") or []):
            raise Conflict(
                "vectorization still reads this NAS entry; take it out of the sources first", code="in_use"
            )
        destination = (document.get("backup") or {}).get("destination") or {}
        if destination.get("kind") == "nas" and destination.get("nas_id") == nas_id:
            raise Conflict(
                "the backup still writes to this NAS entry; change the backup destination first",
                code="in_use",
            )
        document["nas"].remove(existing)
        return {"nas": nas_id}

    return _change(
        db,
        settings,
        actor,
        machine,
        user_id=user_id,
        expected_revision=expected_revision,
        action="appliance.nas.remove",
        apply=apply,
    )


def set_vectorizer(
    db: Session,
    settings: Settings,
    actor: Actor,
    machine: Machine,
    *,
    section: dict[str, Any],
    sealed_secret: Any,
    user_id: uuid.UUID | None,
    expected_revision: int | None = None,
) -> Change:
    """Configure vectorization. The key of a cloud answer provider travels sealed, in
    ``answer.sealed_secret`` of the request, and is stored as ``ai.answer.api_key``."""

    def apply(
        document: dict[str, Any], secrets: dict[str, Any], row: Any, _catalog: Catalog
    ) -> dict[str, Any]:
        new = copy.deepcopy(section)
        answer = new.get("answer")
        cloud = isinstance(answer, dict) and answer.get("provider") in CLOUD_ANSWER_PROVIDERS
        if isinstance(answer, dict):
            answer.pop("secret", None)
        _store_secret(
            row,
            secrets,
            ANSWER_KEY_NAME,
            sealed_secret,
            wanted=cloud,
            what="a cloud answer provider",
            moved=_moved(
                (document.get("vectorizer") or {}).get("answer"),
                answer if isinstance(answer, dict) else {},
                ANSWER_SECRET_BINDING,
                "the answer provider or its address",
            ),
        )
        if cloud:
            answer["secret"] = ANSWER_KEY_NAME
        before = document.get("vectorizer")
        document["vectorizer"] = new
        return {"added": before is None, "changed": _changed_fields(before, new)}

    return _change(
        db,
        settings,
        actor,
        machine,
        user_id=user_id,
        expected_revision=expected_revision,
        action="appliance.vectorizer.set",
        apply=apply,
    )


def remove_vectorizer(
    db: Session,
    settings: Settings,
    actor: Actor,
    machine: Machine,
    *,
    user_id: uuid.UUID | None,
    expected_revision: int | None = None,
) -> Change:
    def apply(
        document: dict[str, Any], _secrets: dict[str, Any], _row: Any, _catalog: Catalog
    ) -> dict[str, Any]:
        if "vectorizer" not in document:
            raise NotFound("vectorization is not configured on the machine")
        plugin = _find(document["plugins"], VECTORIZER_PLUGIN)
        if plugin is not None and plugin.get("enabled"):
            raise Conflict(
                "the vectorizer plugin is enabled and needs this configuration; disable it first",
                code="in_use",
            )
        del document["vectorizer"]
        return {}

    return _change(
        db,
        settings,
        actor,
        machine,
        user_id=user_id,
        expected_revision=expected_revision,
        action="appliance.vectorizer.remove",
        apply=apply,
    )


def set_backup(
    db: Session,
    settings: Settings,
    actor: Actor,
    machine: Machine,
    *,
    section: dict[str, Any],
    sealed_secret: Any,
    user_id: uuid.UUID | None,
    expected_revision: int | None = None,
) -> Change:
    """Configure backups. The secret key of an S3 destination travels sealed, in
    ``destination.sealed_secret`` of the request, and is stored as ``backup.s3.secret_key``."""

    def apply(
        document: dict[str, Any], secrets: dict[str, Any], row: Any, _catalog: Catalog
    ) -> dict[str, Any]:
        new = copy.deepcopy(section)
        destination = new.get("destination")
        s3 = isinstance(destination, dict) and destination.get("kind") == "s3"
        if isinstance(destination, dict):
            destination.pop("secret", None)
        _store_secret(
            row,
            secrets,
            S3_KEY_NAME,
            sealed_secret,
            wanted=s3,
            what="an S3 destination",
            moved=_moved(
                (document.get("backup") or {}).get("destination"),
                destination if isinstance(destination, dict) else {},
                S3_SECRET_BINDING,
                "the S3 endpoint or access key id",
            ),
        )
        if s3:
            destination.setdefault("prefix", "")
            destination["secret"] = S3_KEY_NAME
        before = document.get("backup")
        document["backup"] = new
        return {"added": before is None, "changed": _changed_fields(before, new)}

    return _change(
        db,
        settings,
        actor,
        machine,
        user_id=user_id,
        expected_revision=expected_revision,
        action="appliance.backup.set",
        apply=apply,
    )


def remove_backup(
    db: Session,
    settings: Settings,
    actor: Actor,
    machine: Machine,
    *,
    user_id: uuid.UUID | None,
    expected_revision: int | None = None,
) -> Change:
    def apply(
        document: dict[str, Any], _secrets: dict[str, Any], _row: Any, _catalog: Catalog
    ) -> dict[str, Any]:
        if "backup" not in document:
            raise NotFound("no backup is configured on the machine")
        del document["backup"]
        return {}

    return _change(
        db,
        settings,
        actor,
        machine,
        user_id=user_id,
        expected_revision=expected_revision,
        action="appliance.backup.remove",
        apply=apply,
    )


def set_schedule(
    db: Session,
    settings: Settings,
    actor: Actor,
    machine: Machine,
    schedule_id: str,
    *,
    entry: dict[str, Any],
    user_id: uuid.UUID | None,
    expected_revision: int | None = None,
) -> Change:
    def apply(
        document: dict[str, Any], _secrets: dict[str, Any], _row: Any, _catalog: Catalog
    ) -> dict[str, Any]:
        new = {"id": schedule_id, **{k: v for k, v in entry.items() if k != "id"}}
        added, changed = _put(document["schedules"], new)
        return {"schedule": schedule_id, "job": new.get("job"), "added": added, "changed": changed}

    return _change(
        db,
        settings,
        actor,
        machine,
        user_id=user_id,
        expected_revision=expected_revision,
        action="appliance.schedule.set",
        apply=apply,
    )


def remove_schedule(
    db: Session,
    settings: Settings,
    actor: Actor,
    machine: Machine,
    schedule_id: str,
    *,
    user_id: uuid.UUID | None,
    expected_revision: int | None = None,
) -> Change:
    def apply(
        document: dict[str, Any], _secrets: dict[str, Any], _row: Any, _catalog: Catalog
    ) -> dict[str, Any]:
        existing = _find(document["schedules"], schedule_id)
        if existing is None:
            raise NotFound("this schedule is not configured on the machine")
        document["schedules"].remove(existing)
        return {"schedule": schedule_id}

    return _change(
        db,
        settings,
        actor,
        machine,
        user_id=user_id,
        expected_revision=expected_revision,
        action="appliance.schedule.remove",
        apply=apply,
    )


def set_update(
    db: Session,
    settings: Settings,
    actor: Actor,
    machine: Machine,
    *,
    section: dict[str, Any],
    user_id: uuid.UUID | None,
    expected_revision: int | None = None,
) -> Change:
    def apply(
        document: dict[str, Any], _secrets: dict[str, Any], _row: Any, _catalog: Catalog
    ) -> dict[str, Any]:
        before = document.get("update")
        document["update"] = copy.deepcopy(section)
        return {
            "channel": section.get("channel"),
            "policy": section.get("policy"),
            "changed": _changed_fields(before, section),
        }

    return _change(
        db,
        settings,
        actor,
        machine,
        user_id=user_id,
        expected_revision=expected_revision,
        action="appliance.update.set",
        apply=apply,
    )


def reset_for_new_owner(db: Session, machine: Machine, actor: Actor) -> MachineAppliance:
    """A machine that changes owner starts again from nothing.

    The new owner must not inherit the previous owner's NAS entries, plugins or
    sealed secrets. The document goes back to the default (mode ``vast``, where
    no plugin runs), the secrets are dropped, and the revision goes up so that
    the machine applies it. Called inside the ownership transfer.
    """
    row = _row(db, machine.id, lock=True, create=True)
    previous = stored_document(row)
    dropped = sorted(row.secrets or {})
    row.document = default_document()
    row.secrets = {}
    row.revision = row.revision + 1
    row.updated_by = uuid.UUID(actor.id) if actor.type == "user" and actor.id else None
    row.updated_at = utcnow()
    # What the machine last said describes the previous owner's set-up.
    row.reported = {
        key: value
        for key, value in (row.reported or {}).items()
        if key in ("schema", "control", "capabilities", "catalog", "update")
    }
    # Jobs and updates someone of the previous owner asked for and the machine has not received.
    cancelled = (
        db.execute(
            update(Operation)
            .where(
                Operation.machine_id == machine.id,
                Operation.status == "pending",
                Operation.type.in_(tuple(operation_service.APPLIANCE_ONLY_TYPES)),
            )
            .values(status="cancelled", completed_at=utcnow(), detail="the machine changed owner")
        ).rowcount
        or 0
    )
    db.flush()
    audit(
        db,
        actor,
        "appliance.reset",
        object_type="machine",
        object_id=machine.id,
        owner_id=machine.owner_id,
        details={
            "reason": "ownership transfer",
            "revision": row.revision,
            "previous_mode": previous["mode"],
            "plugins_removed": len(previous["plugins"]),
            "nas_removed": len(previous["nas"]),
            "schedules_removed": len(previous["schedules"]),
            "sealed_removed": dropped,
            "operations_cancelled": cancelled,
        },
    )
    return row


# =============================================================================
# Jobs
# =============================================================================


def request_job(
    db: Session,
    settings: Settings,
    actor: Actor,
    provider: Provider | None,
    machine: Machine,
    *,
    job: str,
    plugin: str | None,
    user_id: uuid.UUID | None,
) -> Operation:
    """Ask the machine to run one appliance job now, as a typed operation."""
    params: dict[str, Any] = {"job": job}
    if plugin is not None:
        params["plugin"] = plugin
    # The shape first, by the same validator the operation table uses.
    clean = operation_service.OPERATION_TYPES["appliance_run_job"](params)
    if "plugin" in clean and _find(stored_document(_row(db, machine.id))["plugins"], clean["plugin"]) is None:
        raise Conflict("this plugin is not configured on the machine")
    return operation_service.request_operation(
        db,
        settings,
        actor,
        provider,
        machine=machine,
        op_type="appliance_run_job",
        params=clean,
        requested_by=user_id,
        via_appliance=True,
    )


# =============================================================================
# What the machine reports (section 6.1)
# =============================================================================

REPORT_LIST_MAX = 32
REPORT_STRING_MAX = 128
REPORT_DETAIL_MAX = 500
UNKNOWN = "unknown"  # what a state the contract does not list is shown as

CONTROL_VALUES = ("cloud", "local", "unknown")
APPLY_STATUSES = ("applied", "partial", "rejected", "disabled", "pending")
PLUGIN_STATES = ("running", "starting", "stopped", "blocked", "error", "not_in_catalog")
NAS_STATES = ("mounted", "unmounted", "error")
SECRET_STATES = ("ok", "unreadable", "missing")
VECTORIZER_STATES = ("disabled", "idle", "running", "error")
BACKUP_STATES = ("disabled", "no_key", "never", "running", "ok", "error")
UPDATE_STATES = ("idle", "downloading", "installing", "installed", "rolled_back", "error")
SCHEDULE_STATUSES = ("ok", "failed", "skipped", "never")
CAPABILITIES = ("plugins", "nas", "backup", "update", "docker")

_VERSION_TEXT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,39}")
_KEY_ID_RE = re.compile(r"[0-9a-f]{8}")
_MAX_COUNT = 2**53


def _enum(value: Any, allowed: tuple[str, ...], fallback: str = UNKNOWN) -> str:
    return value if isinstance(value, str) and value in allowed else fallback


def _detail(value: Any) -> str:
    """Free text from the machine: bounded, without control characters, redacted again here."""
    if not isinstance(value, str):
        return ""
    text = "".join(ch if not has_control_character(ch) else " " for ch in value[: REPORT_DETAIL_MAX * 4])
    return redact_text(text)[:REPORT_DETAIL_MAX]


def _version_text(value: Any) -> str:
    return value if isinstance(value, str) and _VERSION_TEXT_RE.fullmatch(value) else ""


def _moment(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > REPORT_STRING_MAX:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.isoformat() if parsed.tzinfo is not None else None


def _count(value: Any) -> int | None:
    return value if _is_int(value) and 0 <= value <= _MAX_COUNT else None


def _items(value: Any, key: str, pattern: re.Pattern[str]) -> list[dict[str, Any]]:
    """The entries of a reported list that have a well-formed, not yet seen identifier."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    if not isinstance(value, list):
        return out
    for item in value[:REPORT_LIST_MAX]:
        name = item.get(key) if isinstance(item, dict) else None
        if isinstance(name, str) and pattern.fullmatch(name) and name not in seen:
            seen.add(name)
            out.append(item)
    return out


def sanitise_report(raw: dict[str, Any], revision: int) -> dict[str, Any]:
    """Keep the keys of the contract, bound everything, and trust none of it."""
    out: dict[str, Any] = {
        "schema": raw["schema"]
        if _is_int(raw.get("schema")) and 0 < raw["schema"] < 1000
        else DOCUMENT_SCHEMA,
        # Exactly "cloud" or "local"; anything else is "unknown". The agent says
        # "unknown" when it cannot reach its helper, which could not apply a
        # document then: the document waits until the machine says "cloud".
        "control": _enum(raw.get("control"), CONTROL_VALUES, "unknown"),
        "applied_revision": min(max(raw["applied_revision"], 0), revision)
        if _is_int(raw.get("applied_revision"))
        else 0,
        "apply_status": _enum(raw.get("apply_status"), APPLY_STATUSES),
        "apply_detail": _detail(raw.get("apply_detail")),
        "mode": _enum(raw.get("mode"), APPLIANCE_MODES),
    }
    if isinstance(raw.get("capabilities"), dict):
        out["capabilities"] = {
            name: raw["capabilities"][name]
            for name in CAPABILITIES
            if isinstance(raw["capabilities"].get(name), bool)
        }
    if isinstance(raw.get("catalog"), list):
        out["catalog"] = [
            {"id": item["id"], "version": _version_text(item.get("version"))}
            for item in _items(raw["catalog"], "id", ID_RE)
        ]
    if isinstance(raw.get("plugins"), list):
        out["plugins"] = [
            {
                "id": item["id"],
                "state": _enum(item.get("state"), PLUGIN_STATES),
                "detail": _detail(item.get("detail")),
                "version": _version_text(item.get("version")),
                "ports": [
                    port
                    for port in (item.get("ports") if isinstance(item.get("ports"), list) else [])[
                        :REPORT_LIST_MAX
                    ]
                    if _is_int(port) and 1 <= port <= 65535
                ],
            }
            for item in _items(raw["plugins"], "id", ID_RE)
        ]
    if isinstance(raw.get("nas"), list):
        out["nas"] = [
            {
                "id": item["id"],
                "state": _enum(item.get("state"), NAS_STATES),
                "detail": _detail(item.get("detail")),
            }
            for item in _items(raw["nas"], "id", ID_RE)
        ]
    if isinstance(raw.get("secrets"), list):
        out["secrets"] = [
            {"name": item["name"], "state": _enum(item.get("state"), SECRET_STATES)}
            for item in _items(raw["secrets"], "name", SECRET_NAME_RE)
        ]
    section = raw.get("vectorizer")
    if isinstance(section, dict):
        out["vectorizer"] = {
            "state": _enum(section.get("state"), VECTORIZER_STATES),
            "last_run_at": _moment(section.get("last_run_at")),
            "last_ok_at": _moment(section.get("last_ok_at")),
            "files_indexed": _count(section.get("files_indexed")),
            "files_failed": _count(section.get("files_failed")),
            "files_skipped": _count(section.get("files_skipped")),
            "chunks": _count(section.get("chunks")),
            "detail": _detail(section.get("detail")),
        }
    section = raw.get("backup")
    if isinstance(section, dict):
        key_id = section.get("key_id")
        out["backup"] = {
            "state": _enum(section.get("state"), BACKUP_STATES),
            "key_present": section.get("key_present") is True,
            "key_id": key_id if isinstance(key_id, str) and _KEY_ID_RE.fullmatch(key_id) else "",
            "last_ok_at": _moment(section.get("last_ok_at")),
            "last_size_bytes": _count(section.get("last_size_bytes")),
            "detail": _detail(section.get("detail")),
        }
    section = raw.get("update")
    if isinstance(section, dict):
        out["update"] = {
            "current_version": _version_text(section.get("current_version")),
            "state": _enum(section.get("state"), UPDATE_STATES),
            "target_version": _version_text(section.get("target_version")),
            "detail": _detail(section.get("detail")),
        }
    if isinstance(raw.get("schedules"), list):
        out["schedules"] = [
            {
                "id": item["id"],
                "last_run_at": _moment(item.get("last_run_at")),
                "last_status": _enum(item.get("last_status"), SCHEDULE_STATUSES),
                "next_run_at": _moment(item.get("next_run_at")),
            }
            for item in _items(raw["schedules"], "id", ID_RE)
        ]
    return out


def record_report(
    db: Session, machine_appliance: MachineAppliance, raw: dict[str, Any], *, actor: Actor | None = None
) -> None:
    """Store what a machine says about itself in a heartbeat.

    It is shown to people. It is never used to decide what anyone may do.
    """
    row = machine_appliance
    clean = sanitise_report(raw if isinstance(raw, dict) else {}, row.revision)
    row.reported = clean
    row.reported_at = utcnow()
    row.applied_revision = clean["applied_revision"]
    key = raw.get("seal_public_key") if isinstance(raw, dict) else None
    if isinstance(key, str) and len(key) <= 120 and key != row.seal_public_key:
        try:
            parse_seal_public_key(key)
        except InvalidRequest:
            key = None  # not a key: ignored, the one on record stays
        if key is not None:
            machine = db.get(Machine, row.machine_id)
            # A new key means secrets sealed for the old one no longer open. Worth a line:
            # it is also what a stolen device credential would do to receive future secrets.
            audit(
                db,
                actor or Actor.system("appliance-report"),
                "appliance.seal_key",
                object_type="machine",
                object_id=row.machine_id,
                owner_id=machine.owner_id if machine else None,
                details={
                    "first": row.seal_public_key is None,
                    "fingerprint": hashlib.sha256(key.encode()).hexdigest()[:16],
                    "sealed_values_on_record": len(row.secrets or {}),
                },
            )
            row.seal_public_key = key
    db.flush()


def heartbeat_exchange(
    db: Session, machine: Machine, raw: Any, *, actor: Actor | None = None
) -> dict[str, Any] | None:
    """The appliance part of a heartbeat: record the report, answer with the document (6.2).

    Returns None when there is nothing to say: no cloud revision yet. The
    document, with its sealed secrets, goes only to the machine's own device
    credential, only when the machine does not already have this revision, and
    never to a machine that follows its own profile file.
    """
    if not isinstance(raw, dict):
        return None
    row = _row(db, machine.id, lock=True, create=True)
    record_report(db, row, raw, actor=actor)
    if row.revision < 1:
        return None
    out: dict[str, Any] = {"revision": row.revision}
    reported = raw.get("applied_revision")
    up_to_date = _is_int(reported) and reported == row.revision
    # Only to a machine that says it follows the cloud: under local control it
    # ignores the document, and in an unknown state it cannot apply it.
    if _control(row) == "cloud" and not up_to_date:
        out["document"] = {
            **stored_document(row),
            "revision": row.revision,
            "secrets": dict(row.secrets or {}),
        }
    return out


# =============================================================================
# Views
# =============================================================================


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _in_sync(row: MachineAppliance | None) -> bool:
    """The machine finished applying exactly the revision the cloud holds."""
    if row is None or row.revision == 0:
        return True
    reported = row.reported or {}
    return (
        reported.get("control") == "cloud"
        and row.applied_revision == row.revision
        and reported.get("apply_status") == "applied"
    )


def view(db: Session, settings: Settings, principal: Principal, machine: Machine) -> dict[str, Any]:
    """What ``GET /machines/{id}/appliance`` returns. Secrets appear as names only."""
    catalog = get_catalog(settings)
    row = _row(db, machine.id)
    reported = (row.reported if row is not None else None) or {}
    on_machine = {item["id"]: item.get("version", "") for item in reported.get("catalog") or []}
    knows_machine_catalog = isinstance(reported.get("catalog"), list)
    return {
        "machine_id": str(machine.id),
        "management": machine.management,
        "revision": row.revision if row is not None else 0,
        "applied_revision": row.applied_revision if row is not None else 0,
        "in_sync": _in_sync(row),
        "control": _control(row),
        "updated_at": _iso(row.updated_at) if row is not None else None,
        "updated_by": str(row.updated_by) if row is not None and row.updated_by else None,
        "document": stored_document(row),
        "secrets": sorted((row.secrets if row is not None else None) or {}),
        "seal_public_key": row.seal_public_key if row is not None else None,
        "reported": reported or None,
        "reported_at": _iso(row.reported_at) if row is not None else None,
        "catalog": [
            {
                **entry.public(),
                # None: the machine has not said which plugins its firmware has.
                "on_machine": (entry.id in on_machine) if knows_machine_catalog else None,
                "machine_version": on_machine.get(entry.id),
            }
            for entry in catalog
        ],
        "can_operate": access.can_manage_appliance(db, principal, machine, "org_operator"),
        "can_admin": access.can_manage_appliance(db, principal, machine, "org_admin"),
    }


def integration_view(db: Session, machine: Machine) -> dict[str, Any]:
    """What an API client with ``appliance:read`` sees: state, not configuration.

    No NAS host, share or user name, no secret name, and none of the machine's
    free-text details (a mount error can quote a host name).
    """
    row = _row(db, machine.id)
    document = stored_document(row)
    reported = (row.reported if row is not None else None) or {}
    states = {item["id"]: item for item in reported.get("plugins") or []}
    vectorizer = reported.get("vectorizer") or {}
    backup = reported.get("backup") or {}
    updates = reported.get("update") or {}
    wanted_update = document.get("update") or {}
    return {
        "machine_id": str(machine.id),
        "mode": document["mode"],
        "reported_mode": reported.get("mode"),
        "management": machine.management,
        "control": _control(row),
        "revision": row.revision if row is not None else 0,
        "applied_revision": row.applied_revision if row is not None else 0,
        "apply_status": reported.get("apply_status"),
        "in_sync": _in_sync(row),
        "reported_at": _iso(row.reported_at) if row is not None else None,
        "plugins": [
            {
                "id": plugin["id"],
                "enabled": plugin["enabled"],
                "state": states.get(plugin["id"], {}).get("state"),
                "version": states.get(plugin["id"], {}).get("version"),
            }
            for plugin in document["plugins"]
        ],
        "vectorizer": {
            "configured": "vectorizer" in document,
            **{
                key: vectorizer.get(key)
                for key in (
                    "state",
                    "last_run_at",
                    "last_ok_at",
                    "files_indexed",
                    "files_failed",
                    "files_skipped",
                    "chunks",
                )
            },
        },
        "backup": {
            "configured": "backup" in document,
            "enabled": bool((document.get("backup") or {}).get("enabled")),
            **{key: backup.get(key) for key in ("state", "key_present", "last_ok_at", "last_size_bytes")},
        },
        "update": {
            "channel": wanted_update.get("channel", "none"),
            "policy": wanted_update.get("policy", "manual"),
            **{key: updates.get(key) for key in ("current_version", "state", "target_version")},
        },
    }


def update_settings(db: Session, machine: Machine) -> dict[str, Any]:
    """The machine's update channel, policy and window as the cloud holds them. Absent: no channel."""
    section = stored_document(_row(db, machine.id)).get("update") or {}
    return {
        "channel": section.get("channel", "none"),
        "policy": section.get("policy", "manual"),
        "window": section.get("window"),
    }
